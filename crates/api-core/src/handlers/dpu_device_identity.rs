/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Discovery-time DPU device-identity resolution (issue NVIDIA/infra-controller#355 epic).
//!
//! For a DPU, optionally replaces the legacy serial-derived `machine_id` with a
//! hardware-rooted one derived from the BlueField IRoT device-identity
//! certificate. The certificate is fetched **out-of-band** from the DPU BMC over
//! Redfish SPDM `ComponentIntegrity` (the same mechanism the SPDM controller
//! uses); verification, the `[dpu_device_attestation]` mode policy, and the
//! binding record are all delegated to
//! [`ApiDpuDeviceIdentityResolver`](crate::attestation::dpu_id_resolver::ApiDpuDeviceIdentityResolver)
//! — the same pipeline site-explorer uses — so the two paths cannot drift.
//!
//! Requires that site-explorer has pre-ingested the DPU's BMC (the cert fetch
//! correlates the DPU's DMI serial to its explored BMC endpoint).

use carbide_uuid::machine::MachineId;
use model::attestation::spdm::is_bluefield_dpu_irot;
use model::attestation::{DpuDeviceIdentityError, DpuDeviceIdentityResolver};
use model::hardware_info::HardwareInfo;
use model::machine::machine_search_config::MachineSearchConfig;

use crate::CarbideError;
use crate::api::Api;
use crate::attestation::dpu_device;
use crate::attestation::dpu_id_resolver::ApiDpuDeviceIdentityResolver;

/// Resolves the `machine_id` to use for a DPU under the configured
/// [`DpuDeviceAttestationMode`]. `legacy_id` is the serial-derived id. Returns
/// the (possibly device-rooted) id, or an error in `Required` mode when no
/// verified device identity is available for a previously-unseen DPU.
pub(crate) async fn resolve_dpu_device_identity(
    api: &Api,
    hardware_info: &HardwareInfo,
    legacy_id: MachineId,
) -> Result<MachineId, CarbideError> {
    let mode = api.runtime_config.dpu_device_attestation.mode;
    let resolver = ApiDpuDeviceIdentityResolver::new(api.database_connection.clone(), mode);

    // An enrolled DPU (legacy or previously device-rooted) keeps its id in
    // every mode — including `disabled`, so a mode rollback never re-keys
    // adopted DPUs — and skips the BMC fetch entirely.
    if let Some(enrolled) = resolver
        .enrolled_machine_id(legacy_id)
        .await
        .map_err(carbide_error)?
    {
        return Ok(enrolled);
    }

    let irot_chain_pem = if resolver.wants_irot_chain() {
        fetch_irot_chain_pem(api, hardware_info).await
    } else {
        None
    };

    let resolved = resolver
        .resolve_dpu_machine_id(irot_chain_pem.as_deref(), Some(legacy_id))
        .await
        .map_err(carbide_error)?;

    // With a legacy id supplied, resolution always yields an id.
    Ok(resolved.unwrap_or(legacy_id))
}

fn carbide_error(e: DpuDeviceIdentityError) -> CarbideError {
    match e {
        DpuDeviceIdentityError::Required(msg) => CarbideError::FailedPrecondition(msg),
        DpuDeviceIdentityError::Internal(msg) => CarbideError::internal(msg),
    }
}

/// Fetches the BlueField IRoT certificate chain (PEM) from the DPU BMC.
/// Returns `None` (logging the reason) on any soft failure — no serial, no
/// explored BMC, no IRoT component, a Redfish error — so the resolver can
/// apply the mode policy.
async fn fetch_irot_chain_pem(api: &Api, hardware_info: &HardwareInfo) -> Option<String> {
    let serial = hardware_info
        .dmi_data
        .as_ref()
        .map(|d| d.product_serial.clone())
        .filter(|s| !s.is_empty())?;

    let endpoints = db::explored_endpoints::find_by_dpu_serial_numbers(
        &mut api.db_reader(),
        vec![serial.clone()],
    )
    .await
    .map_err(|e| tracing::warn!("DPU {serial}: explored_endpoints lookup failed: {e}"))
    .ok()?;

    if endpoints.len() > 1 {
        // Ambiguous correlation: picking one (e.g. the lowest address) could
        // fetch a *different* DPU's valid IRoT cert and bind its hardware
        // identity to this report. Treat the identity as unavailable so
        // `required` fails closed and `best_effort` falls back to the legacy id.
        tracing::warn!(
            "DPU {serial}: {} explored BMC endpoints match this serial; \
             treating device identity as unavailable (ambiguous correlation)",
            endpoints.len()
        );
        return None;
    }
    let Some(endpoint) = endpoints.into_iter().next() else {
        tracing::info!("DPU {serial}: no explored BMC endpoint; cannot fetch IRoT cert");
        return None;
    };

    let access =
        db::machine_interface::lookup_bmc_access_info(&mut api.db_reader(), endpoint.address, None)
            .await
            .map_err(|e| tracing::warn!("DPU {serial}: BMC access lookup failed: {e}"))
            .ok()?;

    let client = api
        .redfish_pool
        .client_by_info(&access)
        .await
        .map_err(|e| tracing::warn!("DPU {serial}: redfish client creation failed: {e}"))
        .ok()?;

    let integrities = client
        .get_component_integrities()
        .await
        .map_err(|e| tracing::warn!("DPU {serial}: get_component_integrities failed: {e}"))
        .ok()?;

    let Some(cert_link) = integrities
        .members
        .into_iter()
        .find(|m| is_bluefield_dpu_irot(&m.id))
        .and_then(|m| m.spdm)
        .map(|s| {
            s.identity_authentication
                .responder_authentication
                .component_certificate
                .odata_id
        })
    else {
        tracing::info!("DPU {serial}: no BlueField IRoT ComponentIntegrity cert link");
        return None;
    };

    let ca_cert = client
        .get_component_ca_certificate(&cert_link)
        .await
        .map_err(|e| tracing::warn!("DPU {serial}: get_component_ca_certificate failed: {e}"))
        .ok()?;

    Some(ca_cert.certificate_string)
}

/// Re-verifies a DPU's hardware identity for an already-enrolled, device-rooted
/// machine. Re-fetches the BlueField IRoT out-of-band and requires the *live*
/// device to re-verify (chain to a trusted root) to the **same** `machine_id`.
///
/// Used to authorize a cert-free node-token refresh: a stolen bearer token alone
/// cannot satisfy it, because the controller's out-of-band BMC fetch would not
/// return that DPU's IRoT. This is a **strict** check — unlike
/// [`resolve_dpu_device_identity`], there is no best-effort legacy fallback, so a
/// fetch or verification failure denies the refresh.
///
/// Returns `PermissionDenied` when the identity cannot be re-verified or does not
/// match; `FailedPrecondition` when the machine has no stored hardware info.
pub(crate) async fn reverify_dpu_device_identity(
    api: &Api,
    machine_id: &MachineId,
) -> Result<(), CarbideError> {
    let machine = db::machine::find_one(
        &mut api.db_reader(),
        machine_id,
        MachineSearchConfig {
            include_dpus: true,
            ..MachineSearchConfig::default()
        },
    )
    .await?
    .ok_or_else(|| {
        CarbideError::PermissionDeniedError(
            "unknown machine for device-identity refresh".to_string(),
        )
    })?;

    let hardware_info = machine.hardware_info.ok_or_else(|| {
        CarbideError::FailedPrecondition(
            "machine has no hardware info for device-identity re-verification".to_string(),
        )
    })?;

    let Some(pem) = fetch_irot_chain_pem(api, &hardware_info).await else {
        return Err(CarbideError::PermissionDeniedError(
            "DPU device identity could not be re-verified".to_string(),
        ));
    };

    let chain_der = dpu_device::pem_chain_to_der(&pem).map_err(|e| {
        CarbideError::PermissionDeniedError(format!("IRoT cert chain parse failed: {e}"))
    })?;
    let roots = db::attestation::dpu_device_ca_certs::get_all(&mut api.db_reader()).await?;
    let roots_der: Vec<Vec<u8>> = roots.into_iter().map(|r| r.ca_cert_der).collect();
    let verified = dpu_device::verify_device_cert_chain(&chain_der, &roots_der, chrono::Utc::now())
        .map_err(|e| {
            CarbideError::PermissionDeniedError(format!("IRoT cert verification failed: {e}"))
        })?;

    if verified.machine_id != *machine_id {
        return Err(CarbideError::PermissionDeniedError(
            "re-verified DPU device identity does not match the requesting machine".to_string(),
        ));
    }

    Ok(())
}
