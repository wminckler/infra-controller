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

//! In-process certificate vending backed by a local intermediate CA.
//!
//! This is the non-Vault alternative to [`crate::ForgeVaultClient`]: instead of
//! calling Vault PKI, it signs leaf certificates itself with `rcgen`, using a
//! CA key held in memory (loaded by the caller from a Kubernetes Secret or a
//! file). Issued certificates keep the same SPIFFE URI SAN layout and TTL skew
//! as the Vault backend, so the two are shape-compatible for relying parties.

use std::fmt;

use async_trait::async_trait;
use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData, SanType,
};
use time::{Duration, OffsetDateTime};

use crate::SecretsError;
use crate::certificates::{
    Certificate, CertificateProvider, parse_ttl_seconds, skewed_default_ttl_hours,
};
use crate::forge_vault::{SpiffeIdentity, machine_spiffe_uri};

/// PEM-encoded intermediate-CA key material for the local-CA backend. Loading
/// it (from a Kubernetes Secret or a file) is the caller's responsibility; this
/// crate stays free of any Kubernetes dependency.
#[derive(Clone)]
pub struct LocalCaMaterial {
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
}

impl fmt::Debug for LocalCaMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the private key.
        f.debug_struct("LocalCaMaterial").finish_non_exhaustive()
    }
}

fn signing_error(context: &str, err: rcgen::Error) -> SecretsError {
    SecretsError::from(eyre::eyre!("{context}: {err}"))
}

/// Reject the CA material early if the private key does not correspond to the
/// public key in the CA certificate. Without this, a mismatched key/cert pair
/// (an easy Secret-misconfiguration) would silently issue leaves that don't
/// chain to the published `issuing_ca`, only failing when clients reject them.
fn verify_key_matches_cert(ca_cert_pem: &str, signing_key: &KeyPair) -> Result<(), SecretsError> {
    use x509_parser::prelude::*;

    let (_, pem) = parse_x509_pem(ca_cert_pem.as_bytes()).map_err(|err| {
        SecretsError::from(eyre::eyre!(
            "failed to parse local CA certificate PEM: {err}"
        ))
    })?;
    let (_, cert) = parse_x509_certificate(&pem.contents).map_err(|err| {
        SecretsError::from(eyre::eyre!("failed to parse local CA certificate: {err}"))
    })?;

    // Both are canonical SubjectPublicKeyInfo DER, so a matching key/cert pair
    // is byte-identical here.
    if cert.public_key().raw != signing_key.subject_public_key_info().as_slice() {
        return Err(SecretsError::from(eyre::eyre!(
            "local CA private key does not match the CA certificate"
        )));
    }
    Ok(())
}

/// Push a DNS SAN, rejecting malformed names. `Ia5String` only enforces ASCII,
/// so empty labels and embedded whitespace would otherwise slip through.
fn push_dns_san(sans: &mut Vec<SanType>, name: &str) -> Result<(), SecretsError> {
    let well_formed = !name.is_empty()
        && name
            .split('.')
            .all(|label| !label.is_empty() && !label.chars().any(char::is_whitespace));
    if !well_formed {
        return Err(SecretsError::from(eyre::eyre!("invalid DNS SAN {name:?}")));
    }
    sans.push(SanType::DnsName(
        Ia5String::try_from(name.to_string())
            .map_err(|err| SecretsError::from(eyre::eyre!("invalid DNS SAN {name:?}: {err}")))?,
    ));
    Ok(())
}

/// Issues leaf certificates in-process, signed by an in-memory intermediate CA.
pub struct LocalCaCertProvider {
    issuer: Issuer<'static, KeyPair>,
    ca_cert_pem: String,
    spiffe: SpiffeIdentity,
}

impl LocalCaCertProvider {
    /// Build a provider from loaded CA material. The CA certificate and key are
    /// parsed here, so malformed material fails fast at startup rather than on
    /// the first issuance request.
    pub fn from_pem(
        material: &LocalCaMaterial,
        spiffe: SpiffeIdentity,
    ) -> Result<Self, SecretsError> {
        let signing_key = KeyPair::from_pem(&material.ca_key_pem)
            .map_err(|err| signing_error("failed to parse local CA private key", err))?;
        verify_key_matches_cert(&material.ca_cert_pem, &signing_key)?;
        let issuer = Issuer::from_ca_cert_pem(&material.ca_cert_pem, signing_key)
            .map_err(|err| signing_error("failed to parse local CA certificate", err))?;

        Ok(Self {
            issuer,
            ca_cert_pem: material.ca_cert_pem.clone(),
            spiffe,
        })
    }

    fn issue(
        &self,
        unique_identifier: &str,
        alt_names: Option<String>,
        ttl: Option<String>,
    ) -> Result<Certificate, SecretsError> {
        let ttl_seconds = match ttl {
            Some(ttl) => parse_ttl_seconds(&ttl)?,
            None => skewed_default_ttl_hours().saturating_mul(3600),
        };
        let ttl_seconds = i64::try_from(ttl_seconds).map_err(|_| {
            SecretsError::from(eyre::eyre!("certificate TTL is too large: {ttl_seconds}s"))
        })?;

        // SPIFFE URI SAN, matching the Vault backend's identity layout.
        let spiffe_uri = machine_spiffe_uri(
            &self.spiffe.trust_domain,
            &self.spiffe.machine_base_path,
            unique_identifier,
        );
        let mut subject_alt_names = vec![SanType::URI(
            Ia5String::try_from(spiffe_uri)
                .map_err(|err| SecretsError::from(eyre::eyre!("invalid SPIFFE URI SAN: {err}")))?,
        )];
        if let Some(alt_names) = alt_names {
            for name in alt_names
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                push_dns_san(&mut subject_alt_names, name)?;
            }
        }

        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::default();
        params.subject_alt_names = subject_alt_names;
        // Backdate slightly to tolerate clock skew between issuer and clients.
        params.not_before = now - Duration::minutes(5);
        params.not_after = now
            .checked_add(Duration::seconds(ttl_seconds))
            .ok_or_else(|| {
                SecretsError::from(eyre::eyre!("certificate TTL exceeds supported date range"))
            })?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, unique_identifier);
        params.distinguished_name = distinguished_name;

        let leaf_key =
            KeyPair::generate().map_err(|err| signing_error("failed to generate leaf key", err))?;
        let cert = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|err| signing_error("failed to sign certificate", err))?;

        Ok(Certificate {
            issuing_ca: self.ca_cert_pem.clone().into_bytes(),
            public_key: cert.pem().into_bytes(),
            private_key: leaf_key.serialize_pem().into_bytes(),
        })
    }
}

#[async_trait]
impl CertificateProvider for LocalCaCertProvider {
    async fn get_certificate(
        &self,
        unique_identifier: &str,
        alt_names: Option<String>,
        ttl: Option<String>,
    ) -> Result<Certificate, SecretsError> {
        self.issue(unique_identifier, alt_names, ttl)
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::*;

    use super::*;

    fn test_ca() -> LocalCaMaterial {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "test-ca");
        let cert = params.self_signed(&key).expect("self-signed ca");
        LocalCaMaterial {
            ca_cert_pem: cert.pem(),
            ca_key_pem: key.serialize_pem(),
        }
    }

    fn spiffe() -> SpiffeIdentity {
        SpiffeIdentity {
            trust_domain: "nico.local".to_string(),
            machine_base_path: "/forge-system/machine/".to_string(),
        }
    }

    fn issue(id: &str, alt_names: Option<&str>, ttl: Option<&str>) -> Certificate {
        let provider = LocalCaCertProvider::from_pem(&test_ca(), spiffe()).expect("build provider");
        provider
            .issue(id, alt_names.map(str::to_string), ttl.map(str::to_string))
            .expect("issue cert")
    }

    #[test]
    fn issued_cert_embeds_spiffe_uri_and_dns_sans() {
        let cert = issue("machine-123", Some("a.example, b.example"), Some("2h"));

        let pem = parse_x509_pem(&cert.public_key).expect("parse leaf pem").1;
        let leaf = parse_x509_certificate(&pem.contents)
            .expect("parse leaf der")
            .1;

        let san = leaf
            .subject_alternative_name()
            .expect("san ext")
            .expect("san present");
        let uris: Vec<&str> = san
            .value
            .general_names
            .iter()
            .filter_map(|n| match n {
                GeneralName::URI(uri) => Some(*uri),
                _ => None,
            })
            .collect();
        let dns: Vec<&str> = san
            .value
            .general_names
            .iter()
            .filter_map(|n| match n {
                GeneralName::DNSName(dns) => Some(*dns),
                _ => None,
            })
            .collect();

        assert_eq!(
            uris,
            vec!["spiffe://nico.local/forge-system/machine/machine-123"]
        );
        assert_eq!(dns, vec!["a.example", "b.example"]);
    }

    #[test]
    fn issuing_ca_matches_configured_ca() {
        let ca = test_ca();
        let provider = LocalCaCertProvider::from_pem(&ca, spiffe()).expect("build provider");
        let cert = provider.issue("m", None, None).expect("issue");
        assert_eq!(cert.issuing_ca, ca.ca_cert_pem.into_bytes());
        assert!(
            String::from_utf8(cert.private_key)
                .unwrap()
                .contains("PRIVATE KEY")
        );
    }

    #[test]
    fn explicit_ttl_sets_validity_window() {
        let cert = issue("m", None, Some("2h"));
        let pem = parse_x509_pem(&cert.public_key).unwrap().1;
        let leaf = parse_x509_certificate(&pem.contents).unwrap().1;

        let not_before = leaf.validity().not_before.timestamp();
        let not_after = leaf.validity().not_after.timestamp();
        let lifetime = not_after - not_before;
        // 2h window plus the 5-minute backdate.
        assert_eq!(lifetime, 2 * 3600 + 5 * 60);
    }

    #[test]
    fn malformed_ca_material_is_rejected() {
        let material = LocalCaMaterial {
            ca_cert_pem: "not a pem".to_string(),
            ca_key_pem: "also not a pem".to_string(),
        };
        assert!(LocalCaCertProvider::from_pem(&material, spiffe()).is_err());
    }

    #[test]
    fn mismatched_key_and_cert_rejected() {
        let valid = test_ca();
        let other_key = KeyPair::generate().expect("other key");
        let material = LocalCaMaterial {
            ca_cert_pem: valid.ca_cert_pem,
            ca_key_pem: other_key.serialize_pem(),
        };
        assert!(LocalCaCertProvider::from_pem(&material, spiffe()).is_err());
    }

    #[test]
    fn invalid_dns_san_is_rejected() {
        let provider = LocalCaCertProvider::from_pem(&test_ca(), spiffe()).unwrap();
        assert!(
            provider
                .issue("m", Some("bad name".to_string()), None)
                .is_err()
        );
    }
}
