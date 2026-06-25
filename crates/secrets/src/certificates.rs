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
use async_trait::async_trait;
use rand::RngExt;

use crate::SecretsError;

#[derive(Debug, Clone, Default)]
pub struct Certificate {
    pub issuing_ca: Vec<u8>,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[async_trait]
pub trait CertificateProvider: Send + Sync {
    async fn get_certificate(
        &self,
        unique_identifier: &str,
        alt_names: Option<String>,
        ttl: Option<String>,
    ) -> Result<Certificate, SecretsError>;
}

/// Default certificate lifetime in hours, randomly skewed to 60–100% of 30 days
/// so that a fleet of machines does not all renew (or expire) at the same time.
/// Shared by every [`CertificateProvider`] so issued certs behave identically
/// regardless of backend.
pub fn skewed_default_ttl_hours() -> u64 {
    const MAX_HOURS: u64 = 720; // 24 * 30
    const MIN_HOURS: u64 = 432; // 24 * 30 * 0.6
    rand::rng().random_range(MIN_HOURS..MAX_HOURS)
}

/// Parse a Vault-style duration string into whole seconds. Accepts a trailing
/// unit of `s`, `m`, `h`, or `d`; a bare number is treated as seconds (matching
/// Vault). Used by backends that sign locally and therefore need a concrete
/// duration rather than passing the string through to Vault.
pub fn parse_ttl_seconds(ttl: &str) -> Result<u64, SecretsError> {
    let ttl = ttl.trim();
    if ttl.is_empty() {
        return Err(eyre::eyre!("certificate TTL must not be empty").into());
    }

    let (number, multiplier) = match ttl.strip_suffix(['s', 'S']) {
        Some(rest) => (rest, 1u64),
        None => match ttl.strip_suffix(['m', 'M']) {
            Some(rest) => (rest, 60),
            None => match ttl.strip_suffix(['h', 'H']) {
                Some(rest) => (rest, 3600),
                None => match ttl.strip_suffix(['d', 'D']) {
                    Some(rest) => (rest, 86_400),
                    // Bare number: Vault interprets a unit-less TTL as seconds.
                    None => (ttl, 1),
                },
            },
        },
    };

    let value: u64 = number
        .trim()
        .parse()
        .map_err(|_| SecretsError::from(eyre::eyre!("invalid certificate TTL: {ttl:?}")))?;

    value
        .checked_mul(multiplier)
        .ok_or_else(|| SecretsError::from(eyre::eyre!("certificate TTL overflows: {ttl:?}")))
}
