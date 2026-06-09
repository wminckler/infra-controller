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

//! Node-auth: short-lived ES256 JWTs issued to Scout / DPU-agent as a
//! replacement for Vault-issued mTLS client certs (issue NVIDIA/infra-controller#355).
//!
//! [`NodeTokenService`] both **issues** tokens (used by the discovery /
//! attestation / refresh handlers) and **validates** them as a
//! [`BearerTokenAuthenticator`] in the authn middleware. The token subject is
//! the machine's SPIFFE URI built from the SAME trust-domain / machine base
//! path as the mTLS cert path, so a JWT and a cert for the same machine map to
//! an identical [`SpiffeMachineIdentifier`](carbide_authn::middleware::Principal)
//! principal and reuse the existing RBAC unchanged.

use std::sync::Arc;

use carbide_authn::middleware::BearerTokenAuthenticator;
use carbide_secrets::credentials::{CredentialKey, CredentialManager, Credentials};
use carbide_secrets::key_encryption::generate_es256_key_pair;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use p256::SecretKey;
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
use serde::Deserialize;

use crate::cfg::file::NodeAuthConfig;
use crate::machine_identity::{Es256Signer, SignOptions, Signer};

/// Stable key id for the (singleton) node-auth signing key. The key itself is
/// shared across replicas via the credential store; this label only annotates
/// the JWT `kid` header.
const NODE_AUTH_KID: &str = "node-auth-1";

#[derive(Debug, thiserror::Error)]
pub enum NodeAuthError {
    #[error("credential store error: {0}")]
    Secrets(String),
    #[error("signing key generation failed: {0}")]
    KeyGen(String),
    #[error("stored node-auth signing key is malformed: {0}")]
    MalformedKey(String),
    #[error("token signing failed: {0}")]
    Sign(String),
}

/// Minimal claims for validation; registered claims (`exp`/`iss`/`aud`) are
/// enforced by `jsonwebtoken` via [`Validation`], so only `sub` is read out.
#[derive(Debug, Deserialize)]
struct NodeClaims {
    sub: String,
}

/// Issues and validates node-auth JWTs using a single site-level ES256 key.
pub struct NodeTokenService {
    signer: Es256Signer,
    decoding_key: DecodingKey,
    trust_domain: String,
    machine_base_path: String,
    issuer: String,
    audience: String,
    token_ttl_sec: u32,
}

impl NodeTokenService {
    /// Loads the site-level signing key from the credential store, generating
    /// and persisting one on first use. Safe to call concurrently from multiple
    /// replicas: a lost create race falls back to re-reading the winner's key.
    pub async fn load_or_create(
        credential_manager: &dyn CredentialManager,
        trust_domain: String,
        machine_base_path: String,
        cfg: &NodeAuthConfig,
    ) -> Result<Self, NodeAuthError> {
        let key = CredentialKey::NodeAuthSigningKey;
        let existing = credential_manager
            .get_credentials(&key)
            .await
            .map_err(|e| NodeAuthError::Secrets(e.to_string()))?;
        let (kid, private_pem) = match existing {
            Some(Credentials::UsernamePassword { username, password }) => (username, password),
            None => {
                let (private_pem_bytes, _public_pem) =
                    generate_es256_key_pair().map_err(|e| NodeAuthError::KeyGen(e.to_string()))?;
                let private_pem = String::from_utf8(private_pem_bytes)
                    .map_err(|e| NodeAuthError::KeyGen(e.to_string()))?;
                let creds = Credentials::UsernamePassword {
                    username: NODE_AUTH_KID.to_string(),
                    password: private_pem.clone(),
                };
                match credential_manager.create_credentials(&key, &creds).await {
                    Ok(()) => (NODE_AUTH_KID.to_string(), private_pem),
                    // Another replica created the key first; re-read it.
                    Err(_) => match credential_manager
                        .get_credentials(&key)
                        .await
                        .map_err(|e| NodeAuthError::Secrets(e.to_string()))?
                    {
                        Some(Credentials::UsernamePassword { username, password }) => {
                            (username, password)
                        }
                        None => {
                            return Err(NodeAuthError::MalformedKey(
                                "node-auth signing key missing after create race".into(),
                            ));
                        }
                    },
                }
            }
        };

        // Derive the SPKI public PEM from the stored private key for verification.
        let secret_key = SecretKey::from_pkcs8_pem(&private_pem)
            .map_err(|e| NodeAuthError::MalformedKey(e.to_string()))?;
        let public_pem = secret_key
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| NodeAuthError::MalformedKey(e.to_string()))?;
        let decoding_key = DecodingKey::from_ec_pem(public_pem.as_bytes())
            .map_err(|e| NodeAuthError::MalformedKey(e.to_string()))?;
        let signer = Es256Signer::new(private_pem.as_bytes(), &kid)
            .map_err(|e| NodeAuthError::MalformedKey(e.to_string()))?;

        Ok(Self {
            signer,
            decoding_key,
            trust_domain,
            machine_base_path,
            issuer: cfg.issuer.clone(),
            audience: cfg.audience.clone(),
            token_ttl_sec: cfg.token_ttl_sec,
        })
    }

    /// Issues a short-lived JWT whose subject is `machine_id`'s SPIFFE URI.
    pub fn issue(&self, machine_id: &str) -> Result<::rpc::forge::NodeToken, NodeAuthError> {
        let sub = machine_spiffe_uri(&self.trust_domain, &self.machine_base_path, machine_id);
        let now = Utc::now().timestamp();
        let exp = now + i64::from(self.token_ttl_sec);
        let payload = serde_json::json!({
            "sub": sub,
            "iss": self.issuer,
            "aud": self.audience,
            "iat": now,
            "nbf": now,
            "exp": exp,
        });
        let access_token = self
            .signer
            .sign(&payload, &SignOptions::default())
            .map_err(|e| NodeAuthError::Sign(e.to_string()))?;
        Ok(::rpc::forge::NodeToken {
            access_token,
            expires_in_sec: self.token_ttl_sec,
        })
    }

    fn validation(&self) -> Validation {
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation
    }
}

impl BearerTokenAuthenticator for NodeTokenService {
    fn spiffe_id_from_bearer(&self, token: &str) -> Option<String> {
        match decode::<NodeClaims>(token, &self.decoding_key, &self.validation()) {
            Ok(data) => Some(data.claims.sub),
            Err(e) => {
                tracing::debug!("node-auth JWT validation failed: {e}");
                None
            }
        }
    }
}

/// Issues a node-auth token for `machine_id` if node-auth is enabled. Returns
/// `None` (logging any signing error) when the service is absent or signing
/// fails, so callers can treat the token as a best-effort, additive field.
pub fn issue_node_token(
    service: &Option<Arc<NodeTokenService>>,
    machine_id: &str,
) -> Option<::rpc::forge::NodeToken> {
    let svc = service.as_ref()?;
    match svc.issue(machine_id) {
        Ok(token) => Some(token),
        Err(e) => {
            tracing::error!("failed to issue node-auth token for {machine_id}: {e}");
            None
        }
    }
}

/// Builds the machine SPIFFE URI, matching the historical mTLS cert path
/// (`carbide_secrets::forge_vault::machine_spiffe_uri`) so tokens and certs are
/// interchangeable under the same `SpiffeContext`.
fn machine_spiffe_uri(trust_domain: &str, machine_base_path: &str, machine_id: &str) -> String {
    let base = machine_base_path.trim().trim_matches('/');
    if base.is_empty() {
        format!("spiffe://{trust_domain}/{machine_id}")
    } else {
        format!("spiffe://{trust_domain}/{base}/{machine_id}")
    }
}

#[cfg(test)]
mod tests {
    use carbide_secrets::MemoryCredentialStore;

    use super::*;

    fn test_cfg() -> NodeAuthConfig {
        NodeAuthConfig {
            enabled: true,
            issuer: "carbide-api".to_string(),
            audience: "carbide-api".to_string(),
            token_ttl_sec: 3600,
        }
    }

    async fn service() -> NodeTokenService {
        let store = MemoryCredentialStore::default();
        NodeTokenService::load_or_create(
            &store,
            "forge.local".to_string(),
            "/forge-system/machine/".to_string(),
            &test_cfg(),
        )
        .await
        .expect("build node token service")
    }

    #[test]
    fn machine_spiffe_uri_matches_cert_path_format() {
        assert_eq!(
            machine_spiffe_uri("forge.local", "/forge-system/machine/", "abc-123"),
            "spiffe://forge.local/forge-system/machine/abc-123"
        );
        assert_eq!(
            machine_spiffe_uri("forge.local", "", "abc-123"),
            "spiffe://forge.local/abc-123"
        );
    }

    #[tokio::test]
    async fn issued_token_round_trips_to_its_subject() {
        let svc = service().await;
        let token = svc.issue("machine-xyz").expect("issue");
        assert_eq!(token.expires_in_sec, 3600);
        let sub = svc
            .spiffe_id_from_bearer(&token.access_token)
            .expect("valid token");
        assert_eq!(sub, "spiffe://forge.local/forge-system/machine/machine-xyz");
    }

    #[tokio::test]
    async fn garbage_and_wrong_audience_tokens_are_rejected() {
        // Share one credential store so both services sign with the same key;
        // that way the token's signature verifies and rejection is driven by the
        // audience mismatch, not an incidental signing-key difference.
        let store = MemoryCredentialStore::default();
        let svc = NodeTokenService::load_or_create(
            &store,
            "forge.local".to_string(),
            "/forge-system/machine/".to_string(),
            &test_cfg(),
        )
        .await
        .expect("build svc");

        assert!(svc.spiffe_id_from_bearer("not.a.jwt").is_none());

        // A token minted for a different audience must not validate, even though
        // it is signed with the same key svc trusts.
        let other = NodeAuthConfig {
            audience: "someone-else".to_string(),
            ..test_cfg()
        };
        let other_svc = NodeTokenService::load_or_create(
            &store,
            "forge.local".to_string(),
            "/forge-system/machine/".to_string(),
            &other,
        )
        .await
        .expect("build other_svc");
        let token = other_svc.issue("machine-xyz").expect("issue");
        assert!(svc.spiffe_id_from_bearer(&token.access_token).is_none());
    }

    #[tokio::test]
    async fn key_is_persisted_and_reused_across_instances() {
        let store = MemoryCredentialStore::default();
        let svc1 = NodeTokenService::load_or_create(
            &store,
            "forge.local".to_string(),
            "/forge-system/machine/".to_string(),
            &test_cfg(),
        )
        .await
        .expect("build 1");
        let token = svc1.issue("m1").expect("issue");

        // A second instance loading the same store must validate svc1's token.
        let svc2 = NodeTokenService::load_or_create(
            &store,
            "forge.local".to_string(),
            "/forge-system/machine/".to_string(),
            &test_cfg(),
        )
        .await
        .expect("build 2");
        assert_eq!(
            svc2.spiffe_id_from_bearer(&token.access_token).as_deref(),
            Some("spiffe://forge.local/forge-system/machine/m1")
        );
    }
}
