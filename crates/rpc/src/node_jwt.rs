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

//! Client-side node-auth JWT minting (issue NVIDIA/infra-controller#355).
//!
//! The node self-signs short-lived ES256 JWTs with the private key of its
//! EXISTING mTLS client certificate; the certificate chain rides along in the
//! token's `x5c` header (RFC 7515 §4.1.6) so the API can verify it against the
//! same root CA its TLS listener already trusts. No new key material, no key
//! storage, and no refresh RPC: a fresh token is minted locally whenever the
//! cached one nears expiry, and key "rotation" happens for free when the
//! client certificate renews.
//!
//! [`BearerAuthService`] is the tower middleware that stamps the current token
//! onto each outgoing request's `Authorization` header. Minting is best-effort:
//! if the cert/key files are missing or unreadable (e.g. before first
//! registration), requests simply carry no bearer header and the channel's
//! mTLS client cert remains the only credential.

use std::io::Cursor;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE64;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use serde::Serialize;
use tower::Service;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

/// `aud` claim stamped on minted tokens; must match the API's
/// `[node_auth] audience`.
pub const NODE_JWT_AUDIENCE: &str = "nico-api";

/// Lifetime of minted tokens. Deliberately short: tokens cost nothing to
/// re-mint locally, so a leaked one ages out in minutes.
pub const NODE_JWT_TTL_SECS: u64 = 300;

/// A cached token is reused until it has less than this long left, then
/// re-minted. Comfortably above per-request latency, comfortably below TTL.
const REMINT_MARGIN_SECS: u64 = 60;

#[derive(Debug, thiserror::Error)]
pub enum NodeJwtError {
    #[error("could not read client certificate or key: {0}")]
    Io(#[from] std::io::Error),
    #[error("client certificate file contains no parsable certificate")]
    NoCertificate,
    #[error("client certificate is not usable for node JWTs: {0}")]
    BadCertificate(String),
    #[error("client private key is not a usable EC key: {0}")]
    BadKey(String),
    #[error("JWT signing failed: {0}")]
    Sign(#[from] jsonwebtoken::errors::Error),
    #[error("system clock is before the UNIX epoch")]
    Clock,
}

#[derive(Clone)]
struct CachedToken {
    token: String,
    expires_at: u64,
}

/// Mints and caches node-auth JWTs from the node's existing mTLS client
/// certificate and private key files.
///
/// Cert and key are re-read from disk on every mint, so certificate renewal
/// (which rewrites both files in place) is picked up automatically on the
/// next re-mint without any coordination.
pub struct NodeJwtMinter {
    cert_path: String,
    key_path: String,
    cached: RwLock<Option<CachedToken>>,
}

/// Manual impl so the cached token (a live credential) never lands in debug
/// output of the client config.
impl std::fmt::Debug for NodeJwtMinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeJwtMinter")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .finish_non_exhaustive()
    }
}

/// Claims carried by a node-auth JWT. `sub` duplicates the certificate's
/// SPIFFE URI SAN; the server derives identity from the *verified certificate*
/// and only cross-checks `sub` against it, so a forged `sub` buys nothing.
#[derive(Debug, Serialize)]
struct NodeClaims<'a> {
    sub: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

impl NodeJwtMinter {
    #[must_use]
    pub fn new(cert_path: String, key_path: String) -> Arc<Self> {
        Arc::new(Self {
            cert_path,
            key_path,
            cached: RwLock::new(None),
        })
    }

    /// Returns a currently-valid token, re-minting if the cached one is
    /// missing or close to expiry. Returns `None` (and logs at debug) when
    /// minting is impossible — e.g. the cert/key files don't exist yet — so
    /// callers degrade gracefully to mTLS-only.
    pub fn current(&self) -> Option<String> {
        let now = unix_now().ok()?;
        if let Ok(guard) = self.cached.read()
            && let Some(cached) = guard.as_ref()
            && cached.expires_at > now + REMINT_MARGIN_SECS
        {
            return Some(cached.token.clone());
        }
        match self.mint(now) {
            Ok(minted) => {
                let token = minted.token.clone();
                if let Ok(mut guard) = self.cached.write() {
                    *guard = Some(minted);
                }
                Some(token)
            }
            Err(error) => {
                tracing::debug!(
                    cert_path = %self.cert_path,
                    %error,
                    "node-auth: could not mint node JWT; continuing with mTLS only"
                );
                None
            }
        }
    }

    fn mint(&self, now: u64) -> Result<CachedToken, NodeJwtError> {
        let cert_pem = std::fs::read(&self.cert_path)?;
        let key_pem = std::fs::read_to_string(&self.key_path)?;

        let chain = rustls_pemfile::certs(&mut Cursor::new(&cert_pem[..]))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| NodeJwtError::BadCertificate(e.to_string()))?;
        let leaf = chain.first().ok_or(NodeJwtError::NoCertificate)?;
        let sub = spiffe_uri_from_cert(leaf.as_ref())?;

        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("JWT".to_string());
        header.x5c = Some(chain.iter().map(|c| BASE64.encode(c.as_ref())).collect());

        let expires_at = now + NODE_JWT_TTL_SECS;
        let claims = NodeClaims {
            sub: &sub,
            aud: NODE_JWT_AUDIENCE,
            iat: now,
            exp: expires_at,
        };
        let token = jsonwebtoken::encode(&header, &claims, &ec_encoding_key(&key_pem)?)?;
        Ok(CachedToken { token, expires_at })
    }
}

fn unix_now() -> Result<u64, NodeJwtError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| NodeJwtError::Clock)
}

/// Extracts the single SPIFFE URI SAN from the certificate — the same field
/// the server's authn layer maps to a machine principal for mTLS.
fn spiffe_uri_from_cert(der: &[u8]) -> Result<String, NodeJwtError> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| NodeJwtError::BadCertificate(format!("X.509 parse error: {e}")))?;
    let san = cert
        .subject_alternative_name()
        .map_err(|e| NodeJwtError::BadCertificate(format!("bad SAN extension: {e}")))?
        .ok_or_else(|| NodeJwtError::BadCertificate("no SAN extension".to_string()))?;
    san.value
        .general_names
        .iter()
        .find_map(|name| match name {
            GeneralName::URI(uri) if uri.starts_with("spiffe://") => Some(uri.to_string()),
            _ => None,
        })
        .ok_or_else(|| NodeJwtError::BadCertificate("no SPIFFE URI SAN".to_string()))
}

/// Builds an ES256 signing key from the client key PEM. Vault-issued machine
/// keys are SEC1 (`BEGIN EC PRIVATE KEY`), which `jsonwebtoken` cannot load
/// directly, so those are re-encoded to PKCS#8 first.
fn ec_encoding_key(key_pem: &str) -> Result<EncodingKey, NodeJwtError> {
    if key_pem.contains("BEGIN EC PRIVATE KEY") {
        let secret = p256::SecretKey::from_sec1_pem(key_pem)
            .map_err(|e| NodeJwtError::BadKey(e.to_string()))?;
        let pkcs8 = secret
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| NodeJwtError::BadKey(e.to_string()))?;
        EncodingKey::from_ec_pem(pkcs8.as_bytes()).map_err(NodeJwtError::Sign)
    } else {
        EncodingKey::from_ec_pem(key_pem.as_bytes()).map_err(NodeJwtError::Sign)
    }
}

/// Tower middleware that injects `Authorization: Bearer <jwt>` onto each
/// request when a [`NodeJwtMinter`] is configured. A `None` minter is a no-op,
/// so the same client construction path serves both token and mTLS-only modes.
#[derive(Clone)]
pub struct BearerAuthService<S> {
    inner: S,
    minter: Option<Arc<NodeJwtMinter>>,
}

impl<S> BearerAuthService<S> {
    pub fn new(inner: S, minter: Option<Arc<NodeJwtMinter>>) -> Self {
        Self { inner, minter }
    }
}

impl<S, B> Service<hyper::Request<B>> for BearerAuthService<S>
where
    S: Service<hyper::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: hyper::Request<B>) -> Self::Future {
        if let Some(value) = self
            .minter
            .as_ref()
            .and_then(|minter| minter.current())
            .and_then(|token| hyper::http::HeaderValue::from_str(&format!("Bearer {token}")).ok())
        {
            req.headers_mut()
                .insert(hyper::header::AUTHORIZATION, value);
        }
        self.inner.call(req)
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{DecodingKey, Validation};
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    struct Claims {
        sub: String,
        exp: u64,
        iat: u64,
    }

    const SPIFFE_URI: &str = "spiffe://forge.local/forge-system/machine/fm100xtest";

    /// Self-signed leaf with a SPIFFE URI SAN plus its PKCS#8 key PEM —
    /// stand-ins for the Vault-issued client cert/key pair on a node.
    fn cert_and_key() -> (String, String) {
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(SPIFFE_URI.to_string()).expect("uri"),
        )];
        let key = rcgen::KeyPair::generate().expect("key pair");
        let cert = params.self_signed(&key).expect("certificate");
        (cert.pem(), key.serialize_pem())
    }

    fn write_temp(dir: &tempfile::TempDir, name: &str, contents: &str) -> String {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).expect("write");
        path.to_string_lossy().into_owned()
    }

    fn decode_against_own_cert(token: &str) -> Claims {
        // Validate exactly as the server does: pull the leaf from x5c, take
        // its SPKI EC point, verify the signature with it.
        let header = jsonwebtoken::decode_header(token).expect("header");
        assert_eq!(header.alg, Algorithm::ES256);
        let chain = header.x5c_der().expect("x5c decodes").expect("x5c present");
        let (_, cert) = X509Certificate::from_der(&chain[0]).expect("leaf parses");
        let decoding_key = DecodingKey::from_ec_der(&cert.public_key().subject_public_key.data);
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&[NODE_JWT_AUDIENCE]);
        jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)
            .expect("token validates")
            .claims
    }

    #[test]
    fn mints_a_token_signed_by_the_client_cert_key() {
        let (cert_pem, key_pem) = cert_and_key();
        let dir = tempfile::tempdir().expect("tempdir");
        let minter = NodeJwtMinter::new(
            write_temp(&dir, "cert.pem", &cert_pem),
            write_temp(&dir, "key.pem", &key_pem),
        );

        let token = minter.current().expect("token minted");
        let claims = decode_against_own_cert(&token);
        assert_eq!(claims.sub, SPIFFE_URI);
        assert_eq!(claims.exp - claims.iat, NODE_JWT_TTL_SECS);
    }

    #[test]
    fn sec1_key_pem_is_accepted() {
        // Vault PKI hands out SEC1-encoded EC keys; re-encode the test key the
        // same way and make sure minting still works.
        use p256::pkcs8::DecodePrivateKey;
        let (cert_pem, key_pem) = cert_and_key();
        let secret = p256::SecretKey::from_pkcs8_pem(&key_pem).expect("pkcs8 parses");
        let sec1_pem = secret
            .to_sec1_pem(LineEnding::LF)
            .expect("sec1 encodes")
            .to_string();
        assert!(sec1_pem.contains("BEGIN EC PRIVATE KEY"));

        let dir = tempfile::tempdir().expect("tempdir");
        let minter = NodeJwtMinter::new(
            write_temp(&dir, "cert.pem", &cert_pem),
            write_temp(&dir, "key.pem", &sec1_pem),
        );
        let token = minter.current().expect("token minted from SEC1 key");
        assert_eq!(decode_against_own_cert(&token).sub, SPIFFE_URI);
    }

    #[test]
    fn token_is_cached_until_near_expiry() {
        let (cert_pem, key_pem) = cert_and_key();
        let dir = tempfile::tempdir().expect("tempdir");
        let minter = NodeJwtMinter::new(
            write_temp(&dir, "cert.pem", &cert_pem),
            write_temp(&dir, "key.pem", &key_pem),
        );
        let first = minter.current().expect("token");
        let second = minter.current().expect("token");
        assert_eq!(first, second, "fresh token must be served from cache");
    }

    #[test]
    fn missing_files_yield_none_not_panic() {
        let minter = NodeJwtMinter::new(
            "/nonexistent/cert.pem".to_string(),
            "/nonexistent/key.pem".to_string(),
        );
        assert!(minter.current().is_none());
    }
}
