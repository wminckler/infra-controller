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

//! Client-side node-auth bearer token plumbing (issue NVIDIA/infra-controller#355).
//!
//! [`NodeTokenSource`] is a thread-safe, mutable holder for the current
//! node-auth JWT that Scout / DPU-agent present to the API. A background
//! refresher updates it via `set` while in-flight requests read it via `get`.
//! [`BearerAuthService`] is a tower middleware that stamps the current token
//! onto each outgoing request's `Authorization` header.

use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};

use tower::Service;

/// Holds the current node-auth bearer token, shared between the gRPC client
/// (reader) and the token refresher (writer). `None` means "no token yet";
/// in that case [`BearerAuthService`] adds no header and the client falls back
/// to whatever other credential (e.g. mTLS cert) the channel carries.
#[derive(Debug, Default)]
pub struct NodeTokenSource {
    token: RwLock<Option<String>>,
}

impl NodeTokenSource {
    /// Creates a source seeded with an optional initial token.
    #[must_use]
    pub fn new(initial: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            token: RwLock::new(initial),
        })
    }

    /// Replaces the current token (called by the refresher).
    pub fn set(&self, token: String) {
        if let Ok(mut guard) = self.token.write() {
            *guard = Some(token);
        }
    }

    /// Returns the current token, if any.
    #[must_use]
    pub fn get(&self) -> Option<String> {
        self.token.read().ok().and_then(|guard| guard.clone())
    }
}

/// Tower middleware that injects `Authorization: Bearer <token>` onto each
/// request when [`NodeTokenSource`] holds a token. A `None` source is a no-op,
/// so the same client construction path serves both token and mTLS-only modes.
#[derive(Clone)]
pub struct BearerAuthService<S> {
    inner: S,
    source: Option<Arc<NodeTokenSource>>,
}

impl<S> BearerAuthService<S> {
    pub fn new(inner: S, source: Option<Arc<NodeTokenSource>>) -> Self {
        Self { inner, source }
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
        // Log which credential each outgoing request presents (issue #355), so
        // an operator can confirm a node is on bearer-token auth vs. falling
        // back to its mTLS client cert. Per-request, so kept at debug.
        let rpc = req.uri().path().to_string();
        match self
            .source
            .as_ref()
            .and_then(|source| source.get())
            .and_then(|token| hyper::http::HeaderValue::from_str(&format!("Bearer {token}")).ok())
        {
            Some(value) => {
                tracing::debug!(
                    rpc = %rpc,
                    "node-auth: presenting bearer token (mTLS client cert also on channel)"
                );
                req.headers_mut()
                    .insert(hyper::header::AUTHORIZATION, value);
            }
            None => {
                tracing::debug!(
                    rpc = %rpc,
                    "node-auth: no bearer token; authenticating with mTLS client cert only"
                );
            }
        }
        self.inner.call(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_round_trips_token() {
        let source = NodeTokenSource::new(None);
        assert_eq!(source.get(), None);
        source.set("abc.def.ghi".to_string());
        assert_eq!(source.get().as_deref(), Some("abc.def.ghi"));
        source.set("new.token".to_string());
        assert_eq!(source.get().as_deref(), Some("new.token"));
    }

    #[test]
    fn source_seeded_with_initial_token() {
        let source = NodeTokenSource::new(Some("seed".to_string()));
        assert_eq!(source.get().as_deref(), Some("seed"));
    }
}
