# Status — #355 node-auth JWT design + prototype

Working notes (not for commit). Design doc: `docs/design/machine-identity/node-auth-jwt.md`.

## Branches

- **`node-auth-355-simple` (current, off `main`)** — the variant Bill picked
  2026-07-14: nodes self-sign JWTs with their **existing mTLS client-cert
  key**; cert chain in `x5c`; server verifies against the client-cert root CA.
  No machine-identity code, no server key, no refresh RPC.
- `node-auth-355-design` / `agent-jwt` (off older main) — earlier
  server-issued variant (site ES256 key in credential store, RefreshNodeToken,
  DPU device-identity anchor). Kept as reference; superseded for now.

## State (node-auth-355-simple)

- [x] Design doc rewritten for the self-signed variant
- [x] Client: `NodeJwtMinter` + `BearerAuthService` in `crates/rpc/src/node_jwt.rs`; wired in scout + dpu-agent via `with_node_jwt()`
- [x] Server: `NodeJwtValidator` (x5c chain → sig → claims → SPIFFE SAN) in `crates/api-core/src/node_auth.rs`
- [x] Middleware bearer support + machine-cert gate (ported from previous branch; identical tests)
- [x] `[node_auth]` config: `enabled=false`, `mtls_enabled=true`, `audience`, `max_token_ttl_sec` + lockout validation
- [x] Tests: 4 minter (incl. SEC1 key path), 4 validator (round trip, untrusted CA, no-chain, overlong lifetime), middleware suite (31), config lockout
- [ ] End-to-end test in `crates/api-integration-tests` (needs real Postgres + binary)
- [ ] Live verification against a running localdev stack

## Questions that arose, and the answer taken

| # | Question | Answer chosen | Basis |
| - | --- | --- | --- |
| 1 | Which "existing private key"? | Node's mTLS client-cert key (user confirmed via question; recommended option) | Zero new key material; trust rides existing PKI |
| 2 | How does the server get the public key? | `x5c` header verified against `[tls] root_cafile_path` via rustls `WebPkiClientVerifier` | RFC 7515; same roots as the TLS listener → no second trust store |
| 3 | Key type / JWT alg? | ES256 only — Vault PKI role is `key_type=ec, key_bits=256` (helm-prereqs vault-config-job) | Pin the algorithm; reject non-EC leaves |
| 4 | Vault returns SEC1 EC key PEM; jsonwebtoken only takes PKCS#8 | Minter re-encodes SEC1→PKCS#8 via p256 when the PEM tag is `EC PRIVATE KEY`; unit-tested | jsonwebtoken 10.4 `as_ec_private_key` is PKCS8-only (verified in source) |
| 5 | Client-side config knob? | None — scout/agent always mint; server ignores the header when `[node_auth] enabled=false` (existing middleware test proves it) | One switch in the API config, per requirement 3 |
| 6 | Can the client stretch `exp`? | Server enforces `exp-iat` and `exp-now` ≤ `max_token_ttl_sec` (900 s default); `iat` is a required claim | Client-minted tokens need a server-side lifetime bound |
| 7 | Trust `sub` claim? | No — identity from the verified cert SAN; `sub` only cross-checked (mismatch = reject) | Never derive identity from attacker-controlled claims |
| 8 | Replay protection (`jti`)? | Not in prototype — 5-min TTL over TLS to a single audience; noted DPoP/nonce as hardening path | Proportionate: same exposure window as a resumed TLS session |
| 9 | Disable mTLS = disable cert issuance? | No — JWTs are signed by the cert key, so issuance/renewal must continue even with transport mTLS off | Design doc Q4/Q5 |

## PLC security scan (advisory, this work unit)

| Check | Status | Note |
| - | - | - |
| SAST (Semgrep, Rust rules) | PASS | 0 findings on changed files vs main |
| Secrets (Pulse) | SKIP | registry access denied — `docker login gitlab-master.nvidia.com:5005` not configured; run before PR |
| Dependencies (osv-scanner 2.3.5) | PASS | Cargo.lock: 13 advisories, **0 new** — all pre-existing on main (jsonwebtoken/p256 were already workspace deps) |
| License | N/A | no new external dependencies |
| Container | N/A | no container files changed |
| Security review (inline) | PASS | chain-verify-before-key-use order, ES256 pinning (header + Validation), exp/iat/aud + bounded lifetime, identity from verified cert SAN (`sub` cross-check only), redacting Debug on token cache, bearer only over TLS |

Telemetry gap: `scripts/aplc.sh` does not exist in this repo, so skill
invocation/completion events could not be published (recorded here instead).

## Follow-ups

- Integration test: enable `[node_auth]` in the test harness config, drive
  scout → API with bearer over TLS, then with `mtls_enabled=false`.
- Consider surfacing per-request auth-method metrics (bearer vs cert) for
  cutover monitoring.
- Decide fate of the server-issued branches once this lands.
