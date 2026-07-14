# Node-Auth: Self-Signed Bearer JWTs for Scout and DPU-Agent

Design for [#355](https://github.com/NVIDIA/infra-controller/issues/355)
(sub-issue of the Vault-elimination epic
[#195](https://github.com/NVIDIA/infra-controller/issues/195)): Scout and the
DPU-agent authenticate to the API with short-lived bearer JWTs alongside —
and eventually instead of — mTLS client certificates.

This is the **simple variant**: nodes sign their own tokens with the private
key of their **existing** mTLS client certificate. There is no new key
material anywhere, no server-side signing key or key storage, no issuance or
refresh RPCs, and no dependency on the `machine_identity` (tenant JWT-SVID)
subsystem. An earlier, server-issued design (site-level signing key in the
credential store, `RefreshNodeToken` RPC, DPU device-identity refresh anchor)
lives on the `agent-jwt` / `node-auth-355-design` branches and remains the
fallback if per-node keys are ever removed.

It is distinct from the tenant-facing [SPIFFE JWT-SVID design](spiffe-svid-sdd.md):
that issues identity tokens *to tenant workloads* via IMDS; this design covers
how *NICo's own node agents* authenticate to the NICo API.

## How it works

```
node (scout / dpu-agent)                      nico-api
------------------------                      --------
has /opt/forge/machine_cert.pem  ── x5c ──►   1. verify x5c chain against the
and /opt/forge/machine_cert.key                  client-cert root CA (same roots
                                                 as the TLS listener)
mint ES256 JWT signed with the                2. verify JWT signature with the
cert's own key, 5-min TTL,                       verified leaf's public key
cert chain in the x5c header                  3. enforce exp / iat / aud, bounded
                                                 lifetime
attach as Authorization: Bearer               4. SPIFFE-validate the leaf; map its
on every gRPC request                            URI SAN through the same
                                                 SpiffeContext as mTLS certs
                                              ⇒ identical machine principal, RBAC
                                                 unchanged
```

## Auth flow: new DPU → first authorized gRPC call

**Provisioning & bootstrap (no credentials yet)**

- A new DPU is provisioned (BFB installed via DPF); the `forge-dpu-agent` DPF
  service starts on it with only two auth-relevant inputs from its config: the
  API endpoint and the root CA bundle (`forge_system.root_ca`). The cert/key
  files at `/opt/forge/machine_cert.pem` / `machine_cert.key` don't exist yet.
- The agent opens a TLS connection to `nico-api` that is **server-auth only**
  — it verifies the API's cert against the root CA but presents no client
  credential (the API listener uses `allow_unauthenticated()`, so the
  connection is accepted with an anonymous principal).

**First credential: the machine certificate**

- The agent calls `DiscoverMachine`
  (`host-support/registration.rs::register_machine`) carrying its hardware
  enumeration (`DiscoveryInfo`); this RPC is reachable pre-credential by
  design.
- The API registers/matches the machine and returns a `machine_certificate`
  in the response: a Vault-PKI-issued EC P-256 leaf whose SAN is the machine's
  SPIFFE URI (`spiffe://<trust-domain>/<ns>/machine/<machine-id>`), plus the
  issuing CA and private key. (On attestation-enabled sites, hosts get this
  via `AttestQuote` after a TPM challenge instead; DPUs take the discovery
  path.)
- `write_certs` persists leaf+issuing-CA to `/opt/forge/machine_cert.pem` and
  the key to `/opt/forge/machine_cert.key`. **This existing cert key is the
  JWT signing key — nothing else is ever created.**

**Minting the JWT (client side, `rpc::node_jwt`)**

- The agent's gRPC client was built with
  `ForgeClientConfig::new(root_ca, ClientCert{...}).with_node_jwt()`, so a
  `NodeJwtMinter` watches those two file paths.
- On the next outgoing RPC, the minter reads cert+key from disk (re-encoding
  Vault's SEC1 key PEM to PKCS#8) and signs an **ES256 JWT**: header
  `{alg: ES256, x5c: [leaf, issuing CA]}`, claims
  `{sub: <SPIFFE URI from its own cert SAN>, aud: "nico-api", iat: now,
  exp: now+300s}`. The token is cached and re-minted when < 60 s remain — no
  refresh RPC, and cert renewal is picked up automatically because the files
  are re-read at each mint.
- `BearerAuthService` stamps `Authorization: Bearer <jwt>` onto the request.
  (The TLS channel may still present the client cert too — dual-support; each
  is sufficient alone.)

**Validation (server side, requires `[node_auth] enabled = true` + TLS listener)**

- The authn middleware sees the Bearer header and hands it to
  `NodeJwtValidator`, which checks in order:
  - header `alg` is exactly ES256 (no algorithm substitution);
  - the `x5c` chain verifies against the **same root CA file the TLS listener
    uses for client certs** (`[tls] root_cafile_path`) — path building,
    validity window, client-auth EKU;
  - the JWT signature verifies with the *verified leaf's* public key;
  - claims: `exp`/`iat`/`aud` enforced, and lifetime bounded by
    `max_token_ttl_sec` (default 900 s) so a client can't stretch `exp`;
  - the leaf passes SPIFFE validation (leaf-only, single URI SAN), and `sub`
    must equal that SAN — identity comes from the verified cert, never from
    the claim.

**Authorization & the first call**

- The validated SPIFFE URI is mapped through the same `SpiffeContext` as mTLS
  certs → a `SpiffeMachineIdentifier` principal, byte-identical to what the
  cert path would have minted.
- Casbin RBAC evaluates that principal exactly as before (machine class →
  Agent/Scout role rules) — **no RBAC changes** — and the handler executes.
  That is the first authorized gRPC call on bearer auth.

Note: the very first *authorized* call after discovery could ride either
credential, since the agent holds both from the same moment — the JWT only
becomes load-bearing once `mtls_enabled = false`.

## Q1 — How does the agent get a private key that is trusted to create the JWT?

**It already has one.** The node's Vault-issued mTLS client certificate key
(`/opt/forge/machine_cert.key`, EC P-256 — Vault PKI role `key_type=ec,
key_bits=256`) signs the JWT, and the certificate itself rides along in the
token's `x5c` header (RFC 7515 §4.1.6). The key is trusted because the
certificate chains to the root CA the API already trusts for client certs —
the JWT is effectively "mTLS at the application layer".

Bootstrapping is unchanged: a machine obtains its first certificate through
the existing discovery/attestation flow (`DiscoverMachine` / `AttestQuote`
respond with the machine certificate — see the auth-flow walkthrough above),
and from that moment it can mint tokens. Minting is best-effort: before the
cert exists, requests simply carry no bearer header.

## Q2 — JWT side by side with mTLS

The authn middleware (`CertDescriptionMiddleware` in `crates/authn`) mints
principals from **both** sources on every request: the TLS-layer client cert,
and the `Authorization: Bearer` token (validated by `NodeJwtValidator`). Both
paths converge on the same SPIFFE URI → `SpiffeMachineIdentifier` mapping
through the same `SpiffeContext`, so RBAC (Casbin policy, role mapping) is
completely unchanged. A node presenting both credentials gets the same
principal twice — harmless. Clients attach the bearer token unconditionally
(`ForgeClientConfig::with_node_jwt()` in scout and dpu-agent); a server with
node-auth disabled ignores the header, so rollout order doesn't matter.

## Q3 — JWT off by default, configured in the API config

```toml
[node_auth]
enabled = false          # master switch for accepting bearer JWTs
audience = "nico-api"    # `aud` required on presented tokens
max_token_ttl_sec = 900  # upper bound on client-chosen lifetimes (cap 86400)
```

When `enabled = true`, startup requires a TLS listener (bearer tokens are
never accepted over plaintext) and a readable `[tls] root_cafile_path`;
missing prerequisites fail startup rather than silently degrading.

## Q4 — mTLS on by default, disableable in the API config

```toml
[node_auth]
mtls_enabled = true
```

When `mtls_enabled = false`, the middleware stops minting machine principals
from client certificates — bearer JWTs become the only node auth path. The
gate is scoped to **machine** certs: service and admin-CLI certs on the same
listener are unaffected. `enabled = false` + `mtls_enabled = false` is
rejected at startup (node lockout).

Note the trust chain is still the certificate PKI: disabling mTLS here
disables the *transport-layer* cert authentication, not cert issuance. Nodes
must keep renewing certificates because the JWT is signed by the cert key.

## Q5 — Key regeneration and public-key exchange

**Regeneration** is the existing client-certificate renewal: when
`ClientCertRenewer` rotates the cert/key files, the minter picks the new pair
up on its next re-mint (it re-reads both files from disk each time). No
coordination, no state.

**Public-key exchange: the x5c header.** Every token carries the certificate
chain that vouches for its signing key, and the API verifies that chain
against the root CA bundle it already holds (`[tls] root_cafile_path`). There
is no JWKS endpoint, no key registry, and no key distribution problem — CA
rotation is handled wherever the root bundle is handled today.

**Compromise response** is likewise the PKI's: a stolen key/cert pair is the
same incident as a stolen mTLS cert today. Tokens age out in minutes
(`exp - iat ≤ max_token_ttl_sec`, client mints 5-minute tokens); certificate
revocation/re-issue cuts off new token minting entirely.

## Q6 — JWT best-practice checklist

| Practice | How it's honored |
| --- | --- |
| Asymmetric signing, no `alg` confusion | ES256 only; both the header check and `Validation` pin the algorithm, so `none`/HS256 substitution is rejected. |
| Identity never comes from claims | The principal derives from the **chain-verified certificate's SPIFFE SAN**; `sub` is only cross-checked against it. A forged `sub` buys nothing. |
| Short-lived tokens | Clients mint 300 s tokens; the server enforces `exp - iat` and `exp - now` ≤ `max_token_ttl_sec` (default 900 s, hard cap 86400), so a client cannot stretch `exp`. |
| `exp` / `iat` / `aud` enforced | Required claims; validated by `jsonwebtoken` plus the bounded-lifetime check. |
| Chain validation, not pinning | `x5c` verified with rustls `WebPkiClientVerifier` (path building, validity window, client-auth EKU) against the same roots as the TLS listener. |
| SPIFFE leaf constraints | `carbide_authn::validate_x509_certificate` re-checks leaf-ness, key usage, and the single-URI-SAN rule — same code path as mTLS certs. |
| No bearer tokens over plaintext | Startup refuses `enabled = true` on a non-TLS listener; the middleware only installs the validator when the listener is TLS-terminated. |
| No key material at rest beyond the PKI | The server holds no signing key; the client holds only what it already had. Credentials never in logs (token cache has a redacting `Debug`). |

## Component map

| Piece | Where |
| --- | --- |
| Client mint + cache + header injection | `crates/rpc/src/node_jwt.rs` (`NodeJwtMinter`, `BearerAuthService`) |
| Client opt-in | `ForgeClientConfig::with_node_jwt()` (`crates/rpc/src/forge_tls_client.rs`); called in scout `client.rs` and dpu-agent `lib.rs` |
| Server validation | `crates/api-core/src/node_auth.rs` (`NodeJwtValidator`) |
| Config | `NodeAuthConfig` in `crates/api-core/src/cfg/file.rs`, `[node_auth]` section |
| Middleware hook | `BearerTokenAuthenticator` trait + machine-cert gate in `crates/authn/src/middleware.rs` |
| Wiring | `crates/api-core/src/setup.rs` (validation, validator construction), `listener.rs` (middleware install) |

## Design decisions (resolved questions)

1. **Agent-held key vs server-issued tokens** → agent-held: the user chose
   reusing the node's existing client-cert key. This removes the server-side
   key store, issuance RPCs, refresh anchoring, and HA key sharing that the
   server-issued design needed.
2. **How does the server learn the public key?** → from the token itself
   (`x5c`), verified against the existing root CA — the one key-distribution
   mechanism the system already operates.
3. **Why not drop mTLS immediately, since the JWT proves the same key?** →
   dual-support de-risks rollout and keeps requirement 4 orthogonal; and the
   JWT still depends on the cert PKI, so cert issuance must outlive transport
   mTLS.
4. **Client-side config knob?** → none. Nodes always mint when they hold a
   cert; a disabled server ignores the header (verified by middleware test).
   One switch (`[node_auth] enabled`) controls the feature.
5. **Replay window** → a captured token is replayable for ≤ 5 minutes against
   the same API over TLS only. Accepted for the prototype; `jti`/nonce
   tracking or DPoP-style proof-of-possession is the hardening path if needed.
6. **RSA machine certs** → not supported (Vault PKI role is EC P-256
   everywhere); the validator rejects non-EC leaves with a clear debug reason.
