# ShadowTLS patches over upstream rustls

Base: **rustls 0.23.43** (`fcf61cdbba30913cfd5b40aefa83989c6233812d`)

## New files

| File | Purpose |
|------|---------|
| `rustls/src/client/fingerprint.rs` | Chrome 133 ClientHello profile |
| `rustls/src/client/reality.rs` | VLESS REALITY client authentication (session_id + ed25519 verify) |
| `rustls/src/server/reality.rs` | VLESS REALITY server Accept (session_id decrypt + HMAC-Ed25519 cert) |
| `rustls/src/server/reality.rs` | VLESS REALITY server Accept (session_id decrypt + HMAC-Ed25519 cert mint) |

## Modified files

| File | Change |
|------|--------|
| `rustls/src/lib.rs` | Export `ClientHelloFingerprint`, `RealityConfig`, REALITY server Accept API |
| `rustls/src/client/builder.rs` | Default fingerprint fields; `with_reality()` |
| `rustls/src/client/client_conn.rs` | Fingerprint config fields; `enable_ech_grease()`; `new_with_session_id_generator`; `reality_config` |
| `rustls/src/client/hs.rs` | `SessionIdGenerator`; fingerprint; REALITY session_id; skip session-id hook when REALITY active |
| `rustls/src/msgs/handshake.rs` | GREASE in supported versions; `extra_extensions`; fingerprint encode order |
| `rustls/src/server/server_conn.rs` | `ClientHello` exposes session_id/random/key_shares/raw handshake for REALITY |
| `rustls/src/server/hs.rs` | Pass encoded handshake bytes into cert resolver `ClientHello` |
| `rustls/src/server/server_conn.rs` | Extend `ClientHello` with session_id/random/key_shares/raw for REALITY |
| `rustls/src/server/hs.rs` / `handy.rs` | Populate REALITY ClientHello fields |
| `rustls/src/server/test.rs` | `SupportedProtocolVersions { grease: None }` test fix |
| `tokio-rustls/src/client.rs` | `connect_with_session_id_generator` |

## REALITY server Accept

Wire via [`RealityServerCertResolver`] as `ServerConfig::cert_resolver`, or call
`authenticate_reality_client_hello` + `mint_reality_certified_key` from a custom
`ResolvesServerCert` / `LazyConfigAcceptor` flow (including tokio-rustls
`LazyConfigAcceptor`).

Auth path: ECDH(server_private, client X25519 share) → HKDF-SHA256 → AES-256-GCM
open of session_id → mint Ed25519 cert with HMAC-SHA512 tail.

**Not in this crate:** destination dial / record-length camouflage (application layer).

## Intentionally not patched

- Full uTLS parrots (`firefox`, `safari`, …).
- RSA/CBC cipher implementation. Chrome 133's six legacy RSA/CBC suites are
  advertised for wire-shape parity, but rustls aws-lc cannot negotiate them if
  a server selects one.

## tokio-rustls base

**0.26.4** (`0c14e1496ef50adade4ac7c7d1f0270dfb3cdda5`) — only `connect_with_session_id_generator` added; depends on path `../rustls`.
