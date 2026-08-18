# ferro-forge

A small, honestly-scoped JWT decoder and validator, written to have real
fuzzable surface: parsing genuinely untrusted, attacker-shaped input.

This is a **validator**, not a full identity library, and not an
[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token-exchange
implementation. It does one thing — decode and verify HS256 JWTs — and
tries to do that one thing carefully.

```rust
let claims = ferro_forge::decode_and_verify(token, key)?;
```

## Implemented and verified

- **Segment parsing.** Splits a token on `.` into header/payload/signature,
  rejects any token that isn't exactly three segments, and base64url-decodes
  each segment — rejecting invalid base64 as a normal error, not a panic.
- **JSON parsing** of the decoded header and payload (via `serde_json`).
- **Algorithm allow-listing.** Reads `alg` from the header and rejects
  anything not on a small allow-list (currently just `HS256`) — including
  `"alg": "none"` — *before* the payload is decoded, before the signature is
  checked, and before any claim is parsed. This is deliberate: rejecting
  `none` and off-allow-list algorithms is the best-known JWT vulnerability
  class, and the check should read as load-bearing, not incidental.
- **HS256 signature verification**, via the RustCrypto `hmac` + `sha2`
  crates (constant-time comparison through `Mac::verify_slice` — no
  hand-rolled HMAC).
- **Standard claim validation:** `exp` (rejects if expired), `nbf` (rejects
  if not yet valid), and a basic `iat` sanity check (rejects if implausibly
  far in the future, beyond a small clock-skew allowance).
- **Fuzz-tested entry point.** `decode_and_verify` is exercised directly by
  a `cargo-fuzz` target that feeds it arbitrary bytes. A 60-second
  exploratory session ran ~12.7M executions with no crashes, no panics, and
  no artifacts.

## Not yet built

- RFC 8693 token minting / exchange
- RS256 or any asymmetric algorithm
- JWKS key discovery
- The full RFC 7519 registered claim set beyond `sub`/`exp`/`nbf`/`iat`
  (other claims decode into an unvalidated passthrough map, they just
  aren't checked)
- Replay protection / `jti` tracking

## Fuzzing

Requires a nightly toolchain (for libFuzzer coverage instrumentation) and
`cargo-fuzz`:

```
rustup toolchain install nightly
cargo +nightly install cargo-fuzz
cargo +nightly fuzz run decode_and_verify -- -max_total_time=60
```

## Testing

```
cargo test
```

Unit tests specifically cover the deliberate-rejection cases — `alg: none`,
an algorithm off the allow-list, a missing `alg`, malformed base64, a wrong
segment count, malformed JSON, an expired token, a not-yet-valid token, an
implausible `iat`, and a bad signature — plus a happy-path round trip.
