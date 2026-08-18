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
- **Fuzz-tested entry point**, via three complementary `cargo-fuzz` targets
  (see [Fuzzing](#fuzzing) below): one feeding `decode_and_verify` arbitrary
  bytes, and two feeding it structurally valid, correctly-signed tokens so
  the fuzzer can reach claim validation and algorithm rejection instead of
  dying at signature verification. Combined: 0 crashes, 0 panics, 0
  artifacts, 100% line coverage of `src/lib.rs` and `src/claims.rs`.

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
cargo +nightly fuzz run signed_claims -- -max_total_time=60
cargo +nightly fuzz run signed_header -- -max_total_time=60
```

There are three targets, because one alone leaves most of the crate
unreachable:

- **`decode_and_verify`** (`fuzz_targets/decode_and_verify.rs`) feeds raw
  bytes straight into `decode_and_verify`. This is the right tool for the
  segment-splitting, base64, header-JSON, and algorithm-allow-list code —
  but it can't get past HMAC-SHA256 signature verification by chance, so
  everything past that point (`Claims` deserialization, `exp`/`nbf`/`iat`
  validation in `src/claims.rs`) is structurally unreachable to it, no
  matter how long it runs.
- **`signed_claims`** (`fuzz_targets/signed_claims.rs`) lets the fuzzer
  control only the claim values (`sub`, `exp`, `nbf`, `iat`, plus a couple
  of extra scalars that land in the passthrough map) with `alg` fixed to
  `"HS256"`; the harness handles base64 encoding and HMAC signing with the
  known fuzz key, so every generated token has a valid signature by
  construction and the fuzzer's mutation budget goes toward claim-value
  edge cases instead of toward guessing a 256-bit MAC.
- **`signed_header`** (`fuzz_targets/signed_header.rs`) is the same idea,
  but the fuzzer also controls `alg` instead of it being fixed. The
  signature is still computed correctly for whatever header comes out, so
  a token with `alg: "RS256"` (say) is otherwise well-formed and correctly
  signed — the only way it can be rejected is the allow-list check itself,
  which `signed_claims`'s fixed header can't reach and
  `decode_and_verify`'s raw bytes essentially never hit by chance (needs
  valid base64 *and* valid JSON *and* a mismatched `alg` string at once).

Exploratory runs so far: `signed_claims` for 5 minutes (4.7M execs),
`signed_header` for 60s (1.5M execs), `decode_and_verify` for 60s (~12.7M
execs, per an earlier session) — 0 crashes, 0 panics, 0 artifacts across
all three. Coverage (`cargo +nightly fuzz coverage <target>`, reported via
`llvm-cov`) confirms each target earns its keep:

| | `decode_and_verify` | `signed_claims` | `signed_header` | **combined** |
|---|---|---|---|---|
| `src/lib.rs` (lines) | 35.3% | 91.2% | 97.1% | **100.0%** |
| `src/claims.rs` (lines) | 0.0% | 100.0% | 100.0% | **100.0%** |
| `src/error.rs` (lines) | 0.0% | 0.0% | 0.0% | **0.0%** |

One known, understood gap, not a blind spot: `src/error.rs` is 0% covered
by any fuzz target because its only code is the `Display` impl, which
nothing in the fuzz harnesses ever calls — there's no interesting *input*
space there to fuzz. It's covered by a unit test instead
(`error::tests::every_variant_formats_without_panicking`).

## Testing

```
cargo test
```

Unit tests specifically cover the deliberate-rejection cases — `alg: none`,
an algorithm off the allow-list, a missing `alg`, malformed base64, a wrong
segment count, malformed JSON, an expired token, a not-yet-valid token, an
implausible `iat`, and a bad signature — plus a happy-path round trip and
a check that every `DecodeError` variant's `Display` impl formats.
