# FerroForge

ferro_forge is a minimal HS256 JWT decoder and validator built as a fuzzing
target for untrusted input. Rather than acting as a full identity library or an
RFC 8693 token-exchange implementation, it focuses purely on decoding and
verifying HS256 tokens safely.

This is a **validator**, not a full identity library, and not an
[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token-exchange
implementation. It does one thing — decode and verify HS256 JWTs — and
tries to do that one thing carefully.

```rust
let claims = ferro_forge::decode_and_verify(token, key)?;
```

## What's Implemented


- **Segment parsing.** Splits tokens on . into header, payload, and signature.
  Rejects anything without exactly three segments and base64url-decodes each
  part, returning standard errors on malformed input without panicking.
- **Header & payload deserialization** Parses decoded JSON segments via serde_json.
- **Algorithm allow-listing.** Reads `alg` from the header and rejects
- **Strict algorithm allow-listing** Checks the header alg against an explicit
  allow-list (currently HS256 only) and rejects "alg": "none" or unexpected
  algorithms before decoding the payload, verifying the signature, or parsing
  claims.
- **HS256 signature verification** Uses the RustCrypto hmac and sha2 crates,
  relying on Mac::verify_slice for constant-time comparison rather than custom
  crypto.
- **Standard claim validation:** `exp` (rejects if expired), `nbf` (rejects
  if not yet valid), and a basic `iat` sanity check (rejects if implausibly
  far in the future, beyond a small clock-skew allowance).
- **Standard claim validation** Enforces exp (expiration), nbf (not-before),
  and iat (rejecting tokens issued implausibly far in the future beyond a small
  clock-skew window).
- **Fuzzing & differential testing** Tested via four cargo-fuzz targets (see
  Fuzzing below). Three targets feed decode_and_verify raw bytes and
  structurally valid, pre-signed tokens so the fuzzer reaches deep claim and
  algorithm paths rather than bouncing off HMAC verification. A fourth runs
  differential fuzzing against the jsonwebtoken crate. Currently at 100% line
  coverage across src/lib.rs and src/claims.rs with zero crashes and one
  documented boundary difference against jsonwebtoken at exp == now.

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
cargo +nightly fuzz run differential -- -max_total_time=60
```

There are four targets, because one alone leaves most of the crate
unreachable:

We use four separate targets because a single raw-byte fuzzer cannot get past the HMAC check to reach the deeper validation logic:

- **`decode_and_verify`** (`fuzz_targets/decode_and_verify.rs`) Feeds raw bytes
directly into decode_and_verify. Exercises segment splitting, base64
decoding, header JSON parsing, and the algorithm allow-list. Because random
inputs won't produce a valid 256-bit HMAC signature, everything after
signature verification (Claims deserialization and temporal checks in
src/claims.rs) is unreachable here.

- **`signed_header`** (`fuzz_targets/signed_header.rs`) Similar to
  signed_claims, except the fuzzer also controls the header's alg field before
  the harness signs the token. This produces well-formed, validly signed tokens
  with arbitrary alg strings (like "RS256"), specifically targeting the
  allow-list check—a path signed_claims skips and decode_and_verify rarely hits
  with raw bytes.

- **`signed_claims`** (`fuzz_targets/signed_claims.rs`) Fixes alg to "HS256"
  and lets the fuzzer mutate only the claim values (sub, exp, nbf, iat, plus a
  few extra scalars for the passthrough map). The harness base64-encodes and
  signs the payload with the fuzz key so every input has a valid MAC, focusing
  mutations on claim deserialization and boundary checks.

- **`differential`** (`fuzz_targets/differential.rs`) Generates valid signed
  tokens like signed_claims, decodes them with both
  ferro_forge::decode_and_verify and the jsonwebtoken crate (v11.x, rust_crypto
  backend, leeway = 0, validate_nbf = true, validate_aud = false, empty
  required_spec_claims), and panics if the two libraries disagree. exp and nbf
  are generated as small signed offsets from the current wall clock rather than
  absolute timestamps so the seed corpus doesn't go stale over time.


### Differential Fuzzing Findings

Both findings below are documented in the harness with regression seeds committed to the corpus:

- **Boundary difference at `exp == now`:** `ferro_forge` checks `now >= exp`
  (rejecting on equality), whereas `jsonwebtoken` with zero leeway checks `exp
  < now` (accepting on equality). RFC 7519 §4.1.4 specifies that the current
  time MUST be before the expiration time (making `now >= exp` the strict
  reading), though both conventions exist in the wild. We saved the 3-byte
  reproducer (`fuzz/corpus/differential/regression-exp-equals-now-boundary`)
  and excluded `|offset| <= 1` from the differential assertion so wall-clock
  ticks between the harness, `ferro_forge`, and `jsonwebtoken` don't cause
  false failures.
- **Harness integer overflow on `i16::MIN.abs()`:** Calling `.abs()` on
  `exp_offset = -32768` (`i16::MIN`) panicked in the harness itself. Fixed by
  casting to `i32` before taking the absolute value (reproducer at
  `fuzz/corpus/differential/regression-i16-min-abs-overflow`).

### Coverage & Run Summary

Exploratory runs so far:
- `decode_and_verify`: 60s (~12.7M execs)
- `signed_claims`: 5m (4.7M execs)
- `signed_header`: 60s (1.5M execs)
- `differential`: ~5m combined (~2M+ execs, 0 crashes after the two fixes above)

Line coverage via `cargo +nightly fuzz coverage <target>` (`llvm-cov`) across
the first three targets (`differential` is omitted from the table since it hits
the exact same `ferro_forge` code paths as `signed_claims`):

| | `decode_and_verify` | `signed_claims` | `signed_header` | **combined** |
|---|---|---|---|---|
| `src/lib.rs` (lines) | 35.3% | 91.2% | 97.1% | **100.0%** |
| `src/claims.rs` (lines) | 0.0% | 100.0% | 100.0% | **100.0%** |
| `src/error.rs` (lines) | 0.0% | 0.0% | 0.0% | **0.0%** |

`src/error.rs` shows 0% fuzz coverage because it only contains the `Display`
implementation, which the fuzz harnesses never invoke. Error formatting is
verified by unit tests instead (`error::tests::every_variant_formats_without_panicking`).

## Testing

```
cargo test
```
Unit tests cover:
- **Header & format rejections:** wrong segment count, malformed base64 or JSON, missing `alg`, `alg: none`, and unsupported algorithms
- **Crypto & temporal rejections:** invalid HMAC signatures, expired `exp`, not-yet-valid `nbf`, and implausible future `iat` claims
- **Baseline checks:** happy-path round trip and `Display` formatting for every `DecodeError` variant
