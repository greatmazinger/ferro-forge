#![no_main]

use arbitrary::Arbitrary;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, KeyInit, Mac};
use libfuzzer_sys::fuzz_target;
use serde::Serialize;
use sha2::Sha256;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

const KEY: &[u8] = b"fuzz-target-fixed-key";

// exp/nbf are encoded as small offsets from "now" rather than absolute
// timestamps: an absolute-epoch seed goes stale the moment it's in the
// past, and a free-range i64 would need to land on today's exact epoch
// second (astronomically unlikely) to probe the one boundary this
// harness cares about. A small signed offset densely samples exactly
// the region around "now" where two independent exp/nbf implementations
// are most likely to disagree.
#[derive(Arbitrary, Debug)]
struct FuzzClaims {
    sub: Option<String>,
    exp_offset: Option<i16>,
    nbf_offset: Option<i16>,
}

// skip_serializing_if is required, not cosmetic: without it, None
// fields serialize as explicit JSON `null` rather than being omitted,
// and jsonwebtoken's claim deserializer treats a present-but-null claim
// as malformed (rejects) while ferro-forge's plain Option<i64> treats
// null the same as absent. That's a real divergence, but only because
// no real JWT issuer emits `"nbf":null` for an absent claim - omitting
// the field is what actual tokens look like, so that's what this
// harness should generate.
#[derive(Serialize)]
struct Payload {
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
}

fuzz_target!(|claims: FuzzClaims| {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs() as i64;

    let payload = Payload {
        sub: claims.sub.clone(),
        exp: claims.exp_offset.map(|o| now + o as i64),
        nbf: claims.nbf_offset.map(|o| now + o as i64),
    };
    let Ok(payload_json) = serde_json::to_vec(&payload) else {
        return;
    };

    let header_seg = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#);
    let payload_seg = URL_SAFE_NO_PAD.encode(payload_json);

    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).expect("HMAC accepts any key length");
    mac.update(format!("{header_seg}.{payload_seg}").as_bytes());
    let sig_seg = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    let token = format!("{header_seg}.{payload_seg}.{sig_seg}");

    let ferro_ok = ferro_forge::decode_and_verify(&token, KEY).is_ok();

    // Configured to match ferro-forge's exact scope: HS256 only, no
    // clock-skew leeway, nbf checked, no aud/iss/sub/exp requirement
    // (all of ferro-forge's claim fields are optional). iat has no
    // jsonwebtoken equivalent, so it's left out of this harness
    // entirely rather than compared unfairly.
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.leeway = 0;
    validation.validate_nbf = true;
    validation.validate_aud = false;
    validation.required_spec_claims = HashSet::new();
    let decoding_key = jsonwebtoken::DecodingKey::from_secret(KEY);
    let jwt_result = jsonwebtoken::decode::<serde_json::Value>(&token, &decoding_key, &validation);
    let jwt_ok = jwt_result.is_ok();

    // Known, confirmed divergence at exp == now exactly (exp_offset ==
    // Some(0)): ferro-forge's check is `now >= exp` (rejects on
    // equality), jsonwebtoken's is `exp < now` with leeway 0 (accepts
    // on equality). Neither reading is wrong - "does the token expire
    // at exp" is ambiguous about the boundary instant itself - but two
    // independent implementations land on opposite answers. See the
    // README's Fuzzing section for the write-up.
    //
    // Widened to |offset| <= 1, not just 0, because three independent
    // wall-clock reads are involved here (this harness's `now`, used to
    // compute exp; ferro-forge's own internal SystemTime::now(); and
    // jsonwebtoken's internal clock read) - if a real second ticks over
    // between any of them, an offset intended to land exactly on the
    // boundary can drift by one. That produced a non-reproducing
    // "crash" at exp_offset == 1 during exploration: same input bytes,
    // re-run moments later, no panic. Not a logic bug, just wall-clock
    // testing's usual hazard - a real fix would need a mockable clock
    // in both libraries, out of scope for a fuzz-target-only change.
    // (i16 as i32).abs(), not o.abs(): i16::MIN.abs() overflows (there's
    // no positive i16 for 32768) and panicked here during exploration -
    // a bug in this harness, not in either library under test.
    let is_known_exp_boundary_divergence =
        matches!(claims.exp_offset, Some(o) if (o as i32).abs() <= 1) && !ferro_ok && jwt_ok;

    if ferro_ok != jwt_ok && !is_known_exp_boundary_divergence {
        panic!(
            "differential mismatch: ferro-forge accepted={ferro_ok}, jsonwebtoken accepted={jwt_ok}, \
             exp_offset={:?}, nbf_offset={:?}, sub={:?}, jsonwebtoken_err={:?}",
            claims.exp_offset, claims.nbf_offset, claims.sub, jwt_result.err()
        );
    }
});
