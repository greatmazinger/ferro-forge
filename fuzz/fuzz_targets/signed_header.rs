#![no_main]

use arbitrary::Arbitrary;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, KeyInit, Mac};
use libfuzzer_sys::fuzz_target;
use sha2::Sha256;

const KEY: &[u8] = b"fuzz-target-fixed-key";

// Same idea as signed_claims, but the fuzzer also controls `alg` instead
// of it being hardcoded to "HS256". The signature is still computed
// correctly for whatever header this produces, so a token with, say,
// alg: "RS256" is otherwise well-formed and correctly signed — the only
// way decode_and_verify can reject it is the allow-list check itself
// (src/lib.rs's DisallowedAlgorithm branch), which signed_claims's fixed
// header can't reach and decode_and_verify's raw bytes essentially never
// hit by chance.
#[derive(Arbitrary, Debug, serde::Serialize)]
struct FuzzHeader {
    alg: Option<String>,
}

#[derive(Arbitrary, Debug, serde::Serialize)]
struct FuzzClaims {
    sub: Option<String>,
    exp: Option<i64>,
    nbf: Option<i64>,
    iat: Option<i64>,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    header: FuzzHeader,
    claims: FuzzClaims,
}

fuzz_target!(|input: FuzzInput| {
    let Ok(header_json) = serde_json::to_vec(&input.header) else {
        return;
    };
    let Ok(payload_json) = serde_json::to_vec(&input.claims) else {
        return;
    };

    let header_seg = URL_SAFE_NO_PAD.encode(header_json);
    let payload_seg = URL_SAFE_NO_PAD.encode(payload_json);

    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).expect("HMAC accepts any key length");
    mac.update(format!("{header_seg}.{payload_seg}").as_bytes());
    let sig_seg = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    let token = format!("{header_seg}.{payload_seg}.{sig_seg}");
    let _ = ferro_forge::decode_and_verify(&token, KEY);
});
