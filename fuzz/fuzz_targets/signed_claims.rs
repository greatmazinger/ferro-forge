#![no_main]

use arbitrary::Arbitrary;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, KeyInit, Mac};
use libfuzzer_sys::fuzz_target;
use sha2::Sha256;

const KEY: &[u8] = b"fuzz-target-fixed-key";

// Mirrors ferro_forge::Claims's known fields, plus a couple of scalar
// extras that land in its #[serde(flatten)] passthrough map. The fuzzer
// controls only these values; the harness handles base64 + HMAC signing
// so every generated token has a valid signature and reaches
// Claims::validate, which decode_and_verify's own raw-bytes fuzz target
// can't get past.
#[derive(Arbitrary, Debug, serde::Serialize)]
struct FuzzClaims {
    sub: Option<String>,
    exp: Option<i64>,
    nbf: Option<i64>,
    iat: Option<i64>,
    x: Option<i64>,
    y: Option<String>,
}

fuzz_target!(|claims: FuzzClaims| {
    let Ok(payload_json) = serde_json::to_vec(&claims) else {
        return;
    };

    let header_seg = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#);
    let payload_seg = URL_SAFE_NO_PAD.encode(payload_json);

    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).expect("HMAC accepts any key length");
    mac.update(format!("{header_seg}.{payload_seg}").as_bytes());
    let sig_seg = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    let token = format!("{header_seg}.{payload_seg}.{sig_seg}");
    let _ = ferro_forge::decode_and_verify(&token, KEY);
});
