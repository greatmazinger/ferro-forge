mod claims;
mod error;

pub use claims::Claims;
pub use error::DecodeError;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

const ALLOWED_ALGORITHMS: &[&str] = &["HS256"];

#[derive(Deserialize)]
struct Header {
    alg: Option<String>,
}

/// Decode, verify, and validate a JWT. See README for exactly what is and
/// isn't checked — this is a small allow-listed HS256 validator, not a
/// general-purpose JWT library.
pub fn decode_and_verify(token: &str, key: &[u8]) -> Result<Claims, DecodeError> {
    let parts: Vec<&str> = token.split('.').collect();
    let [header_seg, payload_seg, sig_seg] = parts[..] else {
        return Err(DecodeError::MalformedToken);
    };

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_seg)
        .map_err(|_| DecodeError::InvalidBase64("header"))?;
    let header: Header = serde_json::from_slice(&header_bytes)
        .map_err(|_| DecodeError::InvalidJson("header"))?;

    // Algorithm allow-listing must happen before any signature or claim
    // processing: rejecting "none" and off-allow-list algorithms is the
    // whole point, and it must not depend on the payload or signature
    // being well-formed.
    match header.alg.as_deref() {
        None => return Err(DecodeError::MissingAlgorithm),
        Some(alg) if !ALLOWED_ALGORITHMS.contains(&alg) => {
            return Err(DecodeError::DisallowedAlgorithm);
        }
        Some(_) => {}
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_seg)
        .map_err(|_| DecodeError::InvalidBase64("payload"))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_seg)
        .map_err(|_| DecodeError::InvalidBase64("signature"))?;

    let signing_input = format!("{header_seg}.{payload_seg}");
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&sig_bytes)
        .map_err(|_| DecodeError::InvalidSignature)?;

    let claims: Claims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| DecodeError::InvalidJson("payload"))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs() as i64;
    claims.validate(now)?;

    Ok(claims)
}
