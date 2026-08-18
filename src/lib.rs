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

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(header_seg: &str, payload_seg: &str, key: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(format!("{header_seg}.{payload_seg}").as_bytes());
        let sig = mac.finalize().into_bytes();
        URL_SAFE_NO_PAD.encode(sig)
    }

    fn make_token(header_json: &str, payload_json: &str, key: &[u8]) -> String {
        let header_seg = URL_SAFE_NO_PAD.encode(header_json);
        let payload_seg = URL_SAFE_NO_PAD.encode(payload_json);
        let sig_seg = sign(&header_seg, &payload_seg, key);
        format!("{header_seg}.{payload_seg}.{sig_seg}")
    }

    const KEY: &[u8] = b"test-key";

    #[test]
    fn accepts_valid_token() {
        let token = make_token(r#"{"alg":"HS256"}"#, r#"{"sub":"alice"}"#, KEY);
        let claims = decode_and_verify(&token, KEY).unwrap();
        assert_eq!(claims.sub.as_deref(), Some("alice"));
    }

    #[test]
    fn rejects_alg_none() {
        let token = make_token(r#"{"alg":"none"}"#, r#"{}"#, KEY);
        assert_eq!(
            decode_and_verify(&token, KEY),
            Err(DecodeError::DisallowedAlgorithm)
        );
    }

    #[test]
    fn rejects_alg_not_on_allowlist() {
        let token = make_token(r#"{"alg":"HS384"}"#, r#"{}"#, KEY);
        assert_eq!(
            decode_and_verify(&token, KEY),
            Err(DecodeError::DisallowedAlgorithm)
        );
    }

    #[test]
    fn rejects_missing_alg() {
        let token = make_token(r#"{}"#, r#"{}"#, KEY);
        assert_eq!(
            decode_and_verify(&token, KEY),
            Err(DecodeError::MissingAlgorithm)
        );
    }

    #[test]
    fn rejects_wrong_segment_count() {
        assert_eq!(
            decode_and_verify("a.b", KEY),
            Err(DecodeError::MalformedToken)
        );
        assert_eq!(
            decode_and_verify("a.b.c.d", KEY),
            Err(DecodeError::MalformedToken)
        );
    }

    #[test]
    fn rejects_malformed_base64() {
        assert_eq!(
            decode_and_verify("not!valid!base64.b.c", KEY),
            Err(DecodeError::InvalidBase64("header"))
        );
    }

    #[test]
    fn rejects_malformed_json() {
        let header_seg = URL_SAFE_NO_PAD.encode("not json");
        let token = format!("{header_seg}.b.c");
        assert_eq!(
            decode_and_verify(&token, KEY),
            Err(DecodeError::InvalidJson("header"))
        );
    }

    #[test]
    fn rejects_expired_token() {
        let payload = r#"{"exp":1}"#;
        let token = make_token(r#"{"alg":"HS256"}"#, payload, KEY);
        assert_eq!(
            decode_and_verify(&token, KEY),
            Err(DecodeError::TokenExpired)
        );
    }

    #[test]
    fn rejects_not_yet_valid_token() {
        let payload = r#"{"nbf":99999999999}"#;
        let token = make_token(r#"{"alg":"HS256"}"#, payload, KEY);
        assert_eq!(
            decode_and_verify(&token, KEY),
            Err(DecodeError::TokenNotYetValid)
        );
    }

    #[test]
    fn rejects_implausible_iat() {
        let payload = r#"{"iat":99999999999}"#;
        let token = make_token(r#"{"alg":"HS256"}"#, payload, KEY);
        assert_eq!(
            decode_and_verify(&token, KEY),
            Err(DecodeError::ImplausibleIssuedAt)
        );
    }

    #[test]
    fn rejects_bad_signature() {
        let token = make_token(r#"{"alg":"HS256"}"#, r#"{}"#, KEY);
        assert_eq!(
            decode_and_verify(&token, b"wrong-key"),
            Err(DecodeError::InvalidSignature)
        );
    }
}
