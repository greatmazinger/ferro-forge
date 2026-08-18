use std::fmt;

/// Every way `decode_and_verify` can reject a token.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Token did not split into exactly header.payload.signature.
    MalformedToken,
    /// A segment ("header" | "payload" | "signature") was not valid base64url.
    InvalidBase64(&'static str),
    /// A segment ("header" | "payload") did not decode to valid JSON.
    InvalidJson(&'static str),
    /// Header had no `alg` field.
    MissingAlgorithm,
    /// `alg` was present but not on the allow-list (includes `"none"`).
    DisallowedAlgorithm,
    /// HMAC verification failed.
    InvalidSignature,
    /// `exp` is in the past.
    TokenExpired,
    /// `nbf` is in the future.
    TokenNotYetValid,
    /// `iat` is further in the future than clock-skew tolerance allows.
    ImplausibleIssuedAt,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedToken => write!(f, "token is not in header.payload.signature form"),
            Self::InvalidBase64(segment) => write!(f, "{segment} segment is not valid base64url"),
            Self::InvalidJson(segment) => write!(f, "{segment} segment did not decode to valid JSON"),
            Self::MissingAlgorithm => write!(f, "header is missing the `alg` field"),
            Self::DisallowedAlgorithm => write!(f, "`alg` is not on the allow-list"),
            Self::InvalidSignature => write!(f, "signature verification failed"),
            Self::TokenExpired => write!(f, "token has expired"),
            Self::TokenNotYetValid => write!(f, "token is not yet valid"),
            Self::ImplausibleIssuedAt => write!(f, "`iat` is implausibly far in the future"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_formats_without_panicking() {
        let variants = [
            DecodeError::MalformedToken,
            DecodeError::InvalidBase64("header"),
            DecodeError::InvalidJson("payload"),
            DecodeError::MissingAlgorithm,
            DecodeError::DisallowedAlgorithm,
            DecodeError::InvalidSignature,
            DecodeError::TokenExpired,
            DecodeError::TokenNotYetValid,
            DecodeError::ImplausibleIssuedAt,
        ];
        for variant in variants {
            assert!(!variant.to_string().is_empty());
        }
    }
}
