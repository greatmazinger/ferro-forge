use crate::error::DecodeError;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

/// Clock-skew allowance for the `iat` sanity check, not a general feature.
const MAX_FUTURE_SKEW_SECS: i64 = 300;

#[derive(Debug, PartialEq, Deserialize)]
pub struct Claims {
    pub sub: Option<String>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    /// Every other claim, unvalidated. This crate only checks exp/nbf/iat.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl Claims {
    pub(crate) fn validate(&self, now: i64) -> Result<(), DecodeError> {
        if let Some(exp) = self.exp {
            if now >= exp {
                return Err(DecodeError::TokenExpired);
            }
        }
        if let Some(nbf) = self.nbf {
            if now < nbf {
                return Err(DecodeError::TokenNotYetValid);
            }
        }
        if let Some(iat) = self.iat {
            if iat > now + MAX_FUTURE_SKEW_SECS {
                return Err(DecodeError::ImplausibleIssuedAt);
            }
        }
        Ok(())
    }
}
