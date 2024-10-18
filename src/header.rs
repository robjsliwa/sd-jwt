use crate::Algorithm;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub typ: Option<String>,
    pub alg: Algorithm,
    pub cty: Option<String>,
    pub jku: Option<String>,
    pub jwk: Option<Value>,
    pub kid: Option<String>,
    pub x5u: Option<String>,
    pub x5c: Option<Vec<String>>,
    pub x5t: Option<String>,
    pub x5t_s256: Option<String>,
    pub crit: Option<Vec<String>>,
}

impl Header {
    pub fn new(algorithm: Algorithm) -> Self {
        Header {
            typ: Some("sd-jwt".to_string()),
            alg: algorithm,
            cty: None,
            jku: None,
            jwk: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            crit: None,
        }
    }
}

impl Default for Header {
    fn default() -> Self {
        Header::new(Algorithm::default())
    }
}
