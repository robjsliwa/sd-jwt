// This is based on https://github.com/Keats/jsonwebtoken/blob/master/src/validation.rs and is used
// to provide facade for underlying JWT library set the validation parameters for the JWT.

use crate::Algorithm;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validation {
    #[cfg(not(target_arch = "wasm32"))]
    pub required_spec_claims: HashSet<String>,
    pub leeway: u64,
    pub validate_exp: bool,
    pub validate_nbf: bool,
    #[cfg(not(target_arch = "wasm32"))]
    pub validate_aud: bool,
    pub aud: Option<HashSet<String>>,
    #[cfg(not(target_arch = "wasm32"))]
    pub iss: Option<HashSet<String>>,
    #[cfg(target_arch = "wasm32")]
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub algorithms: Algorithm,
}

impl Validation {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(alg: Algorithm) -> Validation {
        let mut required_claims = HashSet::with_capacity(1);
        required_claims.insert("exp".to_owned());

        Validation {
            required_spec_claims: required_claims,
            algorithms: alg,
            leeway: 60,

            validate_exp: true,
            validate_nbf: false,
            validate_aud: true,

            iss: None,
            sub: None,
            aud: None,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn no_exp(mut self) -> Self {
        self.validate_exp = false;
        self.required_spec_claims.remove("exp");
        self
    }

    #[cfg(target_arch = "wasm32")]
    pub fn new(alg: Algorithm) -> Validation {
        let mut required_claims = HashSet::with_capacity(1);
        required_claims.insert("exp".to_owned());

        Validation {
            algorithms: alg,
            leeway: 60,

            validate_exp: true,
            validate_nbf: false,

            iss: None,
            sub: None,
            aud: None,
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn no_exp(mut self) -> Self {
        self.validate_exp = false;
        self
    }
}

impl Default for Validation {
    fn default() -> Self {
        Self::new(Algorithm::RS256)
    }
}
