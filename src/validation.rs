use crate::Algorithm;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validation {
    pub required_spec_claims: Option<HashSet<String>>,
    pub leeway: u64,
    pub validate_exp: bool,
    pub validate_nbf: bool,
    pub validate_aud: bool,
    pub aud: Option<HashSet<String>>,
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub algorithms: Algorithm,
}

impl Validation {
    pub fn new(alg: Algorithm) -> Validation {
        Validation {
            required_spec_claims: None,
            algorithms: alg,
            leeway: 0,

            validate_exp: true,
            validate_nbf: false,
            validate_aud: true,

            iss: None,
            sub: None,
            aud: None,
        }
    }

    /// Disable expiration (`exp`) validation.
    pub fn without_expiry(self) -> Self {
        Self {
            validate_exp: false,
            ..Self::default()
        }
    }

    /// Set a single audience member as the only acceptable value.
    pub fn with_audience<T: ToString>(self, audience: T) -> Self {
        Self {
            aud: Some(HashSet::from([audience.to_string()])),
            ..self
        }
    }

    /// Set the issuer claim to validate.
    pub fn with_issuer<T: ToString>(self, issuer: T) -> Self {
        Self {
            iss: Some(issuer.to_string()),
            ..self
        }
    }

    /// Set the subject claim to validate.
    pub fn with_subject<T: ToString>(self, subject: T) -> Self {
        Self {
            sub: Some(subject.to_string()),
            ..self
        }
    }

    /// Set leeway for time-related claims (`exp`, `nbf`, `iat`).
    pub fn with_leeway(self, leeway: u64) -> Self {
        Self { leeway, ..self }
    }

    /// Add an allowed signing algorithm.
    pub fn with_algorithm(mut self, alg: Algorithm) -> Self {
        self.algorithms = alg;
        self
    }

    /// Add a required claim.
    pub fn with_required_claim<T: ToString>(mut self, claim: T) -> Self {
        if let Some(ref mut required_claims) = self.required_spec_claims {
            required_claims.insert(claim.to_string());
        } else {
            self.required_spec_claims = Some(HashSet::from([claim.to_string()]));
        }
        self
    }
}

impl Default for Validation {
    fn default() -> Self {
        Self::new(Algorithm::RS256)
    }
}
