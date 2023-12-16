use serde_json::Error as SerdeError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to form disclosuer")]
    DisclosureFailed(#[from] SerdeError),
    #[error("invalid disclosure key {0}")]
    InvalidDisclosureKey(String),
    #[error("encoding key error")]
    EncodingKeyError(#[from] jsonwebtoken::errors::Error),
    #[error("invalid path pointer to disclosure")]
    InvalidPathPointer,
    #[error("invalid path pointer array index")]
    InvalidPathPointerArrayIndex(#[from] std::num::ParseIntError),
    #[error("invalid _sd type")]
    InvalidSDType,
    #[error("decoding error")]
    DecodingError(#[from] base64::DecodeError),
    #[error("from utf8 conversion error")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error("invalid disclosure format {0}")]
    InvalidDisclosureFormat(String),
    #[error("sd-jwt rejected {0}")]
    SDJWTRejected(String),
    #[error("invalid hash algorithm {0}")]
    InvalidHashAlgorithm(String),
    #[error("JWT must have exactly three parts")]
    JwtMustHaveThreeParts,
    #[error("Key Binding JWT is required for the presentation.  Use .key_binding() to set it.")]
    KeyBindingJWTRequired,
    #[error("KB-JWT parameter missing: {0}")]
    KeyBindingJWTParameterMissing(String),
}
