#[cfg(target_arch = "wasm32")]
use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")]
use serde_json::Value;
#[cfg(target_arch = "wasm32")]
use serde_wasm_bindgen::to_value;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

// #[cfg(target_arch = "wasm32")]
// #[wasm_bindgen]
// extern "C" {
//     #[wasm_bindgen(js_namespace = console)]
//     fn log(value: &str);
// }

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct SdJwtIssuer {}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl SdJwtIssuer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> SdJwtIssuer {
        SdJwtIssuer {}
    }

    pub fn encode(
        &self,
        claims: &str,
        signing_key: &str,
        algorithm: &str,
    ) -> Result<String, JsValue> {
        let (claims, tagged_paths) = parse_yaml(claims)?;
        let encoding_key = match algorithm {
            "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
                KeyForEncoding::from_rsa_pem(signing_key.as_bytes())?
            }
            "ES256" | "ES384" | "ES512" => KeyForEncoding::from_ec_pem(signing_key.as_bytes())?,
            _ => return Err(JsValue::from_str("Unsupported algorithm")),
        };
        let issuer_sd_jwt = crate::issuer::Issuer::new(claims.clone())?
            .iter_disclosable(tagged_paths.iter())
            .encode(&encoding_key)?;
        Ok(issuer_sd_jwt)
    }
}

#[cfg(target_arch = "wasm32")]
impl Default for SdJwtIssuer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize, Deserialize)]
pub struct DecodedIssuerJwt {
    pub header: Value,
    pub updated_claims: Value,
    pub disclosure_paths: Vec<DisclosurePath>,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct SdJwtHolder {}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl SdJwtHolder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        SdJwtHolder {}
    }

    #[wasm_bindgen]
    pub fn verify(
        &self,
        encoded_issuer_jwt: &str,
        public_key: &str,
        algorithm: &str,
    ) -> Result<JsValue, JsValue> {
        let decoding_key = match algorithm {
            "RS256" | "RS384" | "RS512" => KeyForDecoding::from_rsa_pem(public_key.as_bytes())?,
            "ES256" | "ES384" | "ES512" => KeyForDecoding::from_ec_pem(public_key.as_bytes())?,
            _ => return Err(JsValue::from_str("Unsupported algorithm")),
        };
        let validation = Validation::default().without_expiry();
        let (header, decoded_claims, disclosure_paths) =
            Holder::verify(encoded_issuer_jwt, &decoding_key, &validation)?;
        let decoded_issuer_jwt = DecodedIssuerJwt {
            header,
            updated_claims: decoded_claims,
            disclosure_paths,
        };
        Ok(to_value(&decoded_issuer_jwt)?)
    }
}

#[cfg(target_arch = "wasm32")]
impl Default for SdJwtHolder {
    fn default() -> Self {
        Self::new()
    }
}

pub mod algorithm;
pub mod decoding;
pub(crate) mod decoy;
pub mod disclosure;
pub mod disclosure_path;
pub mod encoding;
pub mod error;
pub mod header;
pub mod holder;
pub mod issuer;
pub mod jwk;
mod parser;
mod utils;
pub mod validation;
pub mod verifier;

#[cfg(test)]
mod test_utils;

pub use algorithm::*;
pub use decoding::*;
pub use disclosure::Disclosure;
pub use disclosure_path::*;
pub use encoding::*;
pub use error::*;
pub use header::*;
pub use holder::*;
pub use issuer::*;
pub use jwk::*;
pub use parser::parse_yaml;
pub use validation::*;
pub use verifier::*;
