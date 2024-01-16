use crate::Algorithm;
use crate::Error;
use crate::Header;
#[cfg(feature = "ring")]
use jsonwebtoken::{
    encode as jwt_encode, Algorithm as JwtAlgorithm, EncodingKey, Header as JwtHeader,
};

#[cfg(feature = "noring")]
use jsonwebtoken_rustcrypto::{
    encode as jwt_encode,
    headers::{JwtHeader, X509Headers},
    Algorithm as JwtAlgorithm, EncodingKey,
};
#[cfg(feature = "noring")]
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};

use serde::Serialize;

#[derive(Clone)]
pub struct KeyForEncoding {
    key: EncodingKey,
}

impl KeyForEncoding {
    pub fn from_secret(secret: &[u8]) -> Self {
        KeyForEncoding {
            key: EncodingKey::from_secret(secret),
        }
    }

    pub fn from_base64_secret(secret: &str) -> Result<Self, Error> {
        Ok(KeyForEncoding {
            key: EncodingKey::from_base64_secret(secret)?,
        })
    }

    #[cfg(feature = "ring")]
    pub fn from_rsa_pem(key: &[u8]) -> Result<Self, Error> {
        Ok(KeyForEncoding {
            key: EncodingKey::from_rsa_pem(key)?,
        })
    }

    #[cfg(feature = "noring")]
    pub fn from_rsa_pem(key: &[u8]) -> Result<Self, Error> {
        let rsa_key = RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(key)?)?;

        Ok(KeyForEncoding {
            key: EncodingKey::from_rsa(rsa_key)?,
        })
    }

    #[cfg(feature = "ring")]
    pub fn from_ec_pem(key: &[u8]) -> Result<Self, Error> {
        Ok(KeyForEncoding {
            key: EncodingKey::from_ec_pem(key)?,
        })
    }

    #[cfg(feature = "ring")]
    pub fn from_ed_pem(key: &[u8]) -> Result<Self, Error> {
        Ok(KeyForEncoding {
            key: EncodingKey::from_ed_pem(key)?,
        })
    }

    #[cfg(feature = "ring")]
    pub fn from_rsa_der(der: &[u8]) -> Self {
        KeyForEncoding {
            key: EncodingKey::from_rsa_der(der),
        }
    }

    #[cfg(feature = "ring")]
    pub fn from_ec_der(der: &[u8]) -> Self {
        KeyForEncoding {
            key: EncodingKey::from_ec_der(der),
        }
    }

    #[cfg(feature = "ring")]
    pub fn from_ed_der(der: &[u8]) -> Self {
        KeyForEncoding {
            key: EncodingKey::from_ed_der(der),
        }
    }
}

#[cfg(feature = "ring")]
fn build_header(header: &Header) -> Result<JwtHeader, Error> {
    let jwk = match &header.jwk {
        Some(jwk) => Some(serde_json::from_value(jwk.clone())?),
        None => None,
    };
    Ok(JwtHeader {
        typ: header.typ.clone(),
        alg: match header.alg {
            Algorithm::HS256 => JwtAlgorithm::HS256,
            Algorithm::HS384 => JwtAlgorithm::HS384,
            Algorithm::HS512 => JwtAlgorithm::HS512,
            Algorithm::RS256 => JwtAlgorithm::RS256,
            Algorithm::RS384 => JwtAlgorithm::RS384,
            Algorithm::RS512 => JwtAlgorithm::RS512,
            Algorithm::ES256 => JwtAlgorithm::ES256,
            Algorithm::ES384 => JwtAlgorithm::ES384,
            Algorithm::PS256 => JwtAlgorithm::PS256,
            Algorithm::PS384 => JwtAlgorithm::PS384,
            Algorithm::PS512 => JwtAlgorithm::PS512,
            Algorithm::EdDSA => JwtAlgorithm::EdDSA,
        },
        cty: header.cty.clone(),
        jku: header.jku.clone(),
        jwk,
        kid: header.kid.clone(),
        x5u: header.x5u.clone(),
        x5c: header.x5c.clone(),
        x5t: header.x5t.clone(),
        x5t_s256: header.x5t_s256.clone(),
    })
}

#[cfg(feature = "noring")]
fn build_header(header: &Header) -> Result<JwtHeader, Error> {
    let jwk = match &header.jwk {
        Some(jwk) => Some(serde_json::from_value(jwk.clone())?),
        None => None,
    };

    let alg = match header.alg {
        Algorithm::HS256 => JwtAlgorithm::HS256,
        Algorithm::HS384 => JwtAlgorithm::HS384,
        Algorithm::HS512 => JwtAlgorithm::HS512,
        Algorithm::RS256 => JwtAlgorithm::RS256,
        Algorithm::RS384 => JwtAlgorithm::RS384,
        Algorithm::RS512 => JwtAlgorithm::RS512,
        Algorithm::ES256 => JwtAlgorithm::ES256,
        Algorithm::ES384 => JwtAlgorithm::ES384,
        Algorithm::PS256 => JwtAlgorithm::PS256,
        Algorithm::PS384 => JwtAlgorithm::PS384,
        Algorithm::PS512 => JwtAlgorithm::PS512,
        Algorithm::EdDSA => JwtAlgorithm::EdDSA,
    };

    let mut jwt_header = JwtHeader::new(alg);
    jwt_header.general_headers.typ = header.typ.clone();
    jwt_header.jwk_set_headers.jku = header.jku.clone();
    jwt_header.jwk_set_headers.kid = header.kid.clone();
    jwt_header.general_headers.cty = header.cty.clone();
    jwt_header.jwk_set_headers.jwk = jwk;

    let mut x509_headers = None;
    if header.x5u.is_some()
        || header.x5c.is_some()
        || header.x5t.is_some()
        || header.x5t_s256.is_some()
    {
        x509_headers = Some(Box::new(X509Headers {
            x5u: header.x5u.clone(),
            x5c: header.x5c.clone(),
            x5t: header.x5t.clone(),
            x5t_s256: header.x5t_s256.clone(),
        }));
    }
    jwt_header.x509_headers = x509_headers;

    Ok(jwt_header)
}

pub fn encode<T: Serialize>(
    header: &Header,
    claims: &T,
    key: &KeyForEncoding,
) -> Result<String, Error> {
    Ok(jwt_encode(&build_header(header)?, claims, &key.key)?)
}
