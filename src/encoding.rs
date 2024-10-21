use crate::Algorithm;
use crate::Error;
use crate::Header;
use jwt_rustcrypto::{
    encode as jwt_encode, Algorithm as JwtAlgorithm, Header as JwtHeader, SigningKey,
};

use serde::Serialize;

#[derive(Clone)]
pub struct KeyForEncoding {
    key: SigningKey,
}

impl KeyForEncoding {
    pub fn from_secret(secret: &[u8]) -> Self {
        KeyForEncoding {
            key: SigningKey::from_secret(secret),
        }
    }

    pub fn from_base64_secret(secret: &str) -> Result<Self, Error> {
        Ok(KeyForEncoding {
            key: SigningKey::from_base64_secret(secret)?,
        })
    }

    pub fn from_rsa_pem(key: &[u8]) -> Result<Self, Error> {
        Ok(KeyForEncoding {
            key: SigningKey::from_rsa_pem(key)?,
        })
    }

    pub fn from_ec_pem(key: &[u8]) -> Result<Self, Error> {
        Ok(KeyForEncoding {
            key: SigningKey::from_ec_pem(key)?,
        })
    }

    pub fn from_ed_pem(key: &[u8]) -> Result<Self, Error> {
        Ok(KeyForEncoding {
            key: SigningKey::from_ed_pem(key)?,
        })
    }

    pub fn from_rsa_der(der: &[u8]) -> Result<Self, Error> {
        Ok(KeyForEncoding {
            key: SigningKey::from_rsa_der(der)?,
        })
    }

    pub fn from_ec_der(der: &[u8]) -> Result<Self, Error> {
        Ok(KeyForEncoding {
            key: SigningKey::from_ec_der(der)?,
        })
    }

    pub fn from_ed_der(der: &[u8]) -> Result<Self, Error> {
        Ok(KeyForEncoding {
            key: SigningKey::from_ed_der(der)?,
        })
    }
}

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
            Algorithm::ES256K => JwtAlgorithm::ES256K,
            Algorithm::ES384 => JwtAlgorithm::ES384,
            Algorithm::ES512 => JwtAlgorithm::ES512,
            Algorithm::PS256 => JwtAlgorithm::PS256,
            Algorithm::PS384 => JwtAlgorithm::PS384,
            Algorithm::PS512 => JwtAlgorithm::PS512,
            // Algorithm::EdDSA => JwtAlgorithm::EdDSA,
        },
        cty: header.cty.clone(),
        jku: header.jku.clone(),
        jwk,
        kid: header.kid.clone(),
        x5u: header.x5u.clone(),
        x5c: header.x5c.clone(),
        x5t: header.x5t.clone(),
        x5t_s256: header.x5t_s256.clone(),
        crit: header.crit.clone(),
    })
}

pub fn encode<T: Serialize>(
    header: &Header,
    claims: &T,
    key: &KeyForEncoding,
) -> Result<String, Error> {
    Ok(jwt_encode(&build_header(header)?, &key.key, claims)?)
}
