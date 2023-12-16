use crate::Algorithm;
use crate::Error;
use crate::Header;
use jsonwebtoken::EncodingKey;
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

    pub fn from_rsa_pem(key: &[u8]) -> Result<Self, Error> {
        Ok(KeyForEncoding {
            key: EncodingKey::from_rsa_pem(key)?,
        })
    }

    pub fn from_ec_pem(key: &[u8]) -> Result<Self, Error> {
        Ok(KeyForEncoding {
            key: EncodingKey::from_ec_pem(key)?,
        })
    }

    pub fn from_ed_pem(key: &[u8]) -> Result<Self, Error> {
        Ok(KeyForEncoding {
            key: EncodingKey::from_ed_pem(key)?,
        })
    }

    pub fn from_rsa_der(der: &[u8]) -> Self {
        KeyForEncoding {
            key: EncodingKey::from_rsa_der(der),
        }
    }

    pub fn from_ec_der(der: &[u8]) -> Self {
        KeyForEncoding {
            key: EncodingKey::from_ec_der(der),
        }
    }

    pub fn from_ed_der(der: &[u8]) -> Self {
        KeyForEncoding {
            key: EncodingKey::from_ed_der(der),
        }
    }
}

fn build_header(header: &Header) -> Result<jsonwebtoken::Header, Error> {
    let jwk = match &header.jwk {
        Some(jwk) => Some(serde_json::from_value(jwk.clone())?),
        None => None,
    };
    Ok(jsonwebtoken::Header {
        typ: header.typ.clone(),
        alg: match header.alg {
            Algorithm::HS256 => jsonwebtoken::Algorithm::HS256,
            Algorithm::HS384 => jsonwebtoken::Algorithm::HS384,
            Algorithm::HS512 => jsonwebtoken::Algorithm::HS512,
            Algorithm::RS256 => jsonwebtoken::Algorithm::RS256,
            Algorithm::RS384 => jsonwebtoken::Algorithm::RS384,
            Algorithm::RS512 => jsonwebtoken::Algorithm::RS512,
            Algorithm::ES256 => jsonwebtoken::Algorithm::ES256,
            Algorithm::ES384 => jsonwebtoken::Algorithm::ES384,
            Algorithm::PS256 => jsonwebtoken::Algorithm::PS256,
            Algorithm::PS384 => jsonwebtoken::Algorithm::PS384,
            Algorithm::PS512 => jsonwebtoken::Algorithm::PS512,
            Algorithm::EdDSA => jsonwebtoken::Algorithm::EdDSA,
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

pub fn encode<T: Serialize>(
    header: &Header,
    claims: &T,
    key: &KeyForEncoding,
) -> Result<String, Error> {
    Ok(jsonwebtoken::encode(
        &build_header(header)?,
        claims,
        &key.key,
    )?)
}
