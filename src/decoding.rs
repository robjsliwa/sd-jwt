use crate::{Algorithm, Error, Validation};
use jwt_rustcrypto::{
    decode as jwt_decode, Algorithm as JwtAlgorithm, ValidationOptions as JwtValidation,
    VerifyingKey,
};
use serde_json::Value;

pub struct KeyForDecoding {
    key: VerifyingKey,
}

impl KeyForDecoding {
    pub fn from_secret(secret: &[u8]) -> Self {
        KeyForDecoding {
            key: VerifyingKey::from_secret(secret),
        }
    }

    pub fn from_base64_secret(secret: &str) -> Result<Self, Error> {
        Ok(KeyForDecoding {
            key: VerifyingKey::from_base64_secret(secret)?,
        })
    }

    pub fn from_rsa_pem(key: &[u8]) -> Result<Self, Error> {
        Ok(KeyForDecoding {
            key: VerifyingKey::from_rsa_pem(key)?,
        })
    }

    pub fn from_rsa_components(modulus: &[u8], exponent: &[u8]) -> Result<Self, Error> {
        Ok(KeyForDecoding {
            key: VerifyingKey::from_rsa_components(modulus, exponent)?,
        })
    }

    pub fn from_ec_pem(key: &[u8]) -> Result<Self, Error> {
        Ok(KeyForDecoding {
            key: VerifyingKey::from_ec_pem(key)?,
        })
    }

    // pub fn from_ed_pem(key: &[u8]) -> Result<Self, Error> {
    //     Ok(KeyForDecoding {
    //         key: DecodingKey::from_ed_pem(key)?,
    //     })
    // }

    pub fn from_rsa_der(der: &[u8]) -> Result<Self, Error> {
        Ok(KeyForDecoding {
            key: VerifyingKey::from_rsa_der(der)?,
        })
    }

    pub fn from_ec_der(der: &[u8]) -> Result<Self, Error> {
        Ok(KeyForDecoding {
            key: VerifyingKey::from_ec_der(der)?,
        })
    }

    pub fn from_ed_der(der: &[u8]) -> Result<Self, Error> {
        Ok(KeyForDecoding {
            key: VerifyingKey::from_ed_der(der)?,
        })
    }
}

fn build_validation(validation: &Validation) -> JwtValidation {
    let mut valid = JwtValidation::new(match validation.algorithms {
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
    });

    valid.required_claims = validation.required_spec_claims.clone();
    valid.leeway = validation.leeway;
    valid.validate_exp = validation.validate_exp;
    valid.validate_nbf = validation.validate_nbf;
    valid.audiences = validation.aud.clone();
    valid.issuer = validation.iss.clone();
    valid
}

pub fn decode(
    token: &str,
    key: &KeyForDecoding,
    validation: &Validation,
) -> Result<(Value, Value), Error> {
    let validation = build_validation(validation);
    let token_data = jwt_decode(token, &key.key, &validation)?;
    let header: Value = serde_json::from_str(&serde_json::to_string(&token_data.header)?)?;
    Ok((header, token_data.payload))
}

pub fn sd_jwt_parts(serialized_jwt: &str) -> (String, Vec<String>, Option<String>) {
    let parts: Vec<&str> = serialized_jwt.split('~').collect();

    let issuer_jwt = parts[0].to_string();

    let disclosures = parts[1..parts.len() - 1]
        .iter()
        .map(|s| s.to_string())
        .collect();

    let key_binding_jwt = if !parts[parts.len() - 1].is_empty() {
        Some(parts[parts.len() - 1].to_string())
    } else {
        None
    };

    (issuer_jwt, disclosures, key_binding_jwt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::signature::Keypair;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;

    const TEST_CLAIMS: &str = r#"{
        "sub": "user_42",
        "given_name": "John",
        "family_name": "Doe",
        "email": "johndoe@example.com",
        "phone_number": "+1-202-555-0101",
        "phone_number_verified": true,
        "address": {
            "street_address": "123 Main St",
            "locality": "Anytown",
            "region": "Anystate",
            "country": "US"
        },
        "birthdate": "1940-01-01",
        "updated_at": 1570000000,
        "nationalities": [
            "US",
            "DE"
        ]
    }"#;

    fn keys() -> (RsaPrivateKey, RsaPublicKey) {
        let mut rng = rand::thread_rng();

        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let signing_key = SigningKey::<Sha256>::new(private_key.clone());
        let public_key = signing_key.verifying_key().into();

        (private_key, public_key)
    }

    fn convert_to_pem(private_key: RsaPrivateKey, public_key: RsaPublicKey) -> (String, String) {
        (
            private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string(),
            public_key
                .to_public_key_pem(rsa::pkcs1::LineEnding::LF)
                .unwrap(),
        )
    }

    #[test]
    fn test_basic_decode() -> Result<(), Error> {
        let (priv_key, pub_key) = keys();
        let (issuer_private_key, issuer_public_key) = convert_to_pem(priv_key, pub_key);
        println!("issuer_private_key: {:?}", issuer_private_key);
        println!("issuer_public_key: {:?}", issuer_public_key);
        let mut claims: Value = serde_json::from_str(TEST_CLAIMS).unwrap();
        let now = Utc::now();
        let expiration = now + Duration::minutes(5);
        let exp = expiration.timestamp();
        claims["exp"] = serde_json::json!(exp);
        let mut issuer = crate::Issuer::new(claims)?;
        let encoded = issuer
            .disclosable("/given_name")
            .disclosable("/family_name")
            .disclosable("/address/street_address")
            .disclosable("/address/locality")
            .disclosable("/nationalities/0")
            .disclosable("/nationalities/1")
            .encode(&crate::KeyForEncoding::from_rsa_pem(
                issuer_private_key.as_bytes(),
            )?)?;
        println!("encoded: {:?}", encoded);
        let dot_segments = encoded.split('.').count();
        let disclosure_segments = encoded.split('~').count() - 2;

        assert_eq!(dot_segments, 3);
        assert_eq!(disclosure_segments, 6);

        // get issuer JWT by splitting left part of the string at the first ~
        let issuer_jwt = encoded.split('~').next().unwrap();
        // println!("issuer_jwt: {:?}", issuer_jwt);
        let (header, claims) = decode(
            issuer_jwt,
            &KeyForDecoding::from_rsa_pem(issuer_public_key.as_bytes()).unwrap(),
            &Validation::default(),
        )?;
        println!("header: {:?}", header);
        println!("claims: {:?}", claims);

        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "sd-jwt");
        assert_eq!(claims["sub"], "user_42");
        assert!(claims["_sd"].is_array());
        assert_eq!(claims["_sd"].as_array().unwrap().len(), 2);
        assert!(claims["address"]["_sd"].is_array());
        assert_eq!(claims["address"]["_sd"].as_array().unwrap().len(), 2);
        assert_eq!(claims["_sd_alg"], "sha-256");
        assert!(claims["nationalities"].is_array());
        assert_eq!(claims["nationalities"].as_array().unwrap().len(), 2);
        assert!(claims["nationalities"][0].is_object());
        assert!(claims["nationalities"][1].is_object());
        Ok(())
    }
}
