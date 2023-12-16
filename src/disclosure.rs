use crate::algorithm::{base64_hash, generate_salt, HashAlgorithm};
use crate::error::Error;
use base64::Engine;
use serde_json::Value;

const ARRAY_DISCLOSURE_LEN: usize = 2;
const OBJECT_DISCLOSURE_LEN: usize = 3;

#[derive(Debug, Clone)]
pub struct Disclosure {
    disclosure: String,
    digest: String,
    key: Option<String>,
    value: Value,
    salt_len: usize,
    algorithm: HashAlgorithm,
}

impl Disclosure {
    const DEFAULT_SALT_LEN: usize = 16;
    const DEFAULT_ALGORITHM: HashAlgorithm = HashAlgorithm::SHA256;

    pub fn new(key: Option<String>, value: Value) -> Self {
        Disclosure {
            disclosure: "".to_string(),
            digest: String::new(),
            key,
            value,
            salt_len: Disclosure::DEFAULT_SALT_LEN,
            algorithm: Disclosure::DEFAULT_ALGORITHM,
        }
    }

    pub fn salt_len(mut self, salt_len: usize) -> Self {
        self.salt_len = salt_len;
        self
    }

    pub fn algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn get_algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    pub fn build(self) -> Result<Disclosure, Error> {
        let mut parts: Vec<Value> = Vec::with_capacity(3);
        let salt = generate_salt(self.salt_len);
        parts.push(salt.into());

        match self.key.as_deref() {
            Some("_sd") | Some("...") => {
                return Err(Error::InvalidDisclosureKey(self.key.unwrap()));
            }
            Some(k) => parts.push(k.into()),
            None => {}
        }

        parts.push(self.value.clone());
        let disclosure =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&parts)?);
        let digest = base64_hash(self.algorithm, &disclosure);
        Ok(Disclosure {
            disclosure,
            digest,
            key: self.key,
            value: self.value,
            salt_len: self.salt_len,
            algorithm: self.algorithm,
        })
    }

    pub fn disclosure(&self) -> &str {
        &self.disclosure
    }

    pub fn digest(&self) -> &String {
        &self.digest
    }

    pub fn key(&self) -> &Option<String> {
        &self.key
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn from_base64(disclosure: &str, algorithm: HashAlgorithm) -> Result<Disclosure, Error> {
        let decoded_disclosure =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(disclosure)?;
        let decoded_disclosure = String::from_utf8(decoded_disclosure)?;

        let disclosure_json: Value = serde_json::from_str(decoded_disclosure.as_str())?;
        let disclosure_array = disclosure_json
            .as_array()
            .ok_or(Error::InvalidDisclosureFormat(disclosure.to_string()))?;
        match disclosure_array.len() {
            ARRAY_DISCLOSURE_LEN | OBJECT_DISCLOSURE_LEN => {
                reconstruct_disclosure(disclosure, algorithm, disclosure_array.as_slice())
            }
            _ => Err(Error::InvalidDisclosureFormat(disclosure.to_string())),
        }
    }
}

pub fn reconstruct_disclosure(
    disclosure: &str,
    algorithm: HashAlgorithm,
    disclosure_array: &[Value],
) -> Result<Disclosure, Error> {
    let digest = base64_hash(algorithm, disclosure);
    let key = if disclosure_array.len() == OBJECT_DISCLOSURE_LEN {
        Some(disclosure_array[1].as_str().unwrap_or_default().to_string())
    } else {
        None
    };
    let value = disclosure_array.last().unwrap().clone();

    Ok(Disclosure {
        disclosure: disclosure.to_string(),
        digest,
        key,
        value,
        salt_len: 0,
        algorithm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_disclosure() {
        let value = serde_json::json!({"test": "value"});
        let disclosure = Disclosure::new(Some("key".to_string()), value.clone());
        assert_eq!(disclosure.salt_len, Disclosure::DEFAULT_SALT_LEN);
        assert_eq!(disclosure.algorithm, Disclosure::DEFAULT_ALGORITHM);
        assert_eq!(disclosure.key, Some("key".to_string()));
        assert_eq!(disclosure.value, value);
    }

    #[test]
    fn test_salt_len_setter() {
        let salt_length = 32;
        let disclosure =
            Disclosure::new(Some("key".to_string()), serde_json::Value::Null).salt_len(salt_length);
        assert_eq!(disclosure.salt_len, salt_length);
    }

    #[test]
    fn test_algorithm_setter() {
        let algorithm = HashAlgorithm::SHA512;
        let disclosure =
            Disclosure::new(Some("key".to_string()), serde_json::Value::Null).algorithm(algorithm);
        assert_eq!(disclosure.algorithm, algorithm);
    }

    #[test]
    fn test_build_success() {
        let disclosure = Disclosure::new(Some("key".to_string()), serde_json::Value::Null).build();
        assert!(disclosure.is_ok());
    }

    #[test]
    fn test_build_invalid_key_error() {
        let disclosure = Disclosure::new(Some("_sd".to_string()), serde_json::Value::Null).build();
        assert!(disclosure.is_err());
    }

    #[test]
    fn test_disclosure_and_digest() {
        let disclosure = Disclosure::new(Some("".to_string()), serde_json::Value::Null)
            .build()
            .unwrap();
        assert!(!disclosure.disclosure().is_empty());
        assert!(!disclosure.digest().is_empty());
    }

    #[test]
    fn test_from_base64_for_object() {
        let disclosure = Disclosure::new(Some("key".to_string()), serde_json::json!("some value"))
            .build()
            .unwrap();
        println!("disclosure: {}", disclosure.disclosure());
        let disclosure_from_base64 =
            Disclosure::from_base64(disclosure.disclosure(), disclosure.algorithm).unwrap();
        assert_eq!(disclosure_from_base64.disclosure(), disclosure.disclosure());
        assert_eq!(disclosure_from_base64.digest(), disclosure.digest());
        assert_eq!(disclosure_from_base64.key, disclosure.key);
        assert_eq!(disclosure_from_base64.value, disclosure.value);
        assert_eq!(disclosure_from_base64.algorithm, disclosure.algorithm);
    }

    #[test]
    fn test_from_base64_for_array() {
        let disclosure = Disclosure::new(None, serde_json::json!("some value"))
            .build()
            .unwrap();
        println!("disclosure: {}", disclosure.disclosure());
        let disclosure_from_base64 =
            Disclosure::from_base64(disclosure.disclosure(), disclosure.algorithm).unwrap();
        assert_eq!(disclosure_from_base64.disclosure(), disclosure.disclosure());
        assert_eq!(disclosure_from_base64.digest(), disclosure.digest());
        assert_eq!(disclosure_from_base64.key, disclosure.key);
        assert_eq!(disclosure_from_base64.value, disclosure.value);
        assert_eq!(disclosure_from_base64.algorithm, disclosure.algorithm);
    }
}
