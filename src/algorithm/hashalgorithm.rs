use crate::Error;
use base64::Engine;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::convert::TryFrom;
use std::fmt;

pub(crate) fn generate_salt(len: usize) -> String {
    let mut salt = vec![0u8; len];
    thread_rng().fill(&mut salt[..]);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(salt)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    SHA256,
    SHA384,
    SHA512,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::SHA256 => write!(f, "sha-256"),
            HashAlgorithm::SHA384 => write!(f, "sha-384"),
            HashAlgorithm::SHA512 => write!(f, "sha-512"),
        }
    }
}

impl TryFrom<&str> for HashAlgorithm {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "sha-256" => Ok(HashAlgorithm::SHA256),
            "sha-384" => Ok(HashAlgorithm::SHA384),
            "sha-512" => Ok(HashAlgorithm::SHA512),
            _ => Err(Error::InvalidHashAlgorithm(s.to_string())),
        }
    }
}

enum Hasher {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::SHA256 => Hasher::Sha256(Sha256::new()),
            HashAlgorithm::SHA384 => Hasher::Sha384(Sha384::new()),
            HashAlgorithm::SHA512 => Hasher::Sha512(Sha512::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(hasher) => hasher.update(data),
            Hasher::Sha384(hasher) => hasher.update(data),
            Hasher::Sha512(hasher) => hasher.update(data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            Hasher::Sha256(hasher) => hasher.finalize().to_vec(),
            Hasher::Sha384(hasher) => hasher.finalize().to_vec(),
            Hasher::Sha512(hasher) => hasher.finalize().to_vec(),
        }
    }
}

pub fn base64_hash(algorithm: HashAlgorithm, data: &str) -> String {
    let mut hasher = Hasher::new(algorithm);

    hasher.update(&data.to_string().into_bytes());
    let hash = hasher.finalize();

    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_salt() {
        let len = 16;
        let salt = generate_salt(len);
        // Length of base64 encoded string without padding
        let expected_length = 4 * ((len + 2) / 3) - 2;
        assert_eq!(salt.len(), expected_length);
        // Ensure randomness
        assert_ne!(generate_salt(len), generate_salt(len));
    }

    #[test]
    fn test_hasher_new() {
        if let Hasher::Sha256(_) = Hasher::new(HashAlgorithm::SHA256) {
        } else {
            panic!("Expected Sha256");
        }
        if let Hasher::Sha384(_) = Hasher::new(HashAlgorithm::SHA384) {
        } else {
            panic!("Expected Sha384");
        }
        if let Hasher::Sha512(_) = Hasher::new(HashAlgorithm::SHA512) {
        } else {
            panic!("Expected Sha512");
        }
    }

    #[test]
    fn test_hasher_update_finalize() {
        let mut hasher = Hasher::new(HashAlgorithm::SHA256);
        hasher.update(b"hello world");
        let hash = hasher.finalize();
        let expected_hash = Sha256::digest(b"hello world");
        assert_eq!(hash, expected_hash.to_vec());

        let mut hasher = Hasher::new(HashAlgorithm::SHA384);
        hasher.update(b"hello world");
        let hash = hasher.finalize();
        let expected_hash = Sha384::digest(b"hello world");
        assert_eq!(hash, expected_hash.to_vec());

        let mut hasher = Hasher::new(HashAlgorithm::SHA512);
        hasher.update(b"hello world");
        let hash = hasher.finalize();
        let expected_hash = Sha512::digest(b"hello world");
        assert_eq!(hash, expected_hash.to_vec());
    }

    #[test]
    fn test_create_hash() {
        let data = "hello world";
        let hash = base64_hash(HashAlgorithm::SHA256, data);
        let expected_hash = Sha256::digest(data.as_bytes());
        let expected_base64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected_hash);
        assert_eq!(hash, expected_base64);

        let data = "hello world";
        let hash = base64_hash(HashAlgorithm::SHA384, data);
        let expected_hash = Sha384::digest(data.as_bytes());
        let expected_base64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected_hash);
        assert_eq!(hash, expected_base64);

        let data = "hello world";
        let hash = base64_hash(HashAlgorithm::SHA512, data);
        let expected_hash = Sha512::digest(data.as_bytes());
        let expected_base64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected_hash);
        assert_eq!(hash, expected_base64);
    }
}
