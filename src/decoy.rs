use crate::algorithm::{base64_hash, HashAlgorithm};
use crate::Error;
use rand::{Rng, SeedableRng, rngs::StdRng};

#[derive(Debug, Clone)]
pub struct Decoy {
    digest: String,
    algorithm: HashAlgorithm,
}

impl Decoy {
    const DEFAULT_ALGORITHM: HashAlgorithm = HashAlgorithm::SHA256;

    pub fn new() -> Self {
        Decoy {
            digest: String::new(),
            algorithm: Decoy::DEFAULT_ALGORITHM,
        }
    }

    pub fn build(self) -> Result<Decoy,Error> {
        let seed: [u8; 32] = rand::random();
        let mut rng = StdRng::from_seed(seed);
        let random_number: u32 = rng.gen();

        let digest = base64_hash(self.algorithm, &random_number.to_string());

        Ok(Decoy {
            digest,
            algorithm: self.algorithm,
        })
    }

    pub fn digest(&self) -> &String {
        &self.digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_algorothm() {
        let decoy = Decoy::new();
        assert_eq!(decoy.algorithm, HashAlgorithm::SHA256);
    }

    #[test]
    fn test_build() {
        let decoy = Decoy::new().build().unwrap();
        assert!(!decoy.digest.is_empty());
    }

    #[test]
    fn test_random_digest() {
        let decoy1 = Decoy::new().build().unwrap();
        let decoy2 = Decoy::new().build().unwrap();
        assert_ne!(decoy1.digest(), decoy2.digest());
    }

}