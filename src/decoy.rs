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
