use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::signature::Keypair;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::value::{Map, Value};
use sha2::Sha256;
use std::collections::HashSet;

pub fn keys() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng();

    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let public_key = signing_key.verifying_key().into();

    (private_key, public_key)
}

pub fn convert_to_pem(private_key: RsaPrivateKey, public_key: RsaPublicKey) -> (String, String) {
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

pub fn publickey_to_jwk(public_key: &RsaPublicKey) -> serde_json::Value {
    let n = public_key.n().to_bytes_be();
    let e = public_key.e().to_bytes_be();

    serde_json::json!({
        "kty": "RSA",
        "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n),
        "e": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(e),
        "alg": "RS256",
        "use": "sig",
    })
}

pub fn compare_json_values(json1: &Value, json2: &Value) -> bool {
    match (json1, json2) {
        (Value::Object(map1), Value::Object(map2)) => compare_json_maps(map1, map2),
        (Value::Array(arr1), Value::Array(arr2)) => compare_json_arrays(arr1, arr2),
        _ => json1 == json2,
    }
}

pub fn compare_json_maps(map1: &Map<String, Value>, map2: &Map<String, Value>) -> bool {
    if map1.len() != map2.len() {
        return false;
    }

    map1.iter().all(|(key, val1)| {
        map2.get(key)
            .map_or(false, |val2| compare_json_values(val1, val2))
    })
}

pub fn compare_json_arrays(arr1: &[Value], arr2: &[Value]) -> bool {
    if arr1.len() != arr2.len() {
        return false;
    }

    let mut matched_indices = HashSet::new();

    for val1 in arr1 {
        let mut is_matched = false;

        for (index, val2) in arr2.iter().enumerate() {
            if !matched_indices.contains(&index) && compare_json_values(val1, val2) {
                is_matched = true;
                matched_indices.insert(index);
                break;
            }
        }

        if !is_matched {
            return false;
        }
    }

    true
}

pub fn separate_jwt_and_disclosures(input: &str) -> (String, String) {
    let parts: Vec<&str> = input.splitn(2, '~').collect();
    if parts.len() == 2 {
        (parts[0].to_string(), parts[1].to_string())
    } else {
        (input.to_string(), "".to_string())
    }
}

pub fn disclosures2vec(disclosures: &str) -> Vec<String> {
    let parts: Vec<&str> = disclosures.split('~').collect();
    if parts.is_empty() {
        return Vec::new();
    }
    parts[..parts.len() - 1]
        .iter()
        .map(|&s| s.to_string())
        .collect()
}
