use crate::{Disclosure, DisclosurePath, Error, HashAlgorithm};
use base64::Engine;
use rand::{distributions::Alphanumeric, Rng};
use serde_json::Value;

#[allow(dead_code)]
pub(crate) enum JWTPart {
    Header,
    Claims,
    Signature,
}

pub(crate) fn get_jwt_part(jwt: &str, part: JWTPart) -> Result<String, Error> {
    let parts: Vec<&str> = jwt.split('.').collect();

    if parts.len() != 3 {
        return Err(Error::JwtMustHaveThreeParts);
    }

    match part {
        JWTPart::Header => Ok(parts[0].to_string()),
        JWTPart::Claims => Ok(parts[1].to_string()),
        JWTPart::Signature => Ok(parts[2].to_string()),
    }
}

pub(crate) fn decode_claims_no_verification(claims: &str) -> Result<Value, Error> {
    let decoded_claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(claims)?;
    let decoded_claims = String::from_utf8(decoded_claims)?;
    let claims: Value = serde_json::from_str(decoded_claims.as_str())?;
    Ok(claims)
}

pub(crate) fn drop_kb(input: &str) -> String {
    let parts = input.split('~').collect::<Vec<&str>>();

    if parts.len() < 2 {
        return String::from(input);
    }

    let filtered_parts = &parts[..parts.len() - 1];

    format!("{}~", filtered_parts.join("~"))
}

pub(crate) fn restore_disclosures(
    claims: &mut Value,
    disclosures: &[String],
    disclosure_paths: &mut Vec<DisclosurePath>,
    algorithm: HashAlgorithm,
) -> Result<(), Error> {
    for disclosure in disclosures {
        let decoded_disclosure = Disclosure::from_base64(disclosure, algorithm)?;
        restore_disclosure(claims, &decoded_disclosure, String::new(), disclosure_paths)?;
    }

    Ok(())
}

pub(crate) fn sd_contains_digest(sd: &Value, digest: &str) -> Result<bool, Error> {
    let sd_array = sd
        .as_array()
        .ok_or_else(|| Error::SDJWTRejected("_sd element must be array".to_string()))?;
    Ok(sd_array.iter().any(|item| item.as_str() == Some(digest)))
}

pub(crate) fn remove_digests(claims: &mut Value) -> Result<(), Error> {
    if let Value::Object(ref mut map) = claims {
        map.remove("_sd_alg");
    }
    remove_all_digests(claims)
}

pub(crate) fn remove_all_digests(claims: &mut Value) -> Result<(), Error> {
    match claims {
        Value::Object(map) => {
            let keys_to_remove: Vec<_> = map.keys().filter(|&k| k == "_sd").cloned().collect();
            for k in keys_to_remove {
                map.remove(&k);
            }

            for value in map.values_mut() {
                remove_all_digests(value)?;
            }
        }
        Value::Array(array) => {
            array.retain(|item| {
                !(item.is_object() && item.get("...").map_or(false, |v| v.is_string()))
            });

            for item in array.iter_mut() {
                remove_all_digests(item)?;
            }
        }
        _ => {}
    }

    Ok(())
}
pub(crate) fn format_path(parent_path: &str, key: &str) -> String {
    if parent_path.is_empty() {
        format!("/{}", key)
    } else {
        format!("{}/{}", parent_path, key)
    }
}

pub(crate) fn restore_disclosure(
    claims: &mut Value,
    disclosure: &Disclosure,
    current_path: String,
    disclosure_paths: &mut Vec<DisclosurePath>,
) -> Result<bool, Error> {
    let mut array_changes = Vec::new();
    let mut is_restored = false;

    match claims {
        Value::Object(map) => {
            if let Some(sd) = map.get_mut("_sd") {
                if sd_contains_digest(sd, disclosure.digest())? {
                    if let Some(key) = disclosure.key() {
                        let path = format_path(&current_path, key);
                        disclosure_paths.push(DisclosurePath::new(&path, disclosure));
                        map.insert(key.to_string(), disclosure.value().clone());
                        is_restored = true;
                    } else {
                        return Err(Error::SDJWTRejected(
                            "Disclosure key is missing".to_string(),
                        ));
                    }
                }
            }

            for (key, value) in map.iter_mut() {
                let path = format_path(&current_path, key);
                if restore_disclosure(value, disclosure, path, disclosure_paths)? {
                    is_restored = true;
                }
            }
        }
        Value::Array(array) => {
            for (idx, item) in array.iter_mut().enumerate() {
                if item.is_object() {
                    let value = item.as_object().unwrap().get("...");
                    if value.is_some() && item.as_object().unwrap().len() != 1 {
                        return Err(Error::SDJWTRejected(
                            ("... key must be only key in object").to_string(),
                        ));
                    }

                    if let Some(v) = value {
                        if v == disclosure.digest() {
                            if !disclosure.key().is_none() {
                                return Err(Error::SDJWTRejected(format!(
                                    "disclosure key must be empty in {} for array elements",
                                    disclosure.disclosure(),
                                )));
                            }
                            let path = format_path(&current_path, &idx.to_string());
                            disclosure_paths.push(DisclosurePath::new(&path, disclosure));
                            array_changes.push(disclosure.value().clone());
                            is_restored = true;
                        }
                    }
                }
            }
            for elem in array_changes {
                array.push(elem);
            }
        }
        _ => {}
    }

    Ok(is_restored)
}

pub(crate) fn generate_nonce(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}
