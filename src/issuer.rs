use crate::decoy::Decoy;
use crate::Disclosure;
use crate::Error;
use crate::Header;
use crate::Jwk;
use crate::{encode, KeyForEncoding};
use chrono::{Duration, Utc};
use core::slice::Iter;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::Serialize;
use serde_json::Value;
use std::ops::Deref;
use std::vec;

/// # Issuer Module
///
/// Represents an issuer of claims.  Issues SD-JWT with all disclosures.
///
/// ## Features
///
/// - Creating new issuers with custom claims.
/// - Marking claims as disclosable.
/// - Optionally requiring a key binding.
/// - Encoding the issuer's claims into a SD-JWT.
///
/// Example:
/// ```
/// use sdjwt::{Issuer, Jwk, Error, KeyForEncoding};
/// use serde_json::Value;
///
/// const ISSUER_CLAIMS: &str = r#"{
/// "sub": "user_42",
/// "given_name": "John",
/// "family_name": "Doe",
/// "email": "johndoe@example.com",
/// "phone_number": "+1-202-555-0101",
/// "phone_number_verified": true,
/// "address": {
///     "street_address": "123 Main St",
///     "locality": "Anytown",
///     "region": "Anystate",
///     "country": "US"
/// },
/// "birthdate": "1940-01-01",
/// "updated_at": 1570000000,
/// "nationalities": [
///     "US",
///     "DE"
/// ]
/// }"#;
///
/// const ISSUER_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDSwzyVZp2AIxS3\n802n0AfwKsMUcMYATMM6kK5VVS21ku3d6QC8kfhvJ0Pcb24dmGUWAJ95H9m19qDF\nbLrVZ9b4iobOsNlXNhKn4TRrsVFa8EaGXAJjGNRPPcL+gFwfV9y3tfR00tkokhR5\nZhhMifwKJf55QlEzY96yyk8ISzhagwO6Kf/E980Eoby1tvhX8q8HIwLG4GjFnmXx\nbKqxVQR1T07vFKHsF1MK8/d6a7+samHPWjoSlLvKSE4rdK8gouRpN/5Who4iS2s7\nlhfS2DcnxCnxj9S9BBm4GIQNk0Tc+lR20btBm+JiehAyEV9vX222BVSLUC9z9HGD\nk39b9ezbAgMBAAECggEBAIXuRxtxX/jDUjEqzVgsXD8EDX95wnkCTrVypzXWsPtH\naRyxKiSqZcLMotT7gnAQHXyD3NMtqD13geazF27xU6wQ62WBADvpQqWn+JXO0jIF\nqetLoMC0UIYiaz0q+F96h+m+GJ/8NL8RRS138U0CCkWwqysHN25+sk/PO7W7hw4M\nOAN/97rBkXqyzJJSvNwl2A66ga+9WC8G/9YgweqkS6re6WAyo4z1KyZAE1r655JR\nEaiIR6GYvahNsy/dNjVtGR189o8bf6xnTPbDUXQ/D61nO3Kg3B7Ca/uQWiDbI9VJ\nMXZxgip9Q7Qil9WuK1vVCUSf6WK38NV6r9fubw/DgsECgYEA70drCiGrC3pvIJF0\nLJL46H6x6SFClR876BZEnN51udJGXRstWV+Ya6NULSTykwusaTYUnr2BC6r3tT4S\nrRLfnXTaI0Tr6Bws6kBSJJC0CS0lLqK2tlKbcypQXv0T6Ulv2NXDq0VqQB3txED6\n8m5GieppHNueqLQqGqM1V4JYw5ECgYEA4X2s7ccLB8MX01j4T6Fnj4BGaZsyc1kV\nn6VHsuAsUxA9ZuwV+lk5k6xaWxDYmQR3xZ4XcQEntRUtGFu4TMLVpCcK26Vqafrp\nymbGjJGFagIaP9YOhQ+5ZMfO0obYUEaDGhPjXH3G9O/dTXoRg5nP5JvdcAnf853y\nm1BaYBHbG6sCgYAfVkQffI9RHoTFSCdl2w28LTORq6hzrTaES75KqRvT7UUH1pJW\n3R0yI57XlroqJeI7mTiUHY9z/r0YQHvjrNAaZ/5VliYrLN15BFl9rnHVrdLry6WQ\nNTtklssV1aEw8UwzorNQj/O9V+4WwMfczjJwx4FipSSfRZEqEevffROw8QKBgGNK\nba0+KjM+yuz7jkuyLOHZgCfcePilz4m+w7WWVK42xnLdnkfgpiPKjvbukhG/D+Zq\n2LOf6JYqPvMs4Bic6mof7v4M9rC4Fd5UJzWaln65ckmNvlMFO4OPIBk/21xt0CjZ\nfRIrKEKOpIoLKE8kmZB2uakuD/k8IaoWVdVbx3mFAoGAMFFWZAAHpB18WaATQRR6\n86JnudPD3TlOw+8Zw4tlOoGv4VXCPVsyAH8CWNSONyTRxeSJpe8Pn6ZvPJ7YBt6c\nchNSaqFIl9UnkMJ1ckE7EX2zKFCg3k8VzqYRLC9TcqqwKTJcNdRu1SbWkAds6Sd8\nKKRrCm+L44uQ01gUYvYYv5c=\n-----END PRIVATE KEY-----\n";
///
/// fn main() -> Result<(), Error> {
///    // holder's public key required for key binding
///    let holder_jwk = Jwk::from_value(serde_json::json!({
///         "kty": "RSA",
///         "n": "...",
///         "e": "...",
///         "alg": "RS256",
///         "use": "sig",
///    }))?;
///
///    // create issuer's claims
///    let claims: Value = serde_json::from_str(ISSUER_CLAIMS).unwrap();
///    let issuer = Issuer::new(claims)?
///      .disclosable("/given_name")
///      .disclosable("/family_name")
///      .disclosable("/address/street_address")
///      .disclosable("/address/locality")
///      .disclosable("/nationalities/0")
///      .disclosable("/nationalities/1")
///      .require_key_binding(holder_jwk)
///      .encode(&KeyForEncoding::from_rsa_pem(
///         ISSUER_SIGNING_KEY_PEM.as_bytes(),
///      )?)?;
///
///    Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Issuer {
    claims: Value,
    disclosable_claim_paths: Vec<String>,
    header: Header,
    key_binding_pubkey: Option<Jwk>,
    max_decoys: Option<i32>,
}

impl Issuer {
    /// Creates a new `Issuer` with the given claims.
    ///
    /// # Arguments
    ///
    /// * `claims` - A serializable object that represents the claims to be included in the SD-JWT.
    ///
    /// # Returns
    ///
    /// A result containing the new `Issuer` instance, or an error if the claims cannot be serialized.
    ///
    /// # Examples
    ///
    /// ```
    /// use sdjwt::Issuer;
    ///
    /// let claims = serde_json::json!({
    ///    "sub": "user_42",
    ///    "given_name": "John",
    ///    "family_name": "Doe",
    ///    "email": "johndoe@example",
    /// });
    /// let issuer = Issuer::new(claims).unwrap();
    /// ```
    pub fn new<T: Serialize>(claims: T) -> Result<Self, Error> {
        Ok(Issuer {
            claims: serde_json::to_value(claims)?,
            disclosable_claim_paths: Vec::new(),
            header: Header::default(),
            key_binding_pubkey: None,
            max_decoys: None,
        })
    }

    /// Marks claim as disclosable.
    ///
    /// # Arguments
    ///
    /// * `path` - A string slice representing the path to a claim that can be disclosed.
    ///
    /// # Returns
    ///
    /// A mutable reference to the issuer for method chaining.
    ///
    /// # Examples
    ///
    /// ```
    /// use sdjwt::Issuer;
    ///
    /// let claims = serde_json::json!({
    ///    "sub": "user_42",
    ///    "given_name": "John",
    ///    "family_name": "Doe",
    ///    "email": "johndoe@example",
    ///    "address": {
    ///       "street_address": "123 Main St",
    ///       "locality": "Anytown",
    ///       "region": "Anystate",
    ///       "country": "US"
    ///   },
    ///   "nationalities": [
    ///      "US",
    ///      "DE"
    ///   ]
    /// });
    ///
    /// let issuer = Issuer::new(claims).unwrap()
    ///     .disclosable("/given_name")
    ///     .disclosable("/family_name")
    ///     .disclosable("/address/street_address")
    ///     .disclosable("/address/locality")
    ///     .disclosable("/nationalities/0")
    ///     .disclosable("/nationalities/1");
    /// ```
    pub fn disclosable(&mut self, path: &str) -> &mut Self {
        self.disclosable_claim_paths.push(path.to_string());
        self
    }

    /// Adds a random number of decoys to payload
    ///
    /// # Arguments
    ///
    /// * `max_decoys` - An integer representing the maximum number of decoys to add to the payload.
    ///
    /// # Returns
    ///
    /// A mutable reference to the issuer for method chaining.
    ///
    /// # Examples
    ///
    /// ```
    /// use sdjwt::Issuer;
    ///
    /// let claims = serde_json::json!({
    ///    "sub": "user_42",
    ///    "given_name": "John",
    ///    "family_name": "Doe",
    ///    "email": "johndoe@example",
    /// });
    ///
    /// let issuer = Issuer::new(claims).unwrap()
    ///     .decoy(6);
    /// ```
    pub fn decoy(&mut self, max_decoys: i32) -> &mut Self {
        self.max_decoys = Some(max_decoys);
        self
    }

    /// Sets the header for the issuer's SD-JWT.
    ///
    /// # Arguments
    ///
    /// * `header` - The `Header` struct representing the JWT header.
    ///
    /// # Returns
    ///
    /// A mutable reference to the issuer for method chaining.
    ///
    /// # Examples
    ///
    /// ```
    /// use sdjwt::{Issuer, Header};
    ///
    /// let mut header = Header::default();
    /// header.typ = Some("application/example+sd-jwt".to_string());
    /// let claims = serde_json::json!({
    ///    "sub": "user_42",
    ///    "given_name": "John",
    ///    "family_name": "Doe",
    ///    "email": "johndoe@example",
    /// });
    /// let issuer = Issuer::new(claims).unwrap()
    ///    .header(header);
    /// ```
    pub fn header(&mut self, header: Header) -> &mut Self {
        self.header = header;
        self
    }

    /// Sets the expiration time of the issuer's SD-JWT.
    ///
    /// # Arguments
    ///
    /// * `seconds` - The number of seconds from now until the token expires.
    ///
    /// # Returns
    ///
    /// A mutable reference to the issuer for method chaining.
    ///
    /// # Examples
    ///
    /// ```
    /// use sdjwt::Issuer;
    ///
    /// let claims = serde_json::json!({
    ///    "sub": "user_42",
    ///    "given_name": "John",
    ///    "family_name": "Doe",
    ///    "email": "johndoe@example",
    /// });
    /// let issuer = Issuer::new(claims).unwrap()
    ///     .expires_in_seconds(3600); // Expires in one hour
    /// ```
    pub fn expires_in_seconds(&mut self, seconds: i64) -> &mut Self {
        let now = Utc::now();
        let expiration = now + Duration::seconds(seconds);
        let exp = expiration.timestamp();
        self.claims["exp"] = serde_json::json!(exp);
        self
    }

    /// Requires a key binding for Holder.
    ///
    /// # Arguments
    ///
    /// * `key_binding_pubkey` - A `Jwk` representing the public key to bind to the JWT.
    ///
    /// # Returns
    ///
    /// A mutable reference to the issuer for method chaining.
    ///
    /// # Examples
    ///
    /// ```
    /// use sdjwt::{Issuer, Jwk};
    ///
    /// let claims = serde_json::json!({
    ///    "sub": "user_42",
    ///    "given_name": "John",
    ///    "family_name": "Doe",
    ///    "email": "johndoe@example",
    /// });
    ///
    /// let holder_jwk = Jwk::from_value(serde_json::json!({
    ///     "kty": "RSA",
    ///     "n": "...",
    ///     "e": "...",
    ///     "alg": "RS256",
    ///     "use": "sig",
    /// })).unwrap();
    /// let issuer = Issuer::new(claims).unwrap()
    ///     .require_key_binding(holder_jwk);
    /// ```
    pub fn require_key_binding(&mut self, key_binding_pubkey: Jwk) -> &mut Self {
        self.key_binding_pubkey = Some(key_binding_pubkey);
        self
    }

    /// Marks claims as disclosable.
    /// This method is useful when you want to mark multiple claims as disclosable.
    /// It accepts an iterator of claim paths.
    ///
    /// # Arguments
    /// * `path_iter` - An iterator of claim paths.
    ///
    /// # Returns
    /// A mutable reference to the issuer for method chaining.
    ///
    /// # Examples
    /// ```
    /// use sdjwt::Issuer;
    ///
    /// let claims = serde_json::json!({
    ///   "sub": "user_42",
    ///  "given_name": "John",
    /// "family_name": "Doe",
    /// "email": "johndoe@example",
    /// "address": {
    ///   "street_address": "123 Main St",
    ///  "locality": "Anytown",
    /// "region": "Anystate",
    /// "country": "US"
    /// },
    /// "nationalities": [
    ///  "US",
    /// "DE"
    /// ]
    /// });
    ///
    /// let mut issuer = Issuer::new(claims).unwrap();
    /// issuer.iter_disclosable(vec![
    ///     "/given_name".to_string(),
    ///     "/family_name".to_string(),
    ///     "/address/street_address".to_string(),
    ///     "/address/locality".to_string(),
    ///     "/nationalities/0".to_string(),
    ///     "/nationalities/1".to_string()].iter());
    /// ```
    pub fn iter_disclosable(&mut self, path_iter: Iter<String>) -> &mut Self {
        path_iter.for_each(|path| {
            self.disclosable(path);
        });
        self
    }

    /// Encodes the issuer into a SD-JWT.
    ///
    /// # Arguments
    ///
    /// * `signer_key` - A reference to a `KeyForEncoding` used for signing the issuer's SD-JWT.
    ///
    /// # Returns
    ///
    /// Serialized SD-JWT in format:
    /// <issuer_sd_jwt>~<disclosure_1>~<disclosure_2>~...~<disclosure_n>~
    ///
    /// # Examples
    ///
    /// ```
    /// use sdjwt::{Issuer, KeyForEncoding};
    ///
    /// const ISSUER_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDSwzyVZp2AIxS3\n802n0AfwKsMUcMYATMM6kK5VVS21ku3d6QC8kfhvJ0Pcb24dmGUWAJ95H9m19qDF\nbLrVZ9b4iobOsNlXNhKn4TRrsVFa8EaGXAJjGNRPPcL+gFwfV9y3tfR00tkokhR5\nZhhMifwKJf55QlEzY96yyk8ISzhagwO6Kf/E980Eoby1tvhX8q8HIwLG4GjFnmXx\nbKqxVQR1T07vFKHsF1MK8/d6a7+samHPWjoSlLvKSE4rdK8gouRpN/5Who4iS2s7\nlhfS2DcnxCnxj9S9BBm4GIQNk0Tc+lR20btBm+JiehAyEV9vX222BVSLUC9z9HGD\nk39b9ezbAgMBAAECggEBAIXuRxtxX/jDUjEqzVgsXD8EDX95wnkCTrVypzXWsPtH\naRyxKiSqZcLMotT7gnAQHXyD3NMtqD13geazF27xU6wQ62WBADvpQqWn+JXO0jIF\nqetLoMC0UIYiaz0q+F96h+m+GJ/8NL8RRS138U0CCkWwqysHN25+sk/PO7W7hw4M\nOAN/97rBkXqyzJJSvNwl2A66ga+9WC8G/9YgweqkS6re6WAyo4z1KyZAE1r655JR\nEaiIR6GYvahNsy/dNjVtGR189o8bf6xnTPbDUXQ/D61nO3Kg3B7Ca/uQWiDbI9VJ\nMXZxgip9Q7Qil9WuK1vVCUSf6WK38NV6r9fubw/DgsECgYEA70drCiGrC3pvIJF0\nLJL46H6x6SFClR876BZEnN51udJGXRstWV+Ya6NULSTykwusaTYUnr2BC6r3tT4S\nrRLfnXTaI0Tr6Bws6kBSJJC0CS0lLqK2tlKbcypQXv0T6Ulv2NXDq0VqQB3txED6\n8m5GieppHNueqLQqGqM1V4JYw5ECgYEA4X2s7ccLB8MX01j4T6Fnj4BGaZsyc1kV\nn6VHsuAsUxA9ZuwV+lk5k6xaWxDYmQR3xZ4XcQEntRUtGFu4TMLVpCcK26Vqafrp\nymbGjJGFagIaP9YOhQ+5ZMfO0obYUEaDGhPjXH3G9O/dTXoRg5nP5JvdcAnf853y\nm1BaYBHbG6sCgYAfVkQffI9RHoTFSCdl2w28LTORq6hzrTaES75KqRvT7UUH1pJW\n3R0yI57XlroqJeI7mTiUHY9z/r0YQHvjrNAaZ/5VliYrLN15BFl9rnHVrdLry6WQ\nNTtklssV1aEw8UwzorNQj/O9V+4WwMfczjJwx4FipSSfRZEqEevffROw8QKBgGNK\nba0+KjM+yuz7jkuyLOHZgCfcePilz4m+w7WWVK42xnLdnkfgpiPKjvbukhG/D+Zq\n2LOf6JYqPvMs4Bic6mof7v4M9rC4Fd5UJzWaln65ckmNvlMFO4OPIBk/21xt0CjZ\nfRIrKEKOpIoLKE8kmZB2uakuD/k8IaoWVdVbx3mFAoGAMFFWZAAHpB18WaATQRR6\n86JnudPD3TlOw+8Zw4tlOoGv4VXCPVsyAH8CWNSONyTRxeSJpe8Pn6ZvPJ7YBt6c\nchNSaqFIl9UnkMJ1ckE7EX2zKFCg3k8VzqYRLC9TcqqwKTJcNdRu1SbWkAds6Sd8\nKKRrCm+L44uQ01gUYvYYv5c=\n-----END PRIVATE KEY-----\n";
    ///
    /// let claims = serde_json::json!({
    ///    "sub": "user_42",
    ///    "given_name": "John",
    ///    "family_name": "Doe",
    ///    "email": "johndoe@example",
    ///    "address": {
    ///       "street_address": "123 Main St",
    ///       "locality": "Anytown",
    ///       "region": "Anystate",
    ///       "country": "US"
    ///   },
    ///   "nationalities": [
    ///      "US",
    ///      "DE"
    ///   ]
    /// });
    ///
    /// let encoded_jwt = Issuer::new(claims).unwrap()
    ///     .disclosable("/given_name")
    ///     .disclosable("/family_name")
    ///     .disclosable("/address/street_address")
    ///     .disclosable("/address/locality")
    ///     .disclosable("/nationalities/0")
    ///     .disclosable("/nationalities/1")
    ///     .decoy(6)
    ///     .encode(&KeyForEncoding::from_rsa_pem(
    ///         ISSUER_SIGNING_KEY_PEM.as_bytes(),
    ///     ).unwrap()).unwrap();
    /// println!("Encoded JWT: {}", encoded_jwt);
    /// ```
    pub fn encode(&mut self, signer_key: &KeyForEncoding) -> Result<String, Error> {
        let mut updated_claims = self.claims.clone();
        let disclosures: Result<Vec<Disclosure>, Error> = self
            .disclosable_claim_paths
            .iter()
            .map(|disclosable_claim| build_disclosure(&mut updated_claims, disclosable_claim))
            .collect();
        let disclosures = disclosures?;

        if let Some(max_decoys) = self.max_decoys {
            let decoy_count = rand::thread_rng().gen_range(1..max_decoys + 1);
            build_decoys(&mut updated_claims, decoy_count)?;
        }

        let mut rng = rand::thread_rng();
        let sd_array = updated_claims
            .get_mut("_sd")
            .and_then(Value::as_array_mut)
            .ok_or(Error::InvalidPathPointer)?;
        sd_array.shuffle(&mut rng);

        if !disclosures.is_empty() {
            let algorithm = disclosures[0].get_algorithm().to_string();
            updated_claims["_sd_alg"] = algorithm.into();
        }

        if self.key_binding_pubkey.is_some() {
            let key_binding_pubkey = self.key_binding_pubkey.as_ref().unwrap();
            updated_claims["cnf"] = serde_json::json!(key_binding_pubkey.deref());
        }

        let issuer_jwt = encode(&self.header, &updated_claims, signer_key)?;
        let mut serialized_sd_jwt = issuer_jwt;
        disclosures.iter().for_each(|disclosure| {
            serialized_sd_jwt = format!("{}~{}", serialized_sd_jwt, disclosure.disclosure());
        });
        serialized_sd_jwt = format!("{}~", serialized_sd_jwt);

        Ok(serialized_sd_jwt)
    }

    #[cfg(test)]
    pub fn claims_copy(&self) -> Value {
        self.claims.clone()
    }
}

fn parent_elem_from_path(path: &str) -> Result<(&str, &str), Error> {
    let last_slash_index = path.rfind('/').ok_or(Error::InvalidPathPointer)?;
    let (parent_path, element_path) = path.split_at(last_slash_index);
    let element_path = element_path.trim_start_matches('/');

    Ok((parent_path, element_path))
}

fn build_disclosure(claims: &mut Value, disclosable_claim: &str) -> Result<Disclosure, Error> {
    let (parent_ptr, elem_ptr) = parent_elem_from_path(disclosable_claim)?;
    let key = elem_ptr.trim_start_matches('/');

    let parent = claims
        .pointer_mut(parent_ptr)
        .ok_or(Error::InvalidPathPointer)?;
    if parent.is_array() {
        let parent = parent.as_array_mut().ok_or(Error::InvalidPathPointer)?;
        let key_index = key.parse()?;
        let value = parent.remove(key_index);
        let disclosure = Disclosure::new(None, value.clone()).build()?;
        parent.insert(key_index, serde_json::json!({ "...": disclosure.digest() }));
        return Ok(disclosure);
    }
    let parent = parent.as_object_mut().ok_or(Error::InvalidPathPointer)?;

    let value = parent.remove(key).ok_or(Error::InvalidPathPointer)?;

    let disclosure = Disclosure::new(Some(key.to_owned()), value.clone()).build()?;

    match parent.get_mut("_sd") {
        Some(sd) => {
            if let Some(sd_array) = sd.as_array_mut() {
                sd_array.push(Value::from(disclosure.digest().as_str()));
            } else {
                return Err(Error::InvalidSDType);
            }
        }
        None => {
            let sd_array = vec![Value::from(disclosure.digest().as_str())];
            parent.insert("_sd".to_string(), sd_array.into());
        }
    }

    Ok(disclosure)
}

fn build_decoys(claims: &mut Value, decoy_count: i32) -> Result<Vec<Decoy>, Error> {
    let mut decoy_list = Vec::<Decoy>::new();
    for _ in 0..decoy_count {
        let new_decoy = Decoy::new().build()?;
        decoy_list.push(new_decoy);
    }

    let sd_array = claims
        .get_mut("_sd")
        .and_then(Value::as_array_mut)
        .ok_or(Error::InvalidPathPointer)?;
    decoy_list.iter().for_each(|decoy| {
        sd_array.push(Value::from(decoy.digest().as_str()));
    });

    Ok(decoy_list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::common_test_utils::{convert_to_pem, keys, publickey_to_jwk};
    use serde_json::Value;

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

    fn setup_common() -> (Issuer, String) {
        let (priv_key, pub_key) = keys();
        let (issuer_private_key, _) = convert_to_pem(priv_key, pub_key);
        let claims: Value = serde_json::from_str(TEST_CLAIMS).unwrap();
        let issuer = Issuer::new(claims).unwrap();
        (issuer, issuer_private_key)
    }

    fn encode_and_test(
        issuer: &mut Issuer,
        issuer_private_key: &str,
        expected_disclosures: usize,
    ) -> Result<(), Error> {
        let encoded = issuer.encode(&KeyForEncoding::from_rsa_pem(
            issuer_private_key.as_bytes(),
        )?)?;
        println!("encoded: {:?}", encoded);
        let dot_segments = encoded.split('.').count();
        let disclosure_segments = encoded.split('~').count() - 2;

        assert_eq!(dot_segments, 3);
        assert_eq!(disclosure_segments, expected_disclosures);
        Ok(())
    }

    #[test]
    fn test_encode_objects() -> Result<(), Error> {
        let (mut issuer, issuer_private_key) = setup_common();
        issuer
            .disclosable("/given_name")
            .disclosable("/family_name")
            .disclosable("/address/street_address")
            .disclosable("/address/locality");
        encode_and_test(&mut issuer, &issuer_private_key, 4)
    }

    #[test]
    fn test_encode_objects_and_array() -> Result<(), Error> {
        let (mut issuer, issuer_private_key) = setup_common();
        issuer
            .disclosable("/given_name")
            .disclosable("/family_name")
            .disclosable("/address/street_address")
            .disclosable("/address/locality")
            .disclosable("/nationalities/0")
            .disclosable("/nationalities/1");
        encode_and_test(&mut issuer, &issuer_private_key, 6)
    }

    #[test]
    fn test_encode_objects_and_array_kb_required() -> Result<(), Error> {
        let (mut issuer, issuer_private_key) = setup_common();
        let (_, holder_public_key) = keys();
        let holder_jwk = publickey_to_jwk(&holder_public_key);
        println!("holder_jwk: {:?}", holder_jwk);

        issuer
            .disclosable("/given_name")
            .disclosable("/family_name")
            .disclosable("/address/street_address")
            .disclosable("/address/locality")
            .disclosable("/nationalities/0")
            .disclosable("/nationalities/1")
            .require_key_binding(Jwk::from_value(holder_jwk)?);
        encode_and_test(&mut issuer, &issuer_private_key, 6)
    }

    #[test]
    fn test_encode_objects_with_single_decoy() -> Result<(), Error> {
        let (mut issuer, issuer_private_key) = setup_common();
        issuer
            .disclosable("/given_name")
            .disclosable("/family_name")
            .disclosable("/address/street_address")
            .disclosable("/address/locality")
            .decoy(1);
        encode_and_test(&mut issuer, &issuer_private_key, 4)
    }

    #[test]
    fn test_encode_objects_with_multiple_decoys() -> Result<(), Error> {
        let (mut issuer, issuer_private_key) = setup_common();
        issuer
            .disclosable("/given_name")
            .disclosable("/family_name")
            .disclosable("/address/street_address")
            .disclosable("/address/locality")
            .decoy(10);
        encode_and_test(&mut issuer, &issuer_private_key, 4)
    }
}
