use chrono::{Duration, Utc};
use sdjwt::{
    decode, parse_yaml, sd_jwt_parts, Algorithm, Disclosure, Error, HashAlgorithm, Holder, Issuer,
    Jwk, KeyForDecoding, KeyForEncoding, Validation, Verifier,
};
use std::collections::HashSet;

use common::{
    compare_json_values, convert_to_pem, disclosures2vec, keys, publickey_to_jwk,
    separate_jwt_and_disclosures,
};
use serde_json::value::Value;

mod common;

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

const TEST_CLAIMS_YAML: &str = r#"
    sub: user_42
    !sd given_name: John
    !sd family_name: Doe
    email: johndoe@example.com
    phone_number: +1-202-555-0101
    phone_number_verified: true
    address:
        !sd street_address: 123 Main St
        !sd locality: Anytown
        region: Anystate
        country: US
    birthdate: 1940-01-01
    updated_at: 1570000000
    nationalities:
        - !sd US
        - !sd DE
    "#;

const TEST_VERIFIER_EXPECTED_CLAIMS: &str = r#"{
        "sub": "user_42",
        "given_name": "John",
        "email": "johndoe@example.com",
        "phone_number": "+1-202-555-0101",
        "phone_number_verified": true,
        "address": {
            "locality": "Anytown",
            "region": "Anystate",
            "country": "US"
        },
        "birthdate": "1940-01-01",
        "updated_at": 1570000000,
        "nationalities": [
            "DE"
        ]
    }"#;

#[test]
fn test_basic_encoding_decoding() -> Result<(), Error> {
    let (priv_key, pub_key) = keys();
    let (issuer_private_key, issuer_public_key) = convert_to_pem(priv_key, pub_key);
    let mut claims: Value = serde_json::from_str(TEST_CLAIMS).unwrap();
    let now = Utc::now();
    let expiration = now + Duration::minutes(5);
    let exp = expiration.timestamp();
    claims["exp"] = serde_json::json!(exp);
    let mut issuer = Issuer::new(claims)?;
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

#[test]
fn test_presentation_verification_with_kb() -> Result<(), Error> {
    // create issuer sd-jwt
    let (priv_key, pub_key) = keys();
    let (issuer_private_key, issuer_public_key) = convert_to_pem(priv_key, pub_key);
    let (holder_private_key, holder_public_key) = keys();
    let holder_jwk = publickey_to_jwk(&holder_public_key);
    let (holder_private_key_pem, _) = convert_to_pem(holder_private_key, holder_public_key);
    let claims: Value = serde_json::from_str(TEST_CLAIMS).unwrap();
    let mut issuer = Issuer::new(claims)?;
    let issuer_sd_jwt = issuer
        .expires_in_seconds(60)
        .disclosable("/given_name")
        .disclosable("/family_name")
        .disclosable("/address/street_address")
        .disclosable("/address/locality")
        .disclosable("/nationalities/0")
        .disclosable("/nationalities/1")
        .require_key_binding(Jwk::from_value(holder_jwk)?)
        .encode(&KeyForEncoding::from_rsa_pem(
            issuer_private_key.as_bytes(),
        )?)?;
    println!("issuer_sd_jwt: {:?}", issuer_sd_jwt);

    // verify issuer sd-jwt by holder
    let validation = Validation::default();
    let decoding_key = KeyForDecoding::from_rsa_pem(issuer_public_key.as_bytes())?;
    let (header, decoded_claims, disclosure_paths) =
        Holder::verify(&issuer_sd_jwt, &decoding_key, &validation)?;
    println!("header: {:?}", header);
    println!("claims: {:?}", decoded_claims);
    println!("disclosure_paths: {:?}", disclosure_paths);

    // holder creates presentation
    let presentation = Holder::presentation(&issuer_sd_jwt)?
        .redact("/family_name")?
        .redact("/address/street_address")?
        .redact("/nationalities/0")?
        .key_binding(
            "https://someone.example.com",
            &KeyForEncoding::from_rsa_pem(holder_private_key_pem.as_bytes())?,
            Algorithm::RS256,
        )?
        .build()?;
    println!("presentation: {:?}", presentation);
    let (issuer_jwt, disclosures, kb_jwt) = sd_jwt_parts(&presentation);

    let issuer_dot_segments = issuer_jwt.split('.').count();
    let kb_jwt_dot_segments = kb_jwt.as_ref().unwrap().split('.').count();

    assert_eq!(issuer_dot_segments, 3);
    assert_eq!(kb_jwt_dot_segments, 3);
    assert_eq!(disclosures.len(), 3);

    let (_, disclosure_parts) = separate_jwt_and_disclosures(&presentation);
    let disclosures = disclosures2vec(&disclosure_parts);
    assert_eq!(disclosures.len(), 3);
    let d0 = Disclosure::from_base64(&disclosures[0], HashAlgorithm::SHA256)?;
    let d1 = Disclosure::from_base64(&disclosures[1], HashAlgorithm::SHA256)?;
    let d2 = Disclosure::from_base64(&disclosures[2], HashAlgorithm::SHA256)?;
    assert_eq!(d0.key(), &Some("given_name".to_string()));
    assert_eq!(d0.value(), &serde_json::json!("John"));
    assert_eq!(d1.key(), &Some("locality".to_string()));
    assert_eq!(d1.value(), &serde_json::json!("Anytown"));
    assert_eq!(d2.key(), &None);
    assert_eq!(d2.value(), &serde_json::json!("DE"));

    // Verifier verifies presentation
    let validation = Validation::default();
    let mut kb_validation = Validation::default().no_exp();
    let mut audience = HashSet::new();
    audience.insert("https://someone.example.com".to_string());
    kb_validation.aud = Some(audience);
    let decoding_key = KeyForDecoding::from_rsa_pem(issuer_public_key.as_bytes())?;
    let (ver_header, ver_claims) = Verifier::verify(
        &presentation,
        &decoding_key,
        &validation,
        &Some(&kb_validation),
    )?;

    println!("ver_header: {:?}", ver_header);
    println!("ver_claims: {:?}", ver_claims);

    let mut ver_claims_without_exp = ver_claims.clone();
    ver_claims_without_exp
        .as_object_mut()
        .unwrap()
        .remove("exp");
    ver_claims_without_exp
        .as_object_mut()
        .unwrap()
        .remove("cnf");
    assert!(compare_json_values(
        &serde_json::from_str(TEST_VERIFIER_EXPECTED_CLAIMS)?,
        &ver_claims_without_exp
    ));

    Ok(())
}

#[test]
fn test_issue_claims_with_yaml() -> Result<(), Error> {
    // create issuer sd-jwt
    let (priv_key, pub_key) = keys();
    let (issuer_private_key, issuer_public_key) = convert_to_pem(priv_key, pub_key);
    let (holder_private_key, holder_public_key) = keys();
    let holder_jwk = publickey_to_jwk(&holder_public_key);
    let (holder_private_key_pem, _) = convert_to_pem(holder_private_key, holder_public_key);

    let (claims, tagged_paths) = parse_yaml(TEST_CLAIMS_YAML)?;
    let mut issuer = Issuer::new(claims)?;
    let issuer_sd_jwt = issuer
        .expires_in_seconds(60)
        .require_key_binding(Jwk::from_value(holder_jwk)?)
        .iter_disclosable(tagged_paths.iter())
        .encode(&KeyForEncoding::from_rsa_pem(
            issuer_private_key.as_bytes(),
        )?)?;
    println!("issuer_sd_jwt: {:?}", issuer_sd_jwt);

    // verify issuer sd-jwt by holder
    let validation = Validation::default();
    let decoding_key = KeyForDecoding::from_rsa_pem(issuer_public_key.as_bytes())?;
    let (header, decoded_claims, disclosure_paths) =
        Holder::verify(&issuer_sd_jwt, &decoding_key, &validation)?;
    println!("header: {:?}", header);
    println!("claims: {:?}", decoded_claims);
    println!("disclosure_paths: {:?}", disclosure_paths);

    // holder creates presentation
    let presentation = Holder::presentation(&issuer_sd_jwt)?
        .redact("/family_name")?
        .redact("/address/street_address")?
        .redact("/nationalities/0")?
        .key_binding(
            "https://someone.example.com",
            &KeyForEncoding::from_rsa_pem(holder_private_key_pem.as_bytes())?,
            Algorithm::RS256,
        )?
        .build()?;
    println!("presentation: {:?}", presentation);
    let (issuer_jwt, disclosures, kb_jwt) = sd_jwt_parts(&presentation);

    let issuer_dot_segments = issuer_jwt.split('.').count();
    let kb_jwt_dot_segments = kb_jwt.as_ref().unwrap().split('.').count();

    assert_eq!(issuer_dot_segments, 3);
    assert_eq!(kb_jwt_dot_segments, 3);
    assert_eq!(disclosures.len(), 3);

    let (_, disclosure_parts) = separate_jwt_and_disclosures(&presentation);
    let disclosures = disclosures2vec(&disclosure_parts);
    assert_eq!(disclosures.len(), 3);
    let d0 = Disclosure::from_base64(&disclosures[0], HashAlgorithm::SHA256)?;
    let d1 = Disclosure::from_base64(&disclosures[1], HashAlgorithm::SHA256)?;
    let d2 = Disclosure::from_base64(&disclosures[2], HashAlgorithm::SHA256)?;
    assert_eq!(d0.key(), &Some("given_name".to_string()));
    assert_eq!(d0.value(), &serde_json::json!("John"));
    assert_eq!(d1.key(), &Some("locality".to_string()));
    assert_eq!(d1.value(), &serde_json::json!("Anytown"));
    assert_eq!(d2.key(), &None);
    assert_eq!(d2.value(), &serde_json::json!("DE"));

    // Verifier verifies presentation
    let validation = Validation::default();
    let mut kb_validation = Validation::default().no_exp();
    let mut audience = HashSet::new();
    audience.insert("https://someone.example.com".to_string());
    kb_validation.aud = Some(audience);
    let decoding_key = KeyForDecoding::from_rsa_pem(issuer_public_key.as_bytes())?;
    let (ver_header, ver_claims) = Verifier::verify(
        &presentation,
        &decoding_key,
        &validation,
        &Some(&kb_validation),
    )?;

    println!("ver_header: {:?}", ver_header);
    println!("ver_claims: {:?}", ver_claims);

    let mut ver_claims_without_exp = ver_claims.clone();
    ver_claims_without_exp
        .as_object_mut()
        .unwrap()
        .remove("exp");
    ver_claims_without_exp
        .as_object_mut()
        .unwrap()
        .remove("cnf");
    assert!(compare_json_values(
        &serde_json::from_str(TEST_VERIFIER_EXPECTED_CLAIMS)?,
        &ver_claims_without_exp
    ));

    Ok(())
}
