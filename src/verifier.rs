use crate::{
    base64_hash, decode, sd_jwt_parts,
    utils::{drop_kb, remove_digests, restore_disclosures},
    Error, HashAlgorithm, Jwk, KeyForDecoding, Validation,
};
use serde_json::Value;

/// # Verifier Module
///
/// Represents a Verifier.  Verifies SD-JWT presentations.
///
/// ## Features
///
/// - Verifying SD-JWT presentations.
///
/// Example
///
/// ```
/// use sdjwt::{Verifier, KeyForDecoding, Validation, Error};
/// use std::collections::HashSet;
///
/// const ISSUER_PUBKEY: &str = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA07aCbyrCS2/qYkuOyznaU/vQdobGtz/SvUKSzx4ic9Ax+pGi8OJM\noewxNg/6zFWkZeuZ1NMQMd/3aJLH+L+SqBNDox8cjWSzgR/Gf8xjVpMNiFrxrTx3\nz1ABaYfgsiDW/PhgoXCC7vF2dqLPTVBuObwmULjgmvPDFKUGEu9w/t05FaT+sccv\n2sMw1b8grlqG392etgbjKcvy29qG8Okj+CVPmYUe69Ce87mUOM5H4S9SF/yNLoFU\nczkUHQSa+sWe+QG6RskKay+3xophsMYYk4g4RHZuArg2LUvlDObmv/rsxKOVE3/B\nzV1DDjLs3AhHTwow2qCkFEZFof1dVOIjNwIDAQAB\n-----END RSA PUBLIC KEY-----\n";
/// const PRESENTATION: &str = "eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsiYlQzVnNrcVBwc0F1RWJ5VXBVb0o1UVVZaFp6TkZWSWw5TUhkN0hiWjNOSSIsInRWam9RWW1iT2FUOEt6YmRTMFpmUTdUTlU2UFlmV1RxQU1nNVlOUVJ1OUEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJhZGRyZXNzIjp7Il9zZCI6WyJ5WC13SXRkMmk1M2pCaV9jeHk3TE5Wd1J6Mm84ajlyd1IxQVJnVVFtVm9vIiwiQi14a3FHNzRvQzFCOUdheDlqQWZTWlVtQlBrVldhVmR1QVBSYlJkWHIyYyJdLCJjb3VudHJ5IjoiVVMiLCJyZWdpb24iOiJBbnlzdGF0ZSJ9LCJiaXJ0aGRhdGUiOiIxOTQwLTAxLTAxIiwiY25mIjp7ImFsZyI6IlJTMjU2IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiMFEta0s0aGZQbzZsMmFvVzlWUHR6S2hTaV9iN2t6ZTZ6eTlfVThTZjFsRmdxUGIwVXBvRTNuTW4zRUpyc0Jfb1hhb1RmY0RxaG4zTi1EblRFUFFmSTBfRTdnaHc3M0g1TWxiREdZM2VyajdzamE0enFIbmUyX1BZRnJvTFd3V0tjZDMzbUQ3VzhVYTdVSGV1a21GekFreXFEZlp1b0ZRcFdYLTFaVVdnalc0LUpoUUtYSXB4NVF6U1ZDX1hwaUFibzN3Zk5jQlFaaE8xSGxlTDV3VnFyMVZrUTgxcXl6Tlo3UFVRTWd0VlJGdkIyX3lPTlBDZ3piVzQ0TGNVQUFzYk5HNkdyX095WlBvblhuQml3b085LUxnNXdoQVc1TnlkU2ZwVi05UzE0NjV3Nm9IenpxdU1DX0JhcUQ5WVFTZ2pPVXpJb21fc3lYZG5GSTNyWWRZaG93IiwidXNlIjoic2lnIn0sImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsImV4cCI6MTcwMzg2NDkxMSwibmF0aW9uYWxpdGllcyI6W3siLi4uIjoiRDVSLXVQVEhMaTVFNVJqWEJwaW5Ia0VfV1Jxckl0UVFndnFyYWpEZ3ZPTSJ9LHsiLi4uIjoiNTJwZGc4enYtQ1RLT3U1bDhnVUpRalNKQ0I2dHF0NVJ1dUk5WkRESTJCdyJ9XSwicGhvbmVfbnVtYmVyIjoiKzEtMjAyLTU1NS0wMTAxIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIjp0cnVlLCJzdWIiOiJ1c2VyXzQyIiwidXBkYXRlZF9hdCI6MTU3MDAwMDAwMH0.aziX_zt4VylvCt4b_ILZacHQYWGFGsMUd0KEVgg4qtj8JwljDoL8845eHjV1ldpBp7hyWnkrV1X7ZtM7WK1F987ntNv5hK9o-5C2H18UpYKI9YZz5f8yETkWBmu9sH5HKtPv0lstJFc-kQB-jKRyidMxhwO_MU_oR_UtjpIjVd6atRLrwlud4ZM-un8R2R209au8TIE4JIAyzJA1IC5NTR4FdCcwGJiodj62lGRVpmvWhQspxtA9aGKSrnx0x8rL82_dE0hBrRkq5cfbiPR5GM1BN7FtA68OrWK9STHCAaH3VQxe0htOg3o8wlQ6rPMIP5B1Oc0932K56bGwXDZPCg~WyJGSjNhS2JyaWNONUdZRGQtdVk2dGVnIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyItQkFxQ2VJN0kzVUdaREJQR1RNcUpRIiwibG9jYWxpdHkiLCJBbnl0b3duIl0~WyI2RF8zUFpoSlQxTHVDR3o2WTVOMjVBIiwiREUiXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL3NvbWVvbmUuZXhhbXBsZS5jb20iLCJpYXQiOjE3MDM4NjQ4NTEsIm5vbmNlIjoiODEzOWN2ZUdVTjFKQW1QTllGeWg5eTdqWmZab2VMZXIiLCJzZF9oYXNoIjoidUU1MTY0eTVqZ1NFNWg1V2FiUFpnU0lLWDFOX015Ti1qMlJhNnE3NDJ0ayJ9.BtYvadr-iT6poH9DQV5xAJxAxIFFsNRJ6AQ1rrGySpCVZ-1Dg7a9mvkP3Tf7dJ-r8O-cndJEaUaiKXSFZW7H8j-wO3hp0hrEqlp9OpCNON2EnwUrSm_XLFUFe-MinJZDMZ3qJeCLk7-AMvOgEHXHautwA3Sj2W_G4oDtH05tEHdy50lTVSblqINOLTdy8Vkz82Hs1WW7CVeUOQbsGbKNNAPczTDf00fQg18n6nGmpkHp7rgMV-Sq4qV2qxDeuXE00AkgPAzcMRyCx3Gk7NSWn9NtkTPK9Bporf58r_p5hf4lp-RoqRT0Uza1d5FcaoONl9GtLnhYURLKlCo9yhCbOA";
///
/// fn main() -> Result<(), Error> {
///     let validation = Validation::default().no_exp();
///     let mut kb_validation = Validation::default().no_exp();
///     let mut audience = HashSet::new();
///     audience.insert("https://someone.example.com".to_string());
///     kb_validation.aud = Some(audience);
///     let decoding_key = KeyForDecoding::from_rsa_pem(ISSUER_PUBKEY.as_bytes())?;
///     let (ver_header, ver_claims) = Verifier::verify(
///         PRESENTATION,
///         &decoding_key,
///         &validation,
///         &Some(&kb_validation),
///     )?;
///     Ok(())
/// }
/// ```
pub struct Verifier {}

impl Verifier {
    pub fn verify_raw(
        issuer_token: &str,
        key: &KeyForDecoding,
        validation: &Validation,
        kb_validation: &Option<&Validation>,
    ) -> Result<(Value, Value, Vec<String>), Error> {
        let (issuer_sd_jwt, disclosures, kb_jwt) = sd_jwt_parts(issuer_token);
        let (header, claims) = decode(&issuer_sd_jwt, key, validation)?;

        if claims["cnf"].is_null() && kb_jwt.is_some() {
            return Err(Error::SDJWTRejected(
                "Issuer SD JWT must contain cnf claim if key binding JWT is included".to_string(),
            ));
        }

        if !claims["cnf"].is_null() && kb_jwt.is_none() {
            return Err(Error::SDJWTRejected(
                "Key binding JWT must be included if cnf claim is included".to_string(),
            ));
        }

        let _ = Jwk::from_value(claims["cnf"].clone())?;

        let hash_alg = match HashAlgorithm::try_from(claims["_sd_alg"].as_str().ok_or(
            Error::SDJWTRejected("Issuer SD JWT must contain _sd_alg claim".to_string()),
        )?) {
            Ok(alg) => alg,
            Err(e) => {
                return Err(Error::InvalidHashAlgorithm(e.to_string()));
            }
        };

        if let Some(kb) = kb_jwt {
            let (_, kb_claims) = verify_kb(
                &kb,
                &claims["cnf"],
                kb_validation.ok_or(Error::SDJWTRejected(
                    "Key binding validation missing".to_string(),
                ))?,
            )?;
            if let Some(sd_hash) = kb_claims["sd_hash"].as_str() {
                if base64_hash(hash_alg, &drop_kb(issuer_token)) != sd_hash {
                    return Err(Error::SDJWTRejected(
                        "KB JWT sd_hash does not match hash of issuer JWT and disclosures"
                            .to_string(),
                    ));
                }
            } else {
                return Err(Error::SDJWTRejected(
                    "Issuer KB JWT must contain sd_hash claim".to_string(),
                ));
            }
        }

        Ok((header, claims, disclosures))
    }

    /// Verifyies SD-JWT presentation received from Holder.
    ///
    /// Example
    ///
    /// ```
    /// use sdjwt::{Verifier, KeyForDecoding, Validation, Error};
    /// use std::collections::HashSet;
    ///
    /// const ISSUER_PUBKEY: &str = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA07aCbyrCS2/qYkuOyznaU/vQdobGtz/SvUKSzx4ic9Ax+pGi8OJM\noewxNg/6zFWkZeuZ1NMQMd/3aJLH+L+SqBNDox8cjWSzgR/Gf8xjVpMNiFrxrTx3\nz1ABaYfgsiDW/PhgoXCC7vF2dqLPTVBuObwmULjgmvPDFKUGEu9w/t05FaT+sccv\n2sMw1b8grlqG392etgbjKcvy29qG8Okj+CVPmYUe69Ce87mUOM5H4S9SF/yNLoFU\nczkUHQSa+sWe+QG6RskKay+3xophsMYYk4g4RHZuArg2LUvlDObmv/rsxKOVE3/B\nzV1DDjLs3AhHTwow2qCkFEZFof1dVOIjNwIDAQAB\n-----END RSA PUBLIC KEY-----\n";
    /// const PRESENTATION: &str = "eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsiYlQzVnNrcVBwc0F1RWJ5VXBVb0o1UVVZaFp6TkZWSWw5TUhkN0hiWjNOSSIsInRWam9RWW1iT2FUOEt6YmRTMFpmUTdUTlU2UFlmV1RxQU1nNVlOUVJ1OUEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJhZGRyZXNzIjp7Il9zZCI6WyJ5WC13SXRkMmk1M2pCaV9jeHk3TE5Wd1J6Mm84ajlyd1IxQVJnVVFtVm9vIiwiQi14a3FHNzRvQzFCOUdheDlqQWZTWlVtQlBrVldhVmR1QVBSYlJkWHIyYyJdLCJjb3VudHJ5IjoiVVMiLCJyZWdpb24iOiJBbnlzdGF0ZSJ9LCJiaXJ0aGRhdGUiOiIxOTQwLTAxLTAxIiwiY25mIjp7ImFsZyI6IlJTMjU2IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiMFEta0s0aGZQbzZsMmFvVzlWUHR6S2hTaV9iN2t6ZTZ6eTlfVThTZjFsRmdxUGIwVXBvRTNuTW4zRUpyc0Jfb1hhb1RmY0RxaG4zTi1EblRFUFFmSTBfRTdnaHc3M0g1TWxiREdZM2VyajdzamE0enFIbmUyX1BZRnJvTFd3V0tjZDMzbUQ3VzhVYTdVSGV1a21GekFreXFEZlp1b0ZRcFdYLTFaVVdnalc0LUpoUUtYSXB4NVF6U1ZDX1hwaUFibzN3Zk5jQlFaaE8xSGxlTDV3VnFyMVZrUTgxcXl6Tlo3UFVRTWd0VlJGdkIyX3lPTlBDZ3piVzQ0TGNVQUFzYk5HNkdyX095WlBvblhuQml3b085LUxnNXdoQVc1TnlkU2ZwVi05UzE0NjV3Nm9IenpxdU1DX0JhcUQ5WVFTZ2pPVXpJb21fc3lYZG5GSTNyWWRZaG93IiwidXNlIjoic2lnIn0sImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsImV4cCI6MTcwMzg2NDkxMSwibmF0aW9uYWxpdGllcyI6W3siLi4uIjoiRDVSLXVQVEhMaTVFNVJqWEJwaW5Ia0VfV1Jxckl0UVFndnFyYWpEZ3ZPTSJ9LHsiLi4uIjoiNTJwZGc4enYtQ1RLT3U1bDhnVUpRalNKQ0I2dHF0NVJ1dUk5WkRESTJCdyJ9XSwicGhvbmVfbnVtYmVyIjoiKzEtMjAyLTU1NS0wMTAxIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIjp0cnVlLCJzdWIiOiJ1c2VyXzQyIiwidXBkYXRlZF9hdCI6MTU3MDAwMDAwMH0.aziX_zt4VylvCt4b_ILZacHQYWGFGsMUd0KEVgg4qtj8JwljDoL8845eHjV1ldpBp7hyWnkrV1X7ZtM7WK1F987ntNv5hK9o-5C2H18UpYKI9YZz5f8yETkWBmu9sH5HKtPv0lstJFc-kQB-jKRyidMxhwO_MU_oR_UtjpIjVd6atRLrwlud4ZM-un8R2R209au8TIE4JIAyzJA1IC5NTR4FdCcwGJiodj62lGRVpmvWhQspxtA9aGKSrnx0x8rL82_dE0hBrRkq5cfbiPR5GM1BN7FtA68OrWK9STHCAaH3VQxe0htOg3o8wlQ6rPMIP5B1Oc0932K56bGwXDZPCg~WyJGSjNhS2JyaWNONUdZRGQtdVk2dGVnIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyItQkFxQ2VJN0kzVUdaREJQR1RNcUpRIiwibG9jYWxpdHkiLCJBbnl0b3duIl0~WyI2RF8zUFpoSlQxTHVDR3o2WTVOMjVBIiwiREUiXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL3NvbWVvbmUuZXhhbXBsZS5jb20iLCJpYXQiOjE3MDM4NjQ4NTEsIm5vbmNlIjoiODEzOWN2ZUdVTjFKQW1QTllGeWg5eTdqWmZab2VMZXIiLCJzZF9oYXNoIjoidUU1MTY0eTVqZ1NFNWg1V2FiUFpnU0lLWDFOX015Ti1qMlJhNnE3NDJ0ayJ9.BtYvadr-iT6poH9DQV5xAJxAxIFFsNRJ6AQ1rrGySpCVZ-1Dg7a9mvkP3Tf7dJ-r8O-cndJEaUaiKXSFZW7H8j-wO3hp0hrEqlp9OpCNON2EnwUrSm_XLFUFe-MinJZDMZ3qJeCLk7-AMvOgEHXHautwA3Sj2W_G4oDtH05tEHdy50lTVSblqINOLTdy8Vkz82Hs1WW7CVeUOQbsGbKNNAPczTDf00fQg18n6nGmpkHp7rgMV-Sq4qV2qxDeuXE00AkgPAzcMRyCx3Gk7NSWn9NtkTPK9Bporf58r_p5hf4lp-RoqRT0Uza1d5FcaoONl9GtLnhYURLKlCo9yhCbOA";
    ///
    /// fn main() -> Result<(), Error> {
    ///     let validation = Validation::default().no_exp();
    ///     let mut kb_validation = Validation::default().no_exp();
    ///     let mut audience = HashSet::new();
    ///     audience.insert("https://someone.example.com".to_string());
    ///     kb_validation.aud = Some(audience);
    ///     let decoding_key = KeyForDecoding::from_rsa_pem(ISSUER_PUBKEY.as_bytes())?;
    ///     let (ver_header, ver_claims) = Verifier::verify(
    ///         PRESENTATION,
    ///         &decoding_key,
    ///         &validation,
    ///         &Some(&kb_validation),
    ///     )?;
    ///     Ok(())
    /// }
    /// ```
    pub fn verify(
        issuer_token: &str,
        key: &KeyForDecoding,
        validation: &Validation,
        kb_validation: &Option<&Validation>,
    ) -> Result<(Value, Value), Error> {
        let (header, claims, disclosures) =
            Verifier::verify_raw(issuer_token, key, validation, kb_validation)?;
        let mut updated_claims = claims.clone();
        let algorithm = claims["_sd_alg"].as_str().unwrap_or("");
        let algorithm = HashAlgorithm::try_from(algorithm)?;
        let mut disclosure_paths = Vec::new();
        restore_disclosures(
            &mut updated_claims,
            &disclosures,
            &mut disclosure_paths,
            algorithm,
        )?;

        remove_digests(&mut updated_claims)?;
        Ok((header, updated_claims))
    }
}

pub fn verify_kb(
    kb_jwt: &str,
    kb_jwk: &Value,
    validation: &Validation,
) -> Result<(Value, Value), Error> {
    if kb_jwk["kty"].as_str() != Some("RSA") {
        return Err(Error::SDJWTRejected(
            "Issuer SD JWT cnf claim must contain RSA key".to_string(),
        ));
    }
    let e = kb_jwk["e"].as_str().ok_or(Error::SDJWTRejected(
        "Issuer SD JWT cnf claim must contain RSA key, invalid exponent".to_string(),
    ))?;
    let n = kb_jwk["n"].as_str().ok_or(Error::SDJWTRejected(
        "Issuer SD JWT cnf claim must contain RSA key, invalid modulus".to_string(),
    ))?;
    let (header, claims) = decode(
        kb_jwt,
        &KeyForDecoding::from_rsa_components(n, e)?,
        validation,
    )?;

    if header["typ"].as_str() != Some("kb+jwt") {
        return Err(Error::SDJWTRejected(
            "KB JWT type must be kb+jwt".to_string(),
        ));
    }

    Ok((header, claims))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::common_test_utils::{
        compare_json_values, convert_to_pem, disclosures2vec, keys, publickey_to_jwk,
        separate_jwt_and_disclosures,
    };
    use crate::{
        utils::{decode_claims_no_verification, get_jwt_part, JWTPart},
        Algorithm, Disclosure, Holder, Issuer, Jwk, KeyForEncoding, Validation,
    };
    use std::collections::HashSet;

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

        let kb_header = decode_claims_no_verification(&get_jwt_part(
            kb_jwt.as_ref().unwrap().as_str(),
            JWTPart::Header,
        )?)?;
        let kb_claims = decode_claims_no_verification(&get_jwt_part(
            kb_jwt.as_ref().unwrap().as_str(),
            JWTPart::Claims,
        )?)?;
        assert!(compare_json_values(
            &serde_json::json!({
              "typ": "kb+jwt",
              "alg": "RS256"
            }),
            &kb_header,
        ));
        assert_eq!(kb_claims["aud"], "https://someone.example.com");
        assert!(kb_claims["nonce"].is_string());
        assert!(kb_claims["iat"].is_number());
        assert!(kb_claims["sd_hash"].is_string());
        let mut issuer_jwt_with_disclosures = issuer_jwt.clone();
        disclosures.iter().for_each(|disclosure| {
            issuer_jwt_with_disclosures.push('~');
            issuer_jwt_with_disclosures.push_str(disclosure);
        });
        issuer_jwt_with_disclosures.push('~');
        assert_eq!(
            kb_claims["sd_hash"],
            base64_hash(HashAlgorithm::SHA256, &issuer_jwt_with_disclosures)
        );

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
}
