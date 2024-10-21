# sd-jwt

This crate implement draft of [SD-JWT](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/), currently at version 7.

# Installation

Add the following to Cargo.toml:

```
sdjwt = "0.7.0"
```

# Supported Algorithms

The library supports the following signing and verifying algorithms:

- **HMAC**: `HS256`, `HS384`, `HS512`
- **RSA**: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`
- **ECDSA**: `ES256`, `ES256K`, `ES384`, `ES512`

# How to use

There are three use cases: Issuer, Holder, and Verifier.

## Issuer

The Issuer module represents an issuer of claims, issuing SD-JWT with all disclosures.
Key features include:

- Creating new issuers with custom claims.
- Marking claims as disclosable.
- Optionally requiring a key binding.
- Encoding the issuer's claims into a SD-JWT.
- Randomly adding decoy digests.

Example:
```rust
use sdjwt::{Issuer, Jwk, Error, KeyForEncoding};
use serde_json::Value;
const ISSUER_CLAIMS: &str = r#"{
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
const ISSUER_SIGNING_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDSwzyVZp2AIxS3\n802n0AfwKsMUcMYATMM6kK5VVS21ku3d6QC8kfhvJ0Pcb24dmGUWAJ95H9m19qDF\nbLrVZ9b4iobOsNlXNhKn4TRrsVFa8EaGXAJjGNRPPcL+gFwfV9y3tfR00tkokhR5\nZhhMifwKJf55QlEzY96yyk8ISzhagwO6Kf/E980Eoby1tvhX8q8HIwLG4GjFnmXx\nbKqxVQR1T07vFKHsF1MK8/d6a7+samHPWjoSlLvKSE4rdK8gouRpN/5Who4iS2s7\nlhfS2DcnxCnxj9S9BBm4GIQNk0Tc+lR20btBm+JiehAyEV9vX222BVSLUC9z9HGD\nk39b9ezbAgMBAAECggEBAIXuRxtxX/jDUjEqzVgsXD8EDX95wnkCTrVypzXWsPtH\naRyxKiSqZcLMotT7gnAQHXyD3NMtqD13geazF27xU6wQ62WBADvpQqWn+JXO0jIF\nqetLoMC0UIYiaz0q+F96h+m+GJ/8NL8RRS138U0CCkWwqysHN25+sk/PO7W7hw4M\nOAN/97rBkXqyzJJSvNwl2A66ga+9WC8G/9YgweqkS6re6WAyo4z1KyZAE1r655JR\nEaiIR6GYvahNsy/dNjVtGR189o8bf6xnTPbDUXQ/D61nO3Kg3B7Ca/uQWiDbI9VJ\nMXZxgip9Q7Qil9WuK1vVCUSf6WK38NV6r9fubw/DgsECgYEA70drCiGrC3pvIJF0\nLJL46H6x6SFClR876BZEnN51udJGXRstWV+Ya6NULSTykwusaTYUnr2BC6r3tT4S\nrRLfnXTaI0Tr6Bws6kBSJJC0CS0lLqK2tlKbcypQXv0T6Ulv2NXDq0VqQB3txED6\n8m5GieppHNueqLQqGqM1V4JYw5ECgYEA4X2s7ccLB8MX01j4T6Fnj4BGaZsyc1kV\nn6VHsuAsUxA9ZuwV+lk5k6xaWxDYmQR3xZ4XcQEntRUtGFu4TMLVpCcK26Vqafrp\nymbGjJGFagIaP9YOhQ+5ZMfO0obYUEaDGhPjXH3G9O/dTXoRg5nP5JvdcAnf853y\nm1BaYBHbG6sCgYAfVkQffI9RHoTFSCdl2w28LTORq6hzrTaES75KqRvT7UUH1pJW\n3R0yI57XlroqJeI7mTiUHY9z/r0YQHvjrNAaZ/5VliYrLN15BFl9rnHVrdLry6WQ\nNTtklssV1aEw8UwzorNQj/O9V+4WwMfczjJwx4FipSSfRZEqEevffROw8QKBgGNK\nba0+KjM+yuz7jkuyLOHZgCfcePilz4m+w7WWVK42xnLdnkfgpiPKjvbukhG/D+Zq\n2LOf6JYqPvMs4Bic6mof7v4M9rC4Fd5UJzWaln65ckmNvlMFO4OPIBk/21xt0CjZ\nfRIrKEKOpIoLKE8kmZB2uakuD/k8IaoWVdVbx3mFAoGAMFFWZAAHpB18WaATQRR6\n86JnudPD3TlOw+8Zw4tlOoGv4VXCPVsyAH8CWNSONyTRxeSJpe8Pn6ZvPJ7YBt6c\nchNSaqFIl9UnkMJ1ckE7EX2zKFCg3k8VzqYRLC9TcqqwKTJcNdRu1SbWkAds6Sd8\nKKRrCm+L44uQ01gUYvYYv5c=\n-----END PRIVATE KEY-----\n";

fn main() -> Result<(), Error> {
   // holder's public key required for key binding
   let holder_jwk = Jwk::from_value(serde_json::json!({
        "kty": "RSA",
        "n": "...",
        "e": "...",
        "alg": "RS256",
        "use": "sig",
   }))?;
   // create issuer's claims
   let claims: Value = serde_json::from_str(ISSUER_CLAIMS).unwrap();
   let issuer = Issuer::new(claims)?
     .disclosable("/given_name")
     .disclosable("/family_name")
     .disclosable("/address/street_address")
     .disclosable("/address/locality")
     .disclosable("/nationalities/0")
     .disclosable("/nationalities/1")
     .require_key_binding(holder_jwk)
     .encode(&KeyForEncoding::from_rsa_pem(
        ISSUER_SIGNING_KEY_PEM.as_bytes(),
     )?)?;
   Ok(())
}
```

Issuer can also create claims using YAML and marking selective disclosures with !sd tag.

Example:
```rust
const ISSUER_CLAIMS_YAML: &str = r#"
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

let (claims, tagged_paths) = parse_yaml(TEST_CLAIMS_YAML)?;
let mut issuer = Issuer::new(claims)?;
let issuer_sd_jwt = issuer
    .require_key_binding(Jwk::from_value(holder_jwk)?)
    .iter_disclosable(tagged_paths.iter())
    .encode(&KeyForEncoding::from_rsa_pem(
        issuer_private_key.as_bytes(),
    )?)?;
println!("issuer_sd_jwt: {:?}", issuer_sd_jwt);
```

Issuer can add a random number of decoy digests.

Example
```rust
    let claims = serde_json::json!({
        "sub": "user_42",
        "given_name": "John",
        "family_name": "Doe",
        "email": "johndoe@example",
        "address": {
            "street_address": "123 Main St",
            "locality": "Anytown",
            "region": "Anystate",
            "country": "US"
        },
        "nationalities": [
            "US",
            "DE"
        ]
    });
    let encoded_jwt = Issuer::new(claims).unwrap()
        .disclosable("/given_name")
        .disclosable("/family_name")
        .disclosable("/address/street_address")
        .disclosable("/address/locality")
        .disclosable("/nationalities/0")
        .disclosable("/nationalities/1")
        .decoy(6)
        .encode(&KeyForEncoding::from_rsa_pem(
            ISSUER_SIGNING_KEY_PEM.as_bytes(),
        ).unwrap()).unwrap();
    println!("Encoded JWT: {}", encoded_jwt);
```

## Holder

The Holder module represents a Holder, presenting SD-JWT including selected disclosures.
Key features include:

- Verifying SD-JWTs for authenticity and integrity.
- Creating presentations with selective disclosures and optional key binding.

Example Verify SD-JWT from Issuer:
```rust
use sdjwt::{Holder, Error, KeyForDecoding, Validation};
const ISSUER_PUBKEY: &str = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA2a7Pz5WA1AmtGfIxSKwB8vU9OL1ti7udYhvC6048l74loAlmJGps\n0hb4u64jv8sAmdGjYeya2Oza1dydtSmlLArMkbeAiSV/n+KKmK0mpA7D7R8ARLKK\n/BZG7Z/QaxEORJl1KspliBQ2mUJJbcFH+EUko9bAdWEWx9GLkRH2pDm9nMO2lTtE\nqzO+JBjnuEoTn/NZ9Ur4dQDf3nWLBwEFyyJfJ90Ga2f6LFeHL2cOcAbHiofW5NAa\nGqh/JWxf6dSClyOUG0Bpe+RV8t0hnFhIC7RFV0aVbp50sqTM4mwYtOPk/2qWVVMF\nBOaswXYbi0ADUc9CqIaGDCAWnmHrHL/J4wIDAQAB\n-----END RSA PUBLIC KEY-----\n";
const ISSUER_SD_JWT: &str = "eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsiVFhsUEt1RjM1cDQ3ZW9XTlpEcklxS0w0R0JFaDBFWXJEQnBjNmFCWjUyQSIsIkdYWlpyVUlsdnBtaDB4b0h4WURadzFOZ211WXJrd1VVS09rNG1XTHZKYUEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJhZGRyZXNzIjp7Il9zZCI6WyJiUjVKM21ULXQ0a05pZ0V0dDJ5RVd1MU92b0hVMzBmSTZ1RVdJd2ozZWJBIiwiczhicTVKeUtJaFFwcVR1Vl9hcVNtd090UVN5UHV1TUlUU2xINXg1UWI5RSJdLCJjb3VudHJ5IjoiVVMiLCJyZWdpb24iOiJBbnlzdGF0ZSJ9LCJiaXJ0aGRhdGUiOiIxOTQwLTAxLTAxIiwiY25mIjp7ImFsZyI6IlJTMjU2IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiNS1EZDU0WHNNQU5UWm9KMllCcHVpWmFfYXpyMzJIcEJ3MUZjanA1d1UwWFBqbW9NQTdKVllDSk4wU05maDZ0dFhyWHhhYWhFNXdmUzd4S1E0N1ZvWXhYTjlLa3kxMzdDSUx0Q0xPWUJDZkdULWFRRXJKS0FJWUVORWtzbVNpU3k0VnVWRk1yTzlMOV9KTzViZk02QjZ6X3pickJYX2MxU2s0UFRLTnBqRTcxcTJHenU4ak5GdTR0c0JaOFFSdmtJVldxNGdxVklQNTFQQmZEcmNfTm53dk1aallGN2pfc0Z5eGg2ZExTVV96QkRrZjJOVWo4VXQ0M25vcW9YMGJoaE96aGdyTlpadGpFMTlrZGFlZTJYbjBweG0td3QzRjBxUjZxd2F2TFRJT21LVHE0OFdXSGxvUk5QWXpGbEo4OHNOaVNLeW9Ta0hXMG9SVDlscUhGX3ZRIiwidXNlIjoic2lnIn0sImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsIm5hdGlvbmFsaXRpZXMiOlt7Ii4uLiI6InhnU2FMYS1CNk03OWpwVWZtaE9Hb0pkSHdNS0RNR0s3eUVKdC0tX0xScDAifSx7Ii4uLiI6Im5vNWxNSkVJSmRWdHozS3lDMVRXVkk2T2tsQnZIMjFCOExOOVEzWkxWRmMifV0sInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwic3ViIjoidXNlcl80MiIsInVwZGF0ZWRfYXQiOjE1NzAwMDAwMDB9.K2h-DNDgnq6q61tSxm1Gv-Hfo46SD8rEcP7yLFxcAlQNKBY-l1-bpXCJcqVZ7jugs2lqng0Cf9e34tM1OPkU3R6Pi5kUMGSyJ2y2ifsaZhGLCgxzNKk5W2ZxdkehzZQ6nHy6iu4flbT92Szv0eBR0hmS3hYTCtHlE4xib9G2dKWTQigB4ylPMkoRzbiKjgkucGkxSLN5ZQRXdxkez19bk5Q9BwuNLQMKG0lanq4ZJWq1C4LPt_K0WhEntyTL6SxVxGfR5HaUSxeYPCCOWSz9AVyZ46DWZGRx48PbuXGgLDH1UJYIsMej2F89CU-3QkWUrFq9b-DCYCQMxbBBekeLog~WyJoV2xxekkxY3piQzhCMnF2Mm5vN3pBIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJ4NXdpQVg1Qks3MFNfYzhXX2Vybm5nIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyI4Q1BKSmNKV2tiOGVwT09yZkl5YUNRIiwic3RyZWV0X2FkZHJlc3MiLCIxMjMgTWFpbiBTdCJd~WyJDTGo2S0tjblA1M2taOG5kOWFueWxnIiwibG9jYWxpdHkiLCJBbnl0b3duIl0~WyI4UEVqT3FlY245cjhGY0llWThhRjh3IiwiVVMiXQ~WyJMR2hVZmV2Y0FkTGVUUEVzRnlCNi1BIiwiREUiXQ~";
fn main() -> Result<(), Error> {
    let mut validation = Validation::default().no_exp();
    let decoding_key = KeyForDecoding::from_rsa_pem(ISSUER_PUBKEY.as_bytes())?;
    let (header, decoded_claims, disclosure_paths) =
        Holder::verify(ISSUER_SD_JWT, &decoding_key, &validation)?;
    println!("header: {:?}", header);
    println!("claims: {:?}", decoded_claims);
    Ok(())
}
```

Example Create Presentation:
```rust
use sdjwt::{Holder, Error, KeyForEncoding, Algorithm};
fn main() -> Result<(), Error> {
    let sd_jwt = "eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsiVFhsUEt1RjM1cDQ3ZW9XTlpEcklxS0w0R0JFaDBFWXJEQnBjNmFCWjUyQSIsIkdYWlpyVUlsdnBtaDB4b0h4WURadzFOZ211WXJrd1VVS09rNG1XTHZKYUEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJhZGRyZXNzIjp7Il9zZCI6WyJiUjVKM21ULXQ0a05pZ0V0dDJ5RVd1MU92b0hVMzBmSTZ1RVdJd2ozZWJBIiwiczhicTVKeUtJaFFwcVR1Vl9hcVNtd090UVN5UHV1TUlUU2xINXg1UWI5RSJdLCJjb3VudHJ5IjoiVVMiLCJyZWdpb24iOiJBbnlzdGF0ZSJ9LCJiaXJ0aGRhdGUiOiIxOTQwLTAxLTAxIiwiY25mIjp7ImFsZyI6IlJTMjU2IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiNS1EZDU0WHNNQU5UWm9KMllCcHVpWmFfYXpyMzJIcEJ3MUZjanA1d1UwWFBqbW9NQTdKVllDSk4wU05maDZ0dFhyWHhhYWhFNXdmUzd4S1E0N1ZvWXhYTjlLa3kxMzdDSUx0Q0xPWUJDZkdULWFRRXJKS0FJWUVORWtzbVNpU3k0VnVWRk1yTzlMOV9KTzViZk02QjZ6X3pickJYX2MxU2s0UFRLTnBqRTcxcTJHenU4ak5GdTR0c0JaOFFSdmtJVldxNGdxVklQNTFQQmZEcmNfTm53dk1aallGN2pfc0Z5eGg2ZExTVV96QkRrZjJOVWo4VXQ0M25vcW9YMGJoaE96aGdyTlpadGpFMTlrZGFlZTJYbjBweG0td3QzRjBxUjZxd2F2TFRJT21LVHE0OFdXSGxvUk5QWXpGbEo4OHNOaVNLeW9Ta0hXMG9SVDlscUhGX3ZRIiwidXNlIjoic2lnIn0sImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsIm5hdGlvbmFsaXRpZXMiOlt7Ii4uLiI6InhnU2FMYS1CNk03OWpwVWZtaE9Hb0pkSHdNS0RNR0s3eUVKdC0tX0xScDAifSx7Ii4uLiI6Im5vNWxNSkVJSmRWdHozS3lDMVRXVkk2T2tsQnZIMjFCOExOOVEzWkxWRmMifV0sInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwic3ViIjoidXNlcl80MiIsInVwZGF0ZWRfYXQiOjE1NzAwMDAwMDB9.K2h-DNDgnq6q61tSxm1Gv-Hfo46SD8rEcP7yLFxcAlQNKBY-l1-bpXCJcqVZ7jugs2lqng0Cf9e34tM1OPkU3R6Pi5kUMGSyJ2y2ifsaZhGLCgxzNKk5W2ZxdkehzZQ6nHy6iu4flbT92Szv0eBR0hmS3hYTCtHlE4xib9G2dKWTQigB4ylPMkoRzbiKjgkucGkxSLN5ZQRXdxkez19bk5Q9BwuNLQMKG0lanq4ZJWq1C4LPt_K0WhEntyTL6SxVxGfR5HaUSxeYPCCOWSz9AVyZ46DWZGRx48PbuXGgLDH1UJYIsMej2F89CU-3QkWUrFq9b-DCYCQMxbBBekeLog~WyJoV2xxekkxY3piQzhCMnF2Mm5vN3pBIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJ4NXdpQVg1Qks3MFNfYzhXX2Vybm5nIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyI4Q1BKSmNKV2tiOGVwT09yZkl5YUNRIiwic3RyZWV0X2FkZHJlc3MiLCIxMjMgTWFpbiBTdCJd~WyJDTGo2S0tjblA1M2taOG5kOWFueWxnIiwibG9jYWxpdHkiLCJBbnl0b3duIl0~WyI4UEVqT3FlY245cjhGY0llWThhRjh3IiwiVVMiXQ~WyJMR2hVZmV2Y0FkTGVUUEVzRnlCNi1BIiwiREUiXQ~";
    let holder_private_key: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDUhGTgOOW+FQwC\nQHKFGMvdV5l5P6GffWTZtmQ2QW2x2ncfXR2HCdtETl+qtoD9FQ0+ZOFzaeXEMzGU\nVdoSh8AWsq7UgWOmeQkqWR8qBaRY8rMHYnTyUL9bOWfy8mTI7vidRYwMNfg/9weD\nKSCAELhmlKyN1xsIzd3oBbVE5ma02+Q8q2phK7p3lznYguxWzn4Bykx2ZVcGdTKa\ny5MQATYRJlnoMRfTsTlHjyfp7hFlUNUmBQ5jYFNtAL+HZ6Uoa+NaQwiZLE+fD+Or\n7xrDnWl9GkZt8ZQW/bK5YZWr0Tmbm/iYoaSQKuKVun57NDvJKCgmL+njigpAIBCv\n1wwYiSGpAgMBAAECggEBAIrGWclB3mSeAdWGmEHpy1ai2Ymfz78Cd1TkEdSMLUGy\n048bkyiXeyPDuh0USG77zEYuQjrHsE7Kz1l6JolrNDiePiRuyc/vwdhxkjQysvuS\noO31kUCbEhpUBllTiBTeWGL7A1UF+TJr8e/ob1yxjnkOJRAKo5DAPmRBNfnkKrV2\noZdR4v6suy5syacBgr1whoLtLrQhfAClReQ9HOfmw0QOm7PwO807ywhfIwMYPhn8\nGLaA/3w4qGK6y3GmhFj53SnFk4wu9ifXmMroo8/T5wbXdXeGQRZGwOQk2h2TkaRr\nOHC94WYBs7wx4qIjDHDqsWqIRXTNmpTNDsXzTmUlkgECgYEA6WDy+3ELcnbG9Uvs\n0Q9Wdm8yc/P9lWZ+AiRdKHfGLOSxWz8o5Z7sdFTL9x+IGT2btrV1nDHPk2pb5muU\n7gLU9p57wTWq36NqH2OXkCT4iqP9v2mp9fi1fSLqAFsnLxwQIZtqlSRwbvnySx0f\n/oqfDRWNL5TMzYCLpbLtGhaTi5ECgYEA6R3JjTPwLQq+Xpt/iFKr21WCFf7BVwoH\nRv5GBRy4D9UibCk8XAvnJslnHxIpSDoeVfW021LZAeLlp5N/H/PCY146xNRzwsd5\npANsGlNGMkRKqGCwdtOCekpFiZN7yzvsDAlbOcwKsaQffr0oIaf3FhrLc8+SAQjx\ni9KGns8jOJkCgYEApAGlwF4pFT+zgh7hRenpcUGjyyjkRGHKm+bCMPY7JsFwghdY\nvkV5FiehTwGxu0s4aqYLCMFYhthvzPY9qyYCU238ukLk2lUU9woeMQZKQ+QLJsEy\n19D4egBXQfjNCKZID9YQiM8a1GKCi5bkLRVtwNwsZAvGAYUcnk2nonXLKoECgYEA\ngw0e4MXBEOFIUlFiqdWoDZ8NiaX1NSRLIQsTfA5AH453Uo0ABNMgOLriwSHpmVQq\n97Iw4Ve67YeMCeAuiFz1+/zeVwcEqQyRArZ10HreLKYdvnjU24hegrc8TnJeFsvy\nEHY2FdDydhlJJ2vZosoVaxTXKZ0YfIJ1oGBTE/Zo24kCgYBPyXEMr/ngR4UTLnIK\nbSJXlxgCZtkJt3dB2Usj+HQQKMGwYbp06/ILtwKeseIfSzTBMk/lsc3k4CAAoyp3\nj/XUIVc4hK4xoHK6lzI9oViagKZw8gZHs3tBoMhm1HKQbX0djl52yeeAZby83ugr\n0HEpFk7OJvra7z9Z0jjqIQwVEg==\n-----END PRIVATE KEY-----\n";
    let presentation = Holder::presentation(sd_jwt)?
       .redact("/family_name")?
       .key_binding(
            "https://someone.example.com",
            &KeyForEncoding::from_rsa_pem(holder_private_key.as_bytes())?,
            Algorithm::RS256,
       )?
      .build()?;
    println!("{:?}", presentation);
    Ok(())
}
```

## Verifier

The Verifier module represents a Verifier, verifying SD-JWT presentations.

Example
```rust
use sdjwt::{Verifier, KeyForDecoding, Validation, Error};
use std::collections::HashSet;
const ISSUER_PUBKEY: &str = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA07aCbyrCS2/qYkuOyznaU/vQdobGtz/SvUKSzx4ic9Ax+pGi8OJM\noewxNg/6zFWkZeuZ1NMQMd/3aJLH+L+SqBNDox8cjWSzgR/Gf8xjVpMNiFrxrTx3\nz1ABaYfgsiDW/PhgoXCC7vF2dqLPTVBuObwmULjgmvPDFKUGEu9w/t05FaT+sccv\n2sMw1b8grlqG392etgbjKcvy29qG8Okj+CVPmYUe69Ce87mUOM5H4S9SF/yNLoFU\nczkUHQSa+sWe+QG6RskKay+3xophsMYYk4g4RHZuArg2LUvlDObmv/rsxKOVE3/B\nzV1DDjLs3AhHTwow2qCkFEZFof1dVOIjNwIDAQAB\n-----END RSA PUBLIC KEY-----\n";
const PRESENTATION: &str = "eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsiYlQzVnNrcVBwc0F1RWJ5VXBVb0o1UVVZaFp6TkZWSWw5TUhkN0hiWjNOSSIsInRWam9RWW1iT2FUOEt6YmRTMFpmUTdUTlU2UFlmV1RxQU1nNVlOUVJ1OUEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJhZGRyZXNzIjp7Il9zZCI6WyJ5WC13SXRkMmk1M2pCaV9jeHk3TE5Wd1J6Mm84ajlyd1IxQVJnVVFtVm9vIiwiQi14a3FHNzRvQzFCOUdheDlqQWZTWlVtQlBrVldhVmR1QVBSYlJkWHIyYyJdLCJjb3VudHJ5IjoiVVMiLCJyZWdpb24iOiJBbnlzdGF0ZSJ9LCJiaXJ0aGRhdGUiOiIxOTQwLTAxLTAxIiwiY25mIjp7ImFsZyI6IlJTMjU2IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiMFEta0s0aGZQbzZsMmFvVzlWUHR6S2hTaV9iN2t6ZTZ6eTlfVThTZjFsRmdxUGIwVXBvRTNuTW4zRUpyc0Jfb1hhb1RmY0RxaG4zTi1EblRFUFFmSTBfRTdnaHc3M0g1TWxiREdZM2VyajdzamE0enFIbmUyX1BZRnJvTFd3V0tjZDMzbUQ3VzhVYTdVSGV1a21GekFreXFEZlp1b0ZRcFdYLTFaVVdnalc0LUpoUUtYSXB4NVF6U1ZDX1hwaUFibzN3Zk5jQlFaaE8xSGxlTDV3VnFyMVZrUTgxcXl6Tlo3UFVRTWd0VlJGdkIyX3lPTlBDZ3piVzQ0TGNVQUFzYk5HNkdyX095WlBvblhuQml3b085LUxnNXdoQVc1TnlkU2ZwVi05UzE0NjV3Nm9IenpxdU1DX0JhcUQ5WVFTZ2pPVXpJb21fc3lYZG5GSTNyWWRZaG93IiwidXNlIjoic2lnIn0sImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsImV4cCI6MTcwMzg2NDkxMSwibmF0aW9uYWxpdGllcyI6W3siLi4uIjoiRDVSLXVQVEhMaTVFNVJqWEJwaW5Ia0VfV1Jxckl0UVFndnFyYWpEZ3ZPTSJ9LHsiLi4uIjoiNTJwZGc4enYtQ1RLT3U1bDhnVUpRalNKQ0I2dHF0NVJ1dUk5WkRESTJCdyJ9XSwicGhvbmVfbnVtYmVyIjoiKzEtMjAyLTU1NS0wMTAxIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIjp0cnVlLCJzdWIiOiJ1c2VyXzQyIiwidXBkYXRlZF9hdCI6MTU3MDAwMDAwMH0.aziX_zt4VylvCt4b_ILZacHQYWGFGsMUd0KEVgg4qtj8JwljDoL8845eHjV1ldpBp7hyWnkrV1X7ZtM7WK1F987ntNv5hK9o-5C2H18UpYKI9YZz5f8yETkWBmu9sH5HKtPv0lstJFc-kQB-jKRyidMxhwO_MU_oR_UtjpIjVd6atRLrwlud4ZM-un8R2R209au8TIE4JIAyzJA1IC5NTR4FdCcwGJiodj62lGRVpmvWhQspxtA9aGKSrnx0x8rL82_dE0hBrRkq5cfbiPR5GM1BN7FtA68OrWK9STHCAaH3VQxe0htOg3o8wlQ6rPMIP5B1Oc0932K56bGwXDZPCg~WyJGSjNhS2JyaWNONUdZRGQtdVk2dGVnIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyItQkFxQ2VJN0kzVUdaREJQR1RNcUpRIiwibG9jYWxpdHkiLCJBbnl0b3duIl0~WyI2RF8zUFpoSlQxTHVDR3o2WTVOMjVBIiwiREUiXQ~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL3NvbWVvbmUuZXhhbXBsZS5jb20iLCJpYXQiOjE3MDM4NjQ4NTEsIm5vbmNlIjoiODEzOWN2ZUdVTjFKQW1QTllGeWg5eTdqWmZab2VMZXIiLCJzZF9oYXNoIjoidUU1MTY0eTVqZ1NFNWg1V2FiUFpnU0lLWDFOX015Ti1qMlJhNnE3NDJ0ayJ9.BtYvadr-iT6poH9DQV5xAJxAxIFFsNRJ6AQ1rrGySpCVZ-1Dg7a9mvkP3Tf7dJ-r8O-cndJEaUaiKXSFZW7H8j-wO3hp0hrEqlp9OpCNON2EnwUrSm_XLFUFe-MinJZDMZ3qJeCLk7-AMvOgEHXHautwA3Sj2W_G4oDtH05tEHdy50lTVSblqINOLTdy8Vkz82Hs1WW7CVeUOQbsGbKNNAPczTDf00fQg18n6nGmpkHp7rgMV-Sq4qV2qxDeuXE00AkgPAzcMRyCx3Gk7NSWn9NtkTPK9Bporf58r_p5hf4lp-RoqRT0Uza1d5FcaoONl9GtLnhYURLKlCo9yhCbOA";
fn main() -> Result<(), Error> {
    let validation = Validation::default().no_exp();
    let mut kb_validation = Validation::default().no_exp();
    let mut audience = HashSet::new();
    audience.insert("https://someone.example.com".to_string());
    kb_validation.aud = Some(audience);
    let decoding_key = KeyForDecoding::from_rsa_pem(ISSUER_PUBKEY.as_bytes())?;
    let (ver_header, ver_claims) = Verifier::verify(
        PRESENTATION,
        &decoding_key,
        &validation,
        &Some(&kb_validation),
    )?;
    Ok(())
}
```