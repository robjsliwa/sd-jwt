use crate::utils::{remove_digests, restore_disclosures};
use crate::{
    base64_hash, decode, encode, sd_jwt_parts,
    utils::{decode_claims_no_verification, generate_nonce, get_jwt_part, JWTPart},
    Algorithm, DisclosurePath, Error, HashAlgorithm, Header, KeyForDecoding, KeyForEncoding,
    Validation,
};
use chrono::Utc;
use serde_json::Value;

/// # Holder Module
///
/// Represents a Holder.  Presents SD-JWT including selected disclosures.
///
/// ## Features
///
/// - Verifying SD-JWTs for authenticity and integrity.
/// - Creating presentations with selective disclosures and optional key binding.
///
/// Example Verify SD-JWT from Issuer:
///
/// ```
/// use sdjwt::{Holder, Error, KeyForDecoding, Validation};
///
/// const ISSUER_PUBKEY: &str = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA2a7Pz5WA1AmtGfIxSKwB8vU9OL1ti7udYhvC6048l74loAlmJGps\n0hb4u64jv8sAmdGjYeya2Oza1dydtSmlLArMkbeAiSV/n+KKmK0mpA7D7R8ARLKK\n/BZG7Z/QaxEORJl1KspliBQ2mUJJbcFH+EUko9bAdWEWx9GLkRH2pDm9nMO2lTtE\nqzO+JBjnuEoTn/NZ9Ur4dQDf3nWLBwEFyyJfJ90Ga2f6LFeHL2cOcAbHiofW5NAa\nGqh/JWxf6dSClyOUG0Bpe+RV8t0hnFhIC7RFV0aVbp50sqTM4mwYtOPk/2qWVVMF\nBOaswXYbi0ADUc9CqIaGDCAWnmHrHL/J4wIDAQAB\n-----END RSA PUBLIC KEY-----\n";
/// const ISSUER_SD_JWT: &str = "eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsiVFhsUEt1RjM1cDQ3ZW9XTlpEcklxS0w0R0JFaDBFWXJEQnBjNmFCWjUyQSIsIkdYWlpyVUlsdnBtaDB4b0h4WURadzFOZ211WXJrd1VVS09rNG1XTHZKYUEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJhZGRyZXNzIjp7Il9zZCI6WyJiUjVKM21ULXQ0a05pZ0V0dDJ5RVd1MU92b0hVMzBmSTZ1RVdJd2ozZWJBIiwiczhicTVKeUtJaFFwcVR1Vl9hcVNtd090UVN5UHV1TUlUU2xINXg1UWI5RSJdLCJjb3VudHJ5IjoiVVMiLCJyZWdpb24iOiJBbnlzdGF0ZSJ9LCJiaXJ0aGRhdGUiOiIxOTQwLTAxLTAxIiwiY25mIjp7ImFsZyI6IlJTMjU2IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiNS1EZDU0WHNNQU5UWm9KMllCcHVpWmFfYXpyMzJIcEJ3MUZjanA1d1UwWFBqbW9NQTdKVllDSk4wU05maDZ0dFhyWHhhYWhFNXdmUzd4S1E0N1ZvWXhYTjlLa3kxMzdDSUx0Q0xPWUJDZkdULWFRRXJKS0FJWUVORWtzbVNpU3k0VnVWRk1yTzlMOV9KTzViZk02QjZ6X3pickJYX2MxU2s0UFRLTnBqRTcxcTJHenU4ak5GdTR0c0JaOFFSdmtJVldxNGdxVklQNTFQQmZEcmNfTm53dk1aallGN2pfc0Z5eGg2ZExTVV96QkRrZjJOVWo4VXQ0M25vcW9YMGJoaE96aGdyTlpadGpFMTlrZGFlZTJYbjBweG0td3QzRjBxUjZxd2F2TFRJT21LVHE0OFdXSGxvUk5QWXpGbEo4OHNOaVNLeW9Ta0hXMG9SVDlscUhGX3ZRIiwidXNlIjoic2lnIn0sImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsIm5hdGlvbmFsaXRpZXMiOlt7Ii4uLiI6InhnU2FMYS1CNk03OWpwVWZtaE9Hb0pkSHdNS0RNR0s3eUVKdC0tX0xScDAifSx7Ii4uLiI6Im5vNWxNSkVJSmRWdHozS3lDMVRXVkk2T2tsQnZIMjFCOExOOVEzWkxWRmMifV0sInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwic3ViIjoidXNlcl80MiIsInVwZGF0ZWRfYXQiOjE1NzAwMDAwMDB9.K2h-DNDgnq6q61tSxm1Gv-Hfo46SD8rEcP7yLFxcAlQNKBY-l1-bpXCJcqVZ7jugs2lqng0Cf9e34tM1OPkU3R6Pi5kUMGSyJ2y2ifsaZhGLCgxzNKk5W2ZxdkehzZQ6nHy6iu4flbT92Szv0eBR0hmS3hYTCtHlE4xib9G2dKWTQigB4ylPMkoRzbiKjgkucGkxSLN5ZQRXdxkez19bk5Q9BwuNLQMKG0lanq4ZJWq1C4LPt_K0WhEntyTL6SxVxGfR5HaUSxeYPCCOWSz9AVyZ46DWZGRx48PbuXGgLDH1UJYIsMej2F89CU-3QkWUrFq9b-DCYCQMxbBBekeLog~WyJoV2xxekkxY3piQzhCMnF2Mm5vN3pBIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJ4NXdpQVg1Qks3MFNfYzhXX2Vybm5nIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyI4Q1BKSmNKV2tiOGVwT09yZkl5YUNRIiwic3RyZWV0X2FkZHJlc3MiLCIxMjMgTWFpbiBTdCJd~WyJDTGo2S0tjblA1M2taOG5kOWFueWxnIiwibG9jYWxpdHkiLCJBbnl0b3duIl0~WyI4UEVqT3FlY245cjhGY0llWThhRjh3IiwiVVMiXQ~WyJMR2hVZmV2Y0FkTGVUUEVzRnlCNi1BIiwiREUiXQ~";
///
/// fn main() -> Result<(), Error> {
///     let mut validation = Validation::default().no_exp();
///     let decoding_key = KeyForDecoding::from_rsa_pem(ISSUER_PUBKEY.as_bytes())?;
///     let (header, decoded_claims, disclosure_paths) =
///         Holder::verify(ISSUER_SD_JWT, &decoding_key, &validation)?;
///     println!("header: {:?}", header);
///     println!("claims: {:?}", decoded_claims);
///
///     Ok(())
/// }
/// ```
///
/// Example Create Presentation:
///
/// ```rust
/// use sdjwt::{Holder, Error, KeyForEncoding, Algorithm};
///
/// fn main() -> Result<(), Error> {
///     let sd_jwt = "eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsiVFhsUEt1RjM1cDQ3ZW9XTlpEcklxS0w0R0JFaDBFWXJEQnBjNmFCWjUyQSIsIkdYWlpyVUlsdnBtaDB4b0h4WURadzFOZ211WXJrd1VVS09rNG1XTHZKYUEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJhZGRyZXNzIjp7Il9zZCI6WyJiUjVKM21ULXQ0a05pZ0V0dDJ5RVd1MU92b0hVMzBmSTZ1RVdJd2ozZWJBIiwiczhicTVKeUtJaFFwcVR1Vl9hcVNtd090UVN5UHV1TUlUU2xINXg1UWI5RSJdLCJjb3VudHJ5IjoiVVMiLCJyZWdpb24iOiJBbnlzdGF0ZSJ9LCJiaXJ0aGRhdGUiOiIxOTQwLTAxLTAxIiwiY25mIjp7ImFsZyI6IlJTMjU2IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiNS1EZDU0WHNNQU5UWm9KMllCcHVpWmFfYXpyMzJIcEJ3MUZjanA1d1UwWFBqbW9NQTdKVllDSk4wU05maDZ0dFhyWHhhYWhFNXdmUzd4S1E0N1ZvWXhYTjlLa3kxMzdDSUx0Q0xPWUJDZkdULWFRRXJKS0FJWUVORWtzbVNpU3k0VnVWRk1yTzlMOV9KTzViZk02QjZ6X3pickJYX2MxU2s0UFRLTnBqRTcxcTJHenU4ak5GdTR0c0JaOFFSdmtJVldxNGdxVklQNTFQQmZEcmNfTm53dk1aallGN2pfc0Z5eGg2ZExTVV96QkRrZjJOVWo4VXQ0M25vcW9YMGJoaE96aGdyTlpadGpFMTlrZGFlZTJYbjBweG0td3QzRjBxUjZxd2F2TFRJT21LVHE0OFdXSGxvUk5QWXpGbEo4OHNOaVNLeW9Ta0hXMG9SVDlscUhGX3ZRIiwidXNlIjoic2lnIn0sImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsIm5hdGlvbmFsaXRpZXMiOlt7Ii4uLiI6InhnU2FMYS1CNk03OWpwVWZtaE9Hb0pkSHdNS0RNR0s3eUVKdC0tX0xScDAifSx7Ii4uLiI6Im5vNWxNSkVJSmRWdHozS3lDMVRXVkk2T2tsQnZIMjFCOExOOVEzWkxWRmMifV0sInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwic3ViIjoidXNlcl80MiIsInVwZGF0ZWRfYXQiOjE1NzAwMDAwMDB9.K2h-DNDgnq6q61tSxm1Gv-Hfo46SD8rEcP7yLFxcAlQNKBY-l1-bpXCJcqVZ7jugs2lqng0Cf9e34tM1OPkU3R6Pi5kUMGSyJ2y2ifsaZhGLCgxzNKk5W2ZxdkehzZQ6nHy6iu4flbT92Szv0eBR0hmS3hYTCtHlE4xib9G2dKWTQigB4ylPMkoRzbiKjgkucGkxSLN5ZQRXdxkez19bk5Q9BwuNLQMKG0lanq4ZJWq1C4LPt_K0WhEntyTL6SxVxGfR5HaUSxeYPCCOWSz9AVyZ46DWZGRx48PbuXGgLDH1UJYIsMej2F89CU-3QkWUrFq9b-DCYCQMxbBBekeLog~WyJoV2xxekkxY3piQzhCMnF2Mm5vN3pBIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJ4NXdpQVg1Qks3MFNfYzhXX2Vybm5nIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyI4Q1BKSmNKV2tiOGVwT09yZkl5YUNRIiwic3RyZWV0X2FkZHJlc3MiLCIxMjMgTWFpbiBTdCJd~WyJDTGo2S0tjblA1M2taOG5kOWFueWxnIiwibG9jYWxpdHkiLCJBbnl0b3duIl0~WyI4UEVqT3FlY245cjhGY0llWThhRjh3IiwiVVMiXQ~WyJMR2hVZmV2Y0FkTGVUUEVzRnlCNi1BIiwiREUiXQ~";
///     let holder_private_key: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDUhGTgOOW+FQwC\nQHKFGMvdV5l5P6GffWTZtmQ2QW2x2ncfXR2HCdtETl+qtoD9FQ0+ZOFzaeXEMzGU\nVdoSh8AWsq7UgWOmeQkqWR8qBaRY8rMHYnTyUL9bOWfy8mTI7vidRYwMNfg/9weD\nKSCAELhmlKyN1xsIzd3oBbVE5ma02+Q8q2phK7p3lznYguxWzn4Bykx2ZVcGdTKa\ny5MQATYRJlnoMRfTsTlHjyfp7hFlUNUmBQ5jYFNtAL+HZ6Uoa+NaQwiZLE+fD+Or\n7xrDnWl9GkZt8ZQW/bK5YZWr0Tmbm/iYoaSQKuKVun57NDvJKCgmL+njigpAIBCv\n1wwYiSGpAgMBAAECggEBAIrGWclB3mSeAdWGmEHpy1ai2Ymfz78Cd1TkEdSMLUGy\n048bkyiXeyPDuh0USG77zEYuQjrHsE7Kz1l6JolrNDiePiRuyc/vwdhxkjQysvuS\noO31kUCbEhpUBllTiBTeWGL7A1UF+TJr8e/ob1yxjnkOJRAKo5DAPmRBNfnkKrV2\noZdR4v6suy5syacBgr1whoLtLrQhfAClReQ9HOfmw0QOm7PwO807ywhfIwMYPhn8\nGLaA/3w4qGK6y3GmhFj53SnFk4wu9ifXmMroo8/T5wbXdXeGQRZGwOQk2h2TkaRr\nOHC94WYBs7wx4qIjDHDqsWqIRXTNmpTNDsXzTmUlkgECgYEA6WDy+3ELcnbG9Uvs\n0Q9Wdm8yc/P9lWZ+AiRdKHfGLOSxWz8o5Z7sdFTL9x+IGT2btrV1nDHPk2pb5muU\n7gLU9p57wTWq36NqH2OXkCT4iqP9v2mp9fi1fSLqAFsnLxwQIZtqlSRwbvnySx0f\n/oqfDRWNL5TMzYCLpbLtGhaTi5ECgYEA6R3JjTPwLQq+Xpt/iFKr21WCFf7BVwoH\nRv5GBRy4D9UibCk8XAvnJslnHxIpSDoeVfW021LZAeLlp5N/H/PCY146xNRzwsd5\npANsGlNGMkRKqGCwdtOCekpFiZN7yzvsDAlbOcwKsaQffr0oIaf3FhrLc8+SAQjx\ni9KGns8jOJkCgYEApAGlwF4pFT+zgh7hRenpcUGjyyjkRGHKm+bCMPY7JsFwghdY\nvkV5FiehTwGxu0s4aqYLCMFYhthvzPY9qyYCU238ukLk2lUU9woeMQZKQ+QLJsEy\n19D4egBXQfjNCKZID9YQiM8a1GKCi5bkLRVtwNwsZAvGAYUcnk2nonXLKoECgYEA\ngw0e4MXBEOFIUlFiqdWoDZ8NiaX1NSRLIQsTfA5AH453Uo0ABNMgOLriwSHpmVQq\n97Iw4Ve67YeMCeAuiFz1+/zeVwcEqQyRArZ10HreLKYdvnjU24hegrc8TnJeFsvy\nEHY2FdDydhlJJ2vZosoVaxTXKZ0YfIJ1oGBTE/Zo24kCgYBPyXEMr/ngR4UTLnIK\nbSJXlxgCZtkJt3dB2Usj+HQQKMGwYbp06/ILtwKeseIfSzTBMk/lsc3k4CAAoyp3\nj/XUIVc4hK4xoHK6lzI9oViagKZw8gZHs3tBoMhm1HKQbX0djl52yeeAZby83ugr\n0HEpFk7OJvra7z9Z0jjqIQwVEg==\n-----END PRIVATE KEY-----\n";
///     let presentation = Holder::presentation(sd_jwt)?
///        .redact("/family_name")?
///        .key_binding(
///             "https://someone.example.com",
///             &KeyForEncoding::from_rsa_pem(holder_private_key.as_bytes())?,
///             Algorithm::RS256,
///        )?
///       .build()?;
///     println!("{:?}", presentation);
///     Ok(())
/// }
/// ```
pub struct Holder {
    sd_jwt: String,
    redacted: Vec<String>,
    disclosure_paths: Vec<DisclosurePath>,
    aud: Option<String>,
    key: Option<KeyForEncoding>,
    algorithm: Option<Algorithm>,
}

impl Holder {
    /// Create a presentation from SD-JWT received from Issuer.
    /// ```rust
    /// use sdjwt::Holder;
    /// use sdjwt::Error;
    ///
    /// fn main() -> Result<(), Error> {
    ///     let sd_jwt = "eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsiVFhsUEt1RjM1cDQ3ZW9XTlpEcklxS0w0R0JFaDBFWXJEQnBjNmFCWjUyQSIsIkdYWlpyVUlsdnBtaDB4b0h4WURadzFOZ211WXJrd1VVS09rNG1XTHZKYUEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJhZGRyZXNzIjp7Il9zZCI6WyJiUjVKM21ULXQ0a05pZ0V0dDJ5RVd1MU92b0hVMzBmSTZ1RVdJd2ozZWJBIiwiczhicTVKeUtJaFFwcVR1Vl9hcVNtd090UVN5UHV1TUlUU2xINXg1UWI5RSJdLCJjb3VudHJ5IjoiVVMiLCJyZWdpb24iOiJBbnlzdGF0ZSJ9LCJiaXJ0aGRhdGUiOiIxOTQwLTAxLTAxIiwiY25mIjp7ImFsZyI6IlJTMjU2IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiNS1EZDU0WHNNQU5UWm9KMllCcHVpWmFfYXpyMzJIcEJ3MUZjanA1d1UwWFBqbW9NQTdKVllDSk4wU05maDZ0dFhyWHhhYWhFNXdmUzd4S1E0N1ZvWXhYTjlLa3kxMzdDSUx0Q0xPWUJDZkdULWFRRXJKS0FJWUVORWtzbVNpU3k0VnVWRk1yTzlMOV9KTzViZk02QjZ6X3pickJYX2MxU2s0UFRLTnBqRTcxcTJHenU4ak5GdTR0c0JaOFFSdmtJVldxNGdxVklQNTFQQmZEcmNfTm53dk1aallGN2pfc0Z5eGg2ZExTVV96QkRrZjJOVWo4VXQ0M25vcW9YMGJoaE96aGdyTlpadGpFMTlrZGFlZTJYbjBweG0td3QzRjBxUjZxd2F2TFRJT21LVHE0OFdXSGxvUk5QWXpGbEo4OHNOaVNLeW9Ta0hXMG9SVDlscUhGX3ZRIiwidXNlIjoic2lnIn0sImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsIm5hdGlvbmFsaXRpZXMiOlt7Ii4uLiI6InhnU2FMYS1CNk03OWpwVWZtaE9Hb0pkSHdNS0RNR0s3eUVKdC0tX0xScDAifSx7Ii4uLiI6Im5vNWxNSkVJSmRWdHozS3lDMVRXVkk2T2tsQnZIMjFCOExOOVEzWkxWRmMifV0sInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwic3ViIjoidXNlcl80MiIsInVwZGF0ZWRfYXQiOjE1NzAwMDAwMDB9.K2h-DNDgnq6q61tSxm1Gv-Hfo46SD8rEcP7yLFxcAlQNKBY-l1-bpXCJcqVZ7jugs2lqng0Cf9e34tM1OPkU3R6Pi5kUMGSyJ2y2ifsaZhGLCgxzNKk5W2ZxdkehzZQ6nHy6iu4flbT92Szv0eBR0hmS3hYTCtHlE4xib9G2dKWTQigB4ylPMkoRzbiKjgkucGkxSLN5ZQRXdxkez19bk5Q9BwuNLQMKG0lanq4ZJWq1C4LPt_K0WhEntyTL6SxVxGfR5HaUSxeYPCCOWSz9AVyZ46DWZGRx48PbuXGgLDH1UJYIsMej2F89CU-3QkWUrFq9b-DCYCQMxbBBekeLog~WyJoV2xxekkxY3piQzhCMnF2Mm5vN3pBIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJ4NXdpQVg1Qks3MFNfYzhXX2Vybm5nIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyI4Q1BKSmNKV2tiOGVwT09yZkl5YUNRIiwic3RyZWV0X2FkZHJlc3MiLCIxMjMgTWFpbiBTdCJd~WyJDTGo2S0tjblA1M2taOG5kOWFueWxnIiwibG9jYWxpdHkiLCJBbnl0b3duIl0~WyI4UEVqT3FlY245cjhGY0llWThhRjh3IiwiVVMiXQ~WyJMR2hVZmV2Y0FkTGVUUEVzRnlCNi1BIiwiREUiXQ~";
    ///     let presentation = Holder::presentation(sd_jwt)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn presentation(sd_jwt: &str) -> Result<Self, Error> {
        let (issuer_sd_jwt, disclosures, kb_jwt) = sd_jwt_parts(sd_jwt);
        if kb_jwt.is_some() {
            return Err(Error::SDJWTRejected(
                ("Issuer SD JWT cannot contain key binding JWT").to_string(),
            ));
        }

        let issuer_jwt = get_jwt_part(issuer_sd_jwt.as_str(), JWTPart::Claims)?;
        let mut issuer_jwt_claims = decode_claims_no_verification(issuer_jwt.as_str())?;
        let algorithm = issuer_jwt_claims["_sd_alg"].as_str().unwrap_or("");
        let algorithm = HashAlgorithm::try_from(algorithm)?;
        let mut disclosure_paths = Vec::new();
        restore_disclosures(
            &mut issuer_jwt_claims,
            &disclosures,
            &mut disclosure_paths,
            algorithm,
        )?;

        Ok(Holder {
            sd_jwt: issuer_sd_jwt,
            redacted: Vec::new(),
            disclosure_paths,
            aud: None,
            key: None,
            algorithm: None,
        })
    }

    /// Redact specific claims from the SD-JWT.
    ///
    /// ```rust
    /// use sdjwt::Holder;
    /// use sdjwt::Error;
    ///
    /// fn main() -> Result<(), Error> {
    ///     let sd_jwt = "eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsiVFhsUEt1RjM1cDQ3ZW9XTlpEcklxS0w0R0JFaDBFWXJEQnBjNmFCWjUyQSIsIkdYWlpyVUlsdnBtaDB4b0h4WURadzFOZ211WXJrd1VVS09rNG1XTHZKYUEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJhZGRyZXNzIjp7Il9zZCI6WyJiUjVKM21ULXQ0a05pZ0V0dDJ5RVd1MU92b0hVMzBmSTZ1RVdJd2ozZWJBIiwiczhicTVKeUtJaFFwcVR1Vl9hcVNtd090UVN5UHV1TUlUU2xINXg1UWI5RSJdLCJjb3VudHJ5IjoiVVMiLCJyZWdpb24iOiJBbnlzdGF0ZSJ9LCJiaXJ0aGRhdGUiOiIxOTQwLTAxLTAxIiwiY25mIjp7ImFsZyI6IlJTMjU2IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiNS1EZDU0WHNNQU5UWm9KMllCcHVpWmFfYXpyMzJIcEJ3MUZjanA1d1UwWFBqbW9NQTdKVllDSk4wU05maDZ0dFhyWHhhYWhFNXdmUzd4S1E0N1ZvWXhYTjlLa3kxMzdDSUx0Q0xPWUJDZkdULWFRRXJKS0FJWUVORWtzbVNpU3k0VnVWRk1yTzlMOV9KTzViZk02QjZ6X3pickJYX2MxU2s0UFRLTnBqRTcxcTJHenU4ak5GdTR0c0JaOFFSdmtJVldxNGdxVklQNTFQQmZEcmNfTm53dk1aallGN2pfc0Z5eGg2ZExTVV96QkRrZjJOVWo4VXQ0M25vcW9YMGJoaE96aGdyTlpadGpFMTlrZGFlZTJYbjBweG0td3QzRjBxUjZxd2F2TFRJT21LVHE0OFdXSGxvUk5QWXpGbEo4OHNOaVNLeW9Ta0hXMG9SVDlscUhGX3ZRIiwidXNlIjoic2lnIn0sImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsIm5hdGlvbmFsaXRpZXMiOlt7Ii4uLiI6InhnU2FMYS1CNk03OWpwVWZtaE9Hb0pkSHdNS0RNR0s3eUVKdC0tX0xScDAifSx7Ii4uLiI6Im5vNWxNSkVJSmRWdHozS3lDMVRXVkk2T2tsQnZIMjFCOExOOVEzWkxWRmMifV0sInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwic3ViIjoidXNlcl80MiIsInVwZGF0ZWRfYXQiOjE1NzAwMDAwMDB9.K2h-DNDgnq6q61tSxm1Gv-Hfo46SD8rEcP7yLFxcAlQNKBY-l1-bpXCJcqVZ7jugs2lqng0Cf9e34tM1OPkU3R6Pi5kUMGSyJ2y2ifsaZhGLCgxzNKk5W2ZxdkehzZQ6nHy6iu4flbT92Szv0eBR0hmS3hYTCtHlE4xib9G2dKWTQigB4ylPMkoRzbiKjgkucGkxSLN5ZQRXdxkez19bk5Q9BwuNLQMKG0lanq4ZJWq1C4LPt_K0WhEntyTL6SxVxGfR5HaUSxeYPCCOWSz9AVyZ46DWZGRx48PbuXGgLDH1UJYIsMej2F89CU-3QkWUrFq9b-DCYCQMxbBBekeLog~WyJoV2xxekkxY3piQzhCMnF2Mm5vN3pBIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJ4NXdpQVg1Qks3MFNfYzhXX2Vybm5nIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyI4Q1BKSmNKV2tiOGVwT09yZkl5YUNRIiwic3RyZWV0X2FkZHJlc3MiLCIxMjMgTWFpbiBTdCJd~WyJDTGo2S0tjblA1M2taOG5kOWFueWxnIiwibG9jYWxpdHkiLCJBbnl0b3duIl0~WyI4UEVqT3FlY245cjhGY0llWThhRjh3IiwiVVMiXQ~WyJMR2hVZmV2Y0FkTGVUUEVzRnlCNi1BIiwiREUiXQ~";
    ///     let presentation = Holder::presentation(sd_jwt)?
    ///        .redact("/family_name")?;
    ///     Ok(())
    /// }
    /// ```
    pub fn redact(&mut self, path: &str) -> Result<&mut Self, Error> {
        self.redacted.push(path.to_string());
        Ok(self)
    }

    /// Add key binding JWT if needed.
    ///
    /// ```rust
    /// use sdjwt::{Holder, Error, KeyForEncoding, Algorithm};
    ///
    /// fn main() -> Result<(), Error> {
    ///     let sd_jwt = "eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsiVFhsUEt1RjM1cDQ3ZW9XTlpEcklxS0w0R0JFaDBFWXJEQnBjNmFCWjUyQSIsIkdYWlpyVUlsdnBtaDB4b0h4WURadzFOZ211WXJrd1VVS09rNG1XTHZKYUEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJhZGRyZXNzIjp7Il9zZCI6WyJiUjVKM21ULXQ0a05pZ0V0dDJ5RVd1MU92b0hVMzBmSTZ1RVdJd2ozZWJBIiwiczhicTVKeUtJaFFwcVR1Vl9hcVNtd090UVN5UHV1TUlUU2xINXg1UWI5RSJdLCJjb3VudHJ5IjoiVVMiLCJyZWdpb24iOiJBbnlzdGF0ZSJ9LCJiaXJ0aGRhdGUiOiIxOTQwLTAxLTAxIiwiY25mIjp7ImFsZyI6IlJTMjU2IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiNS1EZDU0WHNNQU5UWm9KMllCcHVpWmFfYXpyMzJIcEJ3MUZjanA1d1UwWFBqbW9NQTdKVllDSk4wU05maDZ0dFhyWHhhYWhFNXdmUzd4S1E0N1ZvWXhYTjlLa3kxMzdDSUx0Q0xPWUJDZkdULWFRRXJKS0FJWUVORWtzbVNpU3k0VnVWRk1yTzlMOV9KTzViZk02QjZ6X3pickJYX2MxU2s0UFRLTnBqRTcxcTJHenU4ak5GdTR0c0JaOFFSdmtJVldxNGdxVklQNTFQQmZEcmNfTm53dk1aallGN2pfc0Z5eGg2ZExTVV96QkRrZjJOVWo4VXQ0M25vcW9YMGJoaE96aGdyTlpadGpFMTlrZGFlZTJYbjBweG0td3QzRjBxUjZxd2F2TFRJT21LVHE0OFdXSGxvUk5QWXpGbEo4OHNOaVNLeW9Ta0hXMG9SVDlscUhGX3ZRIiwidXNlIjoic2lnIn0sImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsIm5hdGlvbmFsaXRpZXMiOlt7Ii4uLiI6InhnU2FMYS1CNk03OWpwVWZtaE9Hb0pkSHdNS0RNR0s3eUVKdC0tX0xScDAifSx7Ii4uLiI6Im5vNWxNSkVJSmRWdHozS3lDMVRXVkk2T2tsQnZIMjFCOExOOVEzWkxWRmMifV0sInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwic3ViIjoidXNlcl80MiIsInVwZGF0ZWRfYXQiOjE1NzAwMDAwMDB9.K2h-DNDgnq6q61tSxm1Gv-Hfo46SD8rEcP7yLFxcAlQNKBY-l1-bpXCJcqVZ7jugs2lqng0Cf9e34tM1OPkU3R6Pi5kUMGSyJ2y2ifsaZhGLCgxzNKk5W2ZxdkehzZQ6nHy6iu4flbT92Szv0eBR0hmS3hYTCtHlE4xib9G2dKWTQigB4ylPMkoRzbiKjgkucGkxSLN5ZQRXdxkez19bk5Q9BwuNLQMKG0lanq4ZJWq1C4LPt_K0WhEntyTL6SxVxGfR5HaUSxeYPCCOWSz9AVyZ46DWZGRx48PbuXGgLDH1UJYIsMej2F89CU-3QkWUrFq9b-DCYCQMxbBBekeLog~WyJoV2xxekkxY3piQzhCMnF2Mm5vN3pBIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJ4NXdpQVg1Qks3MFNfYzhXX2Vybm5nIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyI4Q1BKSmNKV2tiOGVwT09yZkl5YUNRIiwic3RyZWV0X2FkZHJlc3MiLCIxMjMgTWFpbiBTdCJd~WyJDTGo2S0tjblA1M2taOG5kOWFueWxnIiwibG9jYWxpdHkiLCJBbnl0b3duIl0~WyI4UEVqT3FlY245cjhGY0llWThhRjh3IiwiVVMiXQ~WyJMR2hVZmV2Y0FkTGVUUEVzRnlCNi1BIiwiREUiXQ~";
    ///     let holder_private_key: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDUhGTgOOW+FQwC\nQHKFGMvdV5l5P6GffWTZtmQ2QW2x2ncfXR2HCdtETl+qtoD9FQ0+ZOFzaeXEMzGU\nVdoSh8AWsq7UgWOmeQkqWR8qBaRY8rMHYnTyUL9bOWfy8mTI7vidRYwMNfg/9weD\nKSCAELhmlKyN1xsIzd3oBbVE5ma02+Q8q2phK7p3lznYguxWzn4Bykx2ZVcGdTKa\ny5MQATYRJlnoMRfTsTlHjyfp7hFlUNUmBQ5jYFNtAL+HZ6Uoa+NaQwiZLE+fD+Or\n7xrDnWl9GkZt8ZQW/bK5YZWr0Tmbm/iYoaSQKuKVun57NDvJKCgmL+njigpAIBCv\n1wwYiSGpAgMBAAECggEBAIrGWclB3mSeAdWGmEHpy1ai2Ymfz78Cd1TkEdSMLUGy\n048bkyiXeyPDuh0USG77zEYuQjrHsE7Kz1l6JolrNDiePiRuyc/vwdhxkjQysvuS\noO31kUCbEhpUBllTiBTeWGL7A1UF+TJr8e/ob1yxjnkOJRAKo5DAPmRBNfnkKrV2\noZdR4v6suy5syacBgr1whoLtLrQhfAClReQ9HOfmw0QOm7PwO807ywhfIwMYPhn8\nGLaA/3w4qGK6y3GmhFj53SnFk4wu9ifXmMroo8/T5wbXdXeGQRZGwOQk2h2TkaRr\nOHC94WYBs7wx4qIjDHDqsWqIRXTNmpTNDsXzTmUlkgECgYEA6WDy+3ELcnbG9Uvs\n0Q9Wdm8yc/P9lWZ+AiRdKHfGLOSxWz8o5Z7sdFTL9x+IGT2btrV1nDHPk2pb5muU\n7gLU9p57wTWq36NqH2OXkCT4iqP9v2mp9fi1fSLqAFsnLxwQIZtqlSRwbvnySx0f\n/oqfDRWNL5TMzYCLpbLtGhaTi5ECgYEA6R3JjTPwLQq+Xpt/iFKr21WCFf7BVwoH\nRv5GBRy4D9UibCk8XAvnJslnHxIpSDoeVfW021LZAeLlp5N/H/PCY146xNRzwsd5\npANsGlNGMkRKqGCwdtOCekpFiZN7yzvsDAlbOcwKsaQffr0oIaf3FhrLc8+SAQjx\ni9KGns8jOJkCgYEApAGlwF4pFT+zgh7hRenpcUGjyyjkRGHKm+bCMPY7JsFwghdY\nvkV5FiehTwGxu0s4aqYLCMFYhthvzPY9qyYCU238ukLk2lUU9woeMQZKQ+QLJsEy\n19D4egBXQfjNCKZID9YQiM8a1GKCi5bkLRVtwNwsZAvGAYUcnk2nonXLKoECgYEA\ngw0e4MXBEOFIUlFiqdWoDZ8NiaX1NSRLIQsTfA5AH453Uo0ABNMgOLriwSHpmVQq\n97Iw4Ve67YeMCeAuiFz1+/zeVwcEqQyRArZ10HreLKYdvnjU24hegrc8TnJeFsvy\nEHY2FdDydhlJJ2vZosoVaxTXKZ0YfIJ1oGBTE/Zo24kCgYBPyXEMr/ngR4UTLnIK\nbSJXlxgCZtkJt3dB2Usj+HQQKMGwYbp06/ILtwKeseIfSzTBMk/lsc3k4CAAoyp3\nj/XUIVc4hK4xoHK6lzI9oViagKZw8gZHs3tBoMhm1HKQbX0djl52yeeAZby83ugr\n0HEpFk7OJvra7z9Z0jjqIQwVEg==\n-----END PRIVATE KEY-----\n";
    ///     let presentation = Holder::presentation(sd_jwt)?
    ///        .redact("/family_name")?
    ///        .key_binding(
    ///             "https://someone.example.com",
    ///             &KeyForEncoding::from_rsa_pem(holder_private_key.as_bytes())?,
    ///             Algorithm::RS256,
    ///        )?;
    ///     Ok(())
    /// }
    /// ```
    pub fn key_binding(
        &mut self,
        aud: &str,
        key: &KeyForEncoding,
        algorithm: Algorithm,
    ) -> Result<&mut Self, Error> {
        self.aud = Some(aud.to_string());
        self.key = Some(key.clone());
        self.algorithm = Some(algorithm);

        Ok(self)
    }

    /// Build the final presentation, ready for sharing or transmission.
    ///
    /// ```rust
    /// use sdjwt::{Holder, Error, KeyForEncoding, Algorithm};
    ///
    /// fn main() -> Result<(), Error> {
    ///     let sd_jwt = "eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsiVFhsUEt1RjM1cDQ3ZW9XTlpEcklxS0w0R0JFaDBFWXJEQnBjNmFCWjUyQSIsIkdYWlpyVUlsdnBtaDB4b0h4WURadzFOZ211WXJrd1VVS09rNG1XTHZKYUEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJhZGRyZXNzIjp7Il9zZCI6WyJiUjVKM21ULXQ0a05pZ0V0dDJ5RVd1MU92b0hVMzBmSTZ1RVdJd2ozZWJBIiwiczhicTVKeUtJaFFwcVR1Vl9hcVNtd090UVN5UHV1TUlUU2xINXg1UWI5RSJdLCJjb3VudHJ5IjoiVVMiLCJyZWdpb24iOiJBbnlzdGF0ZSJ9LCJiaXJ0aGRhdGUiOiIxOTQwLTAxLTAxIiwiY25mIjp7ImFsZyI6IlJTMjU2IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiNS1EZDU0WHNNQU5UWm9KMllCcHVpWmFfYXpyMzJIcEJ3MUZjanA1d1UwWFBqbW9NQTdKVllDSk4wU05maDZ0dFhyWHhhYWhFNXdmUzd4S1E0N1ZvWXhYTjlLa3kxMzdDSUx0Q0xPWUJDZkdULWFRRXJKS0FJWUVORWtzbVNpU3k0VnVWRk1yTzlMOV9KTzViZk02QjZ6X3pickJYX2MxU2s0UFRLTnBqRTcxcTJHenU4ak5GdTR0c0JaOFFSdmtJVldxNGdxVklQNTFQQmZEcmNfTm53dk1aallGN2pfc0Z5eGg2ZExTVV96QkRrZjJOVWo4VXQ0M25vcW9YMGJoaE96aGdyTlpadGpFMTlrZGFlZTJYbjBweG0td3QzRjBxUjZxd2F2TFRJT21LVHE0OFdXSGxvUk5QWXpGbEo4OHNOaVNLeW9Ta0hXMG9SVDlscUhGX3ZRIiwidXNlIjoic2lnIn0sImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsIm5hdGlvbmFsaXRpZXMiOlt7Ii4uLiI6InhnU2FMYS1CNk03OWpwVWZtaE9Hb0pkSHdNS0RNR0s3eUVKdC0tX0xScDAifSx7Ii4uLiI6Im5vNWxNSkVJSmRWdHozS3lDMVRXVkk2T2tsQnZIMjFCOExOOVEzWkxWRmMifV0sInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwic3ViIjoidXNlcl80MiIsInVwZGF0ZWRfYXQiOjE1NzAwMDAwMDB9.K2h-DNDgnq6q61tSxm1Gv-Hfo46SD8rEcP7yLFxcAlQNKBY-l1-bpXCJcqVZ7jugs2lqng0Cf9e34tM1OPkU3R6Pi5kUMGSyJ2y2ifsaZhGLCgxzNKk5W2ZxdkehzZQ6nHy6iu4flbT92Szv0eBR0hmS3hYTCtHlE4xib9G2dKWTQigB4ylPMkoRzbiKjgkucGkxSLN5ZQRXdxkez19bk5Q9BwuNLQMKG0lanq4ZJWq1C4LPt_K0WhEntyTL6SxVxGfR5HaUSxeYPCCOWSz9AVyZ46DWZGRx48PbuXGgLDH1UJYIsMej2F89CU-3QkWUrFq9b-DCYCQMxbBBekeLog~WyJoV2xxekkxY3piQzhCMnF2Mm5vN3pBIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJ4NXdpQVg1Qks3MFNfYzhXX2Vybm5nIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyI4Q1BKSmNKV2tiOGVwT09yZkl5YUNRIiwic3RyZWV0X2FkZHJlc3MiLCIxMjMgTWFpbiBTdCJd~WyJDTGo2S0tjblA1M2taOG5kOWFueWxnIiwibG9jYWxpdHkiLCJBbnl0b3duIl0~WyI4UEVqT3FlY245cjhGY0llWThhRjh3IiwiVVMiXQ~WyJMR2hVZmV2Y0FkTGVUUEVzRnlCNi1BIiwiREUiXQ~";
    ///     let holder_private_key: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDUhGTgOOW+FQwC\nQHKFGMvdV5l5P6GffWTZtmQ2QW2x2ncfXR2HCdtETl+qtoD9FQ0+ZOFzaeXEMzGU\nVdoSh8AWsq7UgWOmeQkqWR8qBaRY8rMHYnTyUL9bOWfy8mTI7vidRYwMNfg/9weD\nKSCAELhmlKyN1xsIzd3oBbVE5ma02+Q8q2phK7p3lznYguxWzn4Bykx2ZVcGdTKa\ny5MQATYRJlnoMRfTsTlHjyfp7hFlUNUmBQ5jYFNtAL+HZ6Uoa+NaQwiZLE+fD+Or\n7xrDnWl9GkZt8ZQW/bK5YZWr0Tmbm/iYoaSQKuKVun57NDvJKCgmL+njigpAIBCv\n1wwYiSGpAgMBAAECggEBAIrGWclB3mSeAdWGmEHpy1ai2Ymfz78Cd1TkEdSMLUGy\n048bkyiXeyPDuh0USG77zEYuQjrHsE7Kz1l6JolrNDiePiRuyc/vwdhxkjQysvuS\noO31kUCbEhpUBllTiBTeWGL7A1UF+TJr8e/ob1yxjnkOJRAKo5DAPmRBNfnkKrV2\noZdR4v6suy5syacBgr1whoLtLrQhfAClReQ9HOfmw0QOm7PwO807ywhfIwMYPhn8\nGLaA/3w4qGK6y3GmhFj53SnFk4wu9ifXmMroo8/T5wbXdXeGQRZGwOQk2h2TkaRr\nOHC94WYBs7wx4qIjDHDqsWqIRXTNmpTNDsXzTmUlkgECgYEA6WDy+3ELcnbG9Uvs\n0Q9Wdm8yc/P9lWZ+AiRdKHfGLOSxWz8o5Z7sdFTL9x+IGT2btrV1nDHPk2pb5muU\n7gLU9p57wTWq36NqH2OXkCT4iqP9v2mp9fi1fSLqAFsnLxwQIZtqlSRwbvnySx0f\n/oqfDRWNL5TMzYCLpbLtGhaTi5ECgYEA6R3JjTPwLQq+Xpt/iFKr21WCFf7BVwoH\nRv5GBRy4D9UibCk8XAvnJslnHxIpSDoeVfW021LZAeLlp5N/H/PCY146xNRzwsd5\npANsGlNGMkRKqGCwdtOCekpFiZN7yzvsDAlbOcwKsaQffr0oIaf3FhrLc8+SAQjx\ni9KGns8jOJkCgYEApAGlwF4pFT+zgh7hRenpcUGjyyjkRGHKm+bCMPY7JsFwghdY\nvkV5FiehTwGxu0s4aqYLCMFYhthvzPY9qyYCU238ukLk2lUU9woeMQZKQ+QLJsEy\n19D4egBXQfjNCKZID9YQiM8a1GKCi5bkLRVtwNwsZAvGAYUcnk2nonXLKoECgYEA\ngw0e4MXBEOFIUlFiqdWoDZ8NiaX1NSRLIQsTfA5AH453Uo0ABNMgOLriwSHpmVQq\n97Iw4Ve67YeMCeAuiFz1+/zeVwcEqQyRArZ10HreLKYdvnjU24hegrc8TnJeFsvy\nEHY2FdDydhlJJ2vZosoVaxTXKZ0YfIJ1oGBTE/Zo24kCgYBPyXEMr/ngR4UTLnIK\nbSJXlxgCZtkJt3dB2Usj+HQQKMGwYbp06/ILtwKeseIfSzTBMk/lsc3k4CAAoyp3\nj/XUIVc4hK4xoHK6lzI9oViagKZw8gZHs3tBoMhm1HKQbX0djl52yeeAZby83ugr\n0HEpFk7OJvra7z9Z0jjqIQwVEg==\n-----END PRIVATE KEY-----\n";
    ///     let presentation = Holder::presentation(sd_jwt)?
    ///        .redact("/family_name")?
    ///        .key_binding(
    ///             "https://someone.example.com",
    ///             &KeyForEncoding::from_rsa_pem(holder_private_key.as_bytes())?,
    ///             Algorithm::RS256,
    ///        )?
    ///       .build()?;
    ///     println!("{:?}", presentation);
    ///     Ok(())
    /// }
    /// ```
    pub fn build(&self) -> Result<String, Error> {
        // issuer jwt contains cnf claim then Key Binding JWT is required
        let issuer_claims_part = get_jwt_part(self.sd_jwt.as_str(), JWTPart::Claims)?;
        let issuer_jwt_claims = decode_claims_no_verification(issuer_claims_part.as_str())?;
        if issuer_jwt_claims.get("cnf").is_some()
            && (self.key.is_none() || self.algorithm.is_none() || self.aud.is_none())
        {
            return Err(Error::KeyBindingJWTRequired);
        }

        let presentation_disclosures = self
            .disclosure_paths
            .iter()
            .filter(|disclosure_path| !self.redacted.contains(&disclosure_path.path))
            .map(|disclosure_path| disclosure_path.disclosure.disclosure())
            .collect::<Vec<_>>();

        let mut presentation = presentation_disclosures.iter().fold(
            self.sd_jwt.clone(),
            |mut presentation, disclosure| {
                presentation.push('~');
                presentation.push_str(disclosure);
                presentation
            },
        );
        presentation.push('~');

        if issuer_jwt_claims.get("cnf").is_some() {
            // build kb-jwt
            let sd_alg =
                HashAlgorithm::try_from(issuer_jwt_claims["_sd_alg"].as_str().unwrap_or(""))?;
            let nonce = generate_nonce(32);
            let iat = Utc::now().timestamp();
            let sd_hash = base64_hash(sd_alg, &presentation);
            let mut header = Header::new(self.algorithm.clone().ok_or(
                Error::KeyBindingJWTParameterMissing("algorithm".to_string()),
            )?);
            header.typ = Some("kb+jwt".to_string());
            let claims = serde_json::json!({
                "aud": self.aud.clone().ok_or(Error::KeyBindingJWTParameterMissing("aud".to_string()))?,
                "nonce": nonce,
                "iat": iat,
                "sd_hash": sd_hash,
            });
            let kb_jwt = encode(
                &header,
                &claims,
                self.key
                    .as_ref()
                    .ok_or(Error::KeyBindingJWTParameterMissing(
                        "encoding key".to_string(),
                    ))?,
            )?;
            presentation.push_str(&kb_jwt);
        }

        Ok(presentation)
    }

    pub fn verify_raw(
        issuer_token: &str,
        key: &KeyForDecoding,
        validation: &Validation,
    ) -> Result<(Value, Value, Vec<String>), Error> {
        let (issuer_sd_jwt, disclosures, kb_jwt) = sd_jwt_parts(issuer_token);
        if kb_jwt.is_some() {
            return Err(Error::SDJWTRejected(
                ("Issuer SD JWT cannot contain key binding JWT").to_string(),
            ));
        }

        let (header, claims) = decode(&issuer_sd_jwt, key, validation)?;

        match HashAlgorithm::try_from(claims["_sd_alg"].as_str().ok_or(Error::SDJWTRejected(
            ("Issuer SD JWT must contain _sd_alg claim").to_string(),
        ))?) {
            Ok(_) => {}
            Err(e) => {
                return Err(Error::InvalidHashAlgorithm(e.to_string()));
            }
        }

        Ok((header, claims, disclosures))
    }

    /// Verify SD-JWT from Issuer for authenticity and integrity.
    ///
    /// ```
    /// use sdjwt::{Holder, Error, KeyForDecoding, Validation};
    ///
    /// const ISSUER_PUBKEY: &str = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA2a7Pz5WA1AmtGfIxSKwB8vU9OL1ti7udYhvC6048l74loAlmJGps\n0hb4u64jv8sAmdGjYeya2Oza1dydtSmlLArMkbeAiSV/n+KKmK0mpA7D7R8ARLKK\n/BZG7Z/QaxEORJl1KspliBQ2mUJJbcFH+EUko9bAdWEWx9GLkRH2pDm9nMO2lTtE\nqzO+JBjnuEoTn/NZ9Ur4dQDf3nWLBwEFyyJfJ90Ga2f6LFeHL2cOcAbHiofW5NAa\nGqh/JWxf6dSClyOUG0Bpe+RV8t0hnFhIC7RFV0aVbp50sqTM4mwYtOPk/2qWVVMF\nBOaswXYbi0ADUc9CqIaGDCAWnmHrHL/J4wIDAQAB\n-----END RSA PUBLIC KEY-----\n";
    /// const ISSUER_SD_JWT: &str = "eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsiVFhsUEt1RjM1cDQ3ZW9XTlpEcklxS0w0R0JFaDBFWXJEQnBjNmFCWjUyQSIsIkdYWlpyVUlsdnBtaDB4b0h4WURadzFOZ211WXJrd1VVS09rNG1XTHZKYUEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJhZGRyZXNzIjp7Il9zZCI6WyJiUjVKM21ULXQ0a05pZ0V0dDJ5RVd1MU92b0hVMzBmSTZ1RVdJd2ozZWJBIiwiczhicTVKeUtJaFFwcVR1Vl9hcVNtd090UVN5UHV1TUlUU2xINXg1UWI5RSJdLCJjb3VudHJ5IjoiVVMiLCJyZWdpb24iOiJBbnlzdGF0ZSJ9LCJiaXJ0aGRhdGUiOiIxOTQwLTAxLTAxIiwiY25mIjp7ImFsZyI6IlJTMjU2IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiNS1EZDU0WHNNQU5UWm9KMllCcHVpWmFfYXpyMzJIcEJ3MUZjanA1d1UwWFBqbW9NQTdKVllDSk4wU05maDZ0dFhyWHhhYWhFNXdmUzd4S1E0N1ZvWXhYTjlLa3kxMzdDSUx0Q0xPWUJDZkdULWFRRXJKS0FJWUVORWtzbVNpU3k0VnVWRk1yTzlMOV9KTzViZk02QjZ6X3pickJYX2MxU2s0UFRLTnBqRTcxcTJHenU4ak5GdTR0c0JaOFFSdmtJVldxNGdxVklQNTFQQmZEcmNfTm53dk1aallGN2pfc0Z5eGg2ZExTVV96QkRrZjJOVWo4VXQ0M25vcW9YMGJoaE96aGdyTlpadGpFMTlrZGFlZTJYbjBweG0td3QzRjBxUjZxd2F2TFRJT21LVHE0OFdXSGxvUk5QWXpGbEo4OHNOaVNLeW9Ta0hXMG9SVDlscUhGX3ZRIiwidXNlIjoic2lnIn0sImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsIm5hdGlvbmFsaXRpZXMiOlt7Ii4uLiI6InhnU2FMYS1CNk03OWpwVWZtaE9Hb0pkSHdNS0RNR0s3eUVKdC0tX0xScDAifSx7Ii4uLiI6Im5vNWxNSkVJSmRWdHozS3lDMVRXVkk2T2tsQnZIMjFCOExOOVEzWkxWRmMifV0sInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwic3ViIjoidXNlcl80MiIsInVwZGF0ZWRfYXQiOjE1NzAwMDAwMDB9.K2h-DNDgnq6q61tSxm1Gv-Hfo46SD8rEcP7yLFxcAlQNKBY-l1-bpXCJcqVZ7jugs2lqng0Cf9e34tM1OPkU3R6Pi5kUMGSyJ2y2ifsaZhGLCgxzNKk5W2ZxdkehzZQ6nHy6iu4flbT92Szv0eBR0hmS3hYTCtHlE4xib9G2dKWTQigB4ylPMkoRzbiKjgkucGkxSLN5ZQRXdxkez19bk5Q9BwuNLQMKG0lanq4ZJWq1C4LPt_K0WhEntyTL6SxVxGfR5HaUSxeYPCCOWSz9AVyZ46DWZGRx48PbuXGgLDH1UJYIsMej2F89CU-3QkWUrFq9b-DCYCQMxbBBekeLog~WyJoV2xxekkxY3piQzhCMnF2Mm5vN3pBIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJ4NXdpQVg1Qks3MFNfYzhXX2Vybm5nIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyI4Q1BKSmNKV2tiOGVwT09yZkl5YUNRIiwic3RyZWV0X2FkZHJlc3MiLCIxMjMgTWFpbiBTdCJd~WyJDTGo2S0tjblA1M2taOG5kOWFueWxnIiwibG9jYWxpdHkiLCJBbnl0b3duIl0~WyI4UEVqT3FlY245cjhGY0llWThhRjh3IiwiVVMiXQ~WyJMR2hVZmV2Y0FkTGVUUEVzRnlCNi1BIiwiREUiXQ~";
    ///
    /// fn main() -> Result<(), Error> {
    ///     let mut validation = Validation::default().no_exp();
    ///     let decoding_key = KeyForDecoding::from_rsa_pem(ISSUER_PUBKEY.as_bytes())?;
    ///     let (header, decoded_claims, disclosure_paths) =
    ///         Holder::verify(ISSUER_SD_JWT, &decoding_key, &validation)?;
    ///     println!("header: {:?}", header);
    ///     println!("claims: {:?}", decoded_claims);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn verify(
        issuer_token: &str,
        key: &KeyForDecoding,
        validation: &Validation,
    ) -> Result<(Value, Value, Vec<DisclosurePath>), Error> {
        let (header, claims, disclosures) = Holder::verify_raw(issuer_token, key, validation)?;
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
        Ok((header, updated_claims, disclosure_paths))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::common_test_utils::{
        compare_json_values, convert_to_pem, disclosures2vec, keys, publickey_to_jwk,
        separate_jwt_and_disclosures,
    };
    use crate::{Disclosure, Issuer, Jwk, KeyForEncoding};

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

    fn verify_path_to_disclosure(
        expected_path: &str,
        expected_key: &Option<&str>,
        expected_value: &Value,
        disclosure_path: &DisclosurePath,
    ) -> bool {
        if disclosure_path.path != expected_path {
            return false;
        }

        match (expected_key, &disclosure_path.disclosure.key()) {
            (Some(exp_key), Some(disc_key)) if exp_key == disc_key => {}
            (None, None) => {}
            _ => return false,
        }

        if !compare_json_values(expected_value, disclosure_path.disclosure.value()) {
            return false;
        }

        true
    }

    #[test]
    fn test_verify_sd_jwt_with_sd_objects() -> Result<(), Error> {
        let (priv_key, pub_key) = keys();
        let (issuer_private_key, issuer_public_key) = convert_to_pem(priv_key, pub_key);
        let claims: Value = serde_json::from_str(TEST_CLAIMS).unwrap();
        let mut issuer = Issuer::new(claims)?;
        let encoded = issuer
            .expires_in_seconds(60)
            .disclosable("/given_name")
            .disclosable("/family_name")
            .disclosable("/address/street_address")
            .disclosable("/address/locality")
            .encode(&KeyForEncoding::from_rsa_pem(
                issuer_private_key.as_bytes(),
            )?)?;
        println!("encoded: {:?}", encoded);
        let test_claims = issuer.claims_copy();
        let dot_segments = encoded.split('.').count();
        let disclosure_segments = encoded.split('~').count() - 2;

        assert_eq!(dot_segments, 3);
        assert_eq!(disclosure_segments, 4);

        let validation = Validation::default();
        let decoding_key = KeyForDecoding::from_rsa_pem(issuer_public_key.as_bytes())?;
        let (header, decoded_claims, disclosure_paths) =
            Holder::verify(&encoded, &decoding_key, &validation)?;
        println!("header: {:?}", header);
        println!("claims: {:?}", decoded_claims);
        println!("disclosure_paths: {:?}", disclosure_paths);
        assert!(compare_json_values(&test_claims, &decoded_claims));
        assert!(verify_path_to_disclosure(
            "/given_name",
            &Some("given_name"),
            &serde_json::json!("John"),
            &disclosure_paths[0]
        ));
        assert!(verify_path_to_disclosure(
            "/given_name",
            &Some("given_name"),
            &serde_json::json!("John"),
            &disclosure_paths[0]
        ));
        assert!(verify_path_to_disclosure(
            "/family_name",
            &Some("family_name"),
            &serde_json::json!("Doe"),
            &disclosure_paths[1]
        ));
        assert!(verify_path_to_disclosure(
            "/address/street_address",
            &Some("street_address"),
            &serde_json::json!("123 Main St"),
            &disclosure_paths[2]
        ));
        assert!(verify_path_to_disclosure(
            "/address/locality",
            &Some("locality"),
            &serde_json::json!("Anytown"),
            &disclosure_paths[3]
        ));
        Ok(())
    }

    #[test]
    fn test_verify_sd_jwt_with_sd_objects_array() -> Result<(), Error> {
        let (priv_key, pub_key) = keys();
        let (issuer_private_key, issuer_public_key) = convert_to_pem(priv_key, pub_key);
        let claims: Value = serde_json::from_str(TEST_CLAIMS).unwrap();
        let mut issuer = Issuer::new(claims)?;
        let encoded = issuer
            .expires_in_seconds(60)
            .disclosable("/given_name")
            .disclosable("/family_name")
            .disclosable("/address/street_address")
            .disclosable("/address/locality")
            .disclosable("/nationalities/0")
            .disclosable("/nationalities/1")
            .encode(&KeyForEncoding::from_rsa_pem(
                issuer_private_key.as_bytes(),
            )?)?;
        println!("encoded: {:?}", encoded);
        let test_claims = issuer.claims_copy();
        let dot_segments = encoded.split('.').count();
        let disclosure_segments = encoded.split('~').count() - 2;

        assert_eq!(dot_segments, 3);
        assert_eq!(disclosure_segments, 6);

        let validation = Validation::default();
        let decoding_key = KeyForDecoding::from_rsa_pem(issuer_public_key.as_bytes())?;
        let (header, decoded_claims, disclosure_paths) =
            Holder::verify(&encoded, &decoding_key, &validation)?;
        println!("header: {:?}", header);
        println!("claims: {:?}", decoded_claims);
        println!("disclosure_paths: {:?}", disclosure_paths);
        assert!(compare_json_values(&test_claims, &decoded_claims));
        assert!(verify_path_to_disclosure(
            "/given_name",
            &Some("given_name"),
            &serde_json::json!("John"),
            &disclosure_paths[0]
        ));
        assert!(verify_path_to_disclosure(
            "/given_name",
            &Some("given_name"),
            &serde_json::json!("John"),
            &disclosure_paths[0]
        ));
        assert!(verify_path_to_disclosure(
            "/family_name",
            &Some("family_name"),
            &serde_json::json!("Doe"),
            &disclosure_paths[1]
        ));
        assert!(verify_path_to_disclosure(
            "/address/street_address",
            &Some("street_address"),
            &serde_json::json!("123 Main St"),
            &disclosure_paths[2]
        ));
        assert!(verify_path_to_disclosure(
            "/address/locality",
            &Some("locality"),
            &serde_json::json!("Anytown"),
            &disclosure_paths[3]
        ));
        assert!(verify_path_to_disclosure(
            "/nationalities/0",
            &None,
            &serde_json::json!("US"),
            &disclosure_paths[4]
        ));
        assert!(verify_path_to_disclosure(
            "/nationalities/1",
            &None,
            &serde_json::json!("DE"),
            &disclosure_paths[5]
        ));
        Ok(())
    }

    #[test]
    fn test_presentation() -> Result<(), Error> {
        // create issuer sd-jwt
        let (priv_key, pub_key) = keys();
        let (issuer_private_key, issuer_public_key) = convert_to_pem(priv_key, pub_key);
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
            .build()?;
        println!("presentation: {:?}", presentation);

        let dot_segments = presentation.split('.').count();
        let disclosure_segments = presentation.split('~').count() - 2;

        assert_eq!(dot_segments, 3);
        assert_eq!(disclosure_segments, 3);

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

        Ok(())
    }

    #[test]
    fn test_presentation_with_kb_holder_no_kb() -> Result<(), Error> {
        // create issuer sd-jwt
        let (priv_key, pub_key) = keys();
        let (issuer_private_key, issuer_public_key) = convert_to_pem(priv_key, pub_key);
        let (_, holder_public_key) = keys();
        let holder_jwk = publickey_to_jwk(&holder_public_key);
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
        let result = Holder::presentation(&issuer_sd_jwt)?
            .redact("/family_name")?
            .redact("/address/street_address")?
            .redact("/nationalities/0")?
            .build();
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_presentation_with_kb() -> Result<(), Error> {
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

        Ok(())
    }
}
