//! Known-answer tests against real, publicly published WebAuthn vectors.
//!
//! Unlike roundtrip.rs (which signs its own data), these are genuine responses
//! captured from real authenticators, so they exercise passkeep against outputs
//! it did not produce. They run under whichever crypto backend is compiled in,
//! so both `ring` and `rustcrypto` are checked against the same real signatures.
//!
//! The vectors live as JSON fixtures in tests/vectors/ (with tests/vectors/
//! PROVENANCE.md documenting their source and license). This file loads and
//! decodes them; adding a captured Apple/Android vector is a new JSON file plus
//! a reference here.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use passkeep::{
    AssertionVerification, CoseEs256Key, Error, RegistrationVerification, RelyingParty,
};
use serde::Deserialize;

fn b64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("valid base64url fixture")
}

#[derive(Deserialize)]
struct RegVector {
    rp_id: String,
    origin: String,
    require_user_verification: bool,
    challenge_b64url: String,
    client_data_json_b64url: String,
    attestation_object_b64url: String,
    expected_credential_id_b64url: String,
    expected_fmt: String,
}

/// A real registration whose attestation format is out of this crate's scope:
/// passkeep must reject it cleanly (no panic) after parsing the real authData
/// and COSE key. Used for the Apple and Android device captures.
#[derive(Deserialize)]
struct RegRejectVector {
    rp_id: String,
    origin: String,
    challenge_b64url: String,
    client_data_json_b64url: String,
    attestation_object_b64url: String,
    expected_unsupported_fmt: String,
}

#[derive(Deserialize)]
struct AuthVector {
    rp_id: String,
    origin: String,
    previous_sign_count: u32,
    expected_new_sign_count: u32,
    expected_user_verified: bool,
    challenge_b64url: String,
    client_data_json_b64url: String,
    authenticator_data_b64url: String,
    signature_b64url: String,
    credential_cose_public_key_b64url: String,
}

fn registration_vector() -> RegVector {
    serde_json::from_str(include_str!("vectors/registration_none_es256.json"))
        .expect("registration fixture parses")
}

fn assertion_vector() -> AuthVector {
    serde_json::from_str(include_str!("vectors/assertion_es256.json"))
        .expect("assertion fixture parses")
}

/// Drive a positive registration vector through passkeep and assert its result.
fn assert_registers(v: &RegVector, expect_uv: bool) {
    let credential = RelyingParty::new(&v.rp_id, &v.origin)
        .verify_registration(&RegistrationVerification {
            client_data_json: &b64(&v.client_data_json_b64url),
            attestation_object: &b64(&v.attestation_object_b64url),
            expected_challenge: &b64(&v.challenge_b64url),
            require_user_verification: v.require_user_verification,
        })
        .expect("real registration vector must verify");
    assert_eq!(
        credential.credential_id,
        b64(&v.expected_credential_id_b64url)
    );
    assert_eq!(credential.attestation_format, v.expected_fmt);
    assert_eq!(credential.user_verified, expect_uv);
}

#[test]
fn kat_registration_packed_self_es256() {
    // Real packed self attestation (SimpleWebAuthn capture): passkeep verifies
    // the attestation signature with the credential's own key.
    let v: RegVector = serde_json::from_str(include_str!("vectors/registration_packed_es256.json"))
        .expect("packed fixture parses");
    assert_registers(&v, true);
}

#[test]
fn kat_registration_apple_is_rejected_cleanly() {
    // Real Apple platform authenticator output: fmt "apple" is out of scope, so
    // passkeep parses the real authData and COSE key without panicking, then
    // returns a clean UnsupportedAttestation rather than accepting or crashing.
    assert_unsupported(include_str!("vectors/registration_apple_unsupported.json"));
}

#[test]
fn kat_registration_android_key_is_rejected_cleanly() {
    // Real Android Keystore output: fmt "android-key" is out of scope.
    assert_unsupported(include_str!(
        "vectors/registration_android_key_unsupported.json"
    ));
}

fn assert_unsupported(json: &str) {
    let v: RegRejectVector = serde_json::from_str(json).expect("reject fixture parses");
    let err = RelyingParty::new(&v.rp_id, &v.origin)
        .verify_registration(&RegistrationVerification {
            client_data_json: &b64(&v.client_data_json_b64url),
            attestation_object: &b64(&v.attestation_object_b64url),
            expected_challenge: &b64(&v.challenge_b64url),
            require_user_verification: false,
        })
        .unwrap_err();
    assert!(
        matches!(err, Error::UnsupportedAttestation(fmt) if fmt == v.expected_unsupported_fmt),
        "expected UnsupportedAttestation({}), got a different error",
        v.expected_unsupported_fmt
    );
}

#[test]
fn kat_registration_none_es256() {
    let v = registration_vector();
    let credential = RelyingParty::new(&v.rp_id, &v.origin)
        .verify_registration(&RegistrationVerification {
            client_data_json: &b64(&v.client_data_json_b64url),
            attestation_object: &b64(&v.attestation_object_b64url),
            expected_challenge: &b64(&v.challenge_b64url),
            require_user_verification: v.require_user_verification,
        })
        .expect("real none-attestation registration must verify");

    assert_eq!(
        credential.credential_id,
        b64(&v.expected_credential_id_b64url)
    );
    assert_eq!(credential.attestation_format, v.expected_fmt);
    assert_eq!(credential.aaguid, [0u8; 16]);
    assert!(credential.user_verified);
}

#[test]
fn kat_registration_rejects_wrong_rp_id() {
    let v = registration_vector();
    let err = RelyingParty::new("evil.example", &v.origin)
        .verify_registration(&RegistrationVerification {
            client_data_json: &b64(&v.client_data_json_b64url),
            attestation_object: &b64(&v.attestation_object_b64url),
            expected_challenge: &b64(&v.challenge_b64url),
            require_user_verification: v.require_user_verification,
        })
        .unwrap_err();
    assert!(matches!(err, Error::RpIdHashMismatch));
}

fn assertion_key(v: &AuthVector) -> CoseEs256Key {
    CoseEs256Key::from_cose_bytes(&b64(&v.credential_cose_public_key_b64url))
        .expect("valid ES256 COSE key")
}

#[test]
fn kat_assertion_es256() {
    let v = assertion_vector();
    let key = assertion_key(&v);
    let outcome = RelyingParty::new(&v.rp_id, &v.origin)
        .verify_assertion(&AssertionVerification {
            client_data_json: &b64(&v.client_data_json_b64url),
            authenticator_data: &b64(&v.authenticator_data_b64url),
            signature: &b64(&v.signature_b64url),
            expected_challenge: &b64(&v.challenge_b64url),
            credential_public_key: &key,
            previous_sign_count: v.previous_sign_count,
            require_user_verification: v.expected_user_verified,
        })
        .expect("real EC2 assertion must verify");
    assert_eq!(outcome.new_sign_count, v.expected_new_sign_count);
    assert_eq!(outcome.user_verified, v.expected_user_verified);
}

#[test]
fn kat_assertion_rejects_tampered_signature() {
    let v = assertion_vector();
    let key = assertion_key(&v);
    let mut signature = b64(&v.signature_b64url);
    *signature.last_mut().unwrap() ^= 0x01;
    let err = RelyingParty::new(&v.rp_id, &v.origin)
        .verify_assertion(&AssertionVerification {
            client_data_json: &b64(&v.client_data_json_b64url),
            authenticator_data: &b64(&v.authenticator_data_b64url),
            signature: &signature,
            expected_challenge: &b64(&v.challenge_b64url),
            credential_public_key: &key,
            previous_sign_count: v.previous_sign_count,
            require_user_verification: false,
        })
        .unwrap_err();
    assert!(matches!(err, Error::BadSignature));
}

#[test]
fn kat_assertion_requires_uv_when_asked() {
    // This ceremony did not verify the user; demanding UV must reject it.
    let v = assertion_vector();
    assert!(!v.expected_user_verified, "fixture is a non-UV ceremony");
    let key = assertion_key(&v);
    let err = RelyingParty::new(&v.rp_id, &v.origin)
        .verify_assertion(&AssertionVerification {
            client_data_json: &b64(&v.client_data_json_b64url),
            authenticator_data: &b64(&v.authenticator_data_b64url),
            signature: &b64(&v.signature_b64url),
            expected_challenge: &b64(&v.challenge_b64url),
            credential_public_key: &key,
            previous_sign_count: v.previous_sign_count,
            require_user_verification: true,
        })
        .unwrap_err();
    assert!(matches!(err, Error::UserNotVerified));
}
