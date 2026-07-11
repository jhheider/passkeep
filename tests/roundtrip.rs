//! End-to-end tests that simulate an authenticator: mint a P-256 key, hand-build
//! the CBOR/byte structures a real device would emit, sign with deterministic
//! ECDSA (RFC 6979), and verify through whichever backend is compiled in.
//!
//! These are self-consistency tests, not spec known-answer tests. Real Apple and
//! Android KAT vectors are the next milestone before publish (see the brief).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ciborium::value::{Integer, Value};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use passkeep::{
    AssertionVerification, CoseEs256Key, Error, RegistrationVerification, RelyingParty,
};
use sha2::{Digest, Sha256};

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// A deterministic simulated authenticator key plus its exported coordinates.
fn test_key() -> (SigningKey, CoseEs256Key) {
    let signing_key = SigningKey::from_slice(&[0x11u8; 32]).expect("valid scalar");
    let point = signing_key.verifying_key().to_encoded_point(false);
    let xb: &[u8] = point.x().unwrap();
    let yb: &[u8] = point.y().unwrap();
    let x: [u8; 32] = xb.try_into().unwrap();
    let y: [u8; 32] = yb.try_into().unwrap();
    (signing_key, CoseEs256Key { x, y })
}

fn cose_key_cbor(key: &CoseEs256Key) -> Vec<u8> {
    let map = Value::Map(vec![
        (int(1), int(2)),  // kty: EC2
        (int(3), int(-7)), // alg: ES256
        (int(-1), int(1)), // crv: P-256
        (int(-2), Value::Bytes(key.x.to_vec())),
        (int(-3), Value::Bytes(key.y.to_vec())),
    ]);
    to_cbor(&map)
}

fn attestation_object_none(auth_data: &[u8]) -> Vec<u8> {
    let map = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (
            Value::Text("authData".into()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    to_cbor(&map)
}

fn int(v: i64) -> Value {
    Value::Integer(Integer::from(v))
}

fn to_cbor(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).unwrap();
    out
}

fn client_data(ceremony_type: &str, challenge: &[u8]) -> Vec<u8> {
    let b64 = URL_SAFE_NO_PAD.encode(challenge);
    format!(
        r#"{{"type":"{ceremony_type}","challenge":"{b64}","origin":"{ORIGIN}","crossOrigin":false}}"#
    )
    .into_bytes()
}

/// Registration authenticatorData: header + attested credential data.
fn registration_auth_data(cred_id: &[u8], key: &CoseEs256Key, sign_count: u32) -> Vec<u8> {
    let mut ad = Vec::new();
    ad.extend_from_slice(&sha256(RP_ID.as_bytes())); // rpIdHash
    ad.push(0x45); // UP | UV | AT
    ad.extend_from_slice(&sign_count.to_be_bytes());
    ad.extend_from_slice(&[0u8; 16]); // aaguid
    ad.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    ad.extend_from_slice(cred_id);
    ad.extend_from_slice(&cose_key_cbor(key));
    ad
}

/// Assertion authenticatorData: header only (no attested credential data).
fn assertion_auth_data(sign_count: u32) -> Vec<u8> {
    let mut ad = Vec::new();
    ad.extend_from_slice(&sha256(RP_ID.as_bytes()));
    ad.push(0x05); // UP | UV
    ad.extend_from_slice(&sign_count.to_be_bytes());
    ad
}

fn sign_der(signing_key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let signature: Signature = signing_key.sign(message);
    signature.to_der().as_bytes().to_vec()
}

#[test]
fn registration_none_roundtrip() {
    let rp = RelyingParty::new(RP_ID, ORIGIN);
    let (_sk, key) = test_key();
    let cred_id = b"credential-id-bytes";

    let auth_data = registration_auth_data(cred_id, &key, 0);
    let attestation_object = attestation_object_none(&auth_data);
    let challenge = b"registration-challenge-000001";
    let cdj = client_data("webauthn.create", challenge);

    let credential = rp
        .verify_registration(&RegistrationVerification {
            client_data_json: &cdj,
            attestation_object: &attestation_object,
            expected_challenge: challenge,
            require_user_verification: true,
        })
        .expect("registration should verify");

    assert_eq!(credential.credential_id, cred_id);
    assert_eq!(credential.public_key, key);
    assert_eq!(credential.sign_count, 0);
    assert_eq!(credential.attestation_format, "none");
    assert!(credential.user_verified);
}

#[test]
fn assertion_roundtrip_and_counter() {
    let rp = RelyingParty::new(RP_ID, ORIGIN);
    let (sk, key) = test_key();
    let challenge = b"assertion-challenge-42";

    let auth_data = assertion_auth_data(10);
    let cdj = client_data("webauthn.get", challenge);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&sha256(&cdj));
    let signature = sign_der(&sk, &signed);

    let outcome = rp
        .verify_assertion(&AssertionVerification {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &signature,
            expected_challenge: challenge,
            credential_public_key: &key,
            previous_sign_count: 9,
            require_user_verification: true,
        })
        .expect("assertion should verify");
    assert_eq!(outcome.new_sign_count, 10);

    // Same signature but the counter did not advance: cloned-authenticator signal.
    let err = rp
        .verify_assertion(&AssertionVerification {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &signature,
            expected_challenge: challenge,
            credential_public_key: &key,
            previous_sign_count: 10,
            require_user_verification: true,
        })
        .unwrap_err();
    assert!(matches!(err, Error::SignCountRegression { .. }));
}

#[test]
fn assertion_rejects_wrong_challenge_and_bad_signature() {
    let rp = RelyingParty::new(RP_ID, ORIGIN);
    let (sk, key) = test_key();
    let challenge = b"assertion-challenge-99";

    let auth_data = assertion_auth_data(1);
    let cdj = client_data("webauthn.get", challenge);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&sha256(&cdj));
    let signature = sign_der(&sk, &signed);

    // Wrong expected challenge: caught before any crypto.
    let err = rp
        .verify_assertion(&AssertionVerification {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &signature,
            expected_challenge: b"a-different-challenge",
            credential_public_key: &key,
            previous_sign_count: 0,
            require_user_verification: true,
        })
        .unwrap_err();
    assert!(matches!(err, Error::ChallengeMismatch));

    // Tampered signature: caught by verification.
    let mut bad = signature.clone();
    *bad.last_mut().unwrap() ^= 0xff;
    let err = rp
        .verify_assertion(&AssertionVerification {
            client_data_json: &cdj,
            authenticator_data: &auth_data,
            signature: &bad,
            expected_challenge: challenge,
            credential_public_key: &key,
            previous_sign_count: 0,
            require_user_verification: true,
        })
        .unwrap_err();
    assert!(matches!(err, Error::BadSignature));
}
