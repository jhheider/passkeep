//! Rejection-path tests for the parsers: malformed COSE keys, malformed
//! clientDataJSON, and truncated authenticatorData. These need no crypto, so
//! they run identically under either backend.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ciborium::value::{Integer, Value};
use passkeep::{CoseEs256Key, Error, RegistrationVerification, RelyingParty};

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

fn to_cbor(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).unwrap();
    out
}

fn int(v: i64) -> Value {
    Value::Integer(Integer::from(v))
}

/// A COSE_Key map with the given entries, CBOR-encoded.
fn cose(entries: Vec<(Value, Value)>) -> Vec<u8> {
    to_cbor(&Value::Map(entries))
}

fn good_xy() -> (Value, Value) {
    (Value::Bytes(vec![1u8; 32]), Value::Bytes(vec![2u8; 32]))
}

#[test]
fn cose_key_rejects_non_map() {
    let bytes = to_cbor(&Value::Text("not a map".into()));
    assert!(matches!(
        CoseEs256Key::from_cose_bytes(&bytes),
        Err(Error::CoseKey(_))
    ));
}

#[test]
fn cose_key_rejects_wrong_kty_alg_crv() {
    let (x, y) = good_xy();
    // Wrong kty (OKP = 1, not EC2 = 2).
    let bytes = cose(vec![
        (int(1), int(1)),
        (int(3), int(-7)),
        (int(-1), int(1)),
        (int(-2), x.clone()),
        (int(-3), y.clone()),
    ]);
    assert!(matches!(
        CoseEs256Key::from_cose_bytes(&bytes),
        Err(Error::UnsupportedKey)
    ));

    // Wrong alg (RS256 = -257, not ES256 = -7).
    let bytes = cose(vec![
        (int(1), int(2)),
        (int(3), int(-257)),
        (int(-1), int(1)),
        (int(-2), x.clone()),
        (int(-3), y.clone()),
    ]);
    assert!(matches!(
        CoseEs256Key::from_cose_bytes(&bytes),
        Err(Error::UnsupportedKey)
    ));

    // Wrong crv (P-384 = 2, not P-256 = 1).
    let bytes = cose(vec![
        (int(1), int(2)),
        (int(3), int(-7)),
        (int(-1), int(2)),
        (int(-2), x),
        (int(-3), y),
    ]);
    assert!(matches!(
        CoseEs256Key::from_cose_bytes(&bytes),
        Err(Error::UnsupportedKey)
    ));
}

#[test]
fn cose_key_rejects_missing_and_short_coordinates() {
    // Missing y.
    let bytes = cose(vec![
        (int(1), int(2)),
        (int(3), int(-7)),
        (int(-1), int(1)),
        (int(-2), Value::Bytes(vec![1u8; 32])),
    ]);
    assert!(matches!(
        CoseEs256Key::from_cose_bytes(&bytes),
        Err(Error::CoseKey(_))
    ));

    // x is only 31 bytes.
    let bytes = cose(vec![
        (int(1), int(2)),
        (int(3), int(-7)),
        (int(-1), int(1)),
        (int(-2), Value::Bytes(vec![1u8; 31])),
        (int(-3), Value::Bytes(vec![2u8; 32])),
    ]);
    assert!(matches!(
        CoseEs256Key::from_cose_bytes(&bytes),
        Err(Error::CoseKey(_))
    ));
}

#[test]
fn cose_key_accepts_and_roundtrips_sec1() {
    let bytes = cose(vec![
        (int(1), int(2)),
        (int(3), int(-7)),
        (int(-1), int(1)),
        (int(-2), Value::Bytes(vec![7u8; 32])),
        (int(-3), Value::Bytes(vec![9u8; 32])),
    ]);
    let key = CoseEs256Key::from_cose_bytes(&bytes).expect("valid key");
    let sec1 = key.to_sec1_uncompressed();
    assert_eq!(sec1[0], 0x04);
    assert_eq!(&sec1[1..33], &[7u8; 32]);
    assert_eq!(&sec1[33..65], &[9u8; 32]);
}

// clientDataJSON checks routed through the public registration API. Each fails
// before attestation parsing, so the attestation bytes can be empty.

fn cdj(ceremony_type: &str, challenge_b64: &str, origin: &str) -> Vec<u8> {
    format!(r#"{{"type":"{ceremony_type}","challenge":"{challenge_b64}","origin":"{origin}"}}"#)
        .into_bytes()
}

fn reg(client_data_json: &[u8], expected_challenge: &[u8]) -> Result<(), Error> {
    RelyingParty::new(RP_ID, ORIGIN)
        .verify_registration(&RegistrationVerification {
            client_data_json,
            attestation_object: &[],
            expected_challenge,
            require_user_verification: false,
        })
        .map(|_| ())
}

#[test]
fn client_data_rejects_invalid_json() {
    assert!(matches!(
        reg(b"this is not json", b"x"),
        Err(Error::ClientDataJson(_))
    ));
}

#[test]
fn client_data_rejects_type_mismatch() {
    let challenge = b"abc";
    let b64 = URL_SAFE_NO_PAD.encode(challenge);
    // webauthn.get where a registration expects webauthn.create.
    let data = cdj("webauthn.get", &b64, ORIGIN);
    assert!(matches!(
        reg(&data, challenge),
        Err(Error::TypeMismatch { .. })
    ));
}

#[test]
fn client_data_rejects_origin_mismatch() {
    let challenge = b"abc";
    let b64 = URL_SAFE_NO_PAD.encode(challenge);
    let data = cdj("webauthn.create", &b64, "https://evil.example");
    assert!(matches!(
        reg(&data, challenge),
        Err(Error::OriginMismatch { .. })
    ));
}

#[test]
fn client_data_rejects_challenge_mismatch_and_bad_base64() {
    // Valid base64url but the wrong challenge value.
    let b64 = URL_SAFE_NO_PAD.encode(b"the-wrong-challenge");
    let data = cdj("webauthn.create", &b64, ORIGIN);
    assert!(matches!(
        reg(&data, b"the-right-challenge"),
        Err(Error::ChallengeMismatch)
    ));

    // Challenge that is not valid base64url at all.
    let data = cdj("webauthn.create", "not*valid*base64", ORIGIN);
    assert!(matches!(reg(&data, b"x"), Err(Error::Base64(_))));
}

#[test]
fn auth_data_too_short_is_rejected() {
    // A valid clientData so we reach attestation + authData parsing, then a
    // truncated authData inside the attestation object.
    let challenge = b"abc";
    let b64 = URL_SAFE_NO_PAD.encode(challenge);
    let data = cdj("webauthn.create", &b64, ORIGIN);
    let att = to_cbor(&Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (Value::Text("authData".into()), Value::Bytes(vec![0u8; 10])),
    ]));
    let err = RelyingParty::new(RP_ID, ORIGIN)
        .verify_registration(&RegistrationVerification {
            client_data_json: &data,
            attestation_object: &att,
            expected_challenge: challenge,
            require_user_verification: false,
        })
        .unwrap_err();
    assert!(matches!(err, Error::AuthData(_)));
}
