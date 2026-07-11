use crate::auth_data::AttestedCredential;
use crate::crypto;
use crate::error::{Error, Result};
use ciborium::value::Value;

/// The decoded attestationObject (WebAuthn 6.5): the format tag, the raw
/// authenticatorData bytes, and the format-specific attestation statement.
pub struct AttestationObject {
    pub fmt: String,
    pub auth_data: Vec<u8>,
    pub att_stmt: Value,
}

impl AttestationObject {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Value =
            ciborium::de::from_reader(bytes).map_err(|e| Error::AttestationCbor(e.to_string()))?;
        let map = value
            .as_map()
            .ok_or_else(|| Error::AttestationCbor("attestationObject is not a map".into()))?;

        let mut fmt = None;
        let mut auth_data = None;
        let mut att_stmt = None;
        for (k, v) in map {
            match k.as_text() {
                Some("fmt") => fmt = v.as_text().map(|s| s.to_string()),
                Some("authData") => auth_data = v.as_bytes().cloned(),
                Some("attStmt") => att_stmt = Some(v.clone()),
                _ => {}
            }
        }

        Ok(Self {
            fmt: fmt.ok_or_else(|| Error::AttestationCbor("missing fmt".into()))?,
            auth_data: auth_data
                .ok_or_else(|| Error::AttestationCbor("missing authData".into()))?,
            att_stmt: att_stmt.unwrap_or(Value::Null),
        })
    }
}

/// Verify the attestation statement for the formats this crate supports.
///
/// - `none`: nothing to verify (a legitimate choice at personal scale).
/// - `packed` self attestation: the sig is over `authData || clientDataHash`
///   with the credential's own key.
/// - `packed` with an x5c cert chain (basic/full attestation) is not yet
///   implemented: parsing an X.509 chain is real work and out of the first cut.
pub fn verify_attestation(
    att: &AttestationObject,
    cred: &AttestedCredential,
    client_data_json: &[u8],
) -> Result<()> {
    match att.fmt.as_str() {
        "none" => Ok(()),
        "packed" => verify_packed(att, cred, client_data_json),
        other => Err(Error::UnsupportedAttestation(other.to_string())),
    }
}

fn verify_packed(
    att: &AttestationObject,
    cred: &AttestedCredential,
    client_data_json: &[u8],
) -> Result<()> {
    let map = att
        .att_stmt
        .as_map()
        .ok_or_else(|| Error::AttestationStatement("attStmt is not a map".into()))?;
    let get = |name: &str| -> Option<&Value> {
        map.iter()
            .find(|(k, _)| k.as_text() == Some(name))
            .map(|(_, v)| v)
    };

    let alg = get("alg")
        .and_then(|v| v.as_integer())
        .map(i128::from)
        .ok_or_else(|| Error::AttestationStatement("missing or non-integer alg".into()))?;
    if alg != -7 {
        return Err(Error::AttestationStatement(
            "packed alg is not ES256 (-7)".into(),
        ));
    }

    let sig = get("sig")
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| Error::AttestationStatement("missing sig".into()))?;

    if get("x5c").is_some() {
        return Err(Error::UnsupportedAttestation(
            "packed with x5c (basic/full attestation cert chain) is not yet implemented; \
             use attestation none or packed self attestation"
                .into(),
        ));
    }

    // Self attestation: verification data is authData || SHA-256(clientDataJSON),
    // signed by the credential's own key.
    let mut signed = att.auth_data.clone();
    signed.extend_from_slice(&crypto::sha256(client_data_json));
    crypto::verify_es256(&cred.public_key, &signed, sig)
}
