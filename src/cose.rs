use crate::error::{Error, Result};
use ciborium::value::Value;

/// An ES256 (ECDSA over NIST P-256) public key: the only credential algorithm
/// this relying party supports. Apple and Android platform authenticators both
/// produce ES256 keys, so this one type covers the common passkey case.
///
/// The `x` and `y` fields are the affine coordinates of the public point. Store
/// them (or the SEC1 bytes) alongside the credential id after registration; you
/// hand this back at assertion time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoseEs256Key {
    /// The x coordinate of the public point (32 bytes, big-endian).
    pub x: [u8; 32],
    /// The y coordinate of the public point (32 bytes, big-endian).
    pub y: [u8; 32],
}

impl CoseEs256Key {
    /// The SEC1 uncompressed encoding: `0x04 || x || y` (65 bytes). Both crypto
    /// backends verify against this form.
    pub fn to_sec1_uncompressed(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&self.x);
        out[33..65].copy_from_slice(&self.y);
        out
    }

    /// Parse a COSE_Key (RFC 8152) from the raw credentialPublicKey CBOR bytes
    /// found in the attested credential data. Rejects anything that is not an
    /// ES256 / P-256 key.
    pub fn from_cose_bytes(bytes: &[u8]) -> Result<Self> {
        let value: Value =
            ciborium::de::from_reader(bytes).map_err(|e| Error::CoseKey(e.to_string()))?;
        let map = value
            .as_map()
            .ok_or_else(|| Error::CoseKey("credentialPublicKey is not a CBOR map".into()))?;

        let get = |label: i128| -> Option<&Value> {
            map.iter()
                .find(|(k, _)| int_of(k) == Some(label))
                .map(|(_, v)| v)
        };

        // kty (label 1) must be EC2 (2).
        match get(1).and_then(int_of) {
            Some(2) => {}
            Some(_) => return Err(Error::UnsupportedKey),
            None => return Err(Error::CoseKey("missing kty".into())),
        }
        // alg (label 3) must be ES256 (-7).
        match get(3).and_then(int_of) {
            Some(-7) => {}
            Some(_) => return Err(Error::UnsupportedKey),
            None => return Err(Error::CoseKey("missing alg".into())),
        }
        // crv (label -1) must be P-256 (1).
        match get(-1).and_then(int_of) {
            Some(1) => {}
            Some(_) => return Err(Error::UnsupportedKey),
            None => return Err(Error::CoseKey("missing crv".into())),
        }

        let x = get(-2)
            .and_then(bytes_of)
            .ok_or_else(|| Error::CoseKey("missing x coordinate".into()))?;
        let y = get(-3)
            .and_then(bytes_of)
            .ok_or_else(|| Error::CoseKey("missing y coordinate".into()))?;

        Ok(Self {
            x: to_32(x)?,
            y: to_32(y)?,
        })
    }
}

fn int_of(v: &Value) -> Option<i128> {
    match v {
        Value::Integer(i) => Some(i128::from(*i)),
        _ => None,
    }
}

fn bytes_of(v: &Value) -> Option<&[u8]> {
    match v {
        Value::Bytes(b) => Some(b.as_slice()),
        _ => None,
    }
}

fn to_32(b: &[u8]) -> Result<[u8; 32]> {
    b.try_into()
        .map_err(|_| Error::CoseKey("EC coordinate is not 32 bytes".into()))
}
