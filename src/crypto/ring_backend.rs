use crate::cose::CoseEs256Key;
use crate::error::{Error, Result};
use ring::{digest, signature};

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Verify an ES256 signature. WebAuthn authenticators emit ASN.1 DER ECDSA
/// signatures, so use the ASN.1 verifier; ring computes the SHA-256 of the
/// message internally.
pub(crate) fn verify_es256(key: &CoseEs256Key, message: &[u8], signature_der: &[u8]) -> Result<()> {
    let point = key.to_sec1_uncompressed();
    let public =
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point.as_ref());
    public
        .verify(message, signature_der)
        .map_err(|_| Error::BadSignature)
}
