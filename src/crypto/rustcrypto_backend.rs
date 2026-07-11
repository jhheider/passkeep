use crate::cose::CoseEs256Key;
use crate::error::{Error, Result};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Verify an ES256 signature with pure-Rust p256. The key comes in as its SEC1
/// uncompressed encoding; `Signature::from_der` accepts the ASN.1 DER form
/// authenticators emit, and the verifier hashes the message with SHA-256.
pub(crate) fn verify_es256(key: &CoseEs256Key, message: &[u8], signature_der: &[u8]) -> Result<()> {
    let sec1 = key.to_sec1_uncompressed();
    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| Error::UnsupportedKey)?;
    let signature = Signature::from_der(signature_der).map_err(|_| Error::BadSignature)?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| Error::BadSignature)
}
