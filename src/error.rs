use thiserror::Error;

/// Everything that can go wrong verifying a ceremony. Each variant is a distinct
/// spec check failing, so a caller can log or branch on the reason.
#[derive(Debug, Error)]
pub enum Error {
    #[error("clientDataJSON is not valid JSON: {0}")]
    ClientDataJson(String),

    #[error("ceremony type mismatch: expected {expected}, got {got}")]
    TypeMismatch { expected: &'static str, got: String },

    #[error("challenge does not match the one issued for this ceremony")]
    ChallengeMismatch,

    #[error("origin mismatch: expected {expected}, got {got}")]
    OriginMismatch { expected: String, got: String },

    #[error("attestationObject is not valid CBOR: {0}")]
    AttestationCbor(String),

    #[error("authenticatorData is malformed: {0}")]
    AuthData(String),

    #[error("rpIdHash in authenticatorData does not match the configured rp_id")]
    RpIdHashMismatch,

    #[error("user presence flag (UP) was not set")]
    UserNotPresent,

    #[error("user verification was required but the UV flag was not set")]
    UserNotVerified,

    #[error("credential public key is not ES256 over P-256")]
    UnsupportedKey,

    #[error("COSE key is malformed: {0}")]
    CoseKey(String),

    #[error("attestation format {0} is not supported")]
    UnsupportedAttestation(String),

    #[error("attestation statement is malformed: {0}")]
    AttestationStatement(String),

    #[error("signature verification failed")]
    BadSignature,

    #[error(
        "signature counter regressed (possible cloned authenticator): stored {stored}, got {got}"
    )]
    SignCountRegression { stored: u32, got: u32 },

    #[error("base64url decode failed: {0}")]
    Base64(String),

    #[error("random number generation failed: {0}")]
    Rng(String),
}

/// The crate's result alias.
pub type Result<T> = core::result::Result<T, Error>;
