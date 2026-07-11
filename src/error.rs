use thiserror::Error;

/// Everything that can go wrong verifying a ceremony. Each variant is a distinct
/// spec check failing, so a caller can log or branch on the reason.
#[derive(Debug, Error)]
pub enum Error {
    /// clientDataJSON did not parse as JSON.
    #[error("clientDataJSON is not valid JSON: {0}")]
    ClientDataJson(String),

    /// The clientData `type` was not the value this ceremony requires
    /// (`webauthn.create` for registration, `webauthn.get` for assertion).
    #[error("ceremony type mismatch: expected {expected}, got {got}")]
    TypeMismatch {
        /// The type string this ceremony required.
        expected: &'static str,
        /// The type string the response carried.
        got: String,
    },

    /// The response challenge did not match the one issued for this ceremony.
    #[error("challenge does not match the one issued for this ceremony")]
    ChallengeMismatch,

    /// The response origin was not the configured origin.
    #[error("origin mismatch: expected {expected}, got {got}")]
    OriginMismatch {
        /// The configured origin.
        expected: String,
        /// The origin the response carried.
        got: String,
    },

    /// attestationObject did not parse as CBOR.
    #[error("attestationObject is not valid CBOR: {0}")]
    AttestationCbor(String),

    /// authenticatorData was too short or otherwise malformed.
    #[error("authenticatorData is malformed: {0}")]
    AuthData(String),

    /// The rpIdHash in authenticatorData did not equal SHA-256 of the rp_id.
    #[error("rpIdHash in authenticatorData does not match the configured rp_id")]
    RpIdHashMismatch,

    /// The User Present (UP) flag was not set.
    #[error("user presence flag (UP) was not set")]
    UserNotPresent,

    /// User verification was required but the User Verified (UV) flag was unset.
    #[error("user verification was required but the UV flag was not set")]
    UserNotVerified,

    /// The credential public key was not an ES256 / P-256 key.
    #[error("credential public key is not ES256 over P-256")]
    UnsupportedKey,

    /// The COSE_Key structure was malformed.
    #[error("COSE key is malformed: {0}")]
    CoseKey(String),

    /// The attestation format is one this crate does not verify.
    #[error("attestation format {0} is not supported")]
    UnsupportedAttestation(String),

    /// The attestation statement (attStmt) was malformed for its format.
    #[error("attestation statement is malformed: {0}")]
    AttestationStatement(String),

    /// The signature did not verify against the credential public key.
    #[error("signature verification failed")]
    BadSignature,

    /// The signature counter did not advance, a possible cloned-authenticator
    /// signal.
    #[error(
        "signature counter regressed (possible cloned authenticator): stored {stored}, got {got}"
    )]
    SignCountRegression {
        /// The counter value currently stored for the credential.
        stored: u32,
        /// The counter value the response carried.
        got: u32,
    },

    /// A base64url field failed to decode.
    #[error("base64url decode failed: {0}")]
    Base64(String),

    /// The OS RNG failed while generating a challenge.
    #[error("random number generation failed: {0}")]
    Rng(String),
}

/// The crate's result alias.
pub type Result<T> = core::result::Result<T, Error>;
