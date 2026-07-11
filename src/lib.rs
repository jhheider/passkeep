//! passkeep: a small, pure-Rust WebAuthn relying party.
//!
//! It does exactly the server side of passkeys and nothing else: verify a
//! registration ceremony, verify an assertion ceremony, and tell you what to
//! store. No C crypto in the dependency tree (ring's prebuilt asm by default, or
//! fully-pure-Rust p256 via the `rustcrypto` feature), no database, no HTTP
//! framework, no sessions or user model. You own transport and storage; this
//! crate owns the ceremony checks and the ES256 signature verification.
//!
//! Scope: ES256 (the algorithm Apple and Android platform authenticators emit),
//! attestation `none` and `packed` self attestation. See the README for what is
//! deliberately left out.
//!
//! ```no_run
//! use passkeep::{Challenge, RelyingParty, RegistrationVerification};
//!
//! let rp = RelyingParty::new("example.com", "https://example.com");
//!
//! // 1. Issue a challenge, send its base64url to the browser, remember the raw bytes.
//! let challenge = Challenge::generate().unwrap();
//! let _b64 = challenge.to_base64url();
//!
//! // 2. On the create() response, verify and persist the returned credential.
//! # let client_data_json = b"";
//! # let attestation_object = b"";
//! let verification = RegistrationVerification {
//!     client_data_json,
//!     attestation_object,
//!     expected_challenge: challenge.as_bytes(),
//!     require_user_verification: true,
//! };
//! match rp.verify_registration(&verification) {
//!     Ok(credential) => { /* store credential.credential_id, public_key, sign_count */ }
//!     Err(e) => eprintln!("registration rejected: {e}"),
//! }
//! ```
#![forbid(unsafe_code)]

mod assertion;
mod attestation;
mod auth_data;
mod client_data;
mod cose;
mod crypto;
mod error;
mod registration;

pub use assertion::{AssertionOutcome, AssertionVerification};
pub use cose::CoseEs256Key;
pub use error::{Error, Result};
pub use registration::{RegisteredCredential, RegistrationVerification};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// A configured relying party.
///
/// `rp_id` is the domain the credential is scoped to (an eTLD+1 or a host, e.g.
/// `example.com`); `origin` is the exact origin the browser reports, scheme and
/// all (e.g. `https://example.com`). Both are checked on every ceremony.
#[derive(Clone, Debug)]
pub struct RelyingParty {
    rp_id: String,
    origin: String,
}

impl RelyingParty {
    pub fn new(rp_id: impl Into<String>, origin: impl Into<String>) -> Self {
        Self {
            rp_id: rp_id.into(),
            origin: origin.into(),
        }
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Verify a registration (navigator.credentials.create) response. On success
    /// returns the credential to persist.
    pub fn verify_registration(
        &self,
        v: &RegistrationVerification<'_>,
    ) -> Result<RegisteredCredential> {
        registration::verify(&self.rp_id, &self.origin, v)
    }

    /// Verify an assertion (navigator.credentials.get) response against a stored
    /// credential. On success returns the new sign count to persist.
    pub fn verify_assertion(&self, v: &AssertionVerification<'_>) -> Result<AssertionOutcome> {
        assertion::verify(&self.rp_id, &self.origin, v)
    }
}

/// A freshly generated 32-byte ceremony challenge.
///
/// Issue one per ceremony: send [`Challenge::to_base64url`] to the browser as
/// the `challenge`, and keep [`Challenge::as_bytes`] server-side to pass as the
/// `expected_challenge` when the response comes back.
pub struct Challenge(Vec<u8>);

impl Challenge {
    /// 32 random bytes from the OS RNG.
    pub fn generate() -> Result<Self> {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).map_err(|e| Error::Rng(e.to_string()))?;
        Ok(Self(buf.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.0)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}
