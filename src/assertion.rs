use crate::auth_data::AuthenticatorData;
use crate::client_data::CollectedClientData;
use crate::cose::CoseEs256Key;
use crate::crypto;
use crate::error::{Error, Result};

/// The pieces a caller extracts from a navigator.credentials.get() response,
/// plus the stored credential to check it against.
///
/// You look up `credential_public_key` and `previous_sign_count` by the
/// credential id the client returned; this crate does not own that storage.
/// `client_data_json`, `authenticator_data`, and `signature` are raw decoded
/// bytes, and `expected_challenge` is the raw challenge you issued.
pub struct AssertionVerification<'a> {
    /// Raw clientDataJSON bytes from the response.
    pub client_data_json: &'a [u8],
    /// Raw authenticatorData bytes from the response.
    pub authenticator_data: &'a [u8],
    /// Raw ASN.1 DER ECDSA signature bytes from the response.
    pub signature: &'a [u8],
    /// The raw challenge you issued for this ceremony.
    pub expected_challenge: &'a [u8],
    /// The stored public key, looked up by the returned credential id.
    pub credential_public_key: &'a CoseEs256Key,
    /// The sign count currently stored for this credential (clone detection).
    pub previous_sign_count: u32,
    /// Require the User Verified (UV) flag (e.g. a PIN or biometric was used).
    pub require_user_verification: bool,
}

/// What a successful assertion yields. Persist `new_sign_count` back onto the
/// stored credential (that is the whole point of the counter check).
#[derive(Clone, Debug)]
pub struct AssertionOutcome {
    /// The new signature counter to persist onto the stored credential.
    pub new_sign_count: u32,
    /// Whether the User Verified (UV) flag was set on this assertion.
    pub user_verified: bool,
    /// The Backup State (BS) flag: whether the credential is currently backed up.
    pub backup_state: bool,
}

pub(crate) fn verify(
    rp_id: &str,
    origin: &str,
    v: &AssertionVerification<'_>,
) -> Result<AssertionOutcome> {
    let client = CollectedClientData::parse(v.client_data_json)?;
    client.verify("webauthn.get", v.expected_challenge, origin)?;

    let auth = AuthenticatorData::parse(v.authenticator_data)?;
    if auth.rp_id_hash != crypto::sha256(rp_id.as_bytes()) {
        return Err(Error::RpIdHashMismatch);
    }
    if !auth.user_present() {
        return Err(Error::UserNotPresent);
    }
    if v.require_user_verification && !auth.user_verified() {
        return Err(Error::UserNotVerified);
    }

    // The authenticator signs authenticatorData || SHA-256(clientDataJSON).
    let mut signed = v.authenticator_data.to_vec();
    signed.extend_from_slice(&crypto::sha256(v.client_data_json));
    crypto::verify_es256(v.credential_public_key, &signed, v.signature)?;

    // signCount monotonicity: when both the stored and new counters are zero the
    // authenticator does not implement a counter (allowed); otherwise the new
    // value must strictly exceed the stored one, or the credential may be cloned.
    let both_zero = auth.sign_count == 0 && v.previous_sign_count == 0;
    if !both_zero && auth.sign_count <= v.previous_sign_count {
        return Err(Error::SignCountRegression {
            stored: v.previous_sign_count,
            got: auth.sign_count,
        });
    }

    Ok(AssertionOutcome {
        new_sign_count: auth.sign_count,
        user_verified: auth.user_verified(),
        backup_state: auth.backup_state(),
    })
}
