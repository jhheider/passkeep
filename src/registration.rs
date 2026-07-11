use crate::attestation::{self, AttestationObject};
use crate::auth_data::AuthenticatorData;
use crate::client_data::CollectedClientData;
use crate::cose::CoseEs256Key;
use crate::crypto;
use crate::error::{Error, Result};

/// The pieces a caller extracts from a navigator.credentials.create() response
/// and hands to [`crate::RelyingParty::verify_registration`], plus the
/// expectations to check against.
///
/// Transport-agnostic: you pull these out of whatever JSON your front end posts.
/// `client_data_json` and `attestation_object` are the raw decoded bytes (not
/// base64url), and `expected_challenge` is the raw challenge you issued.
pub struct RegistrationVerification<'a> {
    pub client_data_json: &'a [u8],
    pub attestation_object: &'a [u8],
    pub expected_challenge: &'a [u8],
    pub require_user_verification: bool,
}

/// What to persist after a successful registration. Store at least the
/// credential id, public key, and sign_count; the rest is useful metadata.
#[derive(Clone, Debug)]
pub struct RegisteredCredential {
    pub credential_id: Vec<u8>,
    pub public_key: CoseEs256Key,
    pub sign_count: u32,
    pub aaguid: [u8; 16],
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_format: String,
}

pub(crate) fn verify(
    rp_id: &str,
    origin: &str,
    v: &RegistrationVerification<'_>,
) -> Result<RegisteredCredential> {
    let client = CollectedClientData::parse(v.client_data_json)?;
    client.verify("webauthn.create", v.expected_challenge, origin)?;

    let att = AttestationObject::parse(v.attestation_object)?;
    let auth = AuthenticatorData::parse(&att.auth_data)?;

    if auth.rp_id_hash != crypto::sha256(rp_id.as_bytes()) {
        return Err(Error::RpIdHashMismatch);
    }
    if !auth.user_present() {
        return Err(Error::UserNotPresent);
    }
    if v.require_user_verification && !auth.user_verified() {
        return Err(Error::UserNotVerified);
    }

    let sign_count = auth.sign_count;
    let user_verified = auth.user_verified();
    let backup_eligible = auth.backup_eligible();
    let backup_state = auth.backup_state();

    let cred = auth.attested_credential.ok_or_else(|| {
        Error::AuthData("registration authData has no attested credential data".into())
    })?;

    attestation::verify_attestation(&att, &cred, v.client_data_json)?;

    Ok(RegisteredCredential {
        credential_id: cred.credential_id,
        public_key: cred.public_key,
        sign_count,
        aaguid: cred.aaguid,
        user_verified,
        backup_eligible,
        backup_state,
        attestation_format: att.fmt,
    })
}
