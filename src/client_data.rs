use crate::error::{Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;

/// The CollectedClientData (WebAuthn 5.8.1) the browser hands back, JSON-encoded
/// in the response's clientDataJSON. We only read the fields the ceremony checks
/// need; unknown fields are ignored.
#[derive(Debug, Deserialize)]
pub struct CollectedClientData {
    #[serde(rename = "type")]
    pub ceremony_type: String,
    pub challenge: String,
    pub origin: String,
    // crossOrigin and other fields (tokenBinding, topOrigin) are intentionally
    // ignored: serde drops unknown fields, and the basic ceremony does not gate
    // on them. Add them here if a check ever needs them.
}

impl CollectedClientData {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| Error::ClientDataJson(e.to_string()))
    }

    /// Check the three fields that bind a response to this ceremony: the type
    /// string, the (base64url) challenge, and the origin.
    pub fn verify(
        &self,
        expected_type: &'static str,
        expected_challenge: &[u8],
        expected_origin: &str,
    ) -> Result<()> {
        if self.ceremony_type != expected_type {
            return Err(Error::TypeMismatch {
                expected: expected_type,
                got: self.ceremony_type.clone(),
            });
        }
        let got_challenge = URL_SAFE_NO_PAD
            .decode(self.challenge.as_bytes())
            .map_err(|e| Error::Base64(e.to_string()))?;
        if got_challenge != expected_challenge {
            return Err(Error::ChallengeMismatch);
        }
        if self.origin != expected_origin {
            return Err(Error::OriginMismatch {
                expected: expected_origin.to_string(),
                got: self.origin.clone(),
            });
        }
        Ok(())
    }
}
