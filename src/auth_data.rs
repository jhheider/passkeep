use crate::cose::CoseEs256Key;
use crate::error::{Error, Result};

/// User Present.
pub const FLAG_UP: u8 = 0x01;
/// User Verified.
pub const FLAG_UV: u8 = 0x04;
/// Backup Eligible.
pub const FLAG_BE: u8 = 0x08;
/// Backup State (currently backed up).
pub const FLAG_BS: u8 = 0x10;
/// Attested credential data present.
pub const FLAG_AT: u8 = 0x40;

/// Parsed authenticatorData (WebAuthn 6.1). Present in both ceremonies; only
/// registration carries the attested credential data.
pub struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub attested_credential: Option<AttestedCredential>,
}

/// The credential minted during registration: its id, the authenticator's
/// AAGUID, and its ES256 public key.
pub struct AttestedCredential {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    pub public_key: CoseEs256Key,
}

impl AuthenticatorData {
    pub fn user_present(&self) -> bool {
        self.flags & FLAG_UP != 0
    }
    pub fn user_verified(&self) -> bool {
        self.flags & FLAG_UV != 0
    }
    pub fn backup_eligible(&self) -> bool {
        self.flags & FLAG_BE != 0
    }
    pub fn backup_state(&self) -> bool {
        self.flags & FLAG_BS != 0
    }

    /// Parse the fixed 37-byte header and, if the AT flag is set, the attested
    /// credential data that follows.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 37 {
            return Err(Error::AuthData("shorter than the 37-byte header".into()));
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&data[0..32]);
        let flags = data[32];
        let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
        let rest = &data[37..];

        let attested_credential = if flags & FLAG_AT != 0 {
            if rest.len() < 18 {
                return Err(Error::AuthData(
                    "attested credential data is truncated".into(),
                ));
            }
            let mut aaguid = [0u8; 16];
            aaguid.copy_from_slice(&rest[0..16]);
            let id_len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
            let after_len = &rest[18..];
            if after_len.len() < id_len {
                return Err(Error::AuthData(
                    "credential id length exceeds the buffer".into(),
                ));
            }
            let credential_id = after_len[..id_len].to_vec();
            // The COSE key is the next CBOR item. When the ED flag is also set,
            // extension data follows the key; ciborium reads exactly one item
            // from the head, which is all we need (x and y).
            let key_bytes = &after_len[id_len..];
            let public_key = CoseEs256Key::from_cose_bytes(key_bytes)?;
            Some(AttestedCredential {
                aaguid,
                credential_id,
                public_key,
            })
        } else {
            None
        };

        Ok(Self {
            rp_id_hash,
            flags,
            sign_count,
            attested_credential,
        })
    }
}
