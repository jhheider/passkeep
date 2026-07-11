//! The crypto backend: SHA-256 and ES256 signature verification. Exactly one
//! backend is selected at build time. `ring` (the default) wins if both feature
//! flags are on; `rustcrypto` is the fully-pure-Rust alternative.

#[cfg(feature = "ring")]
mod ring_backend;
#[cfg(feature = "ring")]
pub(crate) use ring_backend::{sha256, verify_es256};

#[cfg(all(feature = "rustcrypto", not(feature = "ring")))]
mod rustcrypto_backend;
#[cfg(all(feature = "rustcrypto", not(feature = "ring")))]
pub(crate) use rustcrypto_backend::{sha256, verify_es256};

#[cfg(not(any(feature = "ring", feature = "rustcrypto")))]
compile_error!("passkeep needs a crypto backend: enable feature `ring` (default) or `rustcrypto`.");
