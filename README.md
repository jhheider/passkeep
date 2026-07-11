# passkeep

A small, pure-Rust WebAuthn **relying party**: verify passkey registration and
assertion ceremonies with **no C crypto in the dependency tree**.

It does exactly the server side of passkeys and nothing else. No database, no
HTTP framework, no session or user model: you own transport and storage, and
passkeep owns the ceremony checks and the ES256 signature verification. The
result is a verified credential to persist (registration) or a new signature
counter to persist (assertion).

## Why it exists

The two established options both pull a C library into your build:

- `webauthn-rs`, the mature choice, depends on OpenSSL.
- `passkey`, the pure-Rust-adjacent choice, uses aws-lc-rs (AWS-LC, C/C++).

For a small self-hosted Rust app, a C toolchain is friction the relying-party
side does not actually need. The RP is not much crypto: for the common case
(platform authenticators, ES256) it is CBOR and byte parsing wrapped around a
single ECDSA P-256 signature verification, which both `ring` and RustCrypto's
`p256` do without a C build. The hard part is spec compliance and getting the
ceremony checks right, not the math. passkeep fills that gap.

## Scope

Supported:

- **ES256** (ECDSA P-256 + SHA-256), the algorithm Apple and Android platform
  authenticators emit. One code path covers both.
- Registration ceremony: parse clientDataJSON and the attestation object, verify
  the rpIdHash and the UP/UV flags, extract the COSE public key, return the
  credential to store.
- Assertion ceremony: verify clientData, rpIdHash, and flags; verify the ES256
  signature over `authenticatorData || SHA-256(clientDataJSON)`; enforce
  signature-counter monotonicity.
- Attestation `none` and `packed` **self** attestation.

Deliberately out of scope (see the brief):

- Being `webauthn-rs`: no full attestation-format zoo, no enterprise
  attestation, no FIDO metadata service.
- RS256 / EdDSA (add if a concrete need appears).
- `packed` **basic/full** attestation with an x5c certificate chain: not yet
  implemented; it returns an error rather than pretending to verify.
- The client/browser side. This is the relying party only.
- A general auth framework (sessions, users, RBAC). passkeep verifies
  ceremonies; your app owns everything else.

## Crypto backend

Chosen at build time behind a feature:

- `ring` (default): ring's prebuilt asm, no cmake or NASM, cross-compiles clean
  to musl and aarch64.
- `rustcrypto`: fully pure Rust (`p256` + `sha2`) for zero C anywhere.

```toml
# default: ring
passkeep = "0.1"

# or the fully-pure-Rust backend
passkeep = { version = "0.1", default-features = false, features = ["rustcrypto"] }
```

Both are verified free of `openssl-sys`, `aws-lc-sys`, and `cmake` in CI.

## Usage

```rust
use passkeep::{
    Challenge, RelyingParty, RegistrationVerification, AssertionVerification,
};

let rp = RelyingParty::new("example.com", "https://example.com");

// Registration. Issue a challenge, send its base64url to the browser as the
// `challenge`, and keep the raw bytes for when the response comes back.
let challenge = Challenge::generate()?;
let _b64 = challenge.to_base64url();

let credential = rp.verify_registration(&RegistrationVerification {
    client_data_json,      // raw decoded bytes from the response
    attestation_object,    // raw decoded bytes from the response
    expected_challenge: challenge.as_bytes(),
    require_user_verification: true,
})?;
// Persist credential.credential_id, credential.public_key, credential.sign_count.

// Assertion. Look up the stored key and counter by the returned credential id.
let outcome = rp.verify_assertion(&AssertionVerification {
    client_data_json,
    authenticator_data,
    signature,
    expected_challenge: challenge.as_bytes(),
    credential_public_key: &stored_public_key,
    previous_sign_count: stored_sign_count,
    require_user_verification: true,
})?;
// Persist outcome.new_sign_count back onto the credential.
# Ok::<(), passkeep::Error>(())
```

An axum wiring example (the beadventory shape: challenge in a signed cookie or
server-side store, credentials in Postgres) is a planned addition.

## Status

Pre-1.0 and **not yet published**. It is tested three ways: self-consistency
roundtrips, parser rejection-path tests, and known-answer tests against real
published WebAuthn vectors (`tests/vectors/`, ~91% line coverage), all run under
both crypto backends. Before the first crates.io release it still needs
Apple/Android-captured vectors on top of the public ones and a pass through the
security-review skill over the hand-rolled parsing and verification. Do not trust
it in production yet.

## License

MIT OR Apache-2.0, at your option.
