# passkeep

A small WebAuthn **relying party**: verify passkey registration and assertion
ceremonies with **no OpenSSL and no aws-lc**, and an optional fully-pure-Rust
build with no C at all.

It does exactly the server side of passkeys and nothing else. No database, no
HTTP framework, no session or user model: you own transport and storage, and
passkeep owns the ceremony checks and the ES256 signature verification. The
result is a verified credential to persist (registration) or a new signature
counter to persist (assertion).

## Why it exists

It comes out of a small self-hosted Leptos/axum app that needs passkey auth for
one or two accounts and wants a minimal, dependency-light server-side verifier.
The RP side is not much crypto: for the common case (platform authenticators,
ES256) it is CBOR and byte parsing wrapped around a single ECDSA P-256 signature
verification. The hard part is spec compliance and getting the ceremony checks
right, not the math. passkeep does only that, synchronously, with a small
dependency set.

How it sits next to the established crates:

- `webauthn-rs` is the mature, full-featured choice. Its current 0.5 release
  links **OpenSSL** (the 0.6 line in progress is migrating to RustCrypto). It is
  a much larger surface than a one-or-two-account app needs.
- `passkey` (1Password's passkey-rs) is already pure-Rust (RustCrypto `p256`),
  but it is a full client-plus-authenticator toolkit: async, pulling
  `reqwest`, `tokio`, `coset`, and `public-suffix`. passkeep is a synchronous,
  relying-party-only verifier with a handful of dependencies.

So the niche is narrow on purpose: RP-only, small and synchronous, and free of
OpenSSL, aws-lc, and any external C build system (cmake, NASM), with a
fully-pure-Rust backend available for those who want zero C anywhere.

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

- `ring` (default): ES256 via ring's own vendored, self-contained crypto
  (pregenerated assembly plus a little C compiled by `cc`). No OpenSSL, no
  aws-lc, no cmake or NASM, and it cross-compiles clean to musl and aarch64.
- `rustcrypto`: `p256` + `sha2`, fully pure Rust for zero C anywhere.

```toml
# default: ring
passkeep = "0.1"

# or the fully-pure-Rust backend
passkeep = { version = "0.1", default-features = false, features = ["rustcrypto"] }
```

Both backends are verified free of `openssl-sys`, `aws-lc-sys`, and `cmake` in
CI, and the `rustcrypto` backend is verified free of `ring` as well.

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
```

`examples/axum_rp.rs` shows the full round trip wired into an axum server, with
the challenge held in an in-memory store keyed by a cookie and the credential
kept in memory (swap both for your session store and database).

You own everything around the ceremony. In particular: bind each issued
challenge to its pending ceremony, **invalidate it after a single
verification** (and ideally expire it), persist the credential id + public key +
sign count, at assertion time look the credential up by its id and verify that
credential belongs to the user you are authenticating, and reject a registration
whose credential id you already store.

## Status

Pre-1.0 and **not yet published to crates.io** (deliberately proving it out
internally first). It is tested four ways, all under both crypto backends:
self-consistency roundtrips, parser rejection-path tests, known-answer tests
against real published WebAuthn vectors including real Apple and Android device
captures (`tests/vectors/`, ~91% line coverage), and a documented pass through
an adversarial security review of the hand-rolled parsing and verification
(no exploitable issues found). Treat it as pre-1.0 regardless: review it
yourself before trusting it in production.

## License

MIT OR Apache-2.0, at your option.
