# Changelog

All notable changes to passkeep are recorded here. The format follows Keep a
Changelog, and the project aims to follow Semantic Versioning once it hits 1.0.

## Unreleased

### Added

- First cut of the relying party: ES256 only, attestation `none` and `packed`
  self attestation.
- Registration ceremony: clientDataJSON and attestationObject parsing, COSE
  ES256 key extraction, rpIdHash and UP/UV flag checks, returns the credential
  to persist.
- Assertion ceremony: signature verification over
  `authenticatorData || SHA-256(clientDataJSON)`, signature-counter monotonicity.
- Two build-time crypto backends: `ring` (default) and `rustcrypto` (p256 +
  sha2), both free of any C toolchain dependency.
- `Challenge` helper for generating and encoding ceremony challenges.
- Self-consistency roundtrip tests across both backends.

### Not yet

- Real Apple/Android known-answer test vectors (blocker for publish).
- Security-review-skill pass over the parsing and verification (blocker for
  publish).
- `packed` basic/full attestation (x5c certificate chain).
- An axum wiring example.
