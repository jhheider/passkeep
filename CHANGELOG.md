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
- Two build-time crypto backends: `ring` (default; its own vendored crypto, no
  OpenSSL/aws-lc/cmake/NASM) and `rustcrypto` (p256 + sha2, zero C). Both
  verified free of openssl-sys/aws-lc-sys/cmake in CI.
- `Challenge` helper for generating and encoding ceremony challenges.
- Self-consistency roundtrip tests plus rejection-path tests across both
  backends.
- Known-answer tests against real published WebAuthn vectors, stored as JSON
  fixtures under tests/vectors/ with PROVENANCE.md: `none` + ES256 assertion
  (duo-labs/py_webauthn, BSD-3), packed self attestation, and real Apple and
  Android device captures that must be rejected cleanly (MasterKale/
  SimpleWebAuthn, MIT). ~91% line coverage.
- `examples/axum_rp.rs`: the full ceremony round trip wired into an axum server.
- Full rustdoc on every public item (`#![warn(missing_docs)]`), and an
  adversarial security review of the parsing and verification (no exploitable
  issues found).

### Not yet

- Publication to crates.io (proving it out internally first).
- `packed` basic/full attestation (x5c certificate chain).
