# CLAUDE.md

passkeep: a small, pure-Rust WebAuthn relying party (the server side of
passkeys). Verify a registration, verify an assertion, nothing more. It exists
because the beadventory rewrite needs passkey auth for one or two accounts and
does not want a C toolchain (OpenSSL via webauthn-rs, AWS-LC via passkey) dragged
into a Leptos/axum app. Original brief:
https://github.com/jhheider/briefs/blob/main/ideas/pure-rust-webauthn-rp.md

## The one rule that defines this crate

**No C crypto in the dependency tree.** ES256 verification goes through `ring`
(default backend, prebuilt asm, no cmake/NASM) or RustCrypto `p256` (the
`rustcrypto` feature, fully pure Rust). After any dependency change, confirm:

```
cargo tree -i openssl-sys        # must be empty
cargo tree -i aws-lc-sys         # must be empty
cargo tree --no-default-features --features rustcrypto -i ring   # must be empty
```

Their presence is a defect to fix, not a default to accept.

## Scope (from the brief)

- ES256 only (P-256 + SHA-256): the algorithm Apple and Android platform
  authenticators emit. RS256/EdDSA only if a concrete need appears.
- Attestation `none` and `packed` self attestation. `packed` with x5c
  (basic/full cert chain) is a deliberate not-yet, and errors honestly.
- Transport- and storage-agnostic: the crate does ceremony logic over plain
  types and returns what to persist. No database, no HTTP framework, no
  sessions or user model.

## The publish gate

`publish = false` in Cargo.toml is intentional. Before the first crates.io
release, two things must happen (they are the actual cost of this crate, per the
brief): real Apple/Android known-answer test vectors, and a pass through the
security-review skill over the hand-rolled parsing and verification. The current
tests are self-consistency roundtrips, not spec KATs. Do not flip `publish` or
tell anyone to depend on it until both are done.

## CI and the runner

Thin callers over jhheider/rust-ci@v1 (ci.yml, style.yml, audit.yml). While the
repo is **private** (pre-publish), jobs run on the self-hosted Mac Studio runner
(`runs-on: self-hosted`), and there is a `passkeep` service in the `gha-runner`
compose. The main CI job covers the default `ring` backend; a second job runs
clippy + tests for the `rustcrypto` backend, which the default build compiles
out.

**When it goes public** (at publish): this is a library, so hosted minutes are
free and fork PRs become a code-execution risk. Revert workflows to
`ubuntu-latest` / the full rust-ci matrix, remove the `passkeep` service from
`gha-runner`, `just up`, `just clean-stale`. Then add a `release.yml` rust-ci
caller (publish-crates: true) and flip `publish` in Cargo.toml.

## House style

- Lean dependency trees. Small crates over kitchen-sink ones; no crate that
  shells out to cmake/NASM or drags a heavy `-sys` subtree.
- Plain ASCII everywhere: no em-dash or en-dash in any file, comments and docs
  included (the style.yml gate enforces it; license texts are skip-listed). Use
  " - " or rephrase.
- `#![forbid(unsafe_code)]` in the crate. Do not add `-A` clippy escapes; fix
  the code.
- Security-sensitive: every parsing/verification change wants a test, and the
  bar for "looks right" is a passing roundtrip plus, eventually, a KAT vector.
