# CLAUDE.md

passkeep: a small, pure-Rust WebAuthn relying party (the server side of
passkeys). Verify a registration, verify an assertion, nothing more. It exists
because the beadventory rewrite needs passkey auth for one or two accounts and
does not want a C toolchain (OpenSSL via webauthn-rs, AWS-LC via passkey) dragged
into a Leptos/axum app. Original brief:
https://github.com/jhheider/briefs/blob/main/ideas/pure-rust-webauthn-rp.md

## The one rule that defines this crate

**No OpenSSL, no aws-lc, no external C build system (cmake/NASM), and a
fully-pure-Rust option.** ES256 verification goes through `ring` by default
(its own vendored crypto: pregenerated asm plus a little C compiled by `cc`, but
no OpenSSL/aws-lc/cmake/NASM, and it cross-compiles clean to musl/aarch64) or
RustCrypto `p256` (the `rustcrypto` feature, genuinely zero C). Do NOT claim
"no C in the tree": the default ring backend does compile a little C. The honest
and enforced invariant is the one above. After any dependency change, confirm:

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

The repo is **public**, but `publish = false` in Cargo.toml is intentional: we
are proving it out internally before the first crates.io release. Two brief
items are already done (real Apple/Android known-answer vectors, and an
adversarial security review of the parsing and verification, no exploitable
issues found). Before flipping `publish` and cutting a release: run cargo-msrv
for the real `rust-version`, add a `release.yml` rust-ci caller
(publish-crates: true), bump the version off `-dev`, and only then tell anyone
to depend on it.

## CI

Public repo, so CI runs on the **hosted** rust-ci matrix (never self-hosted:
fork PRs would run arbitrary code on the box). Thin callers over
jhheider/rust-ci@v1 (ci.yml, style.yml, audit.yml). The main CI job covers the
default `ring` backend; a second job runs clippy + tests for the `rustcrypto`
backend, which the default build compiles out.

History: it was a private repo on the self-hosted Mac Studio runner during
initial development; going public flipped the workflows to hosted and removed
the `passkeep` service from `gha-runner`.

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
