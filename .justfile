# passkeep dev recipes. Local runs mirror CI (jhheider/rust-ci@v1 callers on the
# self-hosted runner). The default backend is `ring`; the `-rustcrypto` recipes
# exercise the fully-pure-Rust backend the default build compiles out.

default:
    @just --list

# Lint with the same flags as CI.
lint:
    cargo clippy --all-targets -- -D warnings

lint-rustcrypto:
    cargo clippy --no-default-features --features rustcrypto --all-targets -- -D warnings

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

test:
    cargo test

test-rustcrypto:
    cargo test --no-default-features --features rustcrypto

# Just the known-answer vectors against real published authenticator output.
kat:
    cargo test --test kat
    cargo test --test kat --no-default-features --features rustcrypto

# Line + region coverage for the default backend (needs cargo-llvm-cov).
coverage:
    cargo llvm-cov --summary-only

# HTML coverage report at target/llvm-cov/html/index.html.
coverage-html:
    cargo llvm-cov --html
    @echo "==> target/llvm-cov/html/index.html"

# The rule that defines this crate: no C crypto toolchain in the tree.
no-c-deps:
    #!/usr/bin/env bash
    set -euo pipefail
    fail=0
    for c in openssl-sys aws-lc-sys; do
        if cargo tree -i "$c" >/dev/null 2>&1; then echo "FOUND $c (default)"; fail=1; fi
        if cargo tree --no-default-features --features rustcrypto -i "$c" >/dev/null 2>&1; then
            echo "FOUND $c (rustcrypto)"; fail=1
        fi
    done
    # ring must be absent from the pure-Rust backend.
    if cargo tree --no-default-features --features rustcrypto -i ring >/dev/null 2>&1; then
        echo "FOUND ring in the rustcrypto backend"; fail=1
    fi
    [ "$fail" = 0 ] && echo "clean: no C crypto toolchain in either backend" || exit 1

audit:
    cargo audit

# Everything CI checks, both backends.
check-all: fmt-check lint lint-rustcrypto test test-rustcrypto no-c-deps
    @echo "==> all local checks passed"

clean:
    cargo clean
