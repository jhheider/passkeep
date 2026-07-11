# Test vector provenance

These are real WebAuthn ceremony responses captured from actual authenticators,
reused here as known-answer tests. passkeep did not generate them, so they check
the parser and verifier against outputs from the wild, not against itself.

## Source

All vectors in this directory come from **duo-labs/py_webauthn**, a widely used
Python WebAuthn library:

- Repository: https://github.com/duo-labs/py_webauthn
- License: BSD-3-Clause, Copyright (c) 2017-2021 Duo Security, Inc.

Per-file origin:

| File                              | Upstream test |
| --------------------------------- | ------------- |
| `registration_none_es256.json`    | `tests/test_verify_registration_response.py::test_verifies_none_attestation_response` |
| `assertion_es256.json`            | `tests/test_verify_authentication_response.py::test_verify_authentication_response_with_EC2_public_key` |

Each JSON file also carries its exact upstream test name in its `source` field.

## Format

Every binary field is stored as unpadded base64url (the same encoding WebAuthn
uses on the wire), so a fixture is a faithful transcription of what the browser
posted. `tests/kat.rs` decodes these and runs them through passkeep, asserting
both the accept path and the documented reject paths (wrong rp_id, tampered
signature, user-verification demanded when the ceremony did not verify).

## Adding vectors

Drop a new JSON file here following the same field names, cite its `source`, add
a row above, and reference it from `tests/kat.rs`. Prefer real captured
responses (Apple and Android platform authenticators are the next targets the
brief calls for) over synthetic ones.
