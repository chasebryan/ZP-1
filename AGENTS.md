# AGENTS.md

## Project overview

This repository implements ZP-1, a post-quantum signed encryption envelope.

ZP-1 combines:

- ML-KEM-1024 for recipient encapsulation
- ML-DSA-87 for signer authentication
- optional SLH-DSA level-5 archival co-signature
- SHA-384 for hashing
- HMAC-SHA384 for extract/expand KDF
- AES-256-GCM-SIV for authenticated chunk encryption
- canonical binary encoding
- signed public manifest
- key commitment
- Merkle-root chunk binding
- uniform authentication failure behavior

This is an experimental reference implementation. Do not claim production readiness.

## Hard rules

- Do not redesign the protocol without updating SPEC.md and tests.
- Do not replace AES-256-GCM-SIV with AES-GCM.
- Do not replace SHA-384 with SHA-256.
- Do not replace ML-KEM-1024 with lower parameter sets in the core profile.
- Do not replace ML-DSA-87 with lower parameter sets in the core profile.
- Do not implement cryptographic primitives manually.
- Do not expose test-only fake crypto outside tests or the `test-utils` feature.
- Do not return distinguishable public errors for bad signature, bad recipient, bad AAD, bad tag, bad parse, or wrong key during Open.
- Do not release plaintext until every required verification succeeds.
- Do not use serde/bincode/JSON/CBOR/postcard for the wire format.
- Do not allow trailing bytes, duplicate fields, unknown critical flags, non-canonical encodings, or impossible lengths.

## Development commands

Run before finishing any task:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --features test-utils -- -D warnings
cargo doc --no-deps
```

If clippy cannot run because the environment lacks a component, report that explicitly.

## Security posture

This crate is experimental until independently reviewed.
New tests must be added for every change to encoding, parsing, key schedule, sealing, opening, or failure behavior.
Prefer small, reviewable modules.
Prefer explicit length checks.
Prefer constant-time equality for secrets, tags, commitments, and hashes.
Zeroize secret material where possible.
