# ZP-1

Experimental post-quantum signed encryption envelope.

ZP-1 is a Rust reference implementation of a signed public-key encryption object format. It uses a KEM/KDF/AEAD envelope with recipient stanzas, canonical binary encoding, a signed public manifest, key commitment, and a Merkle root over authenticated chunks.

This crate is experimental, unaudited, and not production-ready. Do not use it for production secrets.

## Current Status

ZP-1 currently has an experimental Rust reference implementation.
The default crate does not include production PQC providers.
The deterministic provider is tests-only and not cryptographic.
Current validation covers protocol mechanics, canonical parsing, tamper detection, and limit checks.
External cryptographic review has not occurred.

## Validation Status

- positive deterministic vector exists
- negative corpus exists
- wire stability tests exist
- CI exists
- fuzzing scaffold exists
- production providers remain absent
- external review remains absent

## Primitive Suite

ZP-1 Core targets:

- ML-KEM-1024 for recipient encapsulation
- ML-DSA-87 for signer authentication
- SHA-384 for hashing
- HMAC-SHA384 extract/expand KDF
- AES-256-GCM-SIV for AEAD
- canonical binary encoding
- domain-separated SHA-384 Merkle tree

ZP-1 Archive is defined as Core plus an SLH-DSA level-5 archival co-signature. In v0.1, Archive structures are defined but archive operation is not implemented without a real provider.

## Security Goals

ZP-1 Core targets recipient confidentiality, ciphertext integrity, signer authenticity, AAD binding, recipient-key binding, signer-key binding, chunk order and length integrity, key commitment, downgrade resistance, and splice resistance under the assumptions in `SPEC.md`.

This is a design target, not a formal proof artifact.

## Non-Goals

- Production-readiness without independent review
- Implementing ML-KEM, ML-DSA, SLH-DSA, AES, SHA-384, or HMAC in this crate
- Providing a default native post-quantum provider
- Streaming plaintext release before full verification
- JSON, CBOR, serde, bincode, postcard, or map-based wire encoding

## Test-Only Example

The `InsecureTestProvider` is NOT CRYPTOGRAPHICALLY SECURE. TESTS ONLY. It exists to exercise protocol mechanics when no post-quantum provider is installed.

```rust
use zp1::open::{open, OpenOptions};
use zp1::provider::test_utils::InsecureTestProvider;
use zp1::seal::{seal, SealOptions};

let mut provider = InsecureTestProvider::new(b"readme example");
let (recipient_pk, recipient_sk) = provider.generate_kem_keypair(b"recipient");
let (signer_pk, signer_sk) = provider.generate_signature_keypair(b"signer");

let aad = b"artifact metadata";
let plaintext = b"sealed contents";

let object = seal(
    &mut provider,
    &[recipient_pk],
    &signer_sk,
    &signer_pk,
    aad,
    plaintext,
    SealOptions::default(),
)?;

let opened = open(
    &mut provider,
    &recipient_sk,
    &signer_pk,
    aad,
    &object,
    OpenOptions::default(),
)?;

assert_eq!(opened, plaintext);
# Ok::<(), zp1::Zp1Error>(())
```

Production use requires a real provider for ML-KEM-1024 and ML-DSA-87. The default build does not expose fake cryptography.

## Build and Test

```sh
cargo fmt --check
cargo test
cargo test --features test-utils
cargo test --no-default-features
cargo clippy --all-targets --features test-utils -- -D warnings
cargo doc --no-deps
```
