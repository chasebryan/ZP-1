# ZP-1 Audit Packet

Current status: experimental, unaudited, and not production-ready.

## Files And Modules To Review

- `SPEC.md`
- `src/object.rs`
- `src/codec.rs`
- `src/seal.rs`
- `src/open.rs`
- `src/provider.rs`
- `src/kdf.rs`
- `src/hash.rs`
- `src/merkle.rs`
- `src/error.rs`
- `tests/`
- `test-vectors/`
- `fuzz/`

## Protocol Invariants To Verify

- Canonical top-level object order
- No trailing bytes
- Fixed-width big-endian integers
- Suite ID stability
- Domain label stability
- `hash_many` length separation
- KDF label and context formatting
- BaseHeader binding
- Recipient stanza binding
- Content-secret wrapping
- Key commitment construction
- Manifest MAC construction
- Signature transcript construction
- Merkle leaf, node, and root construction
- Chunk AAD construction
- Uniform public Open failure behavior
- No plaintext release before all required verification succeeds
- Test provider isolation behind `test-utils`

## Cryptographic Assumptions

ZP-1 Core assumes ML-KEM-1024 IND-CCA security, ML-DSA-87 EUF-CMA security, SHA-384 collision resistance, HMAC-SHA384 suitability as used by the extract/expand KDF, AES-256-GCM-SIV AEAD security within limits, injective canonical encoding, validated keys, and fixed suite identifiers.

## Provider Assumptions

No production provider is wired in. Future providers must define canonical public key bytes, validate key encodings, enforce KEM ciphertext and signature length limits, provide secret-key-to-public-key hash derivation, and document side-channel properties.

## Test Vector References

- Positive vector: `test-vectors/zp1-core-insecure-test-provider-v0.json`
- Negative vectors: `test-vectors/negative/*.json`

These use `InsecureTestProvider` and are not cryptographic assurance vectors.

## Fuzzing Instructions

```sh
cargo install cargo-fuzz
cargo fuzz build
ZP1_FUZZ_SECONDS=30 ./scripts/run-fuzz-smoke.sh
cargo fuzz run decode_any
cargo fuzz run open_any
cargo fuzz run mutate_valid_vector
```

## Known Limitations

- No real ML-KEM-1024 provider is wired in.
- No real ML-DSA-87 provider is wired in.
- No real SLH-DSA level-5 provider is wired in.
- No independent cryptographic review has occurred.
- No side-channel audit has occurred.
- Long-duration fuzzing evidence is not yet documented unless run separately.
- Archive suite remains structurally defined but unsupported in v0.1.

## Review Blockers Before Production Use

- no real ML-KEM-1024 provider wired in
- no real ML-DSA-87 provider wired in
- no real SLH-DSA level-5 provider wired in
- no independent cryptographic review
- no side-channel audit
- no long-duration fuzzing evidence yet unless Phase 4 runs it successfully

## Questions For External Reviewers

- Does the transcript bind every object component required by the security target?
- Are parser length checks sufficient to prevent excessive allocation from hostile input?
- Is public Open failure collapse complete and consistent?
- Are KDF labels and contexts unambiguous and domain-separated?
- Does the Merkle construction bind chunk index, length, nonce, ciphertext, and chunk AAD as intended?
- Are key commitment and manifest MAC ordering and verification points appropriate?
- What provider canonicalization constraints must be added before production PQC integration?
