# ZP-1 Provider Boundary

ZP-1 core does not implement ML-KEM, ML-DSA, or SLH-DSA itself. The crate defines provider traits so the protocol implementation can remain separate from post-quantum primitive implementations.

This repository currently ships no production cryptographic provider. The deterministic provider is not cryptographic, is for tests only, and must never be used for production data.

## Provider Requirements

Production providers must validate key encodings before use. Invalid, non-canonical, wrong-suite, malformed, or unsupported keys must be rejected by the provider.

Production providers must expose canonical public key bytes. ZP-1 hashes those bytes for signer and recipient binding, so byte canonicalization is part of the security boundary.

Production providers must define how a recipient secret key maps to the canonical recipient public key hash. The `derive_public_key_hash_from_secret` method must return the same value as:

```text
hash1(b"ZP1 recipient-pk", canonical_recipient_public_key)
```

Production providers must enforce KEM ciphertext and signature length limits before returning data to the protocol layer. Provider errors during Open must collapse through the public API to `Zp1Error::Auth` when they are caused by user-controlled object content.

Side-channel resistance depends on provider implementation. ZP-1 uses constant-time equality for protocol hashes, tags, and commitments where possible, but it cannot make an underlying KEM, signature implementation, or key parser side-channel resistant.

## Before Enabling A Production Provider Feature

A production provider feature must not be enabled until the provider implementation, key encoding rules, and error behavior have been reviewed against this boundary.

Production provider integration should not begin until CI is green, positive vectors pass, negative vectors pass, fuzzing has run against decode/open/mutation targets, and provider key canonicalization is specified.

Checklist:

- [ ] ML-KEM-1024 provider is from a vetted implementation
- [ ] ML-DSA-87 provider is from a vetted implementation
- [ ] SLH-DSA level-5 provider is available before Archive suite is enabled
- [ ] public key canonicalization is defined
- [ ] secret key to public key hash derivation is defined
- [ ] KEM ciphertext length limits are enforced
- [ ] signature length limits are enforced
- [ ] provider errors collapse correctly through Open
- [ ] test vectors still pass
- [ ] fuzzing has been run against decode/open
- [ ] no fake provider is reachable in default build
- [ ] external review status is documented

## Test Provider

`InsecureTestProvider` is NOT CRYPTOGRAPHICALLY SECURE. TESTS ONLY.

It exists to test wire format stability, transcript binding, KDF label use, manifest binding, Merkle behavior, AAD binding, and uniform failure behavior. It is gated behind `test-utils` in the library API and must not be reachable in the default build.
