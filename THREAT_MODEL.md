# ZP-1 Threat Model

ZP-1 is experimental and unaudited. This threat model describes the reference envelope implementation before production provider integration.

## Assets Protected

- Plaintext file/object contents
- Content secret
- Recipient KEM shared secrets
- Chunk AEAD keys
- Key commitment and manifest MAC keys
- Signer authenticity binding
- Recipient public-key binding
- AAD binding
- Chunk order and length integrity

## Attacker Capabilities

- arbitrary malformed object bytes
- chosen AAD
- chosen recipient public keys during sealing
- corrupted recipient stanzas
- corrupted manifest
- corrupted chunks
- replayed chunks
- reordered chunks
- truncated objects
- appended trailing bytes
- wrong signer key
- wrong recipient key
- provider failure

## Trust Boundaries

- ZP-1 object bytes are untrusted public input.
- AAD is caller-supplied and must match exactly.
- Recipient public keys supplied to Seal cross into the provider boundary.
- Recipient secret keys and signer public keys supplied to Open cross into the provider boundary.
- Cryptographic primitive correctness is delegated to providers and dependency crates.

## Public Inputs

- Encoded ZP-1 object bytes
- AAD
- Recipient public keys during Seal
- Expected signer public key during Open
- Suite identifiers and flags in encoded objects

## Secret Inputs

- Recipient secret keys
- Signer secret keys during Seal
- Content secret
- KEM shared secrets
- Derived AEAD, commitment, and manifest keys

## Provider Trust Assumptions

Providers must validate key encodings, expose canonical public key bytes, enforce KEM ciphertext and signature length limits, and implement the claimed primitives correctly. Provider errors caused by hostile object bytes must collapse through public Open to `Zp1Error::Auth`.

## Side-Channel Assumptions

The reference crate uses constant-time equality for protocol hashes, tags, and commitments where practical. Side-channel resistance of ML-KEM, ML-DSA, SLH-DSA, AES-256-GCM-SIV, SHA-384, HMAC-SHA384, key parsing, and secret-key handling depends on provider and dependency implementations.

## Serialization Assumptions

Canonical parsing is injective. All integer widths are fixed and big-endian. Parsers reject trailing bytes, unknown suites, unknown critical flags, impossible lengths, zero recipient counts, zero chunk counts, and malformed nested structures.

## Failure Collapse

Public Open must not distinguish parse failure, bad signature, bad AAD, bad recipient, bad wrapped secret, bad key commitment, bad manifest tag, bad Merkle root, bad chunk tag, trailing bytes, unknown flags, or malformed lengths. These failures collapse to `Zp1Error::Auth` except for documented unsupported-suite behavior.

## Out Of Scope

- Production readiness
- Provider implementation audits
- Side-channel proofs
- Compromised endpoints
- Memory disclosure by the host environment
- Denial-of-service resistance against unlimited input size beyond documented parser limits
- Long-term archival security claims before real SLH-DSA provider integration and review
