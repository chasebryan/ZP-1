# ZP-1 Implementation Invariants

## Canonical Parsing

All object parsing is fixed-order and length-prefixed. There are no maps, varints, duplicate fields, or optional-field ambiguities.

## No Trailing Bytes

Every nested parser and the top-level parser must consume exactly all bytes in its declared range.

## Fixed Integer Widths

All integers are big-endian and fixed width. Wire integer widths must not change.

## Suite ID Stability

`SuiteId::Zp1Core` is `0x0001`. `SuiteId::Zp1Archive` is `0x0002`.

## Domain Label Stability

Domain labels in `src/constants.rs` are protocol bytes. Changing them changes the transcript and requires an intentional SPEC and vector update.

## hash_many Length Separation

`hash_many(domain, parts)` encodes `u16_be(domain.len()) || domain || u64_be(part.len()) || part` for each part. Raw concatenation must not replace this where `hash_many` is specified.

## KDF Label Format

KDF expand includes previous block, `u32_be(counter)`, `b"ZP1-KDF-v1"`, label length and label, context length and context, and output length in bits.

## BaseHeader Binding

The public manifest binds `sha384(BaseHeader)`. Chunk AAD binds `sha384(BaseHeader)`.

## Recipient Stanza Binding

Recipient stanzas are hashed in order with `b"ZP1 recipient-stanzas"` and bound into content key derivation, key commitment, chunk AAD, and the signature transcript.

## Content-Secret Wrapping

The content secret is generated once per object and wrapped separately for each recipient using the KEM-derived wrap key and `BaseHeader || RecipientHeader` AAD.

## Key Commitment

The key commitment is HMAC-SHA384 under `K_commit` over the length-separated content key commitment transcript.

## Manifest MAC

The manifest tag is HMAC-SHA384 under `K_manifest` over the length-separated manifest tag transcript.

## Signature Transcript

The ML-DSA signature input is `hash_many(b"ZP1 signature input", [BaseHeader, RecipientStanza..., PublicManifest, ManifestTag])`.

## Merkle Construction

Merkle leaves bind chunk index, plaintext chunk length, nonce, ciphertext, and `sha384(chunk_aad)`. Parent nodes bind level index, pair index, left child, and right child. The root binds original leaf count and final node.

## Chunk AAD Construction

Chunk AAD binds the base header hash, stanzas hash, key commitment, AAD hash, index, chunk count, plaintext length, and chunk length.

## Failure Collapse

Public Open must collapse parser, authentication, binding, and integrity failures to `Zp1Error::Auth`, except documented unsupported-suite behavior.

## No Plaintext Release Before Verification

Open verifies parsing, AAD binding, manifest/header consistency, signature, recipient match, wrapped secret, key commitment, manifest tag, chunk lengths, and Merkle root before returning plaintext.

## Test Provider Isolation

`InsecureTestProvider` and span/inspection helpers are available only under `test-utils` or tests. The default build must not expose fake cryptography.
