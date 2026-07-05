# ZP-1 Specification

This document is the normative protocol specification for ZP-1 v1.

## Profiles

Suite IDs:

- `SuiteId::Zp1Core = 0x0001`
- `SuiteId::Zp1Archive = 0x0002`

Core suite:

- KEM: ML-KEM-1024
- Signature: ML-DSA-87
- Hash: SHA-384
- KDF: HMAC-SHA384 extract/expand
- AEAD: AES-256-GCM-SIV
- Encoding: ZP-1 canonical binary encoding
- Chunks: fixed-size authenticated chunks
- Tree: domain-separated SHA-384 Merkle tree

Archive suite:

- Everything in Core
- Required SLH-DSA level-5 co-signature

In v0.1, the Core envelope is implemented. Archive structures are defined, but Archive may return `UnsupportedSuite` until a real SLH-DSA provider exists.

## Constants

```text
MAGIC = b"ZP1\0"
VERSION = 1

HASH_LEN = 48
CONTENT_SECRET_LEN = 48
OBJECT_ID_LEN = 16
AEAD_KEY_LEN = 32
AES_GCM_SIV_NONCE_LEN = 12
MANIFEST_TAG_LEN = 48
KEY_COMMITMENT_LEN = 48

DEFAULT_CHUNK_SIZE = 1_048_576
MIN_CHUNK_SIZE = 1
MAX_CHUNK_SIZE = 16_777_216

MAX_RECIPIENTS = 1024
MAX_CHUNKS = 4_294_967_295
MAX_PLAINTEXT_LEN = 17_592_186_040_320
MAX_AAD_LEN = 1_073_741_824
MAX_KEM_CT_LEN = 16_384
MAX_SIGNATURE_LEN = 65_536
MAX_PUBLIC_KEY_LEN = 65_536
MAX_OBJECT_LEN = u64::MAX
```

Domain labels are exact byte strings:

```text
b"ZP1 aad"
b"ZP1 signer-pk"
b"ZP1 recipient-pk"
b"ZP1 recipient-stanzas"
b"ZP1 recipient wrap salt"
b"ZP1 wrap key"
b"ZP1 content salt"
b"ZP1 chunk AEAD key"
b"ZP1 key commitment key"
b"ZP1 manifest MAC key"
b"ZP1 content key commitment"
b"ZP1 chunk aad"
b"ZP1 merkle leaf"
b"ZP1 merkle node"
b"ZP1 merkle root"
b"ZP1 manifest tag"
b"ZP1 signature input"
b"ZP1-KDF-v1"
```

## Object Format

All integers are big-endian. There are no varints, maps, duplicate fields, or optional-field ambiguity. Fixed order is mandatory. Parsers reject trailing bytes, unknown critical flags, unknown suite IDs, impossible lengths, and unsupported versions.

Top-level object:

```text
Zp1Object =
    magic[4]
    version:u16
    suite_id:u16
    base_header_len:u32
    base_header
    recipient_count:u16
    recipient_stanza_0_len:u32
    recipient_stanza_0
    ...
    public_manifest_len:u32
    public_manifest
    chunk_count:u64
    chunk_0_len:u32
    chunk_0
    ...
    manifest_tag_len:u16
    manifest_tag
    signature_block_len:u32
    signature_block
```

`manifest_tag_len` must equal 48. Empty plaintext and empty AAD are allowed. Empty recipient lists and empty chunk lists are rejected.

BaseHeader:

```text
domain_len:u16
domain bytes = b"ZP1 base header"
suite_id:u16
object_id[16]
chunk_size:u32
plaintext_length:u64
aad_hash[48]
signer_pk_hash[48]
flags:u32
```

Flags must be zero in v0.1.

RecipientHeader:

```text
domain_len:u16
domain bytes = b"ZP1 recipient header"
recipient_index:u32
recipient_pk_hash[48]
kem_ciphertext_len:u32
kem_ciphertext
```

RecipientStanza:

```text
recipient_header_len:u32
recipient_header
wrapped_content_secret_len:u32
wrapped_content_secret
```

PublicManifest:

```text
domain_len:u16
domain bytes = b"ZP1 public manifest"
base_header_hash[48]
stanzas_hash[48]
key_commitment[48]
chunk_count:u64
chunk_size:u32
plaintext_length:u64
merkle_root[48]
aad_hash[48]
signer_pk_hash[48]
```

SignatureBlock:

```text
domain_len:u16
domain bytes = b"ZP1 signature block"
signer_public_key_len:u32
signer_public_key
mldsa_signature_len:u32
mldsa_signature
archive_present:u8
if archive_present == 1:
    archive_public_key_len:u32
    archive_public_key
    slhdsa_signature_len:u32
    slhdsa_signature
else:
    no archive fields
```

`archive_present` values other than 0 or 1 are rejected.

## Hashes

`sha384(data)` returns SHA-384 over `data`.

`hash_many(domain, parts)` computes:

```text
SHA384(
    u16_be(domain.len()) ||
    domain ||
    for each part:
        u64_be(part.len()) || part
)
```

`hash1(domain, data)` is `hash_many(domain, [data])`.

Definitions:

```text
aad_hash = hash1(b"ZP1 aad", AAD)
signer_pk_hash = hash1(b"ZP1 signer-pk", canonical_signer_public_key)
recipient_pk_hash = hash1(b"ZP1 recipient-pk", canonical_recipient_public_key)
```

## KDF

HMAC-SHA384 extract:

```text
extract(salt, ikm) = HMAC-SHA384(key = salt, data = ikm)
```

Expand:

```text
T = empty
OKM = empty

for counter from 1 to ceil(out_len / 48):
    T = HMAC-SHA384(
        key = prk,
        data =
            previous_T ||
            u32_be(counter) ||
            u16_be(len(b"ZP1-KDF-v1")) ||
            b"ZP1-KDF-v1" ||
            u16_be(len(label)) ||
            label ||
            u32_be(len(context)) ||
            context ||
            u32_be(out_len * 8)
    )
    OKM = OKM || T

return leftmost out_len bytes of OKM
```

## Merkle Tree

Leaf:

```text
L_i = hash_many(
    b"ZP1 merkle leaf",
    [
        u64_be(i),
        u64_be(plaintext_chunk_len),
        nonce_i,
        ciphertext_i,
        sha384(chunk_aad_i)
    ]
)
```

Root:

```text
level = leaves
level_index = 0

while level.len() > 1:
    next = []
    for pair_index in 0..ceil(level.len()/2):
        left = level[2 * pair_index]
        right = level[2 * pair_index + 1] if present else left
        parent = hash_many(
            b"ZP1 merkle node",
            [
                u64_be(level_index),
                u64_be(pair_index),
                left,
                right
            ]
        )
        next.push(parent)
    level = next
    level_index += 1

root = hash_many(
    b"ZP1 merkle root",
    [
        u64_be(original_leaf_count),
        level[0]
    ]
)
```

## Seal Algorithm

Seal validates recipient count, AAD length, plaintext length, chunk size, suite support, and provider output sizes. It generates a 48-byte `content_secret` and 16-byte `object_id`, encodes `BaseHeader`, wraps the content secret separately for each recipient using ML-KEM-derived wrap keys, derives content keys from `content_secret`, encrypts fixed-size chunks with AES-256-GCM-SIV, computes Merkle leaves and root, encodes `PublicManifest`, computes the manifest tag, signs the public transcript with ML-DSA-87, and encodes the top-level object.

The signature input is:

```text
hash_many(
    b"ZP1 signature input",
    [
        BaseHeader,
        RecipientStanza_0,
        ...,
        PublicManifest,
        ManifestTag
    ]
)
```

## Open Algorithm

Open canonically parses the object, validates limits, checks AAD and manifest/header consistency, recomputes `stanzas_hash`, verifies signer binding, verifies the ML-DSA-87 signature before attempting chunk decryption, locates exactly one matching recipient stanza, unwraps the content secret, derives content keys, verifies key commitment and manifest tag, recomputes chunk leaves and the Merkle root from ciphertext and expected plaintext chunk lengths before decrypting chunks, decrypts every chunk, and only then returns plaintext.

No partially decrypted plaintext is released by the simple `open` API.

## Public Error Behavior

Public Open APIs collapse authentication, parsing, and security failures to:

```text
Zp1Error::Auth
```

Allowed public non-auth errors are:

```text
Zp1Error::UnsupportedSuite
Zp1Error::LimitExceeded
Zp1Error::Provider
Zp1Error::Io
```

Open does not expose separate bad-signature, bad-AAD, bad-recipient, bad-tag, bad-key, bad-MAC, bad-Merkle-root, bad-commitment, or parse errors.

## Security Assumptions and Goals

Under the assumptions that ML-KEM-1024 is IND-CCA secure, HMAC-SHA384 is a suitable PRF/extractor for this construction, AES-256-GCM-SIV is AEAD-secure within the stated limits, ML-DSA-87 is EUF-CMA secure, SHA-384 is collision resistant, canonical encoding is injective, keys are validated, and suite identifiers are fixed, ZP-1 Core targets recipient confidentiality, ciphertext integrity, signer authenticity, AAD binding, recipient-key binding, signer-key binding, chunk order and length integrity, key commitment, downgrade resistance, and splice resistance.

This statement is a design target, not a formal proof artifact.

## Implementation Limits

The limits listed in Constants are normative for v0.1. Implementations must reject unsupported suites, non-zero flags, excessive recipient counts, zero chunk counts, excessive chunk sizes, excessive plaintext or AAD lengths, excessive KEM ciphertexts, excessive public keys, and excessive signatures.

## Test Vectors

The deterministic vector in `test-vectors/zp1-core-insecure-test-provider-v0.json` is generated with `InsecureTestProvider`.

NOT CRYPTOGRAPHICALLY SECURE. TEST VECTOR FOR WIRE FORMAT AND TRANSCRIPT STABILITY ONLY.

The deterministic test provider in this repository is not cryptographic and must not be used as a production test-vector source.
