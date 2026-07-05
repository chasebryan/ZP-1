# ZP-1 Negative Test Vectors

The vectors in this directory are generated from `test-vectors/zp1-core-insecure-test-provider-v0.json`.

NOT CRYPTOGRAPHICALLY SECURE. NEGATIVE TEST VECTOR FOR PARSING AND AUTHENTICATION FAILURE BEHAVIOR ONLY.

Each vector mutates a valid deterministic ZP-1 object or its AAD and must fail public `open` with `Zp1Error::Auth`. These vectors are for parser, transcript-binding, and failure-collapse regression testing. They are not cryptographic assurance vectors.

The following constructible semantic mutations are represented as re-encoded objects rather than raw byte flips:

- `duplicate_matching_recipient_hash_if_constructible`
- `reorder_chunks_if_constructible`
- `drop_chunk_if_constructible`

If future mutations require large structural rewrites, keep the negative vector description here and cover the behavior in a normal Rust test.
