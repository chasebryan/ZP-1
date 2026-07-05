# Fuzzing ZP-1

Fuzzing infrastructure is not checked in yet. Recommended fuzz targets:

- Decode arbitrary bytes with `Zp1Object::decode`.
- Open arbitrary bytes with fixed AAD, signer key, and recipient key using the deterministic test provider.
- Mutate a valid sealed object and require Open to return either plaintext for the unmodified object or `Zp1Error::Auth` for modified objects.
- Mutate recipient stanza counts and length prefixes.
- Mutate chunk counts and length prefixes.
- Mutate manifest fields, manifest tags, signature blocks, and signature bytes.

Fuzzing should prioritize parser bounds checks, no trailing-byte acceptance, no panics on malformed input, no excessive allocation from untrusted lengths, failure collapse through Open, and no plaintext release before all required checks succeed.

Do not add `cargo-fuzz` to the default build. Fuzzing dependencies should remain opt-in development tooling.
