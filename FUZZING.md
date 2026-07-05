# Fuzzing ZP-1

Fuzzing scaffolding is checked in under `fuzz/`. It is opt-in development tooling and does not affect normal crate builds.

Recommended commands:

```sh
cargo install cargo-fuzz
cargo fuzz run decode_any
cargo fuzz run open_any
cargo fuzz run mutate_valid_vector
```

To build fuzz targets without running them:

```sh
cargo fuzz build
```

Run the smoke script:

```sh
ZP1_FUZZ_SECONDS=30 ./scripts/run-fuzz-smoke.sh
```

Longer sessions:

```sh
ZP1_FUZZ_SECONDS=600 ./scripts/run-fuzz-smoke.sh
cargo fuzz run decode_any -- -max_total_time=3600
cargo fuzz run open_any -- -max_total_time=3600
cargo fuzz run mutate_valid_vector -- -max_total_time=3600
```

Targets:

- `decode_any`: decode arbitrary bytes with `Zp1Object::decode`.
- `open_any`: open arbitrary bytes with fixed deterministic test-provider keys and fixed AAD.
- `mutate_valid_vector`: start from the frozen positive vector and apply fuzzer-driven byte mutation, truncation, append, or swap operations.

The seed corpus includes:

```text
fuzz/corpus/zp1-core-valid.bin
```

Fuzzing should prioritize parser bounds checks, no trailing-byte acceptance, no panics on malformed input, no excessive allocation from untrusted lengths, failure collapse through Open, and no plaintext release before all required checks succeed.

If a crash is found, minimize it with cargo-fuzz tooling, file an issue with the minimized reproducer, and do not commit crash artifacts containing sensitive real-world data.

Fuzzing does not prove security. It is recommended before production provider integration, alongside deterministic positive vectors, negative vectors, CI, and external review.

Do not add `cargo-fuzz` to the default build. Fuzzing dependencies must remain isolated in `fuzz/`.
