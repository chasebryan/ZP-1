# ZP-1 Tools

The checked-in test vector generator is `src/bin/generate_test_vector.rs`.

It is gated by the `test-utils` feature:

```sh
cargo run --features test-utils --bin generate_test_vector
cargo run --features test-utils --bin generate_test_vector -- --write
```

The generator uses `InsecureTestProvider`, which is not cryptographic and is for tests only.
