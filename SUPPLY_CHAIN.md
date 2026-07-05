# Supply Chain Policy

ZP-1 keeps the default dependency set small and avoids native post-quantum provider dependencies until provider canonicalization, review status, and operational risk are documented.

## Dependency Policy

- Prefer small, maintained Rust crates with compatible licenses.
- Do not add system-package requirements to the default build.
- Do not add network-dependent tests.
- Do not add production cryptographic providers without a provider-boundary review.
- Review every dependency change for license, maintenance status, transitive dependency growth, and whether it changes default build assumptions.

## Cryptographic Providers

ZP-1 core does not implement ML-KEM, ML-DSA, or SLH-DSA itself. Cryptographic primitives must come from vetted providers because provider correctness, key validation, canonical public key encoding, constant-time behavior, and side-channel resistance are outside the envelope layer.

No production PQC provider is included yet because the provider boundary and audit packet need to be stable before wiring in real ML-KEM-1024, ML-DSA-87, or SLH-DSA level-5 implementations.

## Optional Checks

Install and run cargo-deny:

```sh
cargo install cargo-deny
cargo deny check
```

Install and run cargo-audit:

```sh
cargo install cargo-audit
cargo audit
```

These checks are available through the manual `Supply Chain` GitHub Actions workflow. They are not part of ordinary PR CI because advisory database and network availability can be noisy.

## Reviewing Dependency Changes

For each dependency change:

- Confirm the dependency is required for the reference implementation.
- Check the license against `deny.toml`.
- Inspect the transitive dependency diff.
- Confirm no fake provider becomes reachable in the default build.
- Confirm default tests, `test-utils` tests, Clippy, docs, positive vectors, negative vectors, and protocol-drift tests still pass.
- Update `SUPPLY_CHAIN.md`, `PROVIDERS.md`, or `SECURITY.md` if the dependency changes the threat model.
