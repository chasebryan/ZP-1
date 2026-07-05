# ZP-1 Validation Ledger

## Current Status

ZP-1 is experimental and unaudited.
Production ML-KEM-1024 / ML-DSA-87 / SLH-DSA providers are not integrated.
The deterministic provider is tests-only and not cryptographic.
Passing tests and fuzzing do not prove cryptographic security.

## Phase 4 Commit

- Commit hash: `7815b5d Add ZP-1 fuzz smoke audit packet and supply chain policy`
- Date checked: 2026-07-05 UTC
- Branch: `main`
- Working tree clean before push: yes
- Pushed to `origin/main`: yes

## Local Validation

These checks passed locally for the Phase 4 commit before this ledger was added:

- `cargo fmt --check`: pass
- `cargo test`: pass
- `cargo test --features test-utils`: pass
- `cargo test --no-default-features`: pass
- `cargo clippy --all-targets --features test-utils -- -D warnings`: pass
- `cargo doc --no-deps`: pass

Local optional tools were not installed in the Phase 4 environment:

- `cargo fuzz build`: not run locally because `cargo-fuzz` was unavailable
- `cargo deny check`: not run locally because `cargo-deny` was unavailable
- `cargo audit`: not run locally because `cargo-audit` was unavailable

## GitHub Actions CI

- Workflow name: `CI`
- Run ID: `28755250322`
- Run URL: `https://github.com/chasebryan/ZP-1/actions/runs/28755250322`
- Commit tested: `7815b5d`
- Result: pass
- Notes: `cargo fmt --check`, `cargo test`, `cargo test --features test-utils`, `cargo test --no-default-features`, `cargo clippy --all-targets --features test-utils -- -D warnings`, and `cargo doc --no-deps` passed on GitHub Actions.

## Fuzz Smoke

- Workflow triggered: yes
- Workflow name: `Fuzz Smoke`
- Run ID: `28755269511`
- Run URL: `https://github.com/chasebryan/ZP-1/actions/runs/28755269511`
- Targets run: `decode_any`, `open_any`, `mutate_valid_vector`
- Duration per target: 30 seconds
- Result: pass
- Findings: none reported by the smoke run

## Supply-Chain Checks

- Workflow triggered: yes
- Workflow name: `Supply Chain`
- Run ID: `28755339850`
- Run URL: `https://github.com/chasebryan/ZP-1/actions/runs/28755339850`
- `cargo-deny` result: pass
- `cargo-audit` result: pass
- Unresolved findings: none reported by the workflow

## Frozen Protocol Bytes

The frozen positive vector was not changed.

## Pre-Provider Gate

- [x] Phase 4 commit pushed
- [x] Required CI green on GitHub
- [x] Positive vector test passes
- [x] Negative vector tests pass
- [x] Protocol drift tests pass
- [x] Exhaustive mutation tests pass
- [x] Fuzz smoke workflow run
- [x] Supply-chain workflow run
- [x] Provider canonicalization requirements documented
- [x] Production providers still absent
- [x] External review still absent
