#!/bin/sh

set -eu

ZP1_FUZZ_SECONDS=${ZP1_FUZZ_SECONDS:-60}

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo is required" >&2
    exit 1
fi

if ! cargo fuzz --version >/dev/null 2>&1; then
    echo "error: cargo-fuzz is not installed" >&2
    echo "install with: cargo install cargo-fuzz" >&2
    exit 1
fi

echo "ZP-1 fuzz smoke: ${ZP1_FUZZ_SECONDS}s per target"

echo "ZP-1 fuzz smoke: decode_any"
cargo fuzz run decode_any -- -max_total_time="$ZP1_FUZZ_SECONDS"

echo "ZP-1 fuzz smoke: open_any"
cargo fuzz run open_any -- -max_total_time="$ZP1_FUZZ_SECONDS"

echo "ZP-1 fuzz smoke: mutate_valid_vector"
cargo fuzz run mutate_valid_vector -- -max_total_time="$ZP1_FUZZ_SECONDS"

echo "ZP-1 fuzz smoke: complete"
