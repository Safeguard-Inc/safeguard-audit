#!/usr/bin/env bash
# Measures line coverage of the Rust workspace with cargo-llvm-cov and fails
# if the overall line coverage drops below the threshold (default 80%).
#
# The overall figure is the TOTAL row's line-cover column of
# `cargo llvm-cov --workspace --summary-only`. CI runs this script as the
# coverage gate; run it locally with `bash scripts/coverage.sh` (optionally
# pass a threshold, e.g. `bash scripts/coverage.sh 90`).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

THRESHOLD="${1:-${COVERAGE_THRESHOLD:-80}}"

# cargo-llvm-cov needs the llvm-tools-preview component on stable.
rustup component add llvm-tools-preview >/dev/null 2>&1 || true

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    echo "==> cargo-llvm-cov not found; installing (one-time, may take a few minutes)..."
    cargo install cargo-llvm-cov --locked
fi

echo "==> Measuring workspace line coverage (threshold: ${THRESHOLD}%)"
OUT="$(cargo llvm-cov --workspace --summary-only 2>/dev/null)"

COVER="$(echo "$OUT" | grep '^TOTAL' | tail -1 | awk '{print $10}' | tr -d '%')"
if [[ -z "$COVER" ]]; then
    echo "error: could not parse the TOTAL row from cargo-llvm-cov output" >&2
    exit 2
fi

echo "$OUT" | tail -1
echo
echo "==> Overall line coverage: ${COVER}% (threshold ${THRESHOLD}%)"
if python3 -c "import sys; sys.exit(0 if float('$COVER') + 1e-9 >= float('$THRESHOLD') else 1)"; then
    echo "==> PASS"
else
    echo "==> FAIL: coverage below ${THRESHOLD}%" >&2
    exit 1
fi