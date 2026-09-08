# Coverage

## Guarantee

Overall line coverage of the Rust workspace is **≥ 80%**, enforced by the
`coverage` CI job (`.github/workflows/ci.yml`) via
[`scripts/coverage.sh`](../scripts/coverage.sh). The gate fails the build if
the TOTAL line-cover of `cargo llvm-cov --workspace --summary-only` drops
below 80%.

Measured on `main` (September 2026): **92.6%** line coverage overall —
every crate in the workspace is individually above the threshold, including
the verified Soroban wire model and the event-source invariants tests.

## How to run

```bash
rustup component add llvm-tools-preview   # one-time
bash scripts/coverage.sh                  # prints the table and enforces 80%
bash scripts/coverage.sh 90               # raise the bar locally
```

The script installs `cargo-llvm-cov` on first use. CI uses a prebuilt binary
(`taiki-e/install-action`) so the gate stays fast.

## Reading the numbers

Line coverage is the primary metric; the gate keys off the TOTAL row's
line-cover column. Region and branch numbers are informational. Coverage is
measured on the full workspace including the integration-test crates, so a
regression in any parser, source adapter, or correlation path fails CI
before it reaches review.

To see per-module gaps:

```bash
cargo llvm-cov --workspace --summary-only | sort -t'%' -k1
```