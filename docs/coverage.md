# Coverage

## Guarantee

Overall line coverage of the Rust workspace is **≥ 80%**, enforced by the
`coverage` CI job (`.github/workflows/ci.yml`) via
[`scripts/coverage.sh`](../scripts/coverage.sh). The gate fails the build if
the TOTAL line-cover of `cargo llvm-cov --workspace --summary-only` drops
below 80%.

Measured on `main` (September 2026) on the pinned toolchain
(`rust-toolchain.toml`, `1.98.1`): **92.6%** line coverage overall — every
crate in the workspace is individually above the threshold, including the
verified Soroban wire model and the event-source invariants tests.

Coverage is a property of the compiler as well as the tests — instrumentation
and inlining both move it — so the figure is only meaningful next to the
release that produced it. Re-measure and update this line in the same change
that bumps the pin (the procedure is documented in `rust-toolchain.toml`).
When re-measuring, run it exactly as CI does:

```bash
bash scripts/install-toolchain.sh --component llvm-tools-preview
bash scripts/coverage.sh
```

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