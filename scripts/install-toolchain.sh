#!/usr/bin/env bash
#
# Resolves and installs the Rust toolchain pinned in rust-toolchain.toml.
#
# The pin and the CI install are one fact on purpose. When they are two facts,
# CI can quietly build with a channel nobody pinned — which is exactly how the
# published wasm byte count in docs/performance.md stopped reproducing: the
# recorded 25,687 B was measured on one stable release, and the floating
# `channel = "stable"` later built 27,210 B from unchanged sources.
#
# So this script reads the pin, installs exactly it, and fails when the
# version that resolves is not the pin. Bumping the toolchain is therefore a
# one-line change to rust-toolchain.toml (Dependabot proposes it, and the
# measurement docs must be re-measured in the same change).
#
# Usage:
#   scripts/install-toolchain.sh [--component NAME]... [--target TRIPLE]...
#
# Components and targets declared in rust-toolchain.toml are installed by
# rustup from the file itself; the flags exist for what CI needs but a
# contributor does not — llvm-tools-preview, used only by the coverage job.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$root/rust-toolchain.toml"

if [[ ! -f "$manifest" ]]; then
    echo "error: $manifest not found" >&2
    exit 1
fi

pin="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -n1)"

if [[ -z "$pin" ]]; then
    echo "error: no channel pinned in rust-toolchain.toml" >&2
    exit 1
fi

case "$pin" in
stable | beta | nightly)
    echo "error: rust-toolchain.toml pins the floating channel \"$pin\"." >&2
    echo "       Published measurements only reproduce against an exact release." >&2
    echo "       Pin one — see the pinning note in rust-toolchain.toml." >&2
    exit 1
    ;;
esac

components=()
targets=()
while [[ $# -gt 0 ]]; do
    case "$1" in
    --component)
        components+=("$2")
        shift 2
        ;;
    --target)
        targets+=("$2")
        shift 2
        ;;
    *)
        echo "unknown argument: $1" >&2
        exit 2
        ;;
    esac
done

echo "pinned toolchain: $pin (from rust-toolchain.toml)"
rustup toolchain install "$pin" --profile minimal --no-self-update

if ((${#components[@]} > 0)); then
    rustup component add --toolchain "$pin" "${components[@]}"
fi
if ((${#targets[@]} > 0)); then
    rustup target add --toolchain "$pin" "${targets[@]}"
fi

resolved="$(rustup run "$pin" rustc --version)"
if [[ "$resolved" != rustc\ "$pin"\ * ]]; then
    echo "error: expected 'rustc $pin', rustup resolved: $resolved" >&2
    exit 1
fi
echo "resolved: $resolved"
