#!/usr/bin/env bash
# Verifies that the error taxonomy in crates/ matches errors/catalog.json and
# the rendered docs/errors.md. A variant added without a catalog entry, a
# variant removed without being retired, a reused code, or a stale docs page
# all fail this gate. Regenerate with: python3 scripts/error_catalog.py --write
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/error_catalog.py --check
