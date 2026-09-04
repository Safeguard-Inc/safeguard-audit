#!/usr/bin/env bash
# Validates the JSON schemas in schemas/ and every fixture file that
# instantiates them. Uses full JSON Schema semantics when the `jsonschema`
# package is available and falls back to structural checks otherwise (CI
# installs the package so the strict path is the gate).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/check_schemas.py
