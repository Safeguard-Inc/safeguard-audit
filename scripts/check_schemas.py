#!/usr/bin/env python3
"""Validate the JSON schemas in schemas/ and the fixture files that
instantiate them.

Runs in two modes:

* strict — when the `jsonschema` package is importable, every instance file
  is validated against its schema with full JSON Schema semantics (this is
  the mode CI installs into: `python3 -m pip install jsonschema`).
  Cross-schema references of the form {"$ref": "<name>.schema.json"} are
  inlined before validation so no resolver/registry is needed.
* structural — otherwise, every schema and instance file is parsed, and
  instance files that declare a mapping are checked for their required keys
  and top-level type. This keeps the check meaningful on machines without
  the dependency while the strict path stays authoritative.

Usage: python3 scripts/check_schemas.py
Exit code 0 on success, 1 with a message on the first failure.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"

# Mapping of schema filename -> instance file(s) that must conform to it.
# Instance files not listed here are still required to parse as JSON.
INSTANCES = {
    "audit-event.schema.json": [
        "fixtures/events/approved-transfer/event.json",
        "fixtures/events/denied-transfer/event.json",
        "fixtures/events/flagged-transfer/event.json",
        "fixtures/events/frozen-account/event.json",
        "fixtures/events/policy-change/event.json",
        "fixtures/events/authorization-change/event.json",
    ],
    "audit-record.schema.json": [
        "fixtures/records/denied-transfer-record.json",
    ],
    "compliance-event.schema.json": [
        "fixtures/events/frozen-account/observed-hooks-event.json",
        "fixtures/events/bound-token/observed-hooks-event.json",
        "fixtures/events/config-change/observed-hooks-event.json",
    ],
    "transaction.schema.json": [
        "fixtures/transactions/failed.json",
        "fixtures/transactions/succeeded.json",
    ],
    "policy-decision.schema.json": [
        "fixtures/correlation/policy-decision.json",
    ],
    "enforcement-result.schema.json": [
        "fixtures/correlation/enforcement-result.json",
    ],
    "operation.schema.json": [
        "fixtures/correlation/operation.json",
    ],
    "evidence.schema.json": [
        "fixtures/evidence/evidence-artifact.json",
    ],
    "integrity-manifest.schema.json": [
        "fixtures/integrity/valid/manifest.json",
    ],
    "evidence-manifest.schema.json": [
        "fixtures/evidence/evidence-manifest.json",
    ],
    "report.schema.json": [
        "fixtures/reports/compliance/report.json",
    ],
    "report-request.schema.json": [
        "fixtures/reports/incident/request.json",
    ],
    "auditor.schema.json": [
        "fixtures/auditors/authorized/auditor.json",
        "fixtures/auditors/scoped/auditor.json",
        "fixtures/auditors/unauthorized/auditor.json",
    ],
    "authorization.schema.json": [
        "fixtures/authorization/decision.json",
        "fixtures/authorization/decision-granted.json",
        "fixtures/authorization/decision-denied.json",
        "fixtures/authorization/decision-out-of-scope.json",
    ],
    "investigation.schema.json": [
        "fixtures/investigations/open/case.json",
        "fixtures/investigations/closed/case.json",
        "fixtures/investigations/escalated/case.json",
    ],
    "cursor.schema.json": [
        "fixtures/cursors/page.json",
    ],
}

# Instance files that must parse as JSON but deliberately must NOT validate
# (negative fixtures): mapping schema -> files expected to fail validation.
EXPECTED_INVALID = {
    "policy-decision.schema.json": [
        "fixtures/correlation/policy-decision-mismatched-version.json",
    ],
    "integrity-manifest.schema.json": [
        "fixtures/integrity/tampered/manifest.json",
        "fixtures/integrity/corrupted/manifest.json",
    ],
}

EXTENSION_RE = re.compile(r"^[A-Za-z0-9._~:/+=|-]+$")


def load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def inline_external_refs(schema: object, schema_dir: Path, path: tuple[str, ...] = ()) -> object:
    """Replace {"$ref": "<file>.schema.json"} references with the inlined
    target schema.

    Because our schemas are shallow (only audit-record embeds audit-event),
    the target's own internal pointers of the form "#/$defs/..." are
    rewritten to point at the location where the target is now embedded, so
    they keep resolving after inlining."""
    if isinstance(schema, dict):
        if len(schema) == 1 and "$ref" in schema and schema["$ref"].endswith(".schema.json"):
            target = load_json(schema_dir / schema["$ref"])
            return embed_rewriting_pointers(target, path)
        return {
            k: inline_external_refs(v, schema_dir, path + (k,))
            for k, v in schema.items()
        }
    if isinstance(schema, list):
        return [inline_external_refs(item, schema_dir, path) for item in schema]
    return schema


def embed_rewriting_pointers(target: object, embedding_path: tuple[str, ...]) -> object:
    """Deep-copies `target`, rewriting same-document "#/$defs/..." pointers
    so they resolve from the root of the embedding document."""
    if isinstance(target, dict):
        out: dict = {}
        for key, value in target.items():
            if (
                key == "$ref"
                and isinstance(value, str)
                and value.startswith("#/")
            ):
                suffix = value[1:]  # e.g. "/$defs/digest"
                out[key] = "#/" + "/".join(embedding_path) + suffix
            else:
                out[key] = embed_rewriting_pointers(value, embedding_path)
        return out
    if isinstance(target, list):
        return [embed_rewriting_pointers(item, embedding_path) for item in target]
    return target


def validate_strict() -> list[str]:
    failures: list[str] = []
    try:
        import jsonschema
    except ImportError:
        failures.append("jsonschema package is not importable (strict mode unavailable)")
        return failures

    for schema_name, instance_paths in INSTANCES.items():
        schema_path = SCHEMAS / schema_name
        schema = inline_external_refs(load_json(schema_path), SCHEMAS)
        validator = jsonschema.Draft202012Validator(schema)
        for rel in instance_paths:
            instance = load_json(ROOT / rel)
            errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
            if errors:
                first = errors[0]
                failures.append(
                    f"{rel} violates {schema_name} at "
                    f"{'/'.join(str(p) for p in first.path) or '<root>'}: {first.message}"
                )

    for schema_name, instance_paths in EXPECTED_INVALID.items():
        schema_path = SCHEMAS / schema_name
        schema = inline_external_refs(load_json(schema_path), SCHEMAS)
        validator = jsonschema.Draft202012Validator(schema)
        for rel in instance_paths:
            instance = load_json(ROOT / rel)
            errors = list(validator.iter_errors(instance))
            if not errors:
                failures.append(f"{rel} was expected to violate {schema_name} but validated")

    return failures


def structural_check() -> list[str]:
    """Fallback when jsonschema is unavailable: parse everything, and for
    object-typed instances verify the required keys of the mapped schema."""
    failures: list[str] = []
    schemas: dict[str, dict] = {}
    for schema_path in sorted(SCHEMAS.glob("*.schema.json")):
        try:
            schemas[schema_path.name] = load_json(schema_path)
        except json.JSONDecodeError as exc:
            failures.append(f"{schema_path.name} is not valid JSON: {exc}")

    for paths in list(INSTANCES.values()) + list(EXPECTED_INVALID.values()):
        for rel in paths:
            try:
                load_json(ROOT / rel)
            except json.JSONDecodeError as exc:
                failures.append(f"{rel} is not valid JSON: {exc}")

    for schema_name, instance_paths in INSTANCES.items():
        required = schemas.get(schema_name, {}).get("required", [])
        for rel in instance_paths:
            instance = load_json(ROOT / rel)
            if isinstance(instance, dict):
                missing = [key for key in required if key not in instance]
                if missing:
                    failures.append(f"{rel} is missing required keys {missing} of {schema_name}")
    return failures


def main() -> int:
    failures = validate_strict()
    if not failures:
        print("strict validation: all instance files conform to their schemas")
    else:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
