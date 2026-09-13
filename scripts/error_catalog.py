#!/usr/bin/env python3
"""Keep the error taxonomy, its stable codes and its documentation in sync.

The audit domain exposes fourteen error enums. Downstream consumers (the CLI,
an ingestion pipeline, an HTTP boundary, and the *other* Safeguard
repositories) branch on them, so a variant is public API: renaming it,
removing it or renumbering its code is a breaking change that must be a
deliberate, reviewed act — never an accident.

This script makes that enforceable. It reads the `pub enum` declarations
straight out of the Rust sources and holds three artifacts to each other:

* the **source** under `crates/`,
* `errors/catalog.json`, the registry of stable symbolic ids, numeric codes
  and one-line summaries, and
* `docs/errors.md`, the human-readable rendering of the catalog.

Modes
-----

``--check`` (default)
    Verify that the catalog and the rendered docs describe exactly the enums
    and variants that exist in source. Reports missing variants (a new error
    was added without being registered), removed variants (a removed error
    left a stale entry behind) and codes that collide or were reused. Exits
    non-zero on any divergence — this is the CI gate.

``--write``
    Regenerate `errors/catalog.json` and `docs/errors.md` from source.
    New variants get the next free code in their enum's block; codes already
    recorded in the catalog are preserved verbatim so numbers never move.
    Retired entries are moved to the catalog's ``retired`` list rather than
    deleted, so a code is never reissued to a different variant.

``--list``
    Print every catalogued code, one per line, for use in shell pipelines.

Usage: python3 scripts/error_catalog.py [--check|--write|--list]
Exit code 0 on success, 1 with a diagnostic on the first failure.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATES = ROOT / "crates"
CATALOG = ROOT / "errors" / "catalog.json"
DOCS = ROOT / "docs" / "errors.md"

# Enums that form the error taxonomy. The names are explicit rather than
# pattern-matched so that adding a taxonomy enum is a visible, reviewable
# change to this list.
TAXONOMY_ENUMS = (
    "AuditError",
    "AuthorizationError",
    "DecryptionError",
    "EventError",
    "EvidenceError",
    "IndexerError",
    "IntegrityError",
    "InvestigationError",
    "NormalizerError",
    "PermissionReason",
    "ReportingError",
    "RpcError",
    "SourceError",
    "StoreError",
)

# Numeric codes are allocated in per-enum blocks of 100 so a code compounds
# to (enum index, variant index) and stays legible in the field. Block 0 is
# reserved: no taxonomy enum may live there.
CODE_BLOCK_SIZE = 100
CODE_BASE = 1000


# --------------------------------------------------------------------------
# Rust source scanning
# --------------------------------------------------------------------------

def strip_rust_noncode(text: str) -> str:
    """Blank out comments and string/char literals, preserving offsets.

    The scanner works on a character grid, so every removed byte is replaced
    by a space to keep line and column information intact. Without this, a
    `// {` in a doc comment would corrupt brace matching and a `}` inside a
    string literal would terminate an enum early.
    """
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        two = text[i : i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif two == "/*":
            depth = 1
            j = i + 2
            while j < n and depth:
                if text[j : j + 2] == "/*":
                    depth += 1
                    j += 2
                elif text[j : j + 2] == "*/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif text[i] == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif text[i] == "'":
            # A char literal is `'x'` or `'\n'`; a lifetime is `'a`. Only
            # blank the literal form so lifetimes in generics survive.
            m = re.match(r"'(?:\\.|[^\\'])'", text[i:])
            if m:
                for k in range(i, i + m.end()):
                    out[k] = " "
                i += m.end()
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


def match_brace(text: str, open_index: int) -> int:
    """Return the index just past the `}` matching the `{` at `open_index`."""
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    raise ValueError("unbalanced braces")


def split_top_level(body: str) -> list[str]:
    """Split an enum body on the commas that sit at brace/paren/angle depth 0."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in body:
        if ch in "{(<[":
            depth += 1
        elif ch in "})>]":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    if "".join(current).strip():
        parts.append("".join(current))
    return parts


VARIANT_RE = re.compile(r"^([A-Z][A-Za-z0-9_]*)\s*(.*)$", re.DOTALL)


def scan_enums() -> dict[str, list[dict]]:
    """Collect every taxonomy enum variant declared under `crates/`.

    Returns a mapping of enum name -> ordered variant records with the
    variant's kind (unit / tuple / struct), its explicit numeric
    discriminant when it declares one, and its Rust module path.
    """
    found: dict[str, list[dict]] = {}
    for path in sorted(CRATES.rglob("*.rs")):
        raw = path.read_text(encoding="utf-8")
        text = strip_rust_noncode(raw)
        rel = path.relative_to(ROOT).as_posix()
        for m in re.finditer(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>{}]*>)?\s*\{", text):
            name = m.group(1)
            if name not in TAXONOMY_ENUMS:
                continue
            open_index = text.index("{", m.end() - 1)
            end = match_brace(text, open_index)
            body = text[open_index + 1 : end - 1]
            variants: list[dict] = []
            for chunk in split_top_level(body):
                decl = chunk.strip()
                if not decl:
                    continue
                # Drop any remaining attributes on the variant.
                decl = re.sub(r"#\s*\[[^\]]*\]", " ", decl).strip()
                vm = VARIANT_RE.match(decl)
                if not vm:
                    continue
                variant, rest = vm.group(1), vm.group(2).strip()
                if rest.startswith("("):
                    kind = "tuple"
                elif rest.startswith("{"):
                    kind = "struct"
                else:
                    kind = "unit"
                disc = None
                dm = re.search(r"=\s*(\d+)", rest)
                if dm:
                    disc = int(dm.group(1))
                variants.append(
                    {
                        "variant": variant,
                        "kind": kind,
                        "discriminant": disc,
                        "module": rel,
                    }
                )
            if variants:
                found[name] = variants
    return found


def enum_body(raw: str, enum: str) -> str:
    """The raw source between an enum's braces, comments intact."""
    m = re.search(r"\benum\s+" + re.escape(enum) + r"\s*(?:<[^>{}]*>)?\s*\{", raw)
    if not m:
        return ""
    open_index = raw.index("{", m.end() - 1)
    try:
        end = match_brace(strip_rust_noncode(raw), open_index)
    except ValueError:
        return ""
    return raw[open_index + 1 : end - 1]


def variant_doc(body: str, variant: str) -> str:
    """The `///` docs attached to a variant, joined into one sentence.

    Attributes such as `#[error("...")]` commonly sit between the doc block
    and the variant name, so they are skipped rather than treated as the end
    of the documentation.
    """
    pattern = re.compile(
        r"((?:^[ \t]*///[^\n]*\n)+)"
        r"(?:[ \t]*\#[ \t]*\[[^\]]*\][ \t]*\n)*"
        r"[ \t]*" + re.escape(variant) + r"\b",
        re.MULTILINE,
    )
    m = pattern.search(body)
    if not m:
        return ""
    lines = [
        ln.strip().lstrip("/").strip()
        for ln in m.group(1).splitlines()
        if ln.strip().lstrip("/").strip()
    ]
    if not lines:
        return ""
    summary = lines[0]
    # Doc comments in this repo often wrap; join until sentence end so the
    # catalog carries a complete thought rather than a truncated clause.
    index = 1
    while index < len(lines) and not summary.endswith((".", "!", "?", ":")):
        summary = f"{summary} {lines[index]}".strip()
        index += 1
    return re.sub(r"\s+", " ", summary).strip()


# --------------------------------------------------------------------------
# Catalog handling
# --------------------------------------------------------------------------

def symbol_for(enum: str, variant: str) -> str:
    """The stable symbolic id, e.g. `SGA-AUDIT-ERROR-INVALID-IDENTIFIER`."""
    enum_part = re.sub(r"(?<!^)(?=[A-Z])", "-", enum).upper()
    variant_part = re.sub(r"(?<!^)(?=[A-Z])", "-", variant).upper()
    return f"SGA-{enum_part}-{variant_part}"


def enum_block(enum: str) -> int:
    """The code block reserved for `enum`, by its position in the taxonomy."""
    return CODE_BASE + TAXONOMY_ENUMS.index(enum) * CODE_BLOCK_SIZE


def load_catalog() -> dict:
    if CATALOG.exists():
        return json.loads(CATALOG.read_text(encoding="utf-8"))
    return {"version": 1, "codes": [], "retired": []}


def build_catalog(scanned: dict[str, list[dict]], previous: dict) -> tuple[dict, list[str]]:
    """Merge freshly scanned variants with the previously recorded codes.

    Existing codes are carried over untouched. Variants whose enum declares an
    explicit Rust discriminant keep that number, because those are already
    public on-chain/ABI surface. New variants are appended in declaration
    order using the next free slot in their enum's block.
    """
    by_key = {(e["enum"], e["variant"]): e for e in previous.get("codes", [])}
    used = {e["code"] for e in previous.get("codes", []) if "code" in e}
    notes: list[str] = []
    codes: list[dict] = []

    order = [n for n in TAXONOMY_ENUMS if n in scanned]
    for enum in order:
        entries = scanned[enum]
        block = enum_block(enum)
        next_free = block + 1
        for entry in entries:
            variant = entry["variant"]
            key = (enum, variant)
            prior = by_key.get(key)
            if prior is not None:
                entry_out = dict(prior)
                entry_out["kind"] = entry["kind"]
                entry_out["module"] = entry["module"]
                codes.append(entry_out)
                continue
            if entry["discriminant"] is not None:
                code = entry["discriminant"]
                if code in used:
                    notes.append(
                        f"{enum}::{variant} declares discriminant {code}, "
                        f"which is already recorded for another variant"
                    )
            else:
                while next_free in used:
                    next_free += 1
                if next_free >= block + CODE_BLOCK_SIZE:
                    raise SystemExit(
                        f"error: {enum} exhausted its code block at {block}; "
                        "raise CODE_BLOCK_SIZE and record the change as a "
                        "catalog migration"
                    )
                code = next_free
                next_free += 1
            used.add(code)
            codes.append(
                {
                    "id": symbol_for(enum, variant),
                    "code": code,
                    "enum": enum,
                    "variant": variant,
                    "kind": entry["kind"],
                    "module": entry["module"],
                    "summary": "",
                }
            )
    return {"version": previous.get("version", 1), "codes": codes,
            "retired": previous.get("retired", [])}, notes


def attach_summaries(catalog: dict) -> None:
    """Fill each entry's summary from the variant's own doc comment."""
    bodies: dict[tuple[str, str], str] = {}
    for entry in catalog["codes"]:
        key = (entry["module"], entry["enum"])
        if key not in bodies:
            raw = (ROOT / entry["module"]).read_text(encoding="utf-8")
            bodies[key] = enum_body(raw, entry["enum"])
        if entry.get("summary"):
            continue
        entry["summary"] = variant_doc(bodies[key], entry["variant"])


def render_docs(catalog: dict) -> str:
    """Render `docs/errors.md` from the catalog."""
    codes = catalog["codes"]
    out: list[str] = []
    out.append("# Error codes\n")
    out.append(
        "Every error the audit domain can produce has a stable symbolic id and a\n"
        "stable numeric code. **Codes are assign-only and are never reused**: a\n"
        "variant that is removed keeps its number in the catalog's `retired`\n"
        "list, so a code observed in a stored record, a log line or a downstream\n"
        "integration never silently changes meaning.\n"
    )
    out.append(
        "The catalog is generated from the Rust sources and verified on every\n"
        "run of CI, so this file cannot drift from the code:\n\n"
        "```bash\n"
        "python3 scripts/error_catalog.py --check   # gate\n"
        "python3 scripts/error_catalog.py --write   # regenerate\n"
        "```\n"
    )
    out.append("## Code table\n")
    by_enum: dict[str, list[dict]] = {}
    for entry in codes:
        by_enum.setdefault(entry["enum"], []).append(entry)
    for enum in TAXONOMY_ENUMS:
        entries = by_enum.get(enum)
        if not entries:
            continue
        module = entries[0]["module"]
        out.append(f"### `{enum}` — `{module}`\n")
        out.append("| Code | Symbol | Variant | Meaning |")
        out.append("| ---: | ------ | ------- | ------- |")
        for entry in entries:
            summary = entry["summary"] or "*(undocumented — add a `///` doc comment)*"
            out.append(
                f"| {entry['code']} | `{entry['id']}` | `{entry['variant']}` | {summary} |"
            )
        out.append("")
    total = len(codes)
    out.append("## Coverage\n")
    out.append(
        f"{total} codes across {len(by_enum)} enums. "
        f"{sum(1 for e in codes if e['summary'])} carry a documented meaning.\n"
    )
    return "\n".join(out).rstrip() + "\n"


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def check(scanned: dict[str, list[dict]], catalog: dict) -> list[str]:
    """Return a list of human-readable divergences (empty when in sync)."""
    problems: list[str] = []
    registered = {(e["enum"], e["variant"]): e for e in catalog.get("codes", [])}
    retired = {(e["enum"], e["variant"]) for e in catalog.get("retired", [])}

    for enum, entries in scanned.items():
        if enum not in TAXONOMY_ENUMS:
            problems.append(f"{enum} is declared in source but missing from TAXONOMY_ENUMS")
            continue
        for entry in entries:
            key = (enum, entry["variant"])
            if key not in registered:
                if key in retired:
                    problems.append(
                        f"{enum}::{entry['variant']} is retired in the catalog but "
                        "exists in source; a retired variant must not be reintroduced"
                    )
                else:
                    problems.append(
                        f"{enum}::{entry['variant']} ({entry['module']}) is not registered; "
                        "run scripts/error_catalog.py --write"
                    )
    for key, entry in registered.items():
        enum, variant = key
        if enum not in scanned:
            problems.append(f"{enum} is in the catalog but no longer declared in source")
        elif variant not in {e["variant"] for e in scanned[enum]}:
            problems.append(
                f"{enum}::{variant} is in the catalog but no longer exists; "
                "move it to `retired` and keep its code"
            )

    seen: dict[int, tuple[str, str]] = {}
    for entry in catalog.get("codes", []):
        code = entry.get("code")
        if code is None:
            problems.append(f"{entry.get('id')} has no numeric code")
            continue
        owner = (entry["enum"], entry["variant"])
        if code in seen and seen[code] != owner:
            problems.append(f"code {code} is assigned to both {seen[code]} and {owner}")
        seen[code] = owner

    if DOCS.exists():
        expected = render_docs(catalog)
        if DOCS.read_text(encoding="utf-8") != expected:
            problems.append("docs/errors.md is stale; run scripts/error_catalog.py --write")
    else:
        problems.append("docs/errors.md is missing; run scripts/error_catalog.py --write")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="verify (default)")
    group.add_argument("--write", action="store_true", help="regenerate catalog and docs")
    group.add_argument("--list", action="store_true", help="print every code")
    args = parser.parse_args()

    scanned = scan_enums()
    if not scanned:
        print("FAIL: no taxonomy enums found under crates/", file=sys.stderr)
        return 1

    catalog = load_catalog()

    if args.list:
        for entry in catalog.get("codes", []):
            print(f"{entry['code']}\t{entry['id']}\t{entry['enum']}::{entry['variant']}")
        return 0

    if args.write:
        catalog, notes = build_catalog(scanned, catalog)
        attach_summaries(catalog)
        CATALOG.parent.mkdir(parents=True, exist_ok=True)
        CATALOG.write_text(
            json.dumps(catalog, indent=2, sort_keys=False) + "\n", encoding="utf-8"
        )
        DOCS.parent.mkdir(parents=True, exist_ok=True)
        DOCS.write_text(render_docs(catalog), encoding="utf-8")
        print(f"wrote {CATALOG.relative_to(ROOT)} ({len(catalog['codes'])} codes)")
        print(f"wrote {DOCS.relative_to(ROOT)}")
        for note in notes:
            print(f"note: {note}", file=sys.stderr)
        return 0

    problems = check(scanned, catalog)
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print(
        f"error catalog: {len(catalog['codes'])} codes across "
        f"{len(scanned)} enums, in sync with source and docs"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
