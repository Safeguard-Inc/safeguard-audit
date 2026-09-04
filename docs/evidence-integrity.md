# Evidence integrity

Integrity is what makes audit history *tamper-evident*: an investigator
must be able to tell whether a record, a record range, or an export was
altered after it was written. The persisted vocabulary — digests,
schemes, outcomes, manifests — lives in `audit-core` (`integrity.rs`);
the computation lives in the `safeguard-audit-integrity` crate
(`crates/integrity`).

## What a record digest covers

A record digest covers the canonical record **without its own integrity
block**: the digest is computed first and the integrity block (which
carries that digest) is attached afterwards, so the digest never hashes
itself. Verification recomputes over the same integrity-cleared
canonical form, which is what makes the comparison meaningful. All
inputs use the domain's canonical serialization, and the only supported
algorithm is SHA-256 (`sha-256`).

## Schemes

### Standalone

`digest(N) = SHA-256(canonical(N))`

Each record is hashed in isolation. Detects alteration of a single
record, but not reordering, deletion, or wholesale replacement.

### Chained

```text
digest(0) = SHA-256(canonical(0))
digest(N) = SHA-256(prev_digest(N-1) || canonical(N))
```

Each record's integrity block carries its predecessor's digest, which is
what makes the chain verifiable. Altering one record breaks its own
digest **and** every successor's linkage; deleting a middle record
breaks its successor; reordering breaks the linkage at the first
misplaced record. Sealing is deterministic: the same ordered records
always seal to identical integrity blocks, so replay reproduces them.

## Honest limits

Chained digests over locally stored records make tampering *detectable*;
they do not create blockchain-level immutability, and the system never
claims otherwise. The docs distinguish three kinds of integrity:

* **on-chain source integrity** — anchored by the ledger itself;
* **local record integrity** — this module: digests and chains over
  stored records;
* **export integrity** — manifests shipped with evidence packages.

## Verification

Verification never trusts stored digests — it recomputes and compares —
and reports machine-readable results:

* `verify_record` → per-record outcome (`verified`,
  `digest-mismatch`, `missing-digest`, `unsupported-algorithm`).
* `verify_chain` → walks records in order, failing fast with a
  `VerificationFailure` naming the record and the class (`digest-mismatch`
  for altered content, `broken-chain` for linkage breaks).
* `verify_manifest_records` → checks every manifest entry against the
  supplied record set (missing records report `record-missing`).
* `verify_manifest_aggregate` → checks the manifest's aggregate over its
  own entries.
* `locate_tampering` / `detect` → search a history for the first
  breaking record.

## Manifests

`manifest.rs` generates `IntegrityManifest`s over record ranges,
evidence packages, or exports:

* one entry per record with a digest **recomputed** from the canonical
  body — never copied from the stored integrity block, so a forged
  stored digest cannot bless altered content;
* an aggregate digest over the canonical entries so the inventory itself
  is tamper-evident;
* a deterministic manifest id derived from generation parameters plus
  the aggregate.

A verifier given a manifest and the covered records can determine
whether anything was altered after generation.

## Tamper scenarios

The test suites cover the scenarios an investigator actually faces:

* a record altered after sealing → `digest-mismatch` naming the record;
* a deleted middle record → `broken-chain` at its successor;
* a deleted head record → `broken-chain` (the new head expects a
  predecessor);
* reordered records → `broken-chain` at the first misplaced record;
* export records altered in transit → caught by `verify_manifest_records`;
* a manifest entry swapped after generation → caught by the aggregate.

The store-integration tests (`crates/integrity/tests/store_integrity.rs`)
exercise these at the persistence boundary — bytes edited between a
store write and read-back — exactly how they would reach a disk-backed
database.
