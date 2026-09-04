# Evidence

Evidence turns audit records into artifacts that can be exported,
investigated, and independently checked. An auditor who needs to prove
what happened — to a regulator, a counterparty, or a court — seals an
evidence package over the records that support the claim. The package
carries its own integrity, so the proof survives leaving the system.

## Where the pieces live

| Concern | Location |
|---|---|
| Domain models (`EvidenceArtifact`, `EvidenceProvenance`, `EvidenceKind`) | `audit-core` — `evidence.rs` |
| Integrity vocabulary (`IntegrityDigest`, `IntegrityManifest`, `ManifestEntry`) | `audit-core` — `integrity.rs` |
| Generation event (`EvidenceLifecycle`) | `audit-events` — `evidence.rs` |
| Services (`EvidenceBuilder`, `EvidencePackage`, `EvidenceManifest`, `verify_package*`) | `evidence` crate (`crates/evidence`) |
| Hashing/manifest primitives (`hash_bytes`, `build_manifest`, `verify_*`) | `integrity` crate (`crates/integrity`) |

The split mirrors the rest of the repository: `audit-core` defines *what
an artifact is*; the `evidence` crate runs the *machinery*; the
`integrity` crate supplies the primitives; `audit-events` defines the
generation event the trail records.

## What an evidence package is

A package is two things bound together:

* an **artifact** — `evidence_id`, `kind`, `provenance` (which records
  and events support it, which parser and generator versions produced
  it), `generated_at`, `generated_by`, a content digest, and the
  manifest reference;
* an **integrity manifest** — one entry per source record with a digest
  *recomputed from the record body* at generation time (never copied
  from a stored integrity block, so a forged stored digest cannot bless
  altered content), an aggregate digest over the entries, and the
  artifact reference, parser version, and network that make the manifest
  self-describing.

Construction validates the cross-links: the manifest must certify the
artifact it ships with, and the artifact's manifest slot must name that
manifest. A mismatched pair cannot be assembled accidentally.

## The build pipeline

```text
source records ──► authorize ──► fetch ──► integrity gate ──► sort ──► seal
     (audit store)    │              │          │                      │
                      │              └ missing? refuse                ├─► artifact + content digest
                      └ denied? refuse             └ altered? refuse  └─► artifact-linked manifest
                                                                             (per-record + aggregate)
                                              │
                                              ▼
                                    evidence-generated event
                                    recorded into the audit store
```

Every step is deliberate:

1. **Authorize.** Generating evidence requires the `generate-evidence`
   action at the service's network scope (`SeniorAuditor` and above by
   default). A denial is an error, never a silent pass.
2. **Prove the sources exist.** Every named record must be in the audit
   store.
3. **Prove the sources are intact.** The pipeline seals history at
   *verification* time, so stored records may legitimately carry no
   integrity block. A record that does carry one must still match its
   body — a mismatch means it was altered after sealing, and evidence is
   never built over it. Unsealed records are accepted; their digest is
   recomputed and captured in the manifest, so later alteration is
   detectable through the manifest either way.
4. **Order deterministically.** The record set is sorted by record id,
   so the same set always yields the same artifact and manifest,
   whatever order the ids were supplied in. The artifact id itself
   derives from network + kind + source set.
5. **Seal.** The content digest covers the artifact's canonical bytes
   with its integrity slots cleared (the digest and manifest are
   attached *after* content hashing, so they can never be part of the
   content they certify). The manifest ledger range is filled from the
   source records when every one names a ledger.
6. **Record.** The generation lands in the audit store as a derived
   `evidence-generated` event carrying the artifact id, kind, record
   count, manifest reference, and digest — the trail attests to its own
   evidence production.

## Verification at two depths

* **Structure** (`verify_package_structure`) — no store access: recompute
  the artifact's content digest and the manifest's aggregate over its
  entries. This is what an *exported* package can be checked against
  without the generating system.
* **Records** (`verify_package`) — with store access, additionally fetch
  every covered record and recompute each per-record digest, so the
  manifest is trusted to certify the records it names.

Both return machine-readable outcomes (per-record `VerificationOutcome`s
and an aggregate `IntegrityStatus`), not prose, so automation can react
to tampering.

## Honest limits

The artifact digest and manifest make alteration *detectable*; they do
not make the artifact immutable. Nothing here replaces on-chain
anchoring — the Soroban ledger is the ultimate source of truth for the
events these records describe. The repository distinguishes local record
integrity, export integrity (manifests shipped with packages), and
on-chain source integrity, and never claims otherwise.

## Boundaries

* The evidence crate generates and verifies evidence. It does not decide
  policy, enforce transfers, or grant access — authorization decisions
  come from the authorization crate.
* Artifacts reference records by id; protected record content is never
  copied into the artifact. Privacy remains the store's concern, and the
  records' own classification drives redaction downstream.