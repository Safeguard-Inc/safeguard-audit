# Security Policy for safeguard-audit

`safeguard-audit` is security- and privacy-sensitive infrastructure. It
stores and serves evidence about compliance-protected token operations.
This policy describes what we protect, how we develop safely, and how to
report a vulnerability.

## What this repository protects

* **Audit integrity** — records are append-only and tamper-evident within
  this system's guarantees (chained/standalone digests detect alteration;
  they are not a claim of blockchain-level immutability).
* **Authorization** — audit data may only be read, exported, decrypted, or
  reported by explicitly authorized, scoped actors; every protected access
  is attributable.
* **Privacy** — protected financial data (balances, amounts, ciphertexts,
  view-key material) must never leak through records, logs, errors,
  reports, exports, fixtures, or metrics.

## Sensitive data

Never commit or log:

* private keys, seed phrases, or signing material,
* view keys or decryption credentials,
* raw confidential balances, private transfer amounts, or decrypted private
  data (unless an explicitly authorized, secure, audited flow requires it),
* authorization credentials,
* real user financial or personal data.

Fixtures, examples, and test vectors are **synthetic only**. Errors and log
lines carry public identifiers (addresses, hashes, codes) and never
protected values.

## Secret handling

* Secrets are never hard-coded or committed; they arrive via environment
  variables or secure secret stores, with configuration files that carry
  `.example` names rather than real values.
* CLI commands never take secrets as arguments (they leak through process
  listings); secure input mechanisms only.
* Decryption is always explicit, authorized, scope-checked, attributable,
  and recorded as an audit-access event.

## Secure development

CI enforces: formatting, compilation, clippy with `-D warnings`, the full
test suite, strict schema validation, and security/privacy test suites.
Contributors must not introduce:

* fake cryptographic verification, fake decryption, fake signatures,
* authorization that always succeeds, integrity verification that always
  returns true, or hard-coded compliance decisions.

Test-only mocks must state that they are not security boundaries.

## Threat model and known limitations

The full threat model lives in `docs/threat-model.md` and the security
overview in `docs/security.md`. Notable assumptions and limits:

* Local record integrity detects tampering; it cannot make a compromised
  storage backend honest on its own. Anchoring to the ledger (an on-chain
  commitment registry) is a separate, optional component.
* The audit layer is not itself the enforcement layer: it records denials
  it is told about (or reconstructs from authoritative metadata). A
  compromised or spoofed event *source* can inject false records unless
  source identity is authenticated out-of-band.
* `safeguard-audit` is developer-preview infrastructure. Confidential
  Tokens on Stellar are a developer preview; do not treat this repository
  as production financial infrastructure merely because its tests pass.

## Reporting a vulnerability

Please do **not** open a public issue for a vulnerability. Report privately
to the Safeguard maintainers so we can coordinate a fix before disclosure.
Include: affected component and version, a description of the issue,
reproduction steps or a minimal proof of concept, and your assessment of
impact. We will acknowledge receipt and keep you informed as we work
through the report.
