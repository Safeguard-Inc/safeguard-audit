## Summary

<!-- What changes and why. One improvement per PR where possible. -->

## Boundaries

<!-- Confirm none of the safeguard-policy (DEFINE) or safeguard-hooks
(ENFORCE) responsibilities were absorbed here. -->

- [ ] No policy definition or enforcement logic was added.
- [ ] No real/confidential data in fixtures, examples, tests, or docs.
- [ ] No fake security primitives (verification/decryption/authorization).

## Tests

- [ ] `cargo test --workspace` passes.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes.
- [ ] `bash scripts/check-schema.sh` passes (schemas touched or not).

## Files touched

<!-- Bullet list of files changed and why. -->

## Security / privacy considerations

<!-- Access control, integrity, redaction, decryption, or logging impact,
or "none". -->
