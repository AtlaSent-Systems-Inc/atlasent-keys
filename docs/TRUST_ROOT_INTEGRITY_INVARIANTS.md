# Trust-root integrity invariants

`scripts/verify-trust-root-integrity.mjs` is a deterministic, dependency-free
(Node built-ins only) validator that runs in CI (`publish-trust-root.yml`'s
`validate` job, both on PRs and before every publish) alongside the existing
`check-jsonschema` step. Schema validation checks *shape*; this script checks
*meaning*. It is read-only — it never writes to `.well-known/` or any other
published file.

Run it locally with `node scripts/verify-trust-root-integrity.mjs` (add
`--json` for machine-readable output). Exit code `0` = pass, `1` = at least
one finding, `2` = usage/environment error.

## What it enforces (fails CI)

**Structural**
- Every `kid` is unique within a file (independent of JSON Schema's
  whole-object `uniqueItems`, which would not catch two entries sharing a
  `kid` but differing elsewhere).
- Required algorithm/type metadata is present, redundantly re-checked at this
  layer so the invariant holds even if schema validation is skipped.
- `role` / status-shaped fields are drawn only from the registered
  enumerations.
- `replaced_by` references an actually-published `kid`.

**Cryptographic-material validity**
- `x` (and `y`, for EC) decode as well-formed base64url to the correct byte
  length for the declared `kty`/`crv`, and the key material is fed through
  Node's `crypto.createPublicKey` (JWK import) so a malformed encoding or an
  off-curve EC point fails loudly rather than being silently accepted.
  Failure here is always a hard error — never a skip.
- `cosign.pub` parses as a real P-256 public key.

**Cryptographic-material reuse (duplicate classification)**
Every cluster of entries sharing identical `x` (public-key material) is
classified:
- **≥2 non-revoked members** → `DANGEROUS_DUPLICATE_ACTIVE_KEY` (FAIL). Two
  independently-active KIDs must never share a private key.
- **1 non-revoked member + ≥1 revoked/test member** →
  `DANGEROUS_DUPLICATE_ACTIVE_REUSES_REVOKED` (FAIL). An active signer must
  not share material with retired or test material.
- **All members revoked, and the exact KID set matches an entry in
  [`docs/known-key-material-aliases.json`](known-key-material-aliases.json)**
  → `DOCUMENTED_HISTORICAL_ALIAS` (INFO, passes). Today this covers exactly
  the three pre-tenant-adoption placeholder KIDs (`test-key`, `permit-kid`,
  `revoked-kid`) documented in `.well-known/README.md`.
- **All members revoked, not on the allowlist** →
  `UNDOCUMENTED_DUPLICATE_MATERIAL` (WARN). Add a reviewed entry to the
  allowlist (or rotate one of them) rather than let it pass silently
  unexplained.

**Lifecycle**
- Every `valid_from` / `valid_until` (and `nbf`/`issued_at`/`revoked_at`
  where present) parses as a real timestamp, and `valid_from < valid_until`
  wherever both are present (`IMPOSSIBLE_VALIDITY_WINDOW`).
- A revocation's `revoked_at` never precedes the key's own `valid_from`.
- Each required signing role (`R2_permit`, `R3_audit` — the two the runtime
  depends on per this repo's `CLAUDE.md`) has at least one currently-active
  (`revoked: false`, `now` within `[valid_from, valid_until]`) entry
  (`NO_ACTIVE_KEY_FOR_ROLE`).
- Sigstore identity regexps are anchored (`^...$`) per the schema's own
  documented requirement, preventing prefix/suffix smuggling.

**Cross-file consistency (`atlasent-verifier-keys.json` ↔
`atlasent-revocations.json`)**
- Every KID in `atlasent-revocations.json`'s `revoked_keys` must exist in
  `atlasent-verifier-keys.json` and be marked `revoked: true` there
  (`REVOCATION_LEDGER_ORPHAN` / `REVOCATION_LEDGER_STATUS_MISMATCH`, FAIL).
- The reverse direction — a KID marked `revoked: true` in
  `atlasent-verifier-keys.json` with no matching ledger entry — is a WARNING
  (`REVOCATION_LEDGER_INCOMPLETE`), not a hard failure: completing the ledger
  is a same-status bookkeeping action for a human, and (as of 2026-08-22) one
  such pre-existing gap exists in the published data — see "Known pre-existing
  finding" below.

**Staging-key leak prevention**
- Every `kid`/`x` pair recorded in
  [`docs/staging-key-denylist.json`](staging-key-denylist.json) (a
  machine-readable mirror of
  [`docs/STAGING_KEY_TRUST_POLICY.md`](STAGING_KEY_TRUST_POLICY.md)'s
  decision) must never appear in any published file
  (`STAGING_KEY_PUBLISHED`, FAIL).

**Repository hygiene (targeted, not a generic secret scanner — GitHub's
built-in secret scanning already covers the generic case)**
Scans every `git`-tracked text file for:
- A PEM private-key header (`-----BEGIN ... PRIVATE KEY-----`) in any form.
- A private-key-shaped JSON property anywhere in a tracked `.json` file:
  `d` (the RFC 8037/7518 private scalar), `private_key`, `secret_key`, and
  common casing variants.

Both are hard failures with no silent-skip path.

## Known pre-existing finding (as of 2026-08-22, not fixed by this change)

`permit-kid` in `.well-known/atlasent-verifier-keys.json` is `revoked: true`
but has no matching entry in `.well-known/atlasent-revocations.json`'s
`revoked_keys`. This is a real cross-file ledger gap — see
[`AUDIT_KEY_VERSION_RECONCILIATION.md`](AUDIT_KEY_VERSION_RECONCILIATION.md)'s
"Related hygiene" section, which flagged the underlying key-material sharing
issue earlier and left it untouched deliberately ("altering published/derived
key material is an operator decision"). It is **not** a dangerous condition:
`permit-kid`'s key material is shared only with two other already-revoked
placeholder entries (`test-key`, `revoked-kid`), and no active key anywhere
shares material with it. It surfaces here as `REVOCATION_LEDGER_INCOMPLETE`
(WARN, non-blocking) rather than a failure, precisely so this validator does
not need to alter real trust-root data to go green. The fix — adding a
`revoked_keys` entry for `permit-kid` to the ledger — is a same-status
bookkeeping change with no key-material or trust impact, left for a human to
make deliberately in its own small PR.

## Design notes

- The two allowlists (`known-key-material-aliases.json`,
  `staging-key-denylist.json`) are small, human-reviewed, and exist
  specifically so "intentional" and "accidental" duplicate/leaked material
  are never conflated by a silent pass. Add to them only after confirming the
  underlying fact — never to make a validator failure disappear.
- The validator is exported (`runValidator()`) as well as runnable as a CLI,
  so it can be mutation-tested against scratch fixtures without ever writing
  to the real `.well-known/` files.
