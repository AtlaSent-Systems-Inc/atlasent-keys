# `.well-known/` — AtlaSent trust-root

Served by the nginx static container in this repo. Consumers fetch
from `https://keys.atlasent.io/.well-known/`.

Layout and semantics defined in
[`atlasent/docs/design/TRUST_ROOT_ARCHITECTURE.md`](https://github.com/AtlaSent-Systems-Inc/atlasent/blob/main/docs/design/TRUST_ROOT_ARCHITECTURE.md);
schemas in [`schemas/trust-root/v1/`](../schemas/trust-root/v1) in this repo.

## Files

| File | Status | Notes |
|---|---|---|
| `atlasent-trust-root.json` | seeded | Index. `resources[].sha256` and `resources[].sig` point at each resource's bytes and its `.bundle`; the publish workflow recomputes the digests on push. |
| `atlasent-verifier-keys.json` | populated | Carries R2 (permit) and R3 (audit) Ed25519 keys, each with a `kid`, validity window, and `revoked` flag. **`v1` (`role: R3_audit`, `revoked: false`) is the production audit-entry signer's public half, verified 7/7 against production `audit_events` signatures on 2026-09-12 — its `kid` equals the runtime `key_version`, so `atlasent-audit-verify` selects it directly.** `test-key` / `permit-kid` / `revoked-kid` / `v2-audit-2026` are placeholder/historical KIDs, all revoked (`v2-audit-2026` revoked 2026-09-12: never the production signer — see `docs/AUDIT_KEY_VERSION_RECONCILIATION.md`); `ak_2026_q3_atlasent_permit` (`role: R2_permit`, `tenant: "atlasent"`, `revoked: false`) is a real tenant-scoped key onboarded per the "What ops must do" steps below. **`ak_2026_q3_atlasent_audit` (`role: R3_audit`, `tenant: "atlasent"`, `revoked: false`, added 2026-09-14) is the export-envelope signer (`EXPORT_KID`), verified against a live production export before publication — see the 2026-09-14 note below.** |
| `atlasent-sigstore-identities.json` | seeded | R1 identities matching today's publishing workflows. |
| `atlasent-revocations.json` | populated | Lists revoked KIDs (`revoked_keys`) and revoked signing identities (`revoked_identities`). New revocations land here when triggered by the runbook. |

Accompanying `*.json.bundle` files are the cosign Sigstore bundles
(signature + certificate + Rekor entry) produced by the publish
workflow (cosign keyless via Sigstore) and committed back to `main`
with `[skip ci]`. There are no detached `*.sig` files — the `sig`
pointer in the index names the `.bundle`.

## What ops must do before verifier adoption

1. For each active tenant on `atlasent-api`, read `PERMIT_KID` and
   the matching Ed25519 public PEM from the tenant's secret
   manager.
2. Add an entry to `atlasent-verifier-keys.json` with
   `role: R2_permit`, `tenant: <shortcode>`, the base64url-encoded
   public key in `x`, and a `valid_from` timestamp.
3. After atlasent-api#947 ships, repeat for `EXPORT_KID` with
   `role: R3_audit`.
4. Open a PR with the additions. The publish workflow validates,
   signs, and commits the resulting signatures back to `main`.

**Corrected 2026-09-08 — this section was stale.** Steps 1–2 (R2_permit,
tenant `atlasent`) are done: `ak_2026_q3_atlasent_permit` is a real,
active, non-revoked tenant-scoped key (`replaced_by: null`), and it
replaced the placeholder `permit-kid` (now `revoked: true`). Step 3
(R3_audit, gated on atlasent-api#947) is still pending — `v2-audit-2026`
remains the only active R3_audit key and has no `tenant` set. `test-key`
and `revoked-kid` are historical/revoked placeholders. So SDK verifiers
now DO have a real tenant-specific R2_permit key to look up by KID for
tenant `atlasent`; only R3_audit onboarding remains placeholder-only.

**Corrected again 2026-09-12.** The R3_audit half of the paragraph above
is superseded: `v2-audit-2026` was never the production signer and is now
revoked; the active R3_audit key is `v1`, verified against production
signatures (see the table above). `v1` is the **per-row** `audit_events`
signer. The export-**envelope** key id (`EXPORT_KID`, atlasent-api#947
step 3) has still never been configured on the runtime project — every
production export to date carries an empty `key_id` — so that step
remains open, but it is no longer represented by placeholder material
here.

**Published 2026-09-15 after independent ratification.** PR #33 placed
the public-key entry on `main`, but `publish-trust-root` run 34801144971
correctly stopped at the AtlaSent gate because the merged PR had zero approving
reviews (`Authorization DENIED: missing QA approval`). PR #35 then received
an approving review from `jf-atlasent` and merged without changing key
material. The governed publication succeeded, and bot commit
`01968e9cf13c329d7f1133403efe030b6b08beff` refreshed the trust-root index
and Sigstore bundles for the exact ratified material.

`ak_2026_q3_atlasent_audit` (`role: R3_audit`, `tenant:
"atlasent"`, `revoked: false`) is the public half of the runtime export
signing key set on `kttccumlnmdtupgbyfue` on 2026-09-13 (`EXPORT_KID` =
`ATLASENT_EXPORT_SIGNING_KEY_ID` = `ak_2026_q3_atlasent_audit`; SPKI
fingerprint `1903850d6a201501`, which is also the `kid` `v1-signing-key`
derives and advertises). The cryptographic pre-publication check was satisfied by a live
verification: a founder-run `atlasent-api` `scripts/export-kid-preflight.sh
--require-accepted` on 2026-09-14 verified a fresh production export's
outer signature against this exact material (`atlasent-audit-verify`
v0.1.0, ACCEPTED, `key_id=ak_2026_q3_atlasent_audit`). It signs the
**outer envelope** of `v1-export-audit` exports; `v1` remains the per-row
`audit_events` signer — two keys, two roles, both `R3_audit`. Exports
produced before 2026-09-13 21:51Z verify only under `permit-signing-v1`
(`docs/permit-signing-keys.json`); how to label that is a pending founder
decision recorded in `atlasent-internal`.

## Schema validation

The publish workflow validates every file against the schemas in
[`schemas/trust-root/v1/`](../schemas/trust-root/v1) in this repo. To
validate locally:

```bash
pipx run check-jsonschema \
  --schemafile schemas/trust-root/v1/atlasent-verifier-keys.schema.json \
  .well-known/atlasent-verifier-keys.json
```
