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
| `atlasent-verifier-keys.json` | populated | Carries R2 (permit) and R3 (audit) Ed25519 keys, each with a `kid`, validity window, and `revoked` flag. Current entries use placeholder KIDs; ops replaces them with tenant KIDs before verifier adoption (see below). |
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

Until step 1–3 is done, the populated entries are placeholder KIDs
(`test-key` / `permit-kid` / `revoked-kid` / `v2-audit-2026`); SDK
verifiers have nothing tenant-specific to look up by KID.

## Schema validation

The publish workflow validates every file against the schemas in
[`schemas/trust-root/v1/`](../schemas/trust-root/v1) in this repo. To
validate locally:

```bash
pipx run check-jsonschema \
  --schemafile schemas/trust-root/v1/atlasent-verifier-keys.schema.json \
  .well-known/atlasent-verifier-keys.json
```
