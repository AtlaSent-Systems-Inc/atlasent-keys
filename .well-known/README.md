# `.well-known/` — AtlaSent trust-root

Served by the nginx static container in this repo. Consumers fetch
from `https://keys.atlasent.io/.well-known/`.

Layout and semantics defined in
[`atlasent/docs/design/TRUST_ROOT_ARCHITECTURE.md`](https://github.com/AtlaSent-Systems-Inc/atlasent/blob/main/docs/design/TRUST_ROOT_ARCHITECTURE.md);
schemas in
[`atlasent/schemas/trust-root/v1/`](https://github.com/AtlaSent-Systems-Inc/atlasent/tree/main/schemas/trust-root/v1).

## Files

| File | Status | Notes |
|---|---|---|
| `atlasent-trust-root.json` | seeded | Index. `resources[].sha256` zeros at seed; the publish workflow recomputes on push. |
| `atlasent-verifier-keys.json` | **structural only** | Empty `keys[]`. Tenant R2/R3 KIDs must be added by ops before verifiers can use this trust-root for permit/audit verification. |
| `atlasent-sigstore-identities.json` | seeded | Four R1 identities matching today's publishing workflows. |
| `atlasent-revocations.json` | seeded | Empty lists. Revocations land here when triggered by the runbook. |

Accompanying `*.sig` and `*.bundle` files are produced by the
publish workflow (cosign keyless via Sigstore) and committed back
to `main` with `[skip ci]`.

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

Until step 1–3 is done, the trust-root is structurally complete
but has nothing meaningful for SDK verifiers to look up by KID.

## Schema validation

The publish workflow validates every file against the schemas in
`atlasent/schemas/trust-root/v1/`. To validate locally:

```bash
pipx run check-jsonschema \
  --schemafile \
    https://raw.githubusercontent.com/AtlaSent-Systems-Inc/atlasent/main/schemas/trust-root/v1/atlasent-verifier-keys.schema.json \
  .well-known/atlasent-verifier-keys.json
```
