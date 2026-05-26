# Rename proposal: `atlasent-keys` → `atlasent-trust-root`

**Status:** Draft · **Companion to:**
[`atlasent/docs/design/TRUST_ROOT_ARCHITECTURE.md`](https://github.com/AtlaSent-Systems-Inc/atlasent/blob/claude/friendly-rubin-bKYOt/docs/design/TRUST_ROOT_ARCHITECTURE.md)

This repo's name implies enterprise key management. The repo is a
five-line nginx static host. The full architecture doc explains the
fix; this file scopes the rename itself.

## Why

- Customers, sales, and auditors read `atlasent-keys` as a KMS.
- The current `README.md` already documents that it isn't one.
- A name that describes the contents (a *trust root* — the public
  material consumers download to verify our signatures) closes
  the gap.

## The new name

**`atlasent-trust-root`.** Selected because:

- accurately describes the artifact served (a published trust root),
- aligns with industry terminology (TUF, Sigstore, X.509 trust roots),
- does not imply private-key custody.

Rejected alternatives:

- `atlasent-pubkeys` — precise but lower in the abstraction stack;
  customers know "trust root," fewer know "pubkey distribution."
- `atlasent-verify` — confuses with the `atlasent verify` CLI.
- `atlasent-trust` — too broad; collides with `console/trust` page.

## What ships at the new path

See TRUST_ROOT_ARCHITECTURE.md §3 for the full layout. Concretely:

```
/
├── .well-known/
│   ├── atlasent-trust-root.json           # canonical index, cosign-signed
│   ├── atlasent-verifier-keys.json        # R2 (permit) + R3 (audit) JWKS
│   ├── atlasent-sigstore-identities.json  # accepted Fulcio identities
│   └── atlasent-revocations.json          # revoked KIDs + identities
├── cosign.pub                             # legacy R1 fallback
├── pack-publisher.pub                     # R4, until cosign migration
└── CHANGELOG
```

Every `.well-known/*.json` is accompanied by `*.json.sig`, a cosign
signature over the file produced by the publish workflow's Sigstore
identity.

## Rename + alias plan

1. **Phase 1 — additive (no rename yet).** Land the new
   `.well-known/` files on `atlasent-keys` `main`. SDKs continue to
   work against `cosign.pub`. Risk: zero. This branch already
   defines the schema; the implementation PR follows.
2. **Phase 2 — publishing workflow.** GHA workflow signs each file
   on push to `main`. Uses the existing
   `gh-token → Fulcio → cosign sign-blob` chain we already use for
   release signing in `atlasent-api`.
3. **Phase 3 — the rename itself.** GitHub repo rename creates an
   automatic 301 redirect from `atlasent-keys` → `atlasent-trust-root`
   that GitHub maintains indefinitely. We additionally:
     - update DNS to point `trust-root.atlasent.io` at the same
       deployment; keep `keys.atlasent.io` 301-redirecting for 12
       months minimum,
     - update the four downstream workflows below.
4. **Phase 4 — cosign.pub deprecation.** Once the SDK release that
   reads the JWKS ships and customer telemetry shows >80%
   adoption, mark `cosign.pub` deprecated in the README. Do not
   remove it; existing pinned verifiers continue to work.

## Downstream `cosign.pub` references (must update in Phase 3)

Grep across the org finds four places that hard-code
`keys.atlasent.io/cosign.pub` or equivalent paths:

| Repo | File | What to change |
|---|---|---|
| `atlasent-api` | `.github/workflows/publish-runtime.yml` | `COSIGN_PUBLIC_KEY` secret continues to work; consider switching to reading from the trust-root |
| `atlasent-api` | `.github/workflows/publish-console-image.yml` | same |
| `atlasent` | `.github/workflows/audit-verify-release.yml` | Update the verify-blob example in the workflow's banner |
| `atlasent-openapi` | `.github/workflows/release-openapi.yml` | Update the verify-blob instruction block in the release body |

None of these are wire-breaking — they are documentation strings
that verifiers paste into their own scripts. Updating them is
low-risk.

## What stays the same

- The Dockerfile (`nginx:alpine`, copy repo into webroot, expose 80).
  No code changes required to serve the new files.
- The TLS-fronted host (`keys.atlasent.io` today, additionally
  `trust-root.atlasent.io` after Phase 3).
- The cosign keyless signing model for release artifacts.
- The `cosign.pub` file itself (kept as legacy fallback).

## What does not belong here — ever

This repo will not contain:

- private signing keys,
- secrets of any kind,
- a signing service,
- a KMS API,
- HSM-backed material,
- tenant-specific data.

Those live in:

- `atlasent-api` (per-tenant Ed25519 signing material in env-var,
  per-tenant secret managers in Supabase / AWS / GCP),
- `atlasent-control-plane` (tenant secret-manager wiring +
  rotation tooling),
- customer infrastructure (when BYOK).

The new name `atlasent-trust-root` should make that boundary
self-documenting.

## Rollback

A repo rename in GitHub is reversible. A 301 redirect can be torn
down by renaming back. The `.well-known/` additions are pure
appends — deleting them restores the prior state. No phase of this
plan creates a forward-only dependency until Phase 4, by which
point the architecture is committed.

## Next steps

1. Sign-off on this proposal + the architecture doc.
2. Open a PR adding the JSON schemas to `atlasent/schemas/`.
3. Open a PR here adding the publish workflow and the four
   `.well-known/` files (seeded with current state, then signed).
4. Coordinate the rename + DNS changes during a low-traffic
   window.
