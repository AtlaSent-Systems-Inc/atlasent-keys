# CLAUDE.md — atlasent-keys (public trust root)

Public verification material and trust root for AtlaSent. This repo is a
static Nginx host — a five-line Dockerfile copies the repo contents into
`/usr/share/nginx/html` and serves them over HTTP at `keys.atlasent.io`.

> **Rename in progress.** `atlasent-keys` is being renamed
> `atlasent-trust-root`. See `RENAME_PROPOSAL.md` for the phased plan.
> Until the rename completes, the GitHub repo name remains `atlasent-keys`.

## What this repo is (and is NOT)

**Is:**
- A static trust-root host serving public verification keys and JWKS documents
- The canonical source for permit-signing public keys consumed by verifiers and SDKs
- The cosign public key distribution point for supply-chain verification of AtlaSent artifacts

**Is NOT:**
- A Key Management Service (KMS), HSM, or secrets store
- A signing service — it holds no private keys of any kind
- An API server — the container serves flat files only

## Package name / identity

There is no `package.json`. This repo is not an npm package. Its
"package" is the Docker image built from the Dockerfile:

```
FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 80
```

The deployed host is `https://keys.atlasent.io` (future: `https://trust-root.atlasent.io`).

## Assets served

| Path | Description |
|---|---|
| `/cosign.pub` | ECDSA P-256 public key for Sigstore cosign verification of AtlaSent release artifacts |
| `/.well-known/atlasent-trust-root.json` | Canonical index of all trust-root resources with SHA-256 digests |
| `/.well-known/atlasent-verifier-keys.json` | JWKS containing R2 (permit) and R3 (audit) Ed25519 public keys. **Production keys only** — staging keys are deliberately excluded; see [`docs/STAGING_KEY_TRUST_POLICY.md`](docs/STAGING_KEY_TRUST_POLICY.md). |
| `/.well-known/atlasent-sigstore-identities.json` | Accepted Sigstore/Fulcio OIDC identities for AtlaSent release signing |
| `/.well-known/atlasent-revocations.json` | Revoked key IDs and signing identities |
| `docs/permit-signing-keys.json` | JWKS for verifying `AuthorizedTransitionSpec` Ed25519 signatures (pinned reference) |
| `docs/permit-signature-scheme.md` | Full specification for permit signature generation and verification |

Every `.well-known/*.json` is accompanied by a `*.json.bundle` cosign
Sigstore bundle (produced by the `publish-trust-root.yml` CI workflow).

## Tech stack and commands

This repo has no build step and no runtime dependencies. All operational
steps involve Git and the CI workflow.

| Task | Command |
|---|---|
| Validate `.well-known/` JSON against schemas | CI validates on every PR (`publish-trust-root.yml` `validate` job) |
| Sign and publish updated trust-root files | Push to `main` — CI recomputes SHA-256s, cosign-signs, and commits bundles back |
| Manual signing trigger | `workflow_dispatch` on `publish-trust-root.yml` |

The CI workflow (`publish-trust-root.yml`) uses **cosign keyless signing**
via Sigstore: the signing identity is the GitHub Actions OIDC token — no
long-lived private key is required.

## Publish gate (AtlaSent dogfood)

`sign-and-publish` is gated by a real AtlaSent evaluate/permit call
(`AtlaSent publish gate` step, `action: trust_root.publish`) before anything
is recomputed, signed, or pushed back to main. This closed a real gap: the
job previously auto-signed and republished the trust root — the file every
AtlaSent permit/audit signature is verified against — on any push to main
touching `.well-known/**`, with no authorization check at all.

- **Requires an `ATLASENT_API_KEY` secret** (scopes `evaluate:write` +
  `verify:execute`) on the `trust-root-publish` GitHub Environment, minted
  from an org with `trust_root.publish` provisioned (atlasent-api migrations
  `20260848000000` / `20260849000000`). Until that secret is provisioned,
  every run fails at the gate step by design — this is correct fail-closed
  behavior, not a bug, but it means trust-root publishing (including
  legitimate key rotations) is blocked until the key exists.
- **`trust_root.publish` is a Canon specialization of `secret.rotate`
  (CANON-000035)** — see
  `atlasent/contract/canonical-actions/SPECIALIZATIONS.yaml`. `secret.rotate`
  already names "cert-manager / signing pipelines: atlasent evaluate before
  key rollover" as its integration point, and its
  `authorization_pattern.change_windows_required` is `false` — this pipeline
  asserts no change window, because a trust-root publish has no
  application-deployment change window to be inside of. An earlier version
  of this gate used `production.deploy` against an org whose
  `production.deploy` policy was a demo/teaching scenario that could never
  say `allow` — using it to gate a real release pipeline was a category
  error, not a fixable config. `artifact.release` (CANON-000002) was
  considered and rejected for now: it requires the cryptographic
  `requires_verified_actor` primitive plus a `supply_chain` assertion
  issuer, neither of which is wired for any CI caller org-wide yet.
- **Every context field the gate sends is real, not self-asserted.**
  `repository`/`ref`/`sha`/`workflow` are read by `atlasent-action` directly
  from the GitHub Actions environment and cannot be overridden by this
  step's own `context:` input (see `atlasent-action`'s context-override
  fix). `approvals` is read from a live GitHub API call against the merged
  PR's actual review state (`approvals-from: pr-reviews`, the default) —
  never a literal count typed into this file. The gate's `actor` is the
  pipeline's own service/workflow identity (`github-actions[bot]`, matching
  the narrow `allow_actors` this org's policy is scoped to), not the human
  who merged; `github.actor` is carried as `context.triggering_actor` for
  provenance only and is never the authorizing identity. Do not add a
  self-asserted `change_window` or `approvals` field to this step — if a
  real requirement for either ever exists, it needs a trusted source, not a
  YAML literal.
- **No automatic break-glass.** If the AtlaSent API is unreachable,
  publishing blocks — including mid-incident, when the reason you need a
  rotation might be that something is compromised. The override is a
  reviewed PR that temporarily removes the gate step, never a silent
  bypass flag.

## Schemas

JSON Schemas for all `.well-known/` files live in `schemas/trust-root/v1/`.
The CI `validate` job uses `check-jsonschema` to validate every file in
`.well-known/` against its corresponding schema before signing.

## How this relates to atlasent-api Ed25519 permit signing

`atlasent-api` issues signed permit tokens (`pt.v3.*` / `pt.v4.*`) using
Ed25519 keys held securely in the runtime environment (Supabase secrets or
tenant-controlled KMS). The **public** counterparts to those signing keys
are published here in `.well-known/atlasent-verifier-keys.json`:

- **R2 (`permit`)** keys verify permit token signatures from `v1-verify-permit`
- **R3 (`audit`)** keys verify Ed25519 signatures on `evaluation.completed` audit events

Callers and offline verifiers MUST fetch the JWKS from this trust root and
select the key by `kid` to verify permit or audit signatures. Key rotation
follows a 90-day schedule; the JWKS carries both the current key and the
previous key during the overlap window.

The `AuthorizedTransitionSpec` signature scheme (documented in
`docs/permit-signature-scheme.md`) uses the `permit-signing-v1` Ed25519
key from `docs/permit-signing-keys.json` and follows a SHA-256-then-sign
pattern over canonical sorted JSON.

## Key rotation

1. New key pair generated offline (HSM or secure enclave).
2. New public key appended to the JWKS with a new `kid` and `valid_from`.
3. AtlaSent runtime switches to the new signing key at `valid_from`.
4. Previous key's `revoked` flag set to `true` after the overlap window.
5. Every key rotation commit is tagged `keys/YYYY-MM-DD`.

## Branch convention

Use `claude/<topic>` for all work in this repo.

## What does NOT belong here

- Private signing keys — ever
- Secrets of any kind
- A signing service or KMS API
- Tenant-specific data
- Application server code

Those live in:
- `atlasent-api` — per-tenant Ed25519 signing, runtime key management
- `atlasent-control-plane` — tenant secret-manager wiring and rotation tooling
- Customer infrastructure — when BYOK (bring-your-own-key) is configured
