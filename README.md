# atlasent-keys — Public Verification Material

> **What this repo is (and is NOT).**
>
> **Is:** A static HTTP host serving AtlaSent's published public
> verification keys and trust-root documents. The container is a
> five-line Nginx image that copies the repo root into
> `/usr/share/nginx/html`. Assets include `cosign.pub` (used to verify
> signed runtime artifacts) and the `.well-known/` trust-root index,
> verifier-keys JWKS, accepted Sigstore identities, and revocation list.
>
> **Is NOT:** A Key Management Service (KMS), an HSM, a secrets store,
> a private-key manager, or anything that holds, signs with, or controls
> access to private cryptographic material. Despite the repo name,
> there are **no private keys** in this repository and **no key
> management capability** in the running container.
>
> The name `atlasent-keys` is descriptive of its content (public
> verification keys — the kind anyone is expected to download and
> verify against), not its capability. AtlaSent does not hold a
> long-lived private release-signing key: production releases are signed
> with cosign **keyless** signing, where the signing identity is the
> short-lived GitHub Actions OIDC token issued through Sigstore.

## Current assets

- `cosign.pub` — public key for verifying Sigstore-signed runtime artifacts
- `.well-known/atlasent-trust-root.json` — signed canonical index of trust-root resources (each entry names its `sha256` and its `.bundle` signature)
- `.well-known/atlasent-verifier-keys.json` — R2 (permit) + R3 (audit) Ed25519 verifier-keys JWKS
- `.well-known/atlasent-sigstore-identities.json` — accepted Sigstore/Fulcio signing identities
- `.well-known/atlasent-revocations.json` — revoked KIDs and signing identities
- `*.json.bundle` — cosign Sigstore bundles for each `.well-known/*.json`, produced by the publish workflow

## Used for

- supply-chain verification
- runtime artifact verification
- deployment provenance validation
- independent permit and audit-evidence verification

## How it ships

The Dockerfile is intentionally minimal:

```dockerfile
FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 80
```

Building the image produces a container that serves every file at the
repo root over HTTP. Consumers (cosign, CI verifiers, deployment gates)
fetch the public verification material and validate signatures without
requiring access to AtlaSent private infrastructure.

## Where actual key management happens

Production key management is intentionally outside this public repository:

- **Release signing** uses Sigstore + GitHub OIDC keyless signing; no long-lived
  release-signing private key is stored here.
- **Tenant API keys** are issued and rotated by the AtlaSent runtime, not this repo.
- **Customer-managed KMS / HSM** integrations for customer-controlled signing
  remain in the customer's deployment boundary; this repository publishes only
  the public material needed by verifiers.

None of those paths place private keys or tenant credentials in this repository.

## Verification ecosystem

- [`atlasent-verify`](https://github.com/AtlaSent-Systems-Inc/atlasent-verify) — standalone offline audit-chain verifier
- [`atlasent-sdk`](https://github.com/AtlaSent-Systems-Inc/atlasent-sdk) — public client SDKs and wire contract
- [`atlasent-action`](https://github.com/AtlaSent-Systems-Inc/atlasent-action) — execution-time authorization gate for GitHub Actions

If a public verifier needs a trust root, revocation list, or published verifier
key, this repository is the public source. Product-internal runbooks and customer
configuration are deliberately not prerequisites for understanding what is
published here.
