# atlasent-keys — Public Verification Material

> **What this repo is (and is NOT).**
>
> **Is:** A static HTTP host serving AtlaSent's published public
> verification keys. The container is a five-line Nginx image that copies
> the repo root into `/usr/share/nginx/html`. The current asset is
> `cosign.pub`, used to verify signed runtime artifacts.
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
> long-lived private signing key: production releases are signed with
> cosign **keyless** signing, where the signing identity is the
> short-lived GitHub Actions OIDC token issued through Sigstore.

## Current assets

- `cosign.pub` — public key for verifying Sigstore-signed runtime artifacts

## Used for

- supply-chain verification
- runtime artifact verification
- deployment provenance validation

## How it ships

The Dockerfile is intentionally minimal:

```dockerfile
FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 80
```

Building the image produces a container that serves every file at the
repo root over HTTP. Consumers (cosign, CI verifiers, deployment gates)
fetch `cosign.pub` and use it to verify Sigstore-signed artifacts.

## Where actual key management happens

Production AtlaSent key management lives elsewhere:

- **Cosign keyless signing** (via Sigstore + OIDC) — no long-lived
  private signing key in any AtlaSent system; signing identity is the
  GitHub Actions OIDC token.
- **Tenant API keys** — issued and rotated through `atlasent-api`, not
  this repo.
- **Customer-side KMS / HSM** integration for evidence-export signing
  — documented in
  [`atlasent-gxp-starter/docs/production-signing.md`](https://github.com/AtlaSent-Systems-Inc/atlasent-gxp-starter/blob/main/docs/production-signing.md).

None of those touch this repository.

## See also

- [Versioning doctrine](https://github.com/AtlaSent-Systems-Inc/atlasent/blob/main/VERSIONING_DOCTRINE.md)
- [V1 pilot scope](https://github.com/AtlaSent-Systems-Inc/atlasent-internal/blob/main/pilot-readiness/v1-pilot-scope.md)
