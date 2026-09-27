# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in this repository, **do not open a
public GitHub issue**. Report it privately, either:

- via GitHub Security Advisories — use the **"Report a vulnerability"** button
  on the [Security tab](https://github.com/Atlasent/atlasent-keys/security/advisories/new)
  of this repository, or
- by email to [security@atlasent.io](mailto:security@atlasent.io).

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (if available)
- The commit SHA or published file (and its `issued_at`) where you observed the issue
- Your contact information for follow-up

We acknowledge all reports within **2 business days**.

## Scope

This repository is AtlaSent's **public trust root**: a static host
(`keys.atlasent.io`) serving public verification material only. It holds no
private keys, no secrets, and no signing service.

| In scope | Out of scope |
|----------|--------------|
| Published verification material in `.well-known/` (JWKS, Sigstore identity allowlist, revocations, trust-root index) and its Sigstore bundles | The AtlaSent SaaS service itself (report separately to security@atlasent.io) |
| A published key, identity pattern, or revocation that is wrong, missing, or would let an attacker's signature verify | Social engineering or phishing |
| Identity regexps that are unanchored or otherwise permit prefix/suffix smuggling | Theoretical vulnerabilities without a working PoC |
| The `publish-trust-root.yml` workflow (schema validation, integrity guard, publish gate, keyless signing) | Third-party infrastructure (GitHub, Sigstore/Fulcio/Rekor) |
| `scripts/verify-trust-root-integrity.mjs` and the JSON Schemas in `schemas/trust-root/v1/` | |

**If you believe a private key has been exposed** anywhere (in this repo's
history, in a signed artifact, or elsewhere), report it immediately — key
compromise is handled by the revocation process
(`.well-known/atlasent-revocations.json`), and speed matters more than a
complete write-up.

## Disclosure policy

1. Reporter submits via a GitHub Security Advisory or to security@atlasent.io
2. We acknowledge within 2 business days
3. We assess severity (CVSS score where applicable)
4. We develop and test a fix privately
5. We coordinate a disclosure date (typically 14–90 days depending on severity)
6. We publish the corrected trust-root material and a GitHub Security Advisory
7. Reporter is credited in the advisory unless they request anonymity

We follow [responsible disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html) principles.

## Security contact

- **Email**: security@atlasent.io
- **Response SLA**: 2 business days for acknowledgement
