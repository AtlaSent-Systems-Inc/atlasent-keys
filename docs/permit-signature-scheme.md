# Permit Signature Scheme

This document specifies how `AuthorizedTransitionSpec.signature` is generated and verified using the Ed25519 keys published in this repository.

## Overview

Every `AuthorizedTransitionSpec` (the signed permit issued when an evaluate call returns `authorized_trajectory`) carries a cryptographic signature over the canonical JSON body. The signature proves:

1. **Authenticity** — the permit was issued by AtlaSent, not a third party.
2. **Integrity** — the `from_state`, `to_state`, `authorized_trajectory`, `authority_basis`, and `execution_binding` have not been modified.
3. **Non-repudiation** — a specific key ID (`kid`) identifies which signing key was used, supporting rotation audits.

## Key Types

| Key ID pattern | Algorithm | Use |
|---|---|---|
| `permit-signing-v1` | Ed25519 | Signs `AuthorizedTransitionSpec` bodies |
| `cosign-v1` | ECDSA P-256 | Container image / artifact signatures (see `cosign.pub`) |

## Signing Procedure

### 1. Canonical Body

The payload signed is the UTF-8 JSON encoding of the spec body **without** the `signature` field, with keys sorted alphabetically and no extra whitespace:

```json
{
  "authority_basis": { ... },
  "authorized_trajectory": { ... },
  "execution_binding": { ... },
  "from_state": { ... },
  "id": "ats_01JXYZ...",
  "issued_at": "2026-05-30T14:00:00Z",
  "to_state": { ... },
  "ttl_seconds": 3600
}
```

> Keys are sorted at every nesting level. Arrays preserve their original order.

### 2. Hashing

SHA-256 is computed over the canonical JSON bytes:

```
digest = SHA-256(canonical_json_utf8)
```

### 3. Signing

The digest is signed with Ed25519:

```
signature_bytes = Ed25519Sign(private_key, digest)
```

The resulting `signature` field in the spec is:

```json
"signature": {
  "alg": "ed25519",
  "kid": "permit-signing-v1",
  "sig": "<base64url(signature_bytes)>"
}
```

## Verification Procedure

### 1. Fetch the public key

Public keys are served at the JWKS endpoint:

```
GET https://keys.atlasent.io/.well-known/permit-signing-keys.json
```

Or pinned directly from this repository at `.well-known/permit-signing-keys.json`.

Select the key whose `kid` matches `signature.kid`.

### 2. Reconstruct the canonical body

Strip the `signature` field from the received spec, sort keys, serialize to compact JSON.

### 3. Verify

```typescript
import { createVerify } from 'crypto';

function verifyPermit(spec: AuthorizedTransitionSpec): boolean {
  const { signature, ...body } = spec;
  const canonical = JSON.stringify(sortKeys(body));
  const digest = createHash('sha256').update(canonical, 'utf8').digest();

  // Load Ed25519 public key from JWKS (kid = signature.kid)
  const pubKey = loadPublicKey(signature.kid); // Ed25519 PEM or KeyObject

  const verifier = createVerify('SHA256');
  verifier.update(digest);
  return verifier.verify(pubKey, Buffer.from(signature.sig, 'base64url'));
}
```

Python equivalent using `cryptography`:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import json, hashlib, base64

def verify_permit(spec: dict, public_key_pem: bytes) -> bool:
    sig_field = spec.pop("signature", {})
    canonical = json.dumps(spec, sort_keys=True, separators=(',', ':'))
    digest = hashlib.sha256(canonical.encode('utf-8')).digest()
    sig_bytes = base64.urlsafe_b64decode(sig_field['sig'] + '==')
    pub = serialization.load_pem_public_key(public_key_pem)
    pub.verify(sig_bytes, digest)  # raises InvalidSignature on failure
    return True
```

## Key Rotation

Keys are rotated on a 90-day schedule. The JWKS endpoint always carries the **current** key and the **previous** key (for permits issued within the overlap window).

Rotation events:
1. New key pair generated offline in HSM.
2. New public key appended to `.well-known/permit-signing-keys.json` with a new `kid` and `nbf` (not-before timestamp).
3. AtlaSent runtime switches to new signing key at `nbf`.
4. Previous key removed from JWKS 30 days after rotation.

All rotation commits to this repository are signed with the maintainer's GPG key and tagged `keys/YYYY-MM-DD`.

## Compliance Artifact Signatures

`ComplianceComparisonArtifact` carries two signatures:

| Field | Signed by | Covers |
|---|---|---|
| `spec_signature` | AtlaSent authorization system | `authorized_trajectory` + `from_state` + `to_state` |
| `trace_signature` | AtlaSent execution system | `execution_trace` + `fidelity_score` + `deviation_events` |

Both use the same Ed25519 scheme described above.

## Trust Root

This repository (`atlasent-keys`) is the trust root for all AtlaSent permit signatures:

- `cosign.pub` — container image signing key (Sigstore cosign)
- `.well-known/permit-signing-keys.json` — permit signing JWKS
- `docs/permit-signature-scheme.md` — this document

The repository is protected: direct pushes to `main` are prohibited and all changes require a signed commit from an authorized maintainer.
