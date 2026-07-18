# Audit key ↔ `key_version` reconciliation

**Problem.** The offline verifier (`atlasent-verify`) selects the Ed25519 audit
(R3) key by the `key_version` string stamped on each audit-chain entry. The
running runtime stamps **`key_version: v1`**
(`ATLASENT_LOCAL_SIGNING_KEY_VERSION`). This trust root, however, publishes its
audit key under **`kid: v2-audit-2026`** — and no published `kid` equals `v1`.

So an external auditor working only from this JWKS cannot select the right key:
the verifier looks up `v1`, finds nothing, and **skips every signature** while
still exiting 0 on hash continuity — a false green. (The published
`docs/permit-signing-keys.json` `permit-signing-v1` is worse: it is a **permit
(R2)** key — wrong trust domain, different key material.)

`atlasent-verify --require-signatures` now makes that skip a hard failure rather
than a false pass, so the gap is *safe* — but it is not *closed*: an auditor
still needs a way to select the audit key by the runtime's `key_version`.

## The contract

**The published R3_audit `kid` MUST equal the runtime `key_version`.**

The JWKS schema is `additionalProperties: false` with no separate
`key_version`/alias field (`schemas/trust-root/v1/atlasent-verifier-keys.schema.json`),
and the verifier's PEM loader matches a block's `kid` header against the chain's
`key_version`. So the selector *is* the `kid`. The two strings must be identical.

They are not today: the runtime stamps `v1`; the trust root publishes
`v2-audit-2026`. Reconcile by making them the same string.

## Do NOT rename `v2-audit-2026` → `v1` blind

The `v2-audit-2026` entry's key material (`x`) is **not confirmed** to be the
current prod signer's public half. Renaming a published entry to `v1` would
assert a mapping that may be false and would publish a key an auditor then trusts.

Instead, publish the audit key from the **runtime's own advertised counterpart**.
The runtime derives its advertised public key from the private signer and
**fails closed** if a pinned `ATLASENT_LOCAL_SIGNING_KEY_PUBLIC` disagrees
(`atlasent-api` `_shared/kms/mod.ts`), so the fetched key is provably the signer.

## Procedure (operator, run against the running runtime)

1. **Fetch the signer's public counterpart** (it already carries `kid: <key_version>`):

   ```sh
   BASE=https://<runtime-ref>.supabase.co/functions/v1
   curl -sS -X POST "$BASE/v1-export-audit-stream" \
     -H "Authorization: Bearer $ATLASENT_API_KEY" -H "Content-Type: application/json" \
     -d '{"pubkey":true}' -o runtime-audit-key.pem
   head -2 runtime-audit-key.pem   # -----BEGIN ATLASENT PUBLIC KEY-----  /  kid: v1
   ```

2. **Convert it to a schema-valid R3_audit JWKS entry keyed to that `key_version`**
   and splice it in (updates `issued_at`, validates when `check-jsonschema` is present):

   ```sh
   PEM_FILE=runtime-audit-key.pem WRITE=1 bash scripts/audit-key-from-runtime.sh
   ```

   The script (`scripts/audit-key-from-runtime.sh`) never invents key material —
   it extracts the 32-byte Ed25519 public key from the fetched PEM and emits the
   entry with `kid` = the runtime `key_version`. Print-only (omit `WRITE=1`) to
   review first.

3. **Commit + publish.** Push to `main`; `publish-trust-root.yml` recomputes the
   digests and cosign-signs the updated `.well-known` bundle.

After this, `atlasent-audit-verify --chain <export> --keys <jwks-derived pem>
--require-signatures` selects the audit key by `key_version` and prints
`ACCEPTED`.

## Convergence options

| Option | What | When |
|---|---|---|
| **A — publish a `v1` entry** (recommended for Pilot-01) | Add the fetched signer as a new R3_audit key with `kid: v1`. Fast; no runtime change. | Now — unblocks external offline verification against the live chain. |
| **B — rotate `key_version`** | Rotate the runtime `ATLASENT_LOCAL_SIGNING_KEY_VERSION` to a descriptive value (e.g. `v2-audit-2026`) and confirm the published entry's `x` matches the live signer. | Next scheduled key rotation; heavier (re-stamps new chain entries). |

Option A leaves `v2-audit-2026` in place for any historical bundles that were
actually signed under it; readers filter by `valid_from`/`valid_until`/`revoked`.

## Related hygiene (flagged, not changed here)

The JWKS also carries three placeholder entries that share one `x`
(`uCfAGR92U9gKXqMmGs4MCoaTq-LmzoRe_aiwZE6UcnQ`): `test-key` (revoked),
`revoked-kid` (revoked), and **`permit-kid` (R2_permit, NOT revoked)**. Test
material with a non-revoked entry in a public trust root is worth a deliberate
clean-up (revoke/remove `permit-kid`, or replace with the real permit key). Left
untouched here because altering published/derived key material is an operator
decision with downstream-verifier impact — track separately.
