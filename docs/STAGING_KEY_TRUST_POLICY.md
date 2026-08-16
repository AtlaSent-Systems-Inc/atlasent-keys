# Staging signing keys: intentionally not published here

**Decision (atlasent-keys#21, 2026-08-16): option 2 — intentionally
non-trusted externally.** Staging export-signing keys are not published in
this repo's trust root, and staging exports are not expected to verify
against it. This is a stated policy, not an oversight.

## The finding that raised the question

During the 2026-08-16 staging deploy recovery, runtime staging
(`lwnqpmnxpeyhpxvastku`) was confirmed live to sign exports under:

- `kid`: `4d8b824fb0e827dc`
- Ed25519 JWK `x`: `h0b-yO8AgeLJXt9pF_DMaq9pHdeD0cJFpoNJ0rqIY0Q`

That `kid` is **not** an entry in `.well-known/atlasent-verifier-keys.json`
today, and this document is the decision that it should stay that way — not
a gap to close by adding it.

## Why not just publish it (option 1)

- **This file is the public, customer-facing trust anchor.** Everything in
  it is presented to auditors and customers as "AtlaSent's verification
  material." Staging is a testing environment with weaker operational
  protections than production signing material — mixing a staging key into
  the same trust root customers use to verify *production* audit chains and
  permits widens the blast radius of a staging compromise into the thing
  that's supposed to prove production integrity.
- **No precedent for it.** Every entry in `atlasent-verifier-keys.json`
  today (`v2-audit-2026`, `ak_2026_q3_atlasent_permit`, and the retired/
  revoked entries) is production or historical-production key material.
  Staging has never had an entry here.
- **The schema doesn't model environment today**
  (`schemas/trust-root/v1/atlasent-verifier-keys.schema.json` is
  `additionalProperties: false` with no `environment` field). Adding one
  for a single non-production key is a schema change with downstream
  verifier impact for a use case (proving staging is verifiable) nobody has
  asked for — `trust-root-kid-gate.yml`'s `PERMIT_KID`/`EXPORT_KID` checks
  are repo-level variables representing the **production** active KIDs;
  staging was never in their scope.

Per the issue: **do not rotate or substitute the runtime signing key merely
to make the published set match.** The staging key itself is fine — the
question was only ever "should it be in the public trust root," and the
answer is no.

## What this means in practice

A staging `v1-export-audit` bundle carries `key_id: 4d8b824fb0e827dc` and a
well-formed embedded `public_key_pem` (as of the 2026-08-13 fix — see
`atlasent-internal/runbooks/staging-export-signing-config-gap-2026-08-13.md`).
Run the standard offline procedure
(`atlasent-verify/runbooks/external-audit-verify-proof.md`) against it using
**only this published trust root** as `--keys`, and the expected, correct
outcome is:

- **Without `--require-signatures`:** the trusted-key lookup for
  `4d8b824fb0e827dc` finds nothing in `--keys`; the verifier falls back to
  the bundle's own embedded `public_key_pem`, which is well-formed and
  self-consistent, so the envelope layer reports **`verified_untrusted_key`**
  — the signature is cryptographically valid, but the signer's identity is
  not confirmed against an externally-trusted source. This is the honest,
  correct terminal state — not a defect.
- **With `--require-signatures`:** the same lookup miss is promoted to a
  **failure**, by design — that flag exists specifically so a skipped/
  untrusted signature can never silently read as accepted evidence. Do not
  run staging bundles through `--require-signatures` against this published
  trust root and expect `ACCEPTED`; that would only be correct for a
  production bundle signed under a key this trust root actually publishes.

Verifying staging's own internal self-consistency (its `/v1-signing-key`
endpoint agrees with its own export bundles) is a legitimate and different
check — it proves staging's signing pipeline works, not that staging is
externally verifiable the way production is. Don't conflate the two in a
readiness report; say which one a given run actually demonstrated.

## If staging ever needs to be externally verifiable

That's a real, larger decision (schema change to add environment
classification, a policy on which staging bundles are ever shown to a
customer, and likely a distinct KID namespace so a staging key can never be
mistaken for a production one) — track it as its own issue rather than
reopening this one piecemeal.
