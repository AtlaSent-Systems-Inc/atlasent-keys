#!/usr/bin/env bash
# audit-key-from-runtime.sh — turn the RUNTIME's advertised audit signer public
# key into a schema-valid R3_audit JWKS entry whose `kid` EQUALS the runtime
# `key_version` stamped on the audit chain.
#
# WHY: the offline verifier (atlasent-verify) selects the audit key by the
# chain's `key_version`. The runtime stamps `key_version: v1`, but this trust
# root's audit key is published under `kid: v2-audit-2026` — no published kid
# equals `v1`, so an external auditor working only from this JWKS cannot select
# the right key and every signature is skipped. The fix is to publish the audit
# key under a `kid` equal to the runtime `key_version`. See
# docs/AUDIT_KEY_VERSION_RECONCILIATION.md.
#
# This script does NOT invent key material. It reads the ACTUAL signer
# counterpart the runtime advertises (derived from its private signer, fail-closed
# on mismatch), so the published entry is provably the prod signer's public half.
#
# ── Fetch the input first (operator, against the running runtime) ──────────────
#   curl -sS -X POST "$BASE/v1-export-audit-stream" \
#     -H "Authorization: Bearer $ATLASENT_API_KEY" -H "Content-Type: application/json" \
#     -d '{"pubkey":true}' -o runtime-audit-key.pem
#   # -> -----BEGIN ATLASENT PUBLIC KEY-----  with a `kid: <key_version>` header
#
# ── Usage ──────────────────────────────────────────────────────────────────────
#   From a fetched PEM (kid read from the PEM header unless KID is set):
#     PEM_FILE=runtime-audit-key.pem bash scripts/audit-key-from-runtime.sh
#
#   From raw material (base64url 32-byte Ed25519 public key + explicit kid):
#     X_B64URL=<base64url> KID=v1 bash scripts/audit-key-from-runtime.sh
#
#   Append the entry into .well-known/atlasent-verifier-keys.json (updates
#   issued_at; validates with check-jsonschema when available):
#     PEM_FILE=runtime-audit-key.pem WRITE=1 bash scripts/audit-key-from-runtime.sh
#
# Optional env:
#   KID          override the kid (default: the PEM `kid:` header). MUST equal the
#                runtime ATLASENT_LOCAL_SIGNING_KEY_VERSION for verifiers to select it.
#   VALID_FROM   RFC 3339 (default: now, UTC)
#   VALID_UNTIL  RFC 3339 (default: VALID_FROM + ~13 months)
#   WELL_KNOWN_DIR  path to .well-known (default: .well-known)
#   WRITE=1      splice into the JWKS in place (default: print entry to stdout)
#
# Requires: jq, openssl (PEM path only). Optional: check-jsonschema.
set -euo pipefail

PEM_FILE="${PEM_FILE:-}"
X_B64URL="${X_B64URL:-}"
KID="${KID:-}"
WELL_KNOWN_DIR="${WELL_KNOWN_DIR:-.well-known}"
TARGET="${WELL_KNOWN_DIR}/atlasent-verifier-keys.json"
WRITE="${WRITE:-}"

command -v jq >/dev/null || { echo "ERROR: jq is required" >&2; exit 1; }

# ── derive x (base64url 32-byte Ed25519 pubkey) + kid ──────────────────────────
if [ -n "$PEM_FILE" ]; then
  [ -f "$PEM_FILE" ] || { echo "ERROR: PEM_FILE '$PEM_FILE' not found" >&2; exit 1; }
  command -v openssl >/dev/null || { echo "ERROR: openssl required for the PEM path" >&2; exit 1; }
  # The runtime uses a custom '-----BEGIN ATLASENT PUBLIC KEY-----' label around a
  # standard SPKI DER body; normalise the label so openssl accepts it.
  norm="$(sed -e 's/ATLASENT PUBLIC KEY/PUBLIC KEY/g' "$PEM_FILE")"
  X_B64URL="$(printf '%s\n' "$norm" | openssl pkey -pubin -inform PEM -outform DER 2>/dev/null \
    | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=')"
  [ -n "$X_B64URL" ] || { echo "ERROR: could not extract an Ed25519 public key from $PEM_FILE" >&2; exit 1; }
  if [ -z "$KID" ]; then
    KID="$(grep -i '^kid:' "$PEM_FILE" | head -1 | sed 's/^kid:[[:space:]]*//I' | tr -d '\r')"
  fi
  [ -n "$KID" ] || { echo "ERROR: no kid in PEM header; set KID=<runtime key_version>" >&2; exit 1; }
elif [ -n "$X_B64URL" ]; then
  [ -n "$KID" ] || { echo "ERROR: KID is required when providing X_B64URL" >&2; exit 1; }
else
  echo "ERROR: provide PEM_FILE=<file> or X_B64URL=<base64url> + KID=<key_version>" >&2
  exit 1
fi

# Ed25519 32-byte key → base64url (no padding) is 43 chars.
case "$X_B64URL" in *[!A-Za-z0-9_-]*) echo "ERROR: x is not base64url: $X_B64URL" >&2; exit 1;; esac
[ "${#X_B64URL}" -ge 43 ] || echo "WARN: x is ${#X_B64URL} chars; an Ed25519 pubkey base64url is normally 43" >&2

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VALID_FROM="${VALID_FROM:-$now}"
# default ~13 months out (covers the 90-day rotation + overlap with headroom)
VALID_UNTIL="${VALID_UNTIL:-$(date -u -d "${VALID_FROM} +396 days" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)}"

ENTRY="$(jq -nc \
  --arg kid "$KID" --arg x "$X_B64URL" --arg vf "$VALID_FROM" --arg vu "$VALID_UNTIL" \
  '{kid:$kid, role:"R3_audit", kty:"OKP", crv:"Ed25519", alg:"EdDSA",
    x:$x, valid_from:$vf, valid_until:$vu, replaced_by:null, revoked:false, tenant:null}')"

echo "# R3_audit JWKS entry (kid MUST equal the runtime key_version):" >&2
echo "$ENTRY" | jq .

if [ -z "$WRITE" ]; then
  echo >&2
  echo "# Not written. To splice into $TARGET, re-run with WRITE=1, or add manually with:" >&2
  echo "#   jq --argjson e '$ENTRY' '.keys += [\$e] | .issued_at=\"$now\"' $TARGET" >&2
  exit 0
fi

[ -f "$TARGET" ] || { echo "ERROR: $TARGET not found (run from repo root)" >&2; exit 1; }
if jq -e --arg kid "$KID" '.keys[] | select(.kid==$kid)' "$TARGET" >/dev/null 2>&1; then
  echo "ERROR: a key with kid='$KID' already exists in $TARGET — rotate deliberately, do not duplicate." >&2
  echo "       See docs/AUDIT_KEY_VERSION_RECONCILIATION.md (rotation is an operator decision)." >&2
  exit 1
fi

tmp="$(mktemp)"
jq --argjson e "$ENTRY" --arg now "$now" '.keys += [$e] | .issued_at=$now' "$TARGET" > "$tmp"
mv "$tmp" "$TARGET"
echo "Wrote R3_audit key kid='$KID' into $TARGET (issued_at=$now)." >&2

if command -v check-jsonschema >/dev/null 2>&1; then
  check-jsonschema --schemafile schemas/trust-root/v1/atlasent-verifier-keys.schema.json "$TARGET" \
    && echo "Schema OK." >&2 || { echo "ERROR: schema validation failed — revert and inspect." >&2; exit 1; }
else
  echo "NOTE: install check-jsonschema to validate locally (CI validates on PR)." >&2
fi
