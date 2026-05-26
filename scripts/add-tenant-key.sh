#!/usr/bin/env bash
# add-tenant-key.sh — add a tenant Ed25519 public key to
# .well-known/atlasent-verifier-keys.json and update issued_at.
#
# Usage:
#   TENANT_SLUG=acme ROLE=permit PUBLIC_KEY_B64URL=<base64url> \
#     bash scripts/add-tenant-key.sh
#
# Required env vars:
#   TENANT_SLUG        short tenant identifier (e.g. acme, betacorp)
#   ROLE               permit  (R2_permit) or  audit  (R3_audit)
#   PUBLIC_KEY_B64URL  base64url-encoded 32-byte Ed25519 public key
#                      Extract from PKCS8 PEM:
#                        openssl pkey -in permit.pem -pubout -outform DER \
#                          | tail -c 32 | base64 | tr '+/' '-_' | tr -d '='
#
# Optional env vars:
#   VALID_FROM     RFC 3339  (default: first day of current quarter)
#   VALID_UNTIL    RFC 3339  (default: first day of quarter+2, ~6 months out)
#   WELL_KNOWN_DIR path to .well-known dir  (default: .well-known)
#
# Requires: jq
# Optional: check-jsonschema (pipx install check-jsonschema) for local validation

set -euo pipefail

TENANT_SLUG="${TENANT_SLUG:?TENANT_SLUG is required}"
ROLE="${ROLE:?ROLE is required (permit or audit)}"
PUBLIC_KEY_B64URL="${PUBLIC_KEY_B64URL:?PUBLIC_KEY_B64URL is required}"
WELL_KNOWN_DIR="${WELL_KNOWN_DIR:-.well-known}"
TARGET="${WELL_KNOWN_DIR}/atlasent-verifier-keys.json"

if ! command -v jq &>/dev/null; then
  echo "ERROR: jq is required. Install via your package manager." >&2
  exit 1
fi

case "${ROLE}" in
  permit) ROLE_ENUM="R2_permit" ;;
  audit)  ROLE_ENUM="R3_audit"  ;;
  *)
    echo "ERROR: ROLE must be 'permit' or 'audit', got '${ROLE}'" >&2
    exit 1
    ;;
esac

if [ ! -f "${TARGET}" ]; then
  echo "ERROR: ${TARGET} does not exist. Run from repo root." >&2
  exit 1
fi

YEAR=$(date -u +%Y)
MONTH=$(date -u +%-m)
QUARTER=$(( (MONTH - 1) / 3 + 1 ))

KID="ak_${YEAR}_q${QUARTER}_${TENANT_SLUG}_${ROLE}"

# Default valid_from = first day of current quarter
Q_START_MONTH=$(( (QUARTER - 1) * 3 + 1 ))
VALID_FROM="${VALID_FROM:-${YEAR}-$(printf '%02d' "${Q_START_MONTH}")-01T00:00:00Z}"

# Default valid_until = first day of quarter+2 (6 months out gives a 14-day rotation overlap)
Q_FUTURE=$(( QUARTER + 2 ))
Q_FUTURE_YEAR="${YEAR}"
if [ "${Q_FUTURE}" -gt 4 ]; then
  Q_FUTURE=$(( Q_FUTURE - 4 ))
  Q_FUTURE_YEAR=$(( YEAR + 1 ))
fi
Q_FUTURE_MONTH=$(( (Q_FUTURE - 1) * 3 + 1 ))
VALID_UNTIL="${VALID_UNTIL:-${Q_FUTURE_YEAR}-$(printf '%02d' "${Q_FUTURE_MONTH}")-01T00:00:00Z}"

NOW_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Reject duplicate KIDs
if jq -e --arg kid "${KID}" '.keys[] | select(.kid == $kid)' "${TARGET}" >/dev/null 2>&1; then
  echo "ERROR: KID '${KID}' already exists in ${TARGET}. No changes made." >&2
  exit 1
fi

NEW_ENTRY=$(jq -n \
  --arg kid    "${KID}" \
  --arg role   "${ROLE_ENUM}" \
  --arg tenant "${TENANT_SLUG}" \
  --arg x      "${PUBLIC_KEY_B64URL}" \
  --arg vf     "${VALID_FROM}" \
  --arg vu     "${VALID_UNTIL}" \
  '{
    kid:         $kid,
    role:        $role,
    tenant:      $tenant,
    kty:         "OKP",
    crv:         "Ed25519",
    alg:         "EdDSA",
    x:           $x,
    valid_from:  $vf,
    valid_until: $vu,
    replaced_by: null,
    revoked:     false
  }')

tmp="$(mktemp)"
jq --arg now "${NOW_ISO}" --argjson entry "${NEW_ENTRY}" \
  '.issued_at = $now | .keys += [$entry]' \
  "${TARGET}" > "${tmp}"
mv "${tmp}" "${TARGET}"

echo "Added KID:  ${KID}"
echo "Role:       ${ROLE_ENUM}"
echo "Tenant:     ${TENANT_SLUG}"
echo "Valid:      ${VALID_FROM} → ${VALID_UNTIL}"
echo ""
echo "Written to ${TARGET}. Review the diff, then:"
echo ""
echo "  1. Validate locally (optional):" 
echo "       bash scripts/validate-local.sh"
echo "  2. Commit and push:"
echo "       git add ${TARGET}"
echo "       git commit -m 'feat(trust-root): add ${KID}'"
echo "       git push"
echo "  3. Open a PR to main. The publish workflow will validate,"
echo "     cosign-sign each file, and commit .sig / .bundle files back."
