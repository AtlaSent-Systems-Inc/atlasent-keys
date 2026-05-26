#!/usr/bin/env bash
# validate-local.sh — validate all .well-known/*.json against their
# JSON Schemas, mirroring what the publish-trust-root CI job does.
#
# Usage: bash scripts/validate-local.sh
#
# Requires: check-jsonschema  (pipx install check-jsonschema)

set -euo pipefail

ATLASENT_REF="${ATLASENT_REF:-main}"
SCHEMA_BASE="https://raw.githubusercontent.com/AtlaSent-Systems-Inc/atlasent/${ATLASENT_REF}/schemas/trust-root/v1"
WELL_KNOWN_DIR="${WELL_KNOWN_DIR:-.well-known}"

if ! command -v check-jsonschema &>/dev/null; then
  echo "check-jsonschema not found. Installing via pipx..."
  if command -v pipx &>/dev/null; then
    pipx install check-jsonschema
  else
    echo "ERROR: pipx not found. Install with: pip install --user pipx" >&2
    exit 1
  fi
fi

echo "Validating .well-known files against schemas on atlasent@${ATLASENT_REF}..."
echo ""

FAILED=0
for name in atlasent-trust-root atlasent-verifier-keys atlasent-revocations atlasent-sigstore-identities; do
  f="${WELL_KNOWN_DIR}/${name}.json"
  schema="${SCHEMA_BASE}/${name}.schema.json"
  if [ ! -f "${f}" ]; then
    echo "SKIP: ${f} not found"
    continue
  fi
  printf '%-55s' "  ${f}"
  if check-jsonschema --schemafile "${schema}" "${f}" >/dev/null 2>&1; then
    echo "OK"
  else
    echo "FAIL"
    check-jsonschema --schemafile "${schema}" "${f}" || true
    FAILED=$(( FAILED + 1 ))
  fi
done

echo ""
if [ "${FAILED}" -gt 0 ]; then
  echo "${FAILED} file(s) failed validation." >&2
  exit 1
fi
echo "All files valid."
