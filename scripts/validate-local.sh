#!/usr/bin/env bash
# validate-local.sh — validate all .well-known/*.json against their
# JSON Schemas, mirroring what the publish-trust-root CI job does.
#
# Usage: bash scripts/validate-local.sh
#
# Requires: check-jsonschema  (pipx install check-jsonschema)

set -euo pipefail

# Validate against THIS repo's own schema copies (schemas/trust-root/v1/),
# the same ones the publish-trust-root CI `validate` job copies and checks
# against (see .github/workflows/publish-trust-root.yml's "copy local
# schemas" step, SCHEMA_DIR: schemas/trust-root/v1). This script previously
# fetched schemas from a live raw.githubusercontent.com URL in the
# *atlasent* repo instead — a different repo's copy that had already
# drifted (it required resource "sig" paths to end in .sig, a stale R3
# detached-signature convention; this repo's real files use R4 keyless
# .bundle files per docs/TRUST_ROOT_INTEGRITY_INVARIANTS.md), so this
# script failed against the real, currently-valid atlasent-trust-root.json
# while CI passed it — the opposite of "mirroring what CI does".
SCHEMA_DIR="${SCHEMA_DIR:-schemas/trust-root/v1}"
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

echo "Validating .well-known files against local schemas (${SCHEMA_DIR})..."
echo ""

FAILED=0
for name in atlasent-trust-root atlasent-verifier-keys atlasent-revocations atlasent-sigstore-identities; do
  f="${WELL_KNOWN_DIR}/${name}.json"
  schema="${SCHEMA_DIR}/${name}.schema.json"
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
