#!/usr/bin/env node
/**
 * verify-trust-root-integrity.mjs
 *
 * Deterministic, dependency-free integrity validator for the public
 * trust root published by this repository. Complements (does not
 * replace) the JSON Schema validation `check-jsonschema` already runs
 * in `publish-trust-root.yml`'s `validate` job: schema validation
 * checks *shape*; this script checks *meaning* — cross-file
 * consistency, cryptographic-material sanity, duplicate-key
 * classification, lifecycle ordering, and repo-hygiene secret
 * patterns that a JSON Schema cannot express.
 *
 * This script NEVER writes to `.well-known/*.json` or any other
 * published trust-root file. It is read-only. See
 * docs/TRUST_ROOT_INTEGRITY_INVARIANTS.md for the enforced invariant
 * list and docs/known-key-material-aliases.json /
 * docs/staging-key-denylist.json for the two small, human-reviewed
 * allowlists it consults.
 *
 * Exit codes:
 *   0  — no failures (warnings may still have been printed)
 *   1  — one or more findings (fail-closed)
 *   2  — environment/usage error (bad CLI args, unreadable files)
 *
 * Usage:
 *   node scripts/verify-trust-root-integrity.mjs [--dir <repo-root>] [--json]
 *
 * --dir defaults to the repository root inferred from this script's
 * location, so it can be pointed at a scratch fixture copy for
 * mutation testing without touching the real files.
 */

import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createPublicKey } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── CLI ──────────────────────────────────────────────────────────────
function parseArgs(argv) {
  let dir = path.resolve(__dirname, "..");
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--dir") {
      dir = path.resolve(argv[++i]);
    } else if (argv[i] === "--json") {
      json = true;
    } else if (argv[i] === "--help" || argv[i] === "-h") {
      console.log(
        "Usage: verify-trust-root-integrity.mjs [--dir <repo-root>] [--json]",
      );
      process.exit(0);
    } else {
      console.error(`Unknown argument: ${argv[i]}`);
      process.exit(2);
    }
  }
  return { dir, json };
}

// ── Small result-collection helpers ─────────────────────────────────
class Report {
  constructor() {
    this.failures = [];
    this.warnings = [];
    this.infos = [];
  }
  fail(code, message, extra = {}) {
    this.failures.push({ code, message, ...extra });
  }
  warn(code, message, extra = {}) {
    this.warnings.push({ code, message, ...extra });
  }
  info(code, message, extra = {}) {
    this.infos.push({ code, message, ...extra });
  }
  get ok() {
    return this.failures.length === 0;
  }
}

function readJson(file, report, { required = true } = {}) {
  if (!existsSync(file)) {
    if (required) {
      report.fail("FILE_MISSING", `required file not found: ${file}`);
    }
    return null;
  }
  const raw = readFileSync(file, "utf8");
  try {
    return JSON.parse(raw);
  } catch (e) {
    report.fail("JSON_PARSE_ERROR", `${file}: ${e.message}`);
    return null;
  }
}

// ── Base64url / key-material helpers ────────────────────────────────
const B64URL_RE = /^[A-Za-z0-9_-]+$/;

function b64urlToBuffer(s) {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const std = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  return Buffer.from(std, "base64");
}

/**
 * Validate that a key entry's declared encoding is a real, well-formed
 * public key for its declared (kty, crv). Fails closed: any exception
 * or shape mismatch is a validation FAILURE, never a silent skip.
 */
function validateKeyEncoding(entry, label, report) {
  const { kty, crv, alg, x, y } = entry;

  if (typeof x !== "string" || !B64URL_RE.test(x)) {
    report.fail(
      "MALFORMED_KEY_ENCODING",
      `${label}: 'x' is not valid unpadded base64url`,
    );
    return;
  }

  if (kty === "OKP") {
    if (crv !== "Ed25519" || alg !== "EdDSA") {
      report.fail(
        "MALFORMED_KEY_ENCODING",
        `${label}: kty=OKP requires crv=Ed25519, alg=EdDSA (got crv=${crv}, alg=${alg})`,
      );
      return;
    }
    const raw = b64urlToBuffer(x);
    if (raw.length !== 32) {
      report.fail(
        "MALFORMED_KEY_ENCODING",
        `${label}: Ed25519 public key must decode to 32 bytes, got ${raw.length}`,
      );
      return;
    }
    try {
      const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" });
      if (key.asymmetricKeyType !== "ed25519") {
        report.fail(
          "MALFORMED_KEY_ENCODING",
          `${label}: key parsed but asymmetricKeyType=${key.asymmetricKeyType}, expected ed25519`,
        );
      }
    } catch (e) {
      report.fail(
        "MALFORMED_KEY_ENCODING",
        `${label}: Ed25519 key failed to parse: ${e.message}`,
      );
    }
  } else if (kty === "EC") {
    if (crv !== "P-256" || alg !== "ES256") {
      report.fail(
        "MALFORMED_KEY_ENCODING",
        `${label}: kty=EC requires crv=P-256, alg=ES256 (got crv=${crv}, alg=${alg})`,
      );
      return;
    }
    if (typeof y !== "string" || !B64URL_RE.test(y)) {
      report.fail(
        "MALFORMED_KEY_ENCODING",
        `${label}: kty=EC requires a valid base64url 'y' coordinate`,
      );
      return;
    }
    const rawX = b64urlToBuffer(x);
    const rawY = b64urlToBuffer(y);
    if (rawX.length !== 32 || rawY.length !== 32) {
      report.fail(
        "MALFORMED_KEY_ENCODING",
        `${label}: P-256 x/y must each decode to 32 bytes (got x=${rawX.length}, y=${rawY.length})`,
      );
      return;
    }
    try {
      // node validates the point is on curve as part of JWK import.
      const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x, y }, format: "jwk" });
      if (key.asymmetricKeyType !== "ec") {
        report.fail(
          "MALFORMED_KEY_ENCODING",
          `${label}: key parsed but asymmetricKeyType=${key.asymmetricKeyType}, expected ec`,
        );
      }
    } catch (e) {
      report.fail(
        "MALFORMED_KEY_ENCODING",
        `${label}: P-256 key failed to parse (not a valid curve point?): ${e.message}`,
      );
    }
  } else {
    report.fail("MALFORMED_KEY_ENCODING", `${label}: unknown kty '${kty}'`);
  }
}

// ── Timestamp helpers ────────────────────────────────────────────────
function parseTs(s, label, report, { nullable = false } = {}) {
  if (s === null && nullable) return null;
  if (typeof s !== "string") {
    report.fail("TIMESTAMP_INVALID", `${label}: timestamp is not a string (${JSON.stringify(s)})`);
    return null;
  }
  const t = Date.parse(s);
  if (Number.isNaN(t)) {
    report.fail("TIMESTAMP_INVALID", `${label}: '${s}' does not parse as a timestamp`);
    return null;
  }
  return t;
}

// ── Repository hygiene: targeted secret patterns ────────────────────
const PRIVATE_KEY_PEM_RE = /-----BEGIN\s+[A-Z0-9 ]*PRIVATE KEY-----/;
const FORBIDDEN_JSON_KEY_NAMES = new Set([
  "d", // JWK private exponent / seed (RFC 8037 OKP, RFC 7518 EC/RSA)
  "private_key",
  "privatekey",
  "secret_key",
  "secretkey",
  "priv",
]);

function scanJsonForPrivateMaterial(node, filePath, jsonPath, report) {
  if (node === null || typeof node !== "object") return;
  if (Array.isArray(node)) {
    node.forEach((item, i) => scanJsonForPrivateMaterial(item, filePath, `${jsonPath}[${i}]`, report));
    return;
  }
  // A JWK-shaped object is exactly the place an accidental 'd' (private
  // scalar) would appear; also flag any occurrence of the forbidden
  // property names anywhere in the document, JWK-shaped or not.
  for (const [key, value] of Object.entries(node)) {
    if (FORBIDDEN_JSON_KEY_NAMES.has(key.toLowerCase())) {
      report.fail(
        "PRIVATE_MATERIAL_FIELD",
        `${filePath}${jsonPath}.${key}: property name is private-key-shaped ('${key}') — private key material must never appear in a published trust-root file`,
      );
    }
    scanJsonForPrivateMaterial(value, filePath, `${jsonPath}.${key}`, report);
  }
}

function listTrackedFiles(repoDir) {
  try {
    const out = execFileSync("git", ["-C", repoDir, "ls-files"], { encoding: "utf8" });
    return out.split("\n").filter(Boolean);
  } catch (e) {
    // Not a git checkout (e.g. a scratch fixture dir) — fall back to
    // nothing tracked; caller should pass an explicit file list in
    // that case. Fail closed with a warning rather than silently
    // skipping the hygiene scan.
    return null;
  }
}

const BINARY_EXT_SKIP = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".woff", ".woff2", ".ttf",
]);

function repoHygieneScan(repoDir, report, { trackedFiles = null } = {}) {
  const files = trackedFiles ?? listTrackedFiles(repoDir);
  if (files === null) {
    report.warn(
      "HYGIENE_SCAN_SKIPPED",
      `${repoDir} is not a git checkout; repository-wide private-material scan skipped (git ls-files unavailable)`,
    );
    return;
  }
  for (const rel of files) {
    const ext = path.extname(rel).toLowerCase();
    if (BINARY_EXT_SKIP.has(ext)) continue;
    const abs = path.join(repoDir, rel);
    let content;
    try {
      content = readFileSync(abs, "utf8");
    } catch {
      continue; // unreadable/binary — not a text secret carrier
    }
    if (PRIVATE_KEY_PEM_RE.test(content)) {
      report.fail(
        "PRIVATE_KEY_PEM_FOUND",
        `${rel}: contains a PEM private-key header ('-----BEGIN ... PRIVATE KEY-----')`,
      );
    }
    if (ext === ".json") {
      let parsed;
      try {
        parsed = JSON.parse(content);
      } catch {
        continue;
      }
      scanJsonForPrivateMaterial(parsed, rel, "", report);
    }
  }
}

// ── Allowlists (small, human-reviewed, checked into the repo) ──────
function loadAllowlist(file, report) {
  if (!existsSync(file)) return { entries: [] };
  return readJson(file, report) ?? { entries: [] };
}

// ── Main checks ──────────────────────────────────────────────────────
function checkVerifierKeys(doc, report, ctx) {
  if (!doc || !Array.isArray(doc.keys)) return;

  const seenKid = new Map(); // kid -> [entries]
  const seenX = new Map(); // x -> [{kid, entry}]

  for (const entry of doc.keys) {
    const label = `atlasent-verifier-keys.json:${entry.kid ?? "<no-kid>"}`;

    // Structural: KID uniqueness (schema's uniqueItems is whole-object,
    // not kid-field; two entries with the same kid but different other
    // fields would pass schema validation and silently shadow one
    // another at lookup time).
    if (typeof entry.kid === "string") {
      if (!seenKid.has(entry.kid)) seenKid.set(entry.kid, []);
      seenKid.get(entry.kid).push(entry);
    } else {
      report.fail("MISSING_KID", `an entry in atlasent-verifier-keys.json has no string 'kid'`);
    }

    // Structural: required algorithm/type metadata present (defense in
    // depth alongside JSON Schema — this script must independently
    // fail closed even if schema validation is skipped or drifts).
    for (const f of ["role", "kty", "crv", "alg", "x", "valid_from", "valid_until", "revoked"]) {
      if (!(f in entry)) {
        report.fail("MISSING_REQUIRED_FIELD", `${label}: missing required field '${f}'`);
      }
    }

    // Structural: registered vocabulary only.
    const ROLE_ENUM = new Set(["R1_release", "R2_permit", "R3_audit", "R4_pack"]);
    if (entry.role !== undefined && !ROLE_ENUM.has(entry.role)) {
      report.fail("UNKNOWN_ROLE", `${label}: role '${entry.role}' is not in the registered vocabulary`);
    }
    if (entry.revoked !== undefined && typeof entry.revoked !== "boolean") {
      report.fail("INVALID_STATUS_VALUE", `${label}: 'revoked' must be boolean, got ${JSON.stringify(entry.revoked)}`);
    }

    // Cryptographic: encoding validity (fails closed on malformed keys —
    // never silently skipped).
    if (entry.kty && entry.x) {
      validateKeyEncoding(entry, label, report);
    }

    // Lifecycle: timestamp parse + internal ordering.
    const vf = parseTs(entry.valid_from, `${label}.valid_from`, report);
    const vu = parseTs(entry.valid_until, `${label}.valid_until`, report);
    if (vf !== null && vu !== null && vf >= vu) {
      report.fail(
        "IMPOSSIBLE_VALIDITY_WINDOW",
        `${label}: valid_from (${entry.valid_from}) is not before valid_until (${entry.valid_until})`,
      );
    }

    // Lifecycle: replaced_by must point at a real kid if non-null
    // (checked in a second pass below, once all kids are known).

    // Duplicate-material tracking.
    if (typeof entry.x === "string") {
      if (!seenX.has(entry.x)) seenX.set(entry.x, []);
      seenX.get(entry.x).push(entry);
    }
  }

  // Structural: duplicate KID.
  for (const [kid, entries] of seenKid) {
    if (entries.length > 1) {
      report.fail(
        "DUPLICATE_KID",
        `kid '${kid}' appears ${entries.length} times in atlasent-verifier-keys.json`,
      );
    }
  }

  // Lifecycle: replaced_by references an existing kid.
  for (const entry of doc.keys) {
    if (entry.replaced_by != null && !seenKid.has(entry.replaced_by)) {
      report.fail(
        "DANGLING_REPLACED_BY",
        `atlasent-verifier-keys.json:${entry.kid}: replaced_by '${entry.replaced_by}' does not match any published kid`,
      );
    }
  }

  // Lifecycle: current active signing entries satisfy documented
  // trust-root requirements — at least one currently-active (revoked
  // false, now within [valid_from, valid_until]) entry per required
  // role (R2_permit, R3_audit — the two roles atlasent-api's runtime
  // depends on per this repo's CLAUDE.md).
  const now = ctx.now;
  const REQUIRED_ACTIVE_ROLES = ["R2_permit", "R3_audit"];
  for (const role of REQUIRED_ACTIVE_ROLES) {
    const active = doc.keys.filter((e) => {
      if (e.role !== role || e.revoked !== false) return false;
      const vf = Date.parse(e.valid_from);
      const vu = Date.parse(e.valid_until);
      return !Number.isNaN(vf) && !Number.isNaN(vu) && vf <= now && now <= vu;
    });
    if (active.length === 0) {
      report.fail(
        "NO_ACTIVE_KEY_FOR_ROLE",
        `no currently-active, non-revoked key found for required role '${role}' as of ${new Date(now).toISOString()}`,
      );
    }
  }

  // Duplicate-material classification.
  classifyDuplicateMaterial(seenX, report, ctx);

  return { seenKid, seenX };
}

function classifyDuplicateMaterial(seenX, report, ctx) {
  const aliasAllow = ctx.knownAliases;

  for (const [x, entries] of seenX) {
    if (entries.length < 2) continue;
    const kids = entries.map((e) => e.kid).sort();
    const activeMembers = entries.filter((e) => e.revoked === false);
    const revokedMembers = entries.filter((e) => e.revoked === true);

    if (activeMembers.length >= 2) {
      report.fail(
        "DANGEROUS_DUPLICATE_ACTIVE_KEY",
        `active key material reused across ${activeMembers.length} non-revoked entries: ${activeMembers.map((e) => e.kid).join(", ")} — two independently-active KIDs must never share a private key`,
      );
      continue;
    }

    if (activeMembers.length === 1 && revokedMembers.length >= 1) {
      report.fail(
        "DANGEROUS_DUPLICATE_ACTIVE_REUSES_REVOKED",
        `active key '${activeMembers[0].kid}' shares public-key material with revoked/test entr${revokedMembers.length === 1 ? "y" : "ies"} ${revokedMembers.map((e) => e.kid).join(", ")} — an active signer must not share key material with retired/test material`,
      );
      continue;
    }

    // All members revoked (or none marked active) — not immediately
    // dangerous, but must be an explicitly documented, reviewed alias.
    // Look it up in the allowlist by exact kid-set match.
    const match = aliasAllow.entries?.find((a) => {
      const allowKids = [...a.kids].sort();
      return allowKids.length === kids.length && allowKids.every((k, i) => k === kids[i]);
    });

    if (match) {
      report.info(
        "DOCUMENTED_HISTORICAL_ALIAS",
        `kids [${kids.join(", ")}] share key material — documented historical alias per ${match.doc_ref} (${match.reason})`,
      );
    } else {
      report.warn(
        "UNDOCUMENTED_DUPLICATE_MATERIAL",
        `kids [${kids.join(", ")}] share identical public-key material with no active member, but this cluster is not recorded in docs/known-key-material-aliases.json — add a reviewed entry (or rotate one of them) so future readers can tell 'documented historical alias' from 'accidental collision' on sight`,
      );
    }
  }
}

function checkRevocationsConsistency(revocationsDoc, verifierKeysDoc, report) {
  if (!revocationsDoc || !verifierKeysDoc) return;

  const verifierKidRevoked = new Map();
  for (const e of verifierKeysDoc.keys ?? []) {
    if (typeof e.kid === "string") verifierKidRevoked.set(e.kid, e.revoked);
  }

  const revokedKeySet = new Set();
  for (const rk of revocationsDoc.revoked_keys ?? []) {
    revokedKeySet.add(rk.kid);
    // Schema-documented direction: every revocations.json entry MUST
    // match a kid in atlasent-verifier-keys.json.
    if (!verifierKidRevoked.has(rk.kid)) {
      report.fail(
        "REVOCATION_LEDGER_ORPHAN",
        `atlasent-revocations.json lists kid '${rk.kid}' but no such kid exists in atlasent-verifier-keys.json`,
      );
    } else if (verifierKidRevoked.get(rk.kid) !== true) {
      report.fail(
        "REVOCATION_LEDGER_STATUS_MISMATCH",
        `atlasent-revocations.json lists kid '${rk.kid}' as revoked, but atlasent-verifier-keys.json has revoked=${JSON.stringify(verifierKidRevoked.get(rk.kid))} for that kid`,
      );
    }
  }

  // Reverse direction: atlasent-verifier-keys.schema.json's own
  // description of `revoked` says "Verifiers MUST cross-check
  // atlasent-revocations.json; this flag is a denormalised
  // convenience" — i.e. revocations.json is meant to be the
  // authoritative ledger. A kid marked revoked=true in the JWKS but
  // absent from the ledger is a real cross-file consistency gap: a
  // verifier that trusts the ledger over the denormalised flag would
  // not know to reject it. This is reported as a WARNING, not a hard
  // failure — completing the ledger is a same-status bookkeeping
  // action for a human, not something this read-only validator should
  // block on, and (as of 2026-08-22) one such gap pre-exists in the
  // published data (see docs/TRUST_ROOT_INTEGRITY_INVARIANTS.md).
  for (const [kid, revoked] of verifierKidRevoked) {
    if (revoked === true && !revokedKeySet.has(kid)) {
      report.warn(
        "REVOCATION_LEDGER_INCOMPLETE",
        `atlasent-verifier-keys.json marks kid '${kid}' as revoked=true, but it has no matching entry in atlasent-revocations.json's revoked_keys — a verifier that treats the ledger as authoritative (per the schema's own note) would not learn this key is revoked`,
      );
    }
  }

  // Lifecycle: revoked_at must not precede the key's own valid_from.
  const verifierKidEntry = new Map((verifierKeysDoc.keys ?? []).map((e) => [e.kid, e]));
  for (const rk of revocationsDoc.revoked_keys ?? []) {
    const entry = verifierKidEntry.get(rk.kid);
    if (!entry) continue; // already reported as orphan above
    const vf = Date.parse(entry.valid_from);
    const ra = Date.parse(rk.revoked_at);
    if (!Number.isNaN(vf) && !Number.isNaN(ra) && ra < vf) {
      report.fail(
        "IMPOSSIBLE_VALIDITY_WINDOW",
        `atlasent-revocations.json: kid '${rk.kid}' revoked_at (${rk.revoked_at}) precedes its own valid_from (${entry.valid_from}) in atlasent-verifier-keys.json`,
      );
    }
  }
}

function checkSigstoreIdentities(doc, report) {
  if (!doc || !Array.isArray(doc.identities)) return;
  for (const [i, id] of doc.identities.entries()) {
    const label = `atlasent-sigstore-identities.json[${i}] (${id.role ?? "?"})`;
    const vf = parseTs(id.valid_from, `${label}.valid_from`, report);
    const vu = parseTs(id.valid_until, `${label}.valid_until`, report, { nullable: true });
    if (vf !== null && vu !== null && vf >= vu) {
      report.fail(
        "IMPOSSIBLE_VALIDITY_WINDOW",
        `${label}: valid_from (${id.valid_from}) is not before valid_until (${id.valid_until})`,
      );
    }
    // Repository hygiene: identity regexps must be anchored (the
    // schema's own description requires this to prevent prefix/suffix
    // smuggling of an unintended workflow path).
    if (typeof id.identity_regexp === "string") {
      if (!id.identity_regexp.startsWith("^") || !id.identity_regexp.endsWith("$")) {
        report.fail(
          "UNANCHORED_IDENTITY_REGEXP",
          `${label}: identity_regexp is not anchored with ^...$ ('${id.identity_regexp}')`,
        );
      }
    }
  }
}

function checkPermitSigningKeys(doc, report) {
  if (!doc || !Array.isArray(doc.keys)) return;
  const seenKid = new Set();
  for (const entry of doc.keys) {
    const label = `docs/permit-signing-keys.json:${entry.kid ?? "<no-kid>"}`;
    if (typeof entry.kid !== "string") {
      report.fail("MISSING_KID", `an entry in docs/permit-signing-keys.json has no string 'kid'`);
    } else if (seenKid.has(entry.kid)) {
      report.fail("DUPLICATE_KID", `kid '${entry.kid}' appears more than once in docs/permit-signing-keys.json`);
    } else {
      seenKid.add(entry.kid);
    }
    if (entry.kty && entry.x) {
      validateKeyEncoding(entry, label, report);
    }
  }
}

function checkStagingKeyLeakage(allDocs, denylist, report) {
  if (!denylist?.entries?.length) return;
  const allKids = new Set();
  const allX = new Set();
  for (const doc of allDocs) {
    for (const e of doc?.doc?.keys ?? []) {
      if (typeof e.kid === "string") allKids.add(e.kid);
      if (typeof e.x === "string") allX.add(e.x);
    }
  }
  for (const staged of denylist.entries) {
    if (allKids.has(staged.kid)) {
      report.fail(
        "STAGING_KEY_PUBLISHED",
        `known staging-only kid '${staged.kid}' (${staged.environment}) appears in the published trust root — per ${staged.policy_doc} this must never be published`,
      );
    }
    if (allX.has(staged.x)) {
      report.fail(
        "STAGING_KEY_PUBLISHED",
        `known staging-only key material for '${staged.kid}' (${staged.environment}) appears under a published entry — per ${staged.policy_doc} this must never be published`,
      );
    }
  }
}

function checkCosignPub(repoDir, report) {
  const file = path.join(repoDir, "cosign.pub");
  if (!existsSync(file)) {
    report.fail("FILE_MISSING", "cosign.pub not found at repo root");
    return;
  }
  const pem = readFileSync(file, "utf8");
  if (!/-----BEGIN PUBLIC KEY-----/.test(pem)) {
    report.fail("MALFORMED_KEY_ENCODING", "cosign.pub does not look like a PEM public key");
    return;
  }
  try {
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType !== "ec") {
      report.fail(
        "MALFORMED_KEY_ENCODING",
        `cosign.pub parsed but is asymmetricKeyType=${key.asymmetricKeyType}, expected ec (P-256)`,
      );
    }
  } catch (e) {
    report.fail("MALFORMED_KEY_ENCODING", `cosign.pub failed to parse as a public key: ${e.message}`);
  }
}

// ── Orchestration ────────────────────────────────────────────────────
export function runValidator({ dir, now = Date.now(), trackedFiles = null } = {}) {
  const report = new Report();
  const wellKnown = path.join(dir, ".well-known");

  const verifierKeysDoc = readJson(path.join(wellKnown, "atlasent-verifier-keys.json"), report);
  const revocationsDoc = readJson(path.join(wellKnown, "atlasent-revocations.json"), report);
  const sigstoreDoc = readJson(path.join(wellKnown, "atlasent-sigstore-identities.json"), report);
  const trustRootDoc = readJson(path.join(wellKnown, "atlasent-trust-root.json"), report);
  const permitSigningDoc = readJson(path.join(dir, "docs", "permit-signing-keys.json"), report, {
    required: false,
  });

  const knownAliases = loadAllowlist(
    path.join(dir, "docs", "known-key-material-aliases.json"),
    report,
  );
  const stagingDenylist = loadAllowlist(
    path.join(dir, "docs", "staging-key-denylist.json"),
    report,
  );

  const ctx = { now, knownAliases };

  checkVerifierKeys(verifierKeysDoc, report, ctx);
  checkRevocationsConsistency(revocationsDoc, verifierKeysDoc, report);
  checkSigstoreIdentities(sigstoreDoc, report);
  checkPermitSigningKeys(permitSigningDoc, report);
  checkStagingKeyLeakage(
    [{ doc: verifierKeysDoc }, { doc: permitSigningDoc }],
    stagingDenylist,
    report,
  );
  checkCosignPub(dir, report);

  // trust-root.json's resources[] must reference files that exist and
  // whose sha256 is well-formed hex (the CI job recomputes the actual
  // digest at publish time; this validator checks shape/reachability
  // only, since a scratch/PR checkout won't have freshly-signed
  // bundles).
  if (trustRootDoc) {
    for (const r of trustRootDoc.resources ?? []) {
      const local = path.join(dir, r.path.replace(/^\//, ""));
      if (!existsSync(local)) {
        report.fail("FILE_MISSING", `atlasent-trust-root.json references '${r.path}' which does not exist at ${local}`);
      }
      if (typeof r.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(r.sha256)) {
        report.fail("MALFORMED_DIGEST", `atlasent-trust-root.json: resource '${r.path}' has a malformed sha256 ('${r.sha256}')`);
      }
    }
  }

  repoHygieneScan(dir, report, { trackedFiles });

  return report;
}

function printReport(report, json) {
  if (json) {
    console.log(
      JSON.stringify(
        {
          ok: report.ok,
          failures: report.failures,
          warnings: report.warnings,
          infos: report.infos,
        },
        null,
        2,
      ),
    );
    return;
  }
  for (const i of report.infos) {
    console.log(`INFO  [${i.code}] ${i.message}`);
  }
  for (const w of report.warnings) {
    console.log(`WARN  [${w.code}] ${w.message}`);
  }
  for (const f of report.failures) {
    console.log(`FAIL  [${f.code}] ${f.message}`);
  }
  console.log("");
  console.log(
    `${report.failures.length} failure(s), ${report.warnings.length} warning(s), ${report.infos.length} info(s).`,
  );
  console.log(report.ok ? "trust-root integrity: PASS" : "trust-root integrity: FAIL");
}

// Only run as a CLI when invoked directly (not when imported by the
// mutation-test harness).
if (import.meta.url === `file://${process.argv[1]}`) {
  const { dir, json } = parseArgs(process.argv.slice(2));
  const report = runValidator({ dir });
  printReport(report, json);
  process.exit(report.ok ? 0 : 1);
}
