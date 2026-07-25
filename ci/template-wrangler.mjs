#!/usr/bin/env node
// Templates a generated app's wrangler.jsonc: substitutes the platform's
// known placeholder markers (worker name, D1 database name/id, R2 bucket
// name, Access AUD) with the app's real deploy-time values, just before
// `wrangler deploy` runs.
//
// This is a config-mutating script for a security-sensitive file, so it is
// deliberately conservative:
//   - It never does a blind global replace of the bare word "replace"/
//     "REPLACE" — every substitution targets a specific, known marker VALUE
//     (or key+value pair), matched as a whole literal.
//   - It asserts, both before AND after substitution, that each known marker
//     literal is (before) / is no longer (after) present. The post-condition
//     is deliberately scoped to the exact marker literals — not a blanket
//     "replace" word-search — so it can never false-positive on an app name
//     that happens to contain the substring "replace" (e.g. app "toreplace"
//     is a valid slug, and "inno-app-toreplace" legitimately contains
//     "replace"). If a real marker survives, we fail loud rather than ever
//     deploy a half-templated config.
//   - It never touches ENVIRONMENT or any other field.
//
// Usage: node ci/template-wrangler.mjs <app> <databaseId> <accessAud> [wranglerPath=wrangler.jsonc]

import { readFileSync, writeFileSync } from "node:fs";
import { stripJsonComments } from "./check-config.mjs";
import { isMainModule } from "./cli.mjs";

const APP_NAME_RE = /^[a-z][a-z0-9-]{2,28}$/;

// Names that collide with the template markers themselves (an app literally
// named "replace" would make "inno-app-replace" a real value, not a marker,
// and templating would then throw "markers remain" forever). Kept in sync
// with src/registry.ts's RESERVED — a test asserts the two lists are equal —
// but enforced here independently because this script does not consult the
// registry. Exported for that parity test.
export const RESERVED_APP_NAMES = ["platform", "template", "app", "replace", "inno-platform"];

// A double-quote, backslash, or control character in a value interpolated raw
// into the JSONC string could break out of the JSON string literal. `$` is
// rejected too: these values are interpolated into String.replace REPLACEMENT
// strings, where `$1`/`$&`/`$$` are special — real values (hex AUD, UUID db id)
// never contain `$`, so rejecting it closes that footgun for every templater.
const UNSAFE_VALUE_RE = /[$"\\\x00-\x1f]/;

function countMatches(text, re) {
  const m = text.match(re);
  return m ? m.length : 0;
}

/**
 * Substitute the wrangler.jsonc template markers with real deploy-time values.
 *
 * Markers substituted (each targeted precisely as a whole literal — never a
 * blind "replace" -> value string replace):
 *   - "inno-app-replace"   (worker name)      -> "inno-app-{app}"
 *   - "inno-replace-db"    (D1 database_name) -> "inno-{app}-db"
 *   - "inno-replace-data"  (R2 bucket_name)   -> "inno-{app}-data"
 *   - `"database_id": "REPLACE"`               -> `"database_id": "{databaseId}"`
 *   - `"ACCESS_AUD": "REPLACE"`                 -> `"ACCESS_AUD": "{accessAud}"`
 *
 * @param {string} wranglerText
 * @param {{app: string, databaseId: string, accessAud: string}} params
 * @returns {string} the substituted JSONC text
 */
export function templateWrangler(wranglerText, { app, databaseId, accessAud } = {}) {
  // Shared validation so the container path and the worker templaters enforce
  // identical app-name and deploy-value rules (jq missing-field literals,
  // unsafe characters). See assertAppName/assertDeployValue below.
  assertAppName(app);
  assertDeployValue("databaseId", databaseId);
  assertDeployValue("accessAud", accessAud);

  // Safety net: the template must have exactly two bare `"REPLACE"` literal
  // occurrences (database_id and ACCESS_AUD both start out as "REPLACE").
  // If that count is off, the template shape has changed in a way this
  // script doesn't understand — fail loud rather than guess which
  // occurrence maps to which field.
  const replaceLiteralCount = countMatches(wranglerText, /"REPLACE"/g);
  if (replaceLiteralCount !== 2) {
    throw new Error(
      `expected exactly 2 "REPLACE" markers (database_id, ACCESS_AUD) in wrangler.jsonc, found ${replaceLiteralCount}`,
    );
  }

  // Each marker is matched as a whole literal (name/db/bucket, case-
  // insensitive only to tolerate an uppercase template variant) or a
  // key-scoped literal (database_id / ACCESS_AUD, so the two otherwise-
  // identical "REPLACE" values each map to their own real value instead of
  // both receiving the same substitution). None of these patterns can ever
  // match unrelated text such as a comment, because each requires the full
  // quoted marker string (or key+value pair), not the bare word "replace".
  const markers = [
    { pattern: /"inno-app-replace"/i, replacement: `"inno-app-${app}"` },
    { pattern: /"inno-replace-db"/i, replacement: `"inno-${app}-db"` },
    { pattern: /"inno-replace-data"/i, replacement: `"inno-${app}-data"` },
    { pattern: /("database_id"\s*:\s*)"REPLACE"/, replacement: `$1"${databaseId}"` },
    { pattern: /("ACCESS_AUD"\s*:\s*)"REPLACE"/, replacement: `$1"${accessAud}"` },
  ];

  let out = wranglerText;
  for (const { pattern, replacement } of markers) {
    if (!pattern.test(out)) {
      throw new Error(`template marker not found (unexpected template shape): ${pattern}`);
    }
    out = out.replace(pattern, replacement);
  }

  // Post-condition: none of the known marker patterns may still match the
  // output. This is the last line of defense — if a real marker literal
  // survives (e.g. because a replacement string coincidentally re-formed
  // one), we must never deploy a half-templated config.
  const stillPresent = markers.filter((m) => m.pattern.test(out));
  if (stillPresent.length > 0) {
    throw new Error(`template markers remain after substitution: ${stillPresent.map((m) => m.pattern).join(", ")}`);
  }

  // Enforce workers_dev: false (perimeter hardening). The *.workers.dev URL is
  // NOT behind Cloudflare Access — closing it makes the Access-protected custom
  // hostname the sole ingress. Enforced here so it applies to EVERY app at
  // deploy, including apps whose committed wrangler.jsonc predates this policy.
  //
  // Decide from the comment-stripped PARSE — exactly what `wrangler deploy`
  // reads — never from raw text. A raw-text regex/replace can be fooled by a
  // comment that hosts a stray `{` (the injected key lands inside the comment)
  // or that merely mentions the key (injection is skipped): wrangler then
  // strips comments and deploys with the ingress silently left open.
  let config;
  try {
    config = JSON.parse(stripJsonComments(out));
  } catch (e) {
    throw new Error(`templated wrangler.jsonc is not valid JSON: ${e.message}`);
  }
  if (config.workers_dev !== false) {
    // Absent or truthy: normalize to a comment-free JSON document with the flag
    // forced false. Only this corrective branch rewrites; a compliant config
    // (workers_dev already false) passes through untouched, comments intact.
    config.workers_dev = false;
    out = JSON.stringify(config, null, 2) + "\n";
  }
  // Post-condition on the PARSE, not raw text: fail loud rather than ever
  // deploy with the workers.dev ingress left open.
  if (JSON.parse(stripJsonComments(out)).workers_dev !== false) {
    throw new Error("workers_dev must be exactly `false` after templating");
  }

  return out;
}

// --- Worker-type templating (migration 0022) --------------------------------
// Worker-type apps deploy TWO configs — the gateway (service binding, no
// container) and the app's own Worker (its storage bindings). Each carries a
// DIFFERENT marker set than the container wrangler, so they get their own
// templaters rather than overloading templateWrangler (whose exactly-2-REPLACE
// contract is load-bearing for the container path). The shared validation and
// workers_dev enforcement live in helpers so all paths agree on the rules.

function assertAppName(app) {
  if (typeof app !== "string" || !APP_NAME_RE.test(app)) {
    throw new Error(`invalid app name: ${JSON.stringify(app)} (must match ${APP_NAME_RE})`);
  }
  if (RESERVED_APP_NAMES.includes(app)) throw new Error(`reserved app name: ${app}`);
}

// Same JQ_MISSING + unsafe-character guards templateWrangler applies to its
// deploy values, factored out so the worker templaters enforce them identically.
function assertDeployValue(label, v) {
  if (typeof v !== "string" || v.length === 0 || v === "null" || v === "undefined") {
    throw new Error(`invalid ${label}: ${JSON.stringify(v)}`);
  }
  if (UNSAFE_VALUE_RE.test(v)) throw new Error(`invalid character in ${label}`);
}

// Per-marker present -> replace -> absent, matching templateWrangler's
// discipline: every marker must be found before substitution and gone after
// (so a half-templated config can never deploy).
function applyMarkers(text, markers) {
  let out = text;
  for (const { pattern, replacement } of markers) {
    if (!pattern.test(out)) throw new Error(`template marker not found (unexpected template shape): ${pattern}`);
    out = out.replace(pattern, replacement);
  }
  const remaining = markers.filter((m) => m.pattern.test(out));
  if (remaining.length > 0) {
    throw new Error(`template markers remain after substitution: ${remaining.map((m) => m.pattern).join(", ")}`);
  }
  return out;
}

// workers_dev:false enforced from the comment-stripped PARSE (what wrangler
// reads), never raw text — identical reasoning to templateWrangler's block.
function forceWorkersDevFalse(out, label) {
  let config;
  try { config = JSON.parse(stripJsonComments(out)); }
  catch (e) { throw new Error(`templated ${label} is not valid JSON: ${e.message}`); }
  if (config.workers_dev !== false) {
    config.workers_dev = false;
    out = JSON.stringify(config, null, 2) + "\n";
  }
  if (JSON.parse(stripJsonComments(out)).workers_dev !== false) {
    throw new Error(`workers_dev must be exactly \`false\` after templating ${label}`);
  }
  return out;
}

/**
 * Template the worker-type GATEWAY config (gateway/wrangler.worker.jsonc).
 * Markers: the service target ("inno-app-replace-app", substituted BEFORE the
 * name so the name marker can't match inside it), the worker name
 * ("inno-app-replace"), and ACCESS_AUD ("REPLACE"). Exactly one "REPLACE".
 */
export function templateWorkerGateway(text, { app, accessAud } = {}) {
  assertAppName(app);
  assertDeployValue("accessAud", accessAud);
  const replaceCount = countMatches(text, /"REPLACE"/g);
  if (replaceCount !== 1) {
    throw new Error(`expected exactly 1 "REPLACE" marker (ACCESS_AUD) in the worker gateway config, found ${replaceCount}`);
  }
  const out = applyMarkers(text, [
    { pattern: /"inno-app-replace-app"/, replacement: `"inno-app-${app}-app"` },
    { pattern: /"inno-app-replace"/, replacement: `"inno-app-${app}"` },
    { pattern: /("ACCESS_AUD"\s*:\s*)"REPLACE"/, replacement: `$1"${accessAud}"` },
  ]);
  return forceWorkersDevFalse(out, "worker gateway config");
}

/**
 * Template the worker-type APP WORKER config (gateway/app-worker.jsonc).
 * Markers: the worker name ("inno-app-replace-app"), D1 name/id, R2 bucket.
 * Exactly one "REPLACE" (database_id) — no ACCESS_AUD (the gateway owns Access).
 */
export function templateWorkerApp(text, { app, databaseId } = {}) {
  assertAppName(app);
  assertDeployValue("databaseId", databaseId);
  const replaceCount = countMatches(text, /"REPLACE"/g);
  if (replaceCount !== 1) {
    throw new Error(`expected exactly 1 "REPLACE" marker (database_id) in the app worker config, found ${replaceCount}`);
  }
  const out = applyMarkers(text, [
    { pattern: /"inno-app-replace-app"/, replacement: `"inno-app-${app}-app"` },
    { pattern: /"inno-replace-db"/, replacement: `"inno-${app}-db"` },
    { pattern: /"inno-replace-data"/, replacement: `"inno-${app}-data"` },
    { pattern: /("database_id"\s*:\s*)"REPLACE"/, replacement: `$1"${databaseId}"` },
  ]);
  return forceWorkersDevFalse(out, "app worker config");
}

if (isMainModule(import.meta.url)) {
  const [mode, ...rest] = process.argv.slice(2);
  if (mode === "--worker-gateway") {
    const [app, accessAud, path = "wrangler.jsonc"] = rest;
    if (!app || !accessAud) { console.error("Usage: node ci/template-wrangler.mjs --worker-gateway <app> <accessAud> [path]"); process.exit(1); }
    writeFileSync(path, templateWorkerGateway(readFileSync(path, "utf8"), { app, accessAud }));
    console.log(`templated worker gateway ${path} for app "${app}"`);
  } else if (mode === "--worker-app") {
    const [app, databaseId, path = "wrangler.jsonc"] = rest;
    if (!app || !databaseId) { console.error("Usage: node ci/template-wrangler.mjs --worker-app <app> <databaseId> [path]"); process.exit(1); }
    writeFileSync(path, templateWorkerApp(readFileSync(path, "utf8"), { app, databaseId }));
    console.log(`templated app worker ${path} for app "${app}"`);
  } else {
    const [app, databaseId, accessAud, wranglerPath = "wrangler.jsonc"] = [mode, ...rest];
    if (!app || !databaseId || !accessAud) {
      console.error("Usage: node ci/template-wrangler.mjs <app> <databaseId> <accessAud> [wranglerPath=wrangler.jsonc]");
      process.exit(1);
    }
    const templated = templateWrangler(readFileSync(wranglerPath, "utf8"), { app, databaseId, accessAud });
    writeFileSync(wranglerPath, templated);
    console.log(`templated ${wranglerPath} for app "${app}"`);
  }
}
