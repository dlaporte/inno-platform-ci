// Shared "am I the script node was told to run?" guard for every ci/ and
// scripts/ CLI's main block. Lives on its own, apart from broker-post.mjs, so
// a script can take the guard without the request helper.
// The other ci/ helpers every script may need live here too, among them the
// reader of the instance's names (loadInstanceData), so the mirror ships no
// extra file for them.
//
// Fixed here, twice. The old broker-post.mjs version compared
// `importMetaUrl === \`file://${process.argv[1]}\``, a hand-built template
// that breaks for any argv[1] path needing percent-encoding (spaces, etc.):
// file URLs percent-encode such characters, so the template never matched
// and the CLI block silently did nothing. The pathToFileURL(argv[1]) form
// that replaced it missed every symlinked path (isMainModule says why). Both
// sides are now compared as real file paths, and fileURLToPath undoes
// exactly the encoding Node's own import.meta.url applies.
import { readFileSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// A path with its symlinks resolved, or the path itself when it does not
// exist (a caller's argv can name anything).
const realPath = (p) => {
  try { return realpathSync(p); } catch { return resolve(p); }
};

/**
 * True when the module whose `import.meta.url` is passed is the entry point node
 * was invoked with (i.e. run directly, not imported). Callers pass their OWN
 * `import.meta.url` because it is lexically bound to the calling module.
 *
 * Compared as real paths on both sides. Node resolves symlinks in the main
 * module's import.meta.url but leaves argv[1] as typed, so a script run
 * through a symlinked path (anything under macOS's /var, or a checkout
 * reached through a link) compared unequal, and its CLI block silently did
 * nothing and exited 0.
 *
 * @param {string} importMetaUrl - the caller's import.meta.url
 * @returns {boolean}
 */
export function isMainModule(importMetaUrl) {
  if (!process.argv[1]) return false;
  return realPath(fileURLToPath(importMetaUrl)) === realPath(process.argv[1]);
}

/**
 * Parse a numeric CLI argument the workflow read out of a JSON response with
 * `jq -r`. A missing field reaches the shell as the literal string "null",
 * which is truthy in an argv presence check and NaN through Number(), and
 * JSON.stringify then serialises that NaN as null: the broker answers 400
 * bad_request and the log names the wrong side. Every id the ci/ scripts
 * POST goes through here so the failure is local and says which argument.
 *
 * @param {string} label - the argument's name in the usage line, e.g. "deploymentId"
 * @param {string|undefined} raw - the argv value
 * @returns {number}
 */
export function parseIntegerArg(label, raw) {
  const n = Number(raw);
  if (typeof raw !== "string" || raw.trim() === "" || !Number.isInteger(n)) {
    throw new Error(`invalid ${label} ${JSON.stringify(raw)}: expected an integer (a field missing from the JSON the workflow read reaches the shell as the literal "null")`);
  }
  return n;
}

/**
 * Flatten control bytes out of a value and bound its length, for anything a
 * ci/ script interpolates into a GitHub Actions log line or, especially, into
 * a workflow command.
 *
 * A workflow command (`::warning title=...::`, `::error ...::`) is terminated
 * by a newline, so an author-controlled value carrying one forges a clean
 * second command line in the run's log. Node's JSON.parse error message
 * embeds a snippet of the RAW input, newlines and all, and a package name or
 * an advisory id is read out of the app's own repository before npm or pip
 * has validated anything. Every such interpolation goes through here first.
 *
 * CROSS-BUILD TWIN of `flattenControl` in `src/util.ts`. It cannot import it:
 * ci/ ships standalone to the public mirror repo and imports nothing from
 * src/, by standing constraint (ci/broker-post.mjs's header states the same
 * rule for the broker helper). test/constant-parity.node.test.ts pins the two
 * to the same behaviour. The length bound is this side's own addition,
 * because every caller here is writing exactly one log line, whereas src/
 * leaves the bound to each caller.
 *
 * The character class is written as ESCAPES, never as raw bytes: an editing
 * tool flattened this exact class into literal control bytes on 2026-09-18,
 * where it stayed invisible to tsc and to the whole suite. A scan of the
 * committed bytes is the only instrument that finds that, and
 * test/control-bytes.node.test.ts is that scan.
 *
 * @param {unknown} s - the value to flatten
 * @param {number} [n] - maximum length of the result
 * @returns {string}
 */
export const logSafe = (s, n = 200) => String(s).replace(/[\u0000-\u001f\u007f]+/g, " ").slice(0, n);

// --- The instance's names ---------------------------------------------------
// Tenant CI's copy of the one instance value it reads: ci/instance.json,
// which scripts/instance.mjs generates from the instance manifest and the
// publish mirror ships beside these scripts. The accessibility scanner builds
// its synthetic member's group header from the group prefix, and spells no
// name of its own.

// The rule, restated from src/instance.ts (itself restated from
// scripts/lib/manifest.mjs): ci/ ships standalone and imports nothing from
// either. It matters beyond tidiness: the value lands in a request header the
// scanner sends, so the rule is also what keeps a control byte or a quote out
// of it. test/instance-formula-parity.node.test.ts holds it to the Worker's,
// verdict for verdict.
const INSTANCE_RULES = {
  groupPrefix: /^[a-z0-9][a-z0-9-]*-$/,
};

/**
 * @typedef {Readonly<Record<keyof typeof INSTANCE_RULES, string>>} InstanceData
 */

/**
 * Check instance data and return its value, frozen, without any other key.
 * Throws naming the source and the key when it is missing or breaks its rule.
 *
 * @param {unknown} data
 * @param {string} [source] - where the data came from, for the message
 * @returns {InstanceData}
 */
export function checkInstanceData(data, source = "the instance data") {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error(`${source}: the instance data must be a JSON object (ci/instance.json's shape)`);
  }
  /** @type {Record<string, string>} */
  const out = {};
  for (const [key, rule] of Object.entries(INSTANCE_RULES)) {
    const v = /** @type {Record<string, unknown>} */ (data)[key];
    if (typeof v !== "string" || !rule.test(v)) {
      throw new Error(`${source}: ${key} ${v === undefined ? "is missing" : `${JSON.stringify(logSafe(v, 60))} does not match ${rule}`}`);
    }
    out[key] = v;
  }
  return Object.freeze(/** @type {InstanceData} */ (out));
}

/**
 * Read the instance data, from the first of: `path` (a script's
 * --instance flag), the env var INNO_INSTANCE_JSON (the data itself, as
 * JSON; empty counts as unset), and the ci/instance.json beside this file.
 * The last is resolved from this module's own location, not the working
 * directory, because tenant CI runs the scripts as
 * `node inno-platform-ci/ci/<script>` from its own checkout, and the
 * accessibility scanner as /ci/a11y-scan.mjs inside its container.
 *
 * @param {{ path?: string, env?: Record<string, string | undefined> }} [opts]
 * @returns {InstanceData}
 */
export function loadInstanceData({ path, env = process.env } = {}) {
  let source;
  let text;
  if (path) {
    source = path;
    try { text = readFileSync(path, "utf8"); } catch (e) { throw new Error(`${source}: cannot read the instance data (${logSafe(e && e.code ? e.code : e, 40)})`); }
  } else if (env.INNO_INSTANCE_JSON) {
    source = "INNO_INSTANCE_JSON";
    text = env.INNO_INSTANCE_JSON;
  } else {
    source = fileURLToPath(new URL("./instance.json", import.meta.url));
    try { text = readFileSync(source, "utf8"); } catch (e) { throw new Error(`${source}: cannot read the instance data (${logSafe(e && e.code ? e.code : e, 40)})`); }
  }
  let data;
  try { data = JSON.parse(text); } catch { throw new Error(`${source}: the instance data is not valid JSON`); }
  return checkInstanceData(data, source);
}
