#!/usr/bin/env node
// Config-integrity gate: verifies an app repo has not weakened the security
// posture the platform requires — required CLAUDE.md guidance present, and no
// platform-owned build input vendored into the app repo (gateway source,
// worker build inputs, and ANY wrangler config; the platform injects all of
// them at build time from the promoted gateway.ref). See checkConfig's own
// note on the numbering: checks 2-6 (which inspected an app-owned
// wrangler.jsonc for auth mode and container image/limits) were retired when
// that file stopped being app-owned.
//
// Usage: node ci/check-config.mjs <app-dir>
// Exits 0 if compliant, 1 (with violations printed) otherwise.
//
// Zero npm dependencies: node:fs, node:path builtins plus the local (also
// zero-dependency) ci/cli.mjs helper only.

import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { isMainModule } from "./cli.mjs";

// Headers every app's CLAUDE.md must carry, regardless of deployment type.
const REQUIRED_CLAUDE_MD_HEADERS = [
  "## Innovation Platform App",
  "## Identity (do not build auth)",
  "## What CI enforces",
];

// Type-variant header groups: each group carries the same safety guidance for
// its runtime, and ANY member satisfies the gate. The gate stays
// deliberately type-blind — it must not depend on the broker's policy fetch
// (which can fall back to 'container' on an outage) to know which variant to
// demand, and pre-scaffold apps all carry the container member. "## Worker
// contract" is the legacy heading of "## Function contract" (the 'worker'
// preset was renamed 'function' 2026-07-30): scaffolds emit the new heading,
// but existing app repos keep their CLAUDE.md forever, so both satisfy.
const CLAUDE_MD_HEADER_VARIANTS = [
  ["## Persistence (use the storage client)", "## Persistence (use your bindings)"],
  ["## Container contract", "## Function contract", "## Worker contract"],
];

/**
 * Strip `//` and `/* *\/` comments from a JSONC string, without touching
 * `//` or `/*` sequences that appear inside string literals.
 */
export function stripJsonComments(text) {
  let out = "";
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];

    if (inLineComment) {
      if (ch === "\n") {
        inLineComment = false;
        out += ch;
      }
      continue;
    }

    if (inBlockComment) {
      if (ch === "*" && next === "/") {
        inBlockComment = false;
        i++;
      }
      continue;
    }

    if (inString) {
      out += ch;
      if (ch === "\\") {
        // preserve the escaped character verbatim (e.g. \" or \\)
        out += next;
        i++;
        continue;
      }
      if (ch === '"') inString = false;
      continue;
    }

    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === "/" && next === "/") {
      inLineComment = true;
      i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlockComment = true;
      i++;
      continue;
    }
    out += ch;
  }

  return out;
}


// Worker build-input files that are entirely template-owned: the app author
// has no legitimate reason to modify them (the app's own code lives in the
// CONTAINER under app/, not in the worker), and `npm ci` + `wrangler deploy`
// both execute code sourced from these files while the deploy job holds an
// account-wide Cloudflare token. Pinned byte-identical to the template.
// Mirrored by the template-drift reverse-walk job in
// .github/workflows/ci.yml — update both together.
const PINNED_BUILD_INPUT_FILES = ["package.json", "package-lock.json", "tsconfig.json"];

// wrangler discovers its config in the app root as `wrangler.json ??
// wrangler.jsonc ?? wrangler.toml`, honoring env-variants too. The platform
// injects the ONLY permitted config (wrangler.jsonc, from the promoted
// gateway.ref) at deploy time — so ANY wrangler config committed to an app
// repo is a shadow/bypass and is rejected. `--config wrangler.jsonc` at
// deploy pins the file as the belt to this suspenders.
// Matches a wrangler config file we must reject: the bare `wrangler.json` /
// `wrangler.toml`, or any env-variant `wrangler.<something>.(json|jsonc|toml)`.
// wrangler.jsonc itself never matches (no middle segment, and .jsonc is only
// reached via the env-variant arm which requires a `.<env>.` in between).
const COMPETING_WRANGLER_RE = /^wrangler\.(json|toml|.+\.(json|jsonc|toml))$/;

/**
 * Check that `appDir` (a registered app repo) complies with the platform's
 * config-integrity requirements. Everything platform-owned (gateway source,
 * worker build inputs, wrangler.jsonc) is INJECTED at build time from the
 * promoted gateway.ref — this gate verifies the repo does not carry shadow
 * copies, plus the repo-local rules (CLAUDE.md headers, no package-manager
 * config, no wrangler cache dirs).
 *
 * (Check numbering has gaps — 1, 1b, 7, 7b, 8: checks 2–6 were retired when
 * wrangler.jsonc stopped being app-owned. The survivors keep their original
 * numbers so existing references don't shift.)
 *
 * @param {string} appDir
 * @returns {{ok: boolean, violations: string[]}}
 */
export function checkConfig(appDir) {
  const violations = [];

  // --- Check 1: CLAUDE.md has the shared headers + one of each variant pair ---
  const claudeMdPath = join(appDir, "CLAUDE.md");
  if (!existsSync(claudeMdPath)) {
    violations.push("CLAUDE.md is missing");
  } else {
    const claudeMd = readFileSync(claudeMdPath, "utf8");
    for (const header of REQUIRED_CLAUDE_MD_HEADERS) {
      if (!claudeMd.includes(header)) {
        violations.push(`CLAUDE.md is missing required header: "${header}"`);
      }
    }
    for (const pair of CLAUDE_MD_HEADER_VARIANTS) {
      if (!pair.some((h) => claudeMd.includes(h))) {
        violations.push(`CLAUDE.md is missing a required header (any variant): ${pair.map((h) => `"${h}"`).join(" or ")}`);
      }
    }
  }

  // --- Check 1b: no wrangler config file at all in the app root ---
  // NO wrangler config may exist here — the platform injects the only
  // permitted one at deploy time from the promoted gateway.ref. Anything
  // committed could be silently preferred by `wrangler deploy`'s discovery
  // order (wrangler.json OUTRANKS wrangler.jsonc), which is why this gate
  // rejects rather than inspects: it vets none of them.
  //
  // The deploy step pins --config wrangler.jsonc (hard override of wrangler's
  // discovery + redirect); this gate check is the independent belt to that
  // suspenders — keep both. Rejecting .wrangler/ closes the redirect
  // (.wrangler/deploy/config.json) path that would reopen the bypass if
  // --config were ever dropped.
  if (existsSync(appDir)) {
    for (const entry of readdirSync(appDir, { withFileTypes: true })) {
      const name = entry.name;
      if (name === ".wrangler" && (entry.isDirectory() || entry.isSymbolicLink())) {
        violations.push(
          `.wrangler/ must not be committed — it is a wrangler-generated cache/redirect directory ` +
            `(.wrangler/deploy/config.json can redirect the deploy to an unvetted config)`,
        );
        continue;
      }
      if (name === "wrangler.jsonc") {
        violations.push(
          "delete wrangler.jsonc — the platform injects wrangler.jsonc at build time from the promoted gateway.ref " +
            "(see APP-CONTRACT R7 — get_app_contract, or docs/APP-CONTRACT.md)",
        );
        continue;
      }
      if (COMPETING_WRANGLER_RE.test(name)) {
        violations.push(
          `${name} is a wrangler config file — apps may not carry ANY wrangler config; the platform injects it ` +
            `(wrangler's config discovery could silently prefer it over the gate-vetted file)`,
        );
      }
      // A committed .npmrc / .yarnrc(.yml) is an unpinned input to `npm ci` in
      // the deploy job — it can redirect the registry, set install flags, or
      // enable lifecycle behavior. The package-lock is byte-pinned and the
      // deploy runs --ignore-scripts, so no exploit is proven, but these files
      // have no legitimate reason to exist in an app repo: reject them.
      // wrangler loads .env/.env.* from cwd at CLI startup, and env keys the
      // deploy step doesn't set are ADOPTED — a committed .env with
      // CLOUDFLARE_API_BASE_URL (or WRANGLER_DOCKER_BIN/DOCKER_HOST) redirects
      // API calls, bearer token included, to an attacker host. Reject like
      // .npmrc: an unpinned deploy-build input. (2026-07-22 review find.)
      if (/^\.env(\..+)?$/.test(name)) {
        violations.push(
          `${name} must not be committed — wrangler loads .env files at deploy time (an app-set ` +
            `CLOUDFLARE_API_BASE_URL would redirect API calls, account token included); remove it`,
        );
        continue;
      }
      if (/^\.(npmrc|yarnrc)(\.yml)?$/.test(name)) {
        violations.push(
          `${name} must not be committed — package manager config is an unpinned deploy-build input; remove it`,
        );
      }
    }
  }

  // --- Check 7: src/gateway/ must NOT exist — the platform injects the ---
  // promoted gateway (config gateway.ref) at build time; a vendored copy
  // would shadow it and is always stale. No legacy acceptance.
  // lstat (not existsSync): a dangling symlink must fail closed too — same
  // rule as check 8 below.
  let gatewayPresent = false;
  try { lstatSync(join(appDir, "src", "gateway")); gatewayPresent = true; } catch {}
  if (gatewayPresent) {
    violations.push(
      "delete src/gateway/ — the platform injects the gateway at build time (see APP-CONTRACT R7 — get_app_contract, or docs/APP-CONTRACT.md)",
    );
  }

  // --- Check 7b: scaffold/ must NOT exist — registration prunes the ---
  // deployment-type scaffolds out of every app repo; a surviving
  // scaffold/ means the prune failed (or the template was copied by hand)
  // and the repo is carrying BOTH variants' files.
  //
  // EXCEPT while app/.needs-build exists: the template-generation commit (the
  // user's "Use this template") fires its own
  // CI run before registration's prune commit lands, and that run checks out
  // the pristine, unpruned template — failing it would redline every new
  // app's very first run for a transient state that only exists until
  // registration's prune commit lands. The marker is the platform's existing
  // "not an app yet" signal (scaffold-check skips deploys on it), and deleting
  // it to start building re-arms this check; a genuinely failed prune can't
  // deploy anyway (registration halts before the deploy prerequisites exist).
  let scaffoldPresent = false;
  try { lstatSync(join(appDir, "scaffold")); scaffoldPresent = true; } catch {}
  if (scaffoldPresent && !existsSync(join(appDir, "app", ".needs-build"))) {
    violations.push(
      "delete scaffold/ — the deployment-type scaffold directory is template-only; registration prunes it out of app repos",
    );
  }

  // --- Check 8: worker build inputs must NOT exist — the platform injects ---
  // package.json / package-lock.json / tsconfig.json at build time from the
  // promoted gateway ref; a vendored copy would shadow them and is always
  // stale. No legacy acceptance.
  //
  // Presence is an lstat, not existsSync: existsSync FOLLOWS symlinks, so a
  // dangling symlink named e.g. package.json (target absent) reports false
  // and would silently pass this check even though something occupies the
  // name. lstat never follows the link, so ANYTHING at the path — a file, a
  // directory, or a symlink of any kind (dangling included) — is caught.
  for (const relPath of PINNED_BUILD_INPUT_FILES) {
    let present = false;
    try {
      lstatSync(join(appDir, relPath));
      present = true;
    } catch {
      // ENOENT: nothing at this path — compliant.
    }
    if (present) {
      violations.push(
        `delete ${relPath} — the platform injects worker build inputs at build time (see APP-CONTRACT R7 — get_app_contract, or docs/APP-CONTRACT.md)`,
      );
    }
  }

  return { ok: violations.length === 0, violations };
}

// --- CLI wrapper ---
if (isMainModule(import.meta.url)) {
  const [appDir] = process.argv.slice(2);
  if (!appDir) {
    console.error("Usage: node ci/check-config.mjs <app-dir>");
    process.exit(1);
  }

  const { ok, violations } = checkConfig(appDir);
  if (!ok) {
    console.error("config-integrity check FAILED:");
    for (const violation of violations) console.error(`  - ${violation}`);
    process.exit(1);
  }
  console.log("config-integrity check passed.");
}
