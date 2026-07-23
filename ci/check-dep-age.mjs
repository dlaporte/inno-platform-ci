#!/usr/bin/env node
// Dependency-cooldown gate (supply-chain hygiene): flags app dependencies whose
// pinned version was published fewer than `min_release_age_days` days ago. A
// freshly-published version is the highest-risk window for a compromised
// release (typosquat, hijacked maintainer, malicious postinstall) — a short
// cooldown lets the ecosystem and scanners catch most of those before an app
// can pull them. Complements the existing deps gate (npm/pip-audit catch
// KNOWN-vulnerable versions; this catches TOO-NEW ones no one has vetted yet).
//
// Usage: node ci/check-dep-age.mjs <app-dir>
//   env MIN_RELEASE_AGE_DAYS  threshold in days (0 or unset => gate disabled)
// Exits 0 if compliant or disabled, 1 (with violations printed) otherwise.
//
// Scans exact pins only — app/requirements.txt (`name==version`) via PyPI and
// app/package-lock.json (resolved versions) via the npm registry. Ranges and
// un-pinned deps are skipped (nothing to date). A registry lookup that fails or
// returns no date is skipped with a warning rather than failing the deploy: a
// registry hiccup must not block a release, and the known-vulnerable gate still
// runs regardless. Zero npm dependencies: node builtins + local cli.mjs only.

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { isMainModule } from "./cli.mjs";

const DAY_MS = 86_400_000;

// --- Pure parsers -----------------------------------------------------------

// Exact-pinned PyPI requirements only (`name==version`). Skips comments, blank
// lines, includes (`-r`/`-c`), options (`--…`), and any non-`==` specifier
// (ranges have no single publish date to check).
export function parseRequirements(text) {
  const out = [];
  for (const raw of String(text).split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line || line.startsWith("-")) continue;
    const m = /^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._!+-]+)$/.exec(line);
    if (m) out.push({ ecosystem: "pypi", name: m[1].toLowerCase(), version: m[2] });
  }
  return out;
}

// Resolved versions from an npm lockfile (v2/v3 `packages` map). The root
// package (key "") and link/workspace entries (no version) are skipped.
export function parseNpmLock(json) {
  const out = [];
  const pkgs = json && json.packages ? json.packages : {};
  for (const [path, info] of Object.entries(pkgs)) {
    if (!path || !info || typeof info.version !== "string") continue;
    const name = path.split("node_modules/").pop();
    if (name) out.push({ ecosystem: "npm", name, version: info.version });
  }
  return out;
}

// Pure age decision: given entries carrying a resolved publishedAt (ms epoch),
// return the ones younger than the threshold. Entries with a null publishedAt
// were unresolved upstream and are NOT violations here (they surface as
// `skipped`). ageDays is floored for a stable, readable report.
export function evaluateAges(entries, thresholdDays, nowMs) {
  const violations = [];
  for (const e of entries) {
    if (typeof e.publishedAt !== "number") continue;
    const ageDays = Math.floor((nowMs - e.publishedAt) / DAY_MS);
    if (ageDays < thresholdDays) {
      violations.push({ name: e.name, version: e.version, ecosystem: e.ecosystem, ageDays });
    }
  }
  return violations;
}

// --- Registry lookups (I/O; injectable for tests) ---------------------------

async function pypiPublishedAt(fetchImpl, name, version) {
  const res = await fetchImpl(`https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`);
  if (!res.ok) return null;
  const data = await res.json();
  const times = (data.urls || []).map((u) => Date.parse(u.upload_time_iso_8601)).filter((t) => !Number.isNaN(t));
  return times.length ? Math.min(...times) : null;
}

async function npmPublishedAt(fetchImpl, name, version) {
  const res = await fetchImpl(`https://registry.npmjs.org/${name.replace("/", "%2F")}`);
  if (!res.ok) return null;
  const data = await res.json();
  const iso = data.time && data.time[version];
  const t = iso ? Date.parse(iso) : NaN;
  return Number.isNaN(t) ? null : t;
}

export async function resolvePublishTimes(entries, fetchImpl) {
  const resolved = [];
  const skipped = [];
  for (const e of entries) {
    let publishedAt = null;
    try {
      publishedAt = e.ecosystem === "pypi"
        ? await pypiPublishedAt(fetchImpl, e.name, e.version)
        : await npmPublishedAt(fetchImpl, e.name, e.version);
    } catch {
      publishedAt = null;
    }
    if (publishedAt === null) skipped.push(e);
    resolved.push({ ...e, publishedAt });
  }
  return { resolved, skipped };
}

// --- Orchestration ----------------------------------------------------------

export async function checkDepAge({ appDir, thresholdDays, fetchImpl = fetch, nowMs = Date.now(), readManifest }) {
  const read = readManifest ?? ((p) => (existsSync(p) ? readFileSync(p, "utf8") : null));
  const entries = [];

  const reqs = read(join(appDir, "requirements.txt"));
  if (reqs) entries.push(...parseRequirements(reqs));

  const lock = read(join(appDir, "package-lock.json"));
  if (lock) {
    try { entries.push(...parseNpmLock(JSON.parse(lock))); } catch { /* malformed lock: nothing to date */ }
  }

  if (entries.length === 0) return { violations: [], checked: 0, skipped: [] };

  const { resolved, skipped } = await resolvePublishTimes(entries, fetchImpl);
  const violations = evaluateAges(resolved, thresholdDays, nowMs);
  return { violations, checked: resolved.length, skipped };
}

// --- CLI --------------------------------------------------------------------

async function main() {
  const appDir = process.argv[2] || "app";
  const thresholdDays = Number(process.env.MIN_RELEASE_AGE_DAYS || 0);
  if (!Number.isFinite(thresholdDays) || thresholdDays <= 0) {
    console.log("dep-age: min_release_age_days is 0 — cooldown gate disabled, nothing to check.");
    return 0;
  }
  const { violations, checked, skipped } = await checkDepAge({ appDir, thresholdDays });
  for (const s of skipped) {
    console.log(`::warning title=Dependency age unknown::${s.ecosystem}:${s.name}@${s.version} — no publish date from the registry; skipped`);
  }
  if (violations.length === 0) {
    console.log(`dep-age: ${checked} pinned dependency version(s) checked; all at least ${thresholdDays} day(s) old.`);
    return 0;
  }
  console.error(`dep-age: ${violations.length} dependency version(s) younger than the ${thresholdDays}-day cooldown:`);
  for (const v of violations) {
    console.error(`  - ${v.ecosystem}:${v.name}@${v.version} published ${v.ageDays} day(s) ago`);
  }
  console.error("Pin an older, vetted version, or ask a platform admin to lower safety.min_release_age_days for this app.");
  return 1;
}

if (isMainModule(import.meta.url)) {
  main().then((code) => process.exit(code)).catch((e) => { console.error(e); process.exit(1); });
}
