#!/usr/bin/env node
// Normalizes `npm audit --json` output to the platform's SweepFinding shape,
// in two roles:
//   gate <auditJson>                          — CI deploy gate: exit 1 if any
//     HIGH/CRITICAL advisory survives the $IGNORES list (space-separated ids).
//     This is what lets safety.ignore.deps.* apply to npm the way it already
//     applies to pip-audit — without it, a sweep-side ignore still bricks
//     every future deploy.
//   post <base> <app> <deploymentId> <auditJson> [token] — safety-sweep lane:
//     POST ALL normalized findings to /sweep/deps-results; the Worker is the
//     policy brain (floor + ignores) exactly as with trivy results.
// A top-level `error` in the audit JSON means npm audit DID NOT RUN — that is
// a hard failure in both roles, never "clean".

import { readFile } from "node:fs/promises";
import { brokerPost } from "./broker-post.mjs";
import { isMainModule } from "./cli.mjs";

const RANK = { CRITICAL: 0, HIGH: 1, MODERATE: 2, LOW: 3, INFO: 4 };

/**
 * Flatten `npm audit --json` (auditReportVersion 2) into SweepFinding rows —
 * one per advisory id (string vias are transitive refs, skipped), severity
 * uppercased, CRITICAL-first, capped at 200. Throws when the report carries a
 * top-level `error` (npm audit did not run — never "clean").
 *
 * @param {any} audit - parsed `npm audit --json` output
 * @returns {Array<{id: string, pkg?: string, fixed?: string, severity: string, title?: string}>}
 */
export function normalize(audit) {
  if (audit && typeof audit === "object" && audit.error) {
    const e = audit.error;
    throw new Error(`npm audit did not run: ${e.code ?? ""} ${e.summary ?? ""}`.trim());
  }
  const byId = new Map();
  for (const v of Object.values(audit?.vulnerabilities ?? {})) {
    for (const via of v.via ?? []) {
      if (typeof via !== "object" || via === null) continue; // string vias are transitive refs
      const tail = typeof via.url === "string" ? via.url.split("/").pop() : "";
      const id = tail && tail.startsWith("GHSA-") ? tail : String(via.source ?? "");
      if (!id || byId.has(id)) continue;
      const fix = v.fixAvailable;
      byId.set(id, {
        id,
        pkg: typeof via.name === "string" ? via.name : undefined,
        fixed: fix && typeof fix === "object" ? `${fix.name}@${fix.version}` : undefined,
        severity: String(via.severity ?? v.severity ?? "").toUpperCase(),
        title: typeof via.title === "string" ? via.title.slice(0, 120) : undefined,
      });
    }
  }
  return [...byId.values()]
    .sort((a, b) => (RANK[a.severity] ?? 9) - (RANK[b.severity] ?? 9))
    .slice(0, 200);
}

/**
 * The deploy gate's verdict filter: HIGH/CRITICAL advisories not ignored.
 *
 * @param {ReturnType<typeof normalize>} findings
 * @param {string[]} ignores - advisory ids from safety.ignore.deps.*
 * @returns {ReturnType<typeof normalize>}
 */
export function gateSurvivors(findings, ignores) {
  return findings.filter((f) =>
    (f.severity === "HIGH" || f.severity === "CRITICAL") && !ignores.includes(f.id));
}

if (isMainModule(import.meta.url)) {
  try {
    const [mode, ...args] = process.argv.slice(2);
    if (mode === "gate") {
      const [auditPath] = args;
      if (!auditPath) throw new Error("Usage: deps-normalize.mjs gate <auditJson>  (env IGNORES = space-separated ids)");
      const findings = normalize(JSON.parse(await readFile(auditPath, "utf8")));
      const ignores = (process.env.IGNORES ?? "").split(/\s+/).filter(Boolean);
      const survivors = gateSurvivors(findings, ignores);
      const ignored = findings.filter((f) => ignores.includes(f.id)).map((f) => f.id);
      if (ignored.length) console.log(`ignores honored: ${ignored.join(", ")}`);
      if (survivors.length) {
        console.error(`::error title=Dependency gate::${survivors.length} HIGH/CRITICAL advisories: ` +
          survivors.map((f) => `${f.id}${f.pkg ? ` (${f.pkg})` : ""}`).join(", "));
        process.exitCode = 1;
      } else {
        console.log(`dependency gate clean (${findings.length} total advisories below floor or ignored)`);
      }
    } else if (mode === "post") {
      const [base, app, deploymentId, auditPath, tokenArg] = args;
      const token = tokenArg ?? process.env.ACTIONS_ID_TOKEN;
      if (!base || !app || !deploymentId || !auditPath || !token) {
        throw new Error("Usage: deps-normalize.mjs post <base> <app> <deploymentId> <auditJson> [token]");
      }
      const deploymentIdNum = Number(deploymentId);
      if (!Number.isInteger(deploymentIdNum)) throw new Error(`invalid deploymentId ${JSON.stringify(deploymentId)}`);
      const findings = normalize(JSON.parse(await readFile(auditPath, "utf8")));
      const result = await brokerPost(
        { base, path: "/sweep/deps-results", label: "deps-results", token,
          body: { app, deployment_id: deploymentIdNum, findings } },
      );
      console.log(`deps-results: ${JSON.stringify(result)}`);
    } else {
      throw new Error(`unknown mode ${JSON.stringify(mode)} — use "gate" or "post"`);
    }
  } catch (err) {
    console.error(String(err?.message ?? err));
    process.exitCode = 1;
  }
}
