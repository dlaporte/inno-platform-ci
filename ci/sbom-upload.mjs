#!/usr/bin/env node
// Uploads the container job's freshly generated CycloneDX SBOM to the
// platform broker's /deploy-sbom endpoint, which STAGES it keyed by this
// run's verified OIDC run_id claim. /deploy-complete (same run) later
// promotes it to the app's live SBOM pointer, so the safety sweep always
// scans what actually deployed.
//
// `imageId` (R11) is the scanned image's own config digest
// (`docker image inspect --format '{{.Id}}'`), staged alongside the SBOM so
// the deploy job can prove it later loaded and pushed that SAME image rather
// than a rebuild.
//
// Not best-effort (R7-1, v0.17.4): this upload is the one place a run records
// the scanned image's id, and the broker refuses the deploy job's token
// request for a run that recorded none. So the CLI fails its step on any
// failure, with one ::error annotation that carries the broker's refusal
// (flattened by logSafe, so a refusal's text cannot start a workflow command
// of its own), and exits 1. A refusal that carries the broker's own sentence
// (sbom_too_large, app_stopped, repo_unlinked) says what to do, so the line
// adds no remedy of its own: for an SBOM over the cap, re-running the release's
// workflow would rebuild the same image and meet the same refusal. Any other
// failure (no answer, a 5xx, a refusal with no sentence, an unreadable SBOM
// file) ends with the CLI's remedy, re-running the release's workflow. The
// tenant workflow runs it on a release tag only (platform-ci.yml, "Upload
// SBOM and image id to broker").
//
// Usage: node ci/sbom-upload.mjs <brokerUrl> <app> <sbomPath> <token> [imageId]
// `token` is the GitHub Actions OIDC token (verified server-side).

import { readFile } from "node:fs/promises";
import { brokerPost } from "./broker-post.mjs";
import { isMainModule, logSafe } from "./cli.mjs";

/**
 * POST {app, sbom, image_id?} to `${base}/deploy-sbom`, authenticated with the
 * GitHub Actions OIDC token.
 *
 * @param {string} base - broker base URL
 * @param {string} token - GitHub Actions OIDC token
 * @param {string} app
 * @param {object} sbom - parsed CycloneDX document
 * @param {string} [imageId] - the scanned image's config digest (R11)
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} fetcher
 *   - injectable for testing; defaults to global fetch
 * @returns {Promise<any>} the parsed JSON response body (e.g. { stored })
 */
export async function uploadSbom(base, token, app, sbom, imageId, fetcher = fetch) {
  return brokerPost(
    { base, path: "/deploy-sbom", label: "deploy-sbom", token, body: { app, sbom, ...(imageId ? { image_id: imageId } : {}) } },
    fetcher,
  );
}

/**
 * True for a refusal that carries the broker's own sentence: a 4xx whose JSON
 * body has a string `error` and `message` (the shape broker-post.mjs prints as
 * `<error>: <message>`). A 5xx is never one: whatever it says, the remedy is
 * to run again.
 *
 * @param {any} err - what uploadSbom threw
 * @returns {boolean}
 */
export function carriesBrokerSentence(err) {
  if (typeof err?.status !== "number" || err.status >= 500 || typeof err.body !== "string") return false;
  try {
    const j = JSON.parse(err.body);
    return !!j && typeof j.error === "string" && typeof j.message === "string";
  } catch {
    return false;
  }
}

if (isMainModule(import.meta.url)) {
  try {
    const [base, app, sbomPath, token, imageId] = process.argv.slice(2);
    if (!base || !app || !sbomPath || !token) {
      throw new Error("Usage: node ci/sbom-upload.mjs <brokerUrl> <app> <sbomPath> <token> [imageId]");
    }
    let sbom;
    try {
      sbom = JSON.parse(await readFile(sbomPath, "utf8"));
    } catch (err) {
      throw new Error(`could not read/parse SBOM at ${sbomPath}: ${String(err?.message ?? err)}`);
    }
    const result = await uploadSbom(base, token, app, sbom, imageId);
    console.log(`deploy-sbom: ${JSON.stringify(result)}`);
  } catch (err) {
    const message = logSafe(String(err?.message ?? err), 600);
    console.error(carriesBrokerSentence(err)
      ? `::error title=SBOM upload failed::${message}`
      : `::error title=SBOM upload failed::${message}; this release cannot deploy without it: ` +
        "fix what the message names, then re-run the release's workflow");
    process.exitCode = 1;
  }
}
