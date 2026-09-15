#!/usr/bin/env node
// Calls the platform broker's /deploy-complete endpoint after `wrangler
// deploy` succeeds, so the broker can attach the app's DNS/domain and mark
// the deployment (and app) as live.
//
// Usage: node ci/deploy-finalize.mjs <brokerUrl> <app> <deploymentId> <token> [gatewayRef] [imageId]
// `token` is the GitHub Actions OIDC token (verified server-side).
// `gatewayRef` records which promoted gateway build was injected into this
// deploy. `imageId` (R11) is the image id the deploy job actually loaded and
// pushed; the broker refuses to promote the staged SBOM if it doesn't match
// what the container job recorded.

import { brokerPost } from "./broker-post.mjs";
import { isMainModule } from "./cli.mjs";

/**
 * POST {app, deployment_id, gateway_ref?, image_id?} to `${base}/deploy-complete`, authenticated with
 * the GitHub Actions OIDC token.
 *
 * @param {string} base - broker base URL, e.g. "https://inno-platform.example.workers.dev"
 * @param {string} token - GitHub Actions OIDC token
 * @param {string} app
 * @param {number|string} deploymentId
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} fetcher
 *   - injectable for testing; defaults to global fetch
 * @param {string} [gatewayRef] - optional gateway reference
 * @param {string} [imageId] - the image id actually deployed (R11)
 * @returns {Promise<any>} the parsed JSON response body (e.g. { url })
 */
export async function finalize(base, token, app, deploymentId, fetcher = fetch, gatewayRef, imageId) {
  const body = {
    app, deployment_id: deploymentId,
    ...(gatewayRef ? { gateway_ref: gatewayRef } : {}),
    ...(imageId ? { image_id: imageId } : {}),
  };
  return brokerPost(
    { base, path: "/deploy-complete", label: "deploy-complete", token, body },
    fetcher,
  );
}

if (isMainModule(import.meta.url)) {
  try {
    const [base, app, deploymentId, token, gatewayRefArg, imageIdArg] = process.argv.slice(2);
    if (!base || !app || !deploymentId || !token) {
      throw new Error("Usage: node ci/deploy-finalize.mjs <brokerUrl> <app> <deploymentId> <token> [gatewayRef] [imageId]");
    }
    // `jq -r .deployment_id` on a missing field yields the literal string
    // "null", which is truthy above; Number("null") is NaN. Fail here with a
    // clear message instead of POSTing a malformed body to the broker.
    const deploymentIdNum = Number(deploymentId);
    if (!Number.isInteger(deploymentIdNum)) {
      throw new Error(`invalid deploymentId ${JSON.stringify(deploymentId)} — the broker's /deploy-token response may be malformed`);
    }
    const result = await finalize(base, token, app, deploymentIdNum, fetch, gatewayRefArg, imageIdArg);
    // Human-readable line to stderr; the raw JSON result to stdout, so the
    // workflow can capture stdout and pipe it straight into `jq -r .url`
    // instead of re-parsing this log line with sed.
    console.error(`deploy-complete: ${JSON.stringify(result)}`);
    console.log(JSON.stringify(result));
  } catch (err) {
    console.error(String(err?.message ?? err));
    process.exitCode = 1;
  }
}
