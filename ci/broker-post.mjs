// jsonRequest: the text-first JSON request that brokerPost,
// scripts/cf-api.mjs's apiReq and ci/export-app.mjs's R2 list make through.
// It sends a JSON body when there is one, reads the response as text FIRST
// (so a non-2xx, non-JSON body, such as an HTML 500 page, surfaces the real
// status and body instead of a raw JSON parse error), throws
// `<label> failed (<status>): <error>: <message>` on a non-2xx answer that is
// a JSON refusal with a string `error` and `message` (the broker's shape, the
// message flattened and bounded at REFUSAL_MESSAGE_MAX_CHARS) and
// `<label> failed (<status>): <200-character snippet>` on any other, and
// parses the body on success. Which of the files that import this one
// ship in the public mirror is scripts/publish-mirror.sh's manifest
// (test-enforced), not a list kept here. The callers:
//   - brokerPost, below: the POST to a broker endpoint with the GitHub Actions
//     OIDC token as a bearer, which the ci/ scripts that report to the broker
//     share. Every broker endpoint answers a JSON object, so brokerPost
//     refuses an empty body, and a body that is the literal JSON `null`, each
//     with its own message, rather than let a report pass that the broker may
//     never have read.
//   - scripts/cf-api.mjs's apiReq, the operator scripts' Cloudflare API call.
//   - ci/export-app.mjs's R2 list. Its object GET stays raw: it streams the
//     body to disk.
//
// Every request is bounded: no answer, or no end to it, within the caller's
// timeoutMs (BROKER_TIMEOUT_MS when absent) throws
// `<label> failed: no answer within <n> s`, so a broker that accepts the
// connection and never answers cannot hold a job until its own timeout. The
// default is the short reports' (an SBOM, a sweep's or the dependency gate's
// results, an export's end, an R2 list, an operator script's Cloudflare
// call), whose answers are quick. The finalize waits longer on a bound of its
// own (ci/deploy-finalize.mjs FINALIZE_TIMEOUT_MS): a container app's answers
// only after the platform has rolled the image out and uploaded the host.
//
// One import on purpose, ./cli.mjs, for logSafe, the ci/ log sanitiser: it
// ships beside this file in the mirror manifest and imports only Node's own
// modules, so the mirror ships no extra file for these helpers and nothing
// that imports them takes on a dependency beyond Node. Both helpers use the
// global fetch, injectable for tests.
import { logSafe } from "./cli.mjs";

// The most of a refusal's message the thrown error carries: room for the
// longest the platform writes, a finalize's script_rejected quoting up to
// 2000 characters of Cloudflare's answer (src/clients/cloudflare.ts
// SCRIPT_UPLOAD_MAX_ERROR_BODY) after its own words.
export const REFUSAL_MESSAGE_MAX_CHARS = 4000;

// How long a request waits for its answer when its caller names no bound.
export const BROKER_TIMEOUT_MS = 180_000;

// What the thrown error says of a non-2xx answer. A JSON refusal with a string
// `error` and `message`, the shape every broker refusal takes, reads as
// `<error>: <message>`, so the log shows the platform's sentence (and, for a
// script_rejected, Cloudflare's reason for refusing the Worker upload) rather than
// its first 200 characters cut inside the JSON framing. Parsing turns the
// JSON's escapes back into the characters they stand for, a newline among
// them, which would start a forged workflow command in the run's log, so
// both fields pass through logSafe. Any other answer, an HTML error page or
// a refusal without both fields (`{"error":"app_busy"}`), is its first 200
// characters, as it always was.
function refusalText(text) {
  try {
    const j = JSON.parse(text);
    if (j && typeof j.error === "string" && typeof j.message === "string") {
      return `${logSafe(j.error)}: ${logSafe(j.message, REFUSAL_MESSAGE_MAX_CHARS)}`;
    }
  } catch { /* not JSON: the raw text below */ }
  return text.slice(0, 200);
}

/**
 * Send a JSON request and return the parsed JSON response.
 *
 * Reads the body as text first so a non-2xx, non-JSON body (e.g. an HTML 500
 * page) surfaces the real status and body instead of a raw JSON parse error.
 *
 * @param {object} req
 * @param {string} req.url - the full request URL
 * @param {string} req.method - e.g. "GET", "POST"
 * @param {Record<string, string>} req.headers - the caller's headers (auth); Content-Type is added when there is a body
 * @param {any} [req.body] - JSON.stringify'd as-is when present
 * @param {string} req.label - error-message prefix, e.g. "deploy-complete" -> "deploy-complete failed (...)"
 * @param {number} [req.timeoutMs] - how long to wait for the answer; BROKER_TIMEOUT_MS when absent
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @returns {Promise<any>} the parsed JSON response body, or null on an empty body
 * @throws {Error & { status: number, body: string }} on a non-2xx answer
 * @throws {Error} when no answer, or no end to it, arrives within timeoutMs
 */
export async function jsonRequest({ url, method, headers, body, label, timeoutMs = BROKER_TIMEOUT_MS }, fetcher = fetch) {
  const hasBody = body !== undefined;
  let res;
  let text;
  try {
    res = await fetcher(url, {
      method,
      headers: { ...headers, ...(hasBody ? { "Content-Type": "application/json" } : {}) },
      ...(hasBody ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(timeoutMs),
    });
    text = await res.text();
  } catch (e) {
    if (e?.name === "TimeoutError") throw new Error(`${label} failed: no answer within ${timeoutMs / 1000} s`);
    throw e;
  }
  if (!res.ok) {
    // The status and the whole body ride on the error beside the message, so a
    // caller can decide on the answer (deploy-finalize.mjs retries a 409
    // app_busy and nothing else) without parsing the message.
    throw Object.assign(new Error(`${label} failed (${res.status}): ${refusalText(text)}`), {
      status: res.status, body: text,
    });
  }
  return text ? JSON.parse(text) : null;
}

/**
 * POST a JSON body to `${base}${path}` on the platform broker, authenticated
 * with the GitHub Actions OIDC token, and return the parsed JSON response
 * (see jsonRequest for the read and the error shape). An empty 2xx body throws
 * `<label> failed: empty response body`: the broker always answers JSON, so
 * an empty one came from something else, and the caller's report may never
 * have reached it. jsonRequest answers null for a body that is the literal
 * JSON `null` too, which no broker route answers either; that one throws
 * `<label> failed: JSON null response body`, so the two read apart. The text
 * is read through a wrapper around the fetcher, since jsonRequest's answer
 * alone cannot tell them apart and its other callers rely on its null.
 *
 * @param {object} req
 * @param {string} req.base - broker base URL, e.g. "https://inno-platform.example.workers.dev"
 * @param {string} req.path - endpoint path beginning with "/", e.g. "/deploy-complete"
 * @param {string} req.label - error-message prefix, e.g. "deploy-complete" -> "deploy-complete failed (...)"
 * @param {string} req.token - GitHub Actions OIDC token
 * @param {any} req.body - request body, JSON.stringify'd as-is
 * @param {number} [req.timeoutMs] - how long to wait for the answer; BROKER_TIMEOUT_MS when absent
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @returns {Promise<any>} the parsed JSON response body
 * @throws {Error & { status: number, body: string }} on a non-2xx answer
 * @throws {Error} on an empty 2xx body, or one that is the JSON null, or no answer within timeoutMs
 */
export async function brokerPost({ base, path, label, token, body, timeoutMs }, fetcher = fetch) {
  let text = "";
  const answer = await jsonRequest(
    { url: `${base}${path}`, method: "POST", headers: { Authorization: `Bearer ${token}` }, body, label, timeoutMs },
    async (url, init) => {
      const res = await fetcher(url, init);
      return { ok: res.ok, status: res.status, text: async () => (text = await res.text()) };
    },
  );
  if (answer === null) throw new Error(`${label} failed: ${text === "" ? "empty" : "JSON null"} response body`);
  return answer;
}
