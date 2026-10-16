// jsonRequest: the text-first JSON request that brokerPost,
// scripts/cf-api.mjs's apiReq and ci/export-app.mjs's R2 list make through.
// It sends a JSON body when there is one, reads the response as text FIRST
// (so a non-2xx, non-JSON body, such as an HTML 500 page, surfaces the real
// status and body instead of a raw JSON parse error), throws
// `<label> failed (<status>): <200-character snippet>` on a non-2xx answer,
// and parses the body on success. Which of the files that import this one
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
// Zero imports on purpose: both helpers use the global fetch (injectable for
// tests), so nothing that imports them takes on a transitive dependency, and
// the mirror ships no extra file for them.

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
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @returns {Promise<any>} the parsed JSON response body, or null on an empty body
 * @throws {Error & { status: number, body: string }} on a non-2xx answer
 */
export async function jsonRequest({ url, method, headers, body, label }, fetcher = fetch) {
  const hasBody = body !== undefined;
  const res = await fetcher(url, {
    method,
    headers: { ...headers, ...(hasBody ? { "Content-Type": "application/json" } : {}) },
    ...(hasBody ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  if (!res.ok) {
    // The status and the whole body ride on the error beside the message, so a
    // caller can decide on the answer (deploy-finalize.mjs retries a 409
    // app_busy and nothing else) without parsing the message.
    throw Object.assign(new Error(`${label} failed (${res.status}): ${text.slice(0, 200)}`), {
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
 * @param {(url: string, init?: any) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>} [fetcher]
 *   - injectable for testing; defaults to global fetch
 * @returns {Promise<any>} the parsed JSON response body
 * @throws {Error & { status: number, body: string }} on a non-2xx answer
 * @throws {Error} on an empty 2xx body, or one that is the JSON null
 */
export async function brokerPost({ base, path, label, token, body }, fetcher = fetch) {
  let text = "";
  const answer = await jsonRequest(
    { url: `${base}${path}`, method: "POST", headers: { Authorization: `Bearer ${token}` }, body, label },
    async (url, init) => {
      const res = await fetcher(url, init);
      return { ok: res.ok, status: res.status, text: async () => (text = await res.text()) };
    },
  );
  if (answer === null) throw new Error(`${label} failed: ${text === "" ? "empty" : "JSON null"} response body`);
  return answer;
}
