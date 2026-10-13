// Capability 1 (CAPABILITY.md): the browser path asks the platform whether a
// signed-in person may use this app. Access proves who the person is; the
// platform's own member list and the app's open flag decide whether they get
// in (design B1, B9). index.ts calls this after verifyAccessJwt succeeds for
// a person, never for the health probe's service token, which has no person
// to ask about.
//
// The platform's answers (src/routes/access-check.ts) are both 200:
//   allow:   { allow: true,  groups, ttl: 10 }
//   refusal: { allow: false, groups: [], ttl: 2 }, the same bytes for every cause.
// Anything else is an OUTAGE, not a decision: a thrown binding call, a
// non-200, or a body that is not one of those shapes. The gateway fails
// closed on an outage (B6): the person is refused, and the miss is never
// held, so the next request asks again rather than reusing it.
//
// The cache is per isolate, keyed by host and email, and holds each answer
// for the ttl the platform sent with it, as mcp-auth.ts's introspection cache
// holds a token: a Map, never the Workers Cache API (the reason is in
// mcp-auth.ts's header), bounded in size, dropping the oldest entry first.
// A refusal is held too, for its shorter ttl, unlike a negative
// introspection: every request of a refused person would otherwise cost a
// platform call. The email is the one verifyAccessJwt just verified, so a
// held answer is only ever reused for the person it was given about.
import { errLine } from "./log-text";
import { GATEWAY_KEY_HEADER, PLATFORM_ORIGIN } from "./platform";

// Hand-written twin of src/routes/access-check.ts's ACCESS_CHECK_PATH
// (gateway/ builds separately and cannot import it), pinned by
// test/constant-parity.node.test.ts.
export const ACCESS_CHECK_PATH = "/_access/check";

// Bound the isolate's memory, as mcp-auth.ts's MAX_CACHE_ENTRIES does. Far
// above the people one app's isolate sees inside a 10-second window.
export const MAX_ACCESS_CACHE_ENTRIES = 1000;

// The longest any answer is held, whatever ttl arrives with it. The platform
// sends 10 and 2; this ceiling keeps a platform bug or a future value from
// stretching how long a revoked person keeps getting in. It matches
// mcp-auth.ts's MAX_CACHE_SECONDS, the introspection cache's ceiling.
export const MAX_ACCESS_CACHE_SECONDS = 60;

export type AccessAnswer =
  | { kind: "allow"; groups: string[] }
  | { kind: "refuse" }
  // `why` is for the gateway's own log line; it never reaches the person.
  | { kind: "unanswered"; why: string };

// How long the gateway waits for the platform's answer before the check is
// unanswered (a 503). The route reads D1 and may ask Okta for the person's
// account status, which it bounds at 3 seconds (src/mcp/authz.ts
// STATUS_LOOKUP_TIMEOUT_MS), so this leaves room for both.
export const ACCESS_CHECK_TIMEOUT_MS = 5_000;

// How long any one request waits on a question already in flight, its own
// leader's included. Longer than the platform timeout, so the flight
// normally ends first; this is the bound that still holds when the flight
// never settles at all (its I/O cancelled along with the request that
// started it), and it evicts that flight so the next request asks afresh.
export const ACCESS_JOIN_TIMEOUT_MS = 6_000;

export type AccessCheckRequest = {
  platform: Fetcher;
  // The asking request's ExecutionContext.waitUntil, when it has one. The
  // question in flight is handed to it, so a browser that aborts the request
  // that asked (a refresh, a navigation) does not cancel the answer the
  // requests joined to it are waiting on. A throw from it is ignored.
  waitUntil?: (p: Promise<unknown>) => void;
  // GATEWAY_INTROSPECT_KEY, presented when this gateway holds one, the way
  // mcp-auth.ts and storage.ts present it. The route does not demand it, but
  // refuses a wrong one (src/routes/access-check.ts).
  gatewayKey?: string;
  host: string;
  // The email verifyAccessJwt verified, exactly as the JWT carries it. Not
  // normalized: the platform folds case itself (normEmail), so a raw key is
  // only ever finer than the platform's identity, never coarser, and a
  // gateway-side fold that differed from normEmail could merge two people.
  email: string;
  jwt: string;
};

// The one shape a decision may have: `allow` a boolean, `groups` an array of
// strings, `ttl` a finite number of seconds, 0 or more. Anything else is
// unanswered, never a refusal and never an allow.
function parseAnswer(body: unknown): { answer: AccessAnswer; ttl: number } | null {
  if (typeof body !== "object" || body === null) return null;
  const { allow, groups, ttl } = body as { allow?: unknown; groups?: unknown; ttl?: unknown };
  if (typeof allow !== "boolean") return null;
  if (!Array.isArray(groups) || !groups.every((g) => typeof g === "string")) return null;
  if (typeof ttl !== "number" || !Number.isFinite(ttl) || ttl < 0) return null;
  return { answer: allow ? { kind: "allow", groups: groups as string[] } : { kind: "refuse" }, ttl };
}

type Asked = { answer: AccessAnswer; ttl: number } | { why: string };

// Never rejects: every failure is a `why`.
async function askOnce(req: AccessCheckRequest, signal: AbortSignal): Promise<Asked> {
  let res: Response;
  try {
    res = await req.platform.fetch(`${PLATFORM_ORIGIN}${ACCESS_CHECK_PATH}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(req.gatewayKey ? { [GATEWAY_KEY_HEADER]: req.gatewayKey } : {}),
      },
      body: JSON.stringify({ host: req.host, jwt: req.jwt }),
      signal,
    });
  } catch (e) {
    return { why: `the platform could not be reached: ${errLine(e, 120)}` };
  }
  if (res.status !== 200) return { why: `the platform answered ${res.status}` };
  let body: unknown;
  try { body = await res.json(); } catch { return { why: "the platform's answer is not JSON" }; }
  return parseAnswer(body) ?? { why: "the platform's answer is not an access decision" };
}

// The platform's answer, or a `why` once `ms` pass without one. The race
// bounds the body read too, and the abort tells the binding call to stop.
async function askPlatform(req: AccessCheckRequest, ms: number): Promise<Asked> {
  const abort = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<Asked>((resolve) => {
    timer = setTimeout(() => {
      abort.abort();
      resolve({ why: `the platform did not answer within ${ms} ms` });
    }, ms);
  });
  try {
    return await Promise.race([askOnce(req, abort.signal), late]);
  } finally {
    clearTimeout(timer);
  }
}

const TIMED_OUT = Symbol("timed out");

// `p`, or TIMED_OUT once `ms` pass, on the caller's own clock.
async function waitAtMost<T>(p: Promise<T>, ms: number): Promise<T | typeof TIMED_OUT> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([p, new Promise<typeof TIMED_OUT>((r) => { timer = setTimeout(() => r(TIMED_OUT), ms); })]);
  } finally {
    clearTimeout(timer);
  }
}

export type AccessCheckerOptions = {
  // The clock, injectable so a test can move it.
  now?: () => number;
  // ACCESS_CHECK_TIMEOUT_MS and ACCESS_JOIN_TIMEOUT_MS, shortened in tests.
  timeoutMs?: number;
  joinTimeoutMs?: number;
};

/**
 * The access check with its cache. index.ts makes one per app it builds, and
 * builds one app per isolate (its default export), so the cache is per
 * isolate in production; each app a test builds starts with an empty one.
 *
 * One question per key is in flight at a time, and every request that misses
 * while it is pending shares its answer. A browser fetches a page's assets
 * in parallel, so a cold isolate meets them as one burst of misses for one
 * person; asking once per asset would spend the platform's per-person brake
 * (120 a minute) in a page load or two, and its answer on a trip is the
 * refusal, which is then held. An unanswered check is shared only with the
 * requests already waiting on it, and held for no one after.
 *
 * The flight is bounded three ways, so no request can wait on it forever:
 *   - it is handed to its leader's waitUntil, so the leader's request ending
 *     does not cancel it for the others;
 *   - the platform call has its own timeout (ACCESS_CHECK_TIMEOUT_MS);
 *   - every waiting request gives up on its own clock
 *     (ACCESS_JOIN_TIMEOUT_MS) and evicts the flight, so the next request
 *     starts afresh. Only the entry's own flight may clear it or write the
 *     cache, so an evicted flight that settles late touches neither.
 */
export function makeAccessChecker(opts: AccessCheckerOptions = {}): (req: AccessCheckRequest) => Promise<AccessAnswer> {
  const now = opts.now ?? Date.now;
  const timeoutMs = opts.timeoutMs ?? ACCESS_CHECK_TIMEOUT_MS;
  const joinTimeoutMs = opts.joinTimeoutMs ?? ACCESS_JOIN_TIMEOUT_MS;
  const cache = new Map<string, { answer: AccessAnswer; expiresAt: number }>();
  const inFlight = new Map<string, Promise<Asked>>();
  const hold = (key: string, answer: AccessAnswer, ttl: number) => {
    const seconds = Math.min(ttl, MAX_ACCESS_CACHE_SECONDS);
    if (seconds <= 0) return;
    if (cache.size >= MAX_ACCESS_CACHE_ENTRIES) {
      const oldest = cache.keys().next().value;
      if (oldest !== undefined) cache.delete(oldest);
    }
    cache.set(key, { answer, expiresAt: now() + seconds * 1000 });
  };
  return async (req) => {
    // A JSON array, so no separator has to be chosen or defended: no two
    // (host, email) pairs serialize alike.
    const key = JSON.stringify([req.host, req.email]);
    const hit = cache.get(key);
    if (hit) {
      if (hit.expiresAt > now()) return hit.answer;
      cache.delete(key);
    }
    let flight = inFlight.get(key);
    if (!flight) {
      // Held before the flight is released, so a request arriving after it
      // settles finds the answer in the cache rather than asking again; and
      // only while it is still this key's flight (see above).
      const mine: Promise<Asked> = askPlatform(req, timeoutMs)
        .then((got) => {
          if (!("why" in got) && inFlight.get(key) === mine) hold(key, got.answer, got.ttl);
          return got;
        })
        .finally(() => { if (inFlight.get(key) === mine) inFlight.delete(key); });
      flight = mine;
      inFlight.set(key, flight);
      try { req.waitUntil?.(flight); } catch { /* no ExecutionContext (tests) */ }
    }
    const got = await waitAtMost(flight, joinTimeoutMs);
    if (got === TIMED_OUT) {
      if (inFlight.get(key) === flight) inFlight.delete(key);
      return { kind: "unanswered", why: `no answer to the check in flight within ${joinTimeoutMs} ms` };
    }
    return "why" in got ? { kind: "unanswered", why: got.why } : got.answer;
  };
}

// The two pages a person can be shown instead of the app. Plain, and they
// name no one: not the person, not the app, not its owner. no-store, so a
// browser asks again rather than keeping a refusal past a grant or an outage
// past its end.
function plainPage(status: number, title: string, text: string): Response {
  const html = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title></head>
<body><main><h1>${title}</h1><p>${text}</p></main></body>
</html>
`;
  return new Response(html, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

export function noAccessPage(): Response {
  return plainPage(403, "No access", "You do not have access to this app.");
}

export function checkUnavailablePage(): Response {
  return plainPage(503, "Try again shortly", "This app could not check your access just now. Please try again in a moment.");
}
