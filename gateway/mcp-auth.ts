// MCP mode: the gateway as an OAuth 2.1 Resource Server.
//
// mcp-type apps have NO Cloudflare Access application (an MCP client cannot
// complete an interactive Access login), so this file replaces the Access-JWT
// check with a bearer-token check. Everything downstream is unchanged: the same
// AccessIdentity flows into sanitizeAndInject, so the app still receives only
// spoof-proof X-Forwarded-* headers and still implements no authentication —
// APP-CONTRACT R3 holds for mcp apps exactly as it does for the other types.
//
// The platform's access tokens are OPAQUE (workers-oauth-provider encrypts the
// grant into them), so they cannot be verified locally. The gateway asks the
// platform over the PLATFORM service binding — a capability the app author
// cannot forge or reach, since the wrangler config carrying it is
// platform-owned and the config-integrity gate rejects app-owned wrangler files.
//
// One introspection per token per colo: results are cached in the Workers Cache
// API keyed by a SHA-256 of the token, with a TTL bounded by both the token's
// own remaining lifetime and MAX_CACHE_SECONDS. After the first request the hot
// path costs no subrequest, which is what makes opaque tokens as cheap here as
// a locally-verified JWT would have been.

import type { Env } from "./env";
import type { AccessIdentity } from "./access";

// Upper bound on how long a positive introspection is reused. This is the
// revocation lag: a grant revoked at the platform keeps working in an already-
// warm colo for at most this long. 60s is short next to the 24h Access session
// the other app types run with, so this is a tightening, not a loosening.
const MAX_CACHE_SECONDS = 60;

// RFC 9728 §3.1: the metadata document lives under this prefix on the RESOURCE's
// own origin, with the resource's path component INSERTED after it. Our resource
// is `https://inno-{app}.{domain}/mcp`, so the spec-correct URL is
// `/.well-known/oauth-protected-resource/mcp`. Clients differ on this in
// practice, so `isProtectedResourceRequest` accepts the bare prefix too and the
// challenge advertises the spec-correct form.
export const PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource";

// The path-inserted form for a resource whose path is `resourcePath` (e.g.
// "/mcp"). Falls back to the bare prefix for an origin-only resource.
function protectedResourcePathFor(resourcePath: string): string {
  return resourcePath && resourcePath !== "/"
    ? `${PROTECTED_RESOURCE_PATH}${resourcePath}`
    : PROTECTED_RESOURCE_PATH;
}

// Accept either spelling: the bare prefix, or the prefix plus this resource's
// path. Deliberately NOT a blanket prefix match — an unrelated
// `/.well-known/oauth-protected-resource/other` must not be served this app's
// metadata.
export function isProtectedResourceRequest(env: Env, path: string): boolean {
  if (path === PROTECTED_RESOURCE_PATH) return true;
  let resourcePath = "";
  try { resourcePath = new URL(env.MCP_RESOURCE ?? "").pathname; } catch { return false; }
  return path === protectedResourcePathFor(resourcePath);
}

export interface McpAuthResult {
  identity: AccessIdentity;
  // Set when the caller presented the platform's health-probe bearer, which has
  // no user identity. The caller restricts it to GET /healthz.
  service: boolean;
}

interface IntrospectionResponse {
  active: boolean;
  email?: string;
  groups?: string[];
  service?: boolean;
  expires_in?: number;
}

// RFC 6750 §2.1: credentials go in `Authorization: Bearer <token>`. Deliberately
// header-only — no query-parameter fallback, which RFC 6750 §5.3 warns against
// (tokens leak into logs and Referer headers) and which the protected-resource
// metadata's bearer_methods_supported already declares we don't accept.
export function bearerToken(req: Request): string | null {
  const raw = req.headers.get("authorization");
  if (!raw) return null;
  // Case-INSENSITIVE scheme: RFC 7235 §2.1 defines the auth-scheme token as
  // case-insensitive, and RFC 6750's `Bearer` inherits that. A client sending
  // `authorization: bearer <token>` is spec-compliant and must not get an
  // undiagnosable 401.
  const m = /^Bearer +([^\s]+)$/i.exec(raw.trim());
  return m ? m[1] : null;
}

// Cache key: a hash, never the token itself. Cache keys can surface in
// diagnostics, and the Cache API is per-colo shared state — storing raw bearer
// tokens as URLs would be a credential leak.
//
// The hash input is a JSON array rather than a delimiter-joined string, so no
// separator has to be chosen or defended: two different (resource, token) pairs
// can never serialize identically, whatever characters they contain. Including
// the RESOURCE is load-bearing — the Cache API is shared per zone, and every app
// gateway lives on a hostname of the same zone, so a token-only key could let one
// app's cached introspection satisfy another app's gateway.
async function cacheKeyFor(token: string, resource: string): Promise<Request> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify([resource, token])));
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  // A synthetic https URL on a reserved host — never fetched, only used as a key.
  return new Request(`https://mcp-introspection.invalid/${hex}`);
}

// Ask the platform whether this token is live and who it belongs to.
async function introspectViaPlatform(
  env: Env, token: string, resource: string,
): Promise<IntrospectionResponse> {
  const res = await env.PLATFORM!.fetch("https://platform.internal/app-introspect", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token, resource }),
  });
  if (!res.ok) {
    // A platform-side failure must NOT be read as "token valid". Fail closed and
    // let the caller answer 401; the client will retry.
    console.warn(`gateway: introspection failed (${res.status})`);
    return { active: false };
  }
  return (await res.json()) as IntrospectionResponse;
}

// Resolve a bearer token to an identity, using (and populating) the per-colo
// cache. Returns null for any invalid/expired/foreign token.
// `waitUntil` (when the caller has an ExecutionContext) keeps the cache write off
// the response path — the entry is only an optimization, so the request should
// never wait on it.
export async function authenticateMcp(
  env: Env, req: Request, resource: string,
  waitUntil?: (p: Promise<unknown>) => void,
): Promise<McpAuthResult | null> {
  const token = bearerToken(req);
  if (!token) return null;
  if (!env.PLATFORM) {
    // Misconfiguration (an mcp gateway deployed without its service binding).
    // Fail closed rather than serve an app with no identity boundary at all.
    console.error("gateway: MCP mode without a PLATFORM service binding — refusing all requests");
    return null;
  }

  const key = await cacheKeyFor(token, resource);
  const cache = caches.default;
  let body: IntrospectionResponse | null = null;

  const hit = await cache.match(key);
  if (hit) {
    try { body = (await hit.json()) as IntrospectionResponse; } catch { body = null; }
  }

  if (!body) {
    body = await introspectViaPlatform(env, token, resource);
    // Only positive results are cached. Caching negatives would let a token that
    // has just been granted keep failing for the rest of the window, and there
    // is no cost pressure to justify it — an invalid token is not a hot path.
    if (body.active) {
      // TTL is the LESSER of the ceiling and the token's own remaining life, so a
      // nearly-expired token is never honored past its expiry.
      const ttl = Math.max(1, Math.min(MAX_CACHE_SECONDS, body.expires_in ?? MAX_CACHE_SECONDS));
      const write = cache.put(key, new Response(JSON.stringify(body), {
        headers: { "content-type": "application/json", "cache-control": `max-age=${ttl}` },
      }));
      if (waitUntil) waitUntil(write); else await write;
    }
  }

  if (!body.active) return null;
  return {
    identity: { email: body.email ?? "", groups: body.groups ?? [] },
    service: body.service === true,
  };
}

// RFC 9728 §3: the metadata document that tells an MCP client which
// Authorization Server to use. Served publicly and unauthenticated — that is the
// point: it is how an unauthenticated client discovers where to get a token.
// It contains no secret, only URLs.
export function protectedResourceMetadata(env: Env): Response {
  return Response.json({
    resource: env.MCP_RESOURCE,
    authorization_servers: [env.MCP_AUTH_SERVER],
    // Header only — see bearerToken above.
    bearer_methods_supported: ["header"],
    scopes_supported: ["openid", "profile", "email"],
  }, {
    // Public, cacheable metadata; clients re-fetch it on each fresh auth.
    headers: { "cache-control": "public, max-age=3600" },
  });
}

// RFC 9728 §5.1 / MCP auth: a 401 whose WWW-Authenticate names the metadata
// document. Without `resource_metadata` a client has no way to find the AS and
// simply fails, so this header is what makes the whole flow discoverable.
export function unauthorizedChallenge(env: Env): Response {
  // The metadata document lives on the RESOURCE's origin, derived from
  // MCP_RESOURCE so the two can never disagree. Advertises the spec-correct
  // path-inserted form (RFC 9728 §3.1).
  let url = "";
  try {
    const resource = new URL(env.MCP_RESOURCE ?? "");
    url = `${resource.origin}${protectedResourcePathFor(resource.pathname)}`;
  } catch { url = ""; }
  return new Response("unauthorized", {
    status: 401,
    headers: {
      "content-type": "text/plain",
      // Without resource_metadata a client cannot discover the AS at all, so a
      // bare `Bearer` is only the mis-templated-deploy fallback.
      "www-authenticate": url ? `Bearer resource_metadata="${url}"` : "Bearer",
    },
  });
}
