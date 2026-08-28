import type { AccessIdentity } from "./access";

// Identity-bearing headers a client must never supply to the container.
// The exact X-Forwarded-* names we own, plus the entire cf-access-* family
// (the gateway has already consumed the Access JWT before this runs, so the
// container never needs any cf-access-* header — and must not trust one).
// x-caller-assertion is stripped on BOTH perimeters (Access and MCP): it is a
// platform-signed credential (Connections v1) that only the gateway may set —
// a client-supplied value must never survive to be re-injected or forwarded.
const STRIP_EXACT = ["x-forwarded-user", "x-forwarded-groups", "x-forwarded-email", "x-caller-assertion"];
const STRIP_PREFIXES = ["cf-access-"];
// The Access JWT arrives TWICE: as cf-access-jwt-assertion (covered by the
// prefix rule above) and as this cookie — and index.ts accepts either as a
// credential, so stripping only the header left the app holding a live bearer
// for its own gateway. It is valid until exp (Access session_duration 24h) and
// re-accepted with no session or revocation lookup, so app code could replay
// any visitor's identity for a day, past a revoke_access.
const STRIP_COOKIE = "CF_Authorization";

// In MCP mode the caller's credential is a platform-issued OAuth bearer token in
// `Authorization`. The gateway has already consumed it, and the app must never
// see it: a leaked app-scoped token would let the app impersonate its own user
// against the platform, and R3 says the app performs no authentication anyway.
// Stripped only in MCP mode — on the Access path `Authorization` is not a
// platform credential, and removing it there would be a silent behavior change
// for existing apps.
const STRIP_EXACT_MCP = [...STRIP_EXACT, "authorization"];

export function sanitizeAndInject(
  req: Request, identity: AccessIdentity, opts: { mcpMode?: boolean } = {},
): Request {
  const headers = new Headers(req.headers);
  for (const h of opts.mcpMode ? STRIP_EXACT_MCP : STRIP_EXACT) headers.delete(h);
  // Headers.keys() are already lowercased by the Fetch API, so no toLowerCase.
  for (const name of [...headers.keys()]) {
    if (STRIP_PREFIXES.some((p) => name.startsWith(p))) headers.delete(name);
  }
  // Rebuild Cookie without CF_Authorization, preserving the app's own cookies
  // (an app legitimately sets its own; blanket-deleting the header would break
  // every session an app keeps). Cookie names are case-sensitive per RFC 6265,
  // so an exact match is right here — unlike the header names above.
  const cookie = headers.get("cookie");
  if (cookie !== null) {
    const kept = cookie.split(";")
      .filter((pair) => pair.trimStart().split("=")[0].trim() !== STRIP_COOKIE);
    if (kept.length === cookie.split(";").length) {
      // untouched — leave the original bytes alone rather than re-serializing
    } else if (kept.some((p) => p.trim() !== "")) {
      headers.set("cookie", kept.join(";").replace(/^[;\s]+/, ""));
    } else {
      headers.delete("cookie");
    }
  }
  headers.set("X-Forwarded-User", identity.email);
  headers.set("X-Forwarded-Email", identity.email);
  headers.set("X-Forwarded-Groups", identity.groups.join(","));
  // Connections v1: only set when introspection actually minted one (MCP path,
  // CALLER_ASSERTION_KEY provisioned). The app echoes this value back to
  // /_connections/{name}; the gateway never trusts one from the client (see
  // STRIP_EXACT above), only one it just verified came from the platform.
  if (identity.callerAssertion) headers.set("X-Caller-Assertion", identity.callerAssertion);
  return new Request(req, { headers });
}
