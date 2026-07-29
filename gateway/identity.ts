import type { AccessIdentity } from "./access";

// Identity-bearing headers a client must never supply to the container.
// The exact X-Forwarded-* names we own, plus the entire cf-access-* family
// (the gateway has already consumed the Access JWT before this runs, so the
// container never needs any cf-access-* header — and must not trust one).
const STRIP_EXACT = ["x-forwarded-user", "x-forwarded-groups", "x-forwarded-email"];
const STRIP_PREFIXES = ["cf-access-"];

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
  headers.set("X-Forwarded-User", identity.email);
  headers.set("X-Forwarded-Email", identity.email);
  headers.set("X-Forwarded-Groups", identity.groups.join(","));
  return new Request(req, { headers });
}
