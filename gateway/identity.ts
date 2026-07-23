import type { AccessIdentity } from "./access";

// Identity-bearing headers a client must never supply to the container.
// The exact X-Forwarded-* names we own, plus the entire cf-access-* family
// (the gateway has already consumed the Access JWT before this runs, so the
// container never needs any cf-access-* header — and must not trust one).
export const STRIP_EXACT = ["x-forwarded-user", "x-forwarded-groups", "x-forwarded-email"];
export const STRIP_PREFIXES = ["cf-access-"];

export function sanitizeAndInject(req: Request, identity: AccessIdentity): Request {
  const headers = new Headers(req.headers);
  for (const h of STRIP_EXACT) headers.delete(h);
  for (const name of [...headers.keys()]) {
    if (STRIP_PREFIXES.some((p) => name.toLowerCase().startsWith(p))) headers.delete(name);
  }
  headers.set("X-Forwarded-User", identity.email);
  headers.set("X-Forwarded-Email", identity.email);
  headers.set("X-Forwarded-Groups", identity.groups.join(","));
  return new Request(req, { headers });
}
