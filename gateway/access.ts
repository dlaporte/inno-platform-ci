import { jwtVerify } from "jose";

export const ACCESS_JWT_HEADER = "cf-access-jwt-assertion";
export const ACCESS_COOKIE = "CF_Authorization";
// The platform group prefix. Only `inno-` groups are carried into the
// container (prod filter here + the dev X-Mock-Groups filter in index.ts) —
// one constant so the two paths can't drift.
export const GROUP_PREFIX = "inno-";

export interface AccessIdentity {
  email: string;
  groups: string[];
  // Connections v1 (Task 14): the platform-minted, short-TTL statement of this
  // caller's identity (see src/connections/assertion.ts), carried ONLY on the
  // MCP path via introspection's `caller_assertion` (mcp-auth.ts). Injected as
  // X-Caller-Assertion by sanitizeAndInject so the app can echo it back to
  // /_connections/{name} without the gateway ever trusting an app-supplied value.
  callerAssertion?: string;
}

export async function verifyAccessJwt(
  token: string,
  opts: { jwks: Parameters<typeof jwtVerify>[1]; aud: string; teamDomain: string },
  { allowService = false } = {},
): Promise<AccessIdentity> {
  try {
    const { payload } = await jwtVerify(token, opts.jwks, {
      issuer: `https://${opts.teamDomain}`, audience: opts.aud, algorithms: ["RS256"],
    });
    const email = payload.email;
    if (typeof email !== "string" || !email) {
      // Service-token JWTs (the platform's health probe) are valid Access
      // tokens with NO user identity — `common_name` carries the token's
      // client id instead. Only callers that explicitly opt in (the gateway
      // does so for GET /healthz alone) accept them; everywhere else an
      // identity-less token stays a hard 401.
      if (allowService && typeof payload.common_name === "string" && payload.common_name) {
        return { email: "", groups: [] };
      }
      throw new Error("no email claim");
    }
    const rawGroups = Array.isArray(payload.groups) ? payload.groups : [];
    const groups = rawGroups.filter((g): g is string => typeof g === "string" && g.startsWith(GROUP_PREFIX));
    return { email, groups };
  } catch (e) {
    throw new Error(`access_invalid:${String(e).slice(0, 120)}`);
  }
}
