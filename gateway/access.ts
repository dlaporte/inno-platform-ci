import { errors, jwtVerify, type JWTPayload } from "jose";
import { instanceGroups } from "./instance";
import { errLine } from "./log-text";

export const ACCESS_JWT_HEADER = "cf-access-jwt-assertion";
export const ACCESS_COOKIE = "CF_Authorization";

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

// The jose errors a token can cause, by code. Hand-written twin of
// src/access-jwt.ts's TOKEN_FAULTS (whose comment says why each code is on
// it), held equal by test/access-verifier-parity.test.ts.
export const TOKEN_FAULTS: ReadonlySet<string> = new Set([
  errors.JWSInvalid.code,
  errors.JWTInvalid.code,
  errors.JWSSignatureVerificationFailed.code,
  errors.JWTClaimValidationFailed.code,
  errors.JWTExpired.code,
  errors.JOSEAlgNotAllowed.code,
  errors.JOSENotSupported.code,
  errors.JWKSNoMatchingKey.code,
  errors.JWKSMultipleMatchingKeys.code,
]);

// The prefix of the throw for a key set that could not be obtained, which
// index.ts answers as an outage.
export const ACCESS_UNAVAILABLE = "access_unavailable:";

// Cross-build twin of src/access-jwt.ts's makeRealVerifier: the same Access
// JWT, the same issuer/audience/RS256 pins, hand-written on either side of
// the gateway build boundary because gateway/ imports nothing from src/.
// This is the one twin in the pair that is LOGIC rather than a constant, so it
// is pinned by BEHAVIOR: test/access-verifier-parity.test.ts feeds one signed
// token matrix to both verifiers and demands the same accept/reject answer,
// and holds the two TOKEN_FAULTS sets equal. A claims change landing on one
// side only makes the platform refuse what the gateway accepted: every
// /_access/check answers a refusal (capability 1), and every touch fails
// verification silently, which freezes last_seen_at on an app in real use.
//
// Both read a key set that could not be obtained as an outage, not a verdict.
// A token fault (a code in TOKEN_FAULTS) or a token with no email claim
// throws `access_invalid:`, which index.ts answers 401. Anything else
// jwtVerify throws came from obtaining the key set (a timeout, a network
// failure, a certs answer that is not 200 or not a key set) and throws
// ACCESS_UNAVAILABLE, which index.ts answers with its 503 page, except on
// GET /healthz. The platform's twin also keeps a held-keys rule
// (makeRealVerifier), which stops a 503 from telling a registered app's host
// from an unknown one. A gateway serves one host, so it has none to hide and
// keeps no such rule: a token naming an unknown key id during an outage gets
// the 503 page, which is harmless.
//
// Only this instance's groups (opts.groupPrefix, the gateway's GROUP_PREFIX
// var) are kept: the filter instance.ts states once for all three identity
// paths. Since capability 1 the browser path does not tell the app these:
// index.ts replaces them with the groups in the platform's /_access/check
// answer (access-check.ts), so the JWT's groups claim decides nothing there.
export async function verifyAccessJwt(
  token: string,
  opts: { jwks: Parameters<typeof jwtVerify>[1]; aud: string; teamDomain: string; groupPrefix: string },
  { allowService = false } = {},
): Promise<AccessIdentity> {
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, opts.jwks, {
      issuer: `https://${opts.teamDomain}`, audience: opts.aud, algorithms: ["RS256"],
    }));
  } catch (e) {
    const tokenFault = e instanceof errors.JOSEError && TOKEN_FAULTS.has(e.code);
    throw new Error(`${tokenFault ? "access_invalid:" : ACCESS_UNAVAILABLE}${errLine(e, 120)}`);
  }
  const email = payload.email;
  if (typeof email !== "string" || !email) {
    // Service-token JWTs (the platform's health probe) are valid Access
    // tokens with NO user identity: `common_name` carries the token's
    // client id instead. Only callers that explicitly opt in (the gateway
    // does so for GET /healthz alone) accept them; everywhere else an
    // identity-less token stays a hard 401.
    if (allowService && typeof payload.common_name === "string" && payload.common_name) {
      return { email: "", groups: [] };
    }
    throw new Error("access_invalid:no email claim");
  }
  return { email, groups: instanceGroups(opts.groupPrefix, payload.groups) };
}
