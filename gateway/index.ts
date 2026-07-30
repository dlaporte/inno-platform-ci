import { Hono } from "hono";
import { Container, getContainer } from "@cloudflare/containers";
import { createRemoteJWKSet } from "jose";
import type { Env } from "./env";
import { verifyAccessJwt, ACCESS_JWT_HEADER, ACCESS_COOKIE, GROUP_PREFIX, type AccessIdentity } from "./access";
import { sanitizeAndInject } from "./identity";
import { handleStorage } from "./storage";
import {
  authenticateMcp, bearerToken, protectedResourceMetadata, unauthorizedChallenge, isProtectedResourceRequest,
} from "./mcp-auth";

// The @cloudflare/containers runtime routes container calls through an internal
// `ContainerProxy` Durable Object that it looks up via `ctx.exports.ContainerProxy`.
// It only lands on `ctx.exports` if the Worker entrypoint re-exports it — without
// this, container startup fails with "ctx.exports.ContainerProxy is undefined".
export { ContainerProxy } from "@cloudflare/containers";

// NOTE: the lowercased class name is load-bearing OUTSIDE this worker —
// src/naming.ts `containerAppName` derives the billed Cloudflare Container
// application name as `<worker>-appcontainer` from `class AppContainer`.
// Renaming this class silently orphans the billed container on teardown; keep
// the two in sync (see the reciprocal note in src/naming.ts).
export class AppContainer extends Container<Env> {
  defaultPort = 8080;
  // Scale-to-zero timeout. The platform injects SLEEP_AFTER at deploy time
  // (`wrangler deploy --var SLEEP_AFTER:...` in platform-ci, sourced from the
  // config store's container.sleep_after — app-overridable); the grammar guard
  // mirrors the platform's server-side validation so a malformed var can never
  // wedge container startup.
  sleepAfter = "10m";
  constructor(...args: ConstructorParameters<typeof Container<Env>>) {
    super(...args);
    const env = args[1] as Env;
    if (env.SLEEP_AFTER && /^[0-9]{1,4}(s|m|h)$/.test(env.SLEEP_AFTER)) this.sleepAfter = env.SLEEP_AFTER;
  }
}
// Register the storage.internal outbound handler by ASSIGNING after the class
// so the assignment invokes Container's inherited static `outboundByHost` SETTER
// (which registers the handler in the package's outbound registry). Declaring
// `static outboundByHost = {...}` in the class body instead creates an own data
// property that SHADOWS the setter — the handler is never registered, so the
// container's http://storage.internal calls fall through to the enableInternet
// fallback and fail with HTTP 530 (the live "no D1 writes" bug).
AppContainer.outboundByHost = { "storage.internal": (req: Request, env: Env) => handleStorage(req, env) };

type Deps = {
  jwks: (env: Env) => ReturnType<typeof createRemoteJWKSet>;
  forwardToContainer: (env: Env, req: Request) => Promise<Response>;
  // Function-shaped apps (env.APP_WORKER bound) forward here instead — a service
  // binding to the app's own Worker. See makeApp's dispatch below.
  forwardToWorker: (env: Env, req: Request) => Promise<Response>;
};

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
export const realDeps: Deps = {
  jwks: (env) => {
    const url = `https://${env.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`;
    let j = jwksCache.get(url);
    if (!j) { j = createRemoteJWKSet(new URL(url)); jwksCache.set(url, j); }
    return j;
  },
  forwardToContainer: (env, req) => getContainer(env.APP).fetch(req),
  // env.APP_WORKER exists only on function-shaped deploys, where makeApp dispatches
  // here; the `!` is safe because the container branch is chosen whenever it's absent.
  forwardToWorker: (env, req) => env.APP_WORKER!.fetch(req),
};

function readCookie(req: Request, name: string): string | undefined {
  const raw = req.headers.get("cookie") ?? "";
  return raw.split(";").map((s) => s.trim()).find((c) => c.startsWith(`${name}=`))?.slice(name.length + 1);
}

export function makeApp(deps: Deps = realDeps) {
  const app = new Hono<{ Bindings: Env }>();
  app.all("*", async (c) => {
    const env = c.env;
    let identity: AccessIdentity;
    // MCP mode (mcp-type apps): this gateway is an OAuth Resource Server, not an
    // Access-terminating proxy. Handled before the dev branch so the discovery
    // document and the 401 challenge behave identically in dev and production —
    // an MCP client's very first request depends on both.
    if (env.OAUTH_RS_MODE === "true") {
      const path = c.req.path;
      // Public, unauthenticated by design: this is how a client with no token
      // discovers which Authorization Server to use. Contains only URLs.
      if (c.req.method === "GET" && isProtectedResourceRequest(env, path)) {
        return protectedResourceMetadata(env);
      }
      const auth = await authenticateMcp(env, c.req.raw, env.OAUTH_RS_RESOURCE ?? "");
      if (!auth) {
        // Distinguish "presented a bad/expired token" (→ error=invalid_token, so
        // the client refreshes) from "presented none" (→ start authorization).
        const hadToken = bearerToken(c.req.raw) !== null;
        console.warn(`gateway: 401 ${hadToken ? "invalid" : "no"} bearer (${c.req.method} ${path})`);
        return unauthorizedChallenge(env, hadToken);
      }
      // Same rule the Access path applies to its service token: a credential
      // with no user identity is good for GET /healthz and nothing else.
      if (auth.service && !(c.req.method === "GET" && path === "/healthz")) {
        console.warn(`gateway: 403 service credential outside /healthz (${c.req.method} ${path})`);
        return c.text("forbidden", 403);
      }
      identity = auth.identity;
    } else if (env.ENVIRONMENT === "dev") {
      identity = {
        email: c.req.header("X-Mock-User") ?? "dev@davidlaporte.org",
        // Same inno- filter production applies (access.ts), so dev can't inject
        // a non-inno group the real path would strip.
        groups: (c.req.header("X-Mock-Groups") ?? "").split(",").map((s) => s.trim()).filter((g) => g.startsWith(GROUP_PREFIX)),
      };
    } else {
      const path = c.req.path;
      // Fail CLOSED on a mis-templated deploy: without an AUD and team domain
      // there is nothing to verify a JWT against, and proceeding would check the
      // token against `undefined` rather than this app's Access application.
      if (!env.ACCESS_AUD || !env.ACCESS_TEAM_DOMAIN) {
        console.error("gateway: Access mode without ACCESS_AUD/ACCESS_TEAM_DOMAIN — refusing all requests");
        return c.text("unauthorized", 401);
      }
      const token = c.req.header(ACCESS_JWT_HEADER) ?? readCookie(c.req.raw, ACCESS_COOKIE);
      if (!token) { console.warn(`gateway: 401 no Access token (${c.req.method} ${path})`); return c.text("unauthorized", 401); }
      // The platform's health probe authenticates with an Access SERVICE
      // token — a valid JWT with no user identity. It is accepted for
      // exactly one request shape: GET /healthz. Any other path keeps the
      // hard identity requirement (a service token can never browse the app
      // or reach data as a person).
      const isHealthProbe = c.req.method === "GET" && path === "/healthz";
      try {
        identity = await verifyAccessJwt(token,
          { jwks: deps.jwks(env), aud: env.ACCESS_AUD, teamDomain: env.ACCESS_TEAM_DOMAIN },
          { allowService: isHealthProbe });
      } catch (e) {
        console.warn(`gateway: 401 ${String(e).slice(0, 120)} (${c.req.method} ${path})`);
        return c.text("unauthorized", 401);
      }
    }
    // NOTE: this handler proxies ALL paths (including /_storage/*) to the
    // container via forwardToContainer. handleStorage is never called here —
    // it is wired only as AppContainer's outboundByHost["storage.internal"]
    // handler above, reachable solely by the app's own container in-runtime.
    // Do not add a /_storage route here: that would let the public internet
    // reach handleStorage's arbitrary SQL/R2 access directly.
    const proxied = sanitizeAndInject(c.req.raw, identity, { mcpMode: env.OAUTH_RS_MODE === "true" });
    // Deployment-type dispatch: function-shaped apps carry an APP_WORKER service
    // binding and forward to the app's own Worker; container-type apps (no such
    // binding) forward to the container. Either way the gateway did the Access
    // verification and identity injection FIRST, so the target only ever sees a
    // sanitized, authenticated request with spoof-proof X-Forwarded-* headers.
    if (env.APP_WORKER) return deps.forwardToWorker(env, proxied);
    return deps.forwardToContainer(env, proxied);
  });
  return app;
}

export default makeApp();
