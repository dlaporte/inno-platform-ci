import type { AppContainer } from "./index";

export type Env = {
  DB: D1Database; FILES: R2Bucket; APP: DurableObjectNamespace<AppContainer>;
  // Cloudflare Access config, templated per app. OPTIONAL because mcp-type apps
  // have no Access application at all (see the MCP block below) — the Access
  // branch in index.ts refuses to run without them rather than verifying a JWT
  // against `undefined`.
  ACCESS_AUD?: string; ACCESS_TEAM_DOMAIN?: string;
  ENVIRONMENT: string;
  // Injected at deploy time by platform-ci (config store: container.sleep_after).
  SLEEP_AFTER?: string;
  // Present ONLY on worker-type apps: a service binding to the app's own Worker
  // (the "Worker behind the same gateway" deployment type). When set, the
  // gateway forwards authenticated requests here instead of to the container —
  // the app Worker is not publicly routable, so the gateway stays the only
  // entrypoint and identity boundary. Container-type apps never bind this.
  APP_WORKER?: Fetcher;
  // --- mcp-type apps only (gateway/wrangler.mcp.jsonc) ---------------------
  // Present ONLY on mcp-type deploys, where the gateway is an OAuth Resource
  // Server instead of an Access-terminating proxy. MCP_MODE is the switch;
  // ACCESS_AUD is absent on these apps because they have no Access application.
  MCP_MODE?: string;
  // This app's RFC 8707/9728 resource identifier — `https://inno-{app}.{domain}/mcp`,
  // templated by CI from the deploy broker's `mcp_resource`. Compared by EXACT
  // match against a token's audience, so it must not be rebuilt ad hoc.
  MCP_RESOURCE?: string;
  // The Authorization Server issuer the protected-resource metadata advertises
  // (the platform's own origin).
  MCP_AUTH_SERVER?: string;
  // Service binding to the platform Worker, used for token introspection. The
  // binding is ROUTING, not authentication — /app-introspect is publicly
  // reachable and safe by construction (it has no authority and returns only
  // what is already inside the presented token); see src/routes/mcp-introspect.ts.
  PLATFORM?: Fetcher;
};
