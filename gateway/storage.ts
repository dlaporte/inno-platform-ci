import type { Env } from "./env";

// PLATFORM added for Connections v1's /_connections/{name} proxy below. It is
// optional on Env (present only on the two oauth-rs wrangler variants — see
// env.ts), so a sso-perimeter app simply has it undefined and the route below
// answers 501 rather than throwing.
// Not Pick<Env, …>: DB/FILES are optional on Env because the function-shaped
// gateway variants don't bind them, but handleStorage is reachable ONLY as
// AppContainer's storage.internal outbound handler — i.e. only on the
// container-shaped deploys, where both always exist. Stating that here keeps
// the narrowing at the one place the invariant actually holds (index.ts's
// outboundByHost registration) instead of scattering `!` through this file.
export type StorageEnv = { DB: D1Database; FILES: R2Bucket; PLATFORM?: Fetcher };
type S = StorageEnv;

// Same grammar the platform enforces for a connection name (src/connections/store.ts
// CONN_NAME_RE) — restated rather than imported, same reason as APP_NAME_RE below:
// the gateway builds separately from the platform Worker.
const CONNECTION_NAME_RE = /^[a-z][a-z0-9-]{0,63}$/;

// Per-object upload cap (25 MiB). Enforced only when the client sends a
// content-length header — a chunked PUT with no length streams to R2, where
// R2's own object-size limits apply as the backstop.
const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;

// Must match src/links.ts linkBindingFor — the gateway builds separately from
// the platform Worker, so the derivation is restated rather than imported. A
// test asserts the two agree.
const APP_NAME_RE = /^[a-z][a-z0-9-]{2,28}$/;
export function linkBindingFor(sourceApp: string): string {
  return `LINKED_${sourceApp.toUpperCase().replace(/-/g, "_")}`;
}

/**
 * Resolve `/_storage/linked/{app}/...` to the D1 binding the platform injected
 * for that link, or null when no such link is deployed.
 *
 * The presence of the binding IS the authorization: it exists only because the
 * platform templated it into this gateway's config at deploy time, having
 * checked same-owner and membership containment. The container cannot conjure a
 * binding, so a request naming an unlinked app finds nothing.
 */
function resolveLinkedDb(env: S, sourceApp: string): D1Database | null {
  if (!APP_NAME_RE.test(sourceApp)) return null;
  // Linked bindings are named after the SOURCE app, so they cannot appear in the
  // static Env type — look them up dynamically rather than widening Env with an
  // index signature (which would weaken every other binding's typing).
  const candidate = (env as unknown as Record<string, unknown>)[linkBindingFor(sourceApp)];
  // Duck-type rather than instanceof: D1Database is not a constructible global.
  return candidate && typeof (candidate as D1Database).prepare === "function"
    ? (candidate as D1Database)
    : null;
}

export async function handleStorage(request: Request, env: S): Promise<Response> {
  try {
    const url = new URL(request.url);
    const path = url.pathname;
    const m = request.method;

    if (path === "/_storage/sql/query" && m === "POST") {
      const body = await readJson<{ sql: string; params?: unknown[] }>(request);
      if (!body?.sql) return json({ error: "bad_request" }, 400);
      const { results } = await env.DB.prepare(body.sql).bind(...(body.params ?? [])).all();
      return json({ results });
    }
    if (path === "/_storage/sql/execute" && m === "POST") {
      const body = await readJson<{ sql: string; params?: unknown[] }>(request);
      if (!body?.sql) return json({ error: "bad_request" }, 400);
      const r = await env.DB.prepare(body.sql).bind(...(body.params ?? [])).run();
      return json({ changes: r.meta.changes ?? 0, lastRowId: r.meta.last_row_id ?? null });
    }
    // Cross-app data links (migration 0028). Same query/execute surface as the
    // app's own database, scoped to a source app it has a deployed link to.
    // Deliberately mirrors the shape above rather than inventing a second API,
    // so an app author who can read from their own D1 can read from a linked one
    // without learning anything new.
    const linkMatch = path.match(/^\/_storage\/linked\/([^/]+)\/sql\/(query|execute)$/);
    if (linkMatch && m === "POST") {
      const [, sourceApp, op] = linkMatch;
      const linkedDb = resolveLinkedDb(env, sourceApp);
      if (!linkedDb) {
        return json({
          error: "not_linked",
          detail:
            `No deployed data link to "${sourceApp}". Create one with the link_app_data MCP tool ` +
            "(same owner only), then redeploy this app — links are bound at deploy time.",
        }, 404);
      }
      const body = await readJson<{ sql: string; params?: unknown[] }>(request);
      if (!body?.sql) return json({ error: "bad_request" }, 400);
      const stmt = linkedDb.prepare(body.sql).bind(...(body.params ?? []));
      if (op === "query") {
        const { results } = await stmt.all();
        return json({ results });
      }
      const r = await stmt.run();
      return json({ changes: r.meta.changes ?? 0, lastRowId: r.meta.last_row_id ?? null });
    }
    if (path === "/_storage/files" && m === "GET") {
      // R2 caps list() at 1000 keys and sets `truncated` with a cursor — a
      // single call silently returns a PARTIAL listing that an app author
      // reads as "these are all my files". Page to exhaustion, with a hard
      // stop far above any realistic per-app bucket so a truncated-but-
      // cursorless response can never spin forever.
      const keys: string[] = [];
      let cursor: string | undefined;
      for (let page = 0; page < 1000; page++) {
        const list = await env.FILES.list(cursor ? { cursor } : undefined);
        for (const o of list.objects) keys.push(o.key);
        cursor = list.truncated ? list.cursor : undefined;
        if (!cursor) break;
      }
      return json({ keys });
    }
    const fileMatch = path.match(/^\/_storage\/files\/(.+)$/);
    if (fileMatch) {
      const key = decodeURIComponent(fileMatch[1]);
      if (m === "PUT") {
        const len = request.headers.get("content-length");
        if (len && Number(len) > MAX_UPLOAD_BYTES) return json({ error: "too_large" }, 413);
        await env.FILES.put(key, request.body);
        return json({ key });
      }
      if (m === "GET") {
        const obj = await env.FILES.get(key);
        if (!obj) return json({ error: "not_found" }, 404);
        return new Response(obj.body, { status: 200 });
      }
      if (m === "DELETE") { await env.FILES.delete(key); return json({ deleted: true }); }
    }
    if (path.startsWith("/_connections/") && m === "POST") {
      // Per-user backend credentials (APP-CONTRACT Connections). The container
      // echoes the gateway-injected X-Caller-Assertion; identity travels ONLY in
      // that platform-signed token — this outbound handler cannot see the inbound
      // request, and every header here is container-authored (untrusted).
      // Method-gated like every sibling route above (path+method in one
      // condition): the container always POSTs here, so any other verb should
      // fall through to the same unknown_storage_route 404 as an unmatched path,
      // not be silently forwarded to the platform as a hardcoded POST.
      if (!env.PLATFORM) return json({ error: "connections_unavailable" }, 501);
      const name = path.slice("/_connections/".length);
      if (!CONNECTION_NAME_RE.test(name)) return json({ error: "bad_connection_name" }, 400);
      return env.PLATFORM.fetch("https://platform.internal/_connections/fetch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ assertion: request.headers.get("x-caller-assertion") ?? "", connection: name }),
      });
    }
    return json({ error: "unknown_storage_route" }, 404);
  } catch (e) {
    return json({ error: "storage_error", detail: String(e).slice(0, 200) }, 500);
  }
}

async function readJson<T>(req: Request): Promise<T | null> {
  try { return await req.json<T>(); } catch { return null; }
}
function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
