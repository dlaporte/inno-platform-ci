import type { Env } from "./env";

type S = Pick<Env, "DB" | "FILES">;

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
    if (path === "/_storage/files" && m === "GET") {
      const list = await env.FILES.list();
      return json({ keys: list.objects.map((o) => o.key) });
    }
    const fileMatch = path.match(/^\/_storage\/files\/(.+)$/);
    if (fileMatch) {
      const key = decodeURIComponent(fileMatch[1]);
      if (m === "PUT") {
        const len = request.headers.get("content-length");
        if (len && Number(len) > 26214400) return json({ error: "too_large" }, 413);
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
