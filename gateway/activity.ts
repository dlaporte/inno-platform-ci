// Human-activity touch (spec 2026-08-18-human-activity-idle-clock): when an
// authenticated request is real human use, tell the platform so the app's
// idle clock advances. Wired in index.ts after each perimeter's auth.
//
// gateway/ builds separately from src/ and cannot import it — TOUCH_PATH is a
// deliberately duplicated constant (twin: src/routes/activity.ts), pinned by
// test/constant-parity.node.test.ts.
export const TOUCH_PATH = "/_activity/touch";

// JSON-RPC methods that are real work. Protocol chatter (initialize, ping,
// */list, notifications/*) is deliberately absent: a connected-but-unused MCP
// client must not keep its app alive.
const WORK_METHODS = new Set(["tools/call", "resources/read", "prompts/get", "completion/complete"]);

// Peeking means buffering a clone of the body; past this size skip the parse
// and count the request as work — a large POST /mcp under a real user token
// is almost certainly a tools/call payload.
const PEEK_MAX_BYTES = 262_144;

// At most one send per host per window. Module-scope is per-isolate, and each
// app's gateway is its own Worker, so the key space is one host; isolate
// recycling just causes an occasional extra send against an idempotent write.
const TOUCH_DEBOUNCE_MS = 60 * 60_000;
const lastSentAt = new Map<string, number>();

export function shouldTouch(host: string, nowMs: number): boolean {
  const last = lastSentAt.get(host);
  return last === undefined || nowMs - last >= TOUCH_DEBOUNCE_MS;
}

export function markTouched(host: string, nowMs: number): void {
  lastSentAt.set(host, nowMs);
}

// Does this POST /mcp carry a work method? Parses a CLONE so the forwarded
// body is untouched. Unparseable → false (the app will reject it anyway).
export async function mcpWorkRequest(req: Request): Promise<boolean> {
  // A chunked body (no content-length header) falls through this cap
  // uncounted and is buffered whole by the clone-parse below — accepted for
  // now; a read-N-bytes guard belongs to the platform's seam size-caps
  // workstream, not here.
  if (Number(req.headers.get("content-length") ?? "0") > PEEK_MAX_BYTES) return true;
  let body: unknown;
  try { body = await req.clone().json(); } catch { return false; }
  const items = Array.isArray(body) ? body : [body];
  return items.some((m) => WORK_METHODS.has((m as { method?: string })?.method ?? ""));
}

// Fire-and-forget: a touch failure must never affect the user's request.
export async function sendTouch(platform: Fetcher, payload: Record<string, string>): Promise<void> {
  try {
    const res = await platform.fetch(`https://platform.internal${TOUCH_PATH}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
    });
    if (!res.ok) console.warn(`gateway: activity touch refused (${res.status})`);
  } catch (e) {
    console.warn(`gateway: activity touch failed: ${String(e).slice(0, 120)}`);
  }
}
