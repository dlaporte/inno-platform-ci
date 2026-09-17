// Human-activity touch (spec 2026-08-18-human-activity-idle-clock): when an
// authenticated request is real human use, tell the platform so the app's
// idle clock advances. Wired in index.ts after each perimeter's auth.
import { PLATFORM_ORIGIN } from "./platform";

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
//
// The clone read is byte-counted and abandoned past PEEK_MAX_BYTES: the old
// form checked the declared Content-Length and then buffered the clone whole,
// so a chunked body of any size was peeked in full (its own comment said so).
// Over the cap still counts as WORK — a large POST /mcp under a real user
// token is almost certainly a tools/call payload.
export async function mcpWorkRequest(req: Request): Promise<boolean> {
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (declared > PEEK_MAX_BYTES) return true;
  const body = req.clone().body;
  if (!body) return false;
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > PEEK_MAX_BYTES) {
        await reader.cancel().catch(() => {});
        return true;
      }
      chunks.push(value);
    }
  } catch {
    return false;
  }
  const merged = new Uint8Array(total);
  let off = 0;
  for (const ch of chunks) { merged.set(ch, off); off += ch.byteLength; }
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder().decode(merged)); } catch { return false; }
  const items = Array.isArray(parsed) ? parsed : [parsed];
  return items.some((m) => WORK_METHODS.has((m as { method?: string })?.method ?? ""));
}

// Fire-and-forget: a touch failure must never affect the user's request.
export async function sendTouch(platform: Fetcher, payload: Record<string, string>): Promise<void> {
  try {
    const res = await platform.fetch(`${PLATFORM_ORIGIN}${TOUCH_PATH}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
    });
    if (!res.ok) console.warn(`gateway: activity touch refused (${res.status})`);
  } catch (e) {
    console.warn(`gateway: activity touch failed: ${String(e).slice(0, 120)}`);
  }
}
