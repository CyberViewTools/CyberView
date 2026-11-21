// Fetch with a time limit, retries with backoff, and a per-source circuit breaker.
// A 429 or 503 with Retry-After is retried after the wait the source asked for (up to MAX_RETRY_AFTER_MS; a longer one ends the
// run and keeps the circuit open until then); e.retryAfterMs carries it to the caller.
// Errors carry a short code: timeout, http_<status>, network (DNS, refused), circuit_open, bad_json; an HTTP error also
// carries the first 4,000 characters of the reply as e.body (so a caller can tell "no key saved" from another refusal).
const circuits = new Map();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class FetchError extends Error {
  constructor(code, message) { super(message || code); this.code = code; }
}

/** Pure: a Retry-After header (delay-seconds or an HTTP date) in milliseconds from now; 0 when absent or unreadable. */
export function retryAfterMs(v, now = Date.now()) {
  const s = String(v == null ? "" : v).trim();
  if (!s) return 0;
  if (/^\d+$/.test(s)) return Number(s) * 1000;
  const t = Date.parse(s);
  return isFinite(t) ? Math.max(0, t - now) : 0;
}
// a 429 or 503 that asks for a longer wait than this is not retried in this run: the circuit stays open until then
export const MAX_RETRY_AFTER_MS = 60e3;

const retriable = (code) => code === "timeout" || code === "network" || /^http_(408|425|429|5\d\d)$/.test(code);

export function circuitOpen(key, threshold = 3, coolMs = 10 * 60e3) {
  const c = circuits.get(key);
  if (c && c.until && Date.now() < c.until) return true;               // the source asked us to wait (Retry-After)
  return !!(c && c.fails >= threshold && Date.now() - c.at < coolMs);
}

// get(url, { as: "json" | "text" | "buffer", range: "bytes=-65536", timeoutMs, retries, delayMs, factor, key })
export async function get(url, o = {}) {
  const { as = "json", timeoutMs = 20000, retries = 2, delayMs = 2000, factor = 3, key = new URL(url).host, range = "" } = o;
  if (circuitOpen(key)) throw new FetchError("circuit_open", `${key}: skipped after repeated failures`);
  let wait = delayMs, last;
  for (let i = 0; i <= retries; i++) {
    try {
      const headers = { "user-agent": "cyberview-feeds/1.0 (+https://github.com/xanderhutch/CyberView)" };
      if (/^bytes=-?\d+(-\d*)?$/.test(range)) headers.range = range;                   // part of a large file (e.g. the tail of a CSV)
      const r = await fetch(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
      if (!r.ok) { const e = new FetchError(`http_${r.status}`); e.retryAfterMs = r.status === 429 || r.status === 503 ? retryAfterMs(r.headers.get("retry-after")) : 0; try { e.body = (await r.text()).slice(0, 4000); } catch { e.body = null; } throw e; }
      if (as === "buffer") { const b = Buffer.from(await r.arrayBuffer()); circuits.delete(key); return b; }
      const body = await r.text();
      if (as === "text") { circuits.delete(key); return body; }
      try { const j = JSON.parse(body.replace(/^﻿/, "")); circuits.delete(key); return j; }
      catch { throw new FetchError("bad_json"); }
    } catch (e) {
      last = e instanceof FetchError ? e
        : new FetchError(e && (e.name === "TimeoutError" || e.name === "AbortError") ? "timeout" : "network", (e.cause && e.cause.code) || e.message);
      if (i === retries || !retriable(last.code)) break;
      // 429/503 with Retry-After: wait what the source asked (never less than our own backoff); a longer wait ends this run
      if (last.retryAfterMs > MAX_RETRY_AFTER_MS) break;
      await sleep(Math.max(wait, last.retryAfterMs || 0)); wait *= factor;
    }
  }
  const c = circuits.get(key) || { fails: 0, at: 0 };
  circuits.set(key, { fails: c.fails + 1, at: Date.now(), ...(last && last.retryAfterMs ? { until: Date.now() + last.retryAfterMs } : {}) });
  throw last;
}
