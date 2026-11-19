// Fetch with a time limit, retries with backoff, and a per-source circuit breaker.
// Errors carry a short code: timeout, http_<status>, network (DNS, refused), circuit_open, bad_json; an HTTP error also
// carries the first 4,000 characters of the reply as e.body (so a caller can tell "no key saved" from another refusal).
const circuits = new Map();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class FetchError extends Error {
  constructor(code, message) { super(message || code); this.code = code; }
}

const retriable = (code) => code === "timeout" || code === "network" || /^http_(408|425|429|5\d\d)$/.test(code);

export function circuitOpen(key, threshold = 3, coolMs = 10 * 60e3) {
  const c = circuits.get(key);
  return !!(c && c.fails >= threshold && Date.now() - c.at < coolMs);
}

// get(url, { as: "json" | "text" | "buffer", timeoutMs, retries, delayMs, factor, key })
export async function get(url, o = {}) {
  const { as = "json", timeoutMs = 20000, retries = 2, delayMs = 2000, factor = 3, key = new URL(url).host } = o;
  if (circuitOpen(key)) throw new FetchError("circuit_open", `${key}: skipped after repeated failures`);
  let wait = delayMs, last;
  for (let i = 0; i <= retries; i++) {
    try {
      const r = await fetch(url, { headers: { "user-agent": "cyberview-feeds/1.0 (+https://github.com/xanderhutch/CyberView)" }, signal: AbortSignal.timeout(timeoutMs) });
      if (!r.ok) { const e = new FetchError(`http_${r.status}`); try { e.body = (await r.text()).slice(0, 4000); } catch { e.body = null; } throw e; }
      if (as === "buffer") { const b = Buffer.from(await r.arrayBuffer()); circuits.delete(key); return b; }
      const body = await r.text();
      if (as === "text") { circuits.delete(key); return body; }
      try { const j = JSON.parse(body.replace(/^﻿/, "")); circuits.delete(key); return j; }
      catch { throw new FetchError("bad_json"); }
    } catch (e) {
      last = e instanceof FetchError ? e
        : new FetchError(e && (e.name === "TimeoutError" || e.name === "AbortError") ? "timeout" : "network", (e.cause && e.cause.code) || e.message);
      if (i === retries || !retriable(last.code)) break;
      await sleep(wait); wait *= factor;
    }
  }
  const c = circuits.get(key) || { fails: 0, at: 0 };
  circuits.set(key, { fails: c.fails + 1, at: Date.now() });
  throw last;
}
