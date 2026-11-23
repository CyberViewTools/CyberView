// Weekly source link check, no AI model. Run: node scripts/linkcheck.mjs   (behind a proxy: NODE_USE_ENV_PROXY=1)
// Checks the source URLs of events from the last 30 days, at most LINKCHECK_MAX (default 400) per run, four at a time.
// The sorted list is walked in slices: each run starts where the last one stopped (`next` in linkcheck.json), so every URL is reached.
// Writes data/linkcheck.json: {checked_at, checked, total, next, broken:[{event_id,url,status}], blocked:n}.
//   broken  = 404, 410 or the host no longer exists: the data steward finds a replacement or removes the source
//   blocked = 401, 403, 429 or 5xx: the site refuses automated readers or is busy; not counted as broken
// The run never edits events; it only reports.
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, writeJson, nowIso, listEventFiles, dayAgo, readJson, readStatus } from "./lib/store.mjs";

export function classify(status, code) {
  if (status === 404 || status === 410) return "broken";
  if (code === "ENOTFOUND" || code === "EAI_AGAIN_FINAL") return "broken";
  if (status >= 200 && status < 400) return "ok";
  return "blocked";
}

export async function check(u) {
  for (const method of ["HEAD", "GET"]) {
    try {
      const r = await fetch(u, { method, redirect: "follow", signal: AbortSignal.timeout(15000), headers: { "user-agent": "cyberview-linkcheck/1.0 (+https://github.com/xanderhutch/CyberView)" } });
      if (method === "HEAD" && (r.status === 405 || r.status === 403 || r.status === 400 || r.status === 404 || r.status === 410)) continue;   // some servers refuse HEAD only, or answer it 404 for a live page: only a GET that agrees makes a link broken
      return { status: r.status, code: "" };
    } catch (e) { const code = (e.cause && e.cause.code) || e.name || "error"; if (method === "GET") return { status: 0, code }; }
  }
  return { status: 0, code: "error" };
}

/** Pure: the slice of `list` (sorted, so the order is the same every run) of `max` items from `offset`, wrapping round the end.
 *  -> { slice, next } where next is the offset the following run starts from. A missing or bad offset starts at 0. */
export function rotate(list, offset, max) {
  const n = list.length; if (!n) return { slice: [], next: 0 };
  const o = Number.isInteger(offset) && offset >= 0 ? offset % n : 0, k = Math.min(max, n);
  return { slice: Array.from({ length: k }, (_, i) => list[(o + i) % n]), next: (o + k) % n };
}

async function main() {
const MAX = Number(process.env.LINKCHECK_MAX || 400);
const evs = listEventFiles().map((f) => f.e).filter((e) => e && !e.duplicate_of && e.date >= dayAgo(30));
const jobs = [];
for (const e of evs) for (const s of e.sources || []) if (/^https?:\/\//.test(s.url || "")) jobs.push({ id: e.id, url: s.url });
const all = [...new Map(jobs.map((j) => [j.url, j])).values()].sort((a, b) => (a.url < b.url ? -1 : a.url > b.url ? 1 : 0));
const prev = readJson(join(DATA, "linkcheck.json"), {}) || {};   // no file or no `next` yet on the first run: start at 0
const { slice: uniq, next } = rotate(all, prev.next, MAX);

const out = { checked_at: nowIso(), checked: uniq.length, total: all.length, next, broken: [], blocked: 0 };
for (let i = 0; i < uniq.length; i += 4) {
  const batch = uniq.slice(i, i + 4);
  const res = await Promise.all(batch.map((j) => check(j.url)));
  res.forEach((r, k) => {
    const c = classify(r.status, r.code);
    if (c === "broken") out.broken.push({ event_id: batch[k].id, url: batch[k].url, status: r.status || r.code });
    else if (c === "blocked") out.blocked++;
  });
}
writeJson(join(DATA, "linkcheck.json"), out);
const sp = join(DATA, "status.json"), st = readStatus();
st.last_linkcheck_at = out.checked_at; writeJson(sp, st);
console.log(`linkcheck: ${out.checked} links, ${out.broken.length} broken, ${out.blocked} blocked or busy (not counted)`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
