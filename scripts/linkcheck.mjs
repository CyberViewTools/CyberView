// Weekly source link check, no AI model. Run: node scripts/linkcheck.mjs   (behind a proxy: NODE_USE_ENV_PROXY=1)
// Checks every source URL of events from the last 30 days (at most LINKCHECK_MAX, default 400), four at a time.
// Writes data/linkcheck.json: {checked_at, checked, broken:[{event_id,url,status}], blocked:n}.
//   broken  = 404, 410 or the host no longer exists: the data steward finds a replacement or removes the source
//   blocked = 401, 403, 429 or 5xx: the site refuses automated readers or is busy; not counted as broken
// The run never edits events; it only reports.
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, writeJson, nowIso, listEventFiles, dayAgo, readJson } from "./lib/store.mjs";

export function classify(status, code) {
  if (status === 404 || status === 410) return "broken";
  if (code === "ENOTFOUND" || code === "EAI_AGAIN_FINAL") return "broken";
  if (status >= 200 && status < 400) return "ok";
  return "blocked";
}

async function check(u) {
  for (const method of ["HEAD", "GET"]) {
    try {
      const r = await fetch(u, { method, redirect: "follow", signal: AbortSignal.timeout(15000), headers: { "user-agent": "cyberview-linkcheck/1.0 (+https://github.com/xanderhutch/CyberView)" } });
      if (method === "HEAD" && (r.status === 405 || r.status === 403 || r.status === 400)) continue;   // some servers refuse HEAD only
      return { status: r.status, code: "" };
    } catch (e) { const code = (e.cause && e.cause.code) || e.name || "error"; if (method === "GET") return { status: 0, code }; }
  }
  return { status: 0, code: "error" };
}

async function main() {
const MAX = Number(process.env.LINKCHECK_MAX || 400);
const evs = listEventFiles().map((f) => f.e).filter((e) => e && !e.duplicate_of && e.date >= dayAgo(30));
const jobs = [];
for (const e of evs) for (const s of e.sources || []) if (/^https?:\/\//.test(s.url || "")) jobs.push({ id: e.id, url: s.url });
const uniq = [...new Map(jobs.map((j) => [j.url, j])).values()].slice(0, MAX);

const out = { checked_at: nowIso(), checked: uniq.length, broken: [], blocked: 0 };
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
const sp = join(DATA, "status.json"), st = readJson(sp, {});
st.last_linkcheck_at = out.checked_at; writeJson(sp, st);
console.log(`linkcheck: ${out.checked} links, ${out.broken.length} broken, ${out.blocked} blocked or busy (not counted)`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
