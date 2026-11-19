// How fast a lead becomes a published, reviewed event: minutes from the first time a collector saw one of the
// event's source URLs to the event's first_seen (published) and to its review. No AI model.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { DATA } from "./store.mjs";

/** Pure: leadSeen Map(url -> ISO), events [{first_seen, sources, review}] -> { n, publish: {p50,p90}, review: {n,p50,p90} } */
export function latency(leadSeen, events, since) {
  const pub = [], rev = [];
  for (const e of events) {
    if (!e.first_seen || e.first_seen < since || e.duplicate_of) continue;
    let t = null;
    for (const s of e.sources || []) { const x = leadSeen.get((s && s.url) || s); if (x && (!t || x < t)) t = x; }
    if (!t || t > e.first_seen) continue;
    pub.push((Date.parse(e.first_seen) - Date.parse(t)) / 6e4);
    if (e.review && e.review.at && e.review.at >= t) rev.push((Date.parse(e.review.at) - Date.parse(t)) / 6e4);
  }
  const q = (a, p) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y); return Math.round(s[Math.min(s.length - 1, Math.floor(p * s.length))]); };
  return { n: pub.length, publish: { p50: q(pub, 0.5), p90: q(pub, 0.9) }, review: { n: rev.length, p50: q(rev, 0.5), p90: q(rev, 0.9) } };
}

export function measure(hours = 24, now = Date.now()) {
  const since = new Date(now - hours * 36e5).toISOString(), seen = new Map(), dir = join(DATA, "leads");
  for (const f of existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith(".jsonl")).sort().slice(-3) : [])
    for (const l of readFileSync(join(dir, f), "utf8").split("\n")) {
      if (!l) continue; let j; try { j = JSON.parse(l); } catch { continue; }
      if (j.url && j.seen_at && (!seen.has(j.url) || seen.get(j.url) > j.seen_at)) seen.set(j.url, j.seen_at);
    }
  const events = [], ed = join(DATA, "events");
  for (const m of existsSync(ed) ? readdirSync(ed).sort().slice(-2) : []) for (const f of readdirSync(join(ed, m)))
    try { events.push(JSON.parse(readFileSync(join(ed, m, f), "utf8"))); } catch {}
  return { hours, ...latency(seen, events, since) };
}
