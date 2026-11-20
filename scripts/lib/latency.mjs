// How fast a lead becomes a published, reviewed event, in minutes. No AI model.
//   publish: from the lead that started the work to the event's first_seen (published)
//   review:  from the same lead to the event's FIRST second review (review.first_at; review.at for events reviewed before
//            first_at was kept). A later re-review after an update is not "the review of the new event": it is measured
//            on its own as rereview (event changed -> reviewed again).
// "The lead that started the work" is the first time a collector saw one of the event's source URLs, except for a story
// that was closed before (by the owner's rules or by a researcher: not an event, could not confirm, part of another
// event) and reopened when new reporting joined it: its clock starts at the first lead seen after the last closure, among
// the event's sources and the story's URLs. Before that the pipeline had decided not to publish, which is not waiting.
// Such events are counted as `reopened`, and `publish_from_first_lead` keeps the plain figure (first lead ever) so the
// difference stays visible.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { DATA } from "./store.mjs";

const mins = (a, b) => (Date.parse(b) - Date.parse(a)) / 6e4;
const q = (a, p) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y); return Math.round(s[Math.min(s.length - 1, Math.floor(p * s.length))]); };
const urlOf = (s) => (s && s.url) || s;

/** Pure: when the work on event e started. leadSeen Map(url -> ISO); closures Map(url -> [{at, reason}]) (optional);
 *  storyUrls: urls of the story that became e (from its own closure record). Returns { t, first, reopened }. */
export function startOf(e, leadSeen, closures = new Map(), storyUrls = []) {
  let first = null;
  for (const s of e.sources || []) { const x = leadSeen.get(urlOf(s)); if (x && (!first || x < first)) first = x; }
  if (!first || first > e.first_seen) return { t: null, first, reopened: false };
  const urls = [...new Set((e.sources || []).map(urlOf).concat(storyUrls))];
  // the last time one of these urls was closed before the event was published, other than by becoming this event
  let last = null;
  for (const u of urls) for (const c of closures.get(u) || []) {
    if (!c.at || c.at >= e.first_seen || c.at < first || (e.id && String(c.reason || "").includes(e.id))) continue;
    if (!last || c.at > last) last = c.at;
  }
  if (!last) return { t: first, first, reopened: false };
  let next = null;   // the new reporting that reopened the story
  for (const u of urls) { const x = leadSeen.get(u); if (x && x > last && x <= e.first_seen && (!next || x < next)) next = x; }
  return next ? { t: next, first, reopened: true } : { t: first, first, reopened: false };   // no new lead found: count from the first, never less
}

/** Pure: leadSeen Map(url -> ISO), events [{id, first_seen, updated_at, sources, review}] -> the speed figures.
 *  closures Map(url -> [{at, reason}]), storyUrls Map(event id -> [url]) are optional (see startOf). */
export function latency(leadSeen, events, since, closures = new Map(), storyUrls = new Map()) {
  const pub = [], raw = [], rev = [], rer = []; let reopened = 0;
  for (const e of events) {
    if (!e.first_seen || e.duplicate_of) continue;
    const r = e.review && e.review.at ? e.review : null, firstRev = r && (r.first_at || r.at);
    // a re-review of an update (counted whenever the re-review falls in the window)
    if (r && r.first_at && r.at > r.first_at && r.at >= since && e.updated_at && e.updated_at > r.first_at && r.at >= e.updated_at) rer.push(mins(e.updated_at, r.at));
    if (e.first_seen < since) continue;
    const s = startOf(e, leadSeen, closures, storyUrls.get(e.id) || []);
    if (!s.t) continue;
    if (s.reopened) reopened++;
    pub.push(mins(s.t, e.first_seen)); raw.push(mins(s.first, e.first_seen));
    if (firstRev && firstRev >= s.t) rev.push(mins(s.t, firstRev));
  }
  return { n: pub.length, publish: { p50: q(pub, 0.5), p90: q(pub, 0.9) }, review: { n: rev.length, p50: q(rev, 0.5), p90: q(rev, 0.9) },
    reopened, publish_from_first_lead: { p50: q(raw, 0.5), p90: q(raw, 0.9) }, rereview: { n: rer.length, p50: q(rer, 0.5), p90: q(rer, 0.9) } };
}

/** Pure: one day's closures.jsonl text and run logs -> adds to closures Map(url -> [{at, reason}]) and storyUrls Map(event id -> urls). */
export function addClosures(closures, storyUrls, jsonlText, runLogs = [], eventIds = new Set()) {
  const add = (u, at, reason) => { if (u && at) (closures.get(u) || closures.set(u, []).get(u)).push({ at, reason: String(reason || "") }); };
  for (const line of String(jsonlText || "").split("\n")) {
    if (!line) continue; let c; try { c = JSON.parse(line); } catch { continue; }
    const why = String(c.reason || "").trim();
    if (eventIds.has(why)) storyUrls.set(why, [...new Set((storyUrls.get(why) || []).concat(c.urls || []))]);
    (c.urls || []).forEach((u) => add(u, c.at, why));
  }
  for (const r of runLogs) { const at = r && (r.finished_at || r.started_at); for (const l of (r && r.skipped) || []) if (l && l.url) add(l.url, at, l.reason); }
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
    try { events.push({ id: f.replace(/\.json$/, ""), ...JSON.parse(readFileSync(join(ed, m, f), "utf8")) }); } catch {}
  const closures = new Map(), storyUrls = new Map(), ids = new Set(events.map((e) => e.id)), rd = join(DATA, "runs");
  for (const d of existsSync(rd) ? readdirSync(rd).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort().slice(-3) : []) {
    const p = join(rd, d), files = readdirSync(p), logs = [];
    for (const f of files) if (f.endsWith(".json")) try { logs.push(JSON.parse(readFileSync(join(p, f), "utf8"))); } catch {}
    let text = ""; try { text = files.includes("closures.jsonl") ? readFileSync(join(p, "closures.jsonl"), "utf8") : ""; } catch {}
    addClosures(closures, storyUrls, text, logs, ids);
  }
  return { hours, ...latency(seen, events, since, closures, storyUrls) };
}
