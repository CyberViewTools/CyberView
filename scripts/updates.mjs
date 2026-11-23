// New reporting on events already on the map. No AI model. Run: node scripts/updates.mjs <command>
// The triage desk closes a lead whose title matches an event on file ("already on file"), which is right for repeats
// but drops new facts: a confirmation, a figure, an attribution, a patch. This finds leads that match a published
// event, come from a page the event does not cite, and appeared after the event was last updated, so an updater
// (a worker in the research loop) can read them and update the event; the second review then checks the update.
//   plan [--max W] [--per N] [--file F] [--dry-run]   assign the strongest candidates to W updaters (default data/update-plan.json)
// An updater is only ever started for a page nobody has recorded yet (handledFrom: read once; a page that would not load
// is tried once more an hour later, then dropped) and never for an aggregator's redirect (isRedirect).
//   done <event-id> <updated|unchanged|unrelated|unreachable> <url> [url...]   record what an updater found (data/runs/<day>/followups.jsonl)
//   list [--json]                          the candidates now
import { existsSync, readdirSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, readJson, writeJson, nowIso, dayAgo, listEventFiles } from "./lib/store.mjs";
import { matchEvent } from "./triage.mjs";
import { leased } from "./lib/lease.mjs";
import { deepEvent } from "./lib/routing.mjs";

const NOT_NEWS = new Set(["claim", "breach-db", "status", "cve"]);   // attackers' posts and database rows are not reporting
const TIER = { gov: 3, vendor: 3, research: 2, news: 1 };
const CVE = /CVE-\d{4}-\d{4,}/g;

/** Pure: is this an aggregator's redirect, not a publisher's page? An updater cannot read or cite one (measured
 *  2026-11-20 to 22: 82 of 145 "unreachable" outcomes were news.google.com links, each tried twice by a worker). */
export const isRedirect = (u) => /^https:\/\/(news\.google\.com\/|(www\.)?bing\.com\/news|(www\.)?msn\.com\/)/.test(String(u || ""));
/** Pure: leads + events + handled urls -> [{id, title, severity, status, score, leads: [...]}], strongest first.
 *  opts.redirects (default false): keep aggregator redirects. An updater is never started for one (it is left out here,
 *  and counted by skippedRedirects for the plan line); the follow-up desk keeps them as a sign that a story moved. */
export function candidates(leads, events, handled, now = Date.now(), hours = 48, opts = {}) {
  const evs = events.filter((e) => e && !e.duplicate_of && e.id), since = new Date(now - hours * 36e5).toISOString();
  const byCve = new Map(); for (const e of evs) for (const c of e.cves || []) if (!byCve.has(c)) byCve.set(c, e);
  const out = new Map();
  for (const l of leads) {
    if (!l || !/^https:\/\//.test(l.url || "") || NOT_NEWS.has(l.kind) || handled.has(l.url)) continue;
    if (!opts.redirects && isRedirect(l.url)) continue;
    const at = String(l.published || l.seen_at || ""); if (at < since) continue;
    const m = matchEvent(String(l.title || ""), evs, l.published || l.seen_at);
    const e = m ? evs.find((x) => x.id === m.id) : (String(l.title || "").match(CVE) || []).map((c) => byCve.get(c)).find(Boolean);
    if (!e) continue;
    if ((e.sources || []).some((s) => (s && s.url) === l.url)) continue;
    if (at <= String(e.updated_at || e.first_seen || "")) continue;   // already there when the event was last written
    const c = out.get(e.id) || { id: e.id, title: String(e.title || "").slice(0, 160), severity: e.severity || 1, status: e.status || "", deep: deepEvent(e), leads: [] };
    if (!c.leads.some((x) => x.url === l.url)) c.leads.push({ url: l.url, title: String(l.title || "").slice(0, 200), source: String(l.source || "").slice(0, 80), tier: l.tier || "", published: at.slice(0, 20), lang: l.lang || "" });
    out.set(e.id, c);
  }
  for (const c of out.values()) {
    const pubs = new Set(c.leads.map((l) => l.source)).size, best = Math.max(...c.leads.map((l) => TIER[l.tier] || 0));
    c.score = c.severity * 10 + best * 5 + Math.min(pubs, 4) * 3 + (/developing|claimed/.test(c.status) ? 8 : 0);
    c.leads.sort((a, b) => isRedirect(a.url) - isRedirect(b.url) || (TIER[b.tier] || 0) - (TIER[a.tier] || 0) || b.published.localeCompare(a.published));
    c.leads = c.leads.slice(0, 6);
  }
  return [...out.values()].sort((a, b) => b.score - a.score);
}

/** Pure: split candidates between at most W updaters, at most `per` each. Severity 3 and exploited events (c.deep,
 *  scripts/lib/routing.mjs deepEvent) go to their own batches, whose updater runs as updater-deep (Opus); the rest to
 *  routine ones. -> {batches: [[c...]...], deep: [batch numbers]} */
export function planUpdates(q, W, per) {
  const d = q.filter((c) => c.deep), p = q.filter((c) => !c.deep);
  let kd = d.length ? Math.ceil(d.length / per) : 0, kp = p.length ? Math.ceil(p.length / per) : 0;
  while (kd + kp > Math.max(1, W) && (kd > 1 || kp > 1)) { if (kd >= kp && kd > 1) kd--; else kp--; }
  if (kd + kp > Math.max(1, W)) kp = 0;   // one updater and both kinds: the severity 3 and exploited events first, the rest next cycle
  const deal = (xs, k) => { const b = Array.from({ length: k }, () => []); xs.slice(0, k * per).forEach((c, i) => b[i % k].push(c)); return b; };
  const batches = [...deal(d, kd), ...deal(p, kp)].filter((b) => b.length);
  return { batches, deep: batches.map((b, i) => (b.some((c) => c.deep) ? i + 1 : 0)).filter(Boolean) };
}
/** Pure: follow-up records -> urls not to hand out again. A page that would not load is tried once more an hour later, then dropped. */
export function handledFrom(records, now = Date.now()) {
  const by = new Map();
  for (const r of records) for (const u of (r && r.urls) || []) { const x = by.get(u) || { done: false, tries: 0, last: "" }; if (r.outcome === "unreachable") { x.tries++; if (r.at > x.last) x.last = r.at; } else x.done = true; by.set(u, x); }
  const s = new Set();
  for (const [u, x] of by) if (x.done || x.tries >= 2 || now - Date.parse(x.last) < 60 * 6e4) s.add(u);
  return s;
}
function handledUrls(days = 7) {
  const recs = [], runs = join(DATA, "runs");
  if (existsSync(runs)) for (const d of readdirSync(runs).filter((d) => d >= dayAgo(days))) {
    const f = join(runs, d, "followups.jsonl"); if (!existsSync(f)) continue;
    for (const line of readFileSync(f, "utf8").split("\n")) { try { recs.push(JSON.parse(line)); } catch {} }
  }
  return handledFrom(recs);
}
export function recentLeads(days = 3) {
  const dir = join(DATA, "leads"), out = [];
  if (existsSync(dir)) for (const f of readdirSync(dir).filter((f) => f.endsWith(".jsonl") && f.slice(0, 10) >= dayAgo(days)))
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) { try { out.push(JSON.parse(line)); } catch {} }
  return out;
}
export function current(opts = {}) {
  const events = listEventFiles().map((f) => f.e).filter((e) => e && e.date >= dayAgo(30));
  return candidates(recentLeads(), events, handledUrls(), Date.now(), 48, opts);
}
/** Pure: what the plan leaves without an updater because every new lead for the event is an aggregator redirect
 *  (before 2026-11-23 each got a worker, twice): all = candidates with redirects kept, kept = the plan's candidates.
 *  -> { events, leads }. They are not lost: the follow-up desk counts such a lead as new reporting. */
export function redirectOnly(all, kept) {
  const ids = new Set((kept || []).map((c) => c.id)), out = (all || []).filter((c) => !ids.has(c.id));
  return { events: out.length, leads: out.reduce((s, c) => s + c.leads.length, 0) };
}

function main() {
  const [cmd, ...rest] = process.argv.slice(2), arg = (k, d) => { const i = rest.indexOf("--" + k); return i >= 0 ? rest[i + 1] : d; };
  if (cmd === "plan") {
    const W = Math.max(1, Math.min(4, Number(arg("max", 2)) || 2)), per = Math.max(1, Math.min(6, Number(arg("per", 3)) || 3));
    const file = /^update-plan(-[A-Za-z0-9-]+)?\.json$/.test(arg("file", "")) ? arg("file") : "update-plan.json";
    const all = current(), held = leased("event", all.map((c) => c.id), process.env.CYBERVIEW_RUN || ""), q = all.filter((c) => !held.has(c.id)).slice(0, W * per);
    const { batches, deep } = planUpdates(q, W, per);
    if (!rest.includes("--dry-run")) writeJson(join(DATA, file), { planned_at: nowIso(), batches, deep });
    let red = { events: 0, leads: 0 }; try { red = redirectOnly(current({ redirects: true }), all); } catch {}
    console.log(`UPDATE PLAN: ${q.length} event(s) with new reporting for ${batches.length} updater(s), ${deep.length} on the deep model; ${all.length} candidate(s) in all${red.events ? `; ${red.events} skipped: only an aggregator's redirect names them (${red.leads} link(s)), left to the follow-up desk` : ""}.`);
    return;
  }
  if (cmd === "done") {
    const [id, outcome, ...urls] = rest;
    if (!/^[a-z0-9][a-z0-9-]{2,119}$/.test(id || "") || !["updated", "unchanged", "unrelated", "unreachable"].includes(outcome) || !urls.length || urls.some((u) => !/^https:\/\//.test(u))) {
      console.error("usage: updates.mjs done <event-id> <updated|unchanged|unrelated|unreachable> <https url> [url...]"); process.exit(1);
    }
    const at = nowIso(), dir = join(DATA, "runs", at.slice(0, 10)); mkdirSync(dir, { recursive: true });
    appendFileSync(join(dir, "followups.jsonl"), JSON.stringify({ at, event: id, outcome, urls }) + "\n");
    console.log(`recorded: ${id} ${outcome} (${urls.length} page(s))`);
    return;
  }
  if (cmd === "list") {
    const c = current();
    if (rest.includes("--json")) { console.log(JSON.stringify(c)); return; }
    console.log(`${c.length} published event(s) with new reporting:`);
    c.slice(0, 30).forEach((x) => { console.log(`[${x.score}] ${x.id}  ${x.title}`); x.leads.forEach((l) => console.log(`     ${l.source} (${l.tier || "?"}): ${l.title}\n       ${l.url}`)); });
    return;
  }
  console.error("usage: updates.mjs plan [--max W] [--per N] [--file F] | done <id> <outcome> <url...> | list [--json]"); process.exit(1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
