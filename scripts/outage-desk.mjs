// The outage desk: which unchecked outage reports an AI checker should verify, who checks them, and what they found.
// No AI model in this script. Three kinds of report reach the map or the Grid view without anyone having checked them:
//   power     power outages reported in the news (data/grid/news.json, scripts/grid-news.mjs) that no operator feed covers
//             and the grid desk does not take (scripts/grid-desk.mjs newsCandidates checks the cause of the biggest ones)
//   internet  country-level internet disruptions measured by IODA (data/context/ioda.json, scripts/context.mjs)
//   service   major cloud and service outages from the providers' own status pages (leads of kind "status", scripts/osint.mjs;
//             backlog.mjs closes a story made only of these by rule, as a bare database row, so nobody read them)
// This plans them for outage checkers (role "outage", the "Outage checker" brief in docs/jobs.md), validates what they write,
// and keeps the result in data/outages/checks.json (written only here). A check says confirmed (with the source that
// confirms it), not_confirmed (with the reason) or cyber_lead. A cyber cause is never recorded as a fact here: it becomes ONE
// lead in data/leads/<day>.jsonl, and the research loop (with its second review) decides whether it is an event. A confirmed
// internet or service outage may name the category "outage" event the checker wrote or updated through the normal event
// checklist (the second review then checks it); a power outage stays context on the Grid view and never becomes an event.
//   plan [--max N] [--per K] [--file F] [--dry-run]   batches for N checkers, K reports each; leases kind "outage"
//   apply <out file> [--plan F]                       validate a checker's out file and record it (idempotent)
//   list [--json]                                     what is waiting and what was checked
//   status [--json]                                   waiting, checked in 24 h, oldest waiting (the build and the status page)
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join, isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, writeJson, nowIso, dayAgo, readStatus, listEventFiles } from "./lib/store.mjs";
import { claim, readLeases, RUN_ID } from "./lib/lease.mjs";
import { badSource, regDomain, OFFICIAL_HOST, newsCandidates, NATIONWIDE } from "./grid-desk.mjs";

export const BY = "CyberView AI (a Claude model)";
export const DECISIONS = ["confirmed", "not_confirmed", "cyber_lead"];
export const KINDS = ["power", "internet", "service"];
export const DEPTHS = ["full", "summary", "secondary"];
export const SAID_BY = ["official", "reported"];
// kinds whose confirmed outage may be (or update) a category "outage" event: telecom, internet and service outages are
// already events on the map (CLAUDE.md); a power outage is grid context and never an event
export const EVENT_KINDS = new Set(["internet", "service"]);
export const DEFAULTS = { recheck_hours: 12, max_tries: 2, news_min_figure: 5000, news_min_publishers: 3, news_skip_below: 1000, ioda_min_score: 10000, ioda_min_signals: 2, status_hours: 48, event_days: 2 };
// measurement and crowd-report sites: a signal, never a confirmation of an outage on their own
const MEASURE = /(^|\.)(ioda\.inetintel\.cc\.gatech\.edu|radar\.cloudflare\.com|downdetector\.[a-z.]+|isitdownrightnow\.com|statusgator\.com|outage\.report)$/;
// an attack named in a checker's text; NEG: the same words inside someone's denial ("ruled out a cyberattack")
export const ATTACK = /cyber[- ]?attack|\bhack(ed|ers?|ing)?\b|ransomware|\bddos\b|denial[- ]of[- ]service|malware|sabotage|intrusion|cyber[- ]incident/i;
export const NEG = /\b(not|no|never|ruled out|rules out|rule out|ruling out|unrelated to|denied|denies|deny)\b[^.;]{0,60}(cyber|attack|hack|ddos|malware|sabotage|intrusion)/i;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?Z$/;
const ID = /^(pw|net|svc)-[a-z0-9-]{3,150}$/;
const EVENT_ID = /^[a-z0-9][a-z0-9-]{2,150}$/;
const PLAN_FILE = /^outage-plan(-[A-Za-z0-9-]+)?\.json$/;

export const cfgOf = (c) => ({ ...DEFAULTS, ...(c || {}) });
const s = (v, n) => String(v ?? "").replace(/[\u0000-\u001f]/g, " ").slice(0, n);
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } };
const live = (l, now) => l && Date.parse(l.until) > now;
const isoAt = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");

/** Pure: every URL any event cites. */
export const citedUrls = (events) => new Set((events || []).flatMap((e) => (Array.isArray(e && e.sources) ? e.sources : []).map((x) => (x && typeof x === "object" ? x.url : x)).filter(Boolean)));

// ---------- the three kinds of report, each in the same item shape ----------
/** Pure: news-reported power outages for the desk, biggest stated figure first. Left out: those the grid desk checks
 *  (its newsCandidates, or a result on file as grid-news-<id>), those in a country where an operator incident is open
 *  (the operator's feed covers it), and those whose page an event already cites. */
export function powerItems(news, incidents, gridResearch = {}, cited = new Set(), cfg = {}, gridCfg = {}) {
  const c = cfgOf(cfg), list = (news && Array.isArray(news.items)) ? news.items : [];
  const gridTakes = new Set(newsCandidates(news, incidents, gridCfg).map((x) => x.id.replace(/^grid-news-/, "")));
  const open = Array.isArray(incidents) ? incidents.filter((i) => i && !i.closed_at) : ((incidents && incidents.open) || []);
  const covered = new Set(open.filter((i) => i && i.source !== "news").map((i) => i.country));
  const out = [];
  for (const it of list) {
    if (!it || !/^gn-[a-z]{2}-[a-z0-9-]+$/.test(it.id || "") || !Array.isArray(it.publishers) || !it.publishers.length) continue;
    if (gridTakes.has(it.id) || (gridResearch && gridResearch[`grid-news-${it.id}`]) || covered.has(it.country)) continue;
    if (it.publishers.some((p) => p && cited.has(p.url))) continue;
    const n = (it.figure && Number(it.figure.n)) || 0, titles = it.publishers.map((p) => String((p && p.title) || "")).join(" | ");
    if (!(n >= c.news_min_figure || it.publishers.length >= c.news_min_publishers || it.cyber_headline || NATIONWIDE.test(titles))) continue;
    if (n && n < c.news_skip_below && !it.cyber_headline) continue;   // a small stated figure is local news, unless a headline speaks of a cyberattack
    out.push({ id: `pw-${it.id}`.slice(0, 150), key: `pw-${it.id}`.slice(0, 150), kind: "power", country: s(it.country, 2), place: s(it.place, 80),
      title: s(`Power outage reported in ${it.place} (${it.publishers.length} publisher${it.publishers.length === 1 ? "" : "s"})`, 160),
      first_seen: s(it.first_seen, 20), last_seen: s(it.last_seen || it.first_seen, 20),
      figure: n ? { n, unit: s(it.figure.unit, 12), by: s(it.figure.by, 80) } : null, cyber_headline: s(it.cyber_headline, 220),
      publishers: it.publishers.slice(0, 6).map((p) => ({ name: s(p && p.name, 80), title: s(p && p.title, 220), url: s(p && p.url, 400), published: s(p && p.published, 20) })),
      url: s(it.publishers[0].url, 400), rank: n * 10 + it.publishers.length });
  }
  return out.sort((a, b) => b.rank - a.rank || b.last_seen.localeCompare(a.last_seen) || a.id.localeCompare(b.id));
}

const sameCountry = (e, x) => { const c = String((e && e.country) || "").toLowerCase(); return !!c && [x.name, x.map_name].some((n) => n && String(n).toLowerCase() === c); };
/** Pure: IODA country signals strong enough to check (score or several independent measurements), strongest first.
 *  One item per country per UTC day (key net-<cc>, so a country is not checked again within recheck_hours). Left out:
 *  a country with a category "outage" event dated in the last event_days days (already matched to an event). */
export function internetItems(ioda, events = [], cfg = {}, now = Date.now()) {
  const c = cfgOf(cfg), at = String((ioda && ioda.fetched_at) || ""), day = (ISO.test(at) ? at : isoAt(now)).slice(0, 10).replace(/-/g, "");
  const since = new Date(now - c.event_days * 864e5).toISOString().slice(0, 10);
  const recent = (events || []).filter((e) => e && e.category === "outage" && !e.duplicate_of && String(e.date || "") >= since);
  const out = [];
  for (const x of (ioda && Array.isArray(ioda.items)) ? ioda.items : []) {
    if (!x || !/^[A-Z]{2}$/.test(x.code || "")) continue;
    const signals = Array.isArray(x.signals) ? x.signals.map((v) => s(v, 20)).slice(0, 4) : [], score = Number(x.score) || 0;
    if (!(score >= c.ioda_min_score || signals.length >= c.ioda_min_signals)) continue;
    if (recent.some((e) => sameCountry(e, x))) continue;
    const cc = x.code.toLowerCase();
    out.push({ id: `net-${cc}-${day}`, key: `net-${cc}`, kind: "internet", country: x.code, place: s(x.name, 60),
      title: s(`Internet disruption measured in ${x.name} (IODA: ${signals.join(", ") || "signal"})`, 160),
      first_seen: ISO.test(at) ? at : "", last_seen: ISO.test(at) ? at : "", score, signals, events: Number(x.events) || 0,
      url: /^https:\/\/ioda\.inetintel\.cc\.gatech\.edu\//.test(x.url || "") ? s(x.url, 300) : "", rank: score });
  }
  return out.sort((a, b) => b.rank - a.rank || a.id.localeCompare(b.id));
}

/** Pure: status-page outages (leads of kind "status") from the last status_hours (filed or started), biggest providers
 *  first (the lead's priority: the provider's tier in config/status-pages.json, 1 the biggest; a lead without one counts
 *  as 3), then newest. Left out: a page an event already cites, or a category "outage" event of the same provider on the
 *  same day. */
export function serviceItems(leads, events = [], cited = new Set(), cfg = {}, now = Date.now()) {
  const c = cfgOf(cfg), seen = new Set(), out = [];
  const outEv = (events || []).filter((e) => e && e.category === "outage" && !e.duplicate_of);
  for (const l of leads || []) {
    if (!l || l.kind !== "status" || !/^https:\/\//.test(l.url || "") || seen.has(l.url)) continue;
    const t = Date.parse(l.published || l.seen_at || ""), f = Math.max(t, Date.parse(l.seen_at || "") || 0); if (!isFinite(t) || now - f > c.status_hours * 36e5) continue;
    seen.add(l.url);
    if (cited.has(l.url)) continue;
    const provider = s(String(l.source || "").replace(/ status$/i, ""), 60), day = isoAt(t).slice(0, 10);
    if (provider && outEv.some((e) => String(e.date) === day && new RegExp(`\\b${provider.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i").test(`${e.org || ""} ${e.title || ""}`))) continue;
    out.push({ id: `svc-${createHash("sha1").update(l.url).digest("hex").slice(0, 12)}`, key: `svc-${createHash("sha1").update(l.url).digest("hex").slice(0, 12)}`, kind: "service",
      country: s(l.country, 2), place: provider, provider, title: s(l.title, 160), first_seen: isoAt(t), last_seen: isoAt(t), summary: s(l.summary, 300), url: s(l.url, 400),
      priority: [1, 2, 3].includes(Number(l.priority)) ? Number(l.priority) : 3, rank: t });
  }
  return out.sort((a, b) => a.priority - b.priority || b.rank - a.rank || a.id.localeCompare(b.id));
}

/** Pure: is an item due for a check? Not when a final result is on file, when max_tries is reached, when it or another
 *  item with the same key was checked in the last recheck_hours, or while another run holds its lease. */
export function due(it, checks = {}, leases = {}, now = Date.now(), cfg = {}) {
  const c = cfgOf(cfg), r = checks[it.id];
  if (r && (r.final || (Number(r.tries) || 0) >= c.max_tries)) return false;
  for (const [, v] of Object.entries(checks)) if (v && v.key === it.key && now - Date.parse(v.checked_at) < c.recheck_hours * 36e5) return false;
  const l = leases[`outage:${it.id}`]; if (live(l, now) && l.run !== c.run) return false;
  return true;
}
/** Pure: the queue, most important first: the three kinds in turn (service, internet, power), each kind in its own order,
 *  so one kind can never crowd out the others. */
export function queue(lists, checks = {}, leases = {}, now = Date.now(), cfg = {}) {
  const per = ["service", "internet", "power"].map((k) => ((lists && lists[k]) || []).filter((it) => it && ID.test(it.id) && due(it, checks, leases, now, cfg)));
  const out = [];
  for (let i = 0; per.some((l) => i < l.length); i++) for (const l of per) if (i < l.length) out.push(l[i]);
  return out;
}

/** Pure: the facts a checker needs about one item (and what an earlier try found). */
export function brief(it, r) {
  const { rank, ...rest } = it;
  return { ...rest, earlier: r ? { decision: r.decision, summary: s(r.summary, 300), sources: (r.sources || []).slice(0, 6), tries: r.tries || 0 } : null };
}
/** Pure: a stable id for a plan: the same items in the same batches at the same try give the same id. */
export function planId(batches) {
  const map = []; batches.forEach((b, k) => (b.items || b).forEach((x) => map.push([x.id || x, k + 1, (x && x.earlier && Number(x.earlier.tries)) || 0])));
  map.sort((a, b) => a[0].localeCompare(b[0]));
  return "op-" + createHash("sha256").update(JSON.stringify(map)).digest("hex").slice(0, 16);
}
/** Pure: the queue -> { plan_id, batches: [{ batch, out, items }] } for at most max checkers, per each. */
export function makePlan(q, checks = {}, max = 1, per = 4, tag = "") {
  const take = q.slice(0, max * per), k = Math.min(max, Math.ceil(take.length / per)), lists = Array.from({ length: k }, () => []);
  take.forEach((it, i) => lists[i % k].push(brief(it, checks[it.id])));
  const plan_id = planId(lists), t = String(tag).replace(/[^A-Za-z0-9-]/g, "-").slice(0, 80);
  return { plan_id, batches: lists.map((items, j) => ({ batch: j + 1, out: `outage-out${t ? "-" + t : ""}-${j + 1}.json`, items })) };
}

/** Pure: does this url sit on a government, regulator or operator host, or on the reporting provider's own domain (the
 *  status page's provider: cloudflarestatus.com for a Cloudflare status lead)? */
export function officialFor(u, item = {}) {
  const h = hostOf(u); if (!h) return false;
  if (OFFICIAL_HOST.test(h)) return true;
  if (item.kind === "service" && item.url && regDomain(hostOf(item.url)) === regDomain(h)) return true;
  return false;
}
/** Pure: the independent publishers among the sources (registrable domains), measurement and crowd-report sites left out. */
export const publishersOf = (sources) => new Set((sources || []).map(hostOf).filter((h) => h && !MEASURE.test(h)).map(regDomain));

/** Pure: check a checker's out file against its plan. events: Map of event id -> event (to check event_id).
 *  -> { ok, errors: [file-level problems: nothing is applied], bad: { id: [reasons] }, good: [results] } */
export function validate(plan, out, events = new Map(), now = Date.now()) {
  const errors = [], bad = {}, good = [];
  if (!plan || !plan.plan_id) return { ok: false, errors: ["no plan"], bad, good };
  if (!out || typeof out !== "object") return { ok: false, errors: ["out file is not a JSON object"], bad, good };
  if (out.plan_id !== plan.plan_id) errors.push(`plan_id ${JSON.stringify(out.plan_id ?? null)} does not match the plan (${plan.plan_id})`);
  const batches = plan.batches || [], mine = out.batch != null ? batches.filter((b) => String(b.batch) === String(out.batch)) : batches;
  if (out.batch != null && !mine.length) errors.push(`batch ${out.batch} is not in the plan`);
  const planned = new Map(); mine.forEach((b) => (b.items || []).forEach((i) => planned.set(i.id, i)));
  if (!Array.isArray(out.results)) errors.push("results is not an array");
  const count = new Map();
  for (const r of Array.isArray(out.results) ? out.results : []) {
    const id = r && r.id; count.set(id, (count.get(id) || 0) + 1);
    if (!planned.has(id)) errors.push(`${JSON.stringify(id ?? null)} was not planned`);
  }
  for (const [id, n] of count) if (n > 1) errors.push(`${id} appears ${n} times`);
  if (errors.length) return { ok: false, errors, bad, good };
  for (const id of planned.keys()) if (!count.has(id)) bad[id] = ["no result for this planned report"];
  for (const r of out.results) {
    const why = [], it = planned.get(r.id), src = Array.isArray(r.sources) ? r.sources : null, text = `${r.summary || ""} ${r.cause || ""}`;
    if (!DECISIONS.includes(r.decision)) why.push(`decision ${JSON.stringify(r.decision ?? null)} is not one of ${DECISIONS.join(", ")}`);
    if (typeof r.summary !== "string" || !r.summary.trim()) why.push("summary is empty");
    else if (r.summary.length > 300) why.push(`summary is ${r.summary.length} characters (at most 300)`);
    for (const [k, n] of [["publisher", 80], ["cause", 200], ["figures", 200]]) if (r[k] != null && (typeof r[k] !== "string" || r[k].length > n)) why.push(`${k} must be text of at most ${n} characters`);
    for (const k of ["started_at", "ended_at"]) if (r[k] != null && r[k] !== "" && (!ISO.test(String(r[k])) || Date.parse(r[k]) > now + 5 * 6e4)) why.push(`${k} must be a UTC time like 2026-11-20T14:05:00Z, not in the future (leave it out when no page states it)`);
    if (!DEPTHS.includes(r.read_depth)) why.push(`read_depth ${JSON.stringify(r.read_depth ?? null)} is not one of ${DEPTHS.join(", ")}`);
    if (!src) why.push("sources is not an array");
    else {
      if (src.length > 8) why.push("more than 8 sources");
      src.forEach((u) => { const b = badSource(u); if (b) why.push(`source ${String(u).slice(0, 120)}: ${b}`); });
      const official = src.some((u) => officialFor(u, it)), pubs = publishersOf(src);
      if (r.decision === "confirmed") {
        if (!(typeof r.publisher === "string" && r.publisher.trim())) why.push("confirmed needs publisher (who confirmed it)");
        if (!official && pubs.size < 2) why.push("confirmed needs the operator's, provider's or a government's own page, or two independent credible publishers (a measurement or crowd-report site does not count)");
      }
      if (r.decision === "cyber_lead") {
        if (!src.length) why.push("cyber_lead needs the page that reports the cyber cause");
        if (!(typeof r.publisher === "string" && r.publisher.trim())) why.push("cyber_lead needs publisher (who reported the cyber cause)");
        if (!SAID_BY.includes(r.said_by)) why.push(`cyber_lead needs said_by: ${SAID_BY.join(" or ")}`);
        else if (r.said_by === "official" && !official) why.push("an attack claim said_by official needs a source on a government, regulator, operator or the provider's own site");
        else if (r.said_by === "reported" && !/unconfirmed|not confirmed|has not confirmed|have not confirmed/i.test(r.summary || "")) why.push("a reported cyber cause must say in the summary that it is unconfirmed");
      }
      if (r.decision !== "cyber_lead" && ATTACK.test(text) && !NEG.test(text)) why.push("the text names an attack: an outage is never called an attack here; when a source links it to a cyberattack the decision is cyber_lead");
      if (r.decision !== "cyber_lead" && ATTACK.test(text) && NEG.test(text) && !src.length) why.push("a denial of a cyber cause is someone's statement: cite the page that says it");
    }
    if (r.event_id != null && r.event_id !== "") {
      if (r.decision !== "confirmed") why.push("event_id only with a confirmed outage");
      else if (!it || !EVENT_KINDS.has(it.kind)) why.push("a power outage is grid context and never an event: leave event_id out");
      else if (!EVENT_ID.test(String(r.event_id))) why.push("event_id is not an event id");
      else { const e = events.get(r.event_id); if (!e) why.push(`event ${r.event_id} is not on file`); else if (e.category !== "outage") why.push(`event ${r.event_id} is category ${e.category}, not outage`); else if (e.duplicate_of) why.push(`event ${r.event_id} is a duplicate of ${e.duplicate_of}: name that one`); }
    }
    if (why.length) bad[r.id] = why; else good.push(r);
  }
  return { ok: !Object.keys(bad).length, errors, bad, good };
}

/** Pure: one checks.json entry from a valid result. Idempotent: the same plan_id for the same item returns null. */
export function entryFor(r, it, prev, plan_id, now = Date.now(), cfg = {}) {
  const c = cfgOf(cfg);
  if (prev && prev.plan_id === plan_id) return null;
  const tries = (Number(prev && prev.tries) || 0) + 1, final = r.decision !== "not_confirmed" || tries >= c.max_tries;
  const e = { kind: it.kind, key: it.key, title: s(it.title, 160), country: s(it.country, 2), place: s(it.place, 80), decision: r.decision, summary: r.summary.trim().slice(0, 300),
    publisher: s(r.publisher, 80).trim(), cause: r.decision === "confirmed" ? (s(r.cause, 200).trim() || "cause not stated") : s(r.cause, 200).trim(), figures: s(r.figures, 200).trim(),
    started_at: s(r.started_at, 20), ended_at: s(r.ended_at, 20), sources: [...new Set(r.sources)].slice(0, 8), read_depth: r.read_depth,
    checked_at: isoAt(now), tries, by: BY, final, plan_id };
  if (r.decision === "cyber_lead") e.said_by = r.said_by;
  if (r.event_id) e.event_id = r.event_id;
  return e;
}

/** Pure: the lead a cyber cause becomes (the normal research loop turns it into an event, or not). */
export function leadFor(it, e) {
  const official = e.said_by === "official", url = (official && e.sources.find((u) => officialFor(u, it))) || e.sources[0];
  return { seen_at: e.checked_at, source: hostOf(url).replace(/^www\./, ""), tier: official ? "gov" : "news", via: "outage-desk", kind: "outage",
    title: `Outage linked to a cyberattack (${official ? "official" : "reported, unconfirmed"}): ${s(it.title || it.id, 140)}`,
    url, published: e.checked_at, summary: e.summary.slice(0, 300), lang: "en", outage_id: it.id, ...(it.country ? { country: it.country } : {}) };
}

/** Pure: apply valid results. -> { checks, changed: [ids], leads: [lead] } (a lead only for an item that has none yet). */
export function applyResults(checks, plan, good, leadIds = new Set(), now = Date.now(), cfg = {}) {
  const next = { ...checks }, changed = [], leads = [], items = new Map();
  (plan.batches || []).forEach((b) => (b.items || []).forEach((i) => items.set(i.id, i)));
  for (const r of good) {
    const it = items.get(r.id) || { id: r.id, kind: "power", key: r.id };
    const e = entryFor(r, it, checks[r.id], plan.plan_id, now, cfg); if (!e) continue;
    next[r.id] = e; changed.push(r.id);
    if (e.decision === "cyber_lead" && e.sources.length && !leadIds.has(r.id)) { leads.push(leadFor(it, e)); leadIds.add(r.id); }
  }
  return { checks: next, changed, leads };
}

/** Pure: the numbers the status page shows: waiting now, checked in the last 24 h, and how long the oldest has waited. */
export function stats(q, checks = {}, now = Date.now()) {
  const day = Object.values(checks).filter((v) => v && now - Date.parse(v.checked_at) < 864e5);
  const ages = q.map((it) => (now - Date.parse(it.first_seen)) / 6e4).filter((m) => isFinite(m) && m >= 0);
  return { waiting: q.length, checked_24h: day.length, confirmed_24h: day.filter((v) => v.decision === "confirmed").length, cyber_leads_24h: day.filter((v) => v.decision === "cyber_lead").length,
    oldest_min: ages.length ? Math.round(Math.max(...ages)) : 0, by_kind: Object.fromEntries(KINDS.map((k) => [k, q.filter((it) => it.kind === k).length])) };
}

/** Pure: what the site shows for a check (scripts/build.mjs attaches it to the report it checked): the decision, who
 *  confirmed it (or reported the cyber link), the page that says so, the summary, when, and who wrote it. */
export function siteCheck(e) {
  if (!e || !DECISIONS.includes(e.decision)) return null;
  const pick = e.decision === "cyber_lead" && e.said_by === "official" ? (e.sources || []).find((u) => officialFor(u, { kind: e.kind, url: "" })) : null;
  const url = [pick, ...(e.sources || [])].find((u) => u && !badSource(u) && !MEASURE.test(hostOf(u))) || "";
  return { decision: e.decision, summary: s(e.summary, 300), publisher: s(e.publisher, 80), ...(e.decision === "cyber_lead" ? { said_by: SAID_BY.includes(e.said_by) ? e.said_by : "reported" } : {}),
    url: s(url, 400), at: s(e.checked_at, 20), by: BY };
}
/** Pure: the newest check of a key (an IODA country: net-<cc>) from the last `hours`, or null. */
export function latestFor(checks, key, now = Date.now(), hours = 48) {
  let best = null;
  for (const v of Object.values(checks || {})) if (v && v.key === key && now - Date.parse(v.checked_at) < hours * 36e5 && (!best || v.checked_at > best.checked_at)) best = v;
  return best;
}

// ---------- files ----------
export const CHECKS = join(DATA, "outages", "checks.json");
const PIPE = () => readJson(join(ROOT, "config", "pipeline.json"), {}) || {};
export const readCfg = () => cfgOf(PIPE().outage_desk);
function recentLeads(hours) {
  const dir = join(DATA, "leads"), out = [], since = dayAgo(Math.ceil(hours / 24) + 1);
  if (existsSync(dir)) for (const f of readdirSync(dir).filter((f) => f.endsWith(".jsonl") && f.slice(0, 10) >= since)) {
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) { if (!line.includes('"status"')) continue; try { out.push(JSON.parse(line)); } catch {} }
  }
  return out;
}
/** Everything the desk needs from disk: the three lists and the checks on file. */
export function load(now = Date.now()) {
  const cfg = readCfg(), events = listEventFiles().map((f) => f.e).filter(Boolean), cited = citedUrls(events);
  const inc = readJson(join(DATA, "grid", "incidents.json"), { open: [], closed: [] }) || { open: [], closed: [] };
  const lists = {
    power: powerItems(readJson(join(DATA, "grid", "news.json"), {}), inc, readJson(join(DATA, "grid", "research.json"), {}) || {}, cited, cfg, readJson(join(ROOT, "config", "grid.json"), {}) || {}),
    internet: internetItems(readJson(join(DATA, "context", "ioda.json"), {}), events, cfg, now),
    service: serviceItems(recentLeads(cfg.status_hours), events, cited, cfg, now),
  };
  return { cfg, lists, events, checks: readJson(CHECKS, {}) || {} };
}
function leadIdsOnFile() {
  const ids = new Set(), dir = join(DATA, "leads"), since = dayAgo(40);
  if (existsSync(dir)) for (const f of readdirSync(dir).filter((f) => f.endsWith(".jsonl") && f.slice(0, 10) >= since)) {
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) { if (!line.includes('"outage-desk"')) continue; try { const l = JSON.parse(line); if (l.via === "outage-desk" && l.outage_id) ids.add(l.outage_id); } catch {} }
  }
  return ids;
}
function releaseOutage(ids, run) {
  const p = join(DATA, "leases.json"), l = readLeases(), out = {}; let n = 0;
  for (const [k, v] of Object.entries(l)) { if (k.startsWith("outage:") && ids.includes(k.slice(7)) && (!run || (v && v.run === run))) { n++; continue; } out[k] = v; }
  if (n) writeJson(p, out);
}
const findPlan = (plan_id) => {
  if (!existsSync(DATA)) return null;
  for (const f of readdirSync(DATA).filter((f) => PLAN_FILE.test(f))) { const p = readJson(join(DATA, f), null); if (p && p.plan_id === plan_id) return p; }
  return null;
};

function main() {
  const [cmd, ...rest] = process.argv.slice(2), arg = (k, d) => { const i = rest.indexOf("--" + k); return i >= 0 ? rest[i + 1] : d; };
  const now = Date.now();
  if (cmd === "plan") {
    const { cfg, lists, checks } = load(now), dry = rest.includes("--dry-run");
    const N = Math.max(1, Math.min(4, Number(arg("max", 1)) || 1)), K = Math.max(1, Math.min(8, Number(arg("per", 4)) || 4));
    const file = PLAN_FILE.test(arg("file", "")) ? arg("file") : "outage-plan.json", run = RUN_ID();
    const q = queue(lists, checks, readLeases(), now, { ...cfg, run }), p = makePlan(q, checks, N, K, file.replace(/^outage-plan-?|\.json$/g, ""));
    const ids = p.batches.flatMap((b) => b.items.map((i) => i.id));
    if (dry) {
      console.log(`OUTAGE PLAN (dry run, nothing leased or written): ${ids.length} report(s) for ${p.batches.length} checker(s); ${q.length} waiting (${KINDS.map((k) => `${q.filter((x) => x.kind === k).length} ${k}`).join(", ")}).`);
      q.slice(0, 20).forEach((i) => console.log(`  ${i.id}  [${i.kind}] ${i.title}${i.figure ? ` · ${i.figure.n.toLocaleString("en-US")} ${i.figure.unit} (as reported)` : ""}${i.kind === "internet" ? ` · score ${i.score}` : ""}`));
      return;
    }
    if (ids.length) claim("outage", ids, run, 45);
    writeJson(join(DATA, file), { plan_id: p.plan_id, planned_at: nowIso(), run, batches: p.batches });
    console.log(`OUTAGE PLAN: ${ids.length} report(s) for ${p.batches.length} outage checker(s); ${q.length} waiting.`);
    return;
  }
  if (cmd === "apply") {
    const f = rest.find((x) => !x.startsWith("--") && x !== arg("plan")); if (!f) { console.error("usage: outage-desk.mjs apply <out file> [--plan F]"); process.exit(1); }
    const path = [isAbsolute(f) ? f : resolve(f), join(DATA, f)].find((p) => existsSync(p));
    const out = path ? readJson(path, null) : null;
    const pf = arg("plan"), plan = pf && PLAN_FILE.test(pf) ? readJson(join(DATA, pf), null) : out && out.plan_id ? findPlan(out.plan_id) : null;
    const events = new Map(listEventFiles().map((x) => x.e).filter((e) => e && e.id).map((e) => [e.id, e]));
    const v = validate(plan, out, events, now);
    if (v.errors.length) { console.error(`OUTAGE APPLY REFUSED (${f}): ${v.errors.slice(0, 6).join("; ")}`); process.exit(1); }
    const cfg = readCfg(), checks = readJson(CHECKS, {}) || {}, started = nowIso(), r = applyResults(checks, plan, v.good, leadIdsOnFile(), now, cfg);
    if (r.changed.length) writeJson(CHECKS, r.checks);
    if (r.leads.length) { mkdirSync(join(DATA, "leads"), { recursive: true }); appendFileSync(join(DATA, "leads", `${started.slice(0, 10)}.jsonl`), r.leads.map((l) => JSON.stringify(l)).join("\n") + "\n"); }
    releaseOutage([...v.good.map((x) => x.id), ...Object.keys(v.bad)], plan.run || process.env.CYBERVIEW_RUN || "");
    if (r.changed.length) {
      const st = readStatus(); st.last_outage_at = started; writeJson(join(DATA, "status.json"), st);
      const dir = join(DATA, "runs", started.slice(0, 10)); mkdirSync(dir, { recursive: true });
      writeJson(join(dir, `${started.slice(11, 13)}${started.slice(14, 16)}-outage-desk-${String(out.batch ?? "x").replace(/[^A-Za-z0-9]/g, "")}.json`), {
        job: "outage-desk", started_at: started, finished_at: nowIso(), model: "none (script)", plan_id: plan.plan_id, batch: out.batch ?? null,
        updated: r.changed, decisions: Object.fromEntries(r.changed.map((id) => [id, r.checks[id].decision])),
        pages_read: r.changed.flatMap((id) => r.checks[id].sources.map((url) => ({ url, title: "", used_in: id }))),
        added: [], skipped: Object.entries(v.bad).map(([id, why]) => ({ title: id, url: "", reason: "rejected by outage-desk validate: " + why.join("; ").slice(0, 300) })),
        open_leads: r.leads.map((l) => ({ title: l.title, url: l.url, note: "filed as a lead for the research loop", priority: l.tier === "gov" ? "high" : "normal" })), failed_sites: [],
        notes: `${r.changed.length} recorded, ${Object.keys(v.bad).length} rejected, ${r.leads.length} lead(s)` });
    }
    const badN = Object.keys(v.bad).length;
    console.log(`OUTAGE APPLY: ${r.changed.length} recorded, ${v.good.length - r.changed.length} already on file, ${badN} rejected, ${r.leads.length} cyber lead(s).`);
    for (const [id, why] of Object.entries(v.bad)) console.log(`  rejected ${id}: ${why.join("; ").slice(0, 300)}`);
    if (badN) process.exitCode = 1;
    return;
  }
  if (cmd === "list" || cmd === "status") {
    const { cfg, lists, checks } = load(now), q = queue(lists, checks, readLeases(), now, cfg), st = stats(q, checks, now);
    if (rest.includes("--json")) { console.log(JSON.stringify(cmd === "status" ? st : { ...st, waiting_items: q.map((i) => brief(i, checks[i.id])), checks })); return; }
    console.log(`OUTAGE DESK: ${st.waiting} waiting (${KINDS.map((k) => `${st.by_kind[k]} ${k}`).join(", ")}), ${st.checked_24h} checked in 24 h (${st.confirmed_24h} confirmed, ${st.cyber_leads_24h} cyber lead(s)).`);
    if (cmd === "status") return;
    q.slice(0, 30).forEach((i) => console.log(`  ${i.id}  [${i.kind}] ${i.title}`));
    const done = Object.entries(checks).sort((a, b) => String(b[1].checked_at).localeCompare(String(a[1].checked_at))).slice(0, 15);
    if (done.length) { console.log("Recently checked:"); done.forEach(([id, r]) => console.log(`  ${id}  ${r.decision}${r.publisher ? " (" + r.publisher + ")" : ""}: ${String(r.summary).slice(0, 110)}`)); }
    return;
  }
  console.error("usage: outage-desk.mjs plan [--max N] [--per K] [--file F] [--dry-run] | apply <out file> [--plan F] | list [--json] | status [--json]"); process.exit(1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
