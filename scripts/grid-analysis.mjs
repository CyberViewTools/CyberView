// Grid analysis, no AI model. Run: node scripts/grid-analysis.mjs [run] | verify | show [--json]
// Contract: swarm/handoff/grid-analysis-contract.md. Runs after `grid.mjs collect` in every research cycle (and in
// collect.yml after its grid step). Reads data/grid/{incidents,live}.json, data/grid/series/, data/grid/history/,
// data/context/{ioda,gdacs}.json and the last two days of data/leads/; writes data/grid/analysis.json:
//   anomalies      operator regions unusual for this hour of the week (robust z on 4 weeks of 15-minute points)
//   corroboration  per open incident, independent signals in the same country or region within +-6 h, and a score
//   trends         per region over 30 days: incidents, customer-hours, the largest, causes mix, week-over-week
//   research       incidents the rule feed-back sends to the grid researchers with reason `corroborated`
// Everything here is context: an outage, an anomaly or a corroborating signal is never called an attack. News leads are
// counted and named by their title only.
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { DATA, ROOT, readJson, writeJson, nowIso } from "./lib/store.mjs";
import {
  SOURCES, REGIONS, COUNTRIES, OPERATORS, WEATHER, loadConfig, DEFAULT_CFG, str, readLines, checkSeriesLine, verifySeries,
  EIA_BA, basFor, dedupeHistory, expandSeries,
} from "./grid.mjs";
import { newsLeads } from "./grid-news.mjs";

const H = 3600e3, D = 864e5;
export const WINDOW_H = 6;
const BASE_DAYS = 28, TREND_DAYS = 30, MIN_SAME_HOUR = 8, Z_FLAG = 4;
export const SIGNAL_KINDS = ["operator", "internet", "disaster", "news", "demand"];
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
const ms = (s) => { const t = Date.parse(s || ""); return isFinite(t) ? t : NaN; };
const keyOf = (o) => `${o.source}|${o.region}`;
const median = (xs) => { const a = [...xs].sort((x, y) => x - y), n = a.length; return n ? (n % 2 ? a[(n - 1) / 2] : (a[n / 2 - 1] + a[n / 2]) / 2) : NaN; };
const how = (t) => { const d = new Date(t); return d.getUTCDay() * 24 + d.getUTCHours(); };   // hour of the week, UTC

// ---------- baseline and anomaly ----------
/** Median and MAD of unplanned customers for `region` ("<source>|<region>") at the hour of the week of `now`, over the
 *  4 weeks before `now`; with fewer than 8 such points, all hours of those 4 weeks. null when there are no points. */
export function baseline(series, region, now = Date.now()) {
  const from = now - BASE_DAYS * D, bySlot = new Map();
  for (const p of series || []) {
    const t = ms(p && p.at);
    if (!p || keyOf(p) !== region || !(t >= from && t < now) || p.unplanned == null) continue;
    bySlot.set(t, Number(p.unplanned) || 0);          // a slot written twice (two writers) counts once (ops-3)
  }
  const all = [...bySlot].map(([t, x]) => ({ t, x }));
  if (!all.length) return null;
  const same = all.filter((p) => how(p.t) === how(now)), use = same.length >= MIN_SAME_HOUR ? same : all;
  const xs = use.map((p) => p.x), m = median(xs);
  return { median: m, mad: median(xs.map((x) => Math.abs(x - m))), points: xs.length, basis: use === same ? "hour_of_week" : "all_hours" };
}
/** Robust z of x against a baseline; flagged when z >= 4 and x >= open_customers. A MAD of 0 is read as 1 customer. */
export function anomaly(x, base, cfg = DEFAULT_CFG) {
  if (!base || x == null) return { z: null, flagged: false };
  const z = (x - base.median) / Math.max(1.4826 * base.mad, 1);
  return { z: Math.round(z * 10) / 10, flagged: z >= Z_FLAG && x >= cfg.open_customers };
}
/** The latest point of every region (within the last hour) checked against its baseline. Customer sources: robust z;
 *  signal sources (Eskom, ERCOT, AEMO): any level above their normal of 0 is notable. Returns the flagged ones. */
export function anomalies(series, now = Date.now(), cfg = DEFAULT_CFG, incidents = []) {
  const latest = new Map();
  for (const p of series || []) {
    const t = ms(p && p.at);
    if (!(t <= now && t > now - H)) continue;
    const k = keyOf(p), was = latest.get(k);
    if (!was || ms(was.at) < t) latest.set(k, p);
  }
  const byRegion = new Map((incidents || []).filter((i) => i && !i.closed_at).map((i) => [keyOf(i), i]));
  const out = [];
  for (const [k, p] of latest) {
    const inc = byRegion.get(k), base = { id: inc ? inc.id : "", source: p.source, region: p.region,
      name: (REGIONS[k] || {}).name || p.region, at: p.at };
    if (p.customers == null && p.level != null) {
      if (p.level > 0) out.push({ ...base, kind: "level", value: p.level, median: 0, mad: 0, z: null, points: 0, basis: "normal_is_zero" });
      continue;
    }
    const b = baseline(series, k, ms(p.at)), a = anomaly(Number(p.unplanned) || 0, b, cfg);
    if (a.flagged) out.push({ ...base, kind: "customers", value: Number(p.unplanned) || 0, median: b.median, mad: b.mad, z: a.z, points: b.points, basis: b.basis });
  }
  return out.sort((a, b) => (b.z || 0) - (a.z || 0));
}

// ---------- corroboration ----------
const fold = (s) => String(s || "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// power words for leads that are not already classified as power outages (grid-news reports skip this check)
export const POWER_WORDS = /(^|[^\p{L}])(blackouts?|power outages?|power cuts?|without power|knocks? out power|knocked out power|power (is |was )?restored|apag[oó]n(es)?|apag[aã]o|corte de luz|falta de luz|pannes?|coupures? de courant|stromausfall|stroomstoring|awaria pr[aą]du|load[- ]shedding|grid|знеструмлен\p{L}*|отключени[ея] (электричества|света)|відключенн\p{L}* світла)(?![\p{L}])|停電|정전|ไฟดับ|mất điện|انقطاع الكهرباء/iu;
// countries too large for a country-wide signal (IODA, Cloudflare Radar) to say anything about one region's outage
export const LARGE_COUNTRIES = new Set(["US", "CA", "AU", "BR", "RU", "CN", "IN", "AR", "KZ", "MX", "ID", "DZ", "SA", "IR", "MN", "PE", "CL", "CO", "LY", "SD"]);
export const NATIONAL_CUSTOMERS = 250000;
export const NEAR_KM = 300;
/** Is an incident nationally significant, so a country-wide signal can speak to it? Small countries always; large ones
 *  when the incident covers the country (its region is the country) or reaches NATIONAL_CUSTOMERS. */
export function national(inc) {
  if (!LARGE_COUNTRIES.has(inc.country)) return true;
  const cname = COUNTRIES[inc.country] ? COUNTRIES[inc.country][0] : "", rname = (REGIONS[keyOf(inc)] || {}).name || inc.region;
  return rname === cname || inc.region === cname || (Number(inc.peak_customers) || 0) >= NATIONAL_CUSTOMERS;
}
/** Place names a headline may use for an incident: the region's parts, the operator, the country (the country only when a
 *  country-wide match can speak to the incident: see national()). */
export function placeNames(inc) {
  const r = (REGIONS[keyOf(inc)] || {}).name || inc.region || "", out = new Set();
  for (const part of r.replace(/[()]/g, ",").split(/,| and /)) { const p = part.trim(); if (p.length >= 4) out.add(p); }
  if (!/^[A-Z]{2,4}\d$/.test(inc.region || "") && String(inc.region || "").length >= 4) out.add(inc.region);
  if (SOURCES[inc.source]) out.add(SOURCES[inc.source].name);
  if (COUNTRIES[inc.country] && national(inc)) out.add(COUNTRIES[inc.country][0]);
  return [...out];
}
const nameRe = (names) => (names.length ? new RegExp(`(^|[^a-z0-9])(${names.map((n) => esc(fold(n))).join("|")})([^a-z0-9]|$)`) : /(?!)/);
const httpsPublisher = (u) => (/^https:\/\/[^\s"'<>]+$/.test(String(u || "")) && !/^https:\/\/(news\.google\.com|www\.bing\.com|bing\.com)\//.test(u) ? String(u).slice(0, 300) : "");
const dist = (a, b) => {           // km, haversine
  const r = Math.PI / 180, dl = (b.lat - a.lat) * r, dg = (b.lng - a.lng) * r;
  const h = Math.sin(dl / 2) ** 2 + Math.cos(a.lat * r) * Math.cos(b.lat * r) * Math.sin(dg / 2) ** 2;
  return 12742 * Math.asin(Math.sqrt(h));
};
const overlaps = (a0, a1, b0, b1) => a0 <= b1 && b0 <= a1;

/** Independent signals for one incident within +-6 h of its span, near it (logic-2, sources-1):
 *   internet (IODA, Cloudflare Radar): country-wide signals, so they count only for a nationally significant incident
 *     (national()) and say "nationwide"; a Radar annotation that names the incident's region counts anywhere
 *   demand (EIA): only the incident's own balancing authority (basFor) or one within NEAR_KM of it
 *   disaster (GDACS): same country by name, or within 500 km
 *   operator (ENTSO-E): same country (European bidding zones are national)
 *   news: grid-news reports (already classified as current outages) in the same country within NEAR_KM or naming the
 *     region; other leads need a power word and the region, operator or (when national) country in the headline
 *  ctx = { ioda: context file, gdacs: context file, leads: [lead], items: live items (keyed sources), now }.
 *  -> { id, signals: [{ kind, source, detail, url }], score: number of distinct kinds }. The incident is the operator kind. */
export function corroborate(inc, ctx = {}) {
  const now = ctx.now || Date.now(), w0 = ms(inc.opened_at) - WINDOW_H * H, w1 = (inc.closed_at ? ms(inc.closed_at) : now) + WINDOW_H * H;
  const country = inc.country, cname = COUNTRIES[country] ? fold(COUNTRIES[country][0]) : "", signals = [], nat = national(inc);
  const here = inc.lat != null && inc.lng != null ? inc : (REGIONS[keyOf(inc)] || null);
  const near = (o, km = NEAR_KM) => !!here && o && o.lat != null && o.lng != null && dist(here, o) <= km;
  const re = nameRe(placeNames(inc)), regionRe = nameRe(placeNames({ ...inc, country: "" }).filter((n) => n.length >= 4));
  signals.push({ kind: "operator", source: inc.source, detail: str(inc.name, 160), url: inc.url || "" });
  // IODA's summary covers the 24 hours before it was fetched; one item per country: a nationwide signal
  const io = ctx.ioda || {}, ioT = ms(io.fetched_at);
  if (nat && isFinite(ioT) && overlaps(ioT - 24 * H, ioT, w0, w1)) {
    for (const x of (io.items || []).filter((x) => x && x.code === country).slice(0, 1))
      signals.push({ kind: "internet", source: "ioda", detail: str(`IODA: nationwide internet disruption signal in ${x.name} (${(x.signals || []).join(", ")})`, 160), url: x.url || "" });
  }
  // GDACS orange and red alerts: same country by name, or within 500 km of the incident
  for (const g of ((ctx.gdacs || {}).items || [])) {
    if (!g) continue;
    const g0 = ms(g.from && !/Z$/.test(g.from) ? g.from + "Z" : g.from), g1 = g.to ? ms(!/Z$/.test(g.to) ? g.to + "Z" : g.to) : g0;
    if (!isFinite(g0) || !overlaps(g0, isFinite(g1) ? g1 : g0, w0, w1)) continue;
    const close = (nat && cname && fold(g.country).split(/,\s*/).includes(cname)) || near(g, 500);
    if (close) signals.push({ kind: "disaster", source: "gdacs", detail: str(`GDACS ${g.level} alert: ${g.type}, ${g.name}`, 160), url: g.url || "" });
  }
  // keyed sources (when connected)
  const bas = new Set(basFor(inc.source, inc.region));
  for (const it of ctx.items || []) {
    if (!it || it.country !== country) continue;
    const t0 = ms(it.started_at), t1 = it.restore_est ? ms(it.restore_est) : now;
    if (!isFinite(t0) || !overlaps(t0, isFinite(t1) ? t1 : now, w0, w1)) continue;
    if (it.source === "cfradar") {
      const regional = regionRe.test(fold(it.area || ""));
      if (regional || nat) signals.push({ kind: "internet", source: "cfradar", detail: str(`Cloudflare Radar${regional ? "" : ", nationwide signal"}: ${it.cause} (${it.area})`, 160), url: it.url || "" });
    } else if (it.source === "eia") {
      const ba = String(it.id || "").replace(/^eia:/, "").replace(/-\d{4}-\d{2}-\d{2}T\d{2}$/, "");
      const loc = EIA_BA[ba] ? { lat: EIA_BA[ba][0], lng: EIA_BA[ba][1] } : null;
      if (bas.has(ba) || near(loc)) signals.push({ kind: "demand", source: "eia", detail: str(`EIA: ${it.area} ${it.cause}`, 160), url: it.url || "" });
    } else if (it.source === "entsoe" && signals.filter((s) => s.source === "entsoe").length < 3)
      signals.push({ kind: "operator", source: "entsoe", detail: str(`ENTSO-E: ${it.area}, ${it.cause}`, 160), url: it.url || "" });
  }
  // news (counted, titles only, at most 5)
  const seen = new Set();
  for (const l of ctx.leads || []) {
    if (!l || !l.title || signals.filter((s) => s.kind === "news").length >= 5) continue;
    const t = ms(l.published) || ms(l.seen_at);
    if (!(t >= w0 && t <= w1)) continue;
    const title = fold(l.title);
    if (l.via === "grid-news") {
      // already classified as a current power outage by scripts/grid-news.mjs: same country, and near or naming the place
      if (l.country !== country || !(near(l) || re.test(title) || (nat && l.how === "country"))) continue;
    } else if (!POWER_WORDS.test(l.title) || !re.test(title)) continue;
    const k = title.replace(/\W+/g, " ").trim();
    if (seen.has(k)) continue;
    seen.add(k);
    signals.push({ kind: "news", source: str(l.source, 60) || "news", detail: str(l.title, 160), url: httpsPublisher(l.url) });
  }
  return { id: inc.id, signals, score: new Set(signals.map((s) => s.kind)).size };
}

// ---------- trends ----------
export const HOLD_MIN = 60, MIN_COVERAGE = 0.9;
/** Per region over the 30 days before `now`: incidents opened, customer-hours, the largest incident, the operators' causes
 *  mix, and this week against the week before. history: incidents (closed history lines and incidents.json open + closed;
 *  duplicates by id merged), series: points (expanded, see grid.mjs expandSeries).
 *  Customer-hours do not depend on how often collect ran (logic-5): each point's unplanned customers are held until the
 *  next point (the newest one until now), for at most HOLD_MIN minutes; a longer gap is no data. coverage is the
 *  share of the window with data. The week-over-week comparison (week) is given only when both weeks have at least
 *  MIN_COVERAGE of their time covered; otherwise week is null (a partial week is no comparison). */
export function trends(history, series, now = Date.now()) {
  const from = now - TREND_DAYS * D, wk = now - 7 * D, wk2 = now - 14 * D, regions = {};
  const r = (source, region) => {
    const k = `${source}|${region}`;
    return regions[k] || (regions[k] = { source, region, name: (REGIONS[k] || {}).name || region, incidents: 0, customer_hours: 0, coverage: 0,
      largest: null, causes: [], week: null, _c: new Map(), _w: { ch: 0, pch: 0, inc: 0, pinc: 0, cov: 0, pcov: 0 }, _cov: 0 });
  };
  const byId = new Map();
  for (const i of dedupeHistory((history || []).filter((i) => i && i.closed_at))) byId.set(i.id, i);
  for (const i of history || []) { if (i && i.id && !byId.has(i.id)) byId.set(i.id, i); }
  for (const i of byId.values()) {
    const t = ms(i.opened_at);
    if (!(t >= from && t <= now) || !OPERATORS.includes(i.source)) continue;
    const g = r(i.source, i.region);
    g.incidents++;
    if (t >= wk) g._w.inc++; else if (t >= wk2) g._w.pinc++;
    const size = (x) => (x.peak_customers != null ? x.peak_customers : (x.peak_level || x.level || 0) * 100000);
    if (!g.largest || size(i) > size(g.largest._i)) g.largest = { id: i.id, name: str(i.name, 120), peak_customers: i.peak_customers ?? null, peak_level: i.peak_level ?? i.level ?? null, opened_at: i.opened_at, _i: i };
    for (const c of i.causes || []) if (c && c.cause) g._c.set(c.cause, (g._c.get(c.cause) || 0) + (Number(c.customers) || 0));
  }
  // one point per region and slot (the last line wins), as steps
  const pts = new Map();
  for (const p of series || []) {
    const t = ms(p && p.at);
    if (!(t >= from - HOLD_MIN * 6e4 && t <= now) || !OPERATORS.includes(p.source) || Array.isArray(p.ok)) continue;
    const k = `${p.source}|${p.region}`;
    (pts.get(k) || pts.set(k, new Map()).get(k)).set(t, Number(p.unplanned) || 0);
  }
  const overlap = (a0, a1, b0, b1) => Math.max(0, Math.min(a1, b1) - Math.max(a0, b0));
  for (const [k, m] of pts) {
    const [source, ...rest] = k.split("|"), g = r(source, rest.join("|")), ts = [...m.keys()].sort((a, b) => a - b);
    ts.forEach((t, i) => {
      const end = t + Math.max(0, Math.min(i + 1 < ts.length ? ts[i + 1] - t : now - t, HOLD_MIN * 6e4)), u = m.get(t);
      const all = overlap(t, end, from, now), cur = overlap(t, end, wk, now), prev = overlap(t, end, wk2, wk);
      g.customer_hours += (u * all) / H; g._cov += all;
      g._w.ch += (u * cur) / H; g._w.cov += cur; g._w.pch += (u * prev) / H; g._w.pcov += prev;
    });
  }
  for (const g of Object.values(regions)) {
    g.customer_hours = Math.round(g.customer_hours);
    g.coverage = Math.round((g._cov / (now - from)) * 100) / 100;
    const cov = Math.round((g._w.cov / (7 * D)) * 100) / 100, pcov = Math.round((g._w.pcov / (7 * D)) * 100) / 100;
    if (cov >= MIN_COVERAGE && pcov >= MIN_COVERAGE) {
      const ch = Math.round(g._w.ch), pch = Math.round(g._w.pch);
      g.week = { customer_hours: ch, prev_customer_hours: pch, change_pct: pch ? Math.round(((ch - pch) / pch) * 100) : null,
        incidents: g._w.inc, prev_incidents: g._w.pinc, coverage: cov, prev_coverage: pcov };
    }
    g.causes = [...g._c].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([cause, customers]) => ({ cause: str(cause, 120), customers }));
    delete g._c; delete g._w; delete g._cov;
    if (g.largest) delete g.largest._i;
  }
  return { window_days: TREND_DAYS, from: iso(from), to: iso(now), regions };
}

// ---------- rule feed-back ----------
/** Incidents the grid researchers should check because of the analysis: an anomaly AND a score of 3 or more, or an
 *  internet-outage signal when none of the operator's causes is weather. Load shedding and mostly planned work are left
 *  out (their cause is already stated: a supply shortfall the operator announced, or planned work). */
export function feedback(incidents, anomalyList, corroboration) {
  const anom = new Set((anomalyList || []).map((a) => `${a.source}|${a.region}`)), out = [];
  const cor = new Map((corroboration || []).map((c) => [c.id, c]));
  for (const i of incidents || []) {
    const c = cor.get(i.id);
    if (!c || i.closed_at || i.kind === "load_shedding" || (i.planned_share || 0) > 0.5) continue;
    const weather = (i.causes || []).some((x) => WEATHER.test((x && x.cause) || ""));
    if (anom.has(keyOf(i)) && c.score >= 3) out.push({ id: i.id, why: `unusual for this hour, ${c.score} kinds of signal` });
    else if (!weather && c.signals.some((s) => s.kind === "internet")) out.push({ id: i.id, why: "internet outage in the same country, no weather cause reported" });
  }
  return out;
}
/** Set research_needed (reason `corroborated`) on the open incidents named; never clears a flag. Returns the ids changed. */
export function applyFeedback(incidentsDoc, research) {
  const ids = new Set((research || []).map((r) => r.id)), changed = [];
  for (const i of (incidentsDoc && incidentsDoc.open) || []) {
    if (ids.has(i.id) && !i.research_needed) { i.research_needed = true; i.research_reason = "corroborated"; changed.push(i.id); }
  }
  return changed;
}

/** All of it -> the analysis.json document. */
export function analyze({ incidents = { open: [], closed: [] }, history = [], series = [], live = {}, ioda = {}, gdacs = {}, leads = [], cfg = DEFAULT_CFG, now = Date.now() }) {
  const open = (incidents.open || []).filter((i) => i && !i.closed_at);
  const keyedItems = (live.items || []).filter((x) => x && SOURCES[x.source] && SOURCES[x.source].keyed);
  const anoms = anomalies(series, now, cfg, open);
  const corroboration = open.map((i) => corroborate(i, { ioda, gdacs, leads, items: keyedItems, now }));
  const sources = Object.fromEntries(Object.entries(live.sources || {}).map(([k, s]) => [k, { ok: !!(s && s.ok), error: str(s && s.error, 200) }]));
  for (const [k, f] of [["ioda", ioda], ["gdacs", gdacs]]) sources[k] = { ok: !!(f && f.ok), error: str(f && f.error, 200) };
  return { updated_at: iso(now), anomalies: anoms, corroboration, trends: trends([...history, ...open, ...(incidents.closed || [])], series, now),
    research: feedback(open, anoms, corroboration), sources };
}

// ---------- verify ----------
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const isStr = (x, n) => typeof x === "string" && x.length <= n;
const isNum = (x) => typeof x === "number" && isFinite(x);
const okUrl = (u) => u === "" || (isStr(u, 300) && /^https:\/\/[^\s"'<>]+$/.test(u));
export function checkAnalysis(d) {
  const e = [];
  if (!d || typeof d !== "object") return ["root: not an object"];
  if (!ISO.test(d.updated_at || "")) e.push("updated_at: not ISO");
  if (!Array.isArray(d.anomalies)) e.push("anomalies: not an array");
  else d.anomalies.forEach((a, i) => {
    const p = `anomalies[${i}]`;
    if (!a || !OPERATORS.includes(a.source) || !isStr(a.region, 60) || !isStr(a.name, 120) || !isStr(a.id, 120)) e.push(`${p}: source, region, name or id wrong`);
    else {
      if (!["customers", "level"].includes(a.kind)) e.push(`${p}.kind: not customers or level`);
      if (!ISO.test(a.at || "")) e.push(`${p}.at: not ISO`);
      if (!isNum(a.value) || !isNum(a.median) || !isNum(a.mad) || !(a.z === null || isNum(a.z))) e.push(`${p}: value, median, mad or z not numbers`);
    }
  });
  if (!Array.isArray(d.corroboration)) e.push("corroboration: not an array");
  else d.corroboration.forEach((c, i) => {
    const p = `corroboration[${i}]`;
    if (!c || !/^grid-/.test(c.id || "") || !Array.isArray(c.signals)) { e.push(`${p}: not { id, signals, score }`); return; }
    c.signals.forEach((s, j) => {
      if (!s || !SIGNAL_KINDS.includes(s.kind) || !isStr(s.source, 60) || !isStr(s.detail, 160) || !okUrl(s.url)) e.push(`${p}.signals[${j}]: not { kind, source, detail, url (https or "") }`);
    });
    if (c.score !== new Set(c.signals.map((s) => s && s.kind)).size) e.push(`${p}.score: not the number of kinds`);
  });
  const t = d.trends;
  if (!t || typeof t !== "object" || !t.regions || typeof t.regions !== "object") e.push("trends: not { regions }");
  else for (const [k, g] of Object.entries(t.regions)) {
    const p = `trends.regions.${k}`;
    if (!g || !OPERATORS.includes(g.source) || `${g.source}|${g.region}` !== k) { e.push(`${p}: key, source or region wrong`); continue; }
    if (![g.incidents, g.customer_hours].every((x) => Number.isInteger(x) && x >= 0)) e.push(`${p}: incidents or customer_hours not a count`);
    if (!Array.isArray(g.causes) || g.causes.length > 5 || g.causes.some((c) => !c || !isStr(c.cause, 120) || !isNum(c.customers))) e.push(`${p}.causes: not up to 5 { cause, customers }`);
    if (!(g.week === null || (g.week && (g.week.change_pct === null || isNum(g.week.change_pct))))) e.push(`${p}.week: not null or { customer_hours, change_pct, ... }`);
    if (g.coverage !== undefined && !(isNum(g.coverage) && g.coverage >= 0 && g.coverage <= 1)) e.push(`${p}.coverage: not 0..1`);
    if (!(g.largest === null || (g.largest && /^grid-/.test(g.largest.id || "")))) e.push(`${p}.largest: not null or an incident`);
  }
  if (!Array.isArray(d.research) || d.research.some((r) => !r || !/^grid-/.test(r.id || "") || !isStr(r.why, 200))) e.push("research: not [{ id, why }]");
  if (!d.sources || typeof d.sources !== "object") e.push("sources: missing");
  else for (const [k, s] of Object.entries(d.sources)) if (!s || typeof s.ok !== "boolean" || !isStr(s.error, 200)) e.push(`sources.${k}: not { ok, error }`);
  return e;
}
/** analysis.json and the series files -> [{ file, errors }]. */
export function verifyAnalysis(root = ROOT, strict = true) {
  const out = [], f = join(root, "data", "grid", "analysis.json");
  if (!existsSync(f)) { if (strict) out.push({ file: "data/grid/analysis.json", errors: ["file: missing"] }); }
  else {
    let d; try { d = JSON.parse(readFileSync(f, "utf8")); } catch { d = undefined; }
    const e = d === undefined ? ["file: not JSON"] : checkAnalysis(d);
    if (e.length) out.push({ file: "data/grid/analysis.json", errors: e });
  }
  return out.concat(verifySeries(root));
}

// ---------- CLI ----------
const P = { grid: join(DATA, "grid"), ctx: join(DATA, "context"), leads: join(DATA, "leads") };
/** Series points of the last `days` days (day files; bad lines skipped; one point per source|region|slot; the zeros of
 *  quiet regions in answered slots put back: grid.mjs expandSeries). */
export function readSeries(dir, days, now = Date.now()) {
  if (!existsSync(dir)) return [];
  const from = new Date(now - days * D).toISOString().slice(0, 10);
  return expandSeries(readdirSync(dir).filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f) && f.slice(0, 10) >= from).sort()
    .flatMap((f) => readLines(join(dir, f))).filter((p) => checkSeriesLine(p).length === 0));
}
function load(now) {
  const hd = join(P.grid, "history"), day = (n) => new Date(now - n * D).toISOString().slice(0, 10);
  const history = dedupeHistory(existsSync(hd) ? readdirSync(hd).filter((f) => /^\d{4}-\d{2}\.jsonl$/.test(f)).sort().slice(-2).flatMap((f) => readLines(join(hd, f))) : []);
  return {
    incidents: readJson(join(P.grid, "incidents.json"), null) || { open: [], closed: [] }, history,
    series: readSeries(join(P.grid, "series"), TREND_DAYS + 1, now), live: readJson(join(P.grid, "live.json"), {}) || {},
    ioda: readJson(join(P.ctx, "ioda.json"), {}) || {}, gdacs: readJson(join(P.ctx, "gdacs.json"), {}) || {},
    // news leads, plus the publishers' reports grid-news.mjs collected (data/grid/news.json): both count as "news" signals
    leads: [day(0), day(1)].flatMap((d) => readLines(join(P.leads, `${d}.jsonl`))).concat(newsLeads(readJson(join(P.grid, "news.json"), {}))), cfg: loadConfig(), now,
  };
}
function run() {
  const now = Date.now(), input = load(now), a = analyze(input);
  writeJson(join(P.grid, "analysis.json"), a);
  // the feed-back reaches this cycle's grid desk at once; grid.mjs triage keeps it on later collections
  const changed = existsSync(join(P.grid, "incidents.json")) ? applyFeedback(input.incidents, a.research) : [];
  if (changed.length) writeJson(join(P.grid, "incidents.json"), input.incidents);
  console.log(`grid-analysis: ${a.anomalies.length} anomal${a.anomalies.length === 1 ? "y" : "ies"}, ${a.corroboration.length} open incident(s) checked`
    + ` (best score ${Math.max(0, ...a.corroboration.map((c) => c.score))}), ${Object.keys(a.trends.regions).length} region trend(s),`
    + ` ${a.research.length} for research${changed.length ? ` (${changed.length} newly flagged)` : ""}; ${input.series.length} series points`);
  return 0;
}
function show(asJson) {
  const a = readJson(join(P.grid, "analysis.json"), null);
  if (!a) { console.log("grid-analysis: no analysis yet (run node scripts/grid-analysis.mjs)"); return 0; }
  if (asJson) { console.log(JSON.stringify(a, null, 2)); return 0; }
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  console.log(`Grid analysis, ${a.updated_at} (context, not cyber events)`);
  console.log(`Sources: ${Object.entries(a.sources).map(([k, s]) => `${k} ${s.ok ? "ok" : /^not connected/.test(s.error) ? "not connected" : "failing"}`).join(", ")}`);
  console.log(`Anomalies (${a.anomalies.length}):`);
  for (const x of a.anomalies.slice(0, 10)) console.log(`  ${x.name}: ${x.kind === "level" ? `level ${x.value}` : `${fmt(x.value)} customers, usual ${fmt(x.median)} (z ${x.z}, ${x.basis})`}`);
  console.log(`Open incidents corroborated (${a.corroboration.length}):`);
  for (const c of a.corroboration.slice(0, 10)) {
    const kinds = {}; for (const s of c.signals) kinds[s.kind] = (kinds[s.kind] || 0) + 1;
    console.log(`  ${c.id}: score ${c.score} (${Object.entries(kinds).map(([k, n]) => `${k}${n > 1 ? ` (${n})` : ""}`).join(", ")})`);
  }
  console.log(`Trends, ${a.trends.window_days} days:`);
  for (const g of Object.values(a.trends.regions).sort((x, y) => y.customer_hours - x.customer_hours))
    console.log(`  ${g.name}: ${fmt(g.customer_hours)} customer-hours, ${g.incidents} incident(s)${g.week.change_pct != null ? `, week over week ${g.week.change_pct > 0 ? "+" : ""}${g.week.change_pct}%` : ""}`);
  console.log(`For research: ${a.research.length ? a.research.map((r) => `${r.id} (${r.why})`).join("; ") : "none"}`);
  return 0;
}
async function main() {
  const [cmd = "run", ...rest] = process.argv.slice(2);
  if (cmd === "run") process.exit(run());
  if (cmd === "verify") {
    const bad = verifyAnalysis(ROOT, !rest.includes("--lenient"));
    for (const b of bad) for (const e of b.errors.slice(0, 20)) console.error(`${b.file}: ${e}`);
    if (!bad.length) console.log("grid-analysis verify: analysis.json and the series files have the expected shape");
    process.exit(bad.length ? 1 : 0);
  }
  if (cmd === "show") process.exit(show(rest.includes("--json")));
  console.error("usage: node scripts/grid-analysis.mjs [run] | verify [--lenient] | show [--json]");
  process.exit(2);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
