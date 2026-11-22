// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Two read-only additions to findings, from CyberView's own published data. No network to targets here, ever: this module
// only reads files through the data source (scanner/lib/data.mjs) and never touches probe.mjs or udp.mjs.
//
// 1. Incident citations (opt-in with --data-incidents): for each finding's CVE, the CyberView events that name it, from the
//    archive the site publishes (data/archive/search.json for the CVE-to-events index, data/archive/<YYYY-MM>.json for the
//    events). EVERY event naming the CVE is indexed (not workbench.json's first-wins event_of). Only events that are
//    confirmed or official AND passed or corrected by the second review are cited; attackers' claims (status "claimed")
//    are never cited, only counted and labelled as unconfirmed; anything else (developing, unreviewed, flagged) is counted.
//    A citation is thin: title, date, status, the CyberView link, a count of the sources the event cites, and who attributed
//    it only when a government or the investigating firm did (who and where; no actor name). No indicators, hunt rules or
//    summary text are copied.
// 2. Hunt links (always, from workbench.json, already loaded): the publishers' detection files named for the CVE (and for a
//    cited event), as links only: name, format, publisher, https URL. No rule or indicator body is ever copied.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { DEFAULT_SOURCE } from "./data.mjs";

export const INCIDENTS_FLAG = "--data-incidents";
export const SEARCH_PATH = "data/archive/search.json";
export const monthPath = (m) => `data/archive/${m}.json`;
const MONTH = /^\d{4}-\d{2}$/;

const str = (v, n) => (typeof v === "string" ? v.slice(0, n) : "");
const isCve = (s) => /^CVE-\d{4}-\d{4,}$/.test(s || "");
const isDay = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s || "");
const isId = (s) => /^[a-z0-9][a-z0-9-]{2,119}$/.test(s || "");
const https = (u) => (/^https:\/\/[^\s"'<>]+$/.test(u || "") ? u : "");
export const eventLink = (id) => `${DEFAULT_SOURCE}archive.html#q=${encodeURIComponent(id)}`;

export const CITED_STATUS = new Set(["confirmed", "official"]);
export const CITED_REVIEW = new Set(["passed", "corrected"]);
const ATTR_BY = new Set(["government", "investigator"]);
// how many archive months an online scan reads at most (newest first), and citations kept per finding
export const MAX_MONTHS = 36, MAX_CITED = 10;

/**
 * The CVE-to-events index from the archive's compact search rows (search.json: { fields, rows }).
 * Multi-event: a CVE maps to EVERY event naming it (newest first), never only the first one found.
 * -> Map(cve -> [{ id, month, status }])
 */
export function eventIndex(search, want = null) {
  const out = new Map();
  const f = Array.isArray(search && search.fields) ? search.fields : [];
  const at = (k) => f.indexOf(k), iId = at("id"), iDate = at("date"), iStatus = at("status"), iCves = at("cves");
  if (iId < 0 || iDate < 0 || iCves < 0) return out;
  for (const r of (Array.isArray(search.rows) ? search.rows : [])) {
    if (!Array.isArray(r) || !isId(r[iId]) || !isDay(r[iDate])) continue;
    for (const c of (Array.isArray(r[iCves]) ? r[iCves] : []).slice(0, 12)) {
      if (!isCve(c) || (want && !want.has(c))) continue;
      if (!out.has(c)) out.set(c, []);
      const list = out.get(c);
      if (!list.some((x) => x.id === r[iId])) list.push({ id: r[iId], month: r[iDate].slice(0, 7), date: r[iDate], status: str(iStatus >= 0 ? r[iStatus] : "", 12) });
    }
  }
  for (const list of out.values()) list.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : a.id < b.id ? -1 : 1));
  return out;
}

/** Why an event is or is not cited: "cite", "claimed" or "unreviewed" (developing, not yet reviewed, or flagged). */
export function citeRule(e) {
  if (!e || typeof e !== "object") return "unreviewed";
  if (e.status === "claimed") return "claimed";
  const rv = e.review && typeof e.review === "object" ? e.review.state : "";
  return CITED_STATUS.has(e.status) && CITED_REVIEW.has(rv) ? "cite" : "unreviewed";
}

/** One event as a thin citation. Nothing but these fields leaves the archive record. */
export function citation(e) {
  if (!e || !isId(e.id) || citeRule(e) !== "cite") return null;
  const a = e.attribution && typeof e.attribution === "object" ? e.attribution : null;
  const attr = a && ATTR_BY.has(a.by_type) && https(str(a.url, 600)) && str(a.by, 120).trim()
    ? { by: str(a.by, 120).trim(), by_type: a.by_type, url: https(str(a.url, 600)) } : null;
  return { event_id: e.id, title: str(e.title, 160), date: isDay(e.date) ? e.date : "", status: e.status, review: e.review.state,
    sources: (Array.isArray(e.sources) ? e.sources : []).filter((s) => s && https(str(s.url, 600))).length,
    link: eventLink(e.id), ...(attr ? { attribution: attr } : {}) };
}

/**
 * Read the events naming the given CVEs through the data source (only allowlisted archive paths) and sort them by the rule.
 * -> { by: Map(cve -> { cited[], claimed_not_cited, unreviewed_not_cited }), months_read, months_skipped, available }
 */
export async function loadIncidents(src, cves) {
  const want = new Set([...cves].filter(isCve)), by = new Map();
  const res = { by, months_read: 0, months_skipped: 0, available: false };
  if (!want.size) return res;
  const search = await src.json(SEARCH_PATH, { optional: true }).catch(() => null);
  if (!search) return res;
  res.available = true;
  const idx = eventIndex(search, want);
  const months = [...new Set([...idx.values()].flat().map((x) => x.month).filter((m) => MONTH.test(m)))].sort().reverse();
  res.months_skipped = Math.max(0, months.length - MAX_MONTHS);
  const events = new Map();
  for (const m of months.slice(0, MAX_MONTHS)) {
    const j = await src.json(monthPath(m), { optional: true }).catch(() => null);
    if (!j) continue;
    res.months_read++;
    for (const e of (Array.isArray(j.events) ? j.events : [])) if (e && isId(e.id)) events.set(e.id, e);
  }
  for (const [cve, list] of idx) {
    const o = { cited: [], claimed_not_cited: 0, unreviewed_not_cited: 0 };
    for (const { id, status } of list) {
      const e = events.get(id);
      // an event whose month could not be read still respects the claims rule from its search row
      const rule = e ? citeRule(e) : status === "claimed" ? "claimed" : "unreviewed";
      if (rule === "claimed") o.claimed_not_cited++;
      else if (rule === "cite" && (e.cves || []).includes(cve)) { const c = citation(e); if (c && o.cited.length < MAX_CITED) o.cited.push(c); }
      else o.unreviewed_not_cited++;
    }
    by.set(cve, o);
  }
  return res;
}

/** Put the citations on each finding (finding.incidents); findings without any event naming the CVE get none. */
export function attachIncidents(findings, loaded) {
  for (const f of findings) {
    const o = loaded.by.get(f.cve);
    if (!o) continue;
    f.incidents = { cited: o.cited, claimed_not_cited: o.claimed_not_cited, unreviewed_not_cited: o.unreviewed_not_cited,
      rule: "Cited only: confirmed or official events that passed CyberView's second review. Attackers' claims are never cited.",
      by: "CyberView AI (a Claude model), second-reviewed" };
  }
  return findings;
}

export const HUNT_FORMATS = ["stix", "sigma", "yara", "snort", "suricata", "kql", "spl", "csv", "json", "misp", "openioc", "text", "pdf"];
/** A hunt entry as a link only (the same filter as the Vulnerabilities page's cleanHunt). */
export function huntLink(h) {
  if (!h || typeof h !== "object" || !HUNT_FORMATS.includes(h.format)) return null;
  const url = https(str(h.url, 600)); if (!url) return null;
  if (/csaf|cvrf|\bvex\b/i.test(url + " " + str(h.name, 100))) return null;   // machine-readable advisories, not detection content
  return { name: str(h.name, 100) || h.format, format: h.format, publisher: str(h.publisher, 80), url };
}

/**
 * Hunt links for each finding from workbench.json: entries for its CVE (the site's hunt list and the CVE's fix guide), and
 * entries published with an event the finding cites. Links only; deduplicated by URL; at most 12 per finding.
 */
export function attachHunt(findings, wb) {
  const list = Array.isArray(wb && wb.hunt) ? wb.hunt.slice(0, 400) : [];
  const guides = wb && wb.guides && typeof wb.guides === "object" ? wb.guides : {};
  for (const f of findings) {
    const events = new Set(((f.incidents && f.incidents.cited) || []).map((c) => c.event_id));
    const g = Object.prototype.hasOwnProperty.call(guides, f.cve) && guides[f.cve] && Array.isArray(guides[f.cve].hunt) ? guides[f.cve].hunt : [];
    const seen = new Set(), out = [];
    for (const h of [...g, ...list.filter((h) => h && (h.cve === f.cve || (isId(h.event_id) && events.has(h.event_id))))]) {
      const l = huntLink(h); if (!l || seen.has(l.url)) continue;
      seen.add(l.url); out.push(l); if (out.length >= 12) break;
    }
    if (out.length) f.hunt = out;
  }
  return findings;
}

/**
 * Snapshot the archive for offline incident citations (data --data-incidents): the index rows and month files that name a
 * CVE the workbench lists, reduced to the fields citations use, under the same published paths. Small by design.
 */
export async function snapshotIncidents(src, wb, save, { log = () => {} } = {}) {
  const cves = new Set([...((wb && wb.kev) || []), ...((wb && wb.vulns) || [])].map((x) => x && x.cve).filter(isCve));
  const search = await src.json(SEARCH_PATH, { optional: true });
  if (!search) return { incidents: false, incident_events: 0, incident_months: 0 };
  const idx = eventIndex(search, cves), ids = new Set([...idx.values()].flat().map((x) => x.id));
  const f = search.fields, iId = f.indexOf("id");
  save(SEARCH_PATH, { built_at: str(search.built_at, 30), fields: f, rows: search.rows.filter((r) => Array.isArray(r) && ids.has(r[iId])) }); log(SEARCH_PATH);
  const months = [...new Set([...idx.values()].flat().map((x) => x.month).filter((m) => MONTH.test(m)))].sort().reverse().slice(0, MAX_MONTHS);
  let n = 0;
  for (const m of months) {
    const j = await src.json(monthPath(m), { optional: true });
    if (!j) continue;
    const events = (Array.isArray(j.events) ? j.events : []).filter((e) => e && ids.has(e.id)).map((e) => ({
      id: e.id, title: str(e.title, 160), date: str(e.date, 10), status: str(e.status, 12), cves: (Array.isArray(e.cves) ? e.cves : []).filter(isCve).slice(0, 12),
      review: e.review && typeof e.review === "object" ? { state: str(e.review.state, 12) } : undefined,
      sources: (Array.isArray(e.sources) ? e.sources : []).map((s) => ({ url: https(str(s && s.url, 600)) })).filter((s) => s.url).slice(0, 20),
      attribution: e.attribution && ATTR_BY.has(e.attribution.by_type) ? { by: str(e.attribution.by, 120), by_type: e.attribution.by_type, url: https(str(e.attribution.url, 600)) } : undefined }));
    save(monthPath(m), { month: m, events }); log(monthPath(m)); n += events.length;
  }
  return { incidents: true, incident_events: n, incident_months: months.length };
}

/** The `data --data-incidents` step: after snapshot(), add the thin archive files to the folder and note them in its manifest. */
export async function snapshotIncidentsTo(src, out, { log = () => {} } = {}) {
  const save = (rel, j) => { const p = join(out, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(j)); };
  const wb = JSON.parse(readFileSync(join(out, "data", "workbench.json"), "utf8"));
  const r = await snapshotIncidents(src, wb, save, { log });
  const mp = join(out, "manifest.json"), m = JSON.parse(readFileSync(mp, "utf8"));
  writeFileSync(mp, JSON.stringify({ ...m, ...r }, null, 2));
  return r;
}

/** The text-summary lines for one finding (citations, the claims label, hunt links). */
export function citeLines(f) {
  const L = [], o = f.incidents;
  if (o) {
    if (o.cited.length) {
      L.push(`   Reported incidents naming this CVE (CyberView, second-reviewed): ${o.cited.length}`);
      for (const c of o.cited.slice(0, 3)) L.push(`     ${c.date} ${c.title.slice(0, 100)} (${c.status}, ${c.sources} source(s))${c.attribution ? `; attributed by ${c.attribution.by} (${c.attribution.by_type}) ${c.attribution.url}` : ""} ${c.link}`);
      if (o.cited.length > 3) L.push(`     ... ${o.cited.length - 3} more in report.json`);
    }
    if (o.claimed_not_cited) L.push(`   ${o.claimed_not_cited} attacker CLAIM(S) naming this CVE not cited (unconfirmed by the victim or an official source)`);
    if (o.unreviewed_not_cited) L.push(`   ${o.unreviewed_not_cited} other event(s) not cited (developing or not yet passed CyberView's second review)`);
  }
  if ((f.hunt || []).length) {
    L.push("   Hunt (publishers' detection files, links only; nothing copied):");
    for (const h of f.hunt.slice(0, 4)) L.push(`     ${h.name} (${h.format}${h.publisher ? `, ${h.publisher}` : ""}) ${h.url}`);
    if (f.hunt.length > 4) L.push(`     ... ${f.hunt.length - 4} more in report.json`);
  }
  return L;
}
