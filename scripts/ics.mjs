// Industrial control system (ICS) and operational technology (OT) advisories as structured data. No AI model.
// Run: node scripts/ics.mjs [collect] [--no-leads] [--dry]  |  node scripts/ics.mjs status
// (behind a proxy: NODE_USE_ENV_PROXY=1)
//
// Reads the machine-readable advisories that CISA and the big industrial vendors publish themselves:
//   cisa        CISA ICS and ICS medical advisories (ICSA, ICSMA) as CSAF 2.0 JSON from CISA's own GitHub repository
//               (cisagov/CSAF, changes.csv); CISA's two RSS feeds are the fallback when the repository cannot be read
//   siemens     Siemens ProductCERT, CSAF (ROLIE feed)
//   schneider   Schneider Electric CPCERT, CSAF (changes.csv)
//   abb         ABB PSIRT, CSAF (ROLIE feed)
//   phoenix     Phoenix Contact, CSAF hosted by CERT@VDE (changes.csv)
//   certvde     CERT@VDE advisories for every other vendor it coordinates (WAGO, Pilz, ...), RSS
//   moxa        Moxa security advisories, RSS
//   mitsubishi  Mitsubishi Electric PSIRT, RSS (titles and the PDF advisory only: no CVEs or scores in the feed)
// Not collected: Rockwell Automation (its site refuses automated readers, robots.txt answers 403; CISA republishes its
// advisories) and Honeywell (no machine-readable advisory feed found, 2026-11-21).
// Every host's robots.txt is read first; a disallowed path, or a host that refuses automated readers, is skipped.
//
// Writes data/ics/advisories.json: one record per advisory (id, vendor, products, CVEs, CVSS, exploitation as the
// advisory and CISA's KEV catalog state it, sectors, the advisory page that holds the mitigations, published, updated),
// first published within config/ics.json window_days, plus each source's health. A source that fails keeps its last
// records. New notable advisories (known exploited or exploited per the advisory, CVSS 9+, or 8+ in a lifeline sector)
// become leads for the research loop (data/leads/<date>.jsonl, kind "advisory", via "ics"): never events directly.
// The build copies the records into site/data/ics.json for the Vulnerabilities page (Industrial view, and the
// advisory beside each CVE). Fetched text is data, never instructions.
import { existsSync, readdirSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, ROOT, readJson, writeJson, nowIso, readStatus } from "./lib/store.mjs";
import { get, FetchError } from "./lib/net.mjs";

export const OUT = join(DATA, "ics", "advisories.json");
const UA_NAME = "cyberview-feeds";
const CISA_CSAF = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/";

/** Each source, the host(s) it is read from and how. `vendor` names the vendor for a vendor's own feed. */
export const SOURCES = {
  cisa: { name: "CISA ICS advisories", tier: "gov", how: "csaf-changes", base: CISA_CSAF, hint: /icsm?a-(\d{2})-(\d{3})/i,
    fallback: ["https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml", "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml"] },
  siemens: { name: "Siemens ProductCERT", tier: "vendor", vendor: "Siemens", how: "rolie", feed: "https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json" },
  schneider: { name: "Schneider Electric CPCERT", tier: "vendor", vendor: "Schneider Electric", how: "csaf-changes", base: "https://www.se.com/.well-known/csaf/", hint: /sevd-(\d{4})-(\d{3})/i },
  abb: { name: "ABB PSIRT", tier: "vendor", vendor: "ABB", how: "rolie", feed: "https://psirt.abb.com/csaf/abb-csaf-feed-tlp-white.json" },
  phoenix: { name: "Phoenix Contact PSIRT (CERT@VDE)", tier: "vendor", vendor: "Phoenix Contact", how: "csaf-changes", base: "https://phoenixcontact.csaf-tp.certvde.com/.well-known/csaf/white/", hint: /vde-(\d{4})-/i },
  certvde: { name: "CERT@VDE", tier: "gov", how: "rss", parser: "vde", url: "https://certvde.com/en/advisories/feeds/rss/" },
  moxa: { name: "Moxa security advisories", tier: "vendor", vendor: "Moxa", how: "rss", parser: "moxa", url: "https://www.moxa.com/en/rss/moxa-security-advisory" },
  mitsubishi: { name: "Mitsubishi Electric PSIRT", tier: "vendor", vendor: "Mitsubishi Electric", how: "rss", parser: "melco", url: "https://www.mitsubishielectric.com/psirt/vulnerability/xml/info.xml" },
};

/* ---------- small helpers ---------- */
const decode = (s) => String(s == null ? "" : s).replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
  .replace(/&#0?39;|&apos;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(+n)).replace(/&nbsp;/g, " ").replace(/&amp;/g, "&");
export const txt = (s, n) => String(s == null ? "" : s).replace(/<[^>]*>/g, " ").replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
/** Text cut at a word, with an ellipsis when it was cut. */
export const clip = (s, n) => { const t = txt(s, 4000); return t.length <= n ? t : t.slice(0, n - 1).replace(/\s+\S*$/, "") + "…"; };
const https = (u) => (/^https:\/\/[^\s"'<>]{1,600}$/.test(String(u || "")) ? String(u) : "");
const iso = (d) => { const t = Date.parse(d || ""); return isNaN(t) ? "" : new Date(t).toISOString().replace(/\.\d+Z$/, "Z"); };
const CVE_RE = /CVE-\d{4}-\d{4,}/g;
const uniq = (a) => [...new Set(a.filter(Boolean))];
const cvesIn = (s) => uniq(String(s || "").match(CVE_RE) || []);
const tag = (block, names) => { for (const t of names) { const m = block.match(new RegExp(`<${t}\\b[^>]*>([\\s\\S]*?)</${t}>`, "i")); if (m) return m[1]; } return ""; };
const items = (xml) => [...String(xml || "").matchAll(/<item\b[\s\S]*?<\/item>/gi)].map((m) => m[0]);
const sevOf = (s) => (s == null ? "" : s >= 9 ? "C" : s >= 7 ? "H" : s >= 4 ? "M" : s > 0 ? "L" : "N");
// raise when parseCsaf keeps more or reads differently: every CSAF document is read again on the next run
export const PARSE_VERSION = 2;
const RANK = { kev: 4, active: 3, poc: 2, none: 1, "": 0 };
const stronger = (a, b) => (RANK[b] > RANK[a] ? b : a);

/* ---------- robots.txt ---------- */
/** Pure: may a reader named `ua` fetch `path`, by this robots.txt? The group naming the reader wins over "*"; the
 *  longest matching rule decides, Allow on a tie; "*" and a final "$" work as in Google's and RFC 9309's reading. */
export function robotsAllows(txtBody, path, ua = UA_NAME) {
  const groups = []; let cur = null, lastWasAgent = false;
  for (const raw of String(txtBody || "").split(/\r?\n/)) {
    const line = raw.replace(/#.*/, "").trim(); const m = line.match(/^([A-Za-z-]+)\s*:\s*(.*)$/); if (!m) continue;
    const k = m[1].toLowerCase(), v = m[2].trim();
    if (k === "user-agent") { if (!lastWasAgent || !cur) { cur = { agents: [], rules: [] }; groups.push(cur); } cur.agents.push(v.toLowerCase()); lastWasAgent = true; continue; }
    lastWasAgent = false;
    if (cur && (k === "allow" || k === "disallow")) cur.rules.push({ allow: k === "allow", pat: v });
  }
  const mine = groups.filter((g) => g.agents.some((a) => a !== "*" && ua.toLowerCase().includes(a)));
  const use = mine.length ? mine : groups.filter((g) => g.agents.includes("*"));
  let best = null;
  for (const r of use.flatMap((g) => g.rules)) {
    if (!r.pat) continue;                                            // "Disallow:" with nothing allows everything
    const anchored = r.pat.endsWith("$"), body = anchored ? r.pat.slice(0, -1) : r.pat;
    const re = new RegExp("^" + body.split("*").map((x) => x.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + (anchored ? "$" : ""));
    if (!re.test(path)) continue;
    if (!best || r.pat.length > best.pat.length || (r.pat.length === best.pat.length && r.allow)) best = r;
  }
  return !best || best.allow;
}
const robotsCache = new Map();
/** "" when the URL may be read, else why not. A missing robots.txt (404) allows everything; 401/403 means the site refuses
 *  automated readers, so nothing on it is read. */
async function robotsWhy(url) {
  const u = new URL(url);
  if (!robotsCache.has(u.host)) {
    let v;
    try { v = { body: await get(`${u.protocol}//${u.host}/robots.txt`, { as: "text", retries: 1, timeoutMs: 15000, key: "robots-" + u.host }) }; }
    catch (e) { v = /^http_(401|403)$/.test(e.code) ? { refused: true } : /^http_4\d\d$/.test(e.code) ? { body: "" } : { error: e.code || "network" }; }
    robotsCache.set(u.host, v);
  }
  const r = robotsCache.get(u.host);
  if (r.refused) return `${u.host} refuses automated readers (robots.txt answers 401/403)`;
  if (r.error) return `${u.host}/robots.txt could not be read (${r.error})`;
  return robotsAllows(r.body, u.pathname + u.search) ? "" : `robots.txt disallows ${u.pathname}`;
}
async function fetchOk(url, as = "json") {
  const why = await robotsWhy(url); if (why) throw new FetchError("robots", why);
  return get(url, { as, timeoutMs: 60000, retries: 2 });
}

/* ---------- indexes ---------- */
/** CSAF changes.csv: "2026/icsa-26-323-03.json","2026-11-19T06:00:00.000000Z" -> [{ path, at }] newest first. */
export function parseChangesCsv(body) {
  const out = [];
  for (const line of String(body || "").split(/\r?\n/)) {
    const m = line.match(/^"?([\w./-]+\.json)"?\s*,\s*"?([0-9T:.\-+Z]+)"?\s*$/); if (!m || m[1].includes("..")) continue;
    const at = iso(m[2]); if (at) out.push({ path: m[1], at });
  }
  return out.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0));
}
/** A ROLIE feed (CSAF provider) -> [{ id, url, at, published }] newest first. */
export function parseRolie(j) {
  const entries = (j && j.feed && Array.isArray(j.feed.entry)) ? j.feed.entry : [];
  return entries.map((e) => {
    const self = (Array.isArray(e.link) ? e.link : []).find((l) => l && l.rel === "self");
    const url = https((e.content && e.content.src) || (self && self.href));
    return url && /\.json$/i.test(url) ? { id: txt(e.id, 40), url, at: iso(e.updated || e.published), published: iso(e.published) } : null;
  }).filter((x) => x && x.at).sort((a, b) => (a.at < b.at ? 1 : -1));
}
/** The publication day an advisory id encodes, when it does: icsa-26-323-03 (two-digit year, day of year),
 *  sevd-2026-314-01, vde-2026-150 (year only). "" when unknown. */
export function idDay(path, hint) {
  const m = hint ? String(path).match(hint) : null; if (!m) return "";
  const y = m[1].length === 2 ? 2000 + Number(m[1]) : Number(m[1]);
  const d = m[2] ? Number(m[2]) : 1;
  if (!(y >= 1999 && y <= 2100) || !(d >= 1 && d <= 366)) return "";
  return new Date(Date.UTC(y, 0, d)).toISOString().slice(0, 10);
}

/* ---------- CSAF 2.0 ---------- */
const EXPL_TEXT = [
  [/\b(known to (be|have been) exploited|actively exploited|exploited in the wild|active exploitation|is aware of (public |active )?exploitation|has been exploited|have been exploited)\b/i, "active"],
  [/\b(public(ly)? (available )?exploits?( code)? (is|are|has been|have been) (publicly )?(available|released|published)|exploit code is (publicly )?available|proof[- ]of[- ]concept (exploit )?(code )?(is|has been) (publicly )?(available|released|published))\b/i, "poc"],
  [/\bno known (public )?exploitation\b|\bnot (aware of|known to be) (any )?(public )?exploit/i, "none"],
];
/** What a sentence says about exploitation: "active", "poc", "none" or "". Negations are read first. */
export function exploitFromText(s) {
  const t = String(s || "");
  if (EXPL_TEXT[2][0].test(t)) return "none";
  for (const [re, v] of EXPL_TEXT.slice(0, 2)) if (re.test(t)) return v;
  return "";
}
/** CISA's SSVC note ("SSVCv2/E:A/A:N/T:P/...") -> "active" | "poc" | "none" | "". */
export function ssvcExploit(s) { const m = String(s || "").match(/SSVCv\d\/E:([APN])\b/); return m ? { A: "active", P: "poc", N: "none" }[m[1]] : ""; }
const SCORE_NOTE = /CVSS\s*v?(4\.0|3\.[01])\s*(?:Base\s*)?Score[:\s]*([0-9]{1,2}(?:\.[0-9])?)/i;

/** Pure: one CSAF 2.0 document -> an advisory record, or null when it is not one. kev: Set of CVE ids on CISA's KEV catalog. */
export function parseCsaf(doc, { source = "", vendor = "", docUrl = "", srcAt = "", kev = new Set() } = {}) {
  const d = doc && doc.document; if (!d || !d.tracking || typeof d.tracking.id !== "string") return null;
  if (d.category && !/security_advisory|csaf_base|vex/i.test(d.category)) return null;
  const id = txt(d.tracking.id, 40).toUpperCase(); if (!/^[A-Z0-9][A-Z0-9._:-]{2,39}$/.test(id)) return null;
  // products: the product-name branch above each leaf, and the vendor branch above that
  const names = new Map();
  const walk = (b, vend, prod) => {
    if (!b || typeof b !== "object") return;
    const v = b.category === "vendor" ? b.name : vend, p = b.category === "product_name" || (b.category === "product_family" && !prod) ? b.name : prod;
    if (b.product && b.product.product_id) names.set(b.product.product_id, { vendor: txt(v, 60), product: txt(p || b.product.name, 100) });
    (Array.isArray(b.branches) ? b.branches : []).forEach((c) => walk(c, v, p));
  };
  const tree = doc.product_tree || {};
  (Array.isArray(tree.branches) ? tree.branches : []).forEach((b) => walk(b, "", ""));
  (Array.isArray(tree.full_product_names) ? tree.full_product_names : []).forEach((p) => { if (p && p.product_id && !names.has(p.product_id)) names.set(p.product_id, { vendor: "", product: txt(p.name, 100) }); });
  const vulns = Array.isArray(doc.vulnerabilities) ? doc.vulnerabilities : [];
  const affected = new Set(), notAffected = new Set(), cves = [], cvss = {}, cwes = [], remediation = new Set();
  let best = null, expl = "", note = "";
  for (const v of vulns) {
    const ps = v.product_status || {};
    for (const k of ["known_affected", "first_affected", "last_affected", "under_investigation"]) (Array.isArray(ps[k]) ? ps[k] : []).forEach((x) => affected.add(x));
    (Array.isArray(ps.known_not_affected) ? ps.known_not_affected : []).forEach((x) => notAffected.add(x));
    const cve = /^CVE-\d{4}-\d{4,}$/.test(v.cve || "") ? v.cve : ""; if (cve) cves.push(cve);
    if (v.cwe && /^CWE-\d{1,5}$/.test(v.cwe.id || "")) cwes.push(v.cwe.id);
    (Array.isArray(v.remediations) ? v.remediations : []).forEach((r) => { if (/^(vendor_fix|mitigation|workaround|none_available|no_fix_planned)$/.test(r && r.category)) remediation.add(r.category); });
    let top = null;
    for (const s of Array.isArray(v.scores) ? v.scores : []) for (const k of ["cvss_v4", "cvss_v3"]) {
      const c = s && s[k], n = c && Number(c.baseScore);
      if (isFinite(n) && n >= 0 && n <= 10 && (!top || n > top.score)) top = { score: n, vector: txt(c.vectorString, 160), version: txt(c.version, 5) };
    }
    for (const n of Array.isArray(v.notes) ? v.notes : []) {
      const t = `${n && n.title || ""} ${n && n.text || ""}`;
      const m = t.match(SCORE_NOTE); if (m && !top) { const sc = Number(m[2]); if (sc >= 0 && sc <= 10) top = { score: sc, vector: txt((t.match(/CVSS:[34]\.[01]\/[A-Z:/]+/) || [""])[0], 160), version: m[1] }; }
      const ss = ssvcExploit(n && n.text); if (ss) expl = stronger(expl, ss);
    }
    for (const th of Array.isArray(v.threats) ? v.threats : []) if (th && th.category === "exploit_status") { const e = exploitFromText(th.details); if (e) { expl = stronger(expl, e); if (!note) note = txt(th.details, 200); } }
    if (top) { if (cve) cvss[cve] = top.score; if (!best || top.score > best.score) best = top; }
  }
  for (const n of Array.isArray(d.notes) ? d.notes : []) {
    const e = exploitFromText(n && n.text); if (e) { expl = stronger(expl, e); if (!note || e !== "none") note = txt(n.text, 200); }
  }
  const kevHits = cves.filter((c) => kev.has(c));
  if (kevHits.length) expl = "kev";
  // a notice that the vendor's products are NOT affected (Siemens on PHP2Shell): the flaw may be exploited elsewhere, but
  // this advisory names nothing to patch, so it is never a lead and the page says so
  const notAff = affected.size === 0 && notAffected.size > 0;
  const noteBy = (re) => { const n = (Array.isArray(d.notes) ? d.notes : []).find((x) => x && re.test(x.title || "")); return n ? txt(n.text, 300) : ""; };
  const sectors = noteBy(/critical infrastructure sectors?/i).split(/\s*,\s*/).map((s) => txt(s, 60)).filter(Boolean).slice(0, 16);
  const prodList = uniq([...affected].map((x) => names.get(x)).filter(Boolean).map((x) => x.product));
  const vendCount = {}; [...affected].map((x) => names.get(x)).filter(Boolean).forEach((x) => { if (x.vendor) vendCount[x.vendor] = (vendCount[x.vendor] || 0) + 1; });
  const topVendor = Object.entries(vendCount).sort((a, b) => b[1] - a[1])[0];
  const refs = (Array.isArray(d.references) ? d.references : []).filter((r) => r && https(r.url));
  const self = refs.filter((r) => r.category === "self"), page = (r) => !/\.json(\?|$)|raw\.githubusercontent\.com|p_File_Name=[^&]*\.json/i.test(r.url);
  const web = self.find((r) => page(r) && !/\.pdf(\?|$)|\.pdf&|Action=Launch|p_File_Name=[^&]*\.pdf/i.test(r.url)) || self.find(page) || refs.find(page);
  const summary = (Array.isArray(d.notes) ? d.notes : []).find((n) => n && n.category === "summary" && n.text);
  const pub = d.publisher || {};
  return {
    id, source, vendor: txt(vendor || (topVendor && topVendor[0]) || (pub.category === "vendor" ? pub.name : ""), 60),
    title: txt(String(d.title || "").replace(new RegExp("^" + id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\s*[:\\-–]\\s*", "i"), ""), 200),
    products: prodList.slice(0, 12), products_total: prodList.length, cves: uniq(cves).slice(0, 200), cve_cvss: cvss,
    cvss: best ? best.score : null, cvss_version: best ? best.version : "", cvss_vector: best ? best.vector : "", severity: sevOf(best ? best.score : null),
    cwes: uniq(cwes).slice(0, 12), exploited: expl, exploit_note: note, kev_cves: kevHits,
    sectors, countries: txt(noteBy(/countries/i), 120), hq: txt(noteBy(/headquarters/i), 60),
    remediation: [...remediation].sort(), fix: remediation.has("vendor_fix"), not_affected: notAff,
    url: web ? web.url : "", doc: https(docUrl), summary: txt(summary ? summary.text : (vulns[0] && vulns[0].title) || "", 300),
    published: iso(d.tracking.initial_release_date), updated: iso(d.tracking.current_release_date || d.tracking.initial_release_date), src_at: srcAt || "", v: PARSE_VERSION,
  };
}

/* ---------- RSS ---------- */
const rec = (o) => ({ products: [], products_total: 0, cves: [], cve_cvss: {}, cvss: null, cvss_version: "", cvss_vector: "", severity: "", cwes: [], exploited: "", exploit_note: "",
  kev_cves: [], sectors: [], countries: "", hq: "", remediation: [], fix: false, not_affected: false, doc: "", summary: "", updated: "", src_at: "", ...o });
const withKev = (r, kev) => { const k = r.cves.filter((c) => kev.has(c)); if (k.length) { r.kev_cves = k; r.exploited = "kev"; } r.severity = sevOf(r.cvss); return r; };
const maxScore = (s, re) => { let m = null; for (const x of String(s).matchAll(re)) { const n = Number(x[x.length - 1]); if (n >= 0 && n <= 10 && (m === null || n > m)) m = n; } return m; };

/** CISA's ICS (and ICS medical) RSS: the fallback when CISA's CSAF repository cannot be read. */
export function parseCisaRss(xml, kev = new Set()) {
  return items(xml).map((b) => {
    const url = https(decode(tag(b, ["link"])).trim()), desc = decode(tag(b, ["description"])), id = (url.match(/\/(icsm?a-\d{2}-\d{3}-\d{2})\b/i) || [])[1];
    if (!url || !id) return null;
    const vend = desc.match(/<td>\s*v[34](?:\.\d)?\s+[\d.]+\s*<\/td>\s*<td>([^<]{1,80})<\/td>\s*<td>([^<]{1,160})<\/td>/i);
    const sectors = (desc.match(/Critical Infrastructure Sectors:\s*<\/strong>\s*([^<]{1,400})/i) || [])[1] || "";
    const e = exploitFromText(txt(desc, 20000));
    return withKev(rec({ id: id.toUpperCase(), source: "cisa", vendor: txt(vend ? vend[1] : "", 60), title: txt(decode(tag(b, ["title"])), 200), products: vend ? [txt(vend[2], 100)] : [], products_total: vend ? 1 : 0,
      cves: cvesIn(desc).slice(0, 200), cvss: maxScore(desc, /<td>\s*v([34])(?:\.\d)?\s+([\d.]+)\s*<\/td>/gi), sectors: sectors.split(/\s*,\s*/).map((s) => txt(s, 60)).filter(Boolean).slice(0, 16),
      exploited: e, exploit_note: e ? txt(txt(desc, 20000).split(/(?<=\.)\s+/).find((s) => exploitFromText(s) === e) || "", 200) : "", url, summary: txt((desc.match(/<h2>Summary<\/h2>([\s\S]*?)<\/p>/i) || [])[1] || "", 300),
      published: iso(decode(tag(b, ["pubDate"])).trim()) }), kev);
  }).filter(Boolean);
}
/** CERT@VDE's RSS: "Vendor: title", "[VDE-2026-132] description". */
export function parseVdeRss(xml, kev = new Set()) {
  return items(xml).map((b) => {
    const url = https(decode(tag(b, ["link"])).trim()), title = txt(decode(tag(b, ["title"])), 240), desc = txt(decode(tag(b, ["description"])), 4000);
    const id = (url.match(/\/(VDE-\d{4}-\d{3,})\b/i) || desc.match(/\[(VDE-\d{4}-\d{3,})\]/i) || [])[1]; if (!url || !id) return null;
    const m = title.match(/^([^:]{2,60}):\s*(.+)$/);
    return withKev(rec({ id: id.toUpperCase(), source: "certvde", vendor: m ? m[1].trim() : "", title: txt(m ? m[2] : title, 200), cves: cvesIn(desc + " " + title),
      exploited: exploitFromText(desc), url, summary: txt(desc.replace(/^\[VDE-[\d-]+\]\s*/i, ""), 300), published: iso(decode(tag(b, ["pubDate"])).trim()) }), kev);
  }).filter(Boolean);
}
/** Moxa's RSS: CVEs in the title, a CVSS table in the description, the advisory id (MPSA-nnnnnn) in the link. */
export function parseMoxaRss(xml, kev = new Set()) {
  return items(xml).map((b) => {
    const url = https(decode(tag(b, ["link"])).trim()), title = txt(decode(tag(b, ["title"])), 400), desc = decode(tag(b, ["description"]));
    const id = (url.match(/\/(mpsa-\d{4,})/i) || [])[1]; if (!url || !id) return null;
    const plain = txt(desc, 20000);
    return withKev(rec({ id: id.toUpperCase(), source: "moxa", vendor: "Moxa", title: txt(title.replace(/^(CVE-\d{4}-\d{4,}[,\s]*)+:\s*/i, ""), 200), cves: cvesIn(title + " " + desc).slice(0, 200),
      cvss: maxScore(plain, /CVSS\s*v?([34]\.\d)\s*:\s*(\d{1,2}(?:\.\d)?)/gi), exploited: exploitFromText(plain), url, summary: txt(plain.replace(/CVE ID[\s\S]*$/i, ""), 300),
      published: iso(decode(tag(b, ["pubDate"])).trim()) }), kev);
  }).filter(Boolean);
}
/** Mitsubishi Electric's RSS 1.0 (RDF): a title and the PDF advisory; no CVEs or scores in the feed. */
export function parseMelcoRss(xml, kev = new Set()) {
  return items(xml).map((b) => {
    const url = https(decode(tag(b, ["link"])).trim()), id = (url.match(/\/(\d{4}-\d{3})_en\.pdf$/i) || [])[1]; if (!url || !id) return null;
    const title = txt(decode(tag(b, ["title"])), 240), date = iso(decode(tag(b, ["dc:date"])).trim());
    return withKev(rec({ id: "MEL-" + id, source: "mitsubishi", vendor: "Mitsubishi Electric", title: txt(title.replace(/\s*\[Update\]\s*$/i, ""), 200), cves: cvesIn(title), url,
      published: /\[Update\]/i.test(title) ? "" : date, updated: date }), kev);
  }).filter(Boolean);
}
const RSS = { vde: parseVdeRss, moxa: parseMoxaRss, melco: parseMelcoRss };

/* ---------- leads ---------- */
const DEFAULTS = { window_days: 365, max_fetch_per_source: 150, lead_days: 7, max_leads_per_run: 30, lead_cvss: 9, sector_cvss: 8, lifeline_sectors: [] };
export const config = () => ({ ...DEFAULTS, ...(readJson(join(ROOT, "config", "ics.json"), {}) || {}) });
/** Pure: why this advisory is notable for the research loop, or "" when it is not. */
export function notable(a, cfg = DEFAULTS) {
  if (a.not_affected) return "";
  if (a.exploited === "kev") return "known exploited (CISA KEV)";
  if (a.exploited === "active") return "exploited, per the advisory";
  if (a.cvss != null && a.cvss >= cfg.lead_cvss) return `CVSS ${a.cvss.toFixed(1)}`;
  const life = new Set((cfg.lifeline_sectors || []).map((s) => s.toLowerCase()));
  const hit = (a.sectors || []).find((s) => life.has(s.toLowerCase()));
  if (hit && a.cvss != null && a.cvss >= cfg.sector_cvss) return `CVSS ${a.cvss.toFixed(1)} in ${hit}`;
  return "";
}
/** Pure: advisory -> lead in the collectors' shape (data/leads/<date>.jsonl). The title says what makes it notable, in
 *  plain words ("critical", "known exploited"), so the backlog rules never close it as a routine bulletin. */
export function toLead(a, seenAt, why) {
  const src = SOURCES[a.source] || { name: a.source, tier: "vendor" };
  const what = [a.cvss != null ? `CVSS ${a.cvss.toFixed(1)}${a.cvss >= 9 ? " critical" : ""}` : "", a.exploited === "kev" ? "known exploited (CISA KEV)" : a.exploited === "active" ? "exploited per the advisory" : a.exploited === "poc" ? "public exploit" : "",
    (a.sectors || []).length ? `critical infrastructure: ${a.sectors.slice(0, 3).join(", ")}` : ""].filter(Boolean).join("; ");
  return {
    seen_at: seenAt, source: src.name, tier: src.tier, via: "ics", kind: "advisory",
    title: txt(`${a.id} ${a.vendor ? a.vendor + " " : ""}industrial advisory: ${a.vendor && a.title.startsWith(a.vendor + ":") ? a.title.slice(a.vendor.length + 1).trim() : a.title}${what ? ` (${what})` : ""}`, 200),
    url: a.url || a.doc, published: a.published || a.updated || seenAt,
    summary: txt(`${why ? "Notable: " + why + ". " : ""}${a.summary}${a.cves.length ? " CVEs: " + a.cves.slice(0, 8).join(", ") + "." : ""}`, 300), lang: "en",
  };
}

/* ---------- merge ---------- */
const keyOf = (a) => `${a.source}:${a.id}`;
/** Pure: the records to keep. prev and fresh are lists; a source in `failed` keeps its previous records; for the rest a
 *  fresh record replaces the old one with the same key, and old ones the feed no longer lists stay. Only advisories first
 *  published (or, with no publication date, updated) within the window are kept, newest first, at most 3,000. */
export function mergeRecords(prev, fresh, failed = new Set(), sinceDay = "", vdeIds = null) {
  const m = new Map();
  for (const a of prev || []) if (a && a.id && a.source) m.set(keyOf(a), a);
  for (const a of fresh || []) if (a && a.id && a.source && !failed.has(a.source)) m.set(keyOf(a), a);
  // an advisory CERT@VDE coordinates for Phoenix Contact comes from its CSAF document, not the RSS line
  const vde = vdeIds || new Set([...m.values()].filter((a) => a.source === "phoenix").map((a) => a.id));
  return [...m.values()].filter((a) => !(a.source === "certvde" && vde.has(a.id)))
    .filter((a) => !sinceDay || String(a.published || a.updated).slice(0, 10) >= sinceDay)
    .sort((a, b) => String(b.updated || b.published).localeCompare(String(a.updated || a.published)) || a.id.localeCompare(b.id)).slice(0, 3000);
}

/** Pure: the advisory records the page reads (site/data/ics.json), each field checked and cut to length. */
export function siteRows(list) {
  const S = (v, n) => txt(v, n), day = (v) => (/^\d{4}-\d{2}-\d{2}/.test(v || "") ? String(v).slice(0, 10) : "");
  return (Array.isArray(list) ? list : []).map((a) => {
    if (!a || typeof a !== "object" || !SOURCES[a.source] || !/^[A-Z0-9][A-Z0-9._:-]{2,39}$/.test(a.id || "")) return null;
    const cves = (Array.isArray(a.cves) ? a.cves : []).filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c)).slice(0, 60), cc = {};
    for (const c of cves) { const n = a.cve_cvss && Number(a.cve_cvss[c]); if (isFinite(n) && n >= 0 && n <= 10) cc[c] = n; }
    return { id: a.id, source: a.source, vendor: S(a.vendor, 60), title: S(a.title, 200), products: (a.products || []).slice(0, 8).map((p) => S(p, 100)).filter(Boolean), products_total: Math.min(9999, Number(a.products_total) || 0),
      cves, cve_cvss: cc, cvss: typeof a.cvss === "number" && a.cvss >= 0 && a.cvss <= 10 ? a.cvss : null, cvss_version: S(a.cvss_version, 5), cvss_vector: S(a.cvss_vector, 160),
      exploited: RANK[a.exploited] != null ? a.exploited : "", exploit_note: a.exploited === "active" || a.exploited === "poc" ? S(a.exploit_note, 200) : "", kev_cves: (a.kev_cves || []).filter((c) => cves.includes(c)),
      not_affected: a.not_affected === true, sectors: (a.sectors || []).slice(0, 12).map((s) => S(s, 60)), remediation: (a.remediation || []).filter((r) => /^(vendor_fix|mitigation|workaround|none_available|no_fix_planned)$/.test(r)),
      url: https(a.url), doc: https(a.doc), summary: clip(a.summary, 220), published: day(a.published), updated: day(a.updated) };
  }).filter(Boolean);
}

/** Pure: data/ics/advisories.json -> what the build writes to site/data/ics.json (null when it is not usable). */
export function siteData(d, builtAt = "", cfg = config()) {
  if (!d || typeof d !== "object" || !Array.isArray(d.advisories)) return null;
  const sources = {};
  for (const [k, s] of Object.entries(SOURCES)) { const h = (d.sources && d.sources[k]) || {};
    sources[k] = { name: s.name, tier: s.tier, ok: h.ok === true, at: iso(h.at), count: Math.min(99999, Number(h.count) || 0), error: txt(h.error, 160) }; }
  return { built_at: builtAt, updated_at: iso(d.updated_at), window_days: Number(d.window_days) || 365, sources,
    lifeline: (cfg.lifeline_sectors || []).map((x) => txt(x, 60)).slice(0, 30), advisories: siteRows(d.advisories) };
}

/* ---------- collection ---------- */
function kevSet() {
  const dir = join(DATA, "kev");
  return new Set(existsSync(dir) ? readdirSync(dir).filter((f) => /^CVE-\d{4}-\d{4,}\.json$/.test(f)).map((f) => f.slice(0, -5)) : []);
}
async function pool(list, n, fn) { let i = 0; await Promise.all(Array.from({ length: n }, async () => { while (i < list.length) { const x = list[i++]; await fn(x); } })); }

/** Read one CSAF source: which documents to (re)read from its index, and read up to the per-run limit, newest first. */
async function collectCsaf(key, s, prev, cfg, kev, sinceDay) {
  let index;
  if (s.how === "rolie") index = parseRolie(await fetchOk(s.feed)).map((e) => ({ url: e.url, at: e.at, day: (e.published || e.at).slice(0, 10) }));
  else index = parseChangesCsv(await fetchOk(s.base + "changes.csv", "text")).map((e) => ({ url: s.base + e.path, at: e.at, day: idDay(e.path, s.hint) }));
  // a hint with the year only ("2026-01-01") still lets every advisory of that year through; the record's date decides after
  const yearOnly = (d) => /-01-01$/.test(d);
  index = index.filter((e) => !e.day || e.day >= sinceDay || (yearOnly(e.day) && e.day.slice(0, 4) >= sinceDay.slice(0, 4)));
  const byDoc = new Map(prev.filter((a) => a.source === key && a.doc).map((a) => [a.doc, a]));
  const seen = new Set(), todo = [], out = [];
  for (const e of index) { if (seen.has(e.url)) continue; seen.add(e.url); const old = byDoc.get(e.url); if (old && old.src_at === e.at && old.v === PARSE_VERSION) out.push(old); else todo.push(e); }
  const work = todo.slice(0, cfg.max_fetch_per_source); let failed = 0;
  await pool(work, 4, async (e) => {
    try { const r = parseCsaf(await fetchOk(e.url), { source: key, vendor: s.vendor || "", docUrl: e.url, srcAt: e.at, kev }); if (r) out.push(r); }
    catch { failed++; const old = byDoc.get(e.url); if (old) out.push(old); }
  });
  for (const e of todo.slice(cfg.max_fetch_per_source)) { const old = byDoc.get(e.url); if (old) out.push(old); }
  return { records: out, fetched: work.length - failed, failed, waiting: Math.max(0, todo.length - work.length), listed: index.length };
}

export async function collect({ leads = true, dry = false } = {}) {
  const cfg = config(), kev = kevSet(), now = Date.now(), at = nowIso();
  const sinceDay = new Date(now - cfg.window_days * 864e5).toISOString().slice(0, 10);
  const old = readJson(OUT, {}) || {}, prev = Array.isArray(old.advisories) ? old.advisories : [];
  // KEV status changes without the advisory changing: refresh it on every record kept
  for (const a of prev) { const k = (a.cves || []).filter((c) => kev.has(c)); if (k.length) { a.kev_cves = k; a.exploited = "kev"; } }
  const fresh = [], failed = new Set(), health = {};
  for (const [key, s] of Object.entries(SOURCES)) {
    const h = { name: s.name, tier: s.tier, at, ok: false, count: 0, error: "" };
    try {
      if (s.how === "rss") { const r = RSS[s.parser](await fetchOk(s.url, "text"), kev); fresh.push(...r); h.ok = true; h.count = r.length; }
      else {
        try { const r = await collectCsaf(key, s, prev, cfg, kev, sinceDay); fresh.push(...r.records); Object.assign(h, { ok: true, count: r.records.length, fetched: r.fetched, failed: r.failed, waiting: r.waiting, listed: r.listed }); }
        catch (e) {
          if (!s.fallback) throw e;
          const r = []; for (const u of s.fallback) r.push(...parseCisaRss(await fetchOk(u, "text"), kev));
          // the RSS lines are thinner than the CSAF documents: they never replace a record already read from CSAF
          const have = new Set(prev.filter((a) => a.source === key).map((a) => a.id));
          fresh.push(...prev.filter((a) => a.source === key), ...r.filter((a) => !have.has(a.id)));
          Object.assign(h, { ok: true, count: r.length, error: `CSAF not read (${e.code || e.message}); used the RSS feeds` });
        }
      }
    } catch (e) { failed.add(key); h.error = String((e && (e.code === "robots" ? e.message : e.code)) || (e && e.message) || "failed").slice(0, 160); h.count = prev.filter((a) => a.source === key).length; h.stale = true; }
    health[key] = h;
    console.log(`${key}: ${h.ok ? "ok" : "FAILED"} ${h.count} advisories${h.fetched != null ? `, ${h.fetched} read${h.waiting ? `, ${h.waiting} left for later runs` : ""}` : ""}${h.error ? " (" + h.error + ")" : ""}`);
  }
  const advisories = mergeRecords(prev, fresh, failed, sinceDay);
  // leads: each notable advisory once, when it is new
  const filed = { ...(old.filed || {}) }, cut = new Date(now - 60 * 864e5).toISOString();
  for (const k of Object.keys(filed)) if (filed[k] < cut) delete filed[k];
  const leadSince = new Date(now - cfg.lead_days * 864e5).toISOString();
  const out = [];
  for (const a of advisories) {
    if (out.length >= cfg.max_leads_per_run) break;
    if (filed[keyOf(a)] || !(a.published && a.published >= leadSince) || !(a.url || a.doc)) continue;
    const why = notable(a, cfg); if (!why) continue;
    out.push(toLead(a, at, why)); filed[keyOf(a)] = at;
  }
  const result = { updated_at: at, window_days: cfg.window_days, sources: health, count: advisories.length, advisories, filed };
  if (dry) { console.log(`DRY: ${advisories.length} advisories; ${out.length} lead(s) would be filed.`); return result; }
  if (Object.values(health).every((h) => !h.ok) && prev.length) { console.log("ICS: every source failed; the last copy is kept unchanged."); return null; }
  writeJson(OUT, result);
  if (leads && out.length) { const dir = join(DATA, "leads"); mkdirSync(dir, { recursive: true }); appendFileSync(join(dir, `${at.slice(0, 10)}.jsonl`), out.map((l) => JSON.stringify(l)).join("\n") + "\n"); }
  const st = readStatus(); st.last_ics_at = at; writeJson(join(DATA, "status.json"), st);
  const exp = advisories.filter((a) => a.exploited === "kev" || a.exploited === "active").length;
  console.log(`ICS: ${advisories.length} advisories in ${cfg.window_days} days (${exp} exploited); ${out.length} new lead(s).`);
  return result;
}

function status() {
  const d = readJson(OUT, null); if (!d) { console.log("ICS: no data/ics/advisories.json yet."); return; }
  console.log(`ICS advisories, updated ${d.updated_at}: ${d.count} on file.`);
  for (const [k, h] of Object.entries(d.sources || {})) console.log(`  ${k.padEnd(11)} ${h.ok ? "ok    " : "FAILED"} ${String(h.count).padStart(5)}  ${h.error || ""}`);
}

async function main() {
  const cmd = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : "collect";
  if (cmd === "status") return status();
  if (cmd !== "collect") { console.error("usage: ics.mjs [collect] [--no-leads] [--dry] | status"); process.exit(1); }
  const r = await collect({ leads: !process.argv.includes("--no-leads"), dry: process.argv.includes("--dry") });
  if (r && Object.values(r.sources).every((h) => !h.ok)) process.exit(1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
