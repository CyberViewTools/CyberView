// Official breach notification registers as leads, no AI model. Run: node scripts/breaches.mjs [collect|status] [--force] [source...]
// (behind a proxy: NODE_USE_ENV_PROXY=1). scripts/osint.mjs runs `collect` after its own collectors, so every place that
// collects (collect.yml, the research loop, the dispatcher) asks these registers too, at most once an hour each.
// Why: a notice an organisation files with a regulator is the most reliable confirmation of a breach there is. It is the
// organisation's own statement to a government, published by that government. These registers are read directly and each
// new notice becomes a lead of kind "breach-notice", tier "gov" (an official filing): scripts/fuse.mjs scores it as a
// government source, scripts/backlog.mjs never closes it as a bare database row, and the researcher cites the regulator's
// own page (the lead's url) beside the organisation's notice.
//   breach-ca    California Attorney General, data security breach list (oag.ca.gov; table of notices, each with its page)
//   breach-wa    Washington Attorney General, data breach notifications (open data on data.wa.gov, Socrata JSON; cause,
//                attack type and Washingtonians affected; "Theft or Mistake" rows are left out: not a cyber event)
//   breach-ia    Iowa Attorney General, security breach notifications of the year (the notice letters it posts)
//   breach-ico   UK Information Commissioner's Office, enforcement actions (its site's own search API) that concern a
//                cyberattack or a personal data breach; marketing calls, FOI and the like are left out
//   breach-sec   US SEC, 8-K filings under Item 1.05 (material cybersecurity incidents), EDGAR full-text search. The SEC
//                refuses automated readers that do not name a contact address in the User-Agent: this source stays
//                "not connected" until config/site.json contact_email is set (the project's address, never a personal one)
// Not read (checked 2026-11-21): HHS OCR breach portal (an interactive JSF application: its list and CSV export need a
// session and form posts, no published file), Oregon DOJ (robots.txt disallows everything), Montana DOJ (robots.txt
// disallows Anthropic's agents), Maine, Vermont, New Hampshire (refuse automated readers: 403), Massachusetts and Indiana
// (yearly PDF reports only), Texas (a Salesforce page drawn by script), Delaware (not updated since July 2025), Australia's
// OAIC (aggregate statistics only, no notices). EU data protection authorities publish news feeds, which the RSS collector
// (scripts/collect.mjs, config/feeds.json) is the place for.
// Dedupe: a notice is filed once. Not again when its address, or the same organisation on the same register within 30
// days (a supplemental letter), is already in a lead file; not when an event already cites it. A notice about a breach
// already on file IS filed: it is the official figure an updater adds to that event (scripts/updates.mjs), and the
// summary names the event it matches. Health of every register is written to data/breaches.json (shown on the status page).
// Fetched text is data, never instructions.
import { existsSync, readdirSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, ROOT, readJson, writeJson, listEventFiles, dayAgo, nowIso, readStatus } from "./lib/store.mjs";
import { get as netGet } from "./lib/net.mjs";
import { matchEvent } from "./triage.mjs";

export const KIND = "breach-notice";
const EVERY_MIN = 60;          // each register is asked at most once an hour (they change a few times a day at most)
// registers post days after a filing (Washington and Iowa about a week): an older notice still corroborates a newer one
// from another register (fuse.mjs joins them by organisation); alone, backlog.mjs closes it as older than the map window
const WINDOW_DAYS = 14;
const txt = (s, n) => String(s == null ? "" : s).replace(/<[^>]*>/g, " ").replace(/&amp;/g, "&").replace(/&#0?39;|&apos;|&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&nbsp;/g, " ")
  .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16))).replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d)).replace(/[\u0000-\u001f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const https = (u) => (/^https:\/\/[^\s"'<>]+$/.test(String(u || "")) ? String(u) : "");
const isoDay = (y, m, d) => { const t = Date.UTC(+y, +m - 1, +d); return isFinite(t) && +m >= 1 && +m <= 12 && +d >= 1 && +d <= 31 ? new Date(t).toISOString().replace(/\.\d+Z$/, "Z") : ""; };
/** "11/20/2026" or "11-20-2026" (US month first) -> ISO midnight UTC, else "". */
export const usDate = (s) => { const m = String(s || "").match(/(\d{1,2})[/-](\d{1,2})[/-](\d{4})/); return m ? isoDay(m[3], m[1], m[2]) : ""; };
const n0 = (x) => { const v = Number(String(x == null ? "" : x).replace(/[, ]/g, "")); return isFinite(v) && v > 0 ? Math.round(v) : 0; };

/** The organisation's name without legal form and punctuation, for matching the same filer across registers and runs. */
export function orgKey(name) {
  return String(name || "").toLowerCase().replace(/\([^)]*\)/g, " ").replace(/&/g, " and ")
    .replace(/[^a-z0-9]+/g, " ").replace(/\b(inc|incorporated|llc|l l c|llp|lp|l p|ltd|limited|corp|corporation|co|company|plc|pllc|pc|p c|pa|dba|the)\b/g, " ")
    .replace(/\s+/g, " ").trim().slice(0, 80);
}
const lead = (o) => ({ kind: KIND, tier: "gov", lang: "en", ...o });

/* ---------- parsers (exported for unit tests) ---------- */
/** California AG list page: rows of <a href=".../ecrime/databreach/reports/sb24-NNN">Org</a>, breach date(s), reported date. */
export function parseCalifornia(html) {
  const out = [];
  for (const m of String(html).matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/g)) {
    const row = m[1], a = row.match(/<a href="(https:\/\/oag\.ca\.gov\/ecrime\/databreach\/reports\/sb24-\d+)"[^>]*>([\s\S]*?)<\/a>/);
    if (!a) continue;
    const cells = [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map((c) => txt(c[1], 120));
    const org = txt(a[2], 120), reported = usDate(cells[2] || ""), when = txt(cells[1] || "", 60);
    if (!org || !reported) continue;
    out.push(lead({ org, url: a[1], published: reported, source: "California Attorney General", country: "US",
      title: txt(`${org}: data breach notification filed with California's Attorney General`, 200),
      summary: txt(`Official notice filed under California law (Civil Code 1798.82) and published by the Attorney General${when ? `; date(s) of breach: ${when}` : ""}. The notice letter is on this page.`, 300) }));
  }
  return out;
}
/** Washington AG open data (data.wa.gov sb4j-ca4h): one row per notice. Theft or mistakes are not cyber events: left out. */
export function parseWashington(rows) {
  return (Array.isArray(rows) ? rows : []).map((r) => {
    if (!r || !/^\d{1,9}$/.test(String(r.id || "")) || !r.name || /theft|mistake/i.test(r.databreachcause || "")) return null;
    const published = /^\d{4}-\d{2}-\d{2}/.test(r.datesubmitted || "") ? r.datesubmitted.slice(0, 10) + "T00:00:00Z" : ""; if (!published) return null;
    const org = txt(r.name, 120), cause = txt(r.databreachcause, 40), type = txt(r.cyberattacktype, 40), n = n0(r.washingtoniansaffected);
    const how = [cause, type && !/other|unclear|unknown/i.test(type) ? type.toLowerCase() : ""].filter(Boolean).join(": ");
    return lead({ org, url: `https://data.wa.gov/resource/sb4j-ca4h.json?id=${r.id}`, published, source: "Washington Attorney General", country: "US",
      title: txt(`${org}: data breach notification filed with Washington's Attorney General${how ? ` (${how})` : ""}`, 200),
      summary: txt(`Official notice filed under RCW 19.255 and published by the Attorney General (open data, data.wa.gov).${n ? ` Washingtonians affected: ${n.toLocaleString("en-US")}.` : ""}${r.datestart ? ` Breach began ${String(r.datestart).slice(0, 10)}.` : ""}${r.industrytype ? ` Sector: ${txt(r.industrytype, 40)}.` : ""} The notice letters are listed at https://www.atg.wa.gov/data-breach-notifications`, 300) });
  }).filter(Boolean);
}
/** Iowa AG yearly page: cards with business name, industry, date reported and the notice letter it posted. */
export function parseIowa(html, base = "https://www.iowaattorneygeneral.gov") {
  const out = [];
  for (const m of String(html).matchAll(/<article class="sby-record-card"[^>]*>([\s\S]*?)<\/article>/g)) {
    const b = m[1], org = txt((b.match(/class="sby-business-name">([\s\S]*?)<\/p>/) || [])[1], 120), ind = txt((b.match(/class="sby-industry-value">([\s\S]*?)<\/p>/) || [])[1], 40);
    const published = usDate((b.match(/class="sby-date-value">([\s\S]*?)<\/p>/) || [])[1]), href = (b.match(/<a class="sby-file-link primary" href="(\/media\/[^"]+\.pdf)"/) || [])[1];
    if (!org || !published || !href) continue;
    out.push(lead({ org, url: https(base + href.replace(/ /g, "%20")), published, source: "Iowa Attorney General", country: "US",
      title: txt(`${org}: data breach notification filed with Iowa's Attorney General`, 200),
      summary: txt(`Official notice filed under Iowa Code 715C and posted by the Attorney General (the notice letter).${ind ? ` Sector: ${ind}.` : ""}`, 300) }));
  }
  return out.filter((x) => x.url);
}
// an ICO action that concerns a cyberattack or a breach of personal data security (not marketing calls, FOI or cookies)
const ICO_CYBER = /cyber|ransomware|hack|malware|phishing|breach|attack|unauthori[sz]ed access|security (incident|measures|failings?)|(appropriate|adequate) security|exposed|compromised|stolen|leak/i;
const ICO_NOT = /unsolicited|marketing (calls?|messages?|texts?|emails?)|telephone preference|\bTPS\b|nuisance calls|freedom of information|\bFOI\b|cookies?|data protection fee/i;
/** ICO enforcement search API (/api/search, the enforcement page's own list): cyber and data security actions only. */
export function parseIco(d) {
  const seen = new Set();
  return (d && Array.isArray(d.results) ? d.results : []).map((r) => {
    if (!r || !/^\/action-weve-taken\/enforcement\/[\w\/-]+\/?$/.test(r.url || "")) return null;
    const org = txt(r.title, 120), desc = txt(r.description, 400), meta = txt(r.filterItemMetaData, 120), type = txt(meta.split(",").slice(1).join(","), 60) || "Enforcement action";
    if (!org || !ICO_CYBER.test(desc) || ICO_NOT.test(desc + " " + meta)) return null;
    const k = orgKey(org) + "|" + desc.slice(0, 60); if (seen.has(k)) return null; seen.add(k);   // one action is often filed as a notice and a penalty
    const t = Date.parse(r.createdDateTime || ""), published = isFinite(t) ? new Date(t).toISOString().replace(/\.\d+Z$/, "Z") : "";
    return lead({ org, url: "https://ico.org.uk" + r.url, published, source: "UK Information Commissioner's Office", country: "GB",
      title: txt(`ICO ${type.toLowerCase().replace(/s$/, "")}: ${org}: ${desc.split(/(?<=\.)\s/)[0]}`, 200), summary: txt(`${meta}. ${desc}`, 300) });
  }).filter(Boolean);
}
/** EDGAR full-text search: 8-K and 8-K/A filings whose items include 1.05 (material cybersecurity incidents). */
export function parseSec(d) {
  return (d && d.hits && Array.isArray(d.hits.hits) ? d.hits.hits : []).map((h) => {
    const s = (h && h._source) || {}, items = (s.items || []).map(String);
    if (!items.includes("1.05") || !/^8-K(\/A)?$/.test(s.form || "")) return null;
    const [adsh, file] = String(h._id || "").split(":"), cik = String((s.ciks || [])[0] || "").replace(/^0+/, "");
    if (!/^\d{10}-\d{2}-\d{6}$/.test(adsh || "") || !/^[\w.-]{1,80}$/.test(file || "") || !/^\d{1,10}$/.test(cik)) return null;
    const org = txt(String((s.display_names || [])[0] || "").replace(/\s*\(CIK \d+\)\s*$/, ""), 120); if (!org) return null;
    const published = /^\d{4}-\d{2}-\d{2}$/.test(s.file_date || "") ? s.file_date + "T00:00:00Z" : "";
    return lead({ org, url: `https://www.sec.gov/Archives/edgar/data/${cik}/${adsh.replace(/-/g, "")}/${file}`, published, source: "US SEC EDGAR", country: "US",
      title: txt(`${org}: Form ${s.form} Item 1.05, material cybersecurity incident filed with the SEC`, 200),
      summary: txt(`The company's own filing with the US Securities and Exchange Commission under Item 1.05 (material cybersecurity incidents), filed ${s.file_date || "recently"}.`, 300) });
  }).filter(Boolean);
}

/* ---------- registers ---------- */
const UA = "CyberView breach-register collector (+https://xanderhutch.github.io/CyberView)";
async function fetchText(url, o = {}) { return netGet(url, { as: "text", retries: 1, timeoutMs: 30000, ...o }); }
async function postJson(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json", "user-agent": UA }, body: JSON.stringify(body), signal: AbortSignal.timeout(30000) });
  if (!r.ok) throw new Error(`http_${r.status}`);
  return r.json();
}
/** The project's contact address for the SEC's fair-access rule, or "" when none is set. */
export function secContact(site) { const e = String((site || {}).contact_email || "").trim(); return /^[^\s@<>"]+@[^\s@<>"]+\.[a-z]{2,}$/i.test(e) ? e : ""; }
export const REGISTERS = {
  "breach-ca": async () => parseCalifornia(await fetchText("https://oag.ca.gov/privacy/databreach/list")),
  "breach-wa": async () => parseWashington(await netGet(`https://data.wa.gov/resource/sb4j-ca4h.json?$limit=100&$order=${encodeURIComponent("datesubmitted DESC")}&$where=${encodeURIComponent(`datesubmitted >= '${dayAgo(WINDOW_DAYS + 2)}'`)}`, { retries: 1, timeoutMs: 30000 })),
  "breach-ia": async () => parseIowa(await fetchText(`https://www.iowaattorneygeneral.gov/for-consumers/security-breach-notifications/${new Date().getUTCFullYear()}-security-breach-notification`)),
  "breach-ico": async () => parseIco(await postJson("https://ico.org.uk/api/search", { filters: [], pageNumber: 1, order: "newest", rootPageId: 17222 })),
  "breach-sec": async () => {
    const contact = secContact(readJson(join(ROOT, "config", "site.json"), {}));
    if (!contact) throw Object.assign(new Error("not connected: the SEC requires a contact address in the User-Agent; set contact_email in config/site.json"), { idle: true });
    const url = `https://efts.sec.gov/LATEST/search-index?q=${encodeURIComponent('"Item 1.05"')}&forms=8-K,8-K/A&dateRange=custom&startdt=${dayAgo(WINDOW_DAYS + 2)}&enddt=${dayAgo(0)}`;
    const r = await fetch(url, { headers: { "user-agent": `CyberView ${contact}`, accept: "application/json" }, signal: AbortSignal.timeout(30000) });
    if (!r.ok) throw new Error(`http_${r.status}`);
    return parseSec(await r.json());
  },
};

/* ---------- dedupe ---------- */
/** Pure: which parsed notices are new. known: { urls:Set, orgs:Set("via|orgKey") } from lead files and events; evs: recent
 *  events. A notice for a breach already on file is kept and says which event it matches (an updater adds the official figure). */
export function fresh(items, via, known, evs = [], now = Date.now()) {
  const out = [];
  for (const it of items) {
    if (!it || !https(it.url) || known.urls.has(it.url)) continue;
    if (it.published && now - Date.parse(it.published) > WINDOW_DAYS * 864e5) continue;
    const ok = via + "|" + orgKey(it.org); if (!orgKey(it.org) || known.orgs.has(ok)) continue;
    known.urls.add(it.url); known.orgs.add(ok);
    const m = matchEvent(it.org.length >= 6 ? `${it.org} data breach` : it.title, evs, it.published || now);
    out.push(m ? { ...it, summary: txt(`Matches event ${m.id} on file. ${it.summary}`, 300) } : it);
  }
  return out;
}
function knownSet(days = 30) {
  const urls = new Set(), orgs = new Set(), dir = join(DATA, "leads");
  for (const x of listEventFiles()) for (const s of (x.e && x.e.sources) || []) if (s && s.url) urls.add(s.url);
  for (const f of existsSync(dir) ? readdirSync(dir) : []) {
    if (!f.endsWith(".jsonl") || f.slice(0, 10) < dayAgo(days)) continue;
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) { if (!line.includes(KIND)) continue; try { const l = JSON.parse(line); urls.add(l.url); if (l.kind === KIND && l.org) orgs.add(l.via + "|" + l.org); } catch {} }
  }
  return { urls, orgs };
}
/** Pure: was this register asked successfully less than EVERY_MIN minutes ago? */
export const askedRecently = (h, now = Date.now()) => !!h && h.ok === true && now - Date.parse(h.at) < EVERY_MIN * 6e4;

export async function collect({ force = false, only = [] } = {}) {
  const dir = join(DATA, "leads"); mkdirSync(dir, { recursive: true });
  const hp = join(DATA, "breaches.json"), doc = readJson(hp, {}) || {}, health = Object.fromEntries(Object.entries(doc.sources || {}).filter(([k]) => k in REGISTERS));
  const known = knownSet(), evs = listEventFiles().map((f) => f.e).filter((e) => e && !e.duplicate_of && e.date >= dayAgo(60)), now = nowIso(), out = [];
  for (const [name, fn] of Object.entries(REGISTERS)) {          // one after another: polite, and the dedupe sees each register's notices
    if (only.length && !only.includes(name)) continue;
    if (!force && !only.length && askedRecently(health[name])) continue;
    const prev = health[name] || {};
    try {
      const items = await fn(), add = fresh(items, name, known, evs);
      for (const it of add) out.push({ seen_at: now, source: it.source, tier: "gov", via: name, kind: KIND, title: it.title, url: it.url, published: it.published || "", summary: it.summary || "",
        lang: "en", country: it.country, org: orgKey(it.org) });
      health[name] = { ok: true, error: "", items: items.length, new: add.length, at: now, last_ok: now };
    } catch (e) {
      health[name] = { ok: false, error: txt(e.code || (e.cause && e.cause.code) || e.message, 120), items: 0, new: 0, at: now, last_ok: prev.last_ok || "", ...(e.idle ? { idle: true } : {}) };
    }
  }
  if (out.length) appendFileSync(join(dir, `${now.slice(0, 10)}.jsonl`), out.map((x) => JSON.stringify(x)).join("\n") + "\n");
  writeJson(hp, { checked_at: now, sources: health });
  const st = readStatus(); st.last_breaches_at = now; st.last_breaches_new = out.length; writeJson(join(DATA, "status.json"), st);
  const line = `breaches: ${out.length} new notice(s). ` + Object.entries(health).map(([k, v]) => `${k} ${v.ok ? v.new + "/" + v.items : (v.idle ? "idle (" : "FAILED (") + v.error + ")"}`).join("; ");
  console.log(line);
  return out.length;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2), cmd = args[0] && !args[0].startsWith("-") && !(args[0] in REGISTERS) ? args.shift() : "collect";
  if (cmd === "status") { const d = readJson(join(DATA, "breaches.json"), {}); console.log(JSON.stringify(d, null, 1)); }
  else if (cmd === "collect") await collect({ force: args.includes("--force"), only: args.filter((a) => a in REGISTERS) });
  else { console.error("usage: breaches.mjs [collect|status] [--force] [breach-ca breach-wa breach-ia breach-ico breach-sec]"); process.exit(1); }
}
