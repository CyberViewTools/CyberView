// The CVE corpus: every CVE ever published, from the official CVE List (github.com/CVEProject/cvelistV5, with CISA's
// enrichment), FIRST EPSS scores and our CISA known-exploited files. No AI model. Run: node scripts/cve.mjs <command>
//   baseline <dir>      build the corpus from an unpacked cvelistV5 release (every cves/<year>/<n>xxx/CVE-*.json)
//   delta [--max N]     apply the CVE List's change log (cves/deltaLog.json) since the last run (exit 4 when the corpus is
//                       older than the log reaches: rebuild it); new notable CVEs
//                       (exploited per CISA, on KEV, or CVSS 9+) are filed as leads for the research loop
//   epss                attach today's EPSS score and percentile to every CVE
//   kev                 CISA's whole known-exploited catalog: date added, BOD 22-01 due date, known ransomware use
//   nvd                 NVD's own CVSS score per CVE (full read once, then only NVD's changes)
//   audit               our counts against NVD and CISA totals, kept in state.json and shown on the site
//   site [dir]          write the lookup files the site reads (default site/data/cve/): <year>/<thousand>.json buckets
//                       (index.json lists them per year in files_by_year),
//                       index.json (counts, freshness) and recent.json (published or changed in the last 14 days)
//   stats | get <id>
// The corpus lives in CVE_CORPUS (default cache/cve/, not committed): <year>.jsonl plus state.json. The cve workflow
// keeps it in the GitHub Actions cache between runs, so the full history is never committed to git.
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync, appendFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, writeJson, nowIso, dayAgo } from "./lib/store.mjs";
import { get } from "./lib/net.mjs";
import vm from "node:vm";
// the site's rating code, run here too so the counts on the page and the ratings in the browser cannot disagree
const RATE = (() => { const sb = { window: {} }; vm.runInNewContext(readFileSync(join(ROOT, "site", "cvedb-lib.js"), "utf8"), sb); return sb.window.CVDB; })();
import { compact, parseEpss, bucket, deltaSince, notable, toLead, FIELDS, toArr, ID, parseKevCatalog, nvdScore } from "./lib/cve.mjs";

export const CORPUS_VERSION = 2;
/** Critical the way NVD counts it: a CVSS v3 or v4 rating of Critical (CVSS v2 has no Critical). The assigner's or CISA's
 *  score first, NVD's when they gave none. */
export function isCritical(r) {
  if (r.cvss != null) return r.sev === "C" && !/^2/.test(r.ver || "");
  return r.ncvss != null && r.nsev === "C" && /^CVSS:[34]/.test(r.nvec || "");
}   // raise when compact() gains fields: the workflow then rebuilds the corpus from the CVE List
const DIR = process.env.CVE_CORPUS || join(ROOT, "cache", "cve");
const STATE = join(DIR, "state.json");
const DELTA_LOG = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json";
const EPSS = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
const opt = (n, d) => { const i = process.argv.indexOf("--" + n); return i > 0 ? Number(process.argv[i + 1]) || d : d; };

// ---------- corpus store: one jsonl file per year ----------
const yearOf = (id) => id.split("-")[1];
function loadYear(y) {
  const f = join(DIR, `${y}.jsonl`), m = new Map();
  if (existsSync(f)) for (const l of readFileSync(f, "utf8").split("\n")) { if (!l) continue; try { const r = JSON.parse(l); m.set(r.id, r); } catch {} }
  return m;
}
const num = (id) => Number(id.split("-")[2]);
function saveYear(y, m) {
  mkdirSync(DIR, { recursive: true });
  const rows = [...m.values()].sort((a, b) => num(a.id) - num(b.id));
  writeFileSync(join(DIR, `${y}.jsonl`), rows.map((r) => JSON.stringify(r)).join("\n") + (rows.length ? "\n" : ""));
}
const years = () => (existsSync(DIR) ? readdirSync(DIR).filter((f) => /^\d{4}\.jsonl$/.test(f)).map((f) => f.slice(0, 4)).sort() : []);
function* allRows() { for (const y of years()) for (const r of loadYear(y).values()) yield r; }
const state = () => readJson(STATE, {});
const setState = (o) => writeJson(STATE, { ...state(), ...o });

// ---------- commands ----------
function baseline(src) {
  if (!src || !existsSync(src)) { console.error("usage: cve.mjs baseline <unpacked cvelistV5 dir>"); process.exit(1); }
  const byYear = new Map(); let n = 0, bad = 0;
  const walk = (d) => { for (const f of readdirSync(d)) { const p = join(d, f), s = statSync(p);
    if (s.isDirectory()) walk(p);
    else if (/^CVE-\d{4}-\d+\.json$/.test(f)) { try { const r = compact(JSON.parse(readFileSync(p, "utf8"))); if (!r) { bad++; continue; } const y = yearOf(r.id); if (!byYear.has(y)) byYear.set(y, new Map()); byYear.get(y).set(r.id, r); n++; } catch { bad++; } } } };
  walk(src);
  for (const [y, m] of byYear) saveYear(y, m);
  setState({ baseline_at: nowIso(), delta_since: process.env.CVE_BASELINE_AT || nowIso(), pending: [], version: CORPUS_VERSION, nvd_since: null });
  console.log(`BASELINE: ${n} CVE(s) in ${byYear.size} year file(s); ${bad} file(s) skipped.`);
}

// enrichments that do not come from the CVE List itself survive a record's update
const keep = (p) => (p ? { due: p.due || "", ransom: !!p.ransom, ncvss: p.ncvss ?? null, nsev: p.nsev || "", nvec: p.nvec || "", n3: p.n3 || "", n3c: !!p.n3c } : {});

async function delta() {
  const st = state(), max = opt("max", 4000);
  if (!st.delta_since) { console.error("no corpus yet: run baseline first (the cve workflow downloads it)"); process.exit(1); }
  const log = await get(DELTA_LOG, { timeoutMs: 60000 });
  const runs = (Array.isArray(log) ? log : []).map((r) => r.fetchTime).filter(Boolean).sort();
  // the change log only reaches back so far; a corpus older than its first entry would silently miss changes
  if (runs.length && String(st.delta_since) < runs[0]) { console.log(`STALE: the corpus ends ${st.delta_since}, before the change log begins (${runs[0]}); rebuild it from the CVE List release.`); process.exit(4); }
  const todo = deltaSince(log, st.delta_since);
  for (const id of st.pending || []) if (!todo.find((t) => t.id === id)) { const [, y, n] = id.split("-"); todo.push({ id, url: `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${y}/${Math.floor(Number(n) / 1000)}xxx/${id}.json`, at: "", isNew: false }); }
  const work = todo.slice(0, max), failed = todo.slice(max).map((t) => t.id), got = [];
  let i = 0;
  await Promise.all(Array.from({ length: 8 }, async () => { while (i < work.length) { const t = work[i++];
    try { const r = compact(await get(t.url, { timeoutMs: 20000, retries: 1, key: "cvelist-" + t.id })); if (r) got.push({ r, isNew: t.isNew }); } catch { failed.push(t.id); } } }));
  const touched = new Map();
  for (const { r } of got) { const y = yearOf(r.id); if (!touched.has(y)) touched.set(y, loadYear(y)); const prev = touched.get(y).get(r.id); touched.get(y).set(r.id, { ...r, ...keep(prev), epss: prev ? prev.epss : null, pct: prev ? prev.pct : null, kev: r.kev || (prev && prev.kev) || "" }); }
  for (const [y, m] of touched) saveYear(y, m);
  setState({ delta_since: runs.length ? runs[runs.length - 1] : st.delta_since, delta_at: nowIso(), pending: [...new Set(failed)].slice(0, 20000) });
  // new notable CVEs become leads for the research loop (deduplicated against the last three days of leads)
  const leadsDir = join(DATA, "leads"), known = new Set(), seen = nowIso();
  mkdirSync(leadsDir, { recursive: true });
  for (const f of readdirSync(leadsDir).filter((f) => f.endsWith(".jsonl")).sort().slice(-3)) for (const l of readFileSync(join(leadsDir, f), "utf8").split("\n")) { try { known.add(JSON.parse(l).url); } catch {} }
  const leads = got.filter((g) => g.isNew && notable(g.r, dayAgo(7))).map((g) => toLead(g.r, seen)).filter((l) => !known.has(l.url)).slice(0, 60);
  if (leads.length) appendFileSync(join(leadsDir, `${seen.slice(0, 10)}.jsonl`), leads.map((l) => JSON.stringify(l)).join("\n") + "\n");
  console.log(`DELTA: ${got.length} CVE record(s) applied (${got.filter((g) => g.isNew).length} new), ${failed.length} to retry, ${leads.length} new lead(s).`);
}

async function epss() {
  const r = await fetch(EPSS, { signal: AbortSignal.timeout(120000), headers: { "user-agent": "cyberview-feeds/1.0 (+https://github.com/xanderhutch/CyberView)" } });
  if (!r.ok) { console.error(`EPSS: HTTP ${r.status}`); process.exit(1); }
  const csv = gunzipSync(Buffer.from(await r.arrayBuffer())).toString("utf8"), m = parseEpss(csv);
  const date = (csv.match(/score_date:(\d{4}-\d{2}-\d{2})/) || [])[1] || dayAgo(0);
  let n = 0;
  for (const y of years()) { const rows = loadYear(y); for (const row of rows.values()) { const e = m.get(row.id); row.epss = e ? e[0] : null; row.pct = e ? e[1] : null; if (e) n++; } saveYear(y, rows); }
  setState({ epss_date: date });
  console.log(`EPSS: ${m.size} score(s) for ${date}; ${n} CVE(s) in the corpus scored.`);
}

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
/** CISA's whole known-exploited catalog: date added, federal due date (BOD 22-01) and known ransomware use for every entry;
 *  our data/kev files are the fallback when the catalog cannot be fetched. */
async function kev() {
  let cat = null;
  try { cat = parseKevCatalog(await get(KEV_URL, { timeoutMs: 60000 })); } catch (e) { console.log(`KEV: catalog not fetched (${e.code || e.message}); using data/kev`); }
  if (!cat || !cat.size) {
    cat = new Map(); const dir = join(DATA, "kev");
    for (const f of existsSync(dir) ? readdirSync(dir).filter((f) => /^CVE-.*\.json$/.test(f)) : []) { const k = readJson(join(dir, f), {}), id = f.replace(/\.json$/, ""); if (ID.test(id)) cat.set(id, { added: String(k.added || k.dateAdded || "").slice(0, 10), due: String(k.due || k.dueDate || "").slice(0, 10), ransom: k.ransomware === true || /^known$/i.test(k.knownRansomwareCampaignUse || "") }); }
  }
  let n = 0, missing = 0; const byYear = new Map();
  for (const [id, k] of cat) {
    const y = yearOf(id); if (!byYear.has(y)) byYear.set(y, loadYear(y));
    const row = byYear.get(y).get(id); if (!row) { missing++; continue; }
    const before = JSON.stringify([row.kev, row.due, row.ransom]);
    row.kev = k.added || row.kev || "yes"; row.due = k.due || row.due || ""; row.ransom = !!k.ransom;
    if (JSON.stringify([row.kev, row.due, row.ransom]) !== before) n++;
  }
  for (const [y, m] of byYear) saveYear(y, m);
  setState({ kev_catalog: cat.size, kev_at: nowIso() });
  console.log(`KEV: ${cat.size} catalog entries; ${n} CVE row(s) changed; ${missing} not in the corpus yet.`);
}

const NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** NVD's own CVSS score for every CVE: a full read the first time (about 215 pages, ~25 minutes without an API key),
 *  then only what NVD changed since the last run (windows of at most 120 days, as the API requires). */
async function nvd() {
  const NVD_VERSION = 2;   // raise when nvdScore keeps more: the next run reads all of NVD again
  const st = state(), full = !st.nvd_since || (st.nvd_version || 1) < NVD_VERSION, startedAt = nowIso(), key = process.env.NVD_API_KEY || "";
  const pause = key ? 700 : 6500, byYear = new Map(); let pages = 0, scored = 0, seen = 0;
  const windows = [];
  if (full) windows.push("");
  else { let from = Date.parse(st.nvd_since) - 5 * 6e4; const to = Date.now(); while (from < to) { const end = Math.min(to, from + 119 * 864e5); windows.push(`&lastModStartDate=${new Date(from).toISOString()}&lastModEndDate=${new Date(end).toISOString()}`); from = end; } }
  for (const w of windows) {
    for (let start = 0, total = Infinity; start < total; start += 2000) {
      let j = null;
      for (let t = 0; t < 4 && !j; t++) { try { j = await fetch(`${NVD}?resultsPerPage=2000&startIndex=${start}${w}`, { headers: { "user-agent": "cyberview-feeds/1.0 (+https://github.com/xanderhutch/CyberView)", ...(key ? { apiKey: key } : {}) }, signal: AbortSignal.timeout(120000) }).then((r) => (r.ok ? r.json() : null)); } catch {} if (!j) await sleep(30000); }
      if (!j) { console.log(`NVD: page at ${start} failed four times; stopping, the next run resumes`); saveAll(byYear); return; }
      total = j.totalResults || 0; pages++;
      for (const it of j.vulnerabilities || []) {
        const id = it.cve && it.cve.id; if (!ID.test(id || "")) continue; seen++;
        const y = yearOf(id); if (!byYear.has(y)) byYear.set(y, loadYear(y));
        const row = byYear.get(y).get(id), s = nvdScore(it); if (!row) continue;
        row.ncvss = s ? s.ncvss : null; row.nsev = s ? s.nsev : ""; row.nvec = s ? s.nvec : ""; row.n3 = s ? s.n3 : ""; row.n3c = !!(s && s.n3c); if (s && s.ncvss != null) scored++;
      }
      if (start + 2000 < total) await sleep(pause);
    }
  }
  saveAll(byYear);
  setState({ nvd_since: startedAt, nvd_version: NVD_VERSION });
  console.log(`NVD: ${seen} record(s) read in ${pages} page(s)${full ? " (full read)" : ""}; ${scored} with an NVD score.`);
}
function saveAll(byYear) { for (const [y, m] of byYear) saveYear(y, m); }

/** Our counts against the primary sources (NVD totals, CISA's catalog), recorded so the site can show it and a drift is seen. */
async function audit() {
  let total = 0, rejected = 0, kevN = 0, crit = 0, critAny = 0, critNvd = 0, critNvdOwn = 0;
  for (const r of allRows()) { total++; if (r.state === "R") { rejected++; continue; } if (r.kev) kevN++; const c = r.cvss ?? r.ncvss; if (isCritical(r)) crit++; if (r.n3c) critNvd++; if (r.n3 === "C") critNvdOwn++; if ((r.sev === "C" && !/^2/.test(r.ver || "")) || (r.nsev === "C" && /^CVSS:[34]/.test(r.nvec || ""))) critAny++; }
  const q = async (p) => { try { const j = await get(`${NVD}?resultsPerPage=1${p}`, { timeoutMs: 60000 }); return j.totalResults ?? null; } catch { return null; } };
  const nvdAll = await q(""); await sleep(6500); const nvdLive = await q("&noRejected"); await sleep(6500); const nvdCritV3 = await q("&cvssV3Severity=CRITICAL");
  const st = state(), a = { at: nowIso(), ours: { total, rejected, kev: kevN, critical: crit, critical_any_source: critAny, critical_nvd_v3: critNvd, critical_nvd_own_v3: critNvdOwn },
    nvd: { total: nvdAll, rejected: nvdAll != null && nvdLive != null ? nvdAll - nvdLive : null, critical_v3: nvdCritV3 }, cisa_kev: st.kev_catalog ?? null };
  setState({ audit: a });
  console.log(`AUDIT: ours ${total} total / ${rejected} rejected / ${kevN} KEV / ${crit} critical; NVD ${nvdAll} / ${a.nvd.rejected} / critical v3 ${nvdCritV3}; CISA KEV ${a.cisa_kev}`);
}

function site(out = join(ROOT, "site", "data", "cve")) {
  if (!years().length) { console.log("SITE: no corpus here; nothing written."); return; }
  rmSync(out, { recursive: true, force: true }); mkdirSync(out, { recursive: true });
  const buckets = new Map(), byYear = {}, recent = [], since = dayAgo(14), decisions = {}, bands = {}; let total = 0, rejected = 0, exploited = 0, critical = 0, criticalNvd = 0, criticalNvdOwn = 0, kevN = 0, activeOnly = 0, ransom = 0, nvdOnly = 0, unscored = 0;
  for (const r of allRows()) {
    total++; if (r.state === "R") rejected++; if (r.kev || r.expl === "active") exploited++;
    if (r.state !== "R") { if (r.kev) kevN++; else if (r.expl === "active") activeOnly++; if (r.ransom) ransom++; if (isCritical(r)) critical++; if (r.n3c) criticalNvd++; if (r.n3 === "C") criticalNvdOwn++; if (r.cvss == null && r.ncvss != null) nvdOnly++; if (r.cvss == null && r.ncvss == null) unscored++;
      const d = RATE.rate({ ...r, rejected: false }); if (d && d.decision) decisions[d.decision] = (decisions[d.decision] || 0) + 1;
      const sc = RATE.score({ ...r, rejected: false }); if (sc) bands[sc.band] = (bands[sc.band] || 0) + 1; }
    const y = yearOf(r.id); byYear[y] = (byYear[y] || 0) + 1;
    const b = bucket(r.id); if (!buckets.has(b)) buckets.set(b, []); buckets.get(b).push(toArr(r));
    if (r.state === "P" && (r.pub >= since || r.upd >= since)) recent.push(r);
  }
  for (const [b, rows] of buckets) { const [y, k] = b.split("/"); mkdirSync(join(out, y), { recursive: true }); writeFileSync(join(out, y, `${k}.json`), JSON.stringify({ fields: FIELDS, rows })); }
  recent.sort((a, b) => (b.pub || "").localeCompare(a.pub || "") || num(b.id) - num(a.id));
  const st = state();
  writeFileSync(join(out, "recent.json"), JSON.stringify({ fields: FIELDS, since, rows: recent.slice(0, 3000).map(toArr) }));
  const files = {}; for (const b of buckets.keys()) { const [y, k] = b.split("/"); (files[y] ||= []).push(Number(k)); }
  for (const y of Object.keys(files)) files[y].sort((a, b) => a - b);
  writeFileSync(join(out, "index.json"), JSON.stringify({ built_at: nowIso(), total, rejected, exploited, critical, by_year: byYear, buckets: buckets.size, files_by_year: files,
    critical_nvd: criticalNvd, bands, critical_nvd_own: criticalNvdOwn, kev: kevN, cisa_active_not_kev: activeOnly, ransomware: ransom, scored_by_nvd_only: nvdOnly, unscored, decisions, audit: st.audit || null, kev_catalog: st.kev_catalog ?? null,
    sources: { cvelist: st.delta_at || st.baseline_at || null, epss: st.epss_date || null } }));
  console.log(`SITE: ${total} CVE(s) in ${buckets.size} lookup file(s); ${recent.length} published or changed since ${since}.`);
}

function stats() {
  const st = state(); let n = 0; const y = {};
  for (const r of allRows()) { n++; const k = yearOf(r.id); y[k] = (y[k] || 0) + 1; }
  setState({ total: n });
  console.log(`CVE corpus: ${n} CVE(s), years ${Object.keys(y)[0] || "-"} to ${Object.keys(y).pop() || "-"}; baseline ${st.baseline_at || "none"}; changes to ${st.delta_since || "-"}; EPSS ${st.epss_date || "-"}; ${(st.pending || []).length} waiting to retry.`);
}

async function main() {
  const [cmd, a] = process.argv.slice(2);
  if (cmd === "baseline") return baseline(a);
  if (cmd === "delta") return delta();
  if (cmd === "epss") return epss();
  if (cmd === "kev") return kev();
  if (cmd === "nvd") return nvd();
  if (cmd === "audit") return audit();
  if (cmd === "site") return site(a);
  if (cmd === "stats") return stats();
  if (cmd === "get") { if (!ID.test(a || "")) { console.error("usage: cve.mjs get CVE-YYYY-N"); process.exit(1); } console.log(JSON.stringify(loadYear(yearOf(a)).get(a) || null, null, 2)); return; }
  console.error("usage: cve.mjs baseline <dir> | delta [--max N] | epss | kev | nvd | audit | site [dir] | stats | get <id>"); process.exit(1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
