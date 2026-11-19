// The CVE corpus: every CVE ever published, from the official CVE List (github.com/CVEProject/cvelistV5, with CISA's
// enrichment), FIRST EPSS scores and our CISA known-exploited files. No AI model. Run: node scripts/cve.mjs <command>
//   baseline <dir>      build the corpus from an unpacked cvelistV5 release (every cves/<year>/<n>xxx/CVE-*.json)
//   delta [--max N]     apply the CVE List's change log (cves/deltaLog.json) since the last run (exit 4 when the corpus is
//                       older than the log reaches: rebuild it); new notable CVEs
//                       (exploited per CISA, on KEV, or CVSS 9+) are filed as leads for the research loop
//   epss                attach today's EPSS score and percentile to every CVE
//   kev                 mark CVEs in data/kev/ as known exploited
//   site [dir]          write the lookup files the site reads (default site/data/cve/): <year>/<thousand>.json buckets
//                       (index.json lists them per year in files_by_year),
//                       index.json (counts, freshness) and recent.json (published or changed in the last 14 days)
//   stats | get <id>
// The corpus lives in CVE_CORPUS (default cache/cve/, not committed): <year>.jsonl plus state.json. The cve workflow
// keeps it as a release file of this repository between runs, so the full history is never committed to git.
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync, appendFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, writeJson, nowIso, dayAgo } from "./lib/store.mjs";
import { get } from "./lib/net.mjs";
import { compact, parseEpss, bucket, deltaSince, notable, toLead, FIELDS, toArr, ID } from "./lib/cve.mjs";

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
  setState({ baseline_at: nowIso(), delta_since: process.env.CVE_BASELINE_AT || nowIso(), pending: [] });
  console.log(`BASELINE: ${n} CVE(s) in ${byYear.size} year file(s); ${bad} file(s) skipped.`);
}

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
  for (const { r } of got) { const y = yearOf(r.id); if (!touched.has(y)) touched.set(y, loadYear(y)); const prev = touched.get(y).get(r.id); touched.get(y).set(r.id, { ...r, epss: prev ? prev.epss : null, pct: prev ? prev.pct : null, kev: r.kev || (prev && prev.kev) || "" }); }
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

function kev() {
  const dir = join(DATA, "kev"); let n = 0; const byYear = new Map();
  for (const f of existsSync(dir) ? readdirSync(dir).filter((f) => /^CVE-.*\.json$/.test(f)) : []) {
    const k = readJson(join(dir, f), {}), id = f.replace(/\.json$/, ""); if (!ID.test(id)) continue;
    const y = yearOf(id); if (!byYear.has(y)) byYear.set(y, loadYear(y));
    const row = byYear.get(y).get(id); if (row && !row.kev) { row.kev = String(k.added || k.dateAdded || "yes").slice(0, 10); n++; }
  }
  for (const [y, m] of byYear) saveYear(y, m);
  console.log(`KEV: ${n} CVE(s) newly marked known exploited.`);
}

function site(out = join(ROOT, "site", "data", "cve")) {
  if (!years().length) { console.log("SITE: no corpus here; nothing written."); return; }
  rmSync(out, { recursive: true, force: true }); mkdirSync(out, { recursive: true });
  const buckets = new Map(), byYear = {}, recent = [], since = dayAgo(14); let total = 0, rejected = 0, exploited = 0, critical = 0;
  for (const r of allRows()) {
    total++; if (r.state === "R") rejected++; if (r.kev || r.expl === "active") exploited++; if (r.cvss >= 9) critical++;
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
  if (cmd === "site") return site(a);
  if (cmd === "stats") return stats();
  if (cmd === "get") { if (!ID.test(a || "")) { console.error("usage: cve.mjs get CVE-YYYY-N"); process.exit(1); } console.log(JSON.stringify(loadYear(yearOf(a)).get(a) || null, null, 2)); return; }
  console.error("usage: cve.mjs baseline <dir> | delta [--max N] | epss | kev | site [dir] | stats | get <id>"); process.exit(1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
