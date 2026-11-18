// Mechanical feeds, no AI model needed. Run: node scripts/feeds.mjs
// 1. data/kev/<CVE>.json matches the CISA known-exploited catalog for entries added in the last 45 days.
//    Old files are kept (they are the history); the build only publishes the last 45 days.
// 2. EPSS scores from FIRST for every recent KEV entry and every CVE on a recent event.
// 3. CVSS from NVD for up to NVD_MAX entries that lack it (NVD allows ~5 requests per 30 s without a key).
// 4. cve_meta on recent events is refreshed; an event whose CVE is known-exploited is raised to at least severity 2
//    (the AI jobs decide whether it deserves 3). Every change is listed in the output.
// 5. data/status.json gets last_kev_at / last_feeds_at, and data/runs/<date>/<time>-feeds.json logs the run.
// A source that fails is skipped and reported; the script never deletes anything.
import { readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { DATA, readJson, writeJson, listEventFiles, saveEvent, writeRunLog } from "./lib/store.mjs";

const KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json";
const KEV_DAYS = 45, EVENT_DAYS = 9, NVD_MAX = Number(process.env.NVD_MAX || 20);
const now = new Date(), nowIso = now.toISOString().replace(/\.\d+Z$/, "Z");
const day = (n) => new Date(Date.now() - n * 864e5).toISOString().slice(0, 10);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = { job: "feeds", started_at: nowIso, kev_added: [], kev_updated: [], epss_updated: 0, cvss_added: [], events_updated: [], rerated: [], failed: [] };

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const sortKeys = (o) => Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]]));

async function getJson(url, label, tries = 3) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url, { headers: { "user-agent": "cyberview-feeds/1.0" } });
      if (r.ok) return await r.json();
      if (r.status === 404) return null;
      if (r.status !== 429 && r.status < 500) throw new Error("HTTP " + r.status);
    } catch (e) {
      // a connection error (DNS, refused) will not fix itself in two minutes: one quick retry, then give up
      const code = (e.cause && e.cause.code) || e.message;
      if (i >= 1 || /ENOTFOUND|ECONNREFUSED|EAI_AGAIN/.test(code) && i >= 0 && tries === 1) { log.failed.push(`${label}: ${code}`); return null; }
      await sleep(5000); continue;
    }
    await sleep([0, 60000, 120000][i + 1] || 5000);   // 429 or 5xx: the site is busy, space the retries
  }
  log.failed.push(`${label}: no answer after ${tries} tries`);
  return null;
}

// 1. KEV
const kevDir = join(DATA, "kev");
const catalog = await getJson(KEV_URL, "CISA KEV catalog");
if (catalog && Array.isArray(catalog.vulnerabilities)) {
  for (const v of catalog.vulnerabilities) {
    if ((v.dateAdded || "") < day(KEV_DAYS)) continue;
    const p = join(kevDir, `${v.cveID}.json`), old = readJson(p, {});
    const rec = sortKeys({
      ...old,
      cve: v.cveID, vendor: v.vendorProject, product: v.product, name: v.vulnerabilityName,
      added: v.dateAdded, due: v.dueDate, ransomware: v.knownRansomwareCampaignUse === "Known",
      // keep a plain-language description an AI job already wrote; otherwise use CISA's text, trimmed
      desc: old.desc || String(v.shortDescription || "").slice(0, 260),
    });
    if (!same(rec, old)) { writeJson(p, rec); (Object.keys(old).length ? log.kev_updated : log.kev_added).push(v.cveID); }
  }
}

// recent KEV entries and recent events
const kevFiles = existsSync(kevDir) ? readdirSync(kevDir).filter((f) => f.endsWith(".json")) : [];
const kev = Object.fromEntries(kevFiles.map((f) => [f.slice(0, -5), readJson(join(kevDir, f), {})]));
const recentKev = Object.values(kev).filter((k) => (k.added || "") >= day(KEV_DAYS));
const events = listEventFiles().filter((x) => x.e && (x.e.date || "") >= day(EVENT_DAYS) && !x.e.duplicate_of)
  .map((x) => ({ f: x.path, e: x.e }));
const eventCves = new Set(events.flatMap((x) => (Array.isArray(x.e.cves) ? x.e.cves : [])).filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c)));

// 2. EPSS (batches of 50)
const epss = {};
const allCves = [...new Set([...recentKev.map((k) => k.cve), ...eventCves])];
for (let i = 0; i < allCves.length; i += 50) {
  const batch = allCves.slice(i, i + 50);
  const r = await getJson(`https://api.first.org/data/v1/epss?cve=${batch.join(",")}`, "FIRST EPSS");
  for (const row of (r && r.data) || []) epss[row.cve] = Math.round(Number(row.epss) * 1e5) / 1e5;
}

// 3. NVD CVSS for entries without one
const cvss = {};
async function nvd(cve) {
  const r = await getJson(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`, `NVD ${cve}`, 2);
  const m = r && r.vulnerabilities && r.vulnerabilities[0] && r.vulnerabilities[0].cve.metrics;
  if (!m) return null;
  for (const k of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const x = (m[k] || []).find((y) => y.type === "Primary") || (m[k] || [])[0];
    if (x && x.cvssData && typeof x.cvssData.baseScore === "number") return x.cvssData.baseScore;
  }
  return null;
}
let nvdCalls = 0;
for (const k of recentKev) {
  if (typeof k.cvss === "number" || nvdCalls >= NVD_MAX) continue;
  nvdCalls++; const s = await nvd(k.cve); if (s != null) { cvss[k.cve] = s; log.cvss_added.push(k.cve); }
  await sleep(6500);
}

// write KEV scores
for (const k of recentKev) {
  const p = join(kevDir, `${k.cve}.json`), next = { ...k };
  if (epss[k.cve] != null) next.epss = epss[k.cve];
  if (cvss[k.cve] != null) next.cvss = cvss[k.cve];
  if (!same(sortKeys(next), sortKeys(k))) { writeJson(p, sortKeys(next)); log.epss_updated++; }
}

// 4. events: cve_meta and re-rating
for (const { f, e } of events) {
  if (!Array.isArray(e.cves) || !e.cves.length) continue;
  const old = Array.isArray(e.cve_meta) ? e.cve_meta : [];
  const meta = e.cves.map((id) => {
    const prev = old.find((m) => m.id === id) || {}, k = kev[id];
    return {
      id,
      cvss: cvss[id] ?? (k && k.cvss) ?? prev.cvss ?? null,
      epss: epss[id] ?? prev.epss ?? null,
      kev: !!k || !!prev.kev,
      kev_due: (k && k.due) || prev.kev_due || "",
    };
  });
  const next = { ...e, cve_meta: meta };
  if (meta.some((m) => m.kev) && e.severity < 2) { next.severity = 2; log.rerated.push(`${e.id}: 1 -> 2 (known-exploited)`); }
  if (!same(next, e)) { next.updated_at = nowIso; saveEvent(next, f); log.events_updated.push(e.id); }
}

// 5. status and run log
const sp = join(DATA, "status.json"), st = readJson(sp, {});
if (catalog) st.last_kev_at = nowIso;
st.last_feeds_at = nowIso;
writeJson(sp, st);
log.finished_at = new Date().toISOString().replace(/\.\d+Z$/, "Z");
const { job, ...rest } = log;
writeRunLog("feeds", rest);

console.log(`feeds: KEV +${log.kev_added.length} new, ${log.kev_updated.length} updated; scores changed on ${log.epss_updated}; CVSS added ${log.cvss_added.length}; events updated ${log.events_updated.length}; re-rated ${log.rerated.length}` +
  (log.failed.length ? `; failed: ${log.failed.join("; ")}` : ""));
