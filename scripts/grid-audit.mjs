// Grid data audit, no AI model. Checks what a rule can check about every grid source's latest data and about the
// pipeline's own health, so problems surface by themselves instead of waiting for someone to look:
//   per source: fetch state and how long it has been failing, item count against its own recent history (a feed that
//   suddenly returns nothing or ten times more is flagged), points far from the source's country, start times in the
//   future or very old, duplicate ids, missing customer counts, links off the operator's own hosts
//   pipeline: age of each stage (collect, analysis, news, research), open incidents waiting for research, file growth
// Writes data/grid/audit.json (the build copies its flags into health.json for the status page and the guard) and keeps
// a per-source history of item and customer counts in it (last 7 days, hourly), so the next audit can tell normal from odd.
// Run: node scripts/grid-audit.mjs [--json]      exit 0 always (it reports; it never blocks the pipeline)
import { existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, readJson, writeJson, nowIso, readStatus } from "./lib/store.mjs";

const H = 3600e3;
const LARGE = { US: 3500, CA: 3500, RU: 5000, AU: 3000, BR: 3000, CN: 3000, IN: 2200, AR: 2200, KZ: 2000, ZA: 1300, NO: 1300, SE: 1100, FI: 900, JP: 1500, ID: 2500, MX: 1800, CL: 2200, GB: 800, FR: 900, DE: 700, PL: 600, NL: 300, TW: 300, KR: 400, GH: 500 };
const km = (a, b) => { const r = Math.PI / 180, dLa = (b[0] - a[0]) * r, dLo = (b[1] - a[1]) * r;
  const h = Math.sin(dLa / 2) ** 2 + Math.cos(a[0] * r) * Math.cos(b[0] * r) * Math.sin(dLo / 2) ** 2; return 12742 * Math.asin(Math.sqrt(h)); };
const median = (a) => { const s = [...a].sort((x, y) => x - y); return s.length ? s[Math.floor(s.length / 2)] : null; };

/** Pure: the item-level checks for one source. */
export function checkItems(items, def, countries, now = Date.now()) {
  const out = { items: items.length, customers: 0, outages: 0, no_location: 0, far_from_country: 0, future_start: 0, old_start: 0, dup_ids: 0, no_customers: 0, off_host_links: 0, examples: [] };
  const ids = new Set(), hosts = new Set((def && def.hosts) || []);
  const ex = (kind, x) => { if (out.examples.length < 6) out.examples.push({ check: kind, id: String(x.id).slice(0, 80) }); };
  for (const x of items) {
    if (ids.has(x.id)) { out.dup_ids++; ex("dup_id", x); } ids.add(x.id);
    if (x.lat === null || x.lng === null) out.no_location++;
    else {
      const c = countries[x.country];
      if (c && km([x.lat, x.lng], [c[1], c[2]]) > (LARGE[x.country] || 1500)) { out.far_from_country++; ex("far_from_country", x); }
    }
    const t = Date.parse(x.started_at || "");
    if (isFinite(t) && t - now > 2 * H) { out.future_start++; ex("future_start", x); }
    if (isFinite(t) && now - t > 60 * 24 * H && x.kind === "outage" && !x.planned) { out.old_start++; ex("old_start", x); }
    if (x.kind === "outage") { out.outages++; if (x.customers === null) out.no_customers++; else out.customers += x.customers; }
    const m = /^https:\/\/([^/?#]+)/.exec(x.url || "");
    if (x.url && (!m || (hosts.size && !hosts.has(m[1])))) { out.off_host_links++; ex("off_host_link", x); }
  }
  return out;
}

/** Pure: flags for one source from its checks, its fetch state and its item-count history ({ h, n items, c customers }). */
export function flagsFor(k, src, chk, hist, now = Date.now()) {
  const f = [];
  if (src && src.paused) return ["paused"];
  if (src && !src.ok && /^not connected/.test(src.error || "")) return ["not_connected"];
  if (src && !src.ok) {
    // failing since its last success, or (never a success) since the failures began: 4-minute cycles, so 360 a day
    const since = Date.parse(src.fetched_at || ""), n = Number(src.failures) || 0;
    f.push((isFinite(since) && now - since > 24 * H) || (!isFinite(since) && n >= 360) ? "failing_over_24h" : "failing");
  }
  if (src && src.stale) f.push("stale_data");          // answered, but the operator's own data time is old (sources-2)
  if (src && src.dormant) f.push("dormant");           // the feed's newest entry is weeks old: the operator stopped it (sources-5)
  const past = (hist || []).map((h) => h.n).filter((n) => Number.isFinite(n));
  const med = median(past);
  if (past.length >= 12 && med !== null && src && src.ok) {
    if (med >= 5 && chk.items === 0) f.push("suddenly_empty");
    else if (med >= 3 && chk.items > med * 10) f.push("surge");
  }
  // parser drift (sources-3): the items are there but their customers are not
  const pastC = (hist || []).map((h) => h.c).filter((n) => Number.isFinite(n)), medC = median(pastC);
  if (src && src.ok && chk.outages) {
    if (chk.customers === 0 && chk.no_customers < chk.outages) f.push("zero_customers");
    if (chk.no_customers / chk.outages > 0.5 && pastC.some((c) => c > 0)) f.push("customers_missing");
    if (pastC.length >= 12 && medC >= 1000 && chk.customers <= medC * 0.05 && chk.items >= (med || 0) / 2) f.push("customers_fell");
  }
  if (chk.items && chk.far_from_country / chk.items > 0.2) f.push("locations_suspect");
  if (chk.future_start) f.push("future_times");
  if (chk.dup_ids) f.push("duplicate_ids");
  if (chk.off_host_links) f.push("links_off_host");
  return f;
}

function fileSize(p) { try { return statSync(p).size; } catch { return 0; } }
function dirSize(d) { let n = 0; if (!existsSync(d)) return 0; for (const f of readdirSync(d, { withFileTypes: true })) n += f.isDirectory() ? dirSize(join(d, f.name)) : fileSize(join(d, f.name)); return n; }

export async function audit(now = Date.now()) {
  const { SOURCES, COUNTRIES, SERIES_KEEP_DAYS, REGIONS } = await import("./grid.mjs");
  const live = readJson(join(DATA, "grid", "live.json"), {}) || {}, prev = readJson(join(DATA, "grid", "audit.json"), {}) || {};
  const st = readStatus(), inc = readJson(join(DATA, "grid", "incidents.json"), { open: [] }) || { open: [] }, research = readJson(join(DATA, "grid", "research.json"), {}) || {};
  const items = Array.isArray(live.items) ? live.items : [], sources = {};
  const hourKey = new Date(now).toISOString().slice(0, 13);
  for (const k of Object.keys(SOURCES)) {
    const src = (live.sources || {})[k] || null, mine = items.filter((x) => x.source === k);
    const chk = checkItems(mine, SOURCES[k], COUNTRIES, now);
    let hist = ((prev.sources || {})[k] || {}).history || [];
    if (!hist.length || hist[hist.length - 1].h !== hourKey) hist = [...hist, { h: hourKey, n: src && src.ok ? mine.length : null, c: src && src.ok ? chk.customers : null }];
    hist = hist.filter((x) => now - Date.parse(x.h + ":00:00Z") < 7 * 24 * H).slice(-168);
    sources[k] = { name: SOURCES[k].name, ok: !!(src && src.ok), error: (src && src.error) || "", fetched_at: (src && src.fetched_at) || "",
      checks: chk, flags: flagsFor(k, src && { ...src, paused: SOURCES[k].paused }, chk, hist.slice(0, -1), now), history: hist };
  }
  const age = (iso) => { const t = Date.parse(iso || ""); return isFinite(t) ? Math.round((now - t) / 6e4) : null; };
  const pending = (inc.open || []).filter((i) => i.research_needed && !(research[i.id] && research[i.id].final));
  const stages = { collect_min: age(st.last_grid_at), news_min: age(st.last_grid_news_at), research_min: age(st.last_grid_research_at),
    analysis_min: age((readJson(join(DATA, "grid", "analysis.json"), {}) || {}).updated_at) };
  const pipeline = { stages, open_incidents: (inc.open || []).length, waiting_for_research: pending.length,
    oldest_waiting_min: pending.length ? Math.max(...pending.map((i) => age(i.opened_at) || 0)) : 0,
    sizes_kb: { series: Math.round(dirSize(join(DATA, "grid", "series")) / 1024), history: Math.round(dirSize(join(DATA, "grid", "history")) / 1024),
      news: Math.round(fileSize(join(DATA, "grid", "news.json")) / 1024), live: Math.round(fileSize(join(DATA, "grid", "live.json")) / 1024) } };
  const pflags = [];
  if (stages.collect_min === null || stages.collect_min > 30) pflags.push("collect_late");
  if (stages.news_min === null || stages.news_min > 60) pflags.push("news_late");
  if (stages.analysis_min === null || stages.analysis_min > 60) pflags.push("analysis_late");
  if (pending.length && pipeline.oldest_waiting_min > 120) pflags.push("research_waiting_over_2h");
  // the series is expected to hold SERIES_KEEP_DAYS days of ~96 slots per region at ~120 bytes a line, a third of them
  // non-zero (sparse storage); flag it only at 1.5 times that (ops-13: the old 20 MB fired by design)
  const expectedKb = Math.round((Object.keys(REGIONS).length * 96 * 120 * SERIES_KEEP_DAYS) / 3 / 1024);
  pipeline.series_expected_kb = expectedKb;
  if (pipeline.sizes_kb.series > 1.5 * expectedKb) pflags.push("series_large");
  pipeline.flags = pflags;
  const counts = {}; for (const s of Object.values(sources)) for (const f of s.flags) counts[f] = (counts[f] || 0) + 1;
  return { updated_at: nowIso(), pipeline, flag_counts: counts, sources };
}

async function main() {
  const a = await audit();
  writeJson(join(DATA, "grid", "audit.json"), a);
  if (process.argv.includes("--json")) { console.log(JSON.stringify(a, null, 1)); return; }
  const flagged = Object.entries(a.sources).filter(([, s]) => s.flags.length);
  console.log(`grid-audit: ${Object.keys(a.sources).length} sources, ${flagged.length} flagged; pipeline ${a.pipeline.flags.join(", ") || "ok"}; ` +
    `stages ${JSON.stringify(a.pipeline.stages)}; sizes ${JSON.stringify(a.pipeline.sizes_kb)}`);
  for (const [k, s] of flagged) console.log(`  ${k}: ${s.flags.join(", ")}${s.checks.examples.length ? "  e.g. " + s.checks.examples.slice(0, 2).map((e) => `${e.check} ${e.id}`).join("; ") : ""}`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
