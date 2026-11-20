// Grid data audit, no AI model. Checks what a rule can check about every grid source's latest data and about the
// pipeline's own health, so problems surface by themselves instead of waiting for someone to look:
//   per source: fetch state and how long it has been failing, item count against its own recent history (a feed that
//   suddenly returns nothing or ten times more is flagged), points far from the source's country, start times in the
//   future or very old, duplicate ids, missing customer counts, links off the operator's own hosts
//   pipeline: age of each stage (collect, analysis, news, research), open incidents waiting for research, file growth
// Writes data/grid/audit.json (read by the status page, the grid steward job and the guard) and keeps a per-source
// history of item counts in it (last 7 days, hourly), so the next audit can tell normal from odd.
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
  const out = { items: items.length, no_location: 0, far_from_country: 0, future_start: 0, old_start: 0, dup_ids: 0, no_customers: 0, off_host_links: 0, examples: [] };
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
    if (x.kind === "outage" && x.customers === null) out.no_customers++;
    const m = /^https:\/\/([^/?#]+)/.exec(x.url || "");
    if (x.url && (!m || (hosts.size && !hosts.has(m[1])))) { out.off_host_links++; ex("off_host_link", x); }
  }
  return out;
}

/** Pure: flags for one source from its checks, its fetch state and its item-count history. */
export function flagsFor(k, src, chk, hist, now = Date.now()) {
  const f = [];
  if (src && src.paused) return ["paused"];
  if (src && !src.ok && /^not connected/.test(src.error || "")) return ["not_connected"];
  if (src && !src.ok) {
    const since = Date.parse(src.fetched_at || "");
    f.push(isFinite(since) && now - since > 24 * H ? "failing_over_24h" : "failing");
  }
  const past = (hist || []).map((h) => h.n).filter((n) => Number.isFinite(n));
  const med = median(past);
  if (past.length >= 12 && med !== null && src && src.ok) {
    if (med >= 5 && chk.items === 0) f.push("suddenly_empty");
    else if (med >= 3 && chk.items > med * 10) f.push("surge");
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
  const { SOURCES, COUNTRIES } = await import("./grid.mjs");
  const live = readJson(join(DATA, "grid", "live.json"), {}) || {}, prev = readJson(join(DATA, "grid", "audit.json"), {}) || {};
  const st = readStatus(), inc = readJson(join(DATA, "grid", "incidents.json"), { open: [] }) || { open: [] }, research = readJson(join(DATA, "grid", "research.json"), {}) || {};
  const items = Array.isArray(live.items) ? live.items : [], sources = {};
  const hourKey = new Date(now).toISOString().slice(0, 13);
  for (const k of Object.keys(SOURCES)) {
    const src = (live.sources || {})[k] || null, mine = items.filter((x) => x.source === k);
    const chk = checkItems(mine, SOURCES[k], COUNTRIES, now);
    let hist = ((prev.sources || {})[k] || {}).history || [];
    if (!hist.length || hist[hist.length - 1].h !== hourKey) hist = [...hist, { h: hourKey, n: src && src.ok ? mine.length : null }];
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
  if (pipeline.sizes_kb.series > 20 * 1024) pflags.push("series_large");
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
