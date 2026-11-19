// The grid desk: which big grid outages need a cause, who checks them, and what they found. No AI model in this script.
// scripts/grid.mjs (collect) tracks outages from the operators' own feeds and marks the big or odd ones research_needed.
// This plans those incidents for grid workers (role "grid", the "Grid researcher" brief in docs/jobs.md), validates what
// they write, and keeps the result in data/grid/research.json (written only here). An outage is never called an attack
// here: a cyber cause found by a worker becomes ONE lead in data/leads/<day>.jsonl, and the normal research loop (with its
// second review) decides whether it is an event. Contract: swarm/handoff/grid-contract.md.
//   plan [--max N] [--per K] [--file F]   batches for N workers, K incidents each; leases kind "grid"; writes data/<F>
//   apply <out file> [--plan F]           validate a worker's out file and record it (idempotent)
//   list [--json]                         incidents waiting for a cause, and what is on file
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join, isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, writeJson, nowIso, dayAgo, readStatus } from "./lib/store.mjs";
import { claim, readLeases, RUN_ID } from "./lib/lease.mjs";

export const BY = "CyberView AI (a Claude model)";
export const DECISIONS = ["weather", "equipment", "planned", "supply_shortfall", "wildfire_safety", "third_party", "cyber_official", "cyber_reported", "under_investigation", "unknown"];
export const NOT_FINAL = new Set(["under_investigation", "unknown"]);
export const DEPTHS = ["full", "summary", "secondary"];
// hosts whose word counts as official for a cyber cause: operators, market operators, regulators, governments
export const OFFICIAL_HOST = /\.gov(\.[a-z]{2})?$|\.gc\.ca$|\.gov\.uk$|\.gouv\.[a-z]{2}$|\.gob\.[a-z]{2}$|\.gov\.[a-z]{2}$|(^|\.)(ofgem|ercot|aemo|eskom|hydroquebec|bchydro|ukpowernetworks|nerc|energy|cisa|ncsc|nersa|entsoe)\.(com|org|net|gov|ca|co\.uk|org\.uk|com\.au|co\.za|org\.za|eu)$/;
const REDIRECT = /(^|\.)news\.google\.com$|(^|\.)bing\.com$|(^|\.)msn\.com$/;
const DEFAULTS = { retry_hours: 6, max_tries: 3 };
const PLAN_FILE = /^grid-plan(-[A-Za-z0-9-]+)?\.json$/;
const ID = /^grid-[a-z0-9-]{3,140}$/;

export const cfgOf = (c) => ({ ...DEFAULTS, ...(c || {}) });
const size = (i) => Number(i.peak_customers ?? i.customers) || 0;
const live = (l, now) => l && Date.parse(l.until) > now;

/** Pure: incidents ({open, closed} or an array) -> those a grid worker should look at now, biggest first.
 *  research_needed, no final result, retry due (next_at passed), tries below max_tries, no live lease of another run. */
export function candidates(incidents, research = {}, leases = {}, now = Date.now(), cfg = {}) {
  const c = cfgOf(cfg), all = Array.isArray(incidents) ? incidents : [...((incidents && incidents.open) || []), ...((incidents && incidents.closed) || [])];
  const seen = new Set(), out = [];
  for (const i of all) {
    if (!i || !ID.test(String(i.id || "")) || i.research_needed !== true || seen.has(i.id)) continue;
    seen.add(i.id);
    const r = research[i.id];
    if (r && (r.final || (Number(r.tries) || 0) >= c.max_tries)) continue;
    if (r && r.next_at && Date.parse(r.next_at) > now) continue;
    const l = leases[`grid:${i.id}`]; if (live(l, now) && l.run !== c.run) continue;
    out.push(i);
  }
  return out.sort((a, b) => size(b) - size(a) || (Number(b.level) || 0) - (Number(a.level) || 0) || String(a.opened_at).localeCompare(String(b.opened_at)) || a.id.localeCompare(b.id));
}

/** Pure: the facts a worker needs about one incident (and what an earlier try found). */
export function brief(i, r) {
  const s = (v, n) => String(v ?? "").slice(0, n);
  return { id: i.id, source: s(i.source, 40), country: s(i.country, 2), region: s(i.region, 80), kind: s(i.kind, 20), name: s(i.name, 120),
    opened_at: s(i.opened_at, 20), closed_at: s(i.closed_at, 20), customers: i.customers ?? null, peak_customers: i.peak_customers ?? null, peak_at: s(i.peak_at, 20),
    level: i.level ?? null, planned_share: i.planned_share ?? null, causes: (i.causes || []).slice(0, 3).map((x) => ({ cause: s(x && x.cause, 120), customers: (x && x.customers) ?? null })),
    url: /^https:\/\//.test(i.url || "") ? s(i.url, 300) : "", research_reason: s(i.research_reason, 40),
    earlier: r ? { decision: r.decision, cause_summary: s(r.cause_summary, 300), sources: (r.sources || []).slice(0, 6), tries: r.tries || 0 } : null };
}

/** Pure: a stable id for a plan, from its id -> batch map (same assignment, same id). */
export function planId(batches) {
  const map = []; batches.forEach((b, k) => (b.incidents || b).forEach((x) => map.push([x.id || x, k + 1])));
  map.sort((a, b) => a[0].localeCompare(b[0]));
  return "gp-" + createHash("sha256").update(JSON.stringify(map)).digest("hex").slice(0, 16);
}

/** Pure: candidates -> { plan_id, batches: [{ batch, out, incidents }] } for at most max workers, per each. */
export function makePlan(cands, research = {}, max = 1, per = 4, tag = "") {
  const q = cands.slice(0, max * per), k = Math.min(max, Math.ceil(q.length / per)), lists = Array.from({ length: k }, () => []);
  q.forEach((c, i) => lists[i % k].push(brief(c, research[c.id])));
  const plan_id = planId(lists), t = String(tag).replace(/[^A-Za-z0-9-]/g, "-").slice(0, 80);
  return { plan_id, batches: lists.map((incidents, j) => ({ batch: j + 1, out: `grid-out${t ? "-" + t : ""}-${j + 1}.json`, incidents })) };
}

/** Pure: is this a page a worker may cite? "" when it is, else the reason. */
export function badSource(u) {
  let x; try { x = new URL(String(u)); } catch { return "not a URL"; }
  if (x.protocol !== "https:") return "not https";
  if (REDIRECT.test(x.hostname)) return "a search-engine redirect; cite the publisher's own page";
  if (!x.pathname || x.pathname === "/") return "a bare front page";
  return "";
}
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } };
/** Pure: does this url sit on an operator, regulator or government host (or the incident's own operator host)? */
export function officialHost(u, incidentUrl = "") {
  const h = hostOf(u), own = hostOf(incidentUrl).replace(/^www\./, "");
  return !!h && (OFFICIAL_HOST.test(h) || (!!own && (h === own || h.endsWith("." + own))));
}

/** Pure: check a worker's out file against its plan.
 *  -> { ok, errors: [file-level problems: nothing is applied], bad: { id: [reasons] } (those are not applied), good: [results] } */
export function validate(plan, out) {
  const errors = [], bad = {}, good = [];
  if (!plan || !plan.plan_id) return { ok: false, errors: ["no plan"], bad, good };
  if (!out || typeof out !== "object") return { ok: false, errors: ["out file is not a JSON object"], bad, good };
  if (out.plan_id !== plan.plan_id) errors.push(`plan_id ${JSON.stringify(out.plan_id ?? null)} does not match the plan (${plan.plan_id})`);
  const batches = plan.batches || [], mine = out.batch != null ? batches.filter((b) => String(b.batch) === String(out.batch)) : batches;
  if (out.batch != null && !mine.length) errors.push(`batch ${out.batch} is not in the plan`);
  const planned = new Map(); mine.forEach((b) => (b.incidents || []).forEach((i) => planned.set(i.id, i)));
  if (!Array.isArray(out.results)) errors.push("results is not an array");
  const count = new Map();
  for (const r of Array.isArray(out.results) ? out.results : []) {
    const id = r && r.id; count.set(id, (count.get(id) || 0) + 1);
    if (!planned.has(id)) errors.push(`${JSON.stringify(id ?? null)} was not planned`);
  }
  for (const [id, n] of count) if (n > 1) errors.push(`${id} appears ${n} times`);
  if (errors.length) return { ok: false, errors, bad, good };
  for (const id of planned.keys()) if (!count.has(id)) bad[id] = ["no result for this planned incident"];
  for (const r of out.results) {
    const why = [], inc = planned.get(r.id), sources = r.sources;
    if (!DECISIONS.includes(r.decision)) why.push(`decision ${JSON.stringify(r.decision ?? null)} is not one of ${DECISIONS.join(", ")}`);
    if (typeof r.cause_summary !== "string" || !r.cause_summary.trim()) why.push("cause_summary is empty");
    else if (r.cause_summary.length > 300) why.push(`cause_summary is ${r.cause_summary.length} characters (at most 300)`);
    if (!Array.isArray(sources)) why.push("sources is not an array");
    else {
      if (!sources.length && r.decision !== "unknown") why.push("no sources (only an unknown cause may have none)");
      if (sources.length > 8) why.push("more than 8 sources");
      sources.forEach((u) => { const b = badSource(u); if (b) why.push(`source ${String(u).slice(0, 120)}: ${b}`); });
      if (r.decision === "cyber_official" && !sources.some((u) => officialHost(u, inc && inc.url))) why.push("cyber_official needs at least one source on an operator, regulator or government site");
    }
    if (!DEPTHS.includes(r.read_depth)) why.push(`read_depth ${JSON.stringify(r.read_depth ?? null)} is not one of ${DEPTHS.join(", ")}`);
    if (why.length) bad[r.id] = why; else good.push(r);
  }
  return { ok: !Object.keys(bad).length, errors, bad, good };
}

/** Pure: one research.json entry from a valid result. Idempotent: the same plan_id for the same incident changes nothing (returns null). */
export function entryFor(r, prev, plan_id, now = Date.now(), cfg = {}) {
  const c = cfgOf(cfg);
  if (prev && prev.plan_id === plan_id) return null;
  const tries = (Number(prev && prev.tries) || 0) + 1, final = !NOT_FINAL.has(r.decision) || tries >= c.max_tries;
  const at = new Date(now).toISOString().replace(/\.\d+Z$/, "Z");
  return { decision: r.decision, cause_summary: r.cause_summary.trim().slice(0, 300), sources: r.sources.slice(0, 8), read_depth: r.read_depth, checked_at: at, tries, by: BY, final,
    next_at: final ? "" : new Date(now + c.retry_hours * 36e5).toISOString().replace(/\.\d+Z$/, "Z"), plan_id };
}

/** Pure: the lead a cyber cause becomes (the normal research loop turns it into an event, or not). */
export function leadFor(inc, e) {
  const official = e.decision === "cyber_official", url = e.sources[0];
  return { seen_at: e.checked_at, source: hostOf(url).replace(/^www\./, ""), tier: official ? "gov" : "news", via: "grid-desk", kind: "grid",
    title: `Grid outage linked to a cyberattack (${official ? "official" : "reported, unconfirmed"}): ${String(inc.name || inc.id).slice(0, 120)}`,
    url, published: e.checked_at, summary: e.cause_summary.slice(0, 300), lang: "en", grid_id: inc.id };
}

/** Pure: apply valid results to research.json. -> { research, changed: [ids], leads: [lead] } (leads only for incidents with none yet). */
export function applyResults(research, plan, good, leadIds = new Set(), now = Date.now(), cfg = {}) {
  const next = { ...research }, changed = [], leads = [], inc = new Map();
  (plan.batches || []).forEach((b) => (b.incidents || []).forEach((i) => inc.set(i.id, i)));
  for (const r of good) {
    const e = entryFor(r, research[r.id], plan.plan_id, now, cfg); if (!e) continue;
    next[r.id] = e; changed.push(r.id);
    if ((e.decision === "cyber_official" || e.decision === "cyber_reported") && e.sources.length && !leadIds.has(r.id)) { leads.push(leadFor(inc.get(r.id) || { id: r.id }, e)); leadIds.add(r.id); }
  }
  return { research: next, changed, leads };
}

// ---------- files ----------
const GRID = join(DATA, "grid"), RESEARCH = join(GRID, "research.json");
const readCfg = () => cfgOf(readJson(join(ROOT, "config", "grid.json"), {}));
/** Incident ids that already have a grid-desk lead (last 40 days). */
function leadIdsOnFile() {
  const s = new Set(), dir = join(DATA, "leads"), since = dayAgo(40);
  if (existsSync(dir)) for (const f of readdirSync(dir).filter((f) => f.endsWith(".jsonl") && f.slice(0, 10) >= since)) {
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) { if (!line.includes('"grid-desk"')) continue; try { const l = JSON.parse(line); if (l.via === "grid-desk" && l.grid_id) s.add(l.grid_id); } catch {} }
  }
  return s;
}
function releaseGrid(ids, run) {
  const p = join(DATA, "leases.json"), l = readLeases(), out = {}; let n = 0;
  for (const [k, v] of Object.entries(l)) { if (k.startsWith("grid:") && ids.includes(k.slice(5)) && (!run || (v && v.run === run))) { n++; continue; } out[k] = v; }
  if (n) writeJson(p, out);   // nothing to release: the file is not touched (applying twice changes nothing)
}
const findPlan = (plan_id) => {
  if (!existsSync(DATA)) return null;
  for (const f of readdirSync(DATA).filter((f) => PLAN_FILE.test(f))) { const p = readJson(join(DATA, f), null); if (p && p.plan_id === plan_id) return p; }
  return null;
};

function main() {
  const [cmd, ...rest] = process.argv.slice(2), arg = (k, d) => { const i = rest.indexOf("--" + k); return i >= 0 ? rest[i + 1] : d; };
  const cfg = readCfg(), incidents = readJson(join(GRID, "incidents.json"), { open: [], closed: [] }), research = readJson(RESEARCH, {});
  if (cmd === "plan") {
    const N = Math.max(1, Math.min(4, Number(arg("max", 1)) || 1)), K = Math.max(1, Math.min(8, Number(arg("per", 4)) || 4));
    const file = PLAN_FILE.test(arg("file", "")) ? arg("file") : "grid-plan.json", run = RUN_ID();
    const all = candidates(incidents, research, readLeases(), Date.now(), { ...cfg, run }), p = makePlan(all, research, N, K, file.replace(/^grid-plan-?|\.json$/g, ""));
    const ids = p.batches.flatMap((b) => b.incidents.map((i) => i.id));
    if (ids.length) claim("grid", ids, run, 45);
    writeJson(join(DATA, file), { plan_id: p.plan_id, planned_at: nowIso(), run, batches: p.batches });
    console.log(`GRID PLAN: ${ids.length} incident(s) for ${p.batches.length} grid worker(s); ${all.length} waiting for a cause.`);
    return;
  }
  if (cmd === "apply") {
    const f = rest.find((x) => !x.startsWith("--") && x !== arg("plan")); if (!f) { console.error("usage: grid-desk.mjs apply <out file> [--plan F]"); process.exit(1); }
    const path = [isAbsolute(f) ? f : resolve(f), join(DATA, f)].find((p) => existsSync(p));
    const out = path ? readJson(path, null) : null;
    const pf = arg("plan"), plan = pf && PLAN_FILE.test(pf) ? readJson(join(DATA, pf), null) : out && out.plan_id ? findPlan(out.plan_id) : null;
    const v = validate(plan, out);
    if (v.errors.length) { console.error(`GRID APPLY REFUSED (${f}): ${v.errors.slice(0, 6).join("; ")}`); process.exit(1); }
    const started = nowIso(), r = applyResults(research, plan, v.good, leadIdsOnFile(), Date.now(), cfg);
    if (r.changed.length) writeJson(RESEARCH, r.research);
    if (r.leads.length) { const lf = join(DATA, "leads", `${started.slice(0, 10)}.jsonl`); mkdirSync(join(DATA, "leads"), { recursive: true }); appendFileSync(lf, r.leads.map((l) => JSON.stringify(l)).join("\n") + "\n"); }
    const done = v.good.map((x) => x.id); releaseGrid([...done, ...Object.keys(v.bad)], plan.run || process.env.CYBERVIEW_RUN || "");
    if (r.changed.length) {
      const st = readStatus(); st.last_grid_research_at = started; writeJson(join(DATA, "status.json"), st);
      const dir = join(DATA, "runs", started.slice(0, 10)); mkdirSync(dir, { recursive: true });
      writeJson(join(dir, `${started.slice(11, 13)}${started.slice(14, 16)}-grid-desk-${String(out.batch ?? "x").replace(/[^A-Za-z0-9]/g, "")}.json`), {
        job: "grid-desk", started_at: started, finished_at: nowIso(), model: "none (script)", plan_id: plan.plan_id, batch: out.batch ?? null,
        updated: r.changed, decisions: Object.fromEntries(r.changed.map((id) => [id, r.research[id].decision])),
        pages_read: r.changed.flatMap((id) => r.research[id].sources.map((url) => ({ url, title: "", used_in: id }))),
        added: [], skipped: Object.entries(v.bad).map(([id, why]) => ({ title: id, url: "", reason: "rejected by grid-desk validate: " + why.join("; ").slice(0, 300) })),
        open_leads: r.leads.map((l) => ({ title: l.title, url: l.url, note: "filed as a lead for the research loop", priority: l.tier === "gov" ? "high" : "normal" })), failed_sites: [],
        notes: `${r.changed.length} recorded, ${Object.keys(v.bad).length} rejected, ${r.leads.length} lead(s)` });
    }
    const badN = Object.keys(v.bad).length;
    console.log(`GRID APPLY: ${r.changed.length} recorded, ${v.good.length - r.changed.length} already on file, ${badN} rejected, ${r.leads.length} cyber lead(s).`);
    for (const [id, why] of Object.entries(v.bad)) console.log(`  rejected ${id}: ${why.join("; ").slice(0, 300)}`);
    if (badN) process.exitCode = 1;
    return;
  }
  if (cmd === "list") {
    const c = candidates(incidents, research, readLeases(), Date.now(), cfg);
    if (rest.includes("--json")) { console.log(JSON.stringify({ waiting: c.map((i) => brief(i, research[i.id])), research })); return; }
    console.log(`${c.length} grid incident(s) waiting for a cause:`);
    c.slice(0, 30).forEach((i) => console.log(`  ${i.id}  ${String(i.name || "").slice(0, 100)}  [${i.research_reason || "?"}${research[i.id] ? `, try ${research[i.id].tries + 1}` : ""}]`));
    const done = Object.entries(research).sort((a, b) => String(b[1].checked_at).localeCompare(String(a[1].checked_at))).slice(0, 15);
    if (done.length) { console.log("Recently checked:"); done.forEach(([id, r]) => console.log(`  ${id}  ${r.decision}${r.final ? "" : " (retry " + r.next_at + ")"}: ${String(r.cause_summary).slice(0, 110)}`)); }
    return;
  }
  console.error("usage: grid-desk.mjs plan [--max N] [--per K] [--file F] | apply <out file> [--plan F] | list [--json]"); process.exit(1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
