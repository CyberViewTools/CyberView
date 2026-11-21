// Sectors and attack surface for events on file that do not have them yet (a one-off backfill; researchers fill both on
// every new event). Scripts plan and check, workers only judge. Run: node scripts/classify.mjs <command>
//   plan [--per 40]          freeze the events lacking `sectors` or `surface` into batches with a plan_id
//                            (data/classify-plan.json); refuses to re-plan while out files of the current plan exist (--force)
//   show <batch>             the worker's assignment: the fixed lists and each event's own text (job-prompt.mjs classifier)
//   run [--batches 1,2]      start the classifier workers headless (scripts/run-job.mjs pool), batches without a valid out file
//   apply [--dry-run]        check every out file (plan_id, batch, each assigned id exactly once, values on the list, basis)
//                            and write the two fields into the event files; never overwrites a field already set
//   compare [--json]         how often the keyword assignment disagrees with the explicit fields, where both exist
//   status                   how many events are classified, and how
// The worker writes data/classify-out-<batch>.json: {plan_id, batch, items: [{id, sectors: {values, basis}, surface: {value, basis}, why}]}.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, readJson, writeJson, nowIso, listEventFiles } from "./lib/store.mjs";
import { SECTORS, SURFACES, sectorsOf, surfaceOf, keywordLayer, keywordGroup, placement } from "./lib/taxonomy.mjs";
import { checkClassification } from "./lib/validate.mjs";

const PLAN = "classify-plan.json";
const outName = (b) => `classify-out-${b}.json`;
const sha = (s) => createHash("sha1").update(s).digest("hex");
const arg = (n, d) => { const i = process.argv.indexOf("--" + n); return i > 0 ? process.argv[i + 1] : d; };
const has = (n) => process.argv.includes("--" + n);

/** Pure: does this event still need the backfill (either field missing)? Duplicates are left out. */
export const needs = (e) => !!e && !e.duplicate_of && (e.sectors == null || e.surface == null);

/** Pure: frozen batches of ids and a plan_id that changes if any id moves. Newest first, so the map's window is done first. */
export function planOf(events, per = 40, now = nowIso()) {
  per = Math.max(1, Math.min(80, Math.round(Number(per) || 40)));
  const ids = [...new Set(events.filter(needs).sort((a, b) => String(b.date).localeCompare(String(a.date)) || String(a.id).localeCompare(String(b.id))).map((e) => e.id))];
  const batches = [];
  for (let i = 0; i < ids.length; i += per) batches.push({ batch: batches.length + 1, out: outName(batches.length + 1), ids: ids.slice(i, i + per) });
  return { plan_id: sha(JSON.stringify(batches.map((b) => b.ids))).slice(0, 12), created_at: now, per, events: ids.length, batches };
}

/** Pure: the problems in one worker's out file against its batch; [] when it can be applied. `known` (a Set of ids on
 *  file) excuses an assigned event that has left the files since the plan. */
export function checkOut(plan, b, out, known = null) {
  const p = [];
  if (!out || typeof out !== "object" || Array.isArray(out)) return ["out file missing or not a JSON object"];
  if (out.plan_id !== plan.plan_id) p.push(`plan_id ${JSON.stringify(out.plan_id)} is not the current plan ${plan.plan_id}`);
  if (Number(out.batch) !== b.batch) p.push(`batch ${JSON.stringify(out.batch)} is not ${b.batch}`);
  if (!Array.isArray(out.items)) return p.concat(["items must be a list"]);
  const want = new Set(b.ids), seen = new Map();
  out.items.forEach((x, i) => {
    const id = x && typeof x.id === "string" ? x.id : "";
    if (!id) { p.push(`items[${i}]: no id`); return; }
    seen.set(id, (seen.get(id) || 0) + 1);
    if (!want.has(id)) { p.push(`items[${i}]: ${id} is not in batch ${b.batch}`); return; }
    if (x.sectors == null || x.surface == null) p.push(`${id}: both sectors and surface are required`);
    for (const c of checkClassification({ sectors: x.sectors, surface: x.surface })) p.push(`${id}: ${c.code}: ${c.text}`);
    if (x.why != null && (typeof x.why !== "string" || x.why.length > 200)) p.push(`${id}: why must be text of at most 200 characters`);
  });
  for (const [id, n] of seen) if (n > 1 && want.has(id)) p.push(`${id}: listed ${n} times`);
  for (const id of b.ids) if (!seen.has(id) && (!known || known.has(id))) p.push(`${id}: missing`);
  return p;
}

/** Pure: the event with the classification added; fields already set are kept. Key order follows the file's own. */
export function merge(raw, item) {
  const add = {};
  if (raw.sectors == null) add.sectors = { values: item.sectors.values.slice(), basis: item.sectors.basis };
  if (raw.surface == null) add.surface = { value: item.surface.value, basis: item.surface.basis };
  if (!Object.keys(add).length) return null;
  const keys = Object.keys(raw), sorted = keys.every((k, i) => i === 0 || keys[i - 1] <= k), next = { ...raw, ...add };
  return sorted ? Object.fromEntries(Object.keys(next).sort().map((k) => [k, next[k]])) : next;
}

/** Pure: keyword assignment against the explicit fields, where both exist. Lanes only for event kinds that have one. */
export function compare(events) {
  const r = { lane: { n: 0, differ: 0, keyword_none: 0, pairs: {} }, group: { n: 0, differ: 0, keyword_none: 0, pairs: {} } };
  for (const e of events) {
    if (!e || e.duplicate_of) continue;
    const pl = placement(e);
    for (const [k, got, kw] of [["lane", pl.lane, keywordLayer(e)], ["group", pl.group, keywordGroup(e)]]) {
      if (got.basis === "keyword") continue;
      const x = r[k]; x.n++;
      if (got.k !== kw) { x.differ++; if (kw === "org" || kw === "other") x.keyword_none++; const pk = `${kw} -> ${got.k}`; x.pairs[pk] = (x.pairs[pk] || 0) + 1; }
    }
  }
  for (const x of [r.lane, r.group]) { x.rate = x.n ? +(x.differ / x.n).toFixed(3) : null; x.pairs = Object.fromEntries(Object.entries(x.pairs).sort((a, b) => b[1] - a[1]).slice(0, 12)); }
  return r;
}

const clip = (v, n) => String(v == null ? "" : v).replace(/\s+/g, " ").trim().slice(0, n);
/** The worker's assignment text for one batch. */
export function assignmentText(batch, plan = readJson(join(DATA, PLAN), null), events = null) {
  const b = plan && (plan.batches || []).find((x) => String(x.batch) === String(batch));
  if (!b) return `YOUR ASSIGNMENT (classifier ${batch}): no such batch in data/${PLAN}. End with "classifier ${batch}: nothing assigned".`;
  const byId = new Map((events || listEventFiles().filter((f) => f.e).map((f) => f.e)).map((e) => [e.id, e]));
  const rows = b.ids.map((id) => {
    const e = byId.get(id); if (!e) return `- ${id}: (no longer on file: leave it out of items)`;
    return [`- id: ${id}`, `  category: ${e.category}; org: ${clip(e.org, 120) || "(none)"}; sector field: ${clip(e.sector, 80) || "(none)"}; country: ${clip(e.country, 60) || "(none)"}`,
      `  title: ${clip(e.title, 200)}`, `  products: ${clip((e.products || []).join(", "), 200) || "(none)"}; tags: ${(e.tags || []).join(", ") || "(none)"}; techniques: ${clip((e.attack || []).join("; "), 200) || "(none)"}`,
      `  summary: ${clip(e.summary, 700)}`, e.impact ? `  impact: ${clip(e.impact, 400)}` : ""].filter(Boolean).join("\n");
  });
  return `YOUR ASSIGNMENT (classifier ${b.batch}): plan_id ${plan.plan_id}, batch ${b.batch}, ${b.ids.length} events. Out file: data/${b.out}\n`
    + `SECTORS (key: meaning):\n${SECTORS.map((s) => `  ${s.k}: ${s.label}${s.ci ? " [CISA critical infrastructure]" : ""}`).join("\n")}\n`
    + `SURFACES (key: meaning):\n${SURFACES.map((s) => `  ${s.k}: ${s.label}`).join("\n")}\n`
    + `EVENTS:\n${rows.join("\n")}\n`;
}

function load() {
  const plan = readJson(join(DATA, PLAN), null);
  if (!plan || !Array.isArray(plan.batches)) { console.error(`no plan: run \`node scripts/classify.mjs plan\` first`); process.exit(1); }
  return plan;
}

async function main() {
  const cmd = process.argv[2];
  const files = () => listEventFiles().filter((f) => f.e);
  if (cmd === "plan") {
    const old = readJson(join(DATA, PLAN), null);
    if (old && (old.batches || []).some((b) => existsSync(join(DATA, b.out))) && !has("force")) { console.error(`plan ${old.plan_id} has out files waiting: apply them first, or re-plan with --force`); process.exit(1); }
    const plan = planOf(files().map((f) => f.e), arg("per", 40));
    writeJson(join(DATA, PLAN), plan);
    console.log(`classify plan ${plan.plan_id}: ${plan.events} events lack sectors or surface, ${plan.batches.length} batch(es) of up to ${plan.per}`);
    console.log(`BATCHES: ${plan.batches.map((b) => b.batch).join(" ")}`);
  } else if (cmd === "show") {
    process.stdout.write(assignmentText(process.argv[3]));
  } else if (cmd === "run") {
    const plan = load(), only = String(arg("batches", "")).split(",").filter(Boolean).map(Number);
    const known = new Set(files().map((f) => f.id)), bad = (b) => checkOut(plan, b, readJson(join(DATA, b.out), null), known).length > 0;
    const todo = plan.batches.filter((b) => (!only.length || only.includes(b.batch)) && bad(b));
    if (!todo.length) { console.log("every batch has a valid out file: run apply"); return; }
    console.log(`classify run: ${todo.length} classifier worker(s) for plan ${plan.plan_id}`);
    const { pool } = await import("./run-job.mjs");
    await pool("classify", todo.map((b) => ["classifier", b.batch]));
    const left = todo.filter(bad).map((b) => b.batch);
    console.log(left.length ? `still missing or invalid: batch(es) ${left.join(",")}; rerun with --batches ${left.join(",")}` : "every batch has a valid out file: run apply --dry-run, then apply");
  } else if (cmd === "apply") {
    const plan = load(), dry = has("dry-run"), byId = new Map(files().map((f) => [f.id, f]));
    let changed = 0, kept = 0, gone = 0, badBatches = 0;
    for (const b of plan.batches) {
      const out = readJson(join(DATA, b.out), null), p = checkOut(plan, b, out, new Set(byId.keys()));
      if (p.length) { badBatches++; console.log(`batch ${b.batch}: NOT APPLIED, ${p.length} problem(s):\n  ${p.slice(0, 12).join("\n  ")}${p.length > 12 ? `\n  ... ${p.length - 12} more` : ""}`); continue; }
      let n = 0;
      for (const x of out.items) {
        const f = byId.get(x.id); if (!f) { gone++; continue; }
        const raw = JSON.parse(readFileSync(f.path, "utf8")), next = merge(raw, x);
        if (!next) { kept++; continue; }
        if (!dry) writeFileSync(f.path, JSON.stringify(next, null, 2) + "\n");
        n++; changed++;
      }
      console.log(`batch ${b.batch}: ${dry ? "would write" : "wrote"} ${n} event(s)`);
    }
    console.log(`classify apply${dry ? " (dry run)" : ""}: ${changed} event(s) ${dry ? "to classify" : "classified"}, ${kept} already had both fields, ${gone} no longer on file, ${badBatches} batch(es) not applied`);
    if (!dry && changed) console.log("next: node scripts/build.mjs, then node scripts/classify.mjs compare");
    if (badBatches) process.exit(1);
  } else if (cmd === "compare") {
    const r = compare(files().map((f) => f.e));
    if (has("json")) { console.log(JSON.stringify(r, null, 2)); return; }
    for (const [k, name] of [["lane", "attack surface lane"], ["group", "sector group"]]) {
      const x = r[k];
      console.log(`${name}: keyword disagrees with the explicit field on ${x.differ} of ${x.n} events${x.rate != null ? ` (${Math.round(100 * x.rate)}%)` : ""}; ${x.keyword_none} of those the keywords left unplaced`);
      for (const [pk, n] of Object.entries(x.pairs)) console.log(`  ${pk}: ${n}`);
    }
  } else if (cmd === "status") {
    const ev = files().map((f) => f.e).filter((e) => !e.duplicate_of), c = { sectors: { stated: 0, inferred: 0 }, surface: { stated: 0, inferred: 0 } };
    ev.forEach((e) => { const s = sectorsOf(e), u = surfaceOf(e); if (s) c.sectors[s.basis]++; if (u) c.surface[u.basis]++; });
    console.log(`${ev.length} events: sectors ${c.sectors.stated} stated, ${c.sectors.inferred} inferred; surface ${c.surface.stated} stated, ${c.surface.inferred} inferred; ${ev.filter(needs).length} still lack one or both`);
  } else {
    console.error("usage: node scripts/classify.mjs plan [--per 40] | show <batch> | run [--batches 1,2] | apply [--dry-run] | compare [--json] | status");
    process.exit(1);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
