// Swarm runs over a whole queue: scripts plan and verify, agents only judge. No AI model. Run: node scripts/swarm.mjs <command>
// Used for catch-ups that the scheduled jobs would take hours to clear (the research backlog, the exploit analyst's queue).
//   freeze <backlog|analyst> [--per N]   snapshot the queue into swarm/<run>/manifest.json, split it into frozen batches
//                                        (plan.json with a plan_id), write the worker plan file the job prompts read, lock the run
//   validate <run>                       which items are done (story closed or an event; analysis present and valid), by batch;
//                                        writes checkpoint.json; exit 1 while anything is missing
//   retry <run>                          rewrites the worker plan file with only the missing items, in their original batches
//   close <run>                          report.md with reconciled counts, removes RUNNING.lock
//   status                               open runs and their checkpoints
// Never re-plan a locked run: freeze refuses while a run of the same kind holds RUNNING.lock.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, writeJson, listDir, nowIso } from "./lib/store.mjs";
import { build, isOpen } from "./fuse.mjs";
import { backlog } from "./backlog.mjs";
import { checkAnalysis } from "./lib/validate.mjs";

const SW = join(ROOT, "swarm");
const sha = (s) => createHash("sha1").update(s).digest("hex");
const opt = (n, d) => { const i = process.argv.indexOf("--" + n); return i > 0 ? Number(process.argv[i + 1]) || d : d; };
const runDir = (id) => join(SW, id);

/** Pure: items -> frozen batches and a plan_id that changes if any item moves. */
export function planBatches(items, per) {
  const batches = [];
  for (let i = 0; i < items.length; i += per) batches.push({ batch: batches.length + 1, ids: items.slice(i, i + per).map((x) => x.id) });
  const plan_id = sha(JSON.stringify(batches.map((b) => b.ids))).slice(0, 12);
  return { plan_id, batches };
}
/** Pure: which item ids are done, given a predicate; by batch. */
export function reconcile(plan, isDone) {
  const rows = plan.batches.map((b) => ({ batch: b.batch, done: b.ids.filter(isDone), missing: b.ids.filter((id) => !isDone(id)) }));
  return { rows, done: rows.reduce((n, r) => n + r.done.length, 0), missing: rows.reduce((n, r) => n + r.missing.length, 0) };
}

function queueOf(kind) {
  if (kind === "backlog") {
    const d = build();
    return backlog(d.stories).map((s) => ({ id: s.id, hash: sha(s.urls.slice().sort().join("\n")).slice(0, 12), title: s.title, score: s.score, urls: s.urls }));
  }
  if (kind === "analyst") {
    const q = JSON.parse(spawn("node", ["scripts/analyst.mjs", "queue", "--json"]) || "[]");
    return q.map((x) => ({ ...x, id: x.cve, hash: sha(JSON.stringify(x)).slice(0, 12) }));
  }
  throw new Error(`unknown kind "${kind}"`);
}
import { spawnSync } from "node:child_process";
function spawn(cmd, args) { const r = spawnSync(cmd, args, { cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }); return r.stdout; }

function writeWorkerPlan(kind, run, plan, items, onlyMissing) {
  const byId = new Map(items.map((x) => [x.id, x])), keep = (b) => (onlyMissing ? b.ids.filter((id) => onlyMissing.has(id)) : b.ids);
  if (kind === "backlog")
    writeJson(join(DATA, "sweep-plan.json"), { planned_at: nowIso(), backlog: true, swarm: run, plan_id: plan.plan_id,
      stories: plan.batches.flatMap((b) => keep(b).map((id) => ({ id, title: byId.get(id).title, score: byId.get(id).score, batch: b.batch, urls: byId.get(id).urls }))) });
  else
    writeJson(join(DATA, "analyst-plan.json"), { planned_at: nowIso(), swarm: run, plan_id: plan.plan_id,
      batches: plan.batches.map((b) => keep(b).map((id) => byId.get(id))) });
}

function isDoneFn(kind) {
  if (kind === "backlog") {
    const d = build(), openUrls = new Set(d.stories.filter(isOpen).flatMap((s) => s.urls));
    return (items) => { const m = new Map(items.map((x) => [x.id, x])); return (id) => !(m.get(id).urls || []).some((u) => openUrls.has(u)); };
  }
  const ok = new Set(listDir("analyses").filter((x) => x.r && !checkAnalysis(x.r, x.id).length).map((x) => x.id));
  const skipped = new Set();
  const runs = join(DATA, "runs");
  if (existsSync(runs)) for (const day of readdirSync(runs).sort().slice(-2)) for (const f of readdirSync(join(runs, day)).filter((f) => /-analyst-/.test(f)))
    (readJson(join(runs, day, f), {}).skipped || []).forEach((s) => { const c = String((s && (s.cve || s.title || s)) || "").match(/CVE-\d{4}-\d{4,}/); if (c) skipped.add(c[0]); });
  return () => (id) => ok.has(id) || skipped.has(id);
}

function main() {
  const [cmd, a] = process.argv.slice(2);
  if (cmd === "freeze") {
    const kind = a; if (!["backlog", "analyst"].includes(kind)) { console.error("usage: swarm.mjs freeze backlog|analyst [--per N]"); process.exit(1); }
    const live = existsSync(SW) ? readdirSync(SW).filter((r) => r.startsWith(kind + "-") && existsSync(join(runDir(r), "RUNNING.lock"))) : [];
    if (live.length) { console.error(`refusing: ${live[0]} is still running (RUNNING.lock). Validate and close it first.`); process.exit(1); }
    const items = queueOf(kind), per = opt("per", kind === "backlog" ? 8 : 3), run = `${kind}-${nowIso().replace(/[-:]/g, "").slice(0, 13)}`, dir = runDir(run);
    const plan = planBatches(items, per);
    mkdirSync(join(dir, "batches"), { recursive: true });
    writeJson(join(dir, "manifest.json"), { run, kind, frozen_at: nowIso(), count: items.length, items: items.map(({ urls, ...x }) => x) });
    writeJson(join(dir, "plan.json"), { run, kind, plan_id: plan.plan_id, per, batches: plan.batches });
    plan.batches.forEach((b) => writeJson(join(dir, "batches", `batch_${String(b.batch).padStart(2, "0")}.json`), { plan_id: plan.plan_id, ...b }));
    writeWorkerPlan(kind, run, plan, items);
    writeFileSync(join(dir, "RUNNING.lock"), nowIso() + "\n");
    writeJson(join(dir, "checkpoint.json"), { phase: "launched", at: nowIso(), plan_id: plan.plan_id });
    console.log(`SWARM ${run}: ${items.length} item(s) in ${plan.batches.length} batch(es) of up to ${per}; plan ${plan.plan_id}.`);
    console.log(`BATCHES: ${plan.batches.map((b) => b.batch).join(" ") || "none"}`);
    return;
  }
  if (cmd === "validate" || cmd === "retry" || cmd === "close") {
    const dir = runDir(a || ""); if (!a || !existsSync(join(dir, "plan.json"))) { console.error(`no run "${a}"`); process.exit(1); }
    const plan = readJson(join(dir, "plan.json")), man = readJson(join(dir, "manifest.json")), kind = plan.kind;
    const items = kind === "backlog" ? (() => { const d = build(), all = new Map(d.stories.map((s) => [s.id, s])); return man.items.map((x) => ({ ...x, urls: (all.get(x.id) || {}).urls || [] })); })() : man.items;
    const r = reconcile(plan, isDoneFn(kind)(items));
    writeJson(join(dir, "checkpoint.json"), { phase: cmd === "close" ? "closed" : "collected", at: nowIso(), plan_id: plan.plan_id, done: r.done, missing: r.missing, failed_batches: r.rows.filter((x) => x.missing.length).map((x) => x.batch) });
    if (cmd === "retry") {
      const miss = new Set(r.rows.flatMap((x) => x.missing));
      writeWorkerPlan(kind, a, plan, kind === "backlog" ? items.map((x) => ({ ...x, urls: x.urls.length ? x.urls : [] })) : items, miss);
      console.log(`RETRY ${a}: ${miss.size} item(s) in batch(es) ${r.rows.filter((x) => x.missing.length).map((x) => x.batch).join(" ") || "none"}`);
      console.log(`BATCHES: ${r.rows.filter((x) => x.missing.length).map((x) => x.batch).join(" ") || "none"}`);
      return;
    }
    if (cmd === "close") {
      const lines = [`# Swarm ${a}`, "", `Kind: ${kind}. Plan ${plan.plan_id}. Frozen ${man.frozen_at}, closed ${nowIso()}.`, "", `Items: ${man.count}. Done: ${r.done}. Not done: ${r.missing}.`, "",
        "| batch | done | not done |", "|---|---|---|", ...r.rows.map((x) => `| ${x.batch} | ${x.done.length} | ${x.missing.join(", ") || "-"} |`)];
      writeFileSync(join(dir, "report.md"), lines.join("\n") + "\n");
      rmSync(join(dir, "RUNNING.lock"), { force: true });
      console.log(`CLOSED ${a}: ${r.done} of ${man.count} done; ${r.missing} left to the scheduled jobs. Report: swarm/${a}/report.md`);
      return;
    }
    console.log(`VALIDATE ${a}: ${r.done} of ${man.count} done, ${r.missing} missing${r.missing ? " in batch(es) " + r.rows.filter((x) => x.missing.length).map((x) => x.batch).join(" ") : ""}.`);
    process.exit(r.missing ? 1 : 0);
  }
  if (cmd === "status") {
    for (const r of existsSync(SW) ? readdirSync(SW).sort() : []) { const c = readJson(join(runDir(r), "checkpoint.json"), {}); console.log(`${r}: ${c.phase || "?"}${existsSync(join(runDir(r), "RUNNING.lock")) ? " (locked)" : ""} done ${c.done ?? "-"} missing ${c.missing ?? "-"}`); }
    return;
  }
  console.error("usage: swarm.mjs freeze <backlog|analyst> [--per N] | validate <run> | retry <run> | close <run> | status"); process.exit(1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
