// Swarm runs over a whole queue: scripts plan and verify, agents only judge. No AI model. Run: node scripts/swarm.mjs <command>
// Used for catch-ups that the scheduled jobs would take hours to clear (the research backlog, the exploit analyst's queue).
//   freeze <backlog|analyst|review> [--per N]   snapshot the queue into swarm/<run>/manifest.json, split it into frozen batches
//                                        (plan.json with a plan_id), write the worker plan file the job prompts read, lock the run
//   validate <run>                       which items are done (story closed or an event; analysis present and valid), by batch;
//                                        writes checkpoint.json; exit 1 while anything is missing
//   retry <run>                          rewrites the worker plan file with only the missing items, in their original batches
//   close <run>                          report.md with reconciled counts, removes RUNNING.lock
//   run <run>                            work the run with headless workers (scripts/run-job.mjs pool): lease every item so the
//                                        scheduled jobs skip it, run the missing batches, validate, retry once, commit, close
//   status                               open runs and their checkpoints
//   board                                the one status view: every queue, live leases, open runs, paused jobs, last job runs
// Never re-plan a locked run: freeze refuses while a run of the same kind holds RUNNING.lock.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, writeJson, listDir, nowIso } from "./lib/store.mjs";
import { build, isOpen } from "./fuse.mjs";
import { backlog } from "./backlog.mjs";
import { splitAnalyses } from "./analyst.mjs";

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
  if (kind === "review") {
    const q = JSON.parse(spawn("node", ["scripts/review.mjs", "queue", "--limit", "9999", "--json"]) || "[]");
    return q.map((x) => ({ id: x.id, title: x.title, severity: x.severity, hash: sha(JSON.stringify(x)).slice(0, 12) }));
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
  else if (kind === "review")
    writeJson(join(DATA, "review-plan.json"), { planned_at: nowIso(), swarm: run, plan_id: plan.plan_id, batches: plan.batches.map((b) => keep(b)) });
  else {
    // the manifest was frozen earlier: attach each file's problems as they are now, so a worker corrects an analysis on
    // file that breaks a rule instead of researching the flaw again
    const { bad } = splitAnalyses(listDir("analyses"));
    writeJson(join(DATA, "analyst-plan.json"), { planned_at: nowIso(), swarm: run, plan_id: plan.plan_id,
      batches: plan.batches.map((b) => keep(b).map((id) => { const { fix, ...x } = byId.get(id); return bad[id] ? { ...x, fix: bad[id].slice(0, 6) } : x; })) });
  }
}

/** Pure: which analyst items are done. rows: listDir("analyses"); logs: the last two days' -analyst- run logs.
 * Done = an analysis that passes checkAnalysis (the same split as analyst.mjs queue), or a CVE a worker logged as skipped.
 * An analysis on file that breaks a rule is NOT done: the build leaves it out of the workbench. It is returned in `bad`
 * so validate can say "on file, needs fixing" rather than "missing". */
export function analystDone(rows, logs = []) {
  const { done, bad } = splitAnalyses(rows), skipped = new Set();
  for (const l of logs) (l && Array.isArray(l.skipped) ? l.skipped : []).forEach((s) => { const c = String((s && (s.cve || s.title || s)) || "").match(/CVE-\d{4}-\d{4,}/); if (c) skipped.add(c[0]); });
  return { isDone: (id) => id in done || skipped.has(id), bad };
}
function analystLogs() {
  const runs = join(DATA, "runs"), out = [];
  if (existsSync(runs)) for (const day of readdirSync(runs).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort().slice(-2))
    for (const f of readdirSync(join(runs, day)).filter((f) => /-analyst-/.test(f) && f.endsWith(".json"))) out.push(readJson(join(runs, day, f), {}));
  return out;
}

function isDoneFn(kind) {
  if (kind === "backlog") {
    const d = build(), openUrls = new Set(d.stories.filter(isOpen).flatMap((s) => s.urls));
    return (items) => { const m = new Map(items.map((x) => [x.id, x])); return (id) => !(m.get(id).urls || []).some((u) => openUrls.has(u)); };
  }
  if (kind === "review") {
    const reviewed = new Set(listDir("events").filter((x) => x.r && x.r.review).map((x) => x.id));
    return () => (id) => reviewed.has(id);
  }
  const { isDone } = analystDone(listDir("analyses"), analystLogs());
  return () => isDone;
}

// kind -> lease kind, worker role, job name for the ledger, default batch size
const KINDS = { backlog: { lease: "story", role: "researcher", job: "backlog", per: 8 }, analyst: { lease: "cve", role: "exploit-analyst", job: "analyst", per: 3 }, review: { lease: "event", role: "reviewer", job: "review", per: 12 } };

function items(kind, man) {
  if (kind !== "backlog") return man.items;
  const d = build(), all = new Map(d.stories.map((s) => [s.id, s]));
  return man.items.map((x) => ({ ...x, urls: (all.get(x.id) || {}).urls || [] }));
}

/** Work a frozen run with headless workers; leases replace pausing the scheduled jobs. */
async function runSwarm(id) {
  const dir = runDir(id); if (!existsSync(join(dir, "RUNNING.lock"))) { console.error(`run "${id}" is not open`); process.exit(1); }
  const plan = readJson(join(dir, "plan.json")), man = readJson(join(dir, "manifest.json")), K = KINDS[plan.kind];
  process.env.CYBERVIEW_RUN = id;
  const { claim, release } = await import("./lib/lease.mjs");
  const { pool } = await import("./run-job.mjs");
  const all = plan.batches.flatMap((b) => b.ids);
  claim(K.lease, all, id, 240);
  spawnSync("git", ["add", "data/leases.json"], { cwd: ROOT }); spawnSync("git", ["commit", "-q", "-m", `data: leases for swarm ${id}`], { cwd: ROOT });
  spawnSync("node", ["scripts/git-sync.mjs"], { cwd: ROOT, encoding: "utf8", timeout: 180000 });
  const cp = (phase, extra = {}) => writeJson(join(dir, "checkpoint.json"), { phase, at: nowIso(), plan_id: plan.plan_id, ...extra });
  let spent = 0;
  for (let attempt = 0; attempt < 2; attempt++) {
    const r = reconcile(plan, isDoneFn(plan.kind)(items(plan.kind, man)));
    const todo = r.rows.filter((x) => x.missing.length).map((x) => x.batch);
    console.log(`${attempt ? "RETRY" : "WORK"} ${id}: ${r.done} of ${man.count} done; ${todo.length} batch(es) to run`);
    if (!todo.length) break;
    writeWorkerPlan(plan.kind, id, plan, items(plan.kind, man), new Set(r.rows.flatMap((x) => x.missing)));
    cp(attempt ? "retrying" : "working", { batches: todo });
    const res = await pool(K.job, todo.map((b) => [K.role, b]));
    spent += res.reduce((n, x) => n + ((x && x.cost) || 0), 0);
  }
  const r = reconcile(plan, isDoneFn(plan.kind)(items(plan.kind, man)));
  cp("collected", { done: r.done, missing: r.missing, cost: +spent.toFixed(2) });
  release(id);
  const f = spawnSync("node", ["scripts/finish.mjs", K.job], { cwd: ROOT, encoding: "utf8", timeout: 600000 });
  console.log(String(f.stdout || "").trim().split("\n").filter((l) => /^CyberView|FAILED/.test(l)).pop() || "finish: no output");
  console.log(`SWARM ${id}: ${r.done} of ${man.count} done, ${r.missing} left to the scheduled job; $${spent.toFixed(2)}. Close it with: node scripts/swarm.mjs close ${id}`);
}

/** The one status view. */
function board() {
  const line = (cmd, args) => (spawn(cmd, args) || "").trim().split("\n")[0] || "?";
  console.log(`CYBERVIEW BOARD ${nowIso()}`);
  console.log(`  research   ${line("node", ["scripts/backlog.mjs", "status"]).replace(/^BACKLOG: /, "")}`);
  console.log(`  review     ${line("node", ["scripts/review.mjs", "queue", "--limit", "1"])}`);
  console.log(`  analyst    ${line("node", ["scripts/analyst.mjs", "status"]).replace(/^ANALYST: /, "")}`);
  const leases = readJson(join(DATA, "leases.json"), {}), now = Date.now(), byRun = {};
  for (const [k, l] of Object.entries(leases)) if (Date.parse(l.until) > now) (byRun[l.run] ||= []).push(k.split(":")[0]);
  console.log(`  leases     ${Object.entries(byRun).map(([r, ks]) => `${r}: ${ks.length} ${ks[0]}(s)`).join("; ") || "none live"}`);
  const open = existsSync(SW) ? readdirSync(SW).filter((r) => existsSync(join(runDir(r), "RUNNING.lock"))) : [];
  console.log(`  swarm runs ${open.map((r) => { const c = readJson(join(runDir(r), "checkpoint.json"), {}); return `${r} (${c.phase || "?"}${c.done != null ? `, ${c.done} done, ${c.missing} missing` : ""})`; }).join("; ") || "none open"}`);
  const paused = readJson(join(SW, "paused.json"), {});
  console.log(`  paused     ${paused.restored_at || !(paused.triggers || []).length ? "none" : (paused.triggers || []).map((t) => t.name).join(", ")}`);
  const runs = join(DATA, "runs"), last = {};
  if (existsSync(runs)) for (const day of readdirSync(runs).sort().slice(-2)) {
    const f = join(runs, day, "jobruns.jsonl"); if (!existsSync(f)) continue;
    for (const l of readFileSync(f, "utf8").split("\n").filter(Boolean)) { try { const r = JSON.parse(l); last[r.job] = r; } catch {} }
  }
  console.log("  last headless runs:");
  for (const r of Object.values(last).sort((a, b) => String(b.finished_at).localeCompare(String(a.finished_at))))
    console.log(`    ${String(r.finished_at).slice(11, 16)} ${r.job.padEnd(12)} ${r.workers} worker(s) $${r.cost} ${r.minutes} min · ${((r.phases || []).find((p) => p.name === "commit") || {}).note || ""}`.slice(0, 160));
  const lanes = existsSync(join(SW, "LANES.md")) ? readFileSync(join(SW, "LANES.md"), "utf8").split("\n").filter((l) => /^\| [a-z]/.test(l) && !/^\| lane/.test(l)) : [];
  console.log("  lanes:"); lanes.forEach((l) => { const c = l.split("|").map((x) => x.trim()); console.log(`    ${c[1].padEnd(9)} ${c[4].padEnd(8)} ${c[2]}`); });
}

async function main() {
  const [cmd, a] = process.argv.slice(2);
  if (cmd === "freeze") {
    const kind = a; if (!KINDS[kind]) { console.error("usage: swarm.mjs freeze backlog|analyst|review [--per N]"); process.exit(1); }
    const live = existsSync(SW) ? readdirSync(SW).filter((r) => r.startsWith(kind + "-") && existsSync(join(runDir(r), "RUNNING.lock"))) : [];
    if (live.length) { console.error(`refusing: ${live[0]} is still running (RUNNING.lock). Validate and close it first.`); process.exit(1); }
    const items = queueOf(kind), per = opt("per", KINDS[kind].per), run = `${kind}-${nowIso().replace(/[-:]/g, "").slice(0, 13)}`, dir = runDir(run);
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
    const its = items(kind, man);
    const r = reconcile(plan, isDoneFn(kind)(its));
    writeJson(join(dir, "checkpoint.json"), { phase: cmd === "close" ? "closed" : "collected", at: nowIso(), plan_id: plan.plan_id, done: r.done, missing: r.missing, failed_batches: r.rows.filter((x) => x.missing.length).map((x) => x.batch) });
    if (cmd === "retry") {
      const miss = new Set(r.rows.flatMap((x) => x.missing));
      writeWorkerPlan(kind, a, plan, its, miss);
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
    if (kind === "analyst") { const { bad } = analystDone(listDir("analyses")), onFile = r.rows.flatMap((x) => x.missing).filter((id) => bad[id]);
      if (onFile.length) console.log(`  of the missing, ${onFile.length} have a file that breaks a rule (retry hands them out as FIX ONLY; see node scripts/analyst.mjs check): ${onFile.join(" ")}`); }
    process.exit(r.missing ? 1 : 0);
  }
  if (cmd === "run") return runSwarm(a);
  if (cmd === "board") return board();
  if (cmd === "status") {
    for (const r of existsSync(SW) ? readdirSync(SW).sort() : []) { const c = readJson(join(runDir(r), "checkpoint.json"), {}); console.log(`${r}: ${c.phase || "?"}${existsSync(join(runDir(r), "RUNNING.lock")) ? " (locked)" : ""} done ${c.done ?? "-"} missing ${c.missing ?? "-"}`); }
    return;
  }
  console.error("usage: swarm.mjs freeze <backlog|analyst|review> [--per N] | run <run> | validate <run> | retry <run> | close <run> | status | board"); process.exit(1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
