// The dispatcher's script. Run: node scripts/dispatch.mjs <job>
// Every scheduled task sends one short message to the ops session: "run dispatch.mjs <job> and do what it says".
// This prints exactly what to do. The ops session never does research itself and never reads the long job instructions:
// it starts fresh subagents (each reads its own instructions with job-prompt.mjs), so its own history stays small and
// every job gets an agent with a clean head. For the sweep and the review desk the work is planned here, by rule,
// split between workers, and counted afterwards.
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { ROOT, DATA, readJson } from "./lib/store.mjs";

const job = process.argv[2];
// --exec (owner, 2026-11-23: one fresh session per scheduled wake, as few tokens as possible): run a headless job right
// here and print only its last lines, instead of printing instructions for a session to read and then carry out. A
// dispatcher session makes ONE shell call per wake. Anything that still needs a session's judgment (subagent fallback,
// non-headless jobs) prints its DISPATCH instructions as before.
const EXEC = process.argv.includes("--exec");
/** Run one headless command in the foreground and print its last lines; on HEADLESS UNAVAILABLE fall back to printing
 *  the subagent instructions (CYBERVIEW_SUBAGENTS=1), which the session then carries out. */
function execHeadless(env, args, ms, endLine) {
  const x = spawnSync("node", args, { cwd: ROOT, encoding: "utf8", timeout: ms, env: { ...process.env, ...env } });
  const lines = `${x.stdout || ""}${x.stderr || ""}`.split("\n").filter((l) => l.trim());
  if (lines.some((l) => /HEADLESS UNAVAILABLE/.test(l))) {
    const f = spawnSync("node", [join(ROOT, "scripts", "dispatch.mjs"), job], { cwd: ROOT, encoding: "utf8", env: { ...process.env, CYBERVIEW_SUBAGENTS: "1" } });
    console.log(String(f.stdout || "").trim()); process.exit(0);
  }
  const tail = lines.slice(-3);
  if (x.error || x.signal) tail.push(`CyberView ${job}: run stopped (${x.signal || x.error.code || "error"}); the next wake commits the leftover (finish.mjs --force)`);
  else if (!tail.some((l) => l.startsWith(endLine))) tail.push(`${endLine} ended (exit ${x.status})`);
  console.log(tail.join("\n")); process.exit(0);
}
// code and data on separate branches: switch this checkout to the new layout the first time a job runs after the data
// branch exists (scripts/data-branch.mjs ensure: carries uncommitted data over, waits while a research loop runs here),
// then bring the data branch up to date. Never stops the job: the old layout still works.
{
  const e = spawnSync("node", [join(ROOT, "scripts", "data-branch.mjs"), "ensure"], { cwd: ROOT, encoding: "utf8", timeout: 300000 });
  if (/switched/.test(e.stdout || "")) console.error((e.stdout || "").trim());
  const { pullAll } = await import("./lib/repo.mjs"); pullAll();
}
const reg = readJson(join(ROOT, "routines.json"), { routines: [] }), r = reg.routines.find((x) => x.key === job);
if (!r || r.tier !== "ai") { console.error(`unknown AI job "${job}"`); process.exit(1); }
if (r.active === false) { console.log(`CyberView ${job}: retired, duties moved to ${r.merged_into || "another job"}; start no workers (disable this scheduled task)`); process.exit(0); }
const model = /opus/.test(r.model || "") ? "opus" : /haiku/.test(r.model || "") ? "haiku" : "sonnet";
const sh = (cmd, args, ms = 240000) => { const x = spawnSync(cmd, args, { cwd: ROOT, encoding: "utf8", timeout: ms, env: { ...process.env, NODE_USE_ENV_PROXY: "1" } }); return { ok: x.status === 0, out: `${x.stdout || ""}${x.stderr || ""}`.split("\n").filter((l) => l.trim() && !/Warning|trace-warnings/.test(l)) }; };
const out = [];
const say = (s = "") => out.push(s);
// run_in_background false: all workers' results come back as ONE turn of this session. Background workers each wake the
// session separately, and every wake-up re-reads the session's whole history, which is what used up the plan's limit.
const AGENT = (m) => `Agent tool, subagent_type "general-purpose", model "${m}", run_in_background false`;
const worker = (key, batch) => `You are a CyberView ${key.replace("-", " ")}. In ${ROOT} run \`node scripts/job-prompt.mjs ${key}${batch ? " --batch " + batch : ""}\` and carry out the printed instructions exactly and completely. Do not run any git command. End with the one line the instructions ask for.`;
const single = (key) => `You are running the CyberView "${key}" job. In ${ROOT} run \`node scripts/job-prompt.mjs ${key}\` and carry out the printed instructions exactly and completely, including the FINISH steps (build, commit, push). End with one line starting "CyberView ${key}:".`;
const fixer = `In ${ROOT} run \`node scripts/build.mjs\`. Fix every error it names by correcting that record from its own sources (open them; never delete an event; never invent a value). Rerun until it passes. Do not run any git command. End with one line saying what you fixed.`;

// Headless mode (the owner approved it on 2026-11-19): the whole job runs as one script that starts its own workers, so
// this session makes one call per job and its history barely grows. Falls back to subagents if headless is unavailable.
const PL = readJson(join(ROOT, "config", "pipeline.json"), {});
// the research job is a continuous loop (scripts/run-job.mjs flow); its schedules only start it when it is not running
if (job === "sweep" && (PL.flow || {}).enabled !== false && (PL.headless === true || (PL.headless_jobs || []).includes("sweep")) && process.env.CYBERVIEW_SUBAGENTS !== "1") {
  const { flowAlive, FLOW_LOCK } = await import("./run-job.mjs");
  const lock = readJson(FLOW_LOCK, null);
  const { leaderOf, leaderBlocks, hostId } = await import("./lib/lease.mjs"), leader = leaderOf(readJson(join(DATA, "leases.json"), {}));
  // a lease this session took for a loop that no longer runs here (container restarted, process killed) does not block a restart
  if (!flowAlive(lock) && leaderBlocks(leader, "", hostId(), false)) { console.log(`DISPATCH sweep: the research loop is running in another session (${leader.run}, cycle ${leader.cycle ?? "?"}, lease until ${leader.until}). This session is the standby: start nothing. End with exactly: "CyberView sweep: standby, loop running elsewhere"`); process.exit(0); }
  if (flowAlive(lock)) { console.log(`DISPATCH sweep: the continuous flow is running (cycle ${lock.cycle}, ${lock.note || ""}, last beat ${lock.beat}). Start nothing. End with exactly: "CyberView sweep: flow running, cycle ${lock.cycle}"`); process.exit(0); }
  // Run the flow in the FOREGROUND for a bounded span, not as a ~100-minute background loop. A cloud session reaps a
  // backgrounded process a few minutes after the turn ends, so the long loop died before its researchers could finish or
  // commit — it looked "running" by heartbeat while publishing nothing. A short foreground run finishes its cycles and
  // commits before the turn ends; the frequent sweep schedules give continuous coverage, and FLOW_LOCK still makes a
  // second session stand by. config/pipeline.json flow.foreground_minutes tunes the span (kept under the 10-min tool cap).
  const fm = Math.max(2, Math.min(9, Number((PL.flow || {}).foreground_minutes) || 7)), tmo = Math.min(600000, (fm + 2) * 60000);
  if (EXEC) execHeadless({ FLOW_MINUTES: String(fm) }, [join(ROOT, "scripts", "run-job.mjs"), "flow"], tmo - 30000, "CyberView sweep:");
  console.log([`DISPATCH sweep (bounded foreground flow). The owner approved running jobs through scripts/run-job.mjs, which starts headless workers with only the tools each role needs and git denied.`,
    `1. Run this ONE command in the FOREGROUND (run_in_background FALSE) with timeout ${tmo} — it runs about ${fm} minutes of research cycles, committing every few minutes, then returns: FLOW_MINUTES=${fm} node scripts/run-job.mjs flow 2>&1 | tail -3`,
    `   Run it in the foreground so the cycles finish and commit before this turn ends; do NOT background it (a backgrounded loop is reaped by the cloud session and publishes nothing).`,
    `2. If the output contains "HEADLESS UNAVAILABLE", run \`CYBERVIEW_SUBAGENTS=1 node scripts/dispatch.mjs sweep\` and do what it prints instead. Otherwise end with exactly its last line.`].join("\n"));
  process.exit(0);
}
if ((PL.headless === true || (Array.isArray(PL.headless_jobs) && PL.headless_jobs.includes(job))) && process.env.CYBERVIEW_SUBAGENTS !== "1") {
  // Run the job in the FOREGROUND, not the background. run-job.mjs plans, then runs its headless worker pool (triagers,
  // researchers, reviewers...) which takes several minutes; a cloud session reaps a backgrounded process a few minutes
  // after the turn ends, so the workers were killed before they finished — the job committed "0 new" after only its
  // planning step ran (observed for backlog: triagers ran, researchers reaped). A foreground run finishes its workers and
  // commits before the turn ends. config/pipeline.json headless_foreground_minutes caps it under the 10-minute tool cap;
  // if a job ever needs longer it is cut and the next scheduled run commits the leftover with finish.mjs --force.
  const hm = Math.max(2, Math.min(9, Number(PL.headless_foreground_minutes) || 8)), tmo = Math.min(600000, (hm + 1) * 60000);
  if (EXEC) execHeadless({}, [join(ROOT, "scripts", "run-job.mjs"), job], tmo - 30000, `CyberView ${job}:`);
  console.log([`DISPATCH ${job} (headless). The owner approved running jobs through scripts/run-job.mjs, which starts headless workers with only the tools each role needs and git denied.`,
    `1. Run this ONE command in the FOREGROUND (run_in_background FALSE) with timeout ${tmo} — it plans, runs the headless workers and commits, then returns (usually a few minutes): node scripts/run-job.mjs ${job} 2>&1 | tail -3`,
    `   Run it in the foreground so the workers finish and commit before this turn ends; do NOT background it (a backgrounded run is reaped by the cloud session before its workers finish, so nothing is researched).`,
    `2. If the output contains "HEADLESS UNAVAILABLE", run \`CYBERVIEW_SUBAGENTS=1 node scripts/dispatch.mjs ${job}\` and do what it prints instead. Otherwise end with exactly its last line (it starts "CyberView ${job}:").`].join("\n"));
  process.exit(0);
}
// subagents use the same Max plan as headless workers: at "stop" none start; at "tight" the jobs in
// usage_budget.tight_skip_jobs wait for their next schedule only while usage_budget.tight_cuts_work is true (owner,
// 2026-11-21: off; scripts/lib/usage.mjs)
{
  const { budgetState, budgetLine } = await import("./lib/usage.mjs"), B = budgetState();
  if (B.level === "stop" || (B.level === "tight" && (PL.usage_budget || {}).tight_cuts_work === true && ((PL.usage_budget || {}).tight_skip_jobs || []).includes(job))) {
    console.log(`DISPATCH ${job}: ${budgetLine(B)}. Start nothing. End with exactly: "CyberView ${job}: skipped, plan usage ${B.level}"`); process.exit(0);
  }
}
say(`DISPATCH ${job}. Do exactly these steps, in order, and nothing else. Do not research, read data files or read job instructions yourself. Use as few turns as possible: combine shell commands with && in one call, start all subagents of a step in ONE message with run_in_background false, and never wait or poll.`);

if (job === "sweep") {
  const hk = [["kick", "bash", ["scripts/kick.sh"]], ["collect", "node", ["scripts/collect.mjs"]], ["osint", "node", ["scripts/osint.mjs"]], ["triage", "node", ["scripts/triage.mjs"]], ["backlog rules", "node", ["scripts/backlog.mjs", "auto"]]].map(([n, c, a]) => { const x = sh(c, a); return `${n} ${x.ok ? "ok" : "FAILED"}`; });
  const plan = sh("node", ["scripts/sweep-plan.mjs", "plan"]), head = plan.out[0] || "no plan";
  const sp = readJson(join(DATA, "sweep-plan.json"), { stories: [] }), batches = [...new Set((sp.stories || []).map((s) => s.batch))].sort(), deepB = new Set(sp.deep || []);
  // gap searchers once per sweep.gap_every_minutes (by the clock), as many as gapCount allows at this usage level
  const sc = readJson(join(ROOT, "config", "pipeline.json"), {}).sweep || {}, every = Math.max(15, Number(sc.gap_every_minutes) || 30), gapDue = sc.gap_every_run === true || Math.floor((Date.now() % 864e5) / 6e4) % every < 15;
  const { gapCount } = await import("./run-job.mjs"), { budgetState } = await import("./lib/usage.mjs"), gap = gapDue ? gapCount(Date.now(), 0, sc, budgetState()) : 0;
  say(`Housekeeping done by this command: ${hk.join(", ")}. ${head}`);
  // community posts are checked in the same hourly wake-up, so an idle moderator never costs a wake-up of its own
  const chat = sh("node", ["scripts/chat.mjs", "intake"]), posts = chat.out.filter((l) => /^(PENDING|REPORT) /.test(l)).length;
  say(`Community feed: ${posts} post(s) or report(s) waiting.`);
  const tasks = batches.map((b) => worker("researcher", b)).concat(Array.from({ length: gap }, (_, i) => worker("gap", i + 1))).concat(posts ? [`You are the CyberView community moderator. In ${ROOT} run \`node scripts/job-prompt.mjs moderator\` and carry out the printed instructions exactly, EXCEPT: do not run any git command and do not edit data/status.json (the dispatcher commits). End with one line starting "moderator:".`] : []);
  if (!tasks.length) { say('The queue is empty and no search is due this run. Run: node scripts/finish.mjs sweep   then end with exactly: "CyberView sweep: queue empty, nothing to research"'); process.exit(0); }
  say(`1. Start these ${tasks.length} subagents IN ONE MESSAGE so they run in parallel (${AGENT("sonnet")}, except the ones marked [model opus]: model "opus", the deep batches of scripts/lib/routing.mjs). The task text for each, exactly:`);
  tasks.forEach((t, i) => say(`   (${i + 1})${i < batches.length && deepB.has(batches[i]) ? " [model opus]" : ""} ${t}`));
  say("2. When ALL have returned, run: node scripts/sweep-plan.mjs check");
  say(`   If it exits 1 (stories NOT HANDLED), run \`node scripts/sweep-plan.mjs retry\` and start ONE more subagent (${AGENT("sonnet")}) with: ${worker("researcher", "retry")}`);
  say("3. Run: node scripts/finish.mjs sweep");
  say(`   If it prints BUILD FAILED: start ONE subagent (${AGENT("sonnet")}) with: ${fixer}  Then run: node scripts/finish.mjs sweep --force`);
  say('4. End with exactly one line: "CyberView sweep: " followed by the scorecard line and the line finish.mjs printed.');
} else if (job === "backlog") {
  // drains whatever the sweeps cannot reach: rules close the noise, triagers sort headlines, researchers take what is left
  const bc = readJson(join(ROOT, "config", "pipeline.json"), {}).backlog || {}, T = Math.max(1, Math.min(8, Number(bc.triagers) || 3)), R = Math.max(1, Math.min(8, Number(bc.researchers) || 4)), floor = Number(bc.leave_for_sweep ?? 16);
  sh("node", ["scripts/triage.mjs"]);
  const auto = sh("node", ["scripts/backlog.mjs", "auto"]), plan = sh("node", ["scripts/backlog.mjs", "plan", "--per", "40", "--max", String(T)]), st = JSON.parse(sh("node", ["scripts/backlog.mjs", "status", "--json"]).out.join("") || "{}");
  const nb = ((readJson(join(DATA, "backlog-plan.json"), { batches: [] }).batches) || []).length;
  say(`${auto.out[0] || ""} ${plan.out[0] || ""}`);
  if (!(st.waiting > floor)) say(`Only ${st.waiting ?? 0} stories are waiting, which the next sweep covers. Run: node scripts/finish.mjs backlog   then end with exactly: "CyberView backlog: clear (${st.waiting ?? 0} waiting)"`);
  else {
    say(nb ? `1. Start these ${nb} subagents IN ONE MESSAGE so they run in parallel (${AGENT("sonnet")}). The task text for each, exactly:` : "1. (no triage needed this run)");
    for (let i = 1; i <= nb; i++) say(`   (${i}) ${worker("backlog-triager", i)}`);
    say(`2. When ALL have returned, run: node scripts/backlog.mjs apply --per 8 --max ${R}`);
    say(`   Its last line reads "RESEARCHER BATCHES: 1 2 3 ..." (or "none"). For EACH number N on that line start one subagent, all IN ONE MESSAGE (${AGENT("sonnet")}), with exactly this task text, N replaced by the number: ${worker("researcher", "N")}`);
    say("3. When ALL have returned, run: node scripts/sweep-plan.mjs check   (a score under 80% is reported, not retried: the next run takes what is left)");
    say("4. Run: node scripts/finish.mjs backlog");
    say(`   If it prints BUILD FAILED: start ONE subagent (${AGENT("sonnet")}) with: ${fixer}  Then run: node scripts/finish.mjs backlog --force`);
    say('5. Run: node scripts/backlog.mjs status   and end with exactly one line: "CyberView backlog: " followed by that status line and the line finish.mjs printed.');
  }
} else if (job === "analyst") {
  const ac = readJson(join(ROOT, "config", "pipeline.json"), {}).analyst || {}, Wk = Math.max(1, Math.min(4, Number(ac.workers) || 2)), per = Math.max(1, Math.min(5, Number(ac.per_worker) || 3));
  const plan = sh("node", ["scripts/analyst.mjs", "plan", "--workers", String(Wk), "--per", String(per)]), n = ((readJson(join(DATA, "analyst-plan.json"), { batches: [] }).batches) || []).length;
  say(plan.out[0] || "");
  if (!n) say('Nothing is waiting. End with exactly: "CyberView analyst: nothing waiting"');
  else {
    say(`1. Start these ${n} subagents IN ONE MESSAGE so they run in parallel (${AGENT("opus")}). The task text for each, exactly:`);
    for (let i = 1; i <= n; i++) say(`   (${i}) ${worker("exploit-analyst", i)}`);
    say("2. When ALL have returned, run: node scripts/finish.mjs analyst");
    say(`   If it prints BUILD FAILED: start ONE subagent (${AGENT("sonnet")}) with: ${fixer}  Then run: node scripts/finish.mjs analyst --force`);
    say('3. Run: node scripts/analyst.mjs status   and end with exactly one line: "CyberView analyst: " followed by each analyst\'s final line, that status line and the line finish.mjs printed.');
  }
} else if (job === "review") {
  const plan = sh("node", ["scripts/review.mjs", "plan"]), n = ((readJson(join(DATA, "review-plan.json"), { batches: [] }).batches) || []).filter((b) => b.length).length;
  say(plan.out[0] || "");
  if (!n) say('Nothing is waiting for review. End with exactly: "CyberView review: nothing waiting"');
  else {
    say(`1. Start these ${n} subagents IN ONE MESSAGE so they run in parallel (${AGENT("sonnet")}). The task text for each, exactly:`);
    for (let i = 1; i <= n; i++) say(`   (${i}) ${worker("reviewer", i)}`);
    say("2. When ALL have returned, run: node scripts/finish.mjs review");
    say(`   If it prints BUILD FAILED: start ONE subagent (${AGENT("sonnet")}) with: ${fixer}  Then run: node scripts/finish.mjs review --force`);
    say('3. End with exactly one line: "CyberView review: " followed by each reviewer\'s final line and the line finish.mjs printed.');
  }
} else if (job === "deep-sweep") {
  sh("node", ["scripts/collect.mjs"]); sh("node", ["scripts/osint.mjs"]); sh("node", ["scripts/triage.mjs"]);
  say(`1. Start these 3 subagents IN ONE MESSAGE so they run in parallel (${AGENT("opus")}). The task text for each, exactly:`);
  ["a", "b", "c"].forEach((g, i) => say(`   (${i + 1}) ${worker("regional-researcher", g)}`));
  say("2. When ALL have returned, run: node scripts/finish.mjs deep-sweep");
  say(`   If it prints BUILD FAILED: start ONE subagent (${AGENT("sonnet")}) with: ${fixer}  Then run: node scripts/finish.mjs deep-sweep --force`);
  say('3. End with exactly one line: "CyberView deep-sweep: " followed by the line finish.mjs printed.');
} else if (job === "moderator") {
  const x = sh("node", ["scripts/chat.mjs", "intake"]), waiting = x.out.filter((l) => /^(PENDING|REPORT) /.test(l)).length;
  say(x.out[0] || "chat intake ran");
  if (!waiting) say('Nothing is waiting. End with exactly: "CyberView moderator: nothing to review"');
  else { say(`1. Start ONE subagent (${AGENT(model)}) with exactly: ${single("moderator")}`); say("2. When it returns, run `git log --oneline -1` and end with its final line."); }
} else {
  say(`1. Start ONE subagent (${AGENT(model)}) with exactly: ${single(job)}`);
  say("2. When it returns, run `git status --short | head -5` and `git log --oneline -1`. If files are left uncommitted, run: node scripts/finish.mjs " + job + " --force");
  say("3. End with the subagent's final line.");
}
say("If a subagent fails or returns nothing, say so in your final line; do not do its work yourself.");
console.log(out.join("\n"));
