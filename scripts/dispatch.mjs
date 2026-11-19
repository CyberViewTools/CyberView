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
const reg = readJson(join(ROOT, "routines.json"), { routines: [] }), r = reg.routines.find((x) => x.key === job);
if (!r || r.tier !== "ai") { console.error(`unknown AI job "${job}"`); process.exit(1); }
const model = /opus/.test(r.model || "") ? "opus" : /haiku/.test(r.model || "") ? "haiku" : "sonnet";
const sh = (cmd, args, ms = 240000) => { const x = spawnSync(cmd, args, { cwd: ROOT, encoding: "utf8", timeout: ms, env: { ...process.env, NODE_USE_ENV_PROXY: "1" } }); return { ok: x.status === 0, out: `${x.stdout || ""}${x.stderr || ""}`.split("\n").filter((l) => l.trim() && !/Warning|trace-warnings/.test(l)) }; };
const out = [];
const say = (s = "") => out.push(s);
const AGENT = (m) => `Agent tool, subagent_type "general-purpose", model "${m}", run in the foreground`;
const worker = (key, batch) => `You are a CyberView ${key.replace("-", " ")}. In ${ROOT} run \`node scripts/job-prompt.mjs ${key}${batch ? " --batch " + batch : ""}\` and carry out the printed instructions exactly and completely. Do not run any git command. End with the one line the instructions ask for.`;
const single = (key) => `You are running the CyberView "${key}" job. In ${ROOT} run \`node scripts/job-prompt.mjs ${key}\` and carry out the printed instructions exactly and completely, including the FINISH steps (build, commit, push). End with one line starting "CyberView ${key}:".`;
const fixer = `In ${ROOT} run \`node scripts/build.mjs\`. Fix every error it names by correcting that record from its own sources (open them; never delete an event; never invent a value). Rerun until it passes. Do not run any git command. End with one line saying what you fixed.`;

say(`DISPATCH ${job}. Do exactly these steps, in order, and nothing else. Do not research, read data files or read job instructions yourself.`);

if (job === "sweep") {
  const hk = [["kick", "bash", ["scripts/kick.sh"]], ["collect", "node", ["scripts/collect.mjs"]], ["osint", "node", ["scripts/osint.mjs"]], ["triage", "node", ["scripts/triage.mjs"]]].map(([n, c, a]) => { const x = sh(c, a); return `${n} ${x.ok ? "ok" : "FAILED"}`; });
  const plan = sh("node", ["scripts/sweep-plan.mjs", "plan"]), head = plan.out[0] || "no plan";
  const batches = [...new Set((readJson(join(DATA, "sweep-plan.json"), { stories: [] }).stories || []).map((s) => s.batch))].sort();
  const gap = (readJson(join(ROOT, "config", "pipeline.json"), {}).sweep || {}).gap_pass !== false;
  say(`Housekeeping done by this command: ${hk.join(", ")}. ${head}`);
  const tasks = batches.map((b) => worker("researcher", b)).concat(gap ? [worker("gap")] : []);
  say(`1. Start these ${tasks.length} subagents IN ONE MESSAGE so they run in parallel (${AGENT("sonnet")}). The task text for each, exactly:`);
  tasks.forEach((t, i) => say(`   (${i + 1}) ${t}`));
  say("2. When ALL have returned, run: node scripts/sweep-plan.mjs check");
  say(`   If it exits 1 (stories NOT HANDLED), run \`node scripts/sweep-plan.mjs retry\` and start ONE more subagent (${AGENT("sonnet")}) with: ${worker("researcher", "retry")}`);
  say("3. Run: node scripts/finish.mjs sweep");
  say(`   If it prints BUILD FAILED: start ONE subagent (${AGENT("sonnet")}) with: ${fixer}  Then run: node scripts/finish.mjs sweep --force`);
  say('4. End with exactly one line: "CyberView sweep: " followed by the scorecard line and the line finish.mjs printed.');
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
