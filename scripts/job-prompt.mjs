// Prints the full prompt for one scheduled AI job: the shared preamble from docs/jobs.md, a blank line,
// then that job's section. docs/jobs.md stays the single source of truth for every job's instructions.
// Usage: node scripts/job-prompt.mjs <job>   (sweep, verify, report-review, analysis, deep-sweep, brief, watchdog,
//        security-review, triage, regional, followup, steward, tabletop, advisory, moderator, scout, editor, guardian, review)
// For the triage desk and the sweep it first runs the no-AI housekeeping (start overdue workflows, collect feeds,
// clear obvious leads), so that work happens every run whether or not the agent remembers it.
// Set NO_HOUSEKEEPING=1 to skip it (the GitHub Actions fallback does).
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { ROOT, DATA, readJson } from "./lib/store.mjs";

const HEADINGS = {
  "sweep": "Sweep", "verify": "Verify", "report-review": "Report review", "analysis": "Analysis",
  "deep-sweep": "Deep sweep", "brief": "Brief", "watchdog": "Watchdog", "security-review": "Security review", "triage": "Triage desk", "regional": "Regional desk", "followup": "Follow-up desk", "steward": "Data steward", "tabletop": "Tabletop", "advisory": "Advisory desk", "moderator": "Moderator", "scout": "Source scout", "editor": "Editor", "guardian": "Guardian", "review": "Review desk",
  // workers: started by the dispatcher (scripts/dispatch.mjs), one per batch; they never run git
  "researcher": "Researcher", "gap": "Gap researcher", "reviewer": "Reviewer", "regional-researcher": "Regional researcher",
};
const job = process.argv[2];
if (!HEADINGS[job]) { console.error(`unknown job "${job}"; one of: ${Object.keys(HEADINGS).join(", ")}`); process.exit(1); }

if ((job === "sweep" || job === "triage" || job === "moderator") && !process.env.NO_HOUSEKEEPING) {
  const steps = job === "sweep"
    ? [["bash", ["scripts/kick.sh"]], ["node", ["scripts/collect.mjs"]], ["node", ["scripts/osint.mjs"]], ["node", ["scripts/triage.mjs"]], ["node", ["scripts/fuse.mjs"]]]
    : job === "moderator" ? [["node", ["scripts/chat.mjs", "intake"]]]
    : [["node", ["scripts/triage.mjs"]], ["node", ["scripts/fuse.mjs"]]];
  const lines = ["HOUSEKEEPING (already done by this command; nothing for you to run):"];
  for (const [cmd, args] of steps) {
    const r = spawnSync(cmd, args, { cwd: ROOT, encoding: "utf8", timeout: 240000, env: { ...process.env, NODE_USE_ENV_PROXY: "1" } });
    const out = `${r.stdout || ""}${r.stderr || ""}`.split("\n").filter((l) => l.trim() && !/Warning|trace-warnings/.test(l));
    if (job === "moderator") { lines.push(`- ${args[0]}: ${r.status === 0 ? "ok" : "FAILED (" + (r.status ?? r.signal) + ")"}`, ...out.slice(0, 60).map((l) => "  " + l.slice(0, 900))); continue; }
    lines.push(`- ${args[0]}: ${r.status === 0 ? "ok" : "FAILED (" + (r.status ?? r.signal) + ")"}${out.length ? "; " + out.slice(-3).join(" | ").slice(0, 300) : ""}`);
  }
  process.stdout.write(lines.join("\n") + "\n\n");
}

const md = readFileSync(join(ROOT, "docs", "jobs.md"), "utf8");
const block = (heading) => {
  const re = new RegExp(`^## ${heading.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b[^\\n]*\\n+\`\`\`\\n([\\s\\S]*?)\\n\`\`\``, "m");
  const m = md.match(re);
  if (!m) { console.error(`docs/jobs.md has no "## ${heading}" section with a code block`); process.exit(1); }
  return m[1];
};
// a worker's assignment comes from the plan a script wrote, never from the worker's own choice
let assignment = "";
const bi = process.argv.indexOf("--batch"), batch = bi > 0 ? String(process.argv[bi + 1] || "") : "";
if (job === "researcher") {
  const plan = readJson(join(DATA, "sweep-plan.json"), { stories: [] });
  const mine = batch === "retry" ? plan.stories.filter((s) => (plan.retry || []).includes(s.id)) : plan.stories.filter((s) => String(s.batch) === batch);
  assignment = `YOUR ASSIGNMENT (researcher ${batch}): ${mine.length} stories, in this order:\n` + mine.map((s) => `  ${s.id}  ${String(s.title).slice(0, 110)}`).join("\n") + (mine.length ? "" : "\n  (none: end with \"researcher " + batch + ": nothing assigned\")");
} else if (job === "reviewer") {
  const plan = readJson(join(DATA, "review-plan.json"), { batches: [] }), mine = (plan.batches || [])[Number(batch) - 1] || [];
  assignment = `YOUR ASSIGNMENT (reviewer ${batch}): ${mine.length} events:\n` + mine.map((id) => `  ${id}`).join("\n") + (mine.length ? "" : "\n  (none: end with \"reviewer " + batch + ": nothing assigned\")");
} else if (job === "regional-researcher") {
  const G = { a: "Africa (africa); the Middle East and Turkey (middle-east)", b: "Latin America and the Caribbean (latin-america)", c: "South Asia (south-asia); Southeast Asia (southeast-asia); Oceania (oceania)" };
  assignment = `YOUR ASSIGNMENT (regional researcher ${batch}): ${G[batch] || G.a}. The region names in brackets are the ones fuse.mjs --region understands.`;
}
process.stdout.write(block("Shared preamble") + "\n\n" + block(HEADINGS[job]) + "\n" + (assignment ? "\n" + assignment + "\n" : ""));
