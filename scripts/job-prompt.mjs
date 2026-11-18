// Prints the full prompt for one scheduled AI job: the shared preamble from docs/jobs.md, a blank line,
// then that job's section. docs/jobs.md stays the single source of truth for every job's instructions.
// Usage: node scripts/job-prompt.mjs <job>   (sweep, verify, report-review, analysis, deep-sweep, brief, watchdog,
//        security-review, markets, triage, regional, followup, steward)
// For the triage desk and the sweep it first runs the no-AI housekeeping (start overdue workflows, collect feeds,
// clear obvious leads), so that work happens every run whether or not the agent remembers it.
// Set NO_HOUSEKEEPING=1 to skip it (the GitHub Actions fallback does).
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { ROOT } from "./lib/store.mjs";

const HEADINGS = {
  "sweep": "Sweep", "verify": "Verify", "report-review": "Report review", "analysis": "Analysis",
  "deep-sweep": "Deep sweep", "brief": "Brief", "watchdog": "Watchdog", "security-review": "Security review", "markets": "Markets", "triage": "Triage desk", "regional": "Regional desk", "followup": "Follow-up desk", "steward": "Data steward",
};
const job = process.argv[2];
if (!HEADINGS[job]) { console.error(`unknown job "${job}"; one of: ${Object.keys(HEADINGS).join(", ")}`); process.exit(1); }

if ((job === "sweep" || job === "triage") && !process.env.NO_HOUSEKEEPING) {
  const steps = job === "sweep"
    ? [["bash", ["scripts/kick.sh"]], ["node", ["scripts/collect.mjs"]], ["node", ["scripts/triage.mjs"]]]
    : [["node", ["scripts/triage.mjs"]]];
  const lines = ["HOUSEKEEPING (already done by this command; nothing for you to run):"];
  for (const [cmd, args] of steps) {
    const r = spawnSync(cmd, args, { cwd: ROOT, encoding: "utf8", timeout: 240000, env: { ...process.env, NODE_USE_ENV_PROXY: "1" } });
    const out = `${r.stdout || ""}${r.stderr || ""}`.split("\n").filter((l) => l.trim() && !/Warning|trace-warnings/.test(l));
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
process.stdout.write(block("Shared preamble") + "\n\n" + block(HEADINGS[job]) + "\n");
