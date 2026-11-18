// Prints the full prompt for one scheduled AI job: the shared preamble from docs/jobs.md, a blank line,
// then that job's section. docs/jobs.md stays the single source of truth for every job's instructions.
// Usage: node scripts/job-prompt.mjs <sweep|verify|report-review|analysis|deep-sweep|brief|watchdog|security-review>
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "./lib/store.mjs";

const HEADINGS = {
  "sweep": "Sweep", "verify": "Verify", "report-review": "Report review", "analysis": "Analysis",
  "deep-sweep": "Deep sweep", "brief": "Brief", "watchdog": "Watchdog", "security-review": "Security review", "markets": "Markets",
};
const job = process.argv[2];
if (!HEADINGS[job]) { console.error(`unknown job "${job}"; one of: ${Object.keys(HEADINGS).join(", ")}`); process.exit(1); }

const md = readFileSync(join(ROOT, "docs", "jobs.md"), "utf8");
const block = (heading) => {
  const re = new RegExp(`^## ${heading.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b[^\\n]*\\n+\`\`\`\\n([\\s\\S]*?)\\n\`\`\``, "m");
  const m = md.match(re);
  if (!m) { console.error(`docs/jobs.md has no "## ${heading}" section with a code block`); process.exit(1); }
  return m[1];
};
process.stdout.write(block("Shared preamble") + "\n\n" + block(HEADINGS[job]) + "\n");
