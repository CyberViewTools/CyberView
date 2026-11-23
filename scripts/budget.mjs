// The shared usage window, for work that is NOT the pipeline. No AI model, no network.
// Run: node scripts/budget.mjs status [--json]       where the 5-hour window stands, and whether build work may run
//      node scripts/budget.mjs can-build [--json]    exit 0: build work may start agents; exit 1: it must wait (the line says why)
//      node scripts/budget.mjs spent --tokens N [--cost C] [--note TEXT]   record what a build wave used (a local file)
// Why: the pipeline and every code build, swarm and interactive session share one 5-hour usage window. On 2026-11-22 a
// code-build swarm used all of it; the pipeline's workers failed with "You've hit your 5-hour limit" and nothing was
// published for 2.5 hours. Owner, 2026-11-23: usage_budget.pipeline_reserve_pct (35) of the window estimate is kept for
// the pipeline. A build swarm calls `can-build` before it launches agents and again between waves, and stops launching
// while it exits non-zero: the window stands above (100 - reserve)% of the estimate, or the plan refused a pipeline worker
// in the last hour (scripts/lib/usage.mjs canBuild). The pipeline's own budget (budgetState: stop at stop_pct or on a real
// limit) is not changed by this script.
// The pipeline's usage comes from data/usage/<month>.jsonl (mount the data branch: node scripts/data-branch.mjs ensure).
// Build work is not in that ledger, so a swarm that wants to be counted records each wave with `spent`; the file lives
// outside the repository (CYBERVIEW_BUILD_LEDGER, default <tmp>/cyberview-build-usage.jsonl) and is never committed.
import { appendFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { budgetConfig, canBuild, readUsage } from "./lib/usage.mjs";

export const BUILD_LEDGER = () => process.env.CYBERVIEW_BUILD_LEDGER || join(tmpdir(), "cyberview-build-usage.jsonl");
/** The build work recorded with `spent` (lines of the last 7 days; a missing or broken file is no usage). */
export function readBuild(file = BUILD_LEDGER(), now = Date.now()) {
  let txt = ""; try { txt = readFileSync(file, "utf8"); } catch { return []; }
  const out = [];
  for (const l of txt.split("\n")) { if (!l.trim()) continue; try { const j = JSON.parse(l); if (j && typeof j.at === "string" && Date.parse(j.at) > now - 7 * 864e5) out.push(j); } catch {} }
  return out;
}
/** Pure: one build-ledger line. tokens are counted as input tokens (the window estimate adds every kind up). */
export function spentLine(tokens, cost = 0, note = "", now = Date.now()) {
  const t = Math.max(0, Math.round(Number(tokens) || 0)), c = Math.max(0, +(Number(cost) || 0).toFixed(4));
  return { at: new Date(now).toISOString().replace(/\.\d+Z$/, "Z"), job: "build", role: "build", in: t, out: 0, cache_read: 0, cache_write: 0, cost: c, ok: true, note: String(note || "").slice(0, 120) };
}
/** Pure: the exit code and the line `can-build` and `status` print. */
export function verdict(r) {
  return { code: r.ok ? 0 : 1, line: `${r.ok ? "BUILD OK" : "BUILD WAIT"}: ${r.reason}.` };
}

function main() {
  const [cmd, ...rest] = process.argv.slice(2), arg = (k, d) => { const i = rest.indexOf("--" + k); return i >= 0 ? rest[i + 1] : d; };
  const now = Date.now();
  if (cmd === "spent") {
    const tokens = Number(arg("tokens", NaN)), cost = Number(arg("cost", 0));
    if (!(tokens >= 0) && !(cost > 0)) { console.error("usage: budget.mjs spent --tokens N [--cost C] [--note TEXT]"); process.exit(2); }
    const l = spentLine(tokens || 0, cost, arg("note", ""), now); appendFileSync(BUILD_LEDGER(), JSON.stringify(l) + "\n");
    console.log(`recorded: ${l.in.toLocaleString("en-US")} tokens, $${l.cost} of build work (${BUILD_LEDGER()})`);
    return;
  }
  if (cmd === "status" || cmd === "can-build") {
    let lines = []; try { lines = readUsage(now - 7 * 864e5, now); } catch {}
    const r = canBuild(now, budgetConfig(), lines, readBuild(BUILD_LEDGER(), now)), v = verdict(r);
    if (rest.includes("--json")) console.log(JSON.stringify({ ...r, pipeline_lines: lines.length }));
    else {
      console.log(v.line);
      if (cmd === "status") console.log(`pipeline level ${r.level}; ${lines.length} pipeline worker line(s) in the last 7 days${lines.length ? "" : " (no data/usage here: mount the data branch, or the estimate counts nothing)"}`);
    }
    if (cmd === "can-build") process.exit(v.code);
    return;
  }
  console.error("usage: budget.mjs status [--json] | can-build [--json] | spent --tokens N [--cost C] [--note TEXT]"); process.exit(2);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
