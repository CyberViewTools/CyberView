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
import { budgetConfig, canBuild, readUsage, budgetState, fallbackConfig, fallbackDecision, fallbackSpend } from "./lib/usage.mjs";

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
/** Pure: the API-fallback state for `status`, from the pipeline ledger and the dials. keyPresent is a boolean only (the key
 *  VALUE is never read, printed or returned). -> { enabled, cap_usd, state, month, usd, workers, last_at, key_present }. */
export function fallbackStatus(now = Date.now(), cfg = budgetConfig(), lines = [], keyPresent = false) {
  const fb = fallbackConfig(cfg), spend = fallbackSpend(lines, now);
  let limited_until = null; try { limited_until = budgetState(now, cfg, lines).limited_until; } catch {}
  const state = fallbackDecision({ limited_until, now, fallbackKeyPresent: !!keyPresent, enabled: fb.enabled, monthSpendUsd: spend.usd, cap: fb.monthly_usd_cap, fallbackKeyLimited: false });
  return { enabled: fb.enabled, cap_usd: fb.monthly_usd_cap, env_var: fb.env_var, key_present: !!keyPresent, state, month: spend.month, usd: spend.usd, workers: spend.workers, last_at: spend.last_at, limited_until };
}
/** Pure: the one line `status` prints for the fallback. Never contains the key value. */
export function fallbackLine(f) {
  return `API fallback: ${f.enabled ? "enabled" : "disabled"}, cap $${f.cap_usd}/month, key ${f.key_present ? "present" : `not set (${f.env_var})`}; now ${f.state}; $${f.usd} billed to the API this month (${f.workers} worker line(s)${f.last_at ? ", last " + f.last_at : ""}).`;
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
    const cfg = budgetConfig(), r = canBuild(now, cfg, lines, readBuild(BUILD_LEDGER(), now)), v = verdict(r);
    // the key VALUE is never read here: only whether the env var is set is passed on
    const fb = fallbackStatus(now, cfg, lines, !!process.env[fallbackConfig(cfg).env_var]);
    if (rest.includes("--json")) console.log(JSON.stringify({ ...r, pipeline_lines: lines.length, fallback: fb }));
    else {
      console.log(v.line);
      if (cmd === "status") { console.log(`pipeline level ${r.level}; ${lines.length} pipeline worker line(s) in the last 7 days${lines.length ? "" : " (no data/usage here: mount the data branch, or the estimate counts nothing)"}`); console.log(fallbackLine(fb)); }
    }
    if (cmd === "can-build") process.exit(v.code);
    return;
  }
  console.error("usage: budget.mjs status [--json] | can-build [--json] | spent --tokens N [--cost C] [--note TEXT]"); process.exit(2);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
