// Plans the report review job's input, no AI model. Run: node scripts/report-plan.mjs plan
// Reads the events whose original document has not been read in full yet (report.read_depth summary or secondary, added in
// the last 8 days), sorts them into tiers (Critical, High, Routine: scripts/review.mjs tier()), newest first inside each tier,
// keeps config review's report_review.max_items, and writes data/report-plan.json. It changes no event: the job reads the
// list, then writes each report object itself. Output: one summary line, then the items grouped by tier.
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { DATA, ROOT, readJson, writeJson, listEventFiles, nowIso } from "./lib/store.mjs";
import { tier, TIERS } from "./review.mjs";

/** Pure: the report candidates in plan order. events: event objects. Returns {candidates, items} (items capped at max). */
export function planReports(events, now = Date.now(), max = 10) {
  const floor = new Date(now - 8 * 864e5).toISOString().slice(0, 10);
  const cands = events.filter((e) => e && !e.duplicate_of && e.report && ["summary", "secondary"].includes(e.report.read_depth) && String(e.date || "") >= floor);
  const rank = (e) => TIERS.indexOf(tier(e)), stamp = (e) => String(e.first_seen || e.date || "");
  const items = cands.slice().sort((a, b) => (rank(a) - rank(b)) || (stamp(a) < stamp(b) ? 1 : stamp(a) > stamp(b) ? -1 : 0)).slice(0, Math.max(0, max));
  return { candidates: cands.length, items };
}

function main() {
  const [cmd] = process.argv.slice(2);
  if (cmd !== "plan") { console.error("usage: report-plan.mjs plan"); process.exit(1); }
  const cfg = (readJson(join(ROOT, "config", "pipeline.json"), {}).report_review) || {};
  const max = Math.max(1, Math.min(25, Number(cfg.max_items) || 10));
  const events = listEventFiles().map((f) => f.e).filter(Boolean);
  const { candidates, items } = planReports(events, Date.now(), max);
  const groups = Object.fromEntries(TIERS.map((t) => [t, items.filter((e) => tier(e) === t)]));
  const counts = TIERS.map((t) => `${t} ${groups[t].length}`).join(", ");
  writeJson(join(DATA, "report-plan.json"), { planned_at: nowIso(), candidates, max, counts: Object.fromEntries(TIERS.map((t) => [t, groups[t].length])), items: items.map((e) => ({ id: e.id, tier: tier(e), title: e.title, read_depth: e.report.read_depth, url: ((e.sources || [])[0] || {}).url || "" })) });
  console.log(`REPORT PLAN: ${items.length} of ${candidates} document(s) to read (${counts}); order: Critical, High, Routine, newest first.`);
  for (const t of TIERS) {
    if (!groups[t].length) continue;
    console.log(`${t[0].toUpperCase() + t.slice(1)} (${groups[t].length}):`);
    groups[t].forEach((e) => console.log(`  ${e.id}  [${e.report.read_depth}] ${String(e.title).slice(0, 90)}`));
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
