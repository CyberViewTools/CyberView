// Prints the full prompt for one scheduled AI job: the shared preamble from docs/jobs.md, a blank line,
// then that job's section. docs/jobs.md stays the single source of truth for every job's instructions.
// Usage: node scripts/job-prompt.mjs <job>   (sweep, verify, report-review, analysis, deep-sweep, brief, watchdog,
//        security-review, triage, regional, followup, steward, tabletop, advisory, moderator, scout, editor, guardian, review)
// For the triage desk and the sweep it first runs the no-AI housekeeping (start overdue workflows, collect feeds,
// clear obvious leads), so that work happens every run whether or not the agent remembers it.
// Set NO_HOUSEKEEPING=1 to skip it (the GitHub Actions fallback does).
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { ROOT, DATA, readJson, listEventFiles } from "./lib/store.mjs";

const HEADINGS = {
  "sweep": "Sweep", "verify": "Verify", "report-review": "Report review", "analysis": "Analysis",
  "deep-sweep": "Deep sweep", "analyst": "Exploit analyst", "improver": "Improver", "brief": "Brief", "watchdog": "Watchdog", "security-review": "Security review", "triage": "Triage desk", "regional": "Regional desk", "followup": "Follow-up desk", "steward": "Data steward", "tabletop": "Tabletop", "advisory": "Advisory desk", "moderator": "Moderator", "scout": "Source scout", "editor": "Editor", "guardian": "Guardian", "review": "Review desk",
  // workers: started by the dispatcher (scripts/dispatch.mjs), one per batch; they never run git
  "researcher": "Researcher", "backlog-triager": "Backlog triager", "exploit-analyst": "Exploit analyst", "gap": "Gap researcher", "reviewer": "Reviewer", "updater": "Updater", "grid": "Grid researcher", "regional-researcher": "Regional researcher",
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
} else if (job === "exploit-analyst") {
  const plan = readJson(join(DATA, "analyst-plan.json"), { batches: [] }), mine = (plan.batches || [])[Number(batch) - 1] || [];
  assignment = `YOUR ASSIGNMENT (exploit analyst ${batch}): ${mine.length} flaw(s):\n` + mine.map((x) => `  ${x.cve}  ${x.vendor} ${x.product}: ${String(x.name || "").slice(0, 120)}\n      why now: ${x.why}${x.required ? "\n      required action on file: " + String(x.required).slice(0, 240) : ""}${(x.refs || []).length ? "\n      references on file: " + x.refs.join(" ") : ""}${(x.fix || []).length ? `\n      FIX ONLY: data/analyses/${x.cve}.json is on file but breaks these rules, so the workbench leaves it out. Correct those fields (shorten, split or drop items) from the sources it already cites; do not redo the research:\n        - ` + x.fix.map((m) => String(m).slice(0, 200)).join("\n        - ") : ""}`).join("\n") + (mine.length ? "" : "\n  (none: end with \"exploit analyst " + batch + ": nothing assigned\")")
    + (mine.length ? `\nBEFORE YOU FINISH: run \`node scripts/analyst.mjs check ${mine.map((x) => x.cve).join(" ")}\` and fix every problem it prints (the build does not stop on these; an analysis that fails this check is left out of the workbench and handed out again). Rerun until it says they are valid, or log the CVE as skipped with the reason.` : "");
} else if (job === "backlog-triager") {
  const plan = readJson(join(DATA, "backlog-plan.json"), { batches: [] }), mine = (plan.batches || [])[Number(batch) - 1] || [];
  assignment = `YOUR ASSIGNMENT (backlog triager ${batch}): ${mine.length} stories. Answers file: ${join(DATA, "backlog-triage-" + batch + ".json")}\n`
    + mine.map((s) => `  ${s.id}  ${String(s.title).slice(0, 150)}  [${s.publishers} publisher${s.publishers === 1 ? "" : "s"}: ${(s.sources || []).join(", ").slice(0, 70)}${(s.kinds || []).includes("exploited") ? "; exploited" : ""}${(s.langs || []).some((l) => l && l !== "en") ? "; " + s.langs.join("/") : ""}; published ${String(s.published).slice(5, 16)}${s.dated ? "" : " (date not given)"}]`).join("\n");
} else if (job === "updater") {
  const pf = /^update-plan(-[A-Za-z0-9-]+)?\.json$/.test(process.env.CYBERVIEW_UPDATE_PLAN || "") ? process.env.CYBERVIEW_UPDATE_PLAN : "update-plan.json";
  const plan = readJson(join(DATA, pf), { batches: [] }), mine = (plan.batches || [])[Number(batch) - 1] || [];
  assignment = `YOUR ASSIGNMENT (updater ${batch}): ${mine.length} event(s) with new reporting:\n` + mine.map((c) => `  ${c.id}  [severity ${c.severity}${c.status ? ", " + c.status : ""}] ${c.title}\n` + (c.leads || []).map((l) => `     - ${l.source}${l.tier ? " (" + l.tier + ")" : ""}, ${String(l.published).slice(0, 16)}: ${l.title}\n       ${l.url}`).join("\n")).join("\n") + (mine.length ? "" : "\n  (none: end with \"updater " + batch + ": nothing assigned\")");
} else if (job === "grid") {
  const pf = /^grid-plan(-[A-Za-z0-9-]+)?\.json$/.test(process.env.CYBERVIEW_GRID_PLAN || "") ? process.env.CYBERVIEW_GRID_PLAN : "grid-plan.json";
  const plan = readJson(join(DATA, pf), { batches: [] }), b = (plan.batches || [])[Number(batch) - 1] || { incidents: [] }, mine = b.incidents || [];
  const n = (x) => (x == null ? "?" : Number(x).toLocaleString("en-US"));
  assignment = `YOUR ASSIGNMENT (grid researcher ${batch}): plan_id ${plan.plan_id || "?"}, batch ${b.batch ?? batch}. Out file: data/${b.out || "grid-out-" + batch + ".json"}\n${mine.length} grid incident(s), biggest first:\n`
    + mine.map((i) => `  ${i.id}  ${i.name}\n      ${i.country}, ${i.region}; ${i.kind}${i.level != null ? ", level " + i.level : ""}; peak ${n(i.peak_customers)} customers at ${i.peak_at || "?"}; opened ${i.opened_at}${i.closed_at ? ", closed " + i.closed_at : " (still open)"}; planned share ${i.planned_share ?? "?"}; why: ${i.research_reason}`
      + `\n      causes as the operator reports them: ${(i.causes || []).map((c) => `${c.cause || "(none given)"} (${n(c.customers)})`).join("; ") || "none given"}\n      operator page: ${i.url || "none"}`
      + (i.earlier ? `\n      earlier try ${i.earlier.tries}: ${i.earlier.decision}: ${i.earlier.cause_summary}${(i.earlier.sources || []).length ? " [" + i.earlier.sources.join(" ") + "]" : ""}` : "")).join("\n")
    + (mine.length ? "" : "\n  (none: end with \"grid researcher " + batch + ": nothing assigned\")");
} else if (job === "reviewer") {
  const pf = /^review-plan(-[A-Za-z0-9-]+)?\.json$/.test(process.env.CYBERVIEW_REVIEW_PLAN || "") ? process.env.CYBERVIEW_REVIEW_PLAN : "review-plan.json";
  const plan = readJson(join(DATA, pf), { batches: [] }), mine = (plan.batches || [])[Number(batch) - 1] || [];
  assignment = `YOUR ASSIGNMENT (reviewer ${batch}): ${mine.length} events:\n` + mine.map((id) => `  ${id}`).join("\n") + (mine.length ? "" : "\n  (none: end with \"reviewer " + batch + ": nothing assigned\")");
} else if (job === "gap") {
  // the focus rotates by rule with every run and every worker, so two runs in a row never search the same ground
  const FOCUS = [
    ["Western and Northern Europe", "French, German, Dutch or a Nordic language"], ["Latin America and the Caribbean", "Spanish or Portuguese"],
    ["East Asia (Japan, South Korea, Taiwan, China, Hong Kong)", "Japanese, Korean or Chinese"], ["Africa", "French, Arabic, Portuguese or Swahili"],
    ["United States and Canada: state, city, county, school and hospital level", "English or French"], ["The Middle East and Turkey", "Arabic, Turkish, Hebrew or Farsi"],
    ["South Asia (India, Pakistan, Bangladesh, Sri Lanka, Nepal)", "Hindi, Urdu or Bengali"], ["Southern and Eastern Europe", "Italian, Spanish, Polish, Czech, Romanian or Greek"],
    ["Southeast Asia and Oceania", "Indonesian, Malay, Thai, Vietnamese or Filipino"], ["Ukraine, Russia, the Caucasus and Central Asia", "Ukrainian or Russian"],
  ];
  const SECTOR = ["hospitals and health services", "banks, payments and insurers", "energy, water and utilities", "airports, airlines, rail, ports and logistics", "telecoms and internet providers", "national and local government", "schools and universities", "manufacturing and retail", "cloud, software and IT service providers"];
  const n = Math.max(1, Number(batch) || 1), slot = Math.floor(Date.now() / 18e5), f = FOCUS[(slot * 3 + (n - 1) * 5) % FOCUS.length], sec = SECTOR[(slot + (n - 1) * 4) % SECTOR.length];
  const since = Date.now() - 12 * 36e5, searched = [], runsDir = join(DATA, "runs");
  if (existsSync(runsDir)) for (const d of readdirSync(runsDir).sort().slice(-2)) for (const fn of readdirSync(join(runsDir, d)).filter((x) => /sweep-gap/.test(x))) {
    const r = readJson(join(runsDir, d, fn), {}); if (Date.parse(r.started_at || r.finished_at || 0) < since) continue;
    (r.searches || []).forEach((q) => searched.push(String(typeof q === "string" ? q : (q && (q.query || q.q)) || "").slice(0, 90)));
  }
  const onFile = listEventFiles().map((x) => x.e).filter((e) => e && !e.duplicate_of && Date.parse(e.first_seen || 0) > Date.now() - 36 * 36e5).sort((x, y) => String(x.first_seen).localeCompare(String(y.first_seen))).map((e) => String(e.title).slice(0, 90));
  assignment = `YOUR ASSIGNMENT (gap researcher ${n}):\n  Region in depth: ${f[0]}. At least half of your region searches in ${f[1]}.\n  Sector for the headline pass: ${sec} (plus anything major you come across).\n`
    + `  Run log file name: <HHMM>-sweep-gap${n > 1 ? "-" + n : ""}.json\n`
    + (searched.length ? `  Searches the gap researchers already ran in the last 12 hours (do not repeat them; word yours differently):\n${[...new Set(searched.filter(Boolean))].slice(-24).map((q) => "    - " + q).join("\n")}\n` : "")
    + (onFile.length ? `  Added to the map in the last 36 hours (already on file: do not research these again, only add what is NOT here):\n${onFile.slice(-70).map((t) => "    - " + t).join("\n")}\n` : "");
} else if (job === "regional-researcher") {
  const G = { a: "Africa (africa); the Middle East and Turkey (middle-east)", b: "Latin America and the Caribbean (latin-america)", c: "South Asia (south-asia); Southeast Asia (southeast-asia); Oceania (oceania)" };
  assignment = `YOUR ASSIGNMENT (regional researcher ${batch}): ${G[batch] || G.a}. The region names in brackets are the ones fuse.mjs --region understands.`;
}
// The shared preamble is cut to what each role needs: every worker gets the core rules; only roles that write events get
// the event checklist; only web researchers get the search guidance; workers (and every job run by scripts/run-job.mjs,
// --worker) get no git SETUP or FINISH, because a script commits for them. Context is cost: a triager does not need
// eight thousand characters about writing events.
const worker = process.argv.includes("--worker") || !!batch || process.env.CYBERVIEW_WORKER === "1";
const PROFILE = {
  "backlog-triager": ["core"], "exploit-analyst": ["core", "web", "log"], "moderator": ["core", "log"],
  "reviewer": ["core", "events", "web", "log"], "updater": ["core", "events", "web", "log"], "grid": ["core", "web", "log"], "researcher": ["core", "search", "events", "web", "log"], "gap": ["core", "search", "events", "web", "log"],
  "regional-researcher": ["core", "search", "events", "web", "log"],
  "analysis": ["core", "log"], "brief": ["core", "log"], "tabletop": ["core", "log"], "editor": ["core", "log"], "security-review": ["core", "log"], "improver": ["core", "log"],
  "watchdog": ["core", "web", "log"], "advisory": ["core", "web", "log"], "scout": ["core", "search", "web", "log"], "triage": ["core", "log"],
};
const KIND = (first) => /^You maintain|^UNTRUSTED TEXT|^SAVE CONTEXT/.test(first) ? "core" : /^HOW EVERY JOB/.test(first) ? "core" : /^ONE SEARCH ENGINE/.test(first) ? "search"
  : /^THE EVENT CHECKLIST|^WRITING DATA/.test(first) ? "events" : /^RETRIES/.test(first) ? "web" : /^RUN LOG/.test(first) ? "log" : /^SETUP|^FINISH/.test(first) ? "full" : "core";
const parts = block("Shared preamble").split(/\n\s*\n/), want = new Set((PROFILE[job] || ["core", "search", "events", "web", "log"]).concat(worker ? [] : ["full"]));
let pre = parts.filter((p) => want.has(KIND(p.trim().split("\n")[0]))).join("\n\n");
if (worker) pre += "\n\nWORKER: you are one of several workers started by a script. Do NOT run any git command and do not edit data/status.json; the script commits after you. Finish with your run log and a passing `node scripts/build.mjs` where your instructions ask for it.";
process.stdout.write(pre + "\n\n" + block(HEADINGS[job]) + "\n" + (assignment ? "\n" + assignment + "\n" : ""));
