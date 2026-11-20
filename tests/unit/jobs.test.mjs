// Unit tests for the AI routines registry (routines.json), the job instructions (docs/jobs.md) and scripts/job-prompt.mjs:
// every active AI routine has instructions in the standard format, every retired one says why and where its duties went
// and prints only a retired notice, and the gap researchers' focus follows the owner's coverage priorities.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const REG = JSON.parse(readFileSync(join(ROOT, "routines.json"), "utf8")).routines;
const AI = REG.filter((r) => r.tier === "ai");
const MD = readFileSync(join(ROOT, "docs", "jobs.md"), "utf8");
const prompt = (args, env = {}) => spawnSync("node", [join(ROOT, "scripts", "job-prompt.mjs"), ...args], { cwd: ROOT, encoding: "utf8", timeout: 60000, env: { ...process.env, NO_HOUSEKEEPING: "1", ...env } });

test("routines: the 22 AI routines are all still listed, active or retired", () => {
  const keys = AI.map((r) => r.key).sort();
  assert.deepEqual(keys, ["advisory", "analysis", "analyst", "backlog", "brief", "deep-sweep", "editor", "followup", "guardian", "improver", "moderator", "regional", "report-review", "review", "scout", "security-review", "steward", "sweep", "tabletop", "triage", "verify", "watchdog"]);
});

test("routines: a retired routine says why, with evidence, and names an active routine that took its duties", () => {
  const active = new Set(AI.filter((r) => r.active !== false).map((r) => r.key));
  for (const r of AI.filter((x) => x.active === false)) {
    assert.match(String(r.retired || ""), /^\d{4}-\d{2}-\d{2}: .{60,}/, `${r.key}: retired needs the date and the evidence`);
    const to = String(r.merged_into || "").split(/,\s*/).filter(Boolean);
    assert.ok(to.length, `${r.key}: merged_into is empty`);
    for (const k of to) assert.ok(active.has(k), `${r.key}: merged_into "${k}" is not an active AI routine`);
    assert.ok(MD.includes("## Retired routines") && new RegExp(`\\| ${r.name.replace(/[()]/g, "\\$&")} \\(`).test(MD), `${r.key}: no row in docs/jobs.md Retired routines`);
  }
});

test("routines: the guardian, second review, moderator and the four research restarts stay active", () => {
  const on = (k) => AI.find((r) => r.key === k).active !== false;
  for (const k of ["guardian", "review", "moderator", "sweep", "verify"]) assert.ok(on(k), `${k} must stay active`);
  assert.equal(AI.find((r) => r.key === "sweep").cron.split(/\s+/)[0].split(",").length, 4, "the four research schedules restart the loop");
});

test("jobs.md: every active scheduled AI routine has a section in the standard format that prints", () => {
  for (const r of AI.filter((x) => x.active !== false)) {
    if (r.key === "backlog") { assert.equal(prompt(["backlog-triager", "--batch", "1"]).status, 0, "the backlog desk's triager section"); continue; }   // planned by scripts, no section of its own
    const p = prompt([r.key, "--worker"]);
    assert.equal(p.status, 0, `${r.key}: job-prompt failed: ${p.stderr}`);
    assert.doesNotMatch(p.stdout, /^RETIRED/, `${r.key} is active but prints a retired notice`);
    assert.match(p.stdout, new RegExp(`JOB: ${r.key === "report-review" ? "report review" : r.key === "security-review" ? "security review" : r.key === "analyst" ? "exploit analyst" : r.key}\\b`), `${r.key}: no JOB line`);
    if (["analyst", "guardian"].includes(r.key)) continue;   // a worker section, and the guardian's own short format
    for (const part of ["GOAL:", "STEPS", "RULES:", "LIMITS:", "DONE WHEN:"]) assert.ok(p.stdout.includes(part), `${r.key}: section lacks ${part}`);
    if (r.status_key && r.key !== "sweep") assert.match(p.stdout, new RegExp(`TIMESTAMP:[^\\n]*${r.status_key}`), `${r.key}: TIMESTAMP does not name ${r.status_key}`);
  }
});

test("job-prompt: a retired routine and the workers only it starts print a retired notice and nothing else", () => {
  for (const r of AI.filter((x) => x.active === false)) {
    const p = prompt([r.key]);
    assert.equal(p.status, 0);
    assert.match(p.stdout, /^RETIRED: /);
    assert.match(p.stdout, new RegExp(`End with exactly: "CyberView ${r.key}: retired, duties moved to ${r.merged_into}"`));
    assert.doesNotMatch(p.stdout, /FINISH|data-commit|THE EVENT CHECKLIST/, `${r.key}: a retired notice must not carry instructions`);
  }
  if (AI.find((r) => r.key === "deep-sweep").active === false) assert.match(prompt(["regional-researcher", "--batch", "a"]).stdout, /^RETIRED: the CyberView "deep-sweep" routine/);
  assert.equal(prompt(["no-such-job"]).status, 1, "an unknown job still fails");
});

test("job-prompt: without lead data the gap rotation follows the coverage priorities and still reaches every region", () => {
  let thin = 0, ci = 0, n = 0;
  for (let slot = 0; slot < 26; slot++) for (const b of ["1", "2"]) {
    const out = prompt(["gap", "--batch", b], { CYBERVIEW_GAP_SLOT: String(slot), CYBERVIEW_GAP_DATA: "0" }).stdout;
    const region = (/Region in depth: (.+?)\. At least half/.exec(out) || [])[1], sector = (/Sector for the headline pass: (.+?) \(plus/.exec(out) || [])[1];
    assert.ok(region && sector, "no region or sector in the assignment");
    n++;
    if (/Africa|Middle East|Turkey|Latin America|Brazil/.test(region)) thin++;
    if (/energy|hospitals|telecoms|airports/.test(sector)) ci++;
  }
  assert.ok(thin / n >= 0.4, `thin regions get ${Math.round((100 * thin) / n)}% of gap focus, want at least 40%`);
  assert.ok(ci / n >= 0.45, `critical infrastructure gets ${Math.round((100 * ci) / n)}% of sectors, want at least 45%`);
  const all = new Set();
  for (let slot = 0; slot < 13; slot++) all.add((/Region in depth: (.+?)\. At least half/.exec(prompt(["gap", "--batch", "1"], { CYBERVIEW_GAP_SLOT: String(slot), CYBERVIEW_GAP_DATA: "0" }).stdout) || [])[1]);
  assert.equal(all.size, 13, "every focus region comes round within 13 slots");
});

test("job-prompt: with lead data the gap region is chosen from it, says why, and turns over between runs", () => {
  const outs = [0, 1, 2].map((slot) => prompt(["gap", "--batch", "1"], { CYBERVIEW_GAP_SLOT: String(slot) }).stdout);
  const regions = outs.map((o) => (/Region in depth: (.+?)\. At least half/.exec(o) || [])[1]);
  for (const r of regions) assert.ok(r, "no region in the assignment");
  if (!outs.some((o) => /chosen from the data: \d+ lead/.test(o))) return;   // no leads in this checkout: the rotation decides (test above)
  assert.ok(outs.every((o) => /chosen from the data: \d+ lead\(s\) from its region in 3 days, \d+ event\(s\) on the map/.test(o)));
  assert.ok(new Set(regions).size >= 2, "three runs in a row searched the same region");
});
