// .github/workflows/ai-launch.yml starts the AI jobs on a GitHub runner; its schedules must stay equal to routines.json
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const yml = readFileSync(new URL("../../.github/workflows/ai-launch.yml", import.meta.url), "utf8");
const routines = JSON.parse(readFileSync(new URL("../../routines.json", import.meta.url), "utf8")).routines;
const crons = [...yml.matchAll(/^\s*- cron: "([^"]+)"/gm)].map((m) => m[1]);
const cases = new Map([...yml.matchAll(/^\s*"([^"]+)"\)\s+job=([a-z-]+) ;;/gm)].map((m) => [m[1], m[2]]));

test("every schedule in ai-launch.yml picks a job, and each job's cron equals routines.json", () => {
  assert.ok(crons.length >= 15);
  for (const c of crons) {
    const job = cases.get(c); assert.ok(job, `cron "${c}" has no job in the Pick step`);
    const r = routines.find((x) => x.key === job); assert.ok(r, `${job} is not in routines.json`);
    assert.equal(r.tier, "ai"); assert.notEqual(r.active, false, `${job} is retired`);
    assert.equal(r.cron, c, `${job}: routines.json says ${r.cron}`);
  }
  assert.equal(new Set(cases.values()).size, cases.size, "a job is scheduled twice");
});

test("ai-launch.yml signs in with the subscription token, keeps every other scheduled job off until AI_LAUNCH is set, and sends the workspace header", () => {
  assert.match(yml, /CLAUDE_CODE_OAUTH_TOKEN: \$\{\{ secrets\.CLAUDE_CODE_OAUTH_TOKEN \}\}/);
  assert.doesNotMatch(yml, /secrets\.ANTHROPIC_API_KEY/);
  assert.match(yml, /unset ANTHROPIC_API_KEY/);
  assert.match(yml, /AI_LAUNCH: \$\{\{ vars\.AI_LAUNCH \}\}/);
  // scheduled runs (#214 + #215): the Library always; the web-independent jobs only once AI_LAUNCH is "actions";
  // the web jobs never (runner IPs get bot-challenged on core sources, so they stay on the cloud launchers)
  assert.match(yml, /if \[ "\$EVENT" = schedule \] && \[ "\$job" != library \]; then/);
  const webFree = (yml.match(/^\s*([a-z|-]+)\)\n\s*if \[ "\$AI_LAUNCH" != actions \]; then/m) || [])[1];
  assert.ok(webFree, "the web-independent jobs wait for AI_LAUNCH");
  assert.deepEqual(webFree.split("|").sort(), ["analysis", "brief", "improver", "security-review", "tabletop", "triage"]);
  assert.match(yml, /\*\)\n\s*echo "READY=off" >> "\$GITHUB_ENV"; echo "Job: \$job runs on the cloud launcher/);
  const opts = (yml.match(/options: \[([^\]]+)\]/) || [])[1].split(",").map((s) => s.trim());
  assert.deepEqual([...opts].sort(), [...new Set(cases.values())].sort());
  // the Library moved to its own workflow, library.yml (GitHub never started its slot among these 16 schedules)
  assert.ok(![...cases.values()].includes("library"), "the Library is not scheduled in ai-launch.yml");
  // a key that belongs to no workspace needs the anthropic-workspace-id header
  assert.match(yml, /WORKSPACE_ID: \$\{\{ vars\.ANTHROPIC_WORKSPACE_ID \}\}/);
  assert.match(yml, /export ANTHROPIC_CUSTOM_HEADERS="anthropic-workspace-id: \$WORKSPACE_ID"/);
});

const lib = readFileSync(new URL("../../.github/workflows/library.yml", import.meta.url), "utf8");
test("library.yml: one schedule equal to routines.json, the API key only, the workspace header", () => {
  const c = [...lib.matchAll(/^\s*- cron: "([^"]+)"/gm)].map((m) => m[1]);
  assert.deepEqual(c, [routines.find((r) => r.key === "library").cron]);
  assert.match(lib, /workflow_dispatch:/);
  assert.match(lib, /HAS_KEY: \$\{\{ secrets\.CYBERVIEW_FALLBACK_ANTHROPIC_API_KEY != '' \}\}/);
  assert.doesNotMatch(lib, /secrets\.CLAUDE_CODE_OAUTH_TOKEN|secrets\.ANTHROPIC_API_KEY/);
  assert.match(lib, /unset ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN/);
  assert.match(lib, /export ANTHROPIC_CUSTOM_HEADERS="anthropic-workspace-id: \$WORKSPACE_ID"/);
  assert.match(lib, /node scripts\/dispatch\.mjs library --exec/);
});
