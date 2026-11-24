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

test("ai-launch.yml signs in with the subscription token only and stays off until AI_LAUNCH is set", () => {
  assert.match(yml, /CLAUDE_CODE_OAUTH_TOKEN: \$\{\{ secrets\.CLAUDE_CODE_OAUTH_TOKEN \}\}/);
  assert.doesNotMatch(yml, /secrets\.ANTHROPIC_API_KEY/);
  assert.match(yml, /unset ANTHROPIC_API_KEY/);
  assert.match(yml, /vars\.AI_LAUNCH == 'actions'/);
  // the manual choices are exactly the scheduled jobs
  const opts = (yml.match(/options: \[([^\]]+)\]/) || [])[1].split(",").map((s) => s.trim());
  assert.deepEqual([...opts].sort(), [...new Set(cases.values())].sort());
});
