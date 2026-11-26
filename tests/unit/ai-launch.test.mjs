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

test("ai-launch.yml signs in with the subscription token, keeps every other scheduled job off until AI_LAUNCH is set, and runs only the Library on the API key regardless", () => {
  assert.match(yml, /CLAUDE_CODE_OAUTH_TOKEN: \$\{\{ secrets\.CLAUDE_CODE_OAUTH_TOKEN \}\}/);
  assert.doesNotMatch(yml, /secrets\.ANTHROPIC_API_KEY/);
  assert.match(yml, /unset ANTHROPIC_API_KEY/);
  assert.match(yml, /AI_LAUNCH: \$\{\{ vars\.AI_LAUNCH \}\}/);
  assert.match(yml, /if \[ "\$EVENT" = schedule \] && \[ "\$job" != library \] && \[ "\$AI_LAUNCH" != actions \]; then/);
  const opts = (yml.match(/options: \[([^\]]+)\]/) || [])[1].split(",").map((s) => s.trim());
  assert.deepEqual([...opts].sort(), [...new Set(cases.values())].sort());
  // the Library (owner, 2026-11-26): its own schedule runs whatever AI_LAUNCH says, gated on the API key, never the subscription token
  const lib = [...cases].find(([, j]) => j === "library"); assert.ok(lib, "the Library has a schedule");
  assert.match(yml, /if \[ "\$job" = library \]; then ready=\$HAS_KEY; else ready=\$HAS_OAUTH; fi/);
  assert.match(yml, /if \[ "\$JOB" = library \]; then unset CLAUDE_CODE_OAUTH_TOKEN; fi/);
});
