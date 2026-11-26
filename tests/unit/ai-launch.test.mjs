// GitHub Actions launchers (owner 2026-11-26): ai-launch.yml is manual only; each scheduled web-independent job has its own
// workflow with one schedule (job-<job>.yml, shared steps in ai-job.yml); the Library has library.yml.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";

const W = new URL("../../.github/workflows/", import.meta.url);
const read = (f) => readFileSync(new URL(f, W), "utf8");
const yml = read("ai-launch.yml"), shared = read("ai-job.yml");
const routines = JSON.parse(readFileSync(new URL("../../routines.json", import.meta.url), "utf8")).routines;
const ON_ACTIONS = ["analysis", "brief", "improver", "security-review", "tabletop", "triage"];

test("ai-launch.yml is manual only: no schedule, any job (and the Library) by Run workflow", () => {
  assert.doesNotMatch(yml, /^\s*schedule:/m);
  assert.doesNotMatch(yml, /- cron:/);
  const opts = (yml.match(/options: \[([^\]]+)\]/) || [])[1].split(",").map((s) => s.trim());
  for (const j of [...ON_ACTIONS, "sweep", "library"]) assert.ok(opts.includes(j), j);
  assert.match(yml, /unset ANTHROPIC_API_KEY/);
  assert.doesNotMatch(yml, /secrets\.ANTHROPIC_API_KEY/);
  assert.match(yml, /export ANTHROPIC_CUSTOM_HEADERS="anthropic-workspace-id: \$WORKSPACE_ID"/);
  assert.match(yml, /if \[ "\$JOB" = library \]; then unset CLAUDE_CODE_OAUTH_TOKEN; fi/);
});

test("each web-independent job has one workflow with one schedule equal to routines.json, calling ai-job.yml", () => {
  const files = readdirSync(W).filter((f) => /^job-.+\.yml$/.test(f)).sort();
  assert.deepEqual(files, ON_ACTIONS.map((j) => `job-${j}.yml`).sort());
  for (const j of ON_ACTIONS) {
    const f = read(`job-${j}.yml`), c = [...f.matchAll(/^\s*- cron: "([^"]+)"/gm)].map((m) => m[1]);
    const r = routines.find((x) => x.key === j);
    assert.ok(r && r.active !== false, `${j} is an active routine`);
    assert.deepEqual(c, [r.cron], `${j}: one schedule, equal to routines.json`);
    assert.match(f, /workflow_dispatch:/);
    assert.match(f, /uses: \.\/\.github\/workflows\/ai-job\.yml/);
    assert.ok(f.includes(`job: ${j}`));
    assert.match(f, /secrets: inherit/);
  }
});

test("ai-job.yml: the key or the subscription token, the workspace header, one dispatch call", () => {
  assert.match(shared, /workflow_call:/);
  assert.match(shared, /HAS_KEY: \$\{\{ secrets\.CYBERVIEW_FALLBACK_ANTHROPIC_API_KEY != '' \}\}/);
  assert.match(shared, /unset ANTHROPIC_API_KEY/);
  assert.doesNotMatch(shared, /secrets\.ANTHROPIC_API_KEY/);
  assert.match(shared, /export ANTHROPIC_CUSTOM_HEADERS="anthropic-workspace-id: \$WORKSPACE_ID"/);
  assert.match(shared, /node scripts\/dispatch\.mjs "\$JOB" --exec/);
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
