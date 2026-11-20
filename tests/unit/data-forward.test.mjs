// .github/workflows/data-forward.yml: its forward step, run as written in throwaway repositories (no network, no
// deploy): data pushed to main the old way reaches the data branch, a race with another writer is retried, and a run
// with nothing new changes nothing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, appendFileSync, cpSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const REPO = join(import.meta.dirname, "..", "..");
const YML = readFileSync(join(REPO, ".github", "workflows", "data-forward.yml"), "utf8");
const ENV = { ...process.env, CYBERVIEW_NO_DEPLOY: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid" };
const sh = (cwd, cmd, args, env = {}) => spawnSync(cmd, args, { cwd, encoding: "utf8", env: { ...ENV, ...env } });
const git = (cwd, ...a) => sh(cwd, "git", a);

/** The forward step's script, exactly as the workflow runs it. */
function forwardStep() {
  const m = /id: fwd\n[\s\S]*?run: \|\n([\s\S]*?)\n      - name:/.exec(YML);
  assert.ok(m, "forward step found");
  return m[1].split("\n").map((l) => l.replace(/^ {10}/, "")).join("\n") + "\n";
}
const outputs = (p) => Object.fromEntries(readFileSync(p, "utf8").split("\n").filter(Boolean).map((l) => l.split("=")));

test("data-forward: triggers and permissions", () => {
  assert.match(YML, /push:\n\s+branches: \[main\]\n\s+paths: \["data\/\*\*"\]/);
  assert.match(YML, /schedule:/);
  assert.match(YML, /workflow_dispatch:/);
  assert.match(YML, /contents: write/);
  assert.match(YML, /actions: write/);
  assert.match(YML, /group: data-writes/);
  assert.match(YML, /fetch-depth: 0/);
});

test("data-forward: forwards an old-layout push, retries a lost race, then is idempotent", () => {
  const w = mkdtempSync(join(tmpdir(), "cv-forward-")), origin = join(w, "origin.git"), seed = join(w, "seed");
  git(w, "init", "-q", "--bare", "-b", "main", origin);
  mkdirSync(join(seed, "data", "leads"), { recursive: true });
  git(w, "init", "-q", "-b", "main", seed);
  cpSync(join(REPO, "scripts"), join(seed, "scripts"), { recursive: true });
  writeFileSync(join(seed, "package.json"), '{"type":"module"}\n');
  writeFileSync(join(seed, "data", "status.json"), '{"a":1}\n');
  writeFileSync(join(seed, "data", "leads", "d.jsonl"), '{"n":1}\n');
  git(seed, "add", "-A"); git(seed, "commit", "-q", "-m", "seed");
  git(seed, "remote", "add", "origin", origin); git(seed, "push", "-q", "origin", "main");
  let r = sh(seed, "node", ["scripts/data-branch.mjs", "create"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  git(seed, "pull", "-q", "origin", "main");
  // an old checkout pushes data to main, then a code change lands
  appendFileSync(join(seed, "data", "leads", "d.jsonl"), '{"n":9}\n');
  git(seed, "commit", "-q", "-am", "data: old layout");
  writeFileSync(join(seed, "code.txt"), "x\n"); git(seed, "add", "code.txt"); git(seed, "commit", "-q", "-m", "code");
  assert.equal(git(seed, "push", "-q", "origin", "main").status, 0);
  // the workflow's two checkouts: main with history, the data branch (one commit) at .data-branch
  const M = join(w, "M");
  git(w, "clone", "-q", origin, M);
  git(w, "clone", "-q", "--depth", "1", "-b", "data", `file://${origin}`, join(M, ".data-branch"));
  // another writer pushes to the data branch after the checkout: the first push must lose and be retried
  const R = join(w, "R");
  git(w, "clone", "-q", "-b", "data", origin, R);
  appendFileSync(join(R, "leads", "d.jsonl"), '{"n":5}\n');
  git(R, "commit", "-q", "-am", "data: racing writer"); assert.equal(git(R, "push", "-q", "origin", "data").status, 0);

  const out = join(w, "out"), step = join(w, "step.sh");
  writeFileSync(step, forwardStep()); writeFileSync(out, "");
  const env = { D: ".data-branch", RUNNER_TEMP: w, GITHUB_OUTPUT: out };
  r = sh(M, "bash", ["-eo", "pipefail", step], env);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /lost a race/);
  assert.deepEqual(outputs(out), { pushed: "1", deploy: "1" });
  const leads = git(w, "--git-dir", origin, "show", "data:leads/d.jsonl").stdout;
  assert.ok(leads.includes('"n":9') && leads.includes('"n":5'), leads);
  assert.equal(git(w, "--git-dir", origin, "show", "data:.forwarded").stdout.trim(), git(M, "rev-parse", "HEAD").stdout.trim());

  // a second run finds nothing to do: no commit, no deploy
  writeFileSync(out, "");
  r = sh(M, "bash", ["-eo", "pipefail", step], env);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /Nothing to forward|up to date/);
  assert.deepEqual(outputs(out), {});
});

test("data-forward: a forward that moves only the mark or leases asks for no deploy", () => {
  const m = /if grep -vqE '([^']+)'/.exec(forwardStep());
  assert.ok(m);
  const re = new RegExp(m[1]);
  assert.equal([".forwarded", "leases.json", "usage/2026-11.jsonl"].some((f) => !re.test(f)), false);
  assert.equal(re.test("leads/2026-11-20.jsonl"), false);
});
