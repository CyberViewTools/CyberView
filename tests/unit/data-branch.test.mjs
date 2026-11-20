// End-to-end rehearsal of the code/data branch split in throwaway repositories (no network, no deploy).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, cpSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mergeFile } from "../../scripts/data-branch.mjs";

const REPO = join(import.meta.dirname, "..", "..");
const sh = (cwd, cmd, args, env = {}) => { const r = spawnSync(cmd, args, { cwd, encoding: "utf8", env: { ...process.env, CYBERVIEW_NO_DEPLOY: "1", GIT_SYNC_TRIES: "2", ...env } }); return r; };
const git = (cwd, ...a) => sh(cwd, "git", a);
const id = (cwd) => { git(cwd, "config", "user.email", "t@example.invalid"); git(cwd, "config", "user.name", "t"); };

function world() {
  const w = mkdtempSync(join(tmpdir(), "cv-databranch-")), origin = join(w, "origin.git"), seed = join(w, "seed");
  git(w, "init", "-q", "--bare", "-b", "main", origin);
  mkdirSync(join(seed, "data", "leads"), { recursive: true });
  git(w, "init", "-q", "-b", "main", seed); id(seed);
  cpSync(join(REPO, "scripts"), join(seed, "scripts"), { recursive: true });
  writeFileSync(join(seed, "package.json"), '{"type":"module"}\n');
  writeFileSync(join(seed, "data", "status.json"), JSON.stringify({ a: 1 }, null, 2) + "\n");
  writeFileSync(join(seed, "data", "leads", "d.jsonl"), '{"n":1}\n');
  git(seed, "add", "-A"); git(seed, "commit", "-q", "-m", "seed");
  git(seed, "remote", "add", "origin", origin); git(seed, "push", "-q", "origin", "main");
  const clone = (name) => { const d = join(w, name); git(w, "clone", "-q", origin, d); id(d); return d; };
  return { w, origin, seed, clone };
}

test("data branch: pure merge keeps both sides", () => {
  assert.equal(mergeFile("x.jsonl", '{"n":1}\n', '{"n":1}\n{"n":2}\n', '{"n":1}\n{"n":3}\n'), '{"n":1}\n{"n":2}\n{"n":3}\n');
  assert.deepEqual(JSON.parse(mergeFile("s.json", '{"a":1}', '{"a":1,"b":2}', '{"a":5}')), { a: 5, b: 2 });
  assert.equal(mergeFile("x.txt", "old", "theirs", "old"), "theirs");
  assert.equal(mergeFile("x.txt", null, null, "mine"), "mine");
});

test("data branch: create, switch a checkout (carrying uncommitted data), push data, forward an old-layout push", () => {
  const { origin, clone } = world();
  const A = clone("A"), B = clone("B");
  // 1. create the data branch from main's data/, with its history
  let r = sh(A, "node", ["scripts/data-branch.mjs", "create"]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(git(A, "ls-remote", "--heads", origin, "data").stdout.includes("refs/heads/data"), true);
  // 2. A has an uncommitted lead and status change, then switches layout
  writeFileSync(join(A, "data", "leads", "d.jsonl"), '{"n":1}\n{"n":2}\n');
  writeFileSync(join(A, "data", "status.json"), JSON.stringify({ a: 1, mine: true }, null, 2) + "\n");
  r = sh(A, "node", ["scripts/data-branch.mjs", "ensure"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /switched/);
  assert.equal(git(join(A, "data"), "rev-parse", "--abbrev-ref", "HEAD").stdout.trim(), "data");
  assert.equal(readFileSync(join(A, "data", "leads", "d.jsonl"), "utf8"), '{"n":1}\n{"n":2}\n', "uncommitted lead carried over");
  assert.equal(JSON.parse(readFileSync(join(A, "data", "status.json"), "utf8")).mine, true);
  assert.equal(git(A, "status", "--porcelain").stdout.trim(), "", "main is clean: its own data/ is not checked out");
  // 3. A commits data with the same helper every job uses: it lands on origin/data, not main
  r = sh(A, "node", ["-e", 'import("./scripts/lib/repo.mjs").then(m=>{const x=m.commitData("data: test",["data/leads","data/status.json"]);process.exit(x.committed&&x.pushed?0:1)})']);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(git(A, "--git-dir", origin, "show", "data:leads/d.jsonl").stdout, /"n":2/);
  assert.doesNotMatch(git(A, "--git-dir", origin, "show", "main:data/leads/d.jsonl").stdout, /"n":2/, "main is untouched");
  // 4. B still has the old layout and pushes data to main the old way; forward brings it onto the data branch
  writeFileSync(join(B, "data", "leads", "d.jsonl"), '{"n":1}\n{"n":9}\n');
  git(B, "add", "-A"); git(B, "commit", "-q", "-m", "data: old style"); assert.equal(git(B, "push", "-q", "origin", "main").status, 0);
  const D = clone("D"); git(D, "switch", "-q", "data");
  const M = clone("M");
  r = sh(M, "node", ["scripts/data-branch.mjs", "forward", "--main", M, "--data", D]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const merged = readFileSync(join(D, "leads", "d.jsonl"), "utf8");
  assert.ok(merged.includes('"n":2') && merged.includes('"n":9'), merged);
  // forwarding again changes nothing
  git(D, "add", "-A"); git(D, "commit", "-q", "-m", "fwd");
  r = sh(M, "node", ["scripts/data-branch.mjs", "forward", "--main", M, "--data", D]);
  assert.match(r.stdout, /up to date/);
  // 5. ensure on an already-switched checkout does nothing
  assert.match(sh(A, "node", ["scripts/data-branch.mjs", "ensure"]).stdout, /already/);
});
