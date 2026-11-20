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

test("data branch: a clone that fetches main only (cloud sessions) still switches and pushes data", () => {
  const { origin, clone } = world();
  const A = clone("A"), C = clone("C");
  assert.equal(sh(A, "node", ["scripts/data-branch.mjs", "create"]).status, 0);
  // narrow C's fetch settings to main only, as a single-branch clone has them, and drop any origin/data it got
  git(C, "config", "--replace-all", "remote.origin.fetch", "+refs/heads/main:refs/remotes/origin/main");
  git(C, "update-ref", "-d", "refs/remotes/origin/data");
  let r = sh(C, "node", ["scripts/data-branch.mjs", "ensure"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /switched/);
  assert.match(git(C, "config", "--get-all", "remote.origin.fetch").stdout, /refs\/heads\/data:refs\/remotes\/origin\/data/);
  writeFileSync(join(C, "data", "leads", "d.jsonl"), '{"n":1}\n{"n":7}\n');
  r = sh(C, "node", ["-e", 'import("./scripts/lib/repo.mjs").then(m=>{const x=m.commitData("data: c",["data/leads"]);process.exit(x.committed&&x.pushed?0:1)})']);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(git(C, "--git-dir", origin, "show", "data:leads/d.jsonl").stdout, /"n":7/);
});

test("data branch: stage B (main drops data/) leaves switched checkouts intact, and an old checkout still switches", () => {
  const { origin, clone } = world();
  const A = clone("A"), D = clone("D"), S = clone("S");
  assert.equal(sh(A, "node", ["scripts/data-branch.mjs", "create"]).status, 0);
  // the data branch ignores working files (as the real one does)
  const W = join(A, "..", "W"); git(A, "worktree", "add", "-q", W, "origin/data");
  git(A, "fetch", "-q", "origin", "+refs/heads/data:refs/remotes/origin/data");
  git(A, "worktree", "remove", "--force", W); git(A, "worktree", "add", "-q", "-b", "wtmp", W, "origin/data"); id(W);
  writeFileSync(join(W, ".gitignore"), "stories.json\n"); git(W, "add", ".gitignore"); git(W, "commit", "-q", "-m", "ignore"); git(W, "push", "-q", "origin", "HEAD:data");
  git(A, "worktree", "remove", "--force", W);
  assert.match(sh(A, "node", ["scripts/data-branch.mjs", "ensure"]).stdout, /switched/);
  // stage B: main removes data/ (from a third clone)
  git(S, "rm", "-r", "-q", "data"); git(S, "commit", "-q", "-m", "stage B"); assert.equal(git(S, "push", "-q", "origin", "main").status, 0);
  // A (switched) pulls: its ./data is untouched and main stays clean
  let r = sh(A, "node", ["-e", 'import("./scripts/lib/repo.mjs").then(m=>m.pullAll())']);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(git(A, "log", "-1", "--format=%s").stdout.trim(), "stage B");
  assert.equal(existsSync(join(A, "data", "status.json")), true, "the data branch checkout survives main dropping data/");
  assert.equal(git(A, "status", "--porcelain").stdout.trim(), "");
  // D never switched; it has a working file and an uncommitted lead, then switches after stage B
  writeFileSync(join(D, "data", "stories.json"), '{"working":1}\n');
  writeFileSync(join(D, "data", "leads", "d.jsonl"), '{"n":1}\n{"n":4}\n');
  r = sh(D, "node", ["scripts/data-branch.mjs", "ensure"]);
  assert.match(r.stdout, /switched/, r.stdout + r.stderr);
  assert.equal(readFileSync(join(D, "data", "stories.json"), "utf8"), '{"working":1}\n', "working file kept on disk");
  assert.equal(git(join(D, "data"), "status", "--porcelain", "--", "stories.json").stdout.trim(), "", "and ignored, never committed");
  assert.match(readFileSync(join(D, "data", "leads", "d.jsonl"), "utf8"), /"n":4/, "uncommitted data still carried over");
});

test("data branch: deletions of records that are never deleted are put back before committing", async () => {
  const { deletionsToRestore } = await import("../../scripts/lib/repo.mjs");
  assert.deepEqual(deletionsToRestore(["runs/2026-11-01/0100-x.json", "grid/series/2026-10-01.jsonl"]), [], "routine compaction passes");
  assert.deepEqual(deletionsToRestore(["leads/d.jsonl", "events/2026-11/a.json"]), ["leads/d.jsonl", "events/2026-11/a.json"], "a wipe is undone whole");
  assert.deepEqual(deletionsToRestore(["status.json"]), ["status.json"]);
  // end to end: a wiped ./data is not committed
  const { clone } = world();
  const A = clone("A");
  assert.equal(sh(A, "node", ["scripts/data-branch.mjs", "create"]).status, 0);
  assert.match(sh(A, "node", ["scripts/data-branch.mjs", "ensure"]).stdout, /switched/);
  mkdirSync(join(A, "data", "events"), { recursive: true }); writeFileSync(join(A, "data", "events", "e.json"), "{}\n");
  let r = sh(A, "node", ["-e", 'import("./scripts/lib/repo.mjs").then(m=>process.exit(m.commitData("data: e",["data/events"]).pushed?0:1))']);
  assert.equal(r.status, 0, r.stderr);
  for (const f of ["status.json", "events/e.json", "leads/d.jsonl"]) spawnSync("rm", ["-f", join(A, "data", f)]);
  r = sh(A, "node", ["-e", 'import("./scripts/lib/repo.mjs").then(m=>{m.commitData("data: wipe");})']);
  assert.match(r.stderr, /DATA PROTECTED/);
  assert.equal(existsSync(join(A, "data", "status.json")) && existsSync(join(A, "data", "events", "e.json")) && existsSync(join(A, "data", "leads", "d.jsonl")), true);
  assert.notEqual(git(join(A, "data"), "log", "-1", "--format=%s").stdout.trim(), "data: wipe");});

test("research loop: notices new code on main (and only then)", () => {
  const { clone } = world();
  const A = clone("A"), B = clone("B");
  const moved = (code) => sh(A, "node", ["-e", `import("./scripts/run-job.mjs").then(m=>console.log(JSON.stringify(m.codeMoved(${JSON.stringify(code)}))))`]).stdout.trim().split("\n").pop();
  const head = git(A, "rev-parse", "HEAD").stdout.trim();
  assert.equal(moved(head), '""', "same code: keep running");
  assert.equal(moved(""), '""', "no code recorded (off main): never hands over");
  writeFileSync(join(B, "x.txt"), "1\n"); git(B, "add", "x.txt"); git(B, "commit", "-q", "-m", "code"); git(B, "push", "-q", "origin", "main");
  assert.equal(moved(head), JSON.stringify(git(B, "rev-parse", "HEAD").stdout.trim()), "main moved: hand over");
});
