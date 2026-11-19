// scripts/git-sync.mjs: two jobs committing at once must both get pushed, with both jobs' changes kept. Run: node --test tests/unit/
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { mergeJson, mergeLines } from "../../scripts/git-sync.mjs";

const SYNC = resolve("scripts/git-sync.mjs");
const env = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid" };
const sh = (cwd, cmd, ...a) => { const r = spawnSync(cmd, a, { cwd, encoding: "utf8", env }); if (r.status !== 0 && cmd === "git") throw new Error(`${a.join(" ")}: ${r.stderr}`); return r; };

test("merge by key: both sides' changes survive; a key only one side touched keeps that side's value", () => {
  const base = { a: "1", b: "1", n: { x: 1 } }, up = { a: "2", b: "1", c: "new", n: { x: 1, y: 2 } }, mine = { a: "1", b: "3", n: { x: 5 } };
  assert.deepEqual(mergeJson(base, up, mine), { a: "2", b: "3", c: "new", n: { x: 5, y: 2 } });
  assert.equal(mergeLines("l1\nl2\n", "l1\nl3\n"), "l1\nl2\nl3\n");
});

test("two jobs pushing at once: the second one merges status.json and the leads file and pushes", () => {
  const dir = mkdtempSync(join(tmpdir(), "cv-sync-")), remote = join(dir, "remote.git"), a = join(dir, "a"), b = join(dir, "b");
  sh(dir, "git", "init", "-q", "--bare", "-b", "main", remote);
  sh(dir, "git", "clone", "-q", remote, a);
  sh(a, "git", "checkout", "-q", "-b", "main");
  mkdirSync(join(a, "data", "leads"), { recursive: true });
  writeFileSync(join(a, "data", "status.json"), JSON.stringify({ last_collect_at: "t0", last_feeds_at: "t0" }, null, 1) + "\n");
  writeFileSync(join(a, "data", "leads", "d.jsonl"), '{"u":1}\n');
  sh(a, "git", "add", "-A"); sh(a, "git", "commit", "-q", "-m", "init"); sh(a, "git", "push", "-q", "origin", "main");
  sh(dir, "git", "clone", "-q", "-b", "main", remote, b);
  // job A (collect) and job B (feeds) both start from the same commit
  writeFileSync(join(a, "data", "status.json"), JSON.stringify({ last_collect_at: "tA", last_feeds_at: "t0" }, null, 1) + "\n");
  writeFileSync(join(a, "data", "leads", "d.jsonl"), '{"u":1}\n{"u":2}\n');
  sh(a, "git", "commit", "-q", "-am", "collect");
  writeFileSync(join(b, "data", "status.json"), JSON.stringify({ last_collect_at: "t0", last_feeds_at: "tB" }, null, 1) + "\n");
  writeFileSync(join(b, "data", "leads", "d.jsonl"), '{"u":1}\n{"u":3}\n');
  sh(b, "git", "commit", "-q", "-am", "feeds");
  assert.equal(spawnSync("node", [SYNC], { cwd: a, encoding: "utf8", env }).status, 0);
  const r = spawnSync("node", [SYNC], { cwd: b, encoding: "utf8", env });
  assert.equal(r.status, 0, r.stderr);
  const c = join(dir, "c"); sh(dir, "git", "clone", "-q", "-b", "main", remote, c);
  assert.deepEqual(JSON.parse(readFileSync(join(c, "data", "status.json"), "utf8")), { last_collect_at: "tA", last_feeds_at: "tB" });
  assert.equal(readFileSync(join(c, "data", "leads", "d.jsonl"), "utf8"), '{"u":1}\n{"u":2}\n{"u":3}\n');
});

test("a conflict in a file it cannot merge safely is never merged blindly", () => {
  const dir = mkdtempSync(join(tmpdir(), "cv-sync-")), remote = join(dir, "remote.git"), a = join(dir, "a"), b = join(dir, "b");
  sh(dir, "git", "init", "-q", "--bare", "-b", "main", remote);
  sh(dir, "git", "clone", "-q", remote, a); sh(a, "git", "checkout", "-q", "-b", "main");
  writeFileSync(join(a, "app.js"), "one\n"); sh(a, "git", "add", "-A"); sh(a, "git", "commit", "-q", "-m", "i"); sh(a, "git", "push", "-q", "origin", "main");
  sh(dir, "git", "clone", "-q", "-b", "main", remote, b);
  writeFileSync(join(a, "app.js"), "two\n"); sh(a, "git", "commit", "-q", "-am", "a"); sh(a, "git", "push", "-q", "origin", "main");
  writeFileSync(join(b, "app.js"), "three\n"); sh(b, "git", "commit", "-q", "-am", "b");
  const r = spawnSync("node", [SYNC], { cwd: b, encoding: "utf8", env: { ...env, GIT_SYNC_TRIES: "1" }, timeout: 120000 });
  assert.equal(r.status, 1);
  assert.equal(readFileSync(join(b, "app.js"), "utf8"), "three\n");
  assert.ok(!sh(b, "git", "status").stdout.includes("rebase in progress"));
});
