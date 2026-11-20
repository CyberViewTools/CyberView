// site/data/manifest.json records which data branch commit a build used (scripts/lib/data-commit-id.mjs).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { dataCommit } from "../../scripts/lib/data-commit-id.mjs";

const git = (cwd, ...a) => spawnSync("git", ["-c", "user.email=t@example.invalid", "-c", "user.name=t", ...a], { cwd, encoding: "utf8" });
const head = (cwd) => git(cwd, "rev-parse", "HEAD").stdout.trim();

test("data_commit: empty without a data folder or outside git", () => {
  const w = mkdtempSync(join(tmpdir(), "cv-dc-"));
  assert.equal(dataCommit(w), "");
  mkdirSync(join(w, "data"));
  assert.equal(dataCommit(w), "", "a plain folder");
});

test("data_commit: empty in the old layout (data/ is a folder of main)", () => {
  const w = mkdtempSync(join(tmpdir(), "cv-dc-"));
  git(w, "init", "-q", "-b", "main");
  mkdirSync(join(w, "data")); writeFileSync(join(w, "data", "status.json"), "{}\n");
  git(w, "add", "-A"); git(w, "commit", "-q", "-m", "seed");
  assert.equal(dataCommit(w), "");
});

test("data_commit: the data checkout's HEAD when ./data is its own clone (GitHub Actions)", () => {
  const w = mkdtempSync(join(tmpdir(), "cv-dc-"));
  git(w, "init", "-q", "-b", "main"); writeFileSync(join(w, "x"), "1"); git(w, "add", "x"); git(w, "commit", "-q", "-m", "code");
  const d = join(w, "data"); mkdirSync(d);
  git(d, "init", "-q", "-b", "data"); writeFileSync(join(d, "status.json"), "{}\n"); git(d, "add", "-A"); git(d, "commit", "-q", "-m", "data");
  const h = dataCommit(w);
  assert.match(h, /^[0-9a-f]{40}$/);
  assert.equal(h, head(d));
  assert.notEqual(h, head(w), "not main's commit");
});

test("data_commit: the data checkout's HEAD when ./data is a worktree (Claude sessions)", () => {
  const w = mkdtempSync(join(tmpdir(), "cv-dc-"));
  git(w, "init", "-q", "-b", "main"); writeFileSync(join(w, "x"), "1"); git(w, "add", "x"); git(w, "commit", "-q", "-m", "code");
  git(w, "switch", "-q", "--orphan", "data"); writeFileSync(join(w, "status.json"), "{}\n"); git(w, "add", "status.json"); git(w, "commit", "-q", "-m", "data");
  const dataHead = head(w);
  git(w, "switch", "-q", "main");
  assert.equal(git(w, "worktree", "add", "-q", "data", "data").status, 0);
  assert.equal(dataCommit(w), dataHead);
});
