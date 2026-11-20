// Push the commit just made, merging the files every job writes instead of failing on them. No AI model.
// Run after `git commit`: node scripts/git-sync.mjs
// Several jobs (lead collection, feeds, research, review) commit to main within minutes of each other, and they all touch
// data/status.json; a plain `pull --rebase` then stops on a conflict and the job fails, losing its run. Here:
//   - data/status.json and other JSON objects: a three-way merge by key (keys this commit changed win; every other key
//     comes from what is already on main), so two jobs' timestamps both survive
//   - data/leads/*.jsonl, data/runs-style line files: the union of both sides' lines
//   - any other conflict: the rebase is aborted and the script exits 1, so nothing is ever merged blindly
// Up to 5 attempts with backoff. Exit 0 = pushed.
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { existsSync } from "node:fs";
// Code and data live on separate branches (scripts/lib/repo.mjs). In a checkout whose ./data is the data branch, this
// syncs that checkout with origin/data and then starts the deploy at once (the push itself starts nothing: see
// dispatchDeploy). Otherwise it syncs the current checkout with origin/main, as before.
const CWD = process.cwd();
const dataCheckout = (() => {
  const d = join(CWD, "data");
  if (!existsSync(join(d, ".git"))) return false;
  const r = (a) => spawnSync("git", a, { cwd: d, encoding: "utf8" }).stdout.trim();
  return r(["rev-parse", "--abbrev-ref", "HEAD"]) === "data" && r(["rev-parse", "--show-toplevel"]) === d;
})();
const ROOT = dataCheckout ? join(CWD, "data") : CWD, BR = dataCheckout ? "data" : "main";
const git = (...a) => spawnSync("git", a, { cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
async function deployAfterPush(before) {
  if (!dataCheckout) return;                                       // a push to main starts pages.yml by itself
  const changed = git("diff", "--name-only", `${before}..HEAD`).stdout.split("\n").filter(Boolean);
  const { NO_DEPLOY, dispatchDeploy } = await import("./lib/repo.mjs");
  if (!changed.length || changed.every(NO_DEPLOY)) return;
  if (dispatchDeploy(CWD)) console.log("git-sync: deploy requested");
}
const show = (stage, f) => { const r = git("show", `:${stage}:${f}`); return r.status === 0 ? r.stdout : null; };
const sleep = (s) => spawnSync("sleep", [String(s)]);

export { mergeJson, mergeLines } from "./lib/merge.mjs";
import { mergeJson, mergeLines } from "./lib/merge.mjs";
import { heal, markedInOutgoing } from "./lib/conflicts.mjs";

function resolve(merging = false) {
  const files = git("diff", "--name-only", "--diff-filter=U").stdout.split("\n").filter(Boolean);
  for (const f of files) {
    // during a rebase, stage 2 is main (the side being rebased onto) and stage 3 is this commit; during a merge it is the other way round
    const base = show(1, f), up = show(merging ? 3 : 2, f), mine = show(merging ? 2 : 3, f);
    let merged = null;
    if (/\.jsonl$/.test(f)) merged = mergeLines(up, mine);
    else if (/\.json$/.test(f)) {
      try {
        const u = JSON.parse(up || "{}"), m = JSON.parse(mine || "{}"), b = base ? JSON.parse(base) : {};
        if ([u, m, b].every((x) => x && typeof x === "object" && !Array.isArray(x))) merged = JSON.stringify(mergeJson(b, u, m), null, 1) + "\n";
      } catch { merged = null; }
    }
    if (merged === null) { console.error(`git-sync: cannot merge ${f} automatically`); return false; }
    writeFileSync(join(ROOT, f), merged); git("add", f);
  }
  return true;
}

async function main() {
  for (let i = 1, max = Number(process.env.GIT_SYNC_TRIES) || 5; i <= max; i++) {
    // a branch that already holds merge commits (an orchestrator merging builders' branches) is merged, not rebased:
    // a rebase would replay every builder commit one by one and stop on their conflicts (seen 2026-11-19 and -20)
    git("fetch", "-q", "origin", `+refs/heads/${BR}:refs/remotes/origin/${BR}`);
    if (git("rev-list", "--merges", "--count", `origin/${BR}..HEAD`).stdout.trim() !== "0") {
      git("merge", "-q", "--no-edit", `origin/${BR}`);
      if (git("diff", "--name-only", "--diff-filter=U").stdout.trim()) {
        if (!resolve(true) || git("-c", "core.editor=true", "commit", "-q", "--no-edit").status !== 0) { git("merge", "--abort"); console.error(`git-sync: attempt ${i}: merge could not be resolved`); sleep(i * 10); continue; }
      }
      heal(ROOT);
      const bad0 = markedInOutgoing(ROOT, `origin/${BR}`);
      if (bad0.length) { console.error(`git-sync: refusing to push, conflict markers in ${bad0.join(", ")}`); process.exit(1); }
      const before0 = git("rev-parse", `origin/${BR}`).stdout.trim(), r0 = git("push", "-q", "origin", `HEAD:${BR}`);
      if (r0.status === 0) { console.log(`git-sync: pushed (attempt ${i}, merged)`); await deployAfterPush(before0); process.exit(0); }
      console.error(`git-sync: push attempt ${i} failed: ${(r0.stderr || "").trim().split("\n").pop()}`); sleep(i * 10); continue;
    }
    const p = git("pull", "--rebase", "--autostash", "-q", "origin", BR);
    if (p.status !== 0) {
      let ok = true;
      for (let n = 0; n < 50 && ok; n++) {                                         // one round per commit being replayed
        if (!git("diff", "--name-only", "--diff-filter=U").stdout.trim()) break;
        ok = resolve();
        if (ok) { const c = spawnSync("git", ["-c", "core.editor=true", "rebase", "--continue"], { cwd: ROOT, encoding: "utf8", env: { ...process.env, GIT_EDITOR: "true" } }); if (c.status === 0) break; }
      }
      if (!ok || git("status").stdout.includes("rebase in progress")) { git("rebase", "--abort"); console.error(`git-sync: attempt ${i}: ${(p.stderr || "").trim().split("\n")[0]}`); sleep(Number(process.env.GIT_SYNC_TRIES) ? 0 : i * 10); continue; }
    }
    heal(ROOT);
    const bad = markedInOutgoing(ROOT, `origin/${BR}`);
    if (bad.length) { console.error(`git-sync: refusing to push, conflict markers in ${bad.join(", ")}`); process.exit(1); }
    const before = git("rev-parse", `origin/${BR}`).stdout.trim(), r = git("push", "-q", "origin", `HEAD:${BR}`);
    if (r.status === 0) { console.log(`git-sync: pushed (attempt ${i})`); await deployAfterPush(before); process.exit(0); }
    console.error(`git-sync: push attempt ${i} failed: ${(r.stderr || "").trim().split("\n").pop()}`); sleep(i * 10);
  }
  console.error("git-sync: could not push after 5 attempts"); process.exit(1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
