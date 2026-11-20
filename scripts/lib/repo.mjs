// Where data lives in git, and how it is committed, pushed and deployed. No AI model.
// Code and data are on separate branches (owner, 2026-11-20): `main` holds code and is changed through pull requests;
// `data` holds everything that used to be under data/ (the branch root is the data folder), and every automated job
// commits there. In a checkout, the data branch is mounted at ./data (a git worktree locally, a second checkout in
// GitHub Actions) and main's own copy of data/ is excluded with a sparse checkout, so every script still reads and
// writes data/... exactly as before; only committing and pushing differ.
//   dataMode()     "branch" once ./data is the data branch, else "main" (the old layout, still supported so a checkout
//                  that has not switched yet keeps working; scripts/data-branch.mjs switches it)
//   commitData()   commit the given data/ paths in whichever layout, then push (git-sync) and ask for a deploy
//   dispatchDeploy() start the deploy workflow at once (pushes made with the workflow token start nothing by design)
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { ROOT } from "./store.mjs";

export const DATA_BRANCH = "data";
export const DATA_DIR = join(ROOT, "data");
const run = (cwd, args, ms = 120000) => spawnSync("git", args, { cwd, encoding: "utf8", timeout: ms, maxBuffer: 64 * 1024 * 1024 });

/** "branch" when ROOT/data is its own git checkout of the data branch, else "main". */
export function dataMode(root = ROOT) {
  const d = join(root, "data");
  if (!existsSync(join(d, ".git"))) return "main";                       // a worktree or a clone has a .git entry at its root
  const top = run(d, ["rev-parse", "--show-toplevel"]).stdout.trim(), br = run(d, ["rev-parse", "--abbrev-ref", "HEAD"]).stdout.trim();
  return resolve(top) === resolve(d) && br === DATA_BRANCH ? "branch" : "main";
}
/** git in the data checkout (branch mode) or in the repo root (main mode). */
export const dataGitDir = (root = ROOT) => (dataMode(root) === "branch" ? join(root, "data") : root);
/** A data/ path as the data checkout sees it ("data/leads/x.jsonl" -> "leads/x.jsonl" in branch mode). */
export const dataRel = (p, root = ROOT) => (dataMode(root) === "branch" ? String(p).replace(/^data\/?/, "") || "." : p);

/** owner/repo from the origin remote (credentials stripped). */
export function repoSlug(root = ROOT) {
  const u = run(root, ["remote", "get-url", "origin"]).stdout.trim();
  const m = /github\.com[/:]([^/]+)\/([^/.]+?)(?:\.git)?$/.exec(u);
  return m ? `${m[1]}/${m[2]}` : process.env.GITHUB_REPOSITORY || "xanderhutch/CyberView";
}

/** Files that never need a deploy (the old pages.yml paths-ignore). */
export const NO_DEPLOY = (f) => /^(data\/)?(leases\.json|usage\/)/.test(f);

/** Start pages.yml on main now. Returns true when GitHub accepted it. Uses gh (REST), which works in GitHub Actions
 *  (GH_TOKEN) and in the Claude sessions. Never throws: the guard notices a deploy that did not happen. */
export function dispatchDeploy(root = ROOT) {
  if (process.env.CYBERVIEW_NO_DEPLOY === "1") return false;                // tests and rehearsals
  const r = spawnSync("gh", ["api", "-X", "POST", `repos/${repoSlug(root)}/actions/workflows/pages.yml/dispatches`, "-f", "ref=main"], { cwd: root, encoding: "utf8", timeout: 30000 });
  if (r.status === 0) return true;
  console.error(`deploy request failed: ${((r.stderr || r.error && r.error.message) || "").trim().split("\n").pop()}`);
  return false;
}

/** Commit the given repo-relative data/ paths (or all data changes when none are given) with `msg`, then push with
 *  git-sync, which asks for a deploy in branch mode. Returns { committed, pushed }. */
export function commitData(msg, paths = [], root = ROOT) {
  const cwd = dataGitDir(root), branch = dataMode(root) === "branch";
  const rel = paths.length ? paths.map((p) => dataRel(p, root)) : [branch ? "." : "data"];
  // a data checkout made by actions/checkout has no identity; borrow the main repo's
  if (branch && !run(cwd, ["config", "user.email"]).stdout.trim()) {
    for (const k of ["user.name", "user.email"]) { const v = run(root, ["config", k]).stdout.trim(); if (v) run(cwd, ["config", k, v]); }
  }
  run(cwd, ["add", "-A", "--", ...rel]);
  if (run(cwd, ["diff", "--cached", "--quiet"]).status === 0) return { committed: false, pushed: true };
  const c = run(cwd, ["commit", "-q", "-m", msg]);
  if (c.status !== 0) { console.error(`commit failed: ${(c.stderr || c.stdout).trim().split("\n")[0]}`); return { committed: false, pushed: false }; }
  const s = spawnSync("node", [join(root, "scripts", "git-sync.mjs")], { cwd: root, encoding: "utf8", timeout: 300000, stdio: ["ignore", "pipe", "pipe"] });
  process.stdout.write(s.stdout || ""); process.stderr.write(s.stderr || "");
  return { committed: true, pushed: s.status === 0 };
}

/** Bring code (main, fast-forward only) and data (data branch) up to date. Never throws. */
export function pullAll(root = ROOT) {
  if (dataMode(root) === "branch") {
    run(root, ["pull", "-q", "--ff-only", "origin", "main"]);
    // main may still carry its old copy of data/ (until it is removed there): keep git from comparing it with ./data
    run(root, ["config", "sparse.expectFilesOutsideOfPatterns", "true"]);
    run(root, ["sparse-checkout", "reapply"]);
    run(join(root, "data"), ["pull", "-q", "--rebase", "--autostash", "origin", DATA_BRANCH]);
  } else run(root, ["pull", "-q", "--rebase", "--autostash", "origin", "main"]);
}

export const readText = (p) => { try { return readFileSync(p, "utf8"); } catch { return ""; } };
