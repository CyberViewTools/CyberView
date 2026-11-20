// Code on main, data on the data branch: the migration and its upkeep. No AI model. (See scripts/lib/repo.mjs.)
//   node scripts/data-branch.mjs status            which layout this checkout uses, and whether origin/data exists
//   node scripts/data-branch.mjs create            ONCE: split data/ out of main with its history (git subtree split), and
//                                                  push it as the data branch, recording which main commit it came from
//   node scripts/data-branch.mjs ensure            switch THIS checkout to the new layout: main without data/ (sparse
//                                                  checkout) and ./data a worktree of the data branch. Uncommitted data
//                                                  is carried over (line files by union, JSON by key), never dropped.
//                                                  Does nothing until origin/data exists, and waits while a research
//                                                  loop is running here (it would be moving files under a live process).
//   node scripts/data-branch.mjs forward --main <dir> --data <dir>
//                                                  bring every data/ change pushed to main since the last forward onto
//                                                  the data branch (used by .github/workflows/data-forward.yml), so a job
//                                                  still running old code during the switch loses nothing
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync, readdirSync, rmSync, cpSync, appendFileSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT } from "./lib/store.mjs";
import { DATA_BRANCH, dataMode, fetchRef, trackDataBranch } from "./lib/repo.mjs";
import { mergeJson, mergeLines } from "./lib/merge.mjs";

const git = (cwd, ...a) => spawnSync("git", a, { cwd, encoding: "utf8", maxBuffer: 256 * 1024 * 1024, timeout: 600000 });
const say = (s) => console.log(`data-branch: ${s}`);
export const MARK = ".forwarded";            // in the data branch: the main commit whose data/ was last brought over

/** Pure: merge a local copy of a data file into the data branch's copy. Returns the merged text, or null to keep `ours`. */
export function mergeFile(path, base, theirs, ours) {
  if (ours === theirs) return theirs;
  if (theirs === null || theirs === undefined) return ours;                  // only here: keep it
  if (/\.jsonl$/.test(path)) return mergeLines(theirs, ours);
  if (/\.json$/.test(path)) {
    try {
      const b = base ? JSON.parse(base) : {}, t = JSON.parse(theirs), o = JSON.parse(ours);
      if ([b, t, o].every((x) => x && typeof x === "object" && !Array.isArray(x))) return JSON.stringify(mergeJson(b, t, o), null, 2) + "\n";
    } catch { /* fall through */ }
  }
  return ours === base ? theirs : ours;                                      // changed only on one side: that side wins
}

function walk(dir, base = dir, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === ".git") continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, base, out); else out.push(relative(base, p));
  }
  return out;
}
const remoteHasData = (root) => git(root, "ls-remote", "--exit-code", "--heads", "origin", DATA_BRANCH).status === 0;
function flowRunning() {
  try { const l = JSON.parse(readFileSync("/tmp/cyberview-flow.json", "utf8")); process.kill(l.pid, 0); return true; } catch { return false; }
}

function status() {
  const has = remoteHasData(ROOT);
  say(`layout ${dataMode(ROOT) === "branch" ? "data branch at ./data" : "data/ inside main (old)"}; origin/${DATA_BRANCH} ${has ? "exists" : "does not exist yet"}`);
}

function create() {
  if (remoteHasData(ROOT)) { say(`origin/${DATA_BRANCH} already exists; nothing to do`); return; }
  git(ROOT, "fetch", "-q", "origin", "main");
  const head = git(ROOT, "rev-parse", "origin/main").stdout.trim();
  const tmp = "__data_split";
  git(ROOT, "branch", "-D", tmp);
  const r = git(ROOT, "subtree", "split", `--prefix=data`, "origin/main", "-b", tmp);
  if (r.status !== 0) throw new Error(`subtree split failed: ${r.stderr}`);
  // record where it came from, so `forward` brings over only what main gets after this
  const wt = join(ROOT, ".git", "data-create");
  rmSync(wt, { recursive: true, force: true });
  git(ROOT, "worktree", "add", "-q", wt, tmp);
  writeFileSync(join(wt, MARK), head + "\n");
  git(wt, "add", MARK); git(wt, "commit", "-q", "-m", `data: data branch created from main ${head.slice(0, 7)} (history kept)`);
  const p = git(wt, "push", "-q", "origin", `HEAD:refs/heads/${DATA_BRANCH}`);
  git(ROOT, "worktree", "remove", "--force", wt); git(ROOT, "branch", "-D", tmp);
  if (p.status !== 0) throw new Error(`push failed: ${p.stderr}`);
  say(`origin/${DATA_BRANCH} created from main ${head.slice(0, 7)}`);
}

/** Tell git to ignore what is on disk for main's own copy of data/ (./data is the data branch now). Sparse checkout
 *  alone is not enough: git only skips a path whose file matches main's version, and the data branch differs at once. */
export function hideMainData(root = ROOT) {
  // git 2.37+ clears the skip flag of any path whose file exists on disk unless told that files outside the sparse
  // patterns are expected there, which is exactly this layout (./data is a different branch)
  git(root, "config", "sparse.expectFilesOutsideOfPatterns", "true");
  git(root, "sparse-checkout", "reapply");
  const ls = git(root, "ls-files", "-z", "--", "data/");
  if (!ls.stdout) return 0;
  const r = spawnSync("git", ["update-index", "--skip-worktree", "-z", "--stdin"], { cwd: root, input: ls.stdout, encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  return r.status === 0 ? ls.stdout.split("\0").filter(Boolean).length : -1;
}

function ensure() {
  if (dataMode(ROOT) === "branch") { trackDataBranch(ROOT); hideMainData(ROOT); say("already on the data branch layout"); return 0; }
  if (!remoteHasData(ROOT)) { say(`origin/${DATA_BRANCH} does not exist yet; keeping the old layout`); return 0; }
  if (flowRunning()) { say("a research loop is running in this checkout; switching after it ends"); return 0; }
  trackDataBranch(ROOT);
  const f = git(ROOT, "fetch", "-q", "origin", fetchRef(DATA_BRANCH), fetchRef("main"));
  if (f.status !== 0) { say(`could not fetch the data branch (${f.stderr.trim()}); keeping the old layout`); return 1; }
  const stamp = new Date().toISOString().replace(/\D/g, "").slice(0, 14), keep = join(ROOT, `data.pre-${stamp}`);
  // 1. keep a copy of the old data folder (it holds whatever this checkout has not committed yet), then put main's
  //    data/ back to its committed state: git will only leave out of the checkout files it considers unchanged
  if (existsSync(join(ROOT, "data"))) cpSync(join(ROOT, "data"), keep, { recursive: true });
  git(ROOT, "checkout", "--", "data/"); git(ROOT, "clean", "-fdq", "--", "data/");
  // 2. main without data/: a sparse checkout, so main's own copy of data/ never comes back into this folder; and this
  //    checkout ignores the folder (locally only: a checkout still on the old layout must keep seeing new data files)
  git(ROOT, "config", "sparse.expectFilesOutsideOfPatterns", "true");
  git(ROOT, "sparse-checkout", "init", "--no-cone");
  git(ROOT, "sparse-checkout", "set", "--no-cone", "/*", "!/data/");
  rmSync(join(ROOT, "data"), { recursive: true, force: true });
  const ex = join(git(ROOT, "rev-parse", "--git-path", "info/exclude").stdout.trim() || ".git/info/exclude");
  const exP = ex.startsWith("/") ? ex : join(ROOT, ex), cur = existsSync(exP) ? readFileSync(exP, "utf8") : "";
  if (!/^\/data\/$/m.test(cur)) { mkdirSync(dirname(exP), { recursive: true }); appendFileSync(exP, `${cur && !cur.endsWith("\n") ? "\n" : ""}/data/\n/data.pre-*/\n`); }
  // 3. the data branch at ./data
  git(ROOT, "worktree", "prune");
  const w = git(ROOT, "worktree", "add", "-q", "-B", DATA_BRANCH, "data", `origin/${DATA_BRANCH}`);
  if (w.status !== 0) {
    git(ROOT, "sparse-checkout", "disable");
    if (existsSync(keep)) { rmSync(join(ROOT, "data"), { recursive: true, force: true }); renameSync(keep, join(ROOT, "data")); }
    say(`could not mount the data branch (${w.stderr.trim()}); kept the old layout`); return 1;
  }
  git(join(ROOT, "data"), "branch", "--set-upstream-to", `origin/${DATA_BRANCH}`);
  hideMainData(ROOT);
  // 4. carry over anything this checkout changed and had not pushed: files that differ from main's committed copy
  let carried = 0;
  if (existsSync(keep)) {
    for (const f of walk(keep)) {
      const ours = readFileSync(join(keep, f), "utf8");
      const b = git(ROOT, "show", `HEAD:data/${f}`), base = b.status === 0 ? b.stdout : null;
      if (ours === base) continue;                                           // unchanged here: the data branch has it
      const dst = join(ROOT, "data", f), theirs = existsSync(dst) ? readFileSync(dst, "utf8") : null;
      const merged = mergeFile(f, base, theirs, ours);
      if (merged !== theirs) { mkdirSync(dirname(dst), { recursive: true }); writeFileSync(dst, merged); carried++; }
    }
    // the old folder is kept for a day (git-ignored as data.pre-*) in case anything needs a second look
  }
  say(`switched: ./data is now the ${DATA_BRANCH} branch; ${carried} uncommitted file(s) carried over${existsSync(keep) ? `; the old folder is at ${relative(ROOT, keep)}` : ""}`);
  return 0;
}

function forward(mainDir, dataDir) {
  const markP = join(dataDir, MARK), last = existsSync(markP) ? readFileSync(markP, "utf8").trim() : "";
  const head = git(mainDir, "rev-parse", "HEAD").stdout.trim();
  if (!last) { say(`no ${MARK} in the data branch; nothing to forward`); return 0; }
  if (last === head) { say("up to date"); return 0; }
  if (git(mainDir, "cat-file", "-e", `${last}^{commit}`).status !== 0) { say(`main commit ${last.slice(0, 7)} not found (shallow clone?)`); return 1; }
  const changes = git(mainDir, "diff", "--name-status", "--no-renames", `${last}..${head}`, "--", "data/").stdout.split("\n").filter(Boolean);
  let n = 0;
  for (const line of changes) {
    const [st, path] = line.split("\t"), f = path.replace(/^data\//, ""), dst = join(dataDir, f);
    if (f === MARK) continue;
    if (st === "D") continue;                                                // never delete on the data branch because main did
    const ours = git(mainDir, "show", `${head}:${path}`).stdout, b = git(mainDir, "show", `${last}:${path}`), base = b.status === 0 ? b.stdout : null;
    const theirs = existsSync(dst) ? readFileSync(dst, "utf8") : null, merged = mergeFile(f, base, theirs, ours);
    if (merged !== theirs) { mkdirSync(dirname(dst), { recursive: true }); writeFileSync(dst, merged); n++; }
  }
  writeFileSync(markP, head + "\n");
  say(`forwarded ${n} file(s) from main ${last.slice(0, 7)}..${head.slice(0, 7)}`);
  return 0;
}

async function main() {
  const [cmd] = process.argv.slice(2), arg = (k) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : ""; };
  if (cmd === "status") return status();
  if (cmd === "create") return create();
  if (cmd === "ensure") process.exit(ensure());
  if (cmd === "forward") process.exit(forward(arg("--main") || ROOT, arg("--data") || join(ROOT, "data")));
  console.log("usage: data-branch.mjs status | create | ensure | forward --main <dir> --data <dir>"); process.exit(1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
