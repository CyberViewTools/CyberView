// Propose a job's changes to code-side files (config/, docs/) as a pull request to main. No AI model.
// main only takes pull requests (code and data are on separate branches; scripts/lib/repo.mjs). A job that tunes a dial
// (the improver: config/pipeline.json, config/models.json) or adds a feed (the scout: config/feeds.json) calls this
// through scripts/finish.mjs: the changed files are committed on a new branch bot/<job>-<time> made from origin/main,
// pushed, opened as a pull request with auto-merge (squash) switched on, so it merges by itself once CI passes. If
// auto-merge is not allowed in the repository, the pull request waits for the owner.
// Run: node scripts/propose.mjs <job>     prints one line: "proposed <url>" or why not
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, copyFileSync, existsSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { ROOT } from "./lib/store.mjs";
import { repoSlug } from "./lib/repo.mjs";

const git = (cwd, ...a) => spawnSync("git", a, { cwd, encoding: "utf8", timeout: 120000 });
const gh = (...a) => spawnSync("gh", a, { cwd: ROOT, encoding: "utf8", timeout: 60000 });
export const PROPOSABLE = /^(config|docs)\//;

export function propose(job, root = ROOT) {
  const files = git(root, "status", "--porcelain", "--", "config", "docs").stdout.split("\n").filter(Boolean)
    .map((l) => l.slice(3).trim()).filter((f) => PROPOSABLE.test(f) && existsSync(join(root, f)));
  if (!files.length) return { ok: true, msg: "nothing to propose" };
  const stamp = new Date().toISOString().replace(/\D/g, "").slice(0, 12), branch = `bot/${job}-${stamp}`;
  git(root, "fetch", "-q", "origin", "main");
  const wt = mkdtempSync(join(tmpdir(), "cv-propose-"));
  rmSync(wt, { recursive: true, force: true });
  const a = git(root, "worktree", "add", "-q", "-b", branch, wt, "origin/main");
  if (a.status !== 0) return { ok: false, msg: `could not make a branch: ${a.stderr.trim()}` };
  try {
    for (const f of files) { mkdirSync(dirname(join(wt, f)), { recursive: true }); copyFileSync(join(root, f), join(wt, f)); }
    git(wt, "add", "--", ...files);
    if (git(wt, "diff", "--cached", "--quiet").status === 0) return { ok: true, msg: "already on main" };
    const c = git(wt, "commit", "-q", "-m", `${job}: proposed change to ${files.join(", ")}\n\nMade by the ${job} job (CyberView AI, a Claude model) and proposed as a pull request; it merges once CI passes.`);
    if (c.status !== 0) return { ok: false, msg: `commit failed: ${c.stderr.trim()}` };
    const p = git(wt, "push", "-q", "origin", `HEAD:refs/heads/${branch}`);
    if (p.status !== 0) return { ok: false, msg: `push failed: ${p.stderr.trim().split("\n").pop()}` };
    const pr = gh("api", "-X", "POST", `repos/${repoSlug(root)}/pulls`, "-f", `title=${job}: ${files.join(", ")}`, "-f", `head=${branch}`, "-f", "base=main",
      "-f", `body=Proposed by the scheduled ${job} job (CyberView AI, a Claude model). It changes only ${files.join(", ")}. It merges by itself once CI passes; close it to refuse the change.`);
    let url = "", node = "";
    try { const j = JSON.parse(pr.stdout); url = j.html_url || ""; node = j.node_id || ""; } catch { /* below */ }
    if (!url) return { ok: false, msg: `branch ${branch} pushed; opening the pull request failed: ${(pr.stderr || "").trim().split("\n").pop()}` };
    const am = node ? gh("api", "graphql", "-f", `query=mutation($id:ID!){enablePullRequestAutoMerge(input:{pullRequestId:$id,mergeMethod:SQUASH}){clientMutationId}}`, "-f", `id=${node}`) : { status: 1 };
    return { ok: true, msg: `proposed ${url}${am.status === 0 ? " (merges itself once CI passes)" : " (waiting for the owner: auto-merge is off)"}` };
  } finally { git(root, "worktree", "remove", "--force", wt); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const job = String(process.argv[2] || "").replace(/[^a-z0-9-]/g, "");
  if (!job) { console.log("usage: propose.mjs <job>"); process.exit(1); }
  const r = propose(job); console.log(r.msg); process.exit(r.ok ? 0 : 1);
}
