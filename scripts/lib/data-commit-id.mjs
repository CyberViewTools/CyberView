// Which data branch commit a build was made from, for site/data/manifest.json (data_commit). No AI model.
// Code and data live on separate branches (scripts/lib/repo.mjs): when ./data is its own git checkout (the data branch
// mounted there by .github/actions/data or by scripts/data-branch.mjs ensure), this is that checkout's HEAD; in the
// old layout (data/ inside main) or with no git at all it is "", and the manifest's `commit` alone names the build.
import { spawnSync } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { join } from "node:path";

const git = (cwd, ...a) => spawnSync("git", a, { cwd, encoding: "utf8", timeout: 10000 });
const real = (p) => { try { return realpathSync(p); } catch { return p; } };

/** HEAD of the data checkout at <root>/data, or "" when data/ is not its own checkout. Never throws. */
export function dataCommit(root) {
  const d = join(root, "data");
  if (!existsSync(join(d, ".git"))) return "";                     // a clone has a .git folder, a worktree a .git file
  const top = git(d, "rev-parse", "--show-toplevel");
  if (top.status !== 0 || real(top.stdout.trim()) !== real(d)) return "";
  const h = git(d, "rev-parse", "HEAD");
  return h.status === 0 && /^[0-9a-f]{40,64}$/.test(h.stdout.trim()) ? h.stdout.trim() : "";
}
