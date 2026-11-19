// Conflict markers never reach main. No AI model.
// `git pull --rebase --autostash` re-applies a job's uncommitted files after the pull; when another job changed the same
// file, git writes <<<<<<< ======= >>>>>>> markers into it and leaves it for a person. Nobody is watching, so the next
// `git add -A` committed them (19 Nov 2026: data/leads/2026-11-19.jsonl and data/osint.json). Here:
//   heal()   after any pull: files with markers are merged the way git-sync merges a rebase (line files: union of both
//            sides; JSON objects: by key, this run's keys win); anything else is reported and left for refuse()
//   marked() the files among `paths` (or the staged ones) that still contain markers; finish.mjs and git-sync.mjs refuse
//            to commit or push while it is not empty
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { mergeJson, mergeLines } from "./merge.mjs";

const OPEN = /^<<<<<<< /, MID = /^=======$/, CLOSE = /^>>>>>>> /;
export const hasMarkers = (t) => /^<<<<<<< [^\n]*\n[\s\S]*?^=======\n[\s\S]*?^>>>>>>> /m.test(String(t || ""));

/** Pure: the two whole-file versions a marked text stands for: [upstream, stashed] (git's "Updated upstream" / "Stashed changes"). */
export function sides(text) {
  const up = [], mine = []; let state = 0;
  for (const l of String(text).split("\n")) {
    if (state === 0 && OPEN.test(l)) { state = 1; continue; }
    if (state === 1 && MID.test(l)) { state = 2; continue; }
    if (state === 2 && CLOSE.test(l)) { state = 0; continue; }
    if (state !== 2) up.push(l);
    if (state !== 1) mine.push(l);
  }
  return [up.join("\n"), mine.join("\n")];
}

/** Pure: the healed text of one marked file, or null when it cannot be merged safely. */
export function healText(file, text) {
  if (!hasMarkers(text)) return text;
  const [up, mine] = sides(text);
  if (/\.jsonl$/.test(file)) return mergeLines(up, mine);
  if (/\.json$/.test(file)) {
    try {
      const u = JSON.parse(up), m = JSON.parse(mine);
      if ([u, m].every((x) => x && typeof x === "object" && !Array.isArray(x))) return JSON.stringify(mergeJson({}, u, m), null, 2) + "\n";
    } catch { /* fall through */ }
  }
  return null;
}

const git = (root, ...a) => spawnSync("git", a, { cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
const read = (root, f) => { try { return readFileSync(join(root, f), "utf8"); } catch { return ""; } };

/** Files in the working tree with markers: unmerged entries plus modified tracked files. */
function candidates(root) {
  const u = git(root, "diff", "--name-only", "--diff-filter=U").stdout.split("\n");
  const m = git(root, "diff", "--name-only").stdout.split("\n");
  return [...new Set([...u, ...m].filter(Boolean))].filter((f) => existsSync(join(root, f)) && hasMarkers(read(root, f)));
}

/** Heal every marked file in the working tree. Returns { healed: [...], left: [...] }. */
export function heal(root = process.cwd()) {
  const healed = [], left = [];
  for (const f of candidates(root)) {
    const t = healText(f, read(root, f));
    if (t === null) { left.push(f); continue; }
    writeFileSync(join(root, f), t);
    git(root, "reset", "-q", "--", f);                                             // clear the unmerged state; the change stays in the tree
    healed.push(f);
  }
  if (healed.length) console.error(`conflicts: healed ${healed.join(", ")}`);
  if (left.length) console.error(`conflicts: cannot merge ${left.join(", ")} automatically; it will not be committed`);
  return { healed, left };
}

/** The files among `paths` (default: staged) whose content still has markers. */
export function marked(root = process.cwd(), paths = null) {
  const list = paths || git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR").stdout.split("\n").filter(Boolean);
  return list.filter((f) => hasMarkers(paths ? read(root, f) : git(root, "show", `:${f}`).stdout));
}

/** Files changed by the commits about to be pushed that contain markers at HEAD. */
export function markedInOutgoing(root = process.cwd(), base = "origin/main") {
  const files = git(root, "diff", "--name-only", "--diff-filter=ACMR", `${base}..HEAD`).stdout.split("\n").filter(Boolean);
  return files.filter((f) => hasMarkers(git(root, "show", `HEAD:${f}`).stdout));
}
