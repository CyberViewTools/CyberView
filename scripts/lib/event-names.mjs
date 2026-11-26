// Event file names are the event ids: lowercase letters, digits and hyphens (scripts/build.mjs checkEvent). A worker that
// saves "gh0strat-oCam-...json" makes the strict build fail; the job then commits with --force and the deploy quarantines
// the record, but build.yml checks every pull request against the data branch strictly, so one such file turned CI red for
// every pull request (2026-11-26). scripts/finish.mjs renames NEW (never committed) event files to a valid name before it
// builds. A committed file is never renamed here (that would be a delete in the data branch's history).
import { renameSync, existsSync } from "node:fs";
import { join, dirname, basename } from "node:path";

export const ID_RE = /^[a-z0-9][a-z0-9-]{2,119}$/;

/** Pure: a valid id for a file name stem, or null when none can be made: lowercase, every run of other characters becomes
 *  one hyphen, no hyphen at the ends, at most 120 characters. */
export function validId(stem) {
  const id = String(stem || "").toLowerCase().normalize("NFKD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9-]+/g, "-").replace(/-{2,}/g, "-").replace(/^-+|-+$/g, "").slice(0, 120).replace(/-+$/, "");
  return ID_RE.test(id) ? id : null;
}

/** Rename the NEW event files among `paths` (relative to `root`, e.g. "events/2026-11/x.json") whose name is not a valid id.
 *  Returns [{ from, to }] for every rename, and [{ from, to: null }] for a file it could not fix (left as is, the build reports
 *  it). Never overwrites an existing file. */
export function fixNewEventNames(root, paths) {
  const out = [];
  for (const p of paths || []) {
    if (!/^events\/.+\.json$/.test(p)) continue;
    const stem = basename(p, ".json");
    if (ID_RE.test(stem)) continue;
    const id = validId(stem), to = id ? join(dirname(p), id + ".json") : null;
    if (!to || existsSync(join(root, to))) { out.push({ from: p, to: null }); continue; }
    try { renameSync(join(root, p), join(root, to)); out.push({ from: p, to }); } catch { out.push({ from: p, to: null }); }
  }
  return out;
}
