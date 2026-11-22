// Shared access to the data/ folder. Every script reads and writes records through here so the layout lives in one place.
//
// Layout (all plain JSON, one record per file, never deleted):
//   data/events/<YYYY-MM>/<id>.json   events, sharded by the event's month ("date" field)
//   data/kev/<CVE>.json               CISA known-exploited entries (full history; the site shows the last 45 days)
//   data/corrections/<id>.json        corrections log
//   data/runs/<YYYY-MM-DD>/<HHMM>-<job>.json   research log of every job run: searches, pages read, added, skipped leads
//   data/snapshots/brief/<YYYY-MM-DD>.json      daily brief, kept for history
//   data/snapshots/analysis/<YYYY-MM-DD>.json   patterns and ripples, one per day
//   data/status.json, analysis.json, ripples.json, brief.json, history.json   the current single documents
//   data/quality.json                 the pipeline check's findings (scripts/pipecheck.mjs; stages in scripts/lib/stages.mjs)
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync, writeFileSync, mkdirSync, existsSync, statSync, renameSync, unlinkSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const DATA = join(ROOT, "data");

export const readJson = (p, d = null) => { try { return JSON.parse(readFileSync(p, "utf8")); } catch { return d; } };
/** Write JSON atomically (a temporary file, then a rename), so a reader running at the same time (the build, a commit,
 *  a background script) never sees half a file. */
export function writeJson(p, o) {
  mkdirSync(dirname(p), { recursive: true });
  const t = `${p}.tmp-${process.pid}`;
  writeFileSync(t, JSON.stringify(o, null, 2) + "\n");
  try { renameSync(t, p); } catch (e) { try { unlinkSync(t); } catch {} throw e; }
}
export const nowIso = () => new Date().toISOString().replace(/\.\d+Z$/, "Z");
export const dayAgo = (n) => new Date(Date.now() - n * 864e5).toISOString().slice(0, 10);

function walk(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out); else if (name.endsWith(".json")) out.push(p);
  }
  return out;
}

/** The folder an event belongs in, from its date. */
export const monthOf = (e) => (/^\d{4}-\d{2}/.test(e && e.date || "") ? e.date.slice(0, 7) : "undated");
export const eventPath = (e) => join(DATA, "events", monthOf(e), `${e.id}.json`);

/** All event files: [{ path, id, e, error }]. id comes from the file name. */
export function listEventFiles() {
  return walk(join(DATA, "events")).map((path) => {
    const id = basename(path, ".json");
    try { return { path, id, e: { id, ...JSON.parse(readFileSync(path, "utf8")) } }; }
    catch (err) { return { path, id, e: null, error: err.message }; }
  });
}

/** Find one event by id wherever it is stored. */
export function findEvent(id) {
  return listEventFiles().find((x) => x.id === id) || null;
}

/** Pure: of all event file paths, the ones for this id that are not the kept path — stale copies to remove.
 *  An event whose date moves to another month is written to the new folder; its old-folder file must go, or the id is
 *  "stored twice" and the build aborts (e.g. a date corrected across a month boundary). */
export function straysFor(id, keepPath, paths) {
  const name = `${id}.json`;
  return (paths || []).filter((q) => q !== keepPath && basename(q) === name);
}

/** Save an event in its month folder. If its date moved it to another month, the old file is removed, not copied — and
 *  so is any other same-id file left anywhere under events/, whether or not the caller tracked the old path. */
export function saveEvent(e, oldPath) {
  const { id, ...rest } = e; const p = eventPath(e);   // the id lives in the file name, not the file
  writeJson(p, rest);
  const remove = new Set(straysFor(id, p, walk(join(DATA, "events"))));
  if (oldPath && oldPath !== p) remove.add(oldPath);
  for (const q of remove) { try { if (existsSync(q)) unlinkSync(q); } catch {} }
  return p;
}

/** Plain records in a flat folder (kev, corrections). */
export function listDir(dir) {
  return walk(join(DATA, dir)).map((path) => {
    const id = basename(path, ".json");
    try { return { path, id, r: { id, ...JSON.parse(readFileSync(path, "utf8")) } }; }
    catch (err) { return { path, id, r: null, error: err.message }; }
  });
}

/** Write a research log for a job run. */
export function writeRunLog(job, log) {
  const t = nowIso();
  // several agents can finish in the same minute: never overwrite another run's log
  const base = join(DATA, "runs", t.slice(0, 10), `${t.slice(11, 16).replace(":", "")}-${job}`);
  let p = `${base}.json`; for (let i = 2; existsSync(p) && i < 60; i++) p = `${base}-${i}.json`;
  writeJson(p, { job, ...log });
  return p;
}

/** Move any event still in the old flat layout into its month folder. Returns the number moved. */
export function migrateFlatEvents() {
  const dir = join(DATA, "events"); let n = 0;
  if (!existsSync(dir)) return 0;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (!name.endsWith(".json") || statSync(p).isDirectory()) continue;
    const e = readJson(p); if (!e) continue;
    const target = join(dir, monthOf(e), name);
    mkdirSync(dirname(target), { recursive: true }); renameSync(p, target); n++;
  }
  return n;
}

/** Every lead URL a run log or a story closure has ruled out in the last `days` days. Run logs are <HHMM>-<job>.json with a
 *  "skipped" list; story closures are lines in each day's closures.jsonl ({story, reason, urls}). Calls fn(url, reason). */
export function forEachSkipped(days, fn) {
  const dir = join(DATA, "runs"); if (!existsSync(dir)) return;
  for (const d of readdirSync(dir).filter((d) => d >= dayAgo(days)))
    for (const f of readdirSync(join(dir, d))) {
      if (f.endsWith(".jsonl")) { for (const line of readFileSync(join(dir, d, f), "utf8").split("\n")) { if (!line) continue; try { const c = JSON.parse(line); (c.urls || []).forEach((u) => fn(u, c.reason || "")); } catch {} } }
      else if (f.endsWith(".json")) (readJson(join(dir, d, f), {}).skipped || []).forEach((l) => l && l.url && fn(l.url, l.reason || ""));
    }
}

/** data/status.json for a read-modify-write. Never an empty object by accident: if the file does not parse (a write
 *  in progress, or conflict markers left by another job's pull), fall back to the last committed copy, so a writer can
 *  only add or change its own keys and never wipe everyone else's. */
export function readStatus() {
  const p = join(DATA, "status.json");
  try { return JSON.parse(readFileSync(p, "utf8")); } catch {}
  // the last committed copy: on the data branch (./data is its own checkout, the layout since 2026-11-20), else in main's
  // old layout. Before 2026-11-20 only the second existed, so on the data branch every fallback returned {} and the next
  // write wiped every other job's keys (18 lost at 20:54Z on 2026-11-20).
  for (const [cwd, ref] of [[DATA, "HEAD:status.json"], [ROOT, "HEAD:data/status.json"]]) {
    try { const r = spawnSync("git", ["show", ref], { cwd, encoding: "utf8" }); if (r.status === 0) { const o = JSON.parse(r.stdout); if (o && typeof o === "object" && !Array.isArray(o)) return o; } } catch {}
  }
  return {};
}
