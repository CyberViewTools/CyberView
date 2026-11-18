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
import { readFileSync, readdirSync, writeFileSync, mkdirSync, existsSync, statSync, renameSync, unlinkSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const DATA = join(ROOT, "data");

export const readJson = (p, d = null) => { try { return JSON.parse(readFileSync(p, "utf8")); } catch { return d; } };
export function writeJson(p, o) { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(o, null, 2) + "\n"); }
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

/** Save an event in its month folder. If its date moved it to another month, the old file is moved, not copied. */
export function saveEvent(e, oldPath) {
  const { id, ...rest } = e; const p = eventPath(e);   // the id lives in the file name, not the file
  writeJson(p, rest);
  if (oldPath && oldPath !== p && existsSync(oldPath)) unlinkSync(oldPath);
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
  const p = join(DATA, "runs", t.slice(0, 10), `${t.slice(11, 16).replace(":", "")}-${job}.json`);
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
