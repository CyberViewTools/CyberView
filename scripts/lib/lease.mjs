// Leases: a run claims the items it will work so no other run (another schedule, a catch-up session in another container)
// takes them at the same time. Kept in data/leases.json, which is committed, so every container sees every claim.
// A lease expires on its own (default 45 minutes), so a crashed run never blocks an item for long.
// { "<kind>:<id>": { "run": "<run id>", "until": "<ISO time>" } }
import { join } from "node:path";
import { DATA, readJson, writeJson, nowIso } from "./store.mjs";

const FILE = join(DATA, "leases.json");
const live = (l, now) => l && Date.parse(l.until) > now;

/** Pure: which ids are held by a live lease of another run. */
export function heldBy(leases, kind, ids, run, now = Date.now()) {
  return new Set(ids.filter((id) => { const l = leases[`${kind}:${id}`]; return live(l, now) && l.run !== run; }));
}
/** Pure: leases with expired entries dropped and these ids claimed for run. */
export function withClaims(leases, kind, ids, run, minutes = 45, now = Date.now()) {
  const out = {}; for (const [k, l] of Object.entries(leases || {})) if (live(l, now)) out[k] = l;
  const until = new Date(now + minutes * 6e4).toISOString().replace(/\.\d+Z$/, "Z");
  ids.forEach((id) => { out[`${kind}:${id}`] = { run, until }; });
  return out;
}
export function readLeases() { return readJson(FILE, {}); }
/** Ids of `kind` that another run holds right now (planners leave them out). */
export function leased(kind, ids, run = "") { return heldBy(readLeases(), kind, ids, run); }
export function claim(kind, ids, run, minutes) { writeJson(FILE, withClaims(readLeases(), kind, ids, run, minutes)); }
export function release(run) {
  const now = Date.now(), out = {};
  for (const [k, l] of Object.entries(readLeases())) if (live(l, now) && l.run !== run) out[k] = l;
  writeJson(FILE, out);
}
export const RUN_ID = () => process.env.CYBERVIEW_RUN || `run-${nowIso().replace(/[-:]/g, "").slice(0, 13)}-${process.pid}`;

/* ---- the research loop's leader lease: one loop at a time across every session and container ----
   The loop that runs holds "flow:leader" in data/leases.json (committed, so every container sees it) and renews it every
   cycle; a standby session starts a loop only when that lease has expired. It is also the loop's heartbeat. */
export const LEADER_MIN = 20;
/** Pure: the live leader lease, or null. */
export function leaderOf(leases, now = Date.now()) { const l = leases && leases["flow:leader"]; return l && Date.parse(l.until) > now ? l : null; }
