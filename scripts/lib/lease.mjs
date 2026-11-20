// Leases: a run claims the items it will work so no other run (another schedule, a catch-up session in another container)
// takes them at the same time. Kept in data/leases.json, which is committed, so every container sees every claim.
// A lease expires on its own (default 45 minutes), so a crashed run never blocks an item for long.
// { "<kind>:<id>": { "run": "<run id>", "until": "<ISO time>" } }
import { join } from "node:path";
import { openSync, writeSync, closeSync, unlinkSync } from "node:fs";
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
/** Which session this is, as the leader lease records it. */
export const hostId = (env = process.env) => String(env.CLAUDE_CODE_REMOTE_SESSION_ID || env.HOSTNAME || "local").slice(-40);
/** Pure: does a live leader lease stop this session from starting a loop? Not when the lease was taken by THIS session
 *  and no loop is running here (localAlive false): that loop died (its container restarted, or its process was killed)
 *  without releasing the lease, and waiting for the lease to run out left the research idle for up to LEADER_MIN minutes
 *  (measured: 21 minutes with no loop on 2026-11-20, 00:29 to 00:50). Another session's lease is always respected. */
export function leaderBlocks(leader, run, host, localAlive) {
  if (!leader || leader.run === run) return false;
  return !(leader.host && leader.host === host && !localAlive);
}
/** Pure: the live leader lease this loop (run, started at `since`) must give way to, or null. Two loops can each believe they
 *  lead: a loop that read a stale leases.json starts while another holds the lease, and git-sync's merge of leases.json lets
 *  the key a commit changed win, so each loop's renewal overwrote the other's and neither ever looked again (2026-11-19 and
 *  -20: four overlaps, up to 100 minutes, double the plan usage). Every loop now checks each cycle and the OLDER loop keeps
 *  the lead (earlier `since`, then the smaller run id), so both sides agree on who stops. A lease without `since` was taken
 *  by code older than this check, which never gives way, so it counts as the oldest. */
export function yieldsTo(leases, run, since, now = Date.now()) {
  const l = leaderOf(leases, now); if (!l || l.run === run) return null;
  const a = String(l.since || ""), b = String(since || "");
  return a < b || (a === b && String(l.run) < String(run)) ? l : null;
}
/** Take this container's loop lock atomically (create-exclusive), so two starts a few seconds apart in one container cannot
 *  both pass the "is a loop running here?" check while the first is still probing the web (2026-11-19 16:49 and 16:50: two
 *  loops, pids 3034 and 5023). A lock whose loop is gone (alive(lock) false) is replaced. Returns true when taken. */
export function takeLock(file, alive, body = {}) {
  for (let i = 0; i < 2; i++) {
    try { const fd = openSync(file, "wx"); writeSync(fd, JSON.stringify({ pid: process.pid, beat: nowIso(), ...body })); closeSync(fd); return true; }
    catch (e) {
      if (e.code !== "EEXIST") return true;            // cannot lock at all (read-only /tmp): behave as before rather than never run
      if (alive(readJson(file, null))) return false;
      try { unlinkSync(file); } catch {}
    }
  }
  return false;
}
