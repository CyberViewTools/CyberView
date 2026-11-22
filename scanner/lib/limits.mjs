// Politeness limits: rate, concurrency, per-host and global connection budgets, and the run's time limit.
// The defaults are also the ceilings: an operator can set any of them LOWER, never higher, and none can be switched off.
// There is no faster mode and no switch that removes a limit.

export const CAPS = Object.freeze({
  rate: 20,             // new connections per second, whole scan
  concurrency: 8,       // connections open at once, whole scan
  hostConcurrency: 2,   // connections open at once to one host
  hostBudget: 300,      // connections to one host in one run
  budget: 20000,        // connections in one run
  minutes: 480,         // the longest a run may last
});
export const DEFAULTS = Object.freeze({ rate: 20, concurrency: 8, hostConcurrency: 2, hostBudget: 300, budget: 20000, minutes: 60 });
// fixed per-connection limits (not configurable upward either)
export const TIMEOUTS = Object.freeze({ connectMs: 3000, readMs: 4000, maxBytes: 16384 });

/** Operator settings -> { ok, problems[], settings }. A value above its ceiling or below 1 is refused, not clamped. */
export function settings(opts = {}) {
  const problems = [], out = { ...DEFAULTS };
  for (const k of Object.keys(DEFAULTS)) {
    if (opts[k] === undefined || opts[k] === null || opts[k] === "") continue;
    const v = Number(opts[k]);
    if (!Number.isFinite(v) || v <= 0) { problems.push(`--${flag(k)} must be a positive number`); continue; }
    if (v > CAPS[k]) { problems.push(`--${flag(k)} ${v} is above the ceiling of ${CAPS[k]}; limits can only be lowered`); continue; }
    out[k] = k === "rate" || k === "minutes" ? v : Math.max(1, Math.floor(v));
  }
  if (out.rate < 0.1) problems.push("--rate must be at least 0.1 connections per second");
  return { ok: problems.length === 0, problems, settings: out };
}
export const flag = (k) => ({ rate: "rate", concurrency: "concurrency", hostConcurrency: "host-concurrency", hostBudget: "host-budget", budget: "budget", minutes: "max-minutes" }[k] || k);

/**
 * Hands out permission to open one connection. acquire(host) waits for a global slot, a per-host slot and the rate spacing,
 * and resolves to a release function, or to null when the run is stopped or a budget is spent (the caller skips the probe).
 * clock: { now(), sleep(ms) } for tests.
 */
export class Limiter {
  constructor(s, clock = { now: () => Date.now(), sleep: (ms) => new Promise((r) => setTimeout(r, ms)) }) {
    this.s = s; this.clock = clock; this.active = 0; this.byHost = new Map(); this.usedByHost = new Map();
    this.used = 0; this.nextAt = 0; this.waiters = []; this.stopped = ""; this.maxActive = 0; this.denied = { host: 0, global: 0 };
    this.deadline = clock.now() + s.minutes * 60e3;
  }
  stop(reason) { if (!this.stopped) this.stopped = reason || "stopped"; const w = this.waiters; this.waiters = []; w.forEach((f) => f()); }
  remainingMs() { return Math.max(0, this.deadline - this.clock.now()); }
  _free(host) { return this.active < this.s.concurrency && (this.byHost.get(host) || 0) < this.s.hostConcurrency; }
  async acquire(host) {
    for (;;) {
      if (this.stopped) return null;
      if (this.clock.now() >= this.deadline) { this.stop("time limit reached"); return null; }
      if (this.used >= this.s.budget) { this.denied.global++; return null; }
      if ((this.usedByHost.get(host) || 0) >= this.s.hostBudget) { this.denied.host++; return null; }
      if (this._free(host)) break;
      await new Promise((r) => this.waiters.push(r));
    }
    // take the slots and the budget now, then wait for the rate spacing
    this.active++; this.byHost.set(host, (this.byHost.get(host) || 0) + 1); this.maxActive = Math.max(this.maxActive, this.active);
    this.used++; this.usedByHost.set(host, (this.usedByHost.get(host) || 0) + 1);
    const gap = 1000 / this.s.rate, now = this.clock.now(), at = Math.max(now, this.nextAt);
    this.nextAt = at + gap;
    if (at > now) await this.clock.sleep(at - now);
    let done = false;
    const release = () => {
      if (done) return; done = true;
      this.active--; const n = (this.byHost.get(host) || 1) - 1; if (n) this.byHost.set(host, n); else this.byHost.delete(host);
      const w = this.waiters; this.waiters = []; w.forEach((f) => f());
    };
    if (this.stopped) { release(); return null; }
    return release;
  }
  stats() { return { connections: this.used, max_open_at_once: this.maxActive, skipped_host_budget: this.denied.host, skipped_global_budget: this.denied.global, stopped: this.stopped || "" }; }
}

/** Run fn over items with at most `n` running at once (used for hosts; connections are limited by the Limiter). */
export async function pool(items, n, fn) {
  let i = 0;
  const worker = async () => { while (i < items.length) { const k = i++; await fn(items[k], k); } };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(n, items.length)) }, worker));
}
