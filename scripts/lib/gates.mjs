// No-result gates: rules (no AI model, no network) that decide BEFORE a worker is started whether there is anything for
// it to find. Owner, 2026-11-23 ("make this highly efficient"; accuracy first; no event may be lost): measured over three
// days, about 570 of 1,550 worker runs ended with "no new", "unconfirmed", "not found" or "unchanged". A worker that
// re-reads the same pages an hour later finds the same nothing; these gates make the wait between two looks at the same
// item double with every look that changed nothing, and cut the wait to zero the moment something new arrives (a lead
// from a page the item does not cite, a stronger signal). Nothing is dropped: an item that is not due stays in its
// queue with the reason and the time it is due next, and every desk counts what it held back ("skipped: nothing new
// since <time>") in its plan line, its status note and efficiency.json `gates`.
// Every function here is pure and has unit tests (tests/unit/gates.test.mjs). The dials live in config/pipeline.json
// (followup_desk, claims_desk, outage_desk, sweep.gap_*); the defaults below are what an absent dial means.

const HOUR = 36e5;
const iso = (t) => new Date(t).toISOString().replace(/\.\d+Z$/, "Z");
const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : d);
const ms = (v) => { const t = Date.parse(v || ""); return Number.isFinite(t) ? t : 0; };

/** Pure: hours to wait after `n` looks in a row that changed nothing: base, 2x base, 4x base ... never more than cap.
 *  n = 0 (never looked, or the last look changed something) waits the base. */
export function backoffHours(n, base, cap) {
  const b = num(base, 6), c = Math.max(b, num(cap, b)), k = Math.max(0, Math.min(20, Math.floor(Number(n) || 0)));
  return Math.min(c, b * 2 ** k);
}
/** Pure: "nothing new since 2026-11-22 14:05 UTC; due again 2026-11-23 02:05 UTC" for plan lines and status notes. */
export const waitText = (since, next) => `nothing new since ${since ? iso(since).slice(0, 16).replace("T", " ") + " UTC" : "it was written"}${next ? `; due again ${iso(next).slice(0, 16).replace("T", " ")} UTC` : ""}`;

// ---------- the follow-up desk (scripts/followup-desk.mjs) ----------
export const FOLLOWUP_DEFAULTS = { window_days: 10, base_hours: 6, max_hours: 168, urgent_max_hours: 24, sev3_quiet_hours: 72, workers: 3, per_worker: 2 };
/** Pure: is an event urgent for the follow-up desk (a shorter cap on the wait)? Severity 3, an exploited flaw, or still developing. */
export function followupUrgent(e, deep = false) { return !!e && (deep || Number(e.severity) >= 3 || e.status === "developing"); }
/** Pure: the looks in a row that changed nothing, from the newest back. checks: [{ at, outcome }] of one event
 *  (outcome "updated" | "unchanged" | "unfinished"); a look that updated the event, or anyone updating the event after
 *  the last look (updatedAt), ends the run of no-change looks. "unfinished" (the worker was cut off before it got to
 *  the event) is not a look that found nothing: it does not lengthen the wait, but it is the last time the event was
 *  handed out, so the event comes back after the base wait and not in the very next run.
 *  -> { n, last (ms, 0 = never handed out) } */
export function noChangeRun(checks, updatedAt = 0) {
  const c = (checks || []).filter((x) => x && ms(x.at)).sort((a, b) => ms(b.at) - ms(a.at));
  const last = c.length ? ms(c[0].at) : 0; let n = 0;
  if (last && ms(updatedAt) > last) return { n: 0, last };
  for (const x of c) { if (x.outcome === "updated") break; if (x.outcome !== "unfinished") n++; }
  return { n, last };
}
/** Pure: does the follow-up desk plan this event now?
 *  e: the event; checks: its earlier follow-up looks [{ at, outcome }]; newLeadAt: when the newest lead that matches it
 *  from a page it does not cite was published (0/"" = none; scripts/updates.mjs matching); urgent: followupUrgent().
 *  Planned when (a) such a lead is newer than the last look (something new to read), or (b) nobody has touched the event
 *  (updated it or looked at it) for the backoff: base_hours doubling with every look in a row that changed nothing,
 *  capped at max_hours, or at urgent_max_hours for severity 3, exploited and developing events.
 *  firstHours: the wait before the FIRST follow-up of an event nobody has followed up yet, when it is longer than the
 *  base (followup_desk.sev3_quiet_hours 72 for an event that is in the pool only for its severity: a settled advisory).
 *  -> { plan, why, reason, n, last_at, next_at } (reason is the human line; why is "new-lead" | "due" | "never" | "wait") */
export function followupGate(e, checks = [], newLeadAt = 0, now = Date.now(), cfg = {}, urgent = followupUrgent(e), firstHours = 0) {
  const c = { ...FOLLOWUP_DEFAULTS, ...(cfg || {}) }, { n, last } = noChangeRun(checks, e && e.updated_at);
  const touched = Math.max(last, ms(e && (e.updated_at || e.first_seen))), lead = ms(newLeadAt);
  const back = backoffHours(n, c.base_hours, urgent ? Math.min(num(c.urgent_max_hours, 24), num(c.max_hours, 168)) : c.max_hours);
  const wait = (!last ? Math.max(back, Number(firstHours) || 0) : back) * HOUR, next = touched + wait;
  const base = { n, last_at: last ? iso(last) : null, next_at: iso(next) };
  if (lead && lead > last && last) return { ...base, plan: true, why: "new-lead", reason: `new reporting since the last follow-up (${iso(last).slice(0, 16).replace("T", " ")} UTC)` };
  if (now >= next) return { ...base, plan: true, why: last ? "due" : "never", reason: last ? `last follow-up ${Math.round((now - last) / HOUR)} h ago, ${n} in a row without a change (wait ${wait / HOUR} h${urgent ? ", urgent" : ""})` : "never followed up" };
  return { ...base, plan: false, why: "wait", reason: `skipped: ${waitText(touched, next)}${n ? ` (${n} follow-up${n === 1 ? "" : "s"} in a row without a change)` : ""}` };
}

// ---------- the claims desk (scripts/claims-desk.mjs) ----------
export const CLAIM_DEFAULTS = { recheck_hours: 24, recheck_max_hours: 168 };
/** Pure: is a leak-site claim that was already checked due for another check?
 *  r: its check on file ({ decision, checked_at, tries, same }); newReportAt: when the newest non-leak-site lead that
 *  names the victim was first seen (0 = none); exhausted: its result is final (not_found) or max_tries is reached.
 *  - a report newer than the last check: now, whatever the result was (also for not_found and for max_tries reached:
 *    somebody is now writing about the victim, which is exactly what the earlier check did not find)
 *  - else an exhausted claim is never re-checked
 *  - else after recheck_hours, doubling with every check in a row that gave the same result (r.same, else r.tries),
 *    capped at recheck_max_hours (24 h, 48 h, 96 h, 7 days)
 *  -> { due, why: "new-report" | "backoff" | "wait" | "final", reason, next_at } */
export function claimRecheck(r, newReportAt = 0, now = Date.now(), cfg = {}, exhausted = false) {
  const c = { ...CLAIM_DEFAULTS, ...(cfg || {}) }, last = ms(r && r.checked_at), rep = ms(newReportAt);
  if (!r || !last) return { due: true, why: "new", reason: "never checked", next_at: null };
  if (rep > last) return { due: true, why: "new-report", reason: `a new report names the victim since the last check (${iso(last).slice(0, 16).replace("T", " ")} UTC)`, next_at: iso(now) };
  if (exhausted) return { due: false, why: "final", reason: `skipped: ${r.decision || "checked"}, final; re-opened only when a new report names the victim`, next_at: null };
  const same = Math.max(1, Number(r.same) || Number(r.tries) || 1), next = last + backoffHours(same - 1, c.recheck_hours, c.recheck_max_hours) * HOUR;
  if (now >= next) return { due: true, why: "backoff", reason: `${r.decision || "checked"} ${same} time${same === 1 ? "" : "s"} in a row; the wait of ${(next - last) / HOUR} h is over`, next_at: iso(next) };
  return { due: false, why: "wait", reason: `skipped: ${waitText(last, next)} (${r.decision || "checked"} ${same} time${same === 1 ? "" : "s"} in a row)`, next_at: iso(next) };
}

// ---------- the outage desk (scripts/outage-desk.mjs) ----------
export const OUTAGE_DEFAULTS = { recheck_hours: 12, recheck_max_hours: 168, stronger_factor: 2 };
/** Pure: the strength of a report as the desk saw it when it was checked (kept on the check as `seen`), so a later
 *  report with the same key can be told apart from the same thing again. */
export function outageSeen(it) {
  return { score: Number(it && it.score) || 0, publishers: Array.isArray(it && it.publishers) ? it.publishers.length : 0, figure: Number(it && it.figure && it.figure.n) || 0, cyber: !!(it && it.cyber_headline), last_seen: String((it && it.last_seen) || "").slice(0, 20) };
}
/** Pure: is this report stronger than what the last check saw? An IODA score at least stronger_factor times as high, a
 *  publisher more, a stated figure at least stronger_factor times as high, or a cyberattack headline that was not there.
 *  A check without `seen` (written before 2026-11-23) cannot be compared: false. */
export function outageStronger(it, seen, cfg = {}) {
  if (!seen || typeof seen !== "object") return false;
  const f = Math.max(1.1, num(({ ...OUTAGE_DEFAULTS, ...(cfg || {}) }).stronger_factor, 2)), now = outageSeen(it);
  return (now.score > 0 && seen.score > 0 && now.score >= seen.score * f) || now.publishers > (Number(seen.publishers) || 0) || (now.figure > 0 && now.figure >= (Number(seen.figure) || 0) * f && now.figure > (Number(seen.figure) || 0)) || (now.cyber && !seen.cyber);
}
/** Pure: is a report whose key (the same country's IODA signal on another day, the same news outage) was already checked
 *  and not confirmed due for another check?
 *  history: every check on file with this key [{ decision, checked_at, tries, seen }].
 *  - the report is stronger than at the last check: now
 *  - else after recheck_hours, doubling with every not_confirmed check in a row on this key (tries added up), capped at
 *    recheck_max_hours: a country whose IODA signal is noise is looked at after 12 h, 24 h, 48 h ... then weekly
 *  A confirmed or cyber_lead check on the key ends the run (the caller decides what a final result means for one item).
 *  -> { due, why: "new" | "stronger" | "backoff" | "wait", reason, next_at, n } */
export function outageRecheck(it, history = [], now = Date.now(), cfg = {}) {
  const c = { ...OUTAGE_DEFAULTS, ...(cfg || {}) }, h = (history || []).filter((v) => v && ms(v.checked_at)).sort((a, b) => ms(b.checked_at) - ms(a.checked_at));
  if (!h.length) return { due: true, why: "new", reason: "never checked", next_at: null, n: 0 };
  const last = ms(h[0].checked_at); let n = 0;
  for (const v of h) { if (v.decision !== "not_confirmed") break; n += Math.max(1, Number(v.tries) || 1); }
  if (h[0].decision === "not_confirmed" && outageStronger(it, h[0].seen, c)) return { due: true, why: "stronger", reason: "a stronger report than at the last check", next_at: iso(now), n };
  const next = last + backoffHours(Math.max(0, n - 1), c.recheck_hours, c.recheck_max_hours) * HOUR;
  if (now >= next) return { due: true, why: "backoff", reason: n ? `not confirmed ${n} time${n === 1 ? "" : "s"} in a row; the wait of ${(next - last) / HOUR} h is over` : "checked before; the wait is over", next_at: iso(next), n };
  return { due: false, why: "wait", reason: `skipped: ${waitText(last, next)}${n ? ` (not confirmed ${n} time${n === 1 ? "" : "s"} in a row)` : ""}`, next_at: iso(next), n };
}

// ---------- gap searchers (scripts/run-job.mjs gapCount, scripts/job-prompt.mjs) ----------
export const GAP_DEFAULTS = { gap_every_minutes: 60, gap_max_every_minutes: 480 };
/** Pure: gap run logs -> how many of the newest in a row added no event and updated none. runs: [{ at, added, updated }]. */
export function gapDryRun(runs) {
  let n = 0;
  for (const r of (runs || []).filter((x) => x && ms(x.at)).sort((a, b) => ms(b.at) - ms(a.at))) { if ((Number(r.added) || 0) + (Number(r.updated) || 0) > 0) break; n++; }
  return n;
}
/** Pure: minutes between two gap passes. A gap searcher has no input to wait for (it looks for what no collector sent),
 *  so the only signal is its own yield: every `per` runs in a row that added nothing double the interval, from
 *  gap_every_minutes up to gap_max_every_minutes; one run that adds an event brings it back to the base.
 *  per = 4 runs (two passes of two searchers). */
export function gapEveryMinutes(dry, sc = {}, per = 4) {
  const c = { ...GAP_DEFAULTS, ...(sc || {}) }, base = Math.max(15, num(c.gap_every_minutes, 60)), cap = Math.max(base, num(c.gap_max_every_minutes, 480));
  return Math.min(cap, base * 2 ** Math.min(10, Math.floor(Math.max(0, Number(dry) || 0) / Math.max(1, per))));
}

// ---------- clocks that survive a restart ----------
/** Pure: when a role (base name; "followup" also counts "followup-deep") last ran, from the usage ledger's lines, as ms
 *  (0 = never). The research loop restarts every few minutes (flow.foreground_minutes), so a clock kept in the process
 *  starts at zero each time: measured 2026-11-22, the follow-up desk ran every 15 minutes instead of every 2 hours. */
export function lastRunOf(lines, base) {
  let t = 0;
  for (const l of lines || []) { if (!l || String(l.role || "").replace(/-deep$/, "") !== base) continue; const at = ms(l.at); if (at > t) t = at; }
  return t;
}
