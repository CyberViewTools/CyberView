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

import { siteOf } from "./validate.mjs";

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

// ---------- the on-file gate (scripts/updates.mjs plan) ----------
// Owner, 2026-11-23: "gate only, don't close". A story that a rule closed as "already on file: <event>" comes back every
// time one more page joins it (one story 31 times in five days). When that page is only the same publishers saying the
// same thing, no updater is started for it; nothing is closed, marked handled or dropped. The story and its leads stay
// open, and the gate lets it through the moment anything below shows up, or when the wait is over.
export const ONFILE_DEFAULTS = { wait_hours: 24 };
const ONFILE = /already on file: ([a-z0-9][a-z0-9-]{2,119})/;
const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
const SCALE = { thousand: 1e3, k: 1e3, million: 1e6, m: 1e6, billion: 1e9, bn: 1e9, b: 1e9 };
/** Pure: the slug an "already on file: <slug>" closure names, "" for any other reason. */
export const onFileSlug = (reason) => { const m = ONFILE.exec(String(reason || "").toLowerCase()); return m ? m[1] : ""; };
/** Pure: the figures a text states, as comparable strings: "1.2 million" -> "n1200000", "15,000" -> "n15000", "40%" -> "p40".
 *  Bare numbers under 1,000 and years are not figures; a figure in any other form reopens (it is not found on the event). */
export function figuresIn(text) {
  const t = String(text || "").replace(/(\d),(?=\d{3}\b)/g, "$1"), out = new Set();
  for (const m of t.matchAll(/(\d+(?:\.\d+)?)\s?(thousand|million|billion|bn|k|m|b)\b/gi)) out.add("n" + Math.round(Number(m[1]) * SCALE[m[2].toLowerCase()]));
  for (const m of t.matchAll(/(\d+(?:\.\d+)?)\s?%/g)) out.add("p" + Number(m[1]));
  for (const m of t.matchAll(/\b(\d{4,})\b(?!\s?(?:thousand|million|billion|bn|k|m|b)\b)/gi)) { const n = Number(m[1]); if (!(n >= 1900 && n <= 2100)) out.add("n" + n); }
  return out;
}
// every text the event states, not its urls, ids or times: a figure the event does not say is new to it
function eventText(v, key = "") {
  if (typeof v === "string") return /url|date|_at$|^id$|first_seen|published/i.test(key) ? "" : v + " ";
  if (Array.isArray(v)) return v.map((x) => eventText(x, key)).join("");
  if (v && typeof v === "object") return Object.entries(v).map(([k, x]) => eventText(x, k)).join("");
  return typeof v === "number" ? String(v) + " " : "";
}
/** Pure: should a worker be started for the new pages of a story that was closed "already on file"?
 *  closure: its latest closure { at, reason }; event: the event it names (null when it no longer exists); leads: the story's
 *  pages [{ url, title, source, tier, kind, seen_at | published }]; only those newer than the closure are new input.
 *  A publisher is a registrable domain (siteOf: news.example.co.uk and www.example.co.uk are one), compared with the
 *  domains of the event's sources. Due (never skipped) when: the closure names no live event (missing, a duplicate, or
 *  another event than the one passed), a page has no time, a page is from a domain the event does not cite, a page is
 *  from a government, vendor or research source, a leak-site claim or a regulator's notice, a CVE the event does not
 *  name, a figure the event does not state, or the wait is over (cfg.wait_hours since the closure).
 *  Aggregator redirects count for nothing: no one can read or cite them. Rejected as reopen signals, on purpose: a new
 *  headline word, a new date, a non-English page (all too weak, and a skipped story keeps its wait anyway).
 *  -> { due, why, reason, next_at, signals } (why: "no-closure" | "dangling" | "new-input" | "reopened" | "backoff" | "wait" | "nothing-new") */
export function onFileGate(closure, event, leads, now = Date.now(), cfg = {}) {
  const c = { ...ONFILE_DEFAULTS, ...(cfg || {}) }, at = ms(closure && closure.at), slug = onFileSlug(closure && closure.reason);
  const due = (why, reason, signals = []) => ({ due: true, why, reason, next_at: iso(now), signals });
  if (!slug || !at) return due("no-closure", "not closed as already on file");
  if (!event || event.id !== slug || event.duplicate_of) return due("dangling", `the closure names ${slug}, which is ${!event ? "not on file now" : event.id !== slug ? "not the event matched now" : "a duplicate of " + event.duplicate_of}`);
  const fresh = (leads || []).filter((l) => l && !/^https:\/\/(news\.google\.com\/|(www\.)?bing\.com\/news|(www\.)?msn\.com\/)/.test(String(l.url || "")) && (!ms(l.seen_at || l.published) || ms(l.seen_at || l.published) > at));
  const next = at + num(c.wait_hours, 24) * HOUR, signals = [];
  const sites = new Set((event.sources || []).map((s) => siteOf(s && s.url)).filter(Boolean)), text = eventText({ ...event, sources: (event.sources || []).map((s) => ({ title: s && s.title })) });
  const have = figuresIn(text), cves = new Set((String(text).match(CVE_RE) || []).concat(event.cves || []).map((x) => x.toUpperCase()));
  for (const l of fresh) {
    const title = String(l.title || "");
    if (!ms(l.seen_at || l.published)) signals.push("a page with no time");
    if (!siteOf(l.url) || !sites.has(siteOf(l.url))) signals.push(`a new publisher (${siteOf(l.url) || "unknown"})`);
    if (["gov", "vendor", "research"].includes(l.tier)) signals.push(`a ${l.tier} source`);
    if (l.kind === "claim" || l.kind === "breach-notice" || l.kind === "exploited" || l.kind === "advisory") signals.push(`a ${l.kind} lead`);
    for (const x of title.match(CVE_RE) || []) if (!cves.has(x.toUpperCase())) signals.push(`a new CVE (${x.toUpperCase()})`);
    for (const f of figuresIn(title)) if (!have.has(f)) signals.push(`a figure the event does not state (${f.slice(1)}${f[0] === "p" ? "%" : ""})`);
  }
  const uniq = [...new Set(signals)];
  if (uniq.length) return due("reopened", `reopened: ${uniq.slice(0, 3).join("; ")}`, uniq);
  if (now >= next) return { ...due("backoff", `already on file as ${slug}; the wait of ${num(c.wait_hours, 24)} h is over`), next_at: iso(next) };
  const nothing = !fresh.length;
  return { due: false, why: nothing ? "nothing-new" : "wait", reason: `skipped: already on file as ${slug}; ${nothing ? "no new page since the closure" : fresh.length + " new page" + (fresh.length === 1 ? "" : "s") + " from publishers the event already cites, no new figure or CVE"}; ${waitText(at, next)}`, next_at: iso(next), signals: [] };
}
/** Pure: the updater plan's candidates ({ id, leads }) -> { due, skipped }. closures: latest on-file closure per event id
 *  ({ at, reason }); events: every event by id. A skipped candidate keeps its reason and next_at and is not removed from
 *  anywhere: only the worker is not started; the lead stays open. A candidate with no closure on file is always due. */
export function gateOnFile(cands, events, closures, now = Date.now(), cfg = {}) {
  const ev = events instanceof Map ? events : new Map((events || []).map((e) => [e && e.id, e])), due = [], skipped = [];
  for (const k of cands || []) {
    const g = onFileGate(closures && closures[k.id], ev.get(k.id) || null, k.leads, now, cfg);
    if (g.due) due.push(k); else skipped.push({ id: k.id, why: g.why, reason: g.reason, next_at: g.next_at });
  }
  const nexts = skipped.map((s) => s.next_at).filter(Boolean).sort();
  return { due, skipped, next_due_at: nexts[0] || null };
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
