// Second-pair-of-eyes review of new events, the mechanical half. No AI model. Run: node scripts/review.mjs <command>
// Every event is written by one agent. Before it is trusted it is reviewed by a different one (the review desk job).
// This script finds what needs review and does the checks a machine can do, so the reviewers spend their time on the
// checks only a reader can do (does the source really say this?).
//   node scripts/review.mjs queue [--limit 30] [--json]   events added or changed in the last 72 hours that have no review
//                                                         of their current version: any waiting over 20 minutes first
//                                                         (oldest first), then highest risk, each with its flags
//   node scripts/review.mjs flags <id>                    the mechanical flags for one event
//   node scripts/review.mjs pass <id> "<what was checked>"            reviewed against its sources; nothing wrong
//   node scripts/review.mjs corrected <id> "<what was wrong and is now fixed>"   reviewed; the reviewer fixed the record first
//   node scripts/review.mjs flagged <id> "<the problem>"             reviewed; a problem remains that the reviewer could not settle
//   node scripts/review.mjs errors [--days 7] [--json]   what the second review corrects, by type (ERROR_TYPES) and by the role
//                                                         and model that wrote the event (from the run logs)
// pass/corrected/flagged write the event's "review" {state, at, first_at, note, flags} and qa_checked_at (first_at is the time
// of the event's first review, kept through re-reviews of later updates); "flagged" also lowers
// validation to "disputed" so the site shows low confidence until the verify job settles it.
import { leased } from "./lib/lease.mjs";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { existsSync, readdirSync } from "node:fs";
import { DATA, ROOT, readJson, writeJson, listEventFiles, saveEvent, findEvent, nowIso, dayAgo } from "./lib/store.mjs";
import { tokens } from "./triage.mjs";
import { checkEventQuality, sharedSourceProblems, ACCURACY_STRICT_FROM } from "./lib/validate.mjs";

const REDIRECT = /^https?:\/\/(news\.google\.com|(www\.)?bing\.com|(www\.)?msn\.com\/[a-z-]+\/news\/other|t\.co|bit\.ly)\b/i;
const ATTACK = /\b(cyber ?attack|hack(ed|ers?)?|ransomware|breach(ed)?|intrusion|malware)\b/i;
const OFFICIAL = /\b(confirm(ed|s)?|said|stated|according to|official|attribut(ed|es))\b/i;

/** Mechanical flags for one event. evs: the other recent events, for duplicate suspicion. Returns [{code, text}]. */
export function flagsFor(e, evs = [], today = new Date().toISOString().slice(0, 10)) {
  const f = [], add = (code, text) => f.push({ code, text });
  const src = Array.isArray(e.sources) ? e.sources : [], hosts = new Set(src.map((s) => { try { return new URL(s.url).hostname.replace(/^www\./, ""); } catch { return ""; } }).filter(Boolean));
  if (!src.length) add("no-source", "no source at all");
  if (src.some((s) => REDIRECT.test(s.url || ""))) add("redirect-source", "a source is a search-engine or aggregator redirect, not the publisher's own page");
  if (src.some((s) => { try { const u = new URL(s.url); return (u.pathname === "/" || u.pathname === "") && !u.search; } catch { return true; } })) add("front-page-source", "a source is a front page, not a specific article");
  if (hosts.size <= 1 && e.severity >= 3 && e.status !== "official") add("single-source-high", "high severity resting on one publisher");
  if (e.validation && e.validation.state === "corroborated" && hosts.size <= 1 && e.source_tier !== "primary") add("corroborated-one-host", 'marked "corroborated" but every source is the same site');
  if (e.status === "claimed" && e.severity !== 1) add("claim-severity", "an unconfirmed claim must be severity 1");
  if (e.status === "claimed" && e.validation && e.validation.state === "corroborated") add("claim-corroborated", "a claim cannot be corroborated by more attacker posts");
  if (e.category === "outage" && ATTACK.test(`${e.title} ${e.summary || ""}`) && !/cyber cause:|not (a|an) (cyber ?)?attack|no evidence|ruled out|unknown cause/i.test(e.summary || "")) add("outage-as-attack", "an outage described with attack words: confirm an official source says so, or reword");
  if (e.category === "incident" && e.status === "confirmed" && !OFFICIAL.test(e.summary || "") && e.source_tier === "aggregator") add("confirmed-on-aggregator", '"confirmed" but the only sources are aggregators');
  if (e.severity >= 3 && e.category === "vuln" && !(e.cve_meta || []).some((c) => c && c.kev) && !/exploit|patch immediately|actively|critical|zero-day|public (poc|proof)/i.test(`${e.title} ${e.summary || ""} ${e.action || ""}`)) add("severity-3-reason", "severity 3 without exploitation, public exploit code or an official urgent notice in the text");
  if (e.actor && !e.attribution && !/claim|unattributed|unknown/i.test(e.actor) && e.status !== "claimed" && !/attribut|according to|said|linked/i.test(e.summary || "")) add("actor-unsourced", "an actor is named but the summary does not say who attributed it");
  if (e.records_affected && !String(e.summary || "").replace(/[,.\s]/g, "").includes(String(e.records_affected).slice(0, 2))) add("number-check", `records_affected ${e.records_affected} does not appear in the summary: confirm it against the source`);
  const fs = String(e.first_seen || "").slice(0, 10);
  if (/^\d{4}-\d{2}-\d{2}$/.test(fs) && e.date && (Date.parse(fs) - Date.parse(e.date)) / 864e5 > 7 && !e.date_note) add("old-date", "the event date is more than 7 days before it was added and there is no date_note");
  if (e.date > today) add("future-date", "the date is in the future");
  if (e.occurred_at && e.date && Math.abs(Date.parse(e.occurred_at) - Date.parse(e.date + "T12:00:00Z")) > 36 * 36e5) add("time-date-mismatch", "occurred_at is more than a day from date");
  for (const k of ["plain", "exec", "action", "summary"]) if (!String(e[k] || "").trim()) add("missing-" + k, `"${k}" is empty`);
  if (String(e.summary || "").trim().split(/\s+/).length > 75) add("long-summary", "summary over 75 words");
  if ((e.lat == null || e.lng == null) && e.pin_type !== "none" && e.country) add("no-pin", "has a country but no map position");
  if ((e.cves || []).length && !(e.cve_meta || []).length) add("no-cve-meta", "CVEs listed without cve_meta (the feeds job fills it; check the CVE ids are real)");
  if ((e.cves || []).some((c) => !/^CVE-\d{4}-\d{4,}$/.test(c))) add("bad-cve", "a CVE id is malformed");
  const q = tokens(`${e.title} ${e.org || ""}`);
  for (const o of evs) {
    if (o.id === e.id || o.duplicate_of || e.duplicate_of) continue;
    const t = o._tok || (o._tok = tokens(`${o.title} ${o.org || ""}`)); let inter = 0; q.forEach((w) => t.has(w) && inter++);
    const sameCve = (e.cves || []).length && (e.cves || []).every((c) => (o.cves || []).includes(c)) && e.category === o.category && e.org === o.org;
    if ((q.size >= 4 && inter / Math.min(q.size, t.size || 1) >= 0.8) || sameCve) { add("possible-duplicate", `looks like ${o.id}`); break; }
  }
  // the event-quality rules the build applies (scripts/lib/validate.mjs), and the checks across events (shared source
  // pages): shown to the reviewer with the flags above; a code already raised here is not repeated
  const have = new Set(f.map((x) => x.code));
  const quality = checkEventQuality(e).concat(e.id ? (sharedSourceProblems(evs.filter((o) => o && o.id !== e.id).concat([e]), [e.id]).get(e.id) || []) : []);
  for (const x of quality) if (!have.has(x.code)) { have.add(x.code); add(x.code, x.text); }
  return f;
}
/** Flags a reviewer must settle (fix the record) before a "pass": a pass is refused while any remains. */
export const BLOCKS_PASS = ["redirect-source", "no-source", "claim-severity", "claim-corroborated", "future-date", "bad-cve", "confirmed-on-secondary", "corroborated-one-host", "listing-source", "date-after-seen"];
// for events first seen from ACCURACY_STRICT_FROM the accuracy checks block a pass too (for older events they are warnings,
// and an older event re-reviewed after an update is not held to fields it could not have had)
export const BLOCKS_PASS_STRICT = ["figure-no-evidence", "figure-qualifier", "evidence-unsourced", "evidence-shape", "occurred-no-evidence", "action-unsourced", "claim-title", "date-is-publication", "source-published-missing", "primary-no-primary", "corroborated-one-site"];
export const passBlockers = (codes, strict = false) => codes.filter((c) => BLOCKS_PASS.includes(c) || (strict && BLOCKS_PASS_STRICT.includes(c)));

/** What the second review keeps correcting, as types a script can count (classified from the reviewer's note; one note can
 *  carry several). Studied 2026-11-21 on the 176 corrected events of 13-21 November. Each type names the mechanical check
 *  that now catches what a rule can catch (scripts/lib/validate.mjs, codes in `checks`). Order matters only for display. */
export const ERROR_TYPES = [
  { key: "overstated", label: "stronger than the source (hedge lost, may have -> did)", checks: ["claim-title"],
    re: /overstat|stronger|soften|\bmay have\b|\bpossib|potential(ly)?\b|reportedly|\bapparent\b|\blikely\b|outright|as fact|in cyberview voice|implied|conceded|narrowed|generalis|scoped|flatly|not 'breached'|now 'reported|says only|only clipboard|not a compromise|leak not confirmed|not confirmed|attempts? targeting|it is \w+, not/i },
  { key: "unsourced", label: "a fact or claim no page read states", checks: ["figure-no-evidence", "figure-not-in-summary"],
    re: /not in (the |either |any )?(source|sources|page|pages|article|post|summary|microsoft)|in neither|no source|unsourced|unsupported|not stated|not on the page|not on file|which no source|not found in|does not (say|mention|state|credit)|did not say|neither says|not mention|only in\b|only \w+ says|inference|inferred|editor wording|not visible|matched nothing|not confirmed by sources|is in neither|nor\b/i },
  { key: "action", label: "action gives advice the source does not give", checks: ["action-unsourced"],
    re: /\baction('s)?\b|\badvice\b/i },
  { key: "figure", label: "a figure, unit or qualifier changed", checks: ["figure-no-evidence", "figure-qualifier", "figure-plus"],
    re: /\bfigures?\b|\bcounts?\b|qualifier|\d\+|'(about|over|at least|up to|nearly|more than)'|\b(about|over|at least|up to|nearly|more than|under) [\d,.]+|[\d,.]{3,} (not|no longer|was|is|to|fixed|now)\b|\bper (breach|day)\b|\bunit\b|\bshares? within\b|\bdurations?\b|\d+ (hours?|minutes?)\b/i },
  { key: "date", label: "date is the publication or roundup day, or date_note missing", checks: ["date-is-publication", "source-published-missing", "old-date-no-note"],
    re: /date_note|\bdate (was|moved|set|changed|now|is|fixed|\d)|dates? moved|moved from \d|roundup date|publication\)|older than the (map|add)|late entry|\bpublish date\b/i },
  { key: "occurred_at", label: "occurred_at invented or the article's time", checks: ["occurred-placeholder", "occurred-no-evidence"],
    re: /occurred_at|placeholder|\btimestamps?\b/i },
  { key: "validation", label: "validation, status, severity or tier wrong", checks: ["corroborated-one-host", "corroborated-note", "primary-no-primary", "claim-title"],
    re: /validation|corroborated|single_source|unconfirmed_claim|\bstatus\b.*\b(to|now|overstated)\b|status (confirmed|developing|official) to|\bseverity \d\b.*(overstat|now)|source[_ ]tier|\btier (set|raised)|confidence|downgraded/i },
  { key: "source", label: "a source unread, unrelated, a tracker or listing; primary missing", checks: ["listing-source", "confirmed-on-secondary", "primary-no-primary"],
    re: /removed .{0,40}\bsources?\b|\bsources? (removed|added|dropped|now)|dropped .{0,40}\bsources?\b|added .{0,30}(\bsource\b|press release|as a source)|\bunread\b|not read|non-article|tracker|search-label|renders blank|set specific|district source first/i },
  { key: "attribution", label: "who said it missing or wrong", checks: ["actor-unsourced"],
    re: /attribut|misattribut|\bcredit(ed|s)\b|as reported|quoted|is \w+'s own|per \w+ via|as relayed/i },
  { key: "duplicate", label: "duplicate of an event on file", checks: ["possible-duplicate"],
    re: /duplicate_of|same event|same incident|same flaws|same gtig|overlaps/i },
  { key: "tags", label: "tag the source does not support", checks: ["tag-unsupported"], re: /\btags?\b/i },
  { key: "summary", label: "summary missing key facts or over 75 words", checks: ["long-summary"],
    re: /summary (lacked|did not say|now states|now says the|cut under)|cut under 75|over 75|trimmed|added .{0,40}to (the )?summary|added the [\d,.]+ (figure|total)|lacked/i },
  { key: "place", label: "place, pin, organisation or sector wrong", checks: ["no-pin"], re: /\bpin\b|\bplace\b|\bsector\b|based in|\borg\b|office locations/i },
  { key: "misstated", label: "a field says what the source says differently", checks: ["figure-no-evidence"],
    re: /\b(title|summary|plain|exec|impact|key findings?|record)s? (wrongly |had |also )?(said|stated|claimed|called|gave|carried|credited|implied|overstated)\b|\bwrongly\b|\bis the (share|researcher)|\bsays? (only|that)\b/i },
];
// the parts of a note that only report what was checked and found right ("dates, figures match X") say nothing about the error
const CHECKED_ONLY = /\b(match(es|ed)?|checked ok|all hold|they hold|correct|confirmed|checked against|compared (with|title)|read in full|now read|sources now load)\b/i;
const FIXING = /\b(fix(ed)?|now|removed?|reworded|rewrote|rewritten|changed?|moved|added|dropped|softened|corrected|wrong(ly)?|not|no longer|was|were|said|says|but|only|overstat\w*|unsupported|unsourced|narrowed|attributed|cut|trimmed|set)\b/i;
/** Pure: the correction types a reviewer's note describes (keys of ERROR_TYPES; [] when none matches). The clauses that
 *  only list what matched are left out first, so "figures match HIPAA Journal" does not count as a figure error. */
export function classifyCorrection(note) {
  const parts = String(note || "").split(/(?<=[.;])\s+|:\s+|,\s+(?=(?:but|while|and)\b)/).filter((p) => !(CHECKED_ONLY.test(p) && !FIXING.test(p.replace(CHECKED_ONLY, ""))));
  const text = parts.join(" ");
  const out = ERROR_TYPES.filter((t) => t.re.test(text)).map((t) => t.key);
  return out.length || !text.trim() ? out : ["other"];
}

/** Risk order for the queue: high severity, more flags, serious flags first. */
export function risk(e, flags) {
  const serious = flags.filter((x) => /source|claim|outage-as-attack|actor|number|duplicate|severity-3|future/.test(x.code)).length;
  return e.severity * 10 + serious * 6 + flags.length * 2 + (e.status === "claimed" ? 3 : 0);
}
/** Does this event still need a review of its current version? */
export function needsReview(e) {
  if (e.duplicate_of) return false;
  if (!e.review || !e.review.at) return true;
  return Date.parse(e.updated_at) - Date.parse(e.review.at) > 10 * 6e4;   // changed more than 10 minutes after its review
}

/** When this version of an event started waiting for its review: its last change if it was reviewed before, else its publication. */
export const waitingSince = (e) => String((e.review && e.review.at && e.updated_at) || e.first_seen || e.updated_at || "");
export const OVERDUE_MIN = 20;
/** Pure: queue order. Anything waiting longer than OVERDUE_MIN minutes goes first, oldest first, so a run of high-risk
 *  events can never hold a quiet one back for hours; the rest by risk, then oldest first. items: [{e, risk}]. */
export function order(items, now = Date.now()) {
  const late = (x) => now - Date.parse(waitingSince(x.e)) > OVERDUE_MIN * 6e4, older = (a, b) => waitingSince(a.e).localeCompare(waitingSince(b.e));
  return items.slice().sort((a, b) => (late(b) - late(a)) || (late(a) ? older(a, b) : (b.risk - a.risk) || older(a, b)));
}
/** Pure: split the head of the queue between up to n reviewers, at most `per` events each, at least 4 per reviewer before
 *  another starts. With two or more reviewers the first takes the events that started waiting most recently (published
 *  or updated in the last cycle), so a new event is reviewed in the next cycle instead of waiting behind a long tail of
 *  older ones (measured 2026-11-20: published -> second review p50 36 min, p90 1099 min); the others take the queue in
 *  its usual order, overdue first, oldest first. items: [{e}] in order(). Returns [[id...]...], no empty batch. */
export function planBatches(items, n, per) {
  const total = Math.min(items.length, Math.max(1, n) * Math.max(1, per));
  if (!total) return [];
  const k = Math.max(1, Math.min(n, Math.ceil(total / 4)));
  if (k === 1) return [items.slice(0, total).map((x) => x.e.id)];
  const share = Math.min(per, Math.ceil(total / k)), older = (a, b) => waitingSince(a.e).localeCompare(waitingSince(b.e));
  const newest = items.slice().sort((a, b) => older(b, a)).slice(0, share).sort(older), taken = new Set(newest.map((x) => x.e.id));
  const rest = items.filter((x) => !taken.has(x.e.id)).slice(0, total - newest.length), batches = Array.from({ length: k - 1 }, () => []);
  rest.forEach((x, i) => batches[i % (k - 1)].push(x.e.id));
  return [newest.map((x) => x.e.id), ...batches].filter((b) => b.length);
}
/** Pure: the review record. first_at keeps the time of the event's first second review through later re-reviews of updates
 *  (the speed figures measure lead -> first review; review.at is always the latest review). */
export function reviewRecord(prev, state, at, note, flags) {
  const r = { state, at, first_at: (prev && (prev.first_at || prev.at)) || at, note, flags };
  // the correction's types (ERROR_TYPES), so the efficiency report and the improver count them without re-reading notes
  if (state !== "passed") r.categories = classifyCorrection(note);
  return r;
}

/** Who wrote each event: event id -> {role, model}, from the run logs (data/runs/<day>/<HHMM>-<job>.json). A log stamped by
 *  scripts/run-job.mjs carries worker_role and worker_model (exact); an older one is read from its name (sweep-r<n>:
 *  researcher, sweep-gap: gap, update-u<n>: updater, followup, regional, backlog) and its self-reported model. The last
 *  log that added or updated an event wins. logs: [{at, job, model, worker_role, worker_model, added, updated}]. */
export function writersFrom(logs) {
  const out = new Map(), norm = (m) => { const x = String(m || "").toLowerCase(); return /opus/.test(x) ? "opus" : /sonnet/.test(x) ? "sonnet" : /haiku/.test(x) ? "haiku" : "unknown"; };
  const roleOf = (j) => /^sweep-r(\d|etry|$)/.test(j) ? "researcher" : /^(sweep-)?gap/.test(j) ? "gap" : /^update(-u|r)/.test(j) ? "updater" : /^followup/.test(j) ? "followup" : /^regional/.test(j) ? "regional-researcher" : /^backlog/.test(j) ? "researcher" : /^review/.test(j) ? "reviewer" : /^sweep/.test(j) ? "sweep" : j.replace(/-\d+$/, "") || "unknown";
  const idOf = (x) => typeof x === "string" ? x : x && typeof x === "object" ? String(x.id || x.event || x.event_id || "") : "";
  for (const l of logs.slice().sort((a, b) => String(a.at).localeCompare(String(b.at)))) {
    const role = l.worker_role || roleOf(String(l.job || "")), model = norm(l.worker_model || l.model);
    for (const k of ["added", "updated"]) for (const x of Array.isArray(l[k]) ? l[k] : []) { const id = idOf(x); if (/^[a-z0-9][a-z0-9-]{2,119}$/.test(id)) out.set(id, { role, model, at: l.at, how: k }); }
  }
  return out;
}
/** Pure: corrections by type, and by the role and model that wrote the event, for events whose first review is in the last
 *  `days` days. events: event records; writers: writersFrom(). -> {days, reviewed, corrected, flagged, corrected_pct,
 *  types: [{key, label, n, pct_of_corrected, checks}], by_writer: [{role, model, reviewed, corrected, corrected_pct, types}]} */
export function errorReport(events, writers = new Map(), now = Date.now(), days = 7) {
  const since = new Date(now - days * 864e5).toISOString(), types = {}, by = {};
  let reviewed = 0, corrected = 0, flagged = 0;
  for (const e of events) {
    const r = e && !e.duplicate_of && e.review; if (!r || !r.state) continue;
    const at = String(r.first_at || r.at || ""); if (at < since) continue;
    const w = writers.get(e.id) || { role: "unknown", model: "unknown" }, k = `${w.role}|${w.model}`;
    const b = (by[k] ||= { role: w.role, model: w.model, reviewed: 0, corrected: 0, flagged: 0, types: {} });
    reviewed++; b.reviewed++;
    if (r.state === "flagged") { flagged++; b.flagged++; }
    if (r.state !== "corrected") continue;
    corrected++; b.corrected++;
    for (const t of Array.isArray(r.categories) ? r.categories : classifyCorrection(r.note)) { types[t] = (types[t] || 0) + 1; b.types[t] = (b.types[t] || 0) + 1; }
  }
  const pct = (a, n) => (n ? Math.round((a / n) * 1000) / 10 : null), label = Object.fromEntries(ERROR_TYPES.map((t) => [t.key, t]));
  return { days, reviewed, corrected, flagged, corrected_pct: pct(corrected, reviewed),
    types: Object.entries(types).sort((a, b) => b[1] - a[1]).map(([key, n]) => ({ key, label: (label[key] || { label: "other" }).label, n, pct_of_corrected: pct(n, corrected), checks: (label[key] || { checks: [] }).checks })),
    by_writer: Object.values(by).sort((a, b) => b.reviewed - a.reviewed).map((b) => ({ ...b, corrected_pct: pct(b.corrected, b.reviewed), types: Object.fromEntries(Object.entries(b.types).sort((x, y) => y[1] - x[1])) })) };
}
/** The run logs of the last `days` days (and a day before), for writersFrom(). */
export function loadRunLogs(days = 8) {
  const dir = join(DATA, "runs"), out = []; if (!existsSync(dir)) return out;
  for (const d of readdirSync(dir).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d) && d >= dayAgo(days + 1)).sort())
    for (const f of readdirSync(join(dir, d))) {
      const m = f.match(/^(\d{2})(\d{2})-(.+)\.json$/); if (!m) continue;
      const r = readJson(join(dir, d, f), null); if (!r || typeof r !== "object") continue;
      out.push({ at: /^\d{4}-\d{2}-\d{2}T/.test(String(r.finished_at || "")) ? r.finished_at : `${d}T${m[1]}:${m[2]}:00Z`, job: m[3], model: r.model, worker_role: r.worker_role, worker_model: r.worker_model, added: r.added, updated: r.updated });
    }
  return out;
}
/** Pure: is this event in the queue's window? It still needs a review and its current version has waited under 3 days. The window is
 *  on waitingSince (the clock needsReview and order use), not first_seen: an old event changed an hour ago needs a re-review. */
export function inReviewWindow(e, now = Date.now()) {
  return waitingSince(e) >= new Date(now - 3 * 864e5).toISOString().slice(0, 10) && needsReview(e);
}
function queue() {
  const all = listEventFiles().map((f) => f.e).filter((e) => e && !e.duplicate_of), recent = all.filter((e) => e.date >= dayAgo(30));
  return order(all.filter((e) => inReviewWindow(e))
    .map((e) => { const flags = flagsFor(e, recent); return { e, flags, risk: risk(e, flags) }; }));
}

function main() {
  const [cmd, id, ...rest] = process.argv.slice(2);
  if (cmd === "plan") {   // split the head of the queue between reviewers (data/review-plan.json, working file); the dispatcher uses it
    const argv = [id, ...rest], arg = (k) => { const j = argv.indexOf("--" + k); return j >= 0 ? argv[j + 1] : undefined; };
    const file = /^review-plan(-[A-Za-z0-9-]+)?\.json$/.test(arg("file") || "") ? arg("file") : "review-plan.json";
    const c = (readJson(join(ROOT, "config", "pipeline.json"), {}).review) || {}, n = Math.max(1, Math.min(8, Number(arg("max")) || Number(c.reviewers) || 2)), per = Math.max(3, Math.min(15, Number(c.events_per_reviewer) || 10));
    const all = queue(), held = leased("event", all.map((x) => x.e.id), process.env.CYBERVIEW_RUN || ""), batches = planBatches(all.filter((x) => !held.has(x.e.id)), n, per), planned = batches.flat().length;
    writeJson(join(DATA, file), { planned_at: nowIso(), batches });
    console.log(`REVIEW PLAN: ${planned} event(s) for ${batches.length} reviewer(s)${batches.length > 1 ? " (reviewer 1 on the newest)" : ""}; ${all.length} waiting in all.`);
    return;
  }
  if (cmd === "queue") {
    const q = queue(), li = process.argv.indexOf("--limit"), lim = li > 0 ? Number(process.argv[li + 1]) : 30;
    if (process.argv.includes("--json")) { console.log(JSON.stringify(q.slice(0, lim).map((x) => ({ id: x.e.id, severity: x.e.severity, status: x.e.status, category: x.e.category, title: x.e.title, flags: x.flags, sources: (x.e.sources || []).map((s) => s.url) })))); return; }
    console.log(`${q.length} event(s) waiting for a second review (added or changed in the last 72 hours). Waiting over ${OVERDUE_MIN} minutes first, then highest risk:`);
    q.slice(0, lim).forEach((x) => console.log(`[sev ${x.e.severity}${x.e.status === "claimed" ? " claim" : ""}] ${x.e.id}  ${String(x.e.title).slice(0, 90)}\n       ${x.flags.length ? "FLAGS: " + x.flags.map((f) => f.code).join(", ") : "no mechanical flags"}  |  ${(x.e.sources || []).length} source(s)`));
    return;
  }
  if (cmd === "errors") {   // what the second review corrects, by type and by the role and model that wrote the event
    const argv = [id, ...rest], di = argv.indexOf("--days"), days = di >= 0 ? Math.max(1, Math.min(30, Number(argv[di + 1]) || 7)) : 7;
    const r = errorReport(listEventFiles().map((x) => x.e).filter(Boolean), writersFrom(loadRunLogs(days)), Date.now(), days);
    if (argv.includes("--json")) { console.log(JSON.stringify(r)); return; }
    console.log(`SECOND REVIEW, last ${days} days: ${r.corrected} of ${r.reviewed} corrected (${r.corrected_pct ?? "-"}%), ${r.flagged} flagged. Correction types (a correction can have several):`);
    r.types.forEach((t) => console.log(`  ${t.key.padEnd(12)} ${String(t.n).padStart(4)}  ${String(t.pct_of_corrected).padStart(5)}%  ${t.label}${t.checks.length ? "  [checks: " + t.checks.join(", ") + "]" : ""}`));
    console.log("By who wrote the event (role, model: corrected of reviewed; top types):");
    r.by_writer.forEach((b) => console.log(`  ${b.role.padEnd(20)} ${b.model.padEnd(8)} ${String(b.corrected).padStart(3)} of ${String(b.reviewed).padStart(3)} (${b.corrected_pct ?? "-"}%)  ${Object.entries(b.types).slice(0, 4).map(([k, n]) => `${k} ${n}`).join(", ")}`));
    return;
  }
  const f = id && findEvent(id);
  if (!f || !f.e) { console.error(cmd ? `no event "${id}"` : "usage: review.mjs queue | flags <id> | errors [--days N] | pass|corrected|flagged <id> \"<note>\""); process.exit(1); }
  const recent = listEventFiles().map((x) => x.e).filter((e) => e && !e.duplicate_of && e.date >= dayAgo(30));
  if (cmd === "flags") { const fl = flagsFor(f.e, recent); console.log(fl.length ? fl.map((x) => `${x.code}: ${x.text}`).join("\n") : "no mechanical flags"); return; }
  if (!["pass", "corrected", "flagged"].includes(cmd)) { console.error(`unknown command "${cmd}"`); process.exit(1); }
  const note = rest.join(" ").replace(/\s+/g, " ").trim().slice(0, 300);
  if (note.length < 8) { console.error("say what was checked or what is wrong (at least a few words)"); process.exit(1); }
  const left = flagsFor(f.e, recent).map((x) => x.code);
  const strictA = String(f.e.first_seen || "") >= ACCURACY_STRICT_FROM;
  if (cmd === "pass" && passBlockers(left, strictA).length) { console.error(`cannot pass ${id}: fix these first (or use corrected/flagged): ${passBlockers(left, strictA).join(", ")}`); process.exit(1); }
  const at = nowIso(), e = { ...f.e, review: reviewRecord(f.e.review, cmd === "pass" ? "passed" : cmd, at, note, left.slice(0, 12)), qa_checked_at: at };
  if (cmd === "flagged") e.validation = { state: "disputed", checked_at: at, note: ("Second review: " + note).slice(0, 240) };
  saveEvent(e, f.path);
  console.log(`review: ${id} ${e.review.state}${left.length ? " (remaining flags: " + left.join(", ") + ")" : ""}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
