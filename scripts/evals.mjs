// Accuracy evals for the event writers. No AI model. Run: node scripts/evals.mjs <command>
// The second review already says what the writers get wrong: every review leaves {state, note} on the event, and the data
// branch keeps the record as the writer left it (the commit before the review) next to the record as the reviewer fixed
// it. This script turns that into a test set and into numbers, so a prompt or model change is measured, not guessed.
//   build [--out cache/evals] [--days N] [--no-history] [--git <dir>] [--ref <ref>]
//        one case per second review (corrected, flagged, and passed as controls) -> <out>/cases.jsonl, summary.json
//        Each case: event id, writer role and model, the inputs (the sources cited, the pages the writer's run log says it
//        read), the record as written, the fields as written against as corrected (diff), the correction types
//        (ERROR_TYPES in scripts/review.mjs) and the specific mistakes (MISTAKES here). Never any article text: the only
//        page text is the event's own "evidence" quotes (at most 240 characters each).
//        The default --out is cache/evals/ (git-ignored): main never holds data. The scheduled improver runs
//        `node scripts/evals.mjs build --out data/evals` and its finish.mjs commits data/evals/ on the data branch.
//   report [--cases <file>] [--days N] [--json] [--md]
//        correction rate by type, by writer role and model, by category; the 10 most frequent specific mistakes, each
//        with 3 example events and the before/after of the field, and which mechanical check (scripts/lib/validate.mjs)
//        raised a flag on the record as written (caught) or stayed silent (missed). --md prints the short "most common
//        corrections" lines for docs/jobs.md.
//   propose-checks [--cases <file>] [--json]
//        the mistakes a script could decide: each candidate rule run over every record as written (how many corrected
//        records it would have flagged, how many passed ones: its false alarms) and over the events on file today.
//   score --events <file.json|file.jsonl|dir|id,id,...> [--cases <file>] [--json] [--baseline <score.json>]
//        every mechanical check plus the proposed ones over a set of event records -> clean share, findings per event and
//        by code; with --cases, also how often date, severity, status, validation and source_tier agree with the reviewed
//        record of the same id. Score a candidate prompt or model on the regression inputs, compare with the baseline
//        (`score --events <out>/cases.jsonl`, which scores every record as written), no AI judge.
// Without the data branch's git history (--no-history, or a snapshot without .git) a case has the review note and types
// but no diff, and the mistakes are read from the note alone.
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, writeJson, listEventFiles, nowIso } from "./lib/store.mjs";
import { classifyCorrection, writersFrom, ERROR_TYPES } from "./review.mjs";
import { checkEventQuality, sharedSourceProblems, countables, proposedProblems, PROPOSED_CODES } from "./lib/validate.mjs";

// ---------- the record as written against the record as corrected ----------
const TEXT = ["title", "summary", "plain", "exec", "action", "impact"];
export const DIFF_FIELDS = ["title", "date", "date_note", "category", "severity", "status", "org", "country", "place", "pin_type", "actor", "summary", "plain", "exec", "action", "impact",
  "records_affected", "tags", "cves", "products", "sources", "source_tier", "validation", "validation_note", "occurred_at", "time_basis", "attribution", "evidence", "duplicate_of", "sectors", "surface"];
const clip = (v, n = 400) => (typeof v === "string" && v.length > n ? v.slice(0, n) + "…" : v);
/** One field of an event in the form the diff compares: sources as "url (published)", validation as its state. */
export function fieldOf(e, k) {
  if (!e) return null;
  if (k === "sources") return (Array.isArray(e.sources) ? e.sources : []).filter((s) => s && s.url).map((s) => `${s.url}${s.published ? ` (${s.published})` : ""}`);
  if (k === "validation") return (e.validation && e.validation.state) || null;
  if (k === "validation_note") return (e.validation && e.validation.note) || null;
  if (k === "evidence") return (Array.isArray(e.evidence) ? e.evidence : []).map((x) => clip(String((x && x.quote) || ""), 240));
  if (k === "attribution") return e.attribution ? `${e.attribution.actor || ""} (by ${e.attribution.by || "?"})` : null;
  if (k === "sectors") return e.sectors ? `${(e.sectors.values || []).join(",")} [${e.sectors.basis || ""}]` : null;
  if (k === "surface") return e.surface ? `${e.surface.value || ""} [${e.surface.basis || ""}]` : null;
  const v = e[k];
  return v === undefined || v === "" ? null : v;
}
/** Pure: the fields a reviewer changed: [{field, before, after}] (long text clipped). */
export function fieldDiff(before, after) {
  const out = [];
  for (const k of DIFF_FIELDS) {
    const b = fieldOf(before, k), a = fieldOf(after, k);
    if (JSON.stringify(b) !== JSON.stringify(a)) out.push({ field: k, before: Array.isArray(b) ? b.map((x) => clip(x)) : clip(b, 700), after: Array.isArray(a) ? a.map((x) => clip(x)) : clip(a, 700) });
  }
  return out;
}

// ---------- history: every committed version of every event file ----------
const git = (cwd, args, input) => spawnSync("git", args, { cwd, input, maxBuffer: 1 << 30, timeout: 300000 });
/** Every committed version of every event file reachable from `ref`: {id: [{t, e}]} oldest first. Works in the data
 *  checkout (events/...) and in the old layout (data/events/...); a moved file (the month changed) keeps its id. */
export function historyFromGit(cwd, ref = "HEAD") {
  const log = git(cwd, ["log", "--format=@%H %cI", "--name-only", ref, "--", "events", "data/events"]);
  if (log.status !== 0) return {};
  const want = []; let cur = null;
  for (const l of String(log.stdout).split("\n")) {
    if (l[0] === "@") { const [h, t] = l.slice(1).split(" "); cur = { h, t }; }
    else if (cur && /(^|\/)events\/[^/]+\/[a-z0-9][a-z0-9-]{2,119}\.json$/.test(l)) want.push({ h: cur.h, t: cur.t, path: l });
  }
  if (!want.length) return {};
  const r = git(cwd, ["cat-file", "--batch"], want.map((w) => `${w.h}:${w.path}`).join("\n") + "\n");
  const buf = r.stdout || Buffer.alloc(0), out = {}; let p = 0;
  for (const w of want) {
    const nl = buf.indexOf(10, p); if (nl < 0) break;
    const head = buf.subarray(p, nl).toString(); p = nl + 1;
    if (!/^[0-9a-f]+ blob \d+$/.test(head)) continue;                 // "<name> missing": the commit deleted or moved the file
    const size = Number(head.split(" ")[2]), body = buf.subarray(p, p + size).toString(); p += size + 1;
    const id = w.path.split("/").pop().replace(/\.json$/, "");
    let e = null; try { e = JSON.parse(body); } catch { /* a broken version is no version */ }
    if (e && typeof e === "object" && !Array.isArray(e)) (out[id] ||= []).push({ t: w.t, e: { ...e, id } });
  }
  for (const id of Object.keys(out)) out[id].sort((a, b) => Date.parse(a.t) - Date.parse(b.t));
  return out;
}

// ---------- who wrote it ----------
/** Every run log on file, for writerAt(): [{at, job, model, worker_role, worker_model, added, updated, pages_read}]. */
export function loadAllRunLogs(dir = join(DATA, "runs")) {
  const out = []; if (!existsSync(dir)) return out;
  for (const d of readdirSync(dir).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort()) for (const f of readdirSync(join(dir, d))) {
    const m = f.match(/^(\d{2})(\d{2})-(.+)\.json$/); if (!m) continue;
    const r = readJson(join(dir, d, f), null); if (!r || typeof r !== "object" || !(Array.isArray(r.added) && r.added.length) && !(Array.isArray(r.updated) && r.updated.length)) continue;
    out.push({ at: /^\d{4}-\d{2}-\d{2}T/.test(String(r.finished_at || "")) ? r.finished_at : `${d}T${m[1]}:${m[2]}:00Z`, job: m[3], model: r.model, worker_role: r.worker_role, worker_model: r.worker_model, added: r.added, updated: r.updated,
      pages_read: (Array.isArray(r.pages_read) ? r.pages_read : []).filter((p) => p && typeof p.url === "string").map((p) => ({ url: p.url.slice(0, 300), used_in: String(p.used_in || "") })) });
  }
  return out;
}
/** Pure: event id -> the writing runs that added or updated it, oldest first (reviewers left out). Roles and models are
 *  named exactly as `review.mjs errors` names them (writersFrom). */
export function writerIndex(logs) {
  const idx = new Map();
  for (const l of logs.slice().sort((a, b) => String(a.at).localeCompare(String(b.at)))) for (const [id, w] of writersFrom([l])) {
    if (/review/.test(w.role)) continue;
    if (!idx.has(id)) idx.set(id, []);
    idx.get(id).push({ ...w, pages: (l.pages_read || []).filter((p) => !p.used_in || p.used_in.includes(id)).map((p) => p.url).slice(0, 12) });
  }
  return idx;
}
/** Pure: the last writing run on this event at or before `at` (the review's time); {role, model, pages}. */
export function writerAt(idx, id, at) {
  const runs = idx.get(id) || [], before = runs.filter((w) => String(w.at) <= String(at));
  const w = before[before.length - 1] || runs[0];
  return w ? { role: w.role, model: w.model, how: w.how, pages: w.pages } : { role: "unknown", model: "unknown", pages: [] };
}

// ---------- the specific mistakes ----------
const HEDGE = /\b(may|might|could|reportedly|allegedly|possibl[ey]|potential(ly)?|appears?|apparently|suspected|believed|likely|unconfirmed|unverified|not (yet )?(been )?confirmed|no indication|claims?|claimed)\b/gi;
const SAYS = /\b(according to|said|says|told|stated|reported by|reports?|as quoted|quoted|per|relayed by|its (own )?(notice|statement|advisory)|the (notice|statement|advisory|company|agency|ministry|vendor) (says|said|states))\b/gi;
const n = (re, t) => (String(t || "").match(re) || []).length;
const words = (t) => String(t || "").trim().split(/\s+/).filter(Boolean).length;
const figs = (t) => countables(t).map((f) => `${f.value}${f.pct ? "%" : ""}|${f.q}`).sort();
const vals = (t) => new Set(countables(t).map((f) => `${f.value}${f.pct ? "%" : ""}`));
const ACTION_OWN = /^\s*(general advice|no action (is )?(needed|stated|required|given))\b/i;
/**
 * The specific mistakes, each decided from the diff (what the reviewer changed), or from the note when a case has no diff.
 * `lesson` is the line a writer needs; `checks` are the checks of checkEventQuality (scripts/lib/validate.mjs) meant to
 * catch it ([] = none exists; the checks across events, such as possible-duplicate, are not run on a single record): the
 * report counts how often one of them really fired on the record as written. `on` picks the diff entry to show as the
 * example. d: {field: {before, after}}, c: the case.
 */
export const MISTAKES = [
  { key: "certainty-overstated", label: "stated as fact what the source hedges (may have, reportedly, claims)", checks: ["claim-title"], fields: ["title", "summary", "plain", "exec", "impact"], on: (x) => n(HEDGE, x.after) > n(HEDGE, x.before),
    lesson: 'Keep the source\'s certainty: "may have been accessed", "reportedly", "claims" stay in the title, summary, plain and exec; never turn a possibility into a fact.',
    test: (d, c) => ["title", "summary", "plain", "exec", "impact"].some((k) => d[k] && n(HEDGE, d[k].after) > n(HEDGE, d[k].before)) || (!c.diff.length && c.types.includes("overstated")) },
  { key: "who-said-it-missing", label: "a finding in CyberView's voice; the reviewer added who said it", checks: ["actor-unsourced", "summary-unattributed"], fields: ["summary", "plain", "exec", "title"], on: (x) => n(SAYS, x.after) > n(SAYS, x.before),
    lesson: 'Say who said it in the same sentence ("according to Huntress", "the city\'s notice says"), most of all for a cause, a figure, an attribution or a denial only one party states.',
    test: (d, c) => ["title", "summary", "plain", "exec"].some((k) => d[k] && n(SAYS, d[k].after) > n(SAYS, d[k].before)) || (!c.diff.length && c.types.includes("attribution")) },
  { key: "action-not-from-source", label: "action gave advice no page gives, or did not say whose advice it is", checks: ["action-unsourced"], fields: ["action"],
    lesson: 'action is the source\'s own advice, named ("Soft99 advises ..."); if no page gives advice write "No action needed; for awareness." or start "General advice:". Do not invent "check your statements" or "reset passwords".',
    test: (d, c) => !!d.action || (!c.diff.length && c.types.includes("action")) },
  { key: "figure-changed", label: "a figure, its qualifier or its unit was wrong or unsupported", checks: ["figure-no-evidence", "figure-qualifier", "figure-plus", "figure-not-in-summary"], fields: ["summary", "title", "plain", "exec", "impact", "records_affected"], on: (x) => x.field === "records_affected" || JSON.stringify(figs(x.before)) !== JSON.stringify(figs(x.after)),
    lesson: 'Copy every figure with the page\'s own qualifier and unit ("up to 136,968", "about 400", not "400+"), the same in every field, and quote the sentence in "evidence".',
    test: (d, c) => !!d.records_affected || TEXT.some((k) => d[k] && JSON.stringify(figs(d[k].before)) !== JSON.stringify(figs(d[k].after))) || (!c.diff.length && c.types.includes("figure")) },
  { key: "detail-not-in-source", label: "a detail no page states was removed or reworded (summary, plain, exec)", checks: [], fields: ["summary", "plain", "exec", "title", "impact"],
    lesson: "If you cannot point to the sentence on the page, delete it: no cause, scope, consequence or description (\"major retailer\", \"every company\") of your own; plain and exec only restate the summary.",
    test: (d, c) => (c.types.includes("unsourced") || c.types.includes("misstated")) && (!c.diff.length || ["title", "summary", "plain", "exec", "impact"].some((k) => d[k])) },
  { key: "occurred-at-invented", label: "occurred_at was not a time the page states (removed or re-based)", checks: ["occurred-placeholder", "occurred-no-evidence", "occurred-no-basis", "occurred-round-hour"], fields: ["occurred_at", "time_basis"],
    lesson: 'Leave "occurred_at" out unless a page states the time of day; an article\'s publication time is not the event\'s time.',
    test: (d, c) => !!d.occurred_at || !!d.time_basis || (!c.diff.length && c.types.includes("occurred_at")) },
  { key: "date-wrong", label: "date was the article's, roundup's or reading day, not the day it happened", checks: ["date-is-publication", "old-date-no-note", "date-after-seen"], fields: ["date"],
    lesson: '"date" is the day it happened or was disclosed, taken from the page; not the day the article or roundup was published and not the day you read it.',
    test: (d, c) => !!d.date || (!c.diff.length && c.types.includes("date") && /moved|date (was|set|changed|now)/i.test(c.note)) },
  { key: "date-note-missing", label: "date_note missing or wrong (what the date is, why it is added now)", checks: ["date-is-publication", "old-date-no-note", "source-published-missing"], fields: ["date_note"],
    lesson: 'When the page gives only its publication day, use it and say so in "date_note"; a date equal to a source\'s "published" day always needs the note.',
    test: (d) => !!d.date_note && !d.date },
  { key: "source-list-wrong", label: "a source was unread, unrelated, a tracker or a listing; or the original was missing", checks: ["listing-source", "confirmed-on-secondary", "social-source", "primary-no-primary", "tier-secondary"], fields: ["sources"],
    lesson: "List only pages you read that are about this event: no tracker, roundup, tag page or page that did not load; the organisation's or vendor's own notice goes first.",
    test: (d, c) => (!!d.sources && JSON.stringify(d.sources.before.map((s) => s.split(" ")[0]).sort()) !== JSON.stringify(d.sources.after.map((s) => s.split(" ")[0]).sort())) || (!c.diff.length && c.types.includes("source")) },
  { key: "source-published-missing", label: "a source's own publication day was missing or wrong", checks: ["source-published-missing", "source-published-shape", "source-published-partial"], fields: ["sources"],
    lesson: 'Give every source its page\'s own publication day as "published" (YYYY-MM-DD, read from the page).',
    test: (d) => !!d.sources && JSON.stringify(d.sources.before.map((s) => s.split(" ")[0]).sort()) === JSON.stringify(d.sources.after.map((s) => s.split(" ")[0]).sort()) },
  { key: "validation-overstated", label: "validation, status, severity or source_tier claimed more than the sources carry", checks: ["corroborated-one-host", "corroborated-one-site", "corroborated-note", "corroborated-on-secondary", "confirmed-on-secondary", "confirmed-on-aggregator", "primary-no-primary", "tier-secondary", "claim-severity"], fields: ["validation", "status", "severity", "source_tier"],
    lesson: '"corroborated" needs two independent publishers that each state the core fact; "confirmed" needs the organisation\'s or an authority\'s own statement; one publisher is "single_source"; a claim is "claimed", severity 1.',
    test: (d, c) => !!(d.validation || d.status || d.severity || d.source_tier) || (!c.diff.length && c.types.includes("validation")) },
  { key: "summary-too-long", label: "summary over 75 words", checks: ["long-summary"], fields: ["summary"],
    lesson: "Count the summary: 2 to 4 sentences, at most 75 words.",
    test: (d) => !!d.summary && words(d.summary.before) > 75 && words(d.summary.after) <= words(d.summary.before) - 3 },
  { key: "evidence-missing", label: "an evidence quote was missing or not word for word", checks: ["figure-no-evidence", "occurred-no-evidence", "evidence-unsourced", "evidence-shape"], fields: ["evidence"],
    lesson: 'Every figure of 10 or more and every stated time has an "evidence" quote copied word for word from a page in sources.',
    test: (d) => !!d.evidence },
  { key: "tag-unsupported", label: "a tag the sources do not support", checks: ["tag-unsupported"], fields: ["tags"],
    lesson: 'Tag only what a page says: "zero-day" only if exploited before a fix, "supply-chain" only if it came through a supplier, package or update.',
    test: (d, c) => !!d.tags || (!c.diff.length && c.types.includes("tags")) },
  { key: "duplicate", label: "the same event was already on file", checks: [], fields: ["duplicate_of"],
    lesson: "Search by organisation and CVE (q.mjs dupes, q.mjs find) before adding; update the event on file instead.",
    test: (d, c) => !!d.duplicate_of || (!c.diff.length && c.types.includes("duplicate")) },
  { key: "place-or-class-wrong", label: "place, pin, organisation, sector or surface wrong", checks: ["classify-basis", "sectors-value", "surface-value"], fields: ["place", "org", "country", "pin_type", "sectors", "surface"],
    lesson: 'Place, sector and surface as a page states them; "basis" is "stated" only when a page says it.',
    test: (d) => !!(d.place || d.org || d.country || d.pin_type || d.sectors || d.surface) },
];
/** Pure: the specific mistakes of one case (keys of MISTAKES; [] for a pass). */
export function mistakesOf(c) {
  if (c.state !== "corrected") return [];
  const d = Object.fromEntries((c.diff || []).map((x) => [x.field, x]));
  return MISTAKES.filter((m) => { try { return m.test(d, c); } catch { return false; } }).map((m) => m.key);
}

// ---------- cases ----------
const STRIP = ["review", "qa_checked_at", "cve_meta", "hunt", "links", "lat", "lng"];
const slim = (e) => { const o = {}; for (const [k, v] of Object.entries(e || {})) if (!STRIP.includes(k)) o[k] = v; return o; };
const codesOf = (e, now) => [...new Set(checkEventQuality(e, { now }).map((x) => x.code))];
/**
 * Pure: one case per second review. events: the records on file; history: {id: [{t, e}]} from historyFromGit (may be {});
 * widx: writerIndex(). A review is a version whose review.at differs from the version before it; "written" is the version
 * before it (the writer's or updater's record), "diff" what the reviewer changed. An event with no history gives one case
 * from its current review, without a diff. -> [{id, event, state, at, first, note, types, mistakes, category, severity,
 * status, writer: {role, model}, inputs: {sources, pages_read}, written, diff, caught, reference}]
 */
export function buildCases(events, history = {}, widx = new Map(), { days = 0, now = Date.now() } = {}) {
  const since = days ? new Date(now - days * 864e5).toISOString() : "", cases = [];
  for (const cur of events) {
    if (!cur || !cur.id) continue;
    const vs = (history[cur.id] || []).map((v) => v.e), steps = [];
    for (let i = 0; i < vs.length; i++) {
      const r = vs[i].review, pr = i ? vs[i - 1].review : null;
      if (!r || !r.state || !r.at || (pr && pr.at === r.at)) continue;
      steps.push({ r, before: i ? vs[i - 1] : null, after: vs[i], first: !vs.slice(0, i).some((v) => v.review && v.review.state) });
    }
    const r0 = cur.review;
    if (r0 && r0.state && r0.at && !steps.some((s) => s.r.at === r0.at)) steps.push({ r: r0, before: null, after: cur, first: !steps.length });
    for (const s of steps) {
      if (since && String(s.r.at) < since) continue;
      const w = writerAt(widx, cur.id, s.r.at), written = s.before || null, base = written || s.after;
      const c = { id: `${cur.id}@${s.r.at}`, event: cur.id, state: s.r.state, at: s.r.at, first: s.first, note: String(s.r.note || "").slice(0, 300),
        types: s.r.state === "corrected" ? (Array.isArray(s.r.categories) && s.r.categories.length ? s.r.categories : classifyCorrection(s.r.note)) : [],
        category: base.category || "", severity: base.severity ?? null, status: base.status || "", writer: { role: w.role, model: w.model },
        inputs: { sources: (Array.isArray(base.sources) ? base.sources : []).filter((x) => x && x.url).map((x) => ({ name: String(x.name || "").slice(0, 80), url: x.url, ...(x.published ? { published: x.published } : {}) })), pages_read: w.pages || [] },
        has_before: !!written, written: slim(base), diff: written ? fieldDiff(written, s.after) : [],
        caught: written ? codesOf(written, Date.parse(s.r.at) || now) : [] };
      c.reference = Object.fromEntries(["date", "category", "severity", "status", "source_tier"].map((k) => [k, s.after[k] ?? null]).concat([["validation", fieldOf(s.after, "validation")], ["duplicate_of", s.after.duplicate_of || null]]));
      c.mistakes = mistakesOf(c);
      cases.push(c);
    }
  }
  return cases.sort((a, b) => String(a.at).localeCompare(String(b.at)) || a.event.localeCompare(b.event));
}

// ---------- report ----------
const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : null);
const top = (o, k = 4) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, k);
function tally(cases, keyOf) {
  const by = {};
  for (const c of cases) {
    const g = (by[keyOf(c)] ||= { key: keyOf(c), reviewed: 0, corrected: 0, flagged: 0, types: {}, mistakes: {} });
    g.reviewed++; if (c.state === "flagged") g.flagged++;
    if (c.state !== "corrected") continue;
    g.corrected++; for (const t of c.types) g.types[t] = (g.types[t] || 0) + 1; for (const m of c.mistakes) g.mistakes[m] = (g.mistakes[m] || 0) + 1;
  }
  return Object.values(by).map((g) => ({ ...g, corrected_pct: pct(g.corrected, g.reviewed) })).sort((a, b) => b.reviewed - a.reviewed);
}
/**
 * Pure: the accuracy report from cases. -> {reviews, corrected, corrected_pct, first: {...}, with_diff, types, by_writer,
 * by_category, cells (type x role x model x category), mistakes: [{key, label, lesson, n, pct_of_corrected, pct_of_reviews,
 * by_writer, caught, missed, caught_by, examples: [{event, note, field, before, after}]}]}
 */
export function report(cases, { top: k = 10 } = {}) {
  const corr = cases.filter((c) => c.state === "corrected"), first = cases.filter((c) => c.first), label = Object.fromEntries(ERROR_TYPES.map((t) => [t.key, t]));
  const types = {}; for (const c of corr) for (const t of c.types) types[t] = (types[t] || 0) + 1;
  const cells = {};
  for (const c of cases) {
    const base = `${c.writer.role}|${c.writer.model}|${c.category}`;
    (cells[base] ||= { role: c.writer.role, model: c.writer.model, category: c.category, reviewed: 0, corrected: 0, types: {} }).reviewed++;
    if (c.state === "corrected") { cells[base].corrected++; for (const t of c.types) cells[base].types[t] = (cells[base].types[t] || 0) + 1; }
  }
  const order = MISTAKES.map((m) => ({ m, hit: corr.filter((c) => c.mistakes.includes(m.key)) })).filter((x) => x.hit.length).sort((a, b) => b.hit.length - a.hit.length), shown = new Set();
  const mistakes = order.map(({ m }) => {
    const hit = corr.filter((c) => c.mistakes.includes(m.key)), withB = hit.filter((c) => c.has_before), caught = withB.filter((c) => c.caught.some((x) => m.checks.includes(x)));
    const old = withB.filter((c) => c.caught.some((x) => m.checks.includes(x) && !PROPOSED_CODES[x]));
    const by = {}; for (const c of hit) for (const x of c.caught) if (m.checks.includes(x)) by[x] = (by[x] || 0) + 1;
    const bw = {}; for (const c of hit) { const w = `${c.writer.role}/${c.writer.model}`; bw[w] = (bw[w] || 0) + 1; }
    // examples: the newest cases with a diff on one of the mistake's own fields, one per event; an event already shown
    // under a more frequent mistake is used again only when nothing else is left
    const seen = new Set(), examples = [];
    for (const fresh of [true, false]) for (const c of hit.slice().reverse()) {
      if (examples.length >= 3) break;
      const x = (c.diff || []).find((x) => m.fields.includes(x.field) && (!m.on || m.on(x))) || (c.diff || []).find((x) => m.fields.includes(x.field));
      if (!x || seen.has(c.event) || (fresh && shown.has(c.event))) continue;
      seen.add(c.event); examples.push({ event: c.event, at: c.at, note: c.note, field: x.field, before: x.before, after: x.after });
    }
    for (const c of hit.slice().reverse()) { if (examples.length >= 3) break; if (!seen.has(c.event)) { seen.add(c.event); examples.push({ event: c.event, at: c.at, note: c.note, field: null, before: null, after: null }); } }
    examples.forEach((x) => shown.add(x.event));
    return { key: m.key, label: m.label, lesson: m.lesson, checks: m.checks, n: hit.length, pct_of_corrected: pct(hit.length, corr.length), pct_of_reviews: pct(hit.length, cases.length), by_writer: Object.fromEntries(top(bw, 5)),
      with_before: withB.length, caught_before_new_checks: old.length, caught: caught.length, missed: withB.length - caught.length, caught_pct: pct(caught.length, withB.length), caught_by: Object.fromEntries(top(by, 6)), examples };
  });
  return { reviews: cases.length, corrected: corr.length, flagged: cases.filter((c) => c.state === "flagged").length, corrected_pct: pct(corr.length, cases.length),
    first: { reviews: first.length, corrected: first.filter((c) => c.state === "corrected").length, corrected_pct: pct(first.filter((c) => c.state === "corrected").length, first.length) },
    with_diff: corr.filter((c) => c.has_before).length, from: cases.length ? cases[0].at : null, to: cases.length ? cases[cases.length - 1].at : null,
    types: Object.entries(types).sort((a, b) => b[1] - a[1]).map(([key, v]) => ({ key, label: (label[key] || { label: "other" }).label, n: v, pct_of_corrected: pct(v, corr.length), pct_of_reviews: pct(v, cases.length), checks: (label[key] || { checks: [] }).checks })),
    by_writer: tally(cases, (c) => `${c.writer.role}|${c.writer.model}`).map((g) => ({ ...g, role: g.key.split("|")[0], model: g.key.split("|")[1] })),
    by_category: tally(cases, (c) => c.category || "unknown"),
    cells: Object.values(cells).filter((x) => x.reviewed >= 5).map((x) => ({ ...x, corrected_pct: pct(x.corrected, x.reviewed), types: Object.fromEntries(top(x.types, 5).map(([t, v]) => [t, { n: v, pct_of_reviews: pct(v, x.reviewed) }])) })).sort((a, b) => b.reviewed - a.reviewed),
    mistakes: mistakes.slice(0, k), mistakes_rest: mistakes.slice(k).map((m) => ({ key: m.key, n: m.n })) };
}
/** Pure: the short "most common corrections" lines for docs/jobs.md, from a report (at most `max` lines). */
export function lessons(rep, max = 10) {
  return rep.mistakes.slice(0, max).map((m, i) => `${String(i + 1).padStart(2)}. ${m.lesson} (${m.pct_of_corrected}% of corrections)`);
}
/** A compact form of the report for the improver (scripts/improve.mjs report -> data/improve/latest.json `evals`). */
export function reportForImprover(rep) {
  return { reviews: rep.reviews, corrected_pct: rep.corrected_pct, first_review_corrected_pct: rep.first.corrected_pct, with_diff: rep.with_diff,
    mistakes: rep.mistakes.map((m) => ({ key: m.key, label: m.label, n: m.n, pct_of_corrected: m.pct_of_corrected, caught_pct: m.caught_pct, missed: m.missed, by_writer: m.by_writer, examples: m.examples.map((x) => x.event) })),
    by_writer: rep.by_writer.slice(0, 12).map((g) => ({ role: g.role, model: g.model, reviewed: g.reviewed, corrected_pct: g.corrected_pct, mistakes: Object.fromEntries(top(g.mistakes, 4)) })) };
}

// ---------- proposed checks ----------
const sentences = (a) => String(a || "").split(/(?<=[.;])\s+(?=[A-Z])/).map((s) => s.trim()).filter((s) => s.length > 12);
const NAMED = /\b(advis\w*|recommend\w*|urg\w*|warn\w*|says?|said|according to|per\b|asks?|asked|tells?|told|instruct\w*|directs?|offers?|lists?|reports?|reported|states?|stated|guidance|advisor(y|ies)|bulletin|notice|letter|statement|workarounds?|mitigations?|release notes|fixed (in|version|release)|\w+['’]s (fix|patch|update|workaround|advice|post|page|script|hotfix|advisory|notice)|KB\d+|GHSA-|upgrade to|update to)\b/i;
const STRONG_HEDGE = /\b(may have|might have|could have|possibl[ey]|potentially|allegedly|reportedly|suspected|unconfirmed|unverified|not (yet )?(been )?confirmed)\b/i;
const SCOPE = /\b(major|largest|biggest|massive|widespread|nationwide|worldwide|every|entire|thousands|millions|hundreds|dozens|severe|sophisticated|state-sponsored|state-backed|unprecedented|worst)\b/gi;
/**
 * Rules that were tried on the same records and are NOT in validate.mjs, because the review corrects the records they
 * flag hardly more often than any other record: listed with their numbers so nobody proposes them again without a
 * better idea. These mistakes need a reader (the second review) or a change to the writer's instructions.
 */
export const REJECTED = {
  "action-part-unsourced": { mistake: "action-not-from-source", rule: "a sentence of the action names no source and is not after \"General advice:\"",
    test: (e) => { const a = String(e.action || ""); if (!a || /^\s*(general advice|no action)/i.test(a)) return false; let gen = false; return sentences(a).some((s) => { if (/\bgeneral advice\b/i.test(s)) { gen = true; return false; } return !gen && !NAMED.test(s); }); } },
  "action-after-no-action": { mistake: "action-not-from-source", rule: "\"No action needed\" followed by advice that is not marked \"General advice:\"",
    test: (e) => /^\s*no action (is )?(needed|stated|required|given)\b/i.test(e.action || "") && String(e.action).replace(/^[^.;]*[.;]\s*(for awareness\.?)?/i, "").trim().length > 20 && !/\bgeneral advice\b/i.test(e.action) },
  "hedge-lost-in-plain": { mistake: "certainty-overstated", rule: "the summary hedges (may have, reportedly, suspected) and plain has no hedge word",
    test: (e) => STRONG_HEDGE.test(e.summary || "") && !/\b(may|might|could|reportedly|allegedly|possibl[ey]|potential(ly)?|appears?|suspected|believed|likely|unconfirmed|unverified|claims?|claimed|says|said)\b/i.test(e.plain || "") },
  "scope-word-not-in-summary": { mistake: "detail-not-in-source", rule: "exec uses a scope or size word (major, largest, every, nationwide ...) that the title and summary do not",
    test: (e) => { const s = `${e.summary || ""} ${e.title || ""}`.toLowerCase(); return (String(e.exec || "").match(SCOPE) || []).some((w) => !s.includes(w.toLowerCase())); } },
  "restates-adds-figure": { mistake: "figure-changed", rule: "a figure of 10 or more in the title, plain or exec that the summary and impact do not have",
    test: (e) => { const base = new Set(countables(`${e.summary || ""} ${e.impact || ""}`).map((f) => f.value)); return ["title", "plain", "exec"].some((k) => countables(e[k]).some((f) => !base.has(f.value) && !(k === "plain" && f.q === "about"))); } },
  "date-is-first-seen": { mistake: "date-wrong", rule: "date is the day the record was written, with no date_note",
    test: (e) => !!e.date && e.date === String(e.first_seen || "").slice(0, 10) && !String(e.date_note || "").trim() },
  "corroborated-relay-note": { mistake: "validation-overstated", rule: "\"corroborated\" while the validation note says a source relays, cites or repeats another",
    test: (e) => !!e.validation && e.validation.state === "corroborated" && /\b(relay|relays|relaying|relayed|repeats?|repeating|citing|cites|based on|quoting|same (wire|report|statement))\b/i.test(e.validation.note || "") },
  "occurred-basis-published": { mistake: "occurred-at-invented", rule: "occurred_at with time_basis \"published\" on an incident or outage",
    test: (e) => !!e.occurred_at && e.time_basis === "published" && ["incident", "outage"].includes(e.category) },
};
/**
 * Pure: every proposed check (PROPOSED_CODES in scripts/lib/validate.mjs, added from this measurement) and every rejected
 * candidate (REJECTED), measured on the cases: hits = corrected records as written it flags, relevant = those where the
 * reviewer fixed the very thing the check is about (its mistake), false_alarms = passed records it flags; and on the
 * events on file today (after their reviews). precision = hits / (hits + false alarms), to compare with base_rate (the
 * share of all records that were corrected: what a coin would score).
 */
export function proposeChecks(cases, events = []) {
  const use = cases.filter((c) => (c.state === "corrected" && c.has_before) || c.state === "passed"), corr = use.filter((c) => c.state === "corrected"), passed = use.filter((c) => c.state === "passed");
  const live = events.filter((e) => e && !e.duplicate_of);
  const rules = Object.entries(PROPOSED_CODES).map(([code, p]) => ({ code, ...p, in_validate: true, test: (e) => proposedProblems(e).some((x) => x.code === code) }))
    .concat(Object.entries(REJECTED).map(([code, p]) => ({ code, ...p, in_validate: false })));
  return rules.map((r) => {
    const t = (e) => { try { return !!r.test(e); } catch { return false; } };
    const hits = corr.filter((c) => t(c.written)), rel = hits.filter((c) => c.mistakes.includes(r.mistake)), fa = passed.filter((c) => t(c.written)), all = corr.filter((c) => c.mistakes.includes(r.mistake)), now = live.filter(t);
    return { code: r.code, in_validate: r.in_validate, mistake: r.mistake, rule: r.rule, hits: hits.length, relevant: rel.length, mistake_cases: all.length, recall_pct: pct(rel.length, all.length), false_alarms: fa.length,
      precision_pct: pct(hits.length, hits.length + fa.length), base_rate_pct: pct(corr.length, corr.length + passed.length), corrected_seen: corr.length, passed_seen: passed.length,
      on_file_now: now.length, on_file_examples: now.slice(-3).map((e) => e.id), examples: [...new Set(rel.map((c) => c.event))].slice(-3) };
  }).sort((a, b) => (b.in_validate - a.in_validate) || (b.precision_pct ?? 0) - (a.precision_pct ?? 0));
}

// ---------- score ----------
const REF_FIELDS = ["date", "severity", "status", "validation", "source_tier"];
/** Pure: {case id and event id: the reviewed record's date, severity, status ...} from cases (an event's last review wins). */
export function refsFrom(cases) {
  const refs = {};
  for (const c of cases) { refs[c.id] = c.reference; refs[c.event] = c.reference; }
  return refs;
}
/**
 * Pure: every mechanical check of scripts/lib/validate.mjs (checkEventQuality, with the proposed checks, and the checks
 * across events when every id is there once) over a set of event records. refs: refsFrom(cases), to count how often the
 * record agrees with the reviewed record of the same id on the fields a script can compare.
 * -> {events, clean, clean_pct, findings, findings_per_event, errors, by_code, proposed, agreement, score}
 * score = the share of records with no finding, in points; with references, the mean of that and the agreement share.
 */
export function scoreEvents(events, { refs = {}, now = Date.now() } = {}) {
  const evs = events.filter((e) => e && typeof e === "object" && e.id), unique = new Set(evs.map((e) => e.id)).size === evs.length;
  const shared = unique ? sharedSourceProblems(evs, evs.map((e) => e.id)) : new Map(), by = {}, agree = Object.fromEntries(REF_FIELDS.map((k) => [k, { same: 0, of: 0 }]));
  let clean = 0, findings = 0, errors = 0;
  for (const e of evs) {
    const p = checkEventQuality(e, { now }).concat(shared.get(e.id) || []).filter((x) => x.code !== "unclassified"), codes = [...new Set(p.map((x) => x.code))];
    for (const c of codes) by[c] = (by[c] || 0) + 1;
    findings += codes.length; errors += p.filter((x) => x.level === "error").length; if (!codes.length) clean++;
    const ref = refs[e._case] || refs[e.id];
    if (ref) for (const k of REF_FIELDS) { agree[k].of++; if (JSON.stringify(fieldOf(e, k)) === JSON.stringify(ref[k] ?? null)) agree[k].same++; }
  }
  const aSame = REF_FIELDS.reduce((s, k) => s + agree[k].same, 0), aOf = REF_FIELDS.reduce((s, k) => s + agree[k].of, 0), cleanPct = pct(clean, evs.length), agreePct = pct(aSame, aOf);
  return { events: evs.length, clean, clean_pct: cleanPct, findings, findings_per_event: evs.length ? Math.round((findings / evs.length) * 100) / 100 : null, errors,
    by_code: Object.fromEntries(Object.entries(by).sort((a, b) => b[1] - a[1])), proposed: Object.fromEntries(Object.keys(PROPOSED_CODES).map((c) => [c, by[c] || 0])),
    agreement: aOf ? { ...Object.fromEntries(REF_FIELDS.map((k) => [k, { ...agree[k], pct: pct(agree[k].same, agree[k].of) }])), all_pct: agreePct } : null,
    score: cleanPct === null ? null : agreePct === null ? cleanPct : Math.round(((cleanPct + agreePct) / 2) * 10) / 10 };
}
/** Event records from a path or an id list: a .json file (one event or a list), a .jsonl file (events, or cases: their
 *  record as written), a folder of .json files, or ids on file separated by commas. */
export function loadEvents(spec) {
  const p = resolve(String(spec || ""));
  const fromFile = (f) => {
    const t = readFileSync(f, "utf8");
    if (f.endsWith(".jsonl")) return t.split("\n").filter((l) => l.trim()).map((l) => { try { const x = JSON.parse(l); return x && x.written ? { ...x.written, id: x.event || x.written.id, _case: x.id } : x; } catch { return null; } }).filter(Boolean);
    const x = JSON.parse(t); return Array.isArray(x) ? x : Array.isArray(x.events) ? x.events : [{ id: f.split("/").pop().replace(/\.json$/, ""), ...x }];
  };
  if (existsSync(p) && statSync(p).isDirectory()) { const out = []; const walk = (d) => { for (const f of readdirSync(d).sort()) { const q = join(d, f); if (statSync(q).isDirectory()) walk(q); else if (f.endsWith(".json")) out.push(...fromFile(q)); } }; walk(p); return out; }
  if (existsSync(p)) return fromFile(p);
  const ids = new Set(String(spec || "").split(",").map((s) => s.trim()).filter(Boolean));
  return listEventFiles().filter((f) => f.e && ids.has(f.id)).map((f) => f.e);
}

// ---------- command line ----------
const readCases = (f) => (existsSync(f) ? readFileSync(f, "utf8").split("\n").filter((l) => l.trim()).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean) : null);
/** The cases built now from the data on file and, unless history is false, the git history of the event files. */
export function casesNow({ days = 0, history = true, gitDir = "", ref = "HEAD" } = {}) {
  const events = listEventFiles().map((f) => f.e).filter(Boolean);
  let hist = {};
  if (history) { try { hist = historyFromGit(gitDir || (existsSync(join(DATA, ".git")) ? DATA : ROOT), ref); } catch { hist = {}; } }
  return { events, history: hist, cases: buildCases(events, hist, writerIndex(loadAllRunLogs()), { days }) };
}
const flat = (v) => (v == null ? "(empty)" : Array.isArray(v) ? (v.length ? v.join(" | ") : "(none)") : String(v)).replace(/\s+/g, " ");
/** Pure: the two texts cut to the part that differs (with some words around it), so a long summary shows its one change. */
export function changed(before, after, width = 230) {
  const b = flat(before), a = flat(after);
  if (b.length <= width && a.length <= width) return [b, a];
  let i = 0; while (i < b.length && i < a.length && b[i] === a[i]) i++;
  let j = 0; while (j < b.length - i && j < a.length - i && b[b.length - 1 - j] === a[a.length - 1 - j]) j++;
  const from = Math.max(0, i - 60), cut = (t) => (from ? "…" : "") + t.slice(from, from + width) + (t.length > from + width ? "…" : "");
  return [cut(b), cut(a)];
}

function main() {
  const argv = process.argv.slice(2), cmd = argv[0], arg = (k) => { const i = argv.indexOf("--" + k); return i >= 0 ? argv[i + 1] : undefined; }, has = (k) => argv.includes("--" + k);
  const opts = { days: Math.max(0, Number(arg("days")) || 0), history: !has("no-history"), gitDir: arg("git") ? resolve(arg("git")) : "", ref: arg("ref") || "HEAD" };
  const load = () => { const f = arg("cases"); if (f) { const c = readCases(resolve(f)); if (!c) { console.error(`no cases file ${f}`); process.exit(1); } return { cases: opts.days ? c.filter((x) => x.at >= new Date(Date.now() - opts.days * 864e5).toISOString()) : c, events: listEventFiles().map((x) => x.e).filter(Boolean) }; } return casesNow(opts); };
  if (cmd === "build") {
    const out = resolve(arg("out") || join(ROOT, "cache", "evals")), { cases, history } = casesNow(opts), rep = report(cases);
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, "cases.jsonl"), cases.map((c) => JSON.stringify(c)).join("\n") + (cases.length ? "\n" : ""));
    const baseline = scoreEvents(cases.map((c) => ({ ...c.written, id: c.event, _case: c.id })), { refs: refsFrom(cases) });
    writeJson(join(out, "summary.json"), { built_at: nowIso(), baseline, cases: cases.length, corrected: rep.corrected, passed: cases.filter((c) => c.state === "passed").length, flagged: rep.flagged, with_diff: rep.with_diff, events_with_history: Object.keys(history).length, report: reportForImprover(rep) });
    console.log(`EVALS: ${cases.length} case(s) (${rep.corrected} corrected, ${rep.with_diff} with the record as written; ${cases.filter((c) => c.state === "passed").length} passed as controls; ${rep.flagged} flagged) -> ${join(out, "cases.jsonl")}`);
    console.log(`  baseline (every record as written): score ${baseline.score}, ${baseline.clean_pct}% with no finding, ${baseline.findings_per_event} findings per record${baseline.agreement ? `, ${baseline.agreement.all_pct}% agreement with the reviewed record` : ""} -> ${join(out, "summary.json")}`);
    if (!Object.keys(history).length) console.log("  no git history of data/events was readable: cases carry the review note and types, no diff");
    return;
  }
  if (cmd === "report") {
    const { cases } = load(), rep = report(cases);
    if (has("json")) { console.log(JSON.stringify(rep)); return; }
    if (has("md")) { console.log(lessons(rep).join("\n")); return; }
    console.log(`ACCURACY EVALS: ${rep.corrected} of ${rep.reviews} second reviews corrected the record (${rep.corrected_pct ?? "-"}%), ${rep.flagged} flagged; first reviews only: ${rep.first.corrected} of ${rep.first.reviews} (${rep.first.corrected_pct ?? "-"}%). ${rep.with_diff} corrections have the record as written (diff). ${String(rep.from || "").slice(0, 10)} to ${String(rep.to || "").slice(0, 10)}.`);
    console.log("\nBy correction type (a correction can have several; % of reviews is the rate a writer makes it):");
    rep.types.forEach((t) => console.log(`  ${t.key.padEnd(12)} ${String(t.n).padStart(4)}  ${String(t.pct_of_corrected).padStart(5)}% of corrections  ${String(t.pct_of_reviews).padStart(5)}% of reviews  ${t.label}`));
    console.log("\nBy who wrote the record (role, model): corrected of reviewed; top types:");
    rep.by_writer.forEach((g) => console.log(`  ${g.role.padEnd(20)} ${g.model.padEnd(8)} ${String(g.corrected).padStart(3)} of ${String(g.reviewed).padStart(3)} (${g.corrected_pct ?? "-"}%)  ${top(g.types).map(([t, v]) => `${t} ${v}`).join(", ")}`));
    console.log("\nBy category:");
    rep.by_category.forEach((g) => console.log(`  ${g.key.padEnd(12)} ${String(g.corrected).padStart(3)} of ${String(g.reviewed).padStart(3)} (${g.corrected_pct ?? "-"}%)  ${top(g.types).map(([t, v]) => `${t} ${v}`).join(", ")}`));
    console.log("\nType x role x model x category (cells with 5 or more reviews; rate of each type per review):");
    rep.cells.slice(0, 16).forEach((x) => console.log(`  ${x.role.padEnd(18)} ${x.model.padEnd(7)} ${x.category.padEnd(11)} ${String(x.corrected).padStart(3)}/${String(x.reviewed).padStart(3)} (${x.corrected_pct}%)  ${Object.entries(x.types).map(([t, v]) => `${t} ${v.pct_of_reviews}%`).join(", ")}`));
    console.log(`\nTHE ${rep.mistakes.length} MOST FREQUENT SPECIFIC MISTAKES (from what the reviewer changed):`);
    rep.mistakes.forEach((m, i) => {
      console.log(`\n${i + 1}. ${m.key}: ${m.label}\n   ${m.n} corrections (${m.pct_of_corrected}% of corrections, ${m.pct_of_reviews}% of reviews); writers: ${Object.entries(m.by_writer).map(([w, v]) => `${w} ${v}`).join(", ")}`);
      console.log(m.checks.length ? `   mechanical checks on the record as written: caught ${m.caught} of ${m.with_before} (${m.caught_pct ?? "-"}%; ${m.caught_before_new_checks} before the checks of 23 November)${Object.keys(m.caught_by).length ? " by " + Object.entries(m.caught_by).map(([c, v]) => `${c}${PROPOSED_CODES[c] ? " (new)" : ""} ${v}`).join(", ") : ""}; MISSED ${m.missed}. Checks meant for it: ${m.checks.join(", ")}`
        : `   no mechanical check exists for it (${m.with_before} records as written): it takes a reader to see`);
      m.examples.forEach((x) => { const [b, a] = x.field ? changed(x.before, x.after) : []; console.log(`   - ${x.event}${x.field ? `\n       ${x.field} as written:   ${b}\n       ${x.field} as corrected: ${a}` : ""}\n       reviewer: ${flat(x.note).slice(0, 260)}`); });
    });
    if (rep.mistakes_rest.length) console.log("\nLess frequent: " + rep.mistakes_rest.map((m) => `${m.key} ${m.n}`).join(", "));
    return;
  }
  if (cmd === "propose-checks") {
    const { cases, events } = load(), rows = proposeChecks(cases, events);
    if (has("json")) { console.log(JSON.stringify(rows)); return; }
    const b = rows[0] || {}, line = (r) => console.log(`  ${r.code.padEnd(26)} ${String(r.hits).padStart(3)} corrected, ${String(r.false_alarms).padStart(3)} passed: precision ${String(r.precision_pct ?? "-").padStart(5)}%   fixes ${r.mistake}: ${r.relevant} of ${r.mistake_cases} (${r.recall_pct ?? "-"}%)   on file today: ${r.on_file_now}\n      ${r.rule}${r.examples.length ? "\n      e.g. " + r.examples.join(", ") : ""}`);
    console.log(`MISTAKES A SCRIPT CAN DECIDE, measured on ${b.corrected_seen ?? 0} corrected and ${b.passed_seen ?? 0} passed records as their writers left them. A rule that flags records at random has precision ${b.base_rate_pct ?? "-"}%.`);
    console.log("\nIn scripts/lib/validate.mjs as warnings (proposedProblems):");
    rows.filter((r) => r.in_validate).forEach(line);
    console.log("\nTried and rejected (precision near chance, or it catches too little of its mistake): not in validate.mjs:");
    rows.filter((r) => !r.in_validate).forEach(line);
    console.log("\nPromote a warning to an error (PROPOSED_STRICT_FROM in scripts/lib/validate.mjs) only after its precision has held for a week.");
    return;
  }
  if (cmd === "score") {
    const spec = arg("events"); if (!spec) { console.error("usage: evals.mjs score --events <file.json|file.jsonl|dir|id,id,...> [--cases <file>] [--baseline <score.json>] [--json]"); process.exit(1); }
    const evs = loadEvents(spec), cf = arg("cases"), cs = cf ? readCases(resolve(cf)) || [] : [], refs = {};
    Object.assign(refs, refsFrom(cs));                        // cases are oldest first: the last review of an event wins
    const s = scoreEvents(evs, { refs });
    if (has("json")) { console.log(JSON.stringify(s)); return; }
    const bf = arg("baseline") ? readJson(resolve(arg("baseline")), null) : null, base = bf && bf.baseline ? bf.baseline : bf, d = (a, b) => (base && a != null && b != null ? ` (baseline ${b}, ${a - b >= 0 ? "+" : ""}${Math.round((a - b) * 10) / 10})` : "");
    console.log(`SCORE ${s.score ?? "-"}${d(s.score, base && base.score)}: ${s.events} event(s), ${s.clean} with no finding (${s.clean_pct ?? "-"}%${d(s.clean_pct, base && base.clean_pct)}), ${s.findings_per_event ?? "-"} findings per event${d(s.findings_per_event, base && base.findings_per_event)}, ${s.errors} at error level.`);
    if (s.agreement) console.log(`  agreement with the reviewed record: ${REF_FIELDS.map((k) => `${k} ${s.agreement[k].pct ?? "-"}%`).join(", ")}; all ${s.agreement.all_pct}%${d(s.agreement.all_pct, base && base.agreement && base.agreement.all_pct)}`);
    Object.entries(s.by_code).forEach(([c, v]) => console.log(`  ${c.padEnd(26)} ${String(v).padStart(4)}${PROPOSED_CODES[c] ? "  (proposed)" : ""}${base && base.by_code ? `  baseline ${base.by_code[c] || 0}` : ""}`));
    return;
  }
  console.error("usage: evals.mjs build [--out dir] | report [--md|--json] | propose-checks | score --events <...>   (see the head of the file)"); process.exit(1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
