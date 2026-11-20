// What the second review corrects, week by week. No AI model. Run: node scripts/quality.mjs [--days 7] [--json]
// Reads every event's "review" (state, note, flags, at, first_at; "changes" when present) and data/corrections/, sorts each
// correction or flag into categories by fixed keyword rules over the reviewer's note (and the correction file's text), and
// prints: the table for the last <days> days against the <days> before, the correction rate, and which categories still
// have no automatic check in scripts/lib/validate.mjs or scripts/review.mjs. "flagged: source unreachable" is counted on
// its own line: it measures the reviewer's network, not the quality of the first draft.
// The owner's target (2026-11-20): second-review corrections under 10% of reviews.
import { pathToFileURL } from "node:url";
import { listEventFiles, listDir } from "./lib/store.mjs";

/** The categories, in report order. `checks` are the codes of the automatic checks that catch (part of) the category;
 *  an empty list means only a reader can catch it today. */
export const CATEGORIES = [
  { key: "wording", label: "wording stronger than the source", checks: [] },
  { key: "tier", label: "weak source tier", checks: ["tier-secondary", "confirmed-on-aggregator", "confirmed-on-secondary", "listing-source"] },
  { key: "date", label: "wrong date or time", checks: ["old-date-no-note", "old-date", "occurred-no-basis", "occurred-placeholder", "future-date", "future-timestamp", "date-after-seen", "time-date-mismatch"] },
  { key: "figure", label: "figure or version miscopied", checks: ["figure-not-in-summary", "number-check", "figure-qualifier"] },
  { key: "unattributed", label: "unattributed claim", checks: ["actor-unsourced"] },
  { key: "status", label: "unsupported status or validation", checks: ["corroborated-one-host", "corroborated-on-secondary", "confirmed-on-secondary", "claim-severity", "claim-corroborated"] },
  { key: "absence", label: "absence claim (\"no statement\", \"not confirmed\")", checks: [] },
  { key: "tags", label: "tags", checks: ["tag-unsupported"] },
  { key: "duplicate", label: "duplicate", checks: ["possible-duplicate", "roundup-source"] },
  { key: "unreachable", label: "source unreachable", checks: [] },
  { key: "other", label: "other", checks: [] },
];

// A clause that only reports what matched ("dates, figures match HIPAA Journal") says nothing about what was wrong.
const MATCHED = /\b(match(es|ed)?|correct|confirm(s|ed)?|verified|agree[sd]?|checked|are right|stands?)\b/i;
const FIXED = /\b(fix(ed)?|remov(e|ed)|reword(ed)?|rewr(ote|itten)|chang(e|ed)|mov(e|ed)|now|add(ed)?|narrow(ed)?|soften(ed)?|corrected|but|wrong(ly)?|overstat\w*|instead|rather than|claimed|dropp(ed)?|lowered|raised|unsupported|(does|do|did) not)\b/i;
const RULES = [
  ["duplicate", /duplicate_of|\bsame (event|incident|flaws?|story|attack|breach)\b|\bduplicate (record|event|of)\b|marked duplicate|merged (its |the )?sources/i],
  ["unreachable", /unreachable|\b(returned|returns?|gave)\s+(only\s+)?(http\s*)?(4\d\d|5\d\d)\b|\bhttp\s*(4\d\d|5\d\d)\b|\b(403|408|429|451|503)\b(?!\s*(gb|mb|records|people|customers|million))|econnreset|etimedout|timed out|only (returned )?site navigation|could not be (loaded|reached|opened|fetched)/i],
  ["tags", /\btags?\b(?! *(line|ged))/i],
  ["date", /\bdates?\b(?! (and|,)? ?(figures?|counts?) match)|date_note|occurred_at|time_basis|\btimestamps?\b|placeholder|publication day|publish(ed)? date|\b(year|day|weekday|time) (was|is|wrong|fixed|corrected)|\b\d{1,2}:\d{2}\b|\bnot (\d{1,2} )?(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]* ?\d{0,2}\b/i],
  ["figure", /\b(figures?|counts?|numbers?|totals?|miscount\w*|units?|gigab\w+|percent(age)?|share)\b|\b(about|over|nearly|more than|at least|up to|approx\w*)\s+[\d,.]+|[\d,.]+\s*(million|billion|m\b)|\b\d{1,3}(,\d{3})+\b|versions? range|\brange\b|prior to [\d.]+|not before [\d.]+|\d%/i],
  ["tier", /\btier\b|non-article|search-label|listing page|aggregator|tracker|roundup|law-firm|lead page|secondhand|relay(s|ed|ing)?\b|primary source|original (\w+ )?(not read|unread)|unread|not read|only source|single (aggregator|source)|forum page|mirror/i],
  ["status", /\bstatus\b|\bvalidation\b|corroborated|single_source|\bdisputed\b|\bconfirmed\b.*\brests?\b|rests? (only )?on|\bseverity\b/i],
  ["absence", /\b(said|says|claimed|stated|wrote|wrongly said)\b[^.;]{0,50}\b(no|not|never|none|nothing|lacks?|made no|gave no)\b|\bno (confirmation|public statement|statement|response|count|comment)\b|has not (confirmed|commented|responded|said)|ruled out|no-comment|not (a|an) (cyber ?)?attack/i],
  ["unattributed", /\battribut\w*|according to|as reported by|\bcredited\b|\bnow (says|states|names)\b[^.;]{0,60}\b(says|said|reported|reports|names|via|per)\b|\bper [A-Z][\w-]+|\bis the source of\b|\b(outlet|reporting|article)'s own\b|\bas (the )?(outlet|article|report) (says|states|words it)|words it/],
  ["wording", /overstat\w*|stronger|soften\w*|narrow\w*|implied|\bunsupported\b|not (in|on) (the |either |any )?(listed |source |sources|articles?|page|post|report|advisory)|(do|does|did) not (say|state|support|mention|describe|confirm)|not (stated|supported|described)|appear(s)? in no|only in\b|inference|wrong(ly)?|rather than|instead of|matched nothing|not found in|exagger\w*|reworded|rewrote|rewritten|clarif\w*|lacked|missing|tightened|misleading|could not be found|not found on|removed [^.;]{0,60}\b(claim|statement|wording)s?\b|to (the )?report('s)? wording|as the source (states|words it)/i],
];

/** Pure: the clauses of a note that say what was wrong (clauses that only report a match are dropped). */
export function problemClauses(note) {
  return String(note || "").split(/(?<=[.;])\s+|;\s*|\s+-\s+|\n+/).map((s) => s.trim()).filter(Boolean)
    .filter((c) => !(MATCHED.test(c) && !FIXED.test(c.replace(MATCHED, ""))));
}

/** Pure: the categories a reviewer's note (plus any correction text) falls into. Unreachable and duplicate notes are read
 *  whole (they are rarely mixed with matches); the rest only from the clauses that describe a problem. */
export function categorise(note, extra = "") {
  const whole = `${note || ""} ${extra || ""}`, clauses = problemClauses(note).concat(problemClauses(extra)).join(" | ");
  const out = [];
  for (const [k, re] of RULES) if (re.test(k === "unreachable" || k === "duplicate" ? whole : clauses)) out.push(k);
  return out.length ? out : ["other"];
}

/** Pure: is this a "flagged" review only because a source could not be read? */
export const unreachableOnly = (r) => r && r.state === "flagged" && categorise(r.note).includes("unreachable");

const when = (r) => String((r && (r.first_at || r.at)) || "");
/** Pure: the report over events [{id, review}] and corrections [{event_id, title, what_changed, at}] for the window ending at `now`. */
export function report(events, corrections = [], { days = 7, now = Date.now() } = {}) {
  const end = new Date(now).toISOString(), mid = new Date(now - days * 864e5).toISOString(), start = new Date(now - 2 * days * 864e5).toISOString();
  const corrBy = new Map();
  for (const c of corrections) if (c && c.event_id) (corrBy.get(c.event_id) || corrBy.set(c.event_id, []).get(c.event_id)).push(`${c.title || ""}. ${c.what_changed || ""}`);
  const blank = () => ({ reviews: 0, passed: 0, corrected: 0, flagged: 0, flagged_unreachable: 0, cats: Object.fromEntries(CATEGORIES.map((c) => [c.key, 0])), examples: {} });
  const weeks = { this: blank(), prev: blank() }, items = [], daily = {};
  for (const e of events) {
    const r = e && e.review; if (!r || !r.state) continue;
    const t = when(r), w = t >= mid && t <= end ? weeks.this : t >= start && t < mid ? weeks.prev : null;
    if (!w) continue;
    const d = daily[t.slice(0, 10)] || (daily[t.slice(0, 10)] = { reviews: 0, corrected: 0, flagged: 0 });
    d.reviews++; if (r.state !== "passed") d[r.state] = (d[r.state] || 0) + 1;
    w.reviews++; w[r.state === "passed" ? "passed" : r.state] = (w[r.state === "passed" ? "passed" : r.state] || 0) + 1;
    if (r.state === "passed") continue;
    const changes = Array.isArray(r.changes) ? r.changes.join(". ") : typeof r.changes === "string" ? r.changes : "";
    const cats = categorise(r.note, [changes, ...(corrBy.get(e.id) || [])].join(". "));
    if (unreachableOnly(r)) w.flagged_unreachable++;
    for (const k of cats) { w.cats[k]++; if (w === weeks.this && !w.examples[k]) w.examples[k] = { id: e.id, note: String(r.note || "").slice(0, 160) }; }
    if (w === weeks.this) items.push({ id: e.id, state: r.state, at: t, cats });
  }
  // corrections filed outside a second review (the verify and follow-up jobs), by category
  const reviewed = new Set(events.filter((e) => e && e.review).map((e) => e.id)), other = Object.fromEntries(CATEGORIES.map((c) => [c.key, 0]));
  let otherN = 0;
  for (const c of corrections) {
    const t = String((c && c.at) || "");
    if (!(t >= mid && t <= end) || (c.event_id && reviewed.has(c.event_id))) continue;
    otherN++; for (const k of categorise(c.what_changed, c.title)) other[k]++;
  }
  const rate = (w) => (w.reviews ? Math.round((1000 * w.corrected) / w.reviews) / 10 : null);
  const rateQ = (w) => (w.reviews - w.flagged_unreachable ? Math.round((1000 * (w.corrected + w.flagged - w.flagged_unreachable)) / (w.reviews - w.flagged_unreachable)) / 10 : null);
  return {
    window: { days, from: mid, to: end, previous_from: start },
    this_week: { ...weeks.this, corrected_pct: rate(weeks.this), corrected_or_flagged_pct: rateQ(weeks.this) },
    previous_week: { ...weeks.prev, corrected_pct: rate(weeks.prev), corrected_or_flagged_pct: rateQ(weeks.prev) },
    categories: CATEGORIES.map((c) => ({ key: c.key, label: c.label, this_week: weeks.this.cats[c.key], previous_week: weeks.prev.cats[c.key], checks: c.checks, automatic: c.checks.length > 0 })),
    no_automatic_check: CATEGORIES.filter((c) => !c.checks.length).map((c) => c.key),
    other_corrections: { count: otherN, cats: other },
    daily: Object.keys(daily).sort().map((day) => ({ day, ...daily[day], corrected_pct: Math.round((1000 * daily[day].corrected) / daily[day].reviews) / 10 })),
    examples: weeks.this.examples,
    items,
    target_pct: 10,
  };
}

function print(r) {
  const t = r.this_week, p = r.previous_week, pad = (s, n) => String(s).padEnd(n), num = (n) => String(n).padStart(5);
  const arrow = (a, b) => (b == null || a == null ? "" : a > b ? " up" : a < b ? " down" : " same");
  console.log(`SECOND REVIEW QUALITY: ${r.window.from.slice(0, 16)}Z to ${r.window.to.slice(0, 16)}Z (${r.window.days} days), against the ${r.window.days} days before`);
  console.log(`  reviews ${t.reviews} (before: ${p.reviews}); passed ${t.passed}, corrected ${t.corrected}, flagged ${t.flagged} (of them source unreachable: ${t.flagged_unreachable})`);
  console.log(`  corrected: ${t.corrected_pct ?? "-"}% (before: ${p.corrected_pct ?? "-"}%${arrow(t.corrected_pct, p.corrected_pct)}); corrected or flagged, unreachable left out: ${t.corrected_or_flagged_pct ?? "-"}% (before: ${p.corrected_or_flagged_pct ?? "-"}%); target under ${r.target_pct}%`);
  if (r.daily.length) console.log(`  by day of review: ${r.daily.map((d) => `${d.day.slice(5)} ${d.corrected}/${d.reviews} corrected (${d.corrected_pct}%)`).join(", ")}`);
  console.log(`\n  ${pad("category", 50)}${num("week")}${num("prev")}  automatic check`);
  for (const c of r.categories) console.log(`  ${pad(c.label, 50)}${num(c.this_week)}${num(c.previous_week)}  ${c.checks.length ? c.checks.join(", ") : "NONE (a reader only)"}`);
  console.log(`  (a correction can fall into several categories; "flagged: source unreachable" reflects the reviewer's network, not the first draft)`);
  if (r.other_corrections.count) console.log(`\n  corrections filed outside a second review: ${r.other_corrections.count} (${Object.entries(r.other_corrections.cats).filter(([, n]) => n).map(([k, n]) => `${k} ${n}`).join(", ")})`);
  const top = r.categories.filter((c) => c.key !== "unreachable" && c.key !== "other").sort((a, b) => b.this_week - a.this_week).slice(0, 3);
  console.log(`\n  most corrected: ${top.map((c) => `${c.label} (${c.this_week})`).join("; ")}`);
  console.log(`  no automatic check yet: ${r.no_automatic_check.join(", ")}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const a = process.argv.slice(2), di = a.indexOf("--days"), days = Math.max(1, Math.min(60, Number(di >= 0 ? a[di + 1] : 7) || 7));
  const events = listEventFiles().filter((f) => f.e).map((f) => ({ ...f.e, id: f.id })), corrections = listDir("corrections").filter((x) => x.r).map((x) => x.r);
  const r = report(events, corrections, { days });
  if (a.includes("--json")) console.log(JSON.stringify(a.includes("--items") ? r : { ...r, items: undefined }, null, 2)); else print(r);
}
