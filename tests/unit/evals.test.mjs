// The accuracy evals (scripts/evals.mjs): cases from the second reviews, the report, the proposed checks and the score; and
// the checks they proposed (scripts/lib/validate.mjs proposedProblems), each on small made-up events. No AI model, no
// network. Run: node --test tests/unit/
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fieldDiff, fieldOf, historyFromGit, writerIndex, writerAt, buildCases, mistakesOf, MISTAKES, report, lessons, reportForImprover, proposeChecks, REJECTED, scoreEvents, refsFrom, loadEvents, changed } from "../../scripts/evals.mjs";
import { checkEventQuality, proposedProblems, PROPOSED_CODES, PROPOSED_STRICT_FROM, ACCURACY_STRICT_FROM } from "../../scripts/lib/validate.mjs";
import { evidenceFor } from "../../scripts/improve.mjs";
import { ROOT } from "../../scripts/lib/store.mjs";

const A = "https://acme.example/news/security-notice", R = "https://reuters.example/tech/acme-breach-2026-11-22/";
const T0 = "2026-11-22T08:00:00Z", NOW = Date.parse("2026-11-23T00:00:00Z");
const ev = (o = {}) => ({
  id: "acme-breach-2026-11", title: "Acme confirms breach of 1,200 customer records", date: "2026-11-21", category: "incident", severity: 2, status: "confirmed",
  org: "Acme", summary: "Acme said attackers copied 1,200 customer records on November 21. The company has notified regulators.", plain: "Acme says hackers copied customer records.",
  exec: "Customer data exposure.", action: "Acme advises customers to reset their passwords.", tags: ["data-breach"], cves: [],
  sources: [{ name: "Acme", url: A, published: "2026-11-22" }, { name: "Reuters", url: R, published: "2026-11-22" }],
  evidence: [{ url: A, quote: "On 21 November attackers copied 1,200 customer records from our web shop." }],
  sectors: { values: ["commercial-facilities"], basis: "inferred" }, surface: { value: "web-app", basis: "stated" },
  source_tier: "primary", validation: { state: "corroborated", note: "Acme's notice and Reuters each state it" }, first_seen: T0, updated_at: T0, ...o,
});
const rev = (state, at, note) => ({ state, at, first_at: at, note, flags: [] });
const codes = (e) => proposedProblems(e).map((x) => x.code);

// ---------- the proposed checks (warnings) ----------
test("a clean event raises none of the proposed checks, and none of them is an error yet", () => {
  assert.deepEqual(proposedProblems(ev()), []);
  assert.deepEqual(checkEventQuality(ev(), { now: NOW }), []);
  assert.ok(PROPOSED_STRICT_FROM > "2100", "the proposed checks stay warnings until someone sets a date");
  assert.ok(ACCURACY_STRICT_FROM < PROPOSED_STRICT_FROM);
  const bad = ev({ summary: Array(80).fill("word").join(" ") + " Acme said so.", status: "claimed", severity: 2, occurred_at: "2026-11-21T09:00:00Z", time_basis: "published", sources: [{ name: "Acme", url: A, published: "2026-11-22" }, { name: "Reuters", url: R }] });
  const p = checkEventQuality(bad, { now: NOW }).filter((x) => PROPOSED_CODES[x.code]);
  assert.deepEqual(p.map((x) => x.code).sort(), ["claim-severity", "long-summary", "occurred-round-hour", "source-published-partial"]);
  assert.ok(p.every((x) => x.level === "warn"), "a new event with every proposed problem still only gets warnings");
});

test("long-summary: over 75 words", () => {
  assert.ok(!codes(ev({ summary: "Acme said " + Array(73).fill("word").join(" ") })).includes("long-summary"), "75 words pass");
  assert.ok(codes(ev({ summary: "Acme said " + Array(74).fill("word").join(" ") })).includes("long-summary"), "76 words do not");
});

test("source-published-partial: some sources dated, others not; all or none is not this check's business", () => {
  const some = ev({ sources: [{ name: "Acme", url: A, published: "2026-11-22" }, { name: "Reuters", url: R }] });
  assert.ok(codes(some).includes("source-published-partial"));
  assert.match(proposedProblems(some).find((x) => x.code === "source-published-partial").text, /1 of 2 sources/);
  assert.ok(!codes(ev({ sources: [{ name: "Acme", url: A }, { name: "Reuters", url: R }] })).includes("source-published-partial"), "an old event with no published days at all is left alone");
  assert.ok(!codes(ev({ sources: [{ name: "Acme", url: A, published: "2026-11-22" }] })).includes("source-published-partial"));
});

test("summary-unattributed: an incident or outage summary that names nobody who says so", () => {
  const voice = "Attackers stole personal information submitted through the university's online forms going back to 2007. No record count has been given.";
  assert.ok(codes(ev({ summary: voice })).includes("summary-unattributed"));
  assert.ok(codes(ev({ category: "outage", summary: voice })).includes("summary-unattributed"));
  assert.ok(!codes(ev({ summary: "The university said attackers stole personal information submitted through its online forms going back to 2007." })).includes("summary-unattributed"));
  assert.ok(!codes(ev({ summary: "According to BleepingComputer, attackers stole personal information submitted through online forms going back to 2007." })).includes("summary-unattributed"));
  assert.ok(!codes(ev({ category: "vuln", summary: voice })).includes("summary-unattributed"), "only incidents and outages");
  assert.ok(!codes(ev({ summary: "" })).includes("summary-unattributed"), "an empty summary is another check's problem");
});

test("occurred-round-hour: exactly on the hour without a quoted time; 00:00 and 12:00 UTC stay with occurred-placeholder", () => {
  const at = (t, o = {}) => codes(ev({ occurred_at: t, time_basis: "published", ...o }));
  assert.ok(at("2026-11-21T09:00:00Z").includes("occurred-round-hour"));
  assert.ok(at("2026-11-21T16:00:00+09:00").includes("occurred-round-hour"));
  assert.ok(!at("2026-11-21T09:17:00Z").includes("occurred-round-hour"), "a time off the hour is what a stated time looks like");
  assert.ok(!at("2026-11-21T09:00:00Z", { time_basis: "approx" }).includes("occurred-round-hour"), "approx says it is rounded");
  assert.ok(!at("2026-11-21T09:00:00Z", { evidence: [{ url: A, quote: "The outage began at 9:00 a.m. UTC on 21 November." }] }).includes("occurred-round-hour"), "a quoted time of day supports it");
  assert.ok(!at("2026-11-21T12:00:00Z").includes("occurred-round-hour"), "the placeholder check already reports 12:00");
  assert.ok(checkEventQuality(ev({ occurred_at: "2026-11-21T12:00:00Z", time_basis: "published" }), { now: NOW }).some((x) => x.code === "occurred-placeholder"));
  assert.ok(!codes(ev()).includes("occurred-round-hour"), "no occurred_at, no finding");
});

test("claim-severity: a claim is severity 1", () => {
  assert.ok(codes(ev({ status: "claimed", severity: 2, title: "Group claims breach of Acme" })).includes("claim-severity"));
  assert.ok(!codes(ev({ status: "claimed", severity: 1, title: "Group claims breach of Acme" })).includes("claim-severity"));
  assert.ok(!codes(ev({ status: "confirmed", severity: 3 })).includes("claim-severity"));
});

test("every proposed code says which mistake it is for, and that mistake exists", () => {
  const keys = new Set(MISTAKES.map((m) => m.key));
  for (const [code, p] of Object.entries(PROPOSED_CODES)) { assert.ok(keys.has(p.mistake), `${code}: ${p.mistake}`); assert.ok(p.rule.length > 20); assert.ok(MISTAKES.find((m) => m.key === p.mistake).checks.includes(code), `${code} is listed under its mistake's checks`); }
  for (const [code, p] of Object.entries(REJECTED)) { assert.ok(keys.has(p.mistake), code); assert.equal(typeof p.test, "function"); assert.ok(!PROPOSED_CODES[code], `${code} cannot be both proposed and rejected`); }
});

// ---------- diff ----------
test("fieldDiff: only what changed, sources with their published day, validation as its state", () => {
  const b = ev({ sources: [{ name: "Acme", url: A }, { name: "Reuters", url: R, published: "2026-11-22" }] });
  const a = ev({ title: "Acme says about 1,200 customer records were copied", validation: { state: "single_source", note: "Reuters relays Acme" }, occurred_at: undefined });
  const d = Object.fromEntries(fieldDiff(b, a).map((x) => [x.field, x]));
  assert.deepEqual(Object.keys(d).sort(), ["sources", "title", "validation", "validation_note"]);
  assert.equal(d.validation.before, "corroborated"); assert.equal(d.validation.after, "single_source");
  assert.deepEqual(d.sources.before, [A, `${R} (2026-11-22)`]);
  assert.deepEqual(fieldDiff(b, b), []);
  assert.equal(fieldOf(ev({ occurred_at: "" }), "occurred_at"), null, "an empty field and a missing one are the same");
  assert.ok(fieldDiff(ev({ summary: "x".repeat(2000) }), ev())[0].before.length < 800, "long text is clipped");
});

test("changed: a long text is cut to the part that differs", () => {
  const long = "word ".repeat(80), [b, a] = changed(long + "nearly 4,000 retirees. " + long, long + "about 4,000 retirees. " + long);
  assert.ok(b.includes("nearly 4,000") && a.includes("about 4,000"));
  assert.ok(b.length < 260 && b.startsWith("…"));
  assert.deepEqual(changed("2026-11-17", null), ["2026-11-17", "(empty)"]);
});

// ---------- cases ----------
const written = ev({ title: "Acme breach exposes 1,200 customer records", summary: "Attackers copied 1,200 customer records at Acme on November 21 in a major breach. Regulators are involved.", action: "Acme customers: check card statements.", occurred_at: "2026-11-21T09:00:00Z", time_basis: "published", sources: [{ name: "Acme", url: A, published: "2026-11-22" }, { name: "Reuters", url: R }] });
const corrected = ev({ summary: "Acme said attackers may have copied 1,200 customer records on November 21. The company has notified regulators.", review: rev("corrected", "2026-11-22T08:30:00Z", "stronger than the source: Acme says may have copied; unsourced detail 'major breach' removed; action advice now Acme's own; removed occurred_at 09:00 no page states; added Reuters published day") });
const passedEv = ev({ id: "beta-outage-2026-11", category: "outage", org: "Beta", sources: [{ name: "Beta", url: "https://beta.example/status/portal-2026-11-21", published: "2026-11-22" }], source_tier: "primary", validation: { state: "single_source", note: "Beta's own notice" }, tags: [], title: "Beta says its portal was down for two hours", summary: "Beta said its customer portal was down for two hours on November 21.", evidence: undefined, review: rev("passed", "2026-11-22T09:00:00Z", "Title, date and duration match Beta's notice") });
const history = { "acme-breach-2026-11": [{ t: "2026-11-22T08:05:00Z", e: written }, { t: "2026-11-22T08:35:00Z", e: corrected }, { t: "2026-11-22T09:35:00Z", e: { ...corrected, sectors: { values: ["commercial-facilities"], basis: "stated" } } }] };
const logs = [{ at: "2026-11-22T08:04:00Z", job: "sweep-r1", worker_role: "researcher", worker_model: "claude-sonnet-5-5", added: ["acme-breach-2026-11"], updated: [], pages_read: [{ url: A, used_in: "acme-breach-2026-11" }, { url: "https://other.example/x", used_in: "other-event" }] },
  { at: "2026-11-22T08:31:00Z", job: "review-r1", worker_role: "reviewer", worker_model: "sonnet", added: [], updated: ["acme-breach-2026-11"] },
  { at: "2026-11-22T10:00:00Z", job: "update-u1", worker_role: "updater", worker_model: "sonnet", added: [], updated: ["acme-breach-2026-11"] }];
const cases = buildCases([corrected, passedEv], history, writerIndex(logs), { now: NOW });

test("buildCases: one case per review, with the record as written, the diff, the writer and the inputs", () => {
  assert.equal(cases.length, 2);
  const c = cases.find((x) => x.event === "acme-breach-2026-11");
  assert.equal(c.id, "acme-breach-2026-11@2026-11-22T08:30:00Z");
  assert.equal(c.state, "corrected"); assert.equal(c.first, true); assert.equal(c.has_before, true);
  assert.deepEqual(c.writer, { role: "researcher", model: "sonnet" }, "the reviewer and a later updater are not the writer of this version");
  assert.deepEqual(c.inputs.pages_read, [A]);
  assert.deepEqual(c.inputs.sources.map((s) => s.url), [A, R]);
  assert.equal(c.written.title, written.title); assert.equal(c.written.review, undefined, "the record as written carries no review");
  assert.deepEqual(c.diff.map((x) => x.field).sort(), ["action", "occurred_at", "sources", "summary", "time_basis", "title"]);
  assert.ok(c.types.includes("overstated") && c.types.includes("action"));
  assert.ok(c.caught.includes("occurred-round-hour") && c.caught.includes("source-published-partial"), "the checks are run on the record as written");
  assert.equal(c.reference.validation, "corroborated"); assert.equal(c.reference.date, "2026-11-21");
  const p = cases.find((x) => x.event === "beta-outage-2026-11");
  assert.equal(p.state, "passed"); assert.equal(p.has_before, false); assert.deepEqual(p.diff, []); assert.deepEqual(p.mistakes, []);
  assert.deepEqual(p.writer, { role: "unknown", model: "unknown" });
  assert.ok(!JSON.stringify(cases).includes('"review"'), "no review record inside a case's written event");
});

test("buildCases: a version that only repeats the same review is not a second case; --days leaves out old reviews", () => {
  assert.equal(cases.filter((c) => c.event === "acme-breach-2026-11").length, 1);
  assert.equal(buildCases([corrected, passedEv], history, new Map(), { days: 1, now: Date.parse("2026-11-30T00:00:00Z") }).length, 0);
  const noHist = buildCases([corrected], {}, new Map(), { now: NOW });
  assert.equal(noHist.length, 1); assert.equal(noHist[0].has_before, false);
  assert.ok(noHist[0].mistakes.includes("certainty-overstated") && noHist[0].mistakes.includes("action-not-from-source"), "without history the mistakes come from the note");
});

test("mistakesOf: decided from what the reviewer changed", () => {
  const m = cases.find((x) => x.event === "acme-breach-2026-11").mistakes;
  for (const k of ["certainty-overstated", "who-said-it-missing", "action-not-from-source", "occurred-at-invented", "source-published-missing", "detail-not-in-source"]) assert.ok(m.includes(k), k);
  for (const k of ["date-wrong", "source-list-wrong", "validation-overstated", "summary-too-long", "duplicate"]) assert.ok(!m.includes(k), k);
  const mk = (diff, note = "fixed", types = []) => mistakesOf({ state: "corrected", note, types, diff });
  assert.deepEqual(mk([{ field: "date", before: "2026-11-19", after: "2026-11-18" }]), ["date-wrong"]);
  assert.deepEqual(mk([{ field: "date_note", before: null, after: "The notice gives no earlier day." }]), ["date-note-missing"]);
  assert.deepEqual(mk([{ field: "title", before: "Leak of 209 GB build", after: "Leak of roughly 209 GB build" }]), ["figure-changed"]);
  assert.deepEqual(mk([{ field: "sources", before: [A, R], after: [A] }]), ["source-list-wrong"]);
  assert.deepEqual(mk([{ field: "validation", before: "corroborated", after: "single_source" }]), ["validation-overstated"]);
  assert.deepEqual(mk([{ field: "summary", before: Array(90).fill("w").join(" "), after: Array(70).fill("w").join(" ") }]), ["summary-too-long"]);
  assert.deepEqual(mk([{ field: "duplicate_of", before: null, after: "acme-breach-2026-11" }]), ["duplicate"]);
  assert.deepEqual(mistakesOf({ state: "passed", note: "all match", types: [], diff: [{ field: "date", before: "a", after: "b" }] }), [], "a pass has no mistake");
});

// ---------- report ----------
test("report: rates by type, writer and category, and the mistakes with examples and what the checks caught", () => {
  const r = report(cases);
  assert.equal(r.reviews, 2); assert.equal(r.corrected, 1); assert.equal(r.corrected_pct, 50); assert.equal(r.with_diff, 1);
  assert.deepEqual(r.first, { reviews: 2, corrected: 1, corrected_pct: 50 });
  assert.ok(r.types.find((t) => t.key === "overstated").pct_of_reviews === 50);
  assert.deepEqual(r.by_writer.map((g) => [g.role, g.model, g.corrected, g.reviewed]).sort(), [["researcher", "sonnet", 1, 1], ["unknown", "unknown", 0, 1]]);
  assert.deepEqual(r.by_category.map((g) => [g.key, g.corrected_pct]).sort(), [["incident", 100], ["outage", 0]]);
  const occ = r.mistakes.find((m) => m.key === "occurred-at-invented");
  assert.equal(occ.n, 1); assert.equal(occ.caught, 1); assert.equal(occ.missed, 0); assert.ok(occ.caught_before_new_checks <= occ.caught);
  assert.equal(occ.caught_by["occurred-round-hour"], 1);
  assert.deepEqual([occ.examples[0].event, occ.examples[0].field, occ.examples[0].before, occ.examples[0].after], ["acme-breach-2026-11", "occurred_at", "2026-11-21T09:00:00Z", null]);
  const det = r.mistakes.find((m) => m.key === "detail-not-in-source");
  assert.deepEqual(det.checks, []); assert.equal(det.missed, 1, "no mechanical check exists for a detail no page states");
  assert.ok(r.mistakes.every((m) => m.examples.length >= 1 && m.lesson));
  assert.equal(report(cases, { top: 2 }).mistakes.length, 2);
  assert.deepEqual(report([]).mistakes, []);
});

test("lessons and the improver's form: short, ranked, with the measured share", () => {
  const r = report(cases), l = lessons(r, 3);
  assert.equal(l.length, 3); assert.match(l[0], /^ 1\. .+\(100% of corrections\)$/);
  const f = reportForImprover(r);
  assert.equal(f.corrected_pct, 50); assert.ok(f.mistakes[0].examples.includes("acme-breach-2026-11")); assert.ok(JSON.stringify(f).length < 6000);
  const m = evidenceFor("models.roles.researcher.max_turns", { evals: f });
  assert.equal(m.corrected_pct, 50); assert.equal(m.top_mistakes.length, 3); assert.equal(m.role[0].role, "researcher");
  assert.equal(evidenceFor("pipeline.sweep.researchers", { evals: f }).role, undefined);
  assert.equal(evidenceFor("pipeline.sweep.researchers", {}), null);
});

test("docs/jobs.md: the writers' most common corrections are the report's own lessons, at most 10 lines", () => {
  const md = readFileSync(join(ROOT, "docs", "jobs.md"), "utf8"), m = md.match(/\nTHE EVENT CHECKLIST, MOST COMMON CORRECTIONS[^\n]*\n((?: ?\d+\. [^\n]+\n)+)/);
  assert.ok(m, "the section is in the shared preamble, in the part event writers get (it starts THE EVENT CHECKLIST)");
  const lines = m[1].trim().split("\n");
  assert.ok(lines.length >= 5 && lines.length <= 10);
  for (const l of lines) assert.ok(MISTAKES.some((x) => l.replace(/^ ?\d+\. /, "").startsWith(x.lesson)), `not a lesson of MISTAKES: ${l.slice(0, 60)}`);
});

// ---------- propose-checks ----------
test("proposeChecks: every rule measured on corrected and passed records as written, and on the events on file", () => {
  const rows = proposeChecks(cases, [corrected, passedEv]);
  assert.equal(rows.length, Object.keys(PROPOSED_CODES).length + Object.keys(REJECTED).length);
  assert.ok(rows.findIndex((r) => !r.in_validate) >= Object.keys(PROPOSED_CODES).length, "the checks in validate.mjs come first");
  const occ = rows.find((r) => r.code === "occurred-round-hour");
  assert.deepEqual([occ.hits, occ.relevant, occ.false_alarms, occ.precision_pct, occ.recall_pct, occ.on_file_now], [1, 1, 0, 100, 100, 0]);
  assert.equal(occ.base_rate_pct, 50);
  const una = rows.find((r) => r.code === "summary-unattributed");
  assert.equal(una.hits, 1); assert.equal(una.relevant, 1);
  const rej = rows.find((r) => r.code === "action-part-unsourced");
  assert.equal(rej.in_validate, false); assert.equal(rej.hits, 1);
  assert.deepEqual(proposeChecks([], []).map((r) => r.precision_pct), rows.map(() => null));
});

// ---------- score ----------
test("scoreEvents: clean share, findings by code, agreement with the reviewed record", () => {
  const refs = refsFrom(cases);
  const base = scoreEvents([written, passedEv], { refs, now: NOW });
  assert.equal(base.events, 2); assert.equal(base.clean, 1); assert.equal(base.clean_pct, 50);
  assert.ok(base.by_code["occurred-round-hour"] === 1 && base.proposed["source-published-partial"] === 1);
  assert.equal(base.agreement.all_pct, 100, "the reviewer changed no date, severity, status, validation or tier");
  const better = scoreEvents([corrected, passedEv], { refs, now: NOW });
  assert.equal(better.clean_pct, 100); assert.ok(better.score > base.score);
  const worse = scoreEvents([{ ...written, date: "2026-11-22", validation: { state: "single_source" } }], { refs, now: NOW });
  assert.deepEqual([worse.agreement.date.same, worse.agreement.validation.same, worse.agreement.severity.same], [0, 0, 1]);
  assert.equal(worse.agreement.all_pct, 60);
  const none = scoreEvents([], {});
  assert.equal(none.score, null); assert.equal(none.agreement, null);
  assert.equal(scoreEvents([corrected], { now: NOW }).agreement, null, "no references, no agreement figure");
});

test("loadEvents: a folder, a list, one event, or a cases file (the records as written)", () => {
  const dir = mkdtempSync(join(tmpdir(), "cv-evals-"));
  try {
    mkdirSync(join(dir, "ev", "2026-11"), { recursive: true });
    const { id, ...body } = corrected;
    writeFileSync(join(dir, "ev", "2026-11", `${id}.json`), JSON.stringify(body));
    writeFileSync(join(dir, "list.json"), JSON.stringify([corrected, passedEv]));
    writeFileSync(join(dir, "cases.jsonl"), cases.map((c) => JSON.stringify(c)).join("\n") + "\n");
    assert.deepEqual(loadEvents(join(dir, "ev")).map((e) => e.id), ["acme-breach-2026-11"]);
    assert.equal(loadEvents(join(dir, "list.json")).length, 2);
    const fromCases = loadEvents(join(dir, "cases.jsonl"));
    assert.equal(fromCases.length, 2);
    assert.equal(fromCases.find((e) => e.id === "acme-breach-2026-11").title, written.title);
    assert.equal(scoreEvents(fromCases, { refs: refsFrom(cases), now: NOW }).clean_pct, 50, "scoring a cases file gives the baseline");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---------- history ----------
test("historyFromGit: every committed version of an event file, oldest first, in either layout", () => {
  const dir = mkdtempSync(join(tmpdir(), "cv-evals-git-"));
  const g = (...a) => { const r = spawnSync("git", a, { cwd: dir, encoding: "utf8", env: { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" } }); assert.equal(r.status, 0, r.stderr); };
  try {
    g("init", "-q", "-b", "data");
    mkdirSync(join(dir, "events", "2026-11"), { recursive: true });
    const f = join(dir, "events", "2026-11", "acme-breach-2026-11.json"), put = (e, date) => { const { id, ...b } = e; writeFileSync(f, JSON.stringify(b, null, 2)); g("add", "-A"); process.env.GIT_COMMITTER_DATE = date; g("commit", "-q", "-m", "data: test", "--date", date); };
    const keep = process.env.GIT_COMMITTER_DATE;
    put(written, "2026-11-22T08:05:00Z"); put(corrected, "2026-11-22T08:35:00Z");
    writeFileSync(join(dir, "events", "2026-11", "broken-event-2026-11.json"), "{ not json"); g("add", "-A"); g("commit", "-q", "-m", "data: broken");
    if (keep === undefined) delete process.env.GIT_COMMITTER_DATE; else process.env.GIT_COMMITTER_DATE = keep;
    const h = historyFromGit(dir, "HEAD");
    assert.deepEqual(Object.keys(h), ["acme-breach-2026-11"], "a version that does not parse is no version");
    assert.equal(h["acme-breach-2026-11"].length, 2);
    assert.equal(h["acme-breach-2026-11"][0].e.review, undefined); assert.equal(h["acme-breach-2026-11"][1].e.review.state, "corrected");
    const c = buildCases([corrected], h, writerIndex(logs), { now: NOW });
    assert.equal(c.length, 1); assert.equal(c[0].has_before, true); assert.ok(c[0].diff.some((x) => x.field === "summary"));
    assert.deepEqual(historyFromGit(dir, "no-such-ref"), {});
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("writerAt: the last writing run at or before the review; reviewers never count", () => {
  const idx = writerIndex(logs);
  assert.equal(writerAt(idx, "acme-breach-2026-11", "2026-11-22T08:30:00Z").role, "researcher");
  assert.equal(writerAt(idx, "acme-breach-2026-11", "2026-11-22T11:00:00Z").role, "updater");
  assert.equal(writerAt(idx, "nobody-knows", "2026-11-22T11:00:00Z").role, "unknown");
});
