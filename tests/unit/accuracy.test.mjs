// The accuracy checks of 21 November 2026 (scripts/lib/validate.mjs accuracyProblems) and the correction types the second
// review records (scripts/review.mjs ERROR_TYPES, errors). Run: node --test tests/unit/
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkEventQuality, countables, siteOf, ACCURACY_STRICT_FROM, QUALITY_STRICT_FROM } from "../../scripts/lib/validate.mjs";
import { classifyCorrection, errorReport, writersFrom, reviewRecord, passBlockers, ERROR_TYPES } from "../../scripts/review.mjs";

const A = "https://acme.example/news/security-notice", R = "https://reuters.example/tech/acme-breach-2026-11-22/";
const NEW = "2026-11-22T08:00:00Z", OLD = "2026-11-20T08:00:00Z";
const ev = (o = {}) => ({
  id: "acme-breach-2026-11", title: "Acme confirms breach of 1,200 customer records", date: "2026-11-21", category: "incident", severity: 2, status: "confirmed",
  org: "Acme", summary: "Acme said attackers copied 1,200 customer records on November 21. The company has notified regulators.", plain: "Acme says hackers copied customer records.",
  exec: "Customer data exposure.", action: "Acme advises customers to reset their passwords.", tags: ["data-breach"], cves: [],
  sources: [{ name: "Acme", url: A, published: "2026-11-22" }, { name: "Reuters", url: R, published: "2026-11-22" }],
  evidence: [{ url: A, quote: "On 21 November attackers copied 1,200 customer records from our web shop." }],
  source_tier: "primary", validation: { state: "corroborated", note: "Acme's notice and Reuters each state it" }, first_seen: NEW, updated_at: NEW, ...o,
});
const NOW = { now: Date.parse("2026-11-23T00:00:00Z") };
const find = (e, code) => checkEventQuality(e, NOW).find((x) => x.code === code);
const level = (e, code) => (find(e, code) || {}).level;

test("the strict date is after the first quality cut-off, and a clean new event passes every accuracy check", () => {
  assert.ok(ACCURACY_STRICT_FROM > QUALITY_STRICT_FROM);
  assert.deepEqual(checkEventQuality(ev(), NOW), []);
});

test("countables: counts, money, percentages and durations; never years, versions, CVEs, CVSS scores, dates or times", () => {
  assert.deepEqual(countables("about 400 partner environments").map((f) => [f.value, f.q]), [[400, "about"]]);
  assert.deepEqual(countables("over 125 million SMS").map((f) => [f.value, f.q]), [[125e6, "above"]]);
  assert.deepEqual(countables("8.83M records and 40% of firms").map((f) => [f.value, f.pct]), [[8830000, false], [40, true]]);
  assert.deepEqual(countables("CVSS 9.8, version 6.1.4, CVE-2026-12345, Windows 11, in 2024, on 17 Nov at 09:46, 5 hosts"), []);
});

test("figure-no-evidence: every figure needs a quote that states it (error for new events, warning for older ones with evidence, nothing for older ones without)", () => {
  assert.equal(level(ev({ evidence: [] }), "figure-no-evidence"), "error");
  assert.equal(level(ev({ evidence: undefined }), "figure-no-evidence"), "error");
  assert.equal(level(ev({ first_seen: OLD, updated_at: OLD, evidence: [{ url: A, quote: "Records were copied." }] }), "figure-no-evidence"), "warn");
  assert.equal(find(ev({ first_seen: OLD, updated_at: OLD, evidence: undefined }), "figure-no-evidence"), undefined);
  assert.equal(level(ev({ records_affected: 5000 }), "figure-no-evidence"), "error", "records_affected is a figure too");
  assert.equal(find(ev({ title: "Acme confirms breach", summary: "Acme said attackers copied customer records.", evidence: [] }), "figure-no-evidence"), undefined, "no figure, no quote needed");
  // plain may round with "about"
  assert.equal(find(ev({ plain: "Acme says hackers copied about 1,190 customer records." }), "figure-no-evidence"), undefined);
});

test("figure-qualifier: the page's own qualifier in every field", () => {
  const e = ev({ evidence: [{ url: A, quote: "attackers copied more than 1,200 customer records" }] });
  assert.equal(level(e, "figure-qualifier"), "error", "the page says more than 1,200; the record says 1,200");
  assert.equal(find(ev({ title: "Acme confirms breach of more than 1,200 customer records", summary: "Acme said attackers copied more than 1,200 customer records.", evidence: [{ url: A, quote: "more than 1,200 customer records" }] }), "figure-qualifier"), undefined);
});

test("evidence: shape, and every quote from a page in sources", () => {
  assert.equal(level(ev({ evidence: [{ url: A, quote: "x".repeat(241) }] }), "evidence-shape"), "error");
  assert.equal(level(ev({ evidence: "1,200" }), "evidence-shape"), "error");
  assert.equal(level(ev({ evidence: [{ url: "https://other.example/a", quote: "1,200 customer records" }] }), "evidence-unsourced"), "error");
});

test("occurred-no-evidence: a stated time of day is quoted; approx needs no quote", () => {
  assert.equal(level(ev({ occurred_at: "2026-11-21T09:46:00Z", time_basis: "occurred" }), "occurred-no-evidence"), "error");
  assert.equal(find(ev({ occurred_at: "2026-11-21T09:46:00Z", time_basis: "occurred", evidence: [{ url: A, quote: "copied 1,200 customer records at 9:46 a.m." }] }), "occurred-no-evidence"), undefined);
  assert.equal(find(ev({ occurred_at: "2026-11-21T09:00:00Z", time_basis: "approx" }), "occurred-no-evidence"), undefined);
});

test("action-unsourced: the action names whose advice it is, or is marked as CyberView's general advice", () => {
  assert.equal(level(ev({ action: "Reset passwords and enable MFA." }), "action-unsourced"), "error");
  assert.equal(level(ev({ first_seen: OLD, updated_at: OLD, evidence: undefined, action: "Reset passwords and enable MFA." }), "action-unsourced"), "warn");
  for (const a of ["General advice: reset reused passwords and watch for phishing.", "No action needed; for awareness.", "Acme urges customers to reset passwords.", "Apply the vendor's fix in 6.1.6 (advisory GHSA-qc22-rmgc-vg94).", "Treat unexpected calls with caution, as the notice advises."])
    assert.equal(find(ev({ action: a }), "action-unsourced"), undefined, a);
});

test("corroborated: two publishers on two sites, and the note names them", () => {
  const same = [{ name: "Example News", url: "https://news.example.com/a", published: "2026-11-22" }, { name: "Example", url: "https://www.example.com/b" }];
  assert.equal(siteOf("https://news.bbc.co.uk/x"), "bbc.co.uk");
  assert.equal(level(ev({ source_tier: "established", sources: same, evidence: [{ url: same[0].url, quote: "1,200 customer records" }] }), "corroborated-one-site"), "error");
  assert.equal(level(ev({ validation: { state: "corroborated", note: "two outlets" } }), "corroborated-note"), "warn");
});

test("primary-no-primary: a primary tier needs the organisation's, vendor's or an authority's own page", () => {
  const news = [{ name: "Reuters", url: R, published: "2026-11-22" }, { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/news/security/acme/", published: "2026-11-22" }];
  assert.equal(level(ev({ sources: news, evidence: [{ url: R, quote: "1,200 customer records" }] }), "primary-no-primary"), "error");
  assert.equal(find(ev(), "primary-no-primary"), undefined, "acme.example is the organisation's own site");
  assert.equal(find(ev({ sources: [{ name: "CISA", url: "https://www.cisa.gov/news/x", published: "2026-11-22" }, news[0]], evidence: [{ url: R, quote: "1,200 customer records" }] }), "primary-no-primary"), undefined);
});

test("claim-title: a claim says it is a claim", () => {
  const c = { status: "claimed", severity: 1, validation: { state: "unconfirmed_claim" } };
  assert.equal(level(ev({ ...c, title: "Acme hit by ransomware" }), "claim-title"), "error");
  assert.equal(find(ev({ ...c, title: "Qilin claims attack on Acme" }), "claim-title"), undefined);
});

test("date-is-publication and source-published-missing: an incident's date is not just its article's day", () => {
  assert.equal(level(ev({ date: "2026-11-22" }), "date-is-publication"), "error");
  assert.equal(find(ev({ date: "2026-11-22", date_note: "The notice of 22 November gives no earlier day." }), "date-is-publication"), undefined);
  assert.equal(find(ev({ date: "2026-11-22", time_basis: "occurred" }), "date-is-publication"), undefined);
  assert.equal(find(ev({ date: "2026-11-22", category: "vuln" }), "date-is-publication"), undefined, "a release or advisory is dated by its publication");
  assert.equal(level(ev({ sources: [{ name: "Acme", url: A }, { name: "Reuters", url: R }] }), "source-published-missing"), "error");
  assert.equal(find(ev({ first_seen: OLD, updated_at: OLD, evidence: undefined, sources: [{ name: "Acme", url: A }, { name: "Reuters", url: R }] }), "source-published-missing"), undefined);
  assert.equal(level(ev({ sources: [{ name: "Acme", url: A, published: "22 Nov" }, { name: "Reuters", url: R }] }), "source-published-shape"), "error");
});

test("classifyCorrection reads the error types from real review notes, ignoring what only matched", () => {
  const has = (note, k) => assert.ok(classifyCorrection(note).includes(k), `${k} in: ${note} -> ${classifyCorrection(note)}`);
  has("Roundup says 'over 125 million' SMS; record said about 125 million; fixed in impact, plain, summary.", "figure");
  has("Removed unsourced action detail and 'attacks likely soon' wording.", "action");
  has("Date was 17 Nov (publication); The Record and heise say he pleaded guilty on Monday, so date is now 2026-11-16 with date_note", "date");
  has("Removed occurred_at 08:00Z, a time the page does not state.", "occurred_at");
  has("Validation said corroborated but only Ynetnews is a source; now single_source.", "validation");
  has("Source says third party 'may have' accessed; summary and plain now say so", "overstated");
  has("Same event and same Talk Business source as fort-smith-2026-11; marked duplicate_of the earlier record.", "duplicate");
  assert.ok(!classifyCorrection("Figures match HIPAA Journal and the notice; dates match.").includes("figure"), "a note that only lists what matched is not a figure error");
  assert.deepEqual(classifyCorrection(""), []);
  assert.ok(ERROR_TYPES.every((t) => t.key && t.label && Array.isArray(t.checks)));
});

test("reviewRecord keeps the correction's types; passBlockers holds new events to the accuracy checks", () => {
  assert.deepEqual(reviewRecord(null, "corrected", "2026-11-22T10:00:00Z", "Removed unsourced action advice.", []).categories, ["unsourced", "action"]);
  assert.equal(reviewRecord(null, "passed", "2026-11-22T10:00:00Z", "checked", []).categories, undefined);
  assert.deepEqual(passBlockers(["action-unsourced", "figure-no-evidence", "number-check"]), []);
  assert.deepEqual(passBlockers(["action-unsourced", "figure-no-evidence", "number-check"], true), ["action-unsourced", "figure-no-evidence"]);
});

test("errors: corrections counted by type and by the role and model that wrote the event", () => {
  const logs = [
    { at: "2026-11-22T10:00:00Z", job: "sweep-r1", model: "claude-sonnet-5-5", added: ["a-2026-11", "b-2026-11"] },
    { at: "2026-11-22T10:05:00Z", job: "sweep-r2", worker_role: "researcher-deep", worker_model: "opus", added: [{ id: "c-2026-11" }] },
    { at: "2026-11-22T11:00:00Z", job: "update-u1", model: null, updated: ["a-2026-11"] },
  ];
  const w = writersFrom(logs);
  assert.deepEqual([w.get("a-2026-11").role, w.get("b-2026-11").role, w.get("c-2026-11").role, w.get("c-2026-11").model], ["updater", "researcher", "researcher-deep", "opus"]);
  assert.equal(w.get("b-2026-11").model, "sonnet");
  const at = "2026-11-22T12:00:00Z", events = [
    { id: "a-2026-11", review: { state: "corrected", at, note: "Removed unsourced action advice." } },
    { id: "b-2026-11", review: { state: "corrected", at, note: "x", categories: ["figure"] } },
    { id: "c-2026-11", review: { state: "passed", at, note: "ok" } },
    { id: "d-2026-11", review: { state: "flagged", at: "2026-10-01T00:00:00Z", note: "too old" } },
  ];
  const r = errorReport(events, w, Date.parse("2026-11-23T00:00:00Z"), 7);
  assert.deepEqual([r.reviewed, r.corrected, r.flagged, r.corrected_pct], [3, 2, 0, 66.7]);
  assert.deepEqual(r.types.map((t) => [t.key, t.n]), [["unsourced", 1], ["action", 1], ["figure", 1]]);
  const deep = r.by_writer.find((b) => b.role === "researcher-deep");
  assert.deepEqual([deep.model, deep.reviewed, deep.corrected, deep.corrected_pct], ["opus", 1, 0, 0]);
});
