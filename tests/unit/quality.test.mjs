import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { categorise, problemClauses, unreachableOnly, report, CATEGORIES } from "../../scripts/quality.mjs";

// real second-review notes from 19-20 November 2026 (data/events/2026-11/*.json, review.note)
const has = (note, k) => categorise(note).includes(k);

test("match-only clauses are dropped; clauses that say what was wrong are kept", () => {
  const c = problemClauses("Compared with HIPAA Journal (13 Nov): Aug 10-12 window, data types, Dire Wolf via VenariX correct; added the 58,249 figure to the summary");
  assert.deepEqual(c, ["added the 58,249 figure to the summary"]);
  assert.deepEqual(problemClauses("Dates, 82,574 and 80,061 figures, data types match HIPAA Journal."), []);
});

test("wording stronger than the source", () => {
  assert.ok(has("ASX statement, ACSC, normal operations, no evidence of data taken match iTnews and InDaily; 'containing' not in sources, changed to 'investigating'", "wording"));
  assert.ok(has("Checked against ABC News 4: dates, data removed, SLED, no actor match; exec said data theft, stronger than removed, reworded", "wording"));
  assert.ok(has("Summary claimed decision came four days before a United outage; The Record (12 Nov) does not mention an outage.", "wording"));
});

test("figures and version ranges", () => {
  assert.ok(has("Roundup says 'over 125 million' SMS; record said about 125 million; fixed in impact, plain, summary.", "figure"));
  assert.ok(has("Noovo says nearly 2,500 accounts, Narcity quotes more than 2,500 connections; summary now states both", "figure"));
  assert.ok(has("Versions match NCSC NZ alert; Javassist range is 3.13.0-GA to 3.31.x, not before 3.32.0-GA; action fixed", "figure"));
  assert.ok(!has("Dates, 82,574 and 80,061 figures, data types match HIPAA Journal; exec's incomplete remediation was unsupported (article says unclear if related), reworded", "figure"));
});

test("dates and times", () => {
  assert.ok(has("Date was 17 Nov (publication); The Record and heise (both 17 Nov) say he pleaded guilty on Monday, so date is now 2026-11-16 with date_note; correction file added.", "date"));
  assert.ok(has("Checked BleepingComputer, Wiz, Socket, ITmedia: versions match. Fixed occurred_at from placeholder 12:00Z to 20:35Z (Wiz: 1.26.1 published 20:35 UTC).", "date"));
  assert.ok(has("Compared with heise, Euronews: Sysper re-crash was Wednesday 18 Nov not 19 Nov (fixed)", "date"));
});

test("attribution, status, tier, absence, tags, duplicates", () => {
  assert.ok(has("Summary did not say the FBI attributes the activity; now states FBI attribution; figures checked against FLASH PDF", "unattributed"));
  assert.ok(has("Validation said corroborated but only Ynetnews is a source; now single_source.", "status"));
  assert.ok(has("Added BleepingComputer (15 Nov; TSMC SEC filing). Summary reworded to match; source tier raised to established since the tracker alone was aggregator.", "tier"));
  assert.ok(has("Facts match BleepingComputer and RTE; exec wrongly said supplier made no public statement, now says its notices state it lacks logs", "absence"));
  assert.ok(has("Facts match ReversingLabs and Help Net Security; removed supply-chain tag as source states no supply-chain compromise", "tags"));
  assert.ok(has("Same event and same sources as sbc-medical-group-customer-data-2026-11 (reviewed earlier); marked duplicate_of the earlier record.", "duplicate"));
  assert.deepEqual(categorise("Securelist matches: 18 Nov, audit and consulting fee, C++ to Rust, v5.2.8."), ["other"]);
});

test("source unreachable is counted on its own", () => {
  for (const n of ["Source unreachable: both City of Osaka press releases return HTTP 408 after retries", "Kaspersky ICS CERT report unreachable (ECONNRESET twice); only The Hacker News read.", "MLex source returned 403. eSecurityPlanet gives apology Nov 12", "AWS Security Blog (primary) returned only site navigation after retry"])
    assert.ok(has(n, "unreachable"), n);
  assert.ok(!has("Compared with ESET: 403 records match", "unreachable"));
  assert.ok(unreachableOnly({ state: "flagged", note: "source unreachable: redpacketsecurity.com returned 403; it is the only source" }));
  assert.ok(!unreachableOnly({ state: "corrected", note: "Censor.net 403 so validation downgraded to single_source" }));
});

test("report: windows, rates, unreachable left out of the quality rate, corrections joined by event", () => {
  const now = Date.parse("2026-11-20T12:00:00Z");
  const ev = (id, state, at, note) => ({ id, review: { state, at, note } });
  const events = [
    ev("a", "passed", "2026-11-19T10:00:00Z", "fine"), ev("b", "corrected", "2026-11-19T11:00:00Z", "Validation said corroborated but only one site; now single_source"),
    ev("c", "flagged", "2026-11-18T11:00:00Z", "Source unreachable: returned 403"), ev("d", "passed", "2026-11-18T09:00:00Z", "ok"),
    ev("e", "corrected", "2026-11-10T09:00:00Z", "removed supply-chain tag"), ev("f", "passed", "2026-11-09T09:00:00Z", "ok"), { id: "g" },
  ];
  const r = report(events, [{ event_id: "b", title: "x", what_changed: "date moved from Nov 16 to Nov 13", at: "2026-11-19T11:00:00Z" }, { event_id: "zz", title: "Figure fixed", what_changed: "count was 1,200 not 12,000", at: "2026-11-19T01:00:00Z" }], { days: 7, now });
  assert.equal(r.this_week.reviews, 4); assert.equal(r.this_week.corrected, 1); assert.equal(r.this_week.flagged_unreachable, 1);
  assert.equal(r.this_week.corrected_pct, 25); assert.equal(r.this_week.corrected_or_flagged_pct, 33.3);
  assert.equal(r.previous_week.reviews, 2); assert.equal(r.previous_week.corrected_pct, 50);
  const cat = (k) => r.categories.find((c) => c.key === k);
  assert.equal(cat("status").this_week, 1); assert.equal(cat("date").this_week, 1); assert.equal(cat("tags").previous_week, 1);
  assert.equal(r.other_corrections.count, 1); assert.equal(r.other_corrections.cats.figure, 1);
  assert.deepEqual(r.no_automatic_check, CATEGORIES.filter((c) => !c.checks.length).map((c) => c.key));
  assert.equal(r.daily.length, 4);
});

test("every automatic check named in the categories exists in validate.mjs or review.mjs", () => {
  const src = readFileSync(new URL("../../scripts/lib/validate.mjs", import.meta.url), "utf8") + readFileSync(new URL("../../scripts/review.mjs", import.meta.url), "utf8");
  for (const c of CATEGORIES) for (const code of c.checks) assert.ok(src.includes(`"${code}"`), `${c.key}: ${code}`);
});
