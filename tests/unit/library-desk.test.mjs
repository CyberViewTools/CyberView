// The Library desk runner (scripts/library-desk.mjs): the plan (pilot first, backlog only when the owner switches it on, never while the
// pipeline needs the window), the pilot set and its completion predicate, the budget-bound stage loop, the pilot report, the
// efficiency block, and the config, routine, heartbeat and health checks that go with it. No model, no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, plan, selectPilot, pilotSha1s, pilotKeys, pilotLoose, pilotComplete, loadPilot, savePilot, addLoose, backfillOrder, deskState, runStages, pilotReport, libraryBlock, deskConfig, reserveMs, DESK_DEFAULTS } from "../../scripts/library-desk.mjs";
import { STAGES } from "../../scripts/lib/stages.mjs";
import { libraryProblems, THRESHOLD } from "../../scripts/pipecheck.mjs";
import { PAUSE_NOTICE } from "../../scripts/lib/library-audit.mjs";

const ROOT = join(import.meta.dirname, "..", "..");
const rj = (f) => JSON.parse(readFileSync(join(ROOT, f), "utf8"));
const hx = (n) => n.toString(16).padStart(40, "0");
const CFG = { ...DESK_DEFAULTS };
const STATE = { pilotDone: false, paused: false, failedCards: 0, pilot: { read: 100, write: 8 }, newRecords: 0, backlog: 0, writeNew: 0, writeBacklog: 0, drafts: 10, auditable: 10 };

/* ---------- plan ---------- */
test("plan: the pipeline's window comes first", () => {
  const p = plan(STATE, CFG, false);
  assert.equal(p.mode, "wait"); assert.deepEqual([p.read, p.write, p.review, p.audit], [0, 0, 0, 0]);
});
test("plan: library.enabled false is the same as waiting", () => {
  const p = plan(STATE, { ...CFG, enabled: false }, true);
  assert.equal(p.mode, "wait"); assert.equal(p.read + p.write + p.review + p.audit, 0);
});
test("plan: the pilot is limited to the pilot set and audits every card", () => {
  const p = plan({ ...STATE, backlog: 29000, newRecords: 5, writeBacklog: 900 }, CFG, true);
  assert.equal(p.mode, "pilot");
  assert.equal(p.read, 40); assert.equal(p.write, 6); assert.equal(p.review, 6); assert.equal(p.audit, 4); assert.equal(p.auditPct, 100);
  const small = plan({ ...STATE, pilot: { read: 7, write: 2 }, drafts: 1, auditable: 3 }, CFG, true);
  assert.deepEqual([small.read, small.write, small.review, small.audit], [7, 2, 1, 3]);
});
test("plan: with backfill off, a finished pilot never touches the backlog", () => {
  const p = plan({ ...STATE, pilotDone: true, newRecords: 3, backlog: 29000, writeNew: 2, writeBacklog: 5000 }, { ...CFG, backfill: false }, true);
  assert.equal(p.mode, "steady"); assert.equal(p.read, 3); assert.equal(p.write, 2); assert.equal(p.auditPct, CFG.audit_pct);
  const idle = plan({ ...STATE, pilotDone: true, backlog: 29000, writeBacklog: 5000 }, CFG, true);
  assert.equal(idle.read, 0); assert.equal(idle.write, 0);
});
test("plan: backfill reads and writes the backlog too, a wave at a time", () => {
  const p = plan({ ...STATE, pilotDone: true, newRecords: 3, backlog: 29000, writeNew: 2, writeBacklog: 5000 }, { ...CFG, backfill: true }, true);
  assert.equal(p.mode, "backfill"); assert.equal(p.read, 40); assert.equal(p.write, 6);
  assert.equal(plan({ ...STATE, pilotDone: true, newRecords: 3, backlog: 4 }, { ...CFG, backfill: true }, true).read, 7);
});
test("plan: a backfill switch cannot skip the pilot", () => {
  assert.equal(plan({ ...STATE, pilotDone: false, backlog: 29000 }, { ...CFG, backfill: true }, true).mode, "pilot");
});
test("plan: while paused only the failed cards are read again, the audit runs at its wave size, nothing is written or reviewed", () => {
  const p = plan({ ...STATE, pilotDone: true, paused: true, failedCards: 3, newRecords: 50, writeNew: 9, drafts: 4, auditable: 9 }, CFG, true);
  assert.equal(p.read, 3); assert.equal(p.write, 0); assert.equal(p.review, 0); assert.equal(p.audit, 4); assert.equal(p.auditPct, 100);
});

/* ---------- the pilot set ---------- */
// 12 actors: A0..A11. Actor i has i reports (A0 none), so A11 and A10 are the biggest. Report ids are increasing with time.
function world(nReports = 300) {
  const actors = Array.from({ length: 20 }, (_, i) => ({ id: 100 + i, name: `Actor ${String.fromCharCode(65 + i)}`, aliases: [] }));
  const reports = [];
  for (let n = 0; n < nReports; n++) reports.push({ sha1: hx(n + 1), created: "", actors: [] });
  // report n is one day newer than report n-1
  reports.forEach((r, n) => { r.created = new Date(Date.UTC(2020, 0, 1) + n * 864e5).toISOString(); });
  return { actors, reports };
}
function withActors(w) {
  // the OLDEST reports belong to actors, biggest first: Actor L (i = 11) has 60 (indexes 0..59), K 50 (60..109), then 9, 8 ... 1
  let n = 0;
  for (let i = 11; i >= 1; i--) for (let k = 0; k < (i === 11 ? 60 : i === 10 ? 50 : i); k++) w.reports[n++].actors = [w.actors[i].name];
  return w;
}
const AT = "2026-11-26T00:00:00Z";
const PCFG = { reports: 200, top_actors: 10, thin_actors: 5, loose: 5 };

test("selectPilot: the 200 newest reports plus the top actors' reports (40 per actor, newest first), and 10 + 5 actors", () => {
  const w = withActors(world());
  const p = selectPilot(w.reports, w.actors, PCFG, AT);
  assert.equal(p.version, 1); assert.equal(p.chosen_at, AT);
  assert.equal(p.newest.length, 200);
  assert.deepEqual(p.newest.slice(0, 2), [hx(300), hx(299)]);
  const top = p.actors.filter((a) => a.group === "top"), thin = p.actors.filter((a) => a.group === "thin");
  assert.equal(top.length, 10); assert.equal(thin.length, 5);
  assert.deepEqual(top.slice(0, 2).map((a) => a.name), ["Actor L", "Actor K"]);
  // the newest 200 are indexes 100..299. L is capped at its 40 newest (20..59: 40 outside), K at 70..109 (70..99: 30 outside), the rest are inside
  assert.equal(p.extra.length, 70); assert.equal(p.counts.top_extra, 70);
  assert.equal(pilotSha1s(p).length, 270); assert.equal(p.counts.reports, 270);
  assert.equal(new Set(pilotSha1s(p)).size, 270);
  assert.ok(p.extra.includes(hx(60)) && !p.extra.includes(hx(20)), "Actor L: its 40 newest reports (indexes 20..59), not the oldest 20");
  assert.equal(p.newest_at, w.reports[299].created);
});
test("selectPilot: thin actors prefer one-report actors whose report is in the newest 200, then no-report actors, by name", () => {
  const w = world();
  // actors 1..3 have one report each: actor 1's is in the newest 200, 2's is old, 3's is in the newest 200; 4 and 5 have none
  w.reports[299].actors = [w.actors[3].name]; w.reports[250].actors = [w.actors[1].name]; w.reports[3].actors = [w.actors[2].name];
  for (let i = 6; i < 12; i++) for (let k = 0; k < 5 + i; k++) w.reports[20 + (i - 6) * 30 + k].actors = [w.actors[i].name];   // 6..11 are the busy ones
  const p = selectPilot(w.reports, w.actors, { ...PCFG, top_actors: 6, thin_actors: 5 }, AT);
  assert.deepEqual(p.actors.filter((a) => a.group === "top").map((a) => a.name).sort(), ["Actor G", "Actor H", "Actor I", "Actor J", "Actor K", "Actor L"]);
  const thin = p.actors.filter((a) => a.group === "thin").map((a) => a.name);
  assert.deepEqual(thin, ["Actor B", "Actor D", "Actor A", "Actor E", "Actor F"], "Actor C's only report is old, so it comes after the one-report ones in the 200 and the no-report ones");
  assert.deepEqual(selectPilot(w.reports, w.actors, { ...PCFG, top_actors: 6 }, "later").actors, selectPilot(w.reports, w.actors, { ...PCFG, top_actors: 6 }, AT).actors, "deterministic");
});
test("pilotKeys: actors then loose subjects", () => {
  const p = { actors: [{ key: "a-1", group: "top" }, { key: "a-2", group: "thin" }], loose: [{ key: "s-9", name: "X" }] };
  assert.deepEqual(pilotKeys(p), ["a-1", "a-2", "s-9"]);
});

const card = (sha, o = {}) => ({ sha1: sha, status: "read", kind: "malware-analysis", summary: "s", read_at: "2026-11-26T01:00:00Z", model: "haiku", facts: { tools: [{ v: "A", q: "q" }, { v: "B", q: "q" }, { v: "C", q: "q" }], techniques: [], sectors: [], countries: [], dates: [], cves: [], actors: [], figures: [] }, subject: { type: "malware", name: "BadThing" }, ...o });
const audited = (c) => ({ ...c, audit: { at: "2026-11-26T02:00:00Z", ok: true, note: "", by: "auditor" } });

test("pilotLoose: waits for the newest 200 to be read, then picks the loose subjects with most reports, additively", () => {
  const w = world(20);
  const p = selectPilot(w.reports, w.actors, { ...PCFG, reports: 10, top_actors: 0, thin_actors: 0 }, AT);
  const cards = new Map(); for (const s of p.newest.slice(0, 5)) cards.set(s, card(s));
  assert.deepEqual(pilotLoose(p, w.reports, w.actors, cards, 5), [], "not every pilot card is resolved yet");
  for (const s of p.newest) cards.set(s, card(s));
  const got = pilotLoose(p, w.reports, w.actors, cards, 5);
  assert.equal(got.length, 1); assert.equal(got[0].name, "BadThing"); assert.match(got[0].key, /^s-/);
  assert.deepEqual(pilotLoose({ ...p, loose: got }, w.reports, w.actors, cards, 5), [], "already chosen: nothing more");
});

test("pilotComplete: every report resolved, every read card audited by the auditor, every pilot subject published or parked", () => {
  const p = { newest: [hx(1), hx(2), hx(3)], extra: [], actors: [{ key: "a-1" }], loose: [{ key: "s-1" }] };
  const cards = new Map([[hx(1), audited(card(hx(1)))], [hx(2), { sha1: hx(2), status: "no-text" }], [hx(3), { sha1: hx(3), status: "unread", tries: 2 }]]);
  const live = (s) => ({ live: { status: s }, next: null });
  const stories = new Map([["a-1", live("published")], ["s-1", { live: null, next: { status: "parked" } }]]);
  assert.equal(pilotComplete(p, cards, stories).done, true);
  const no = (c, s) => pilotComplete(p, c, s);
  assert.equal(no(new Map([...cards, [hx(3), { sha1: hx(3), status: "unread", tries: 1 }]]), stories).done, false, "an unread card with tries left");
  assert.equal(no(new Map([...cards].filter(([k]) => k !== hx(2))), stories).done, false, "a missing card");
  assert.equal(no(new Map([...cards, [hx(1), card(hx(1))]]), stories).done, false, "a read card with no audit");
  assert.equal(no(new Map([...cards, [hx(1), { ...card(hx(1)), audit: { ok: true, by: "reviewer" } }]]), stories).done, false, "a reviewer's flag is not an auditor verdict");
  assert.equal(no(cards, new Map([["a-1", live("published")]])).done, false, "no story for a loose subject");
  assert.equal(no(cards, new Map([["a-1", live("stale")], ["s-1", { live: null, next: { status: "parked" } }]])).done, false, "a stale story");
  assert.equal(no(cards, new Map([["a-1", { live: null, next: { status: "draft" } }], ["s-1", live("published")]])).done, false, "a draft is not published");
  assert.ok(no(cards, new Map()).why.length > 0);
});

test("pilot.json: chosen once and kept; loose subjects are added, never dropped; an unreadable file is never overwritten", () => {
  const dir = mkdtempSync(join(tmpdir(), "pilot-")), f = join(dir, "pilot.json");
  try {
    assert.equal(loadPilot(f).state, "none");
    const w = withActors(world());
    const p = selectPilot(w.reports, w.actors, PCFG, AT);
    assert.equal(savePilot(f, p), true);
    const again = loadPilot(f); assert.equal(again.state, "ok"); assert.deepEqual(again.pilot.newest, p.newest);
    assert.equal(savePilot(f, { ...p, chosen_at: "other" }), false, "an existing pilot is not replaced");
    assert.equal(loadPilot(f).pilot.chosen_at, AT);
    addLoose(f, [{ key: "s-1", name: "One" }]); addLoose(f, [{ key: "s-2", name: "Two" }, { key: "s-1", name: "One" }]);
    assert.deepEqual(loadPilot(f).pilot.loose.map((x) => x.key), ["s-1", "s-2"]);
    assert.equal(loadPilot(f).pilot.counts.loose, 2);
    writeFileSync(f, "{ not json");
    assert.equal(loadPilot(f).state, "bad");
    assert.equal(savePilot(f, p), false); assert.equal(readFileSync(f, "utf8"), "{ not json");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

/* ---------- backfill order ---------- */
test("backfillOrder: reports of actors by actor report count first, then the rest newest first", () => {
  const w = world(30);
  w.reports[5].actors = [w.actors[1].name];                                              // actor B: 1 report (old)
  w.reports[6].actors = [w.actors[2].name]; w.reports[7].actors = [w.actors[2].name]; w.reports[8].actors = [w.actors[2].name];   // actor C: 3
  const order = backfillOrder(w.reports, w.actors);
  assert.deepEqual(order.slice(0, 6), [hx(9), hx(8), hx(7), hx(6), hx(30), hx(29)], "actor C (3 reports) first, then B (1), then the rest newest first");
});

/* ---------- desk state ---------- */
test("deskState: counts the pilot's work and keeps the backlog apart; orders carry the pilot first", () => {
  const w = withActors(world());
  const pilot = selectPilot(w.reports, w.actors, PCFG, AT);
  const cards = new Map(pilotSha1s(pilot).slice(0, 30).map((s) => [s, audited(card(s))]));
  const { state, orders } = deskState({ reports: w.reports, actors: w.actors, cards, stories: new Map(), pilot, cfg: CFG });
  assert.equal(state.pilotDone, false);
  assert.equal(state.pilot.read, 240);                       // 270 pilot reports, 30 read
  assert.equal(state.backlog, 30);                           // the 30 reports outside the pilot are the backlog
  assert.equal(state.newRecords, 0);
  assert.equal(orders.read.length, 240); assert.ok(orders.write.every((k) => pilotKeys(pilot).includes(k)));
  assert.ok(state.pilot.write >= 15, "the 15 pilot actors have no story yet");
});
test("deskState: a report newer than the pilot's newest is a new record; a finished pilot reads only those in steady mode", () => {
  const w = world(10);
  const pilot = selectPilot(w.reports, w.actors, { ...PCFG, reports: 10, top_actors: 0, thin_actors: 0 }, AT);
  const cards = new Map(w.reports.map((r) => [r.sha1, audited(card(r.sha1))]));
  const fresh = { sha1: hx(999), created: "2030-01-01T00:00:00Z", actors: [] };
  const { state, orders } = deskState({ reports: [...w.reports, fresh], actors: [], cards, stories: new Map(), pilot: { ...pilot, actors: [], loose: [] }, cfg: CFG });
  assert.equal(state.pilotDone, true); assert.equal(state.newRecords, 1); assert.equal(state.backlog, 0);
  assert.deepEqual(orders.read, [hx(999)]);
});

/* ---------- the stage loop ---------- */
test("runStages: review, audit, write, read in that order; each in waves; stops with the time left for the role", async () => {
  const calls = []; let t = 0;
  const deps = {
    review: async ({ max }) => { calls.push(["review", max]); t += 100000; return { published: max, stopped: "" }; },
    audit: async ({ max, pilot }) => { calls.push(["audit", max, pilot]); t += 60000; return { ok: max, wrong: 0, stopped: "" }; },
    write: async ({ max, order }) => { calls.push(["write", max, order]); t += 100000; return { drafted: max, stopped: "" }; },
    read: async ({ max, order }) => { calls.push(["read", max, order]); t += 20000; return { read: max, stopped: "" }; },
  };
  const orders = { read: Array.from({ length: 10 }, (_, i) => hx(i + 1)), write: ["a-1", "a-2", "a-3", "a-4", "a-5", "a-6"] };
  const out = await runStages({ plan: { read: 10, write: 6, review: 4, audit: 4, auditPct: 100, mode: "pilot" }, orders, deps, now: () => t, deadline: 1e9, chunk: { review: 2, audit: 2, write: 3, read: 4 }, pilot: true, log: () => {} });
  assert.deepEqual(calls.map((c) => c[0]), ["review", "review", "audit", "audit", "write", "write", "read", "read", "read"]);
  assert.deepEqual(calls.filter((c) => c[0] === "audit").map((c) => c[2]), [true, true], "the audit is told it is the pilot");
  assert.deepEqual(calls.filter((c) => c[0] === "read").map((c) => c[1]), [4, 4, 2]);
  assert.deepEqual(calls.filter((c) => c[0] === "read")[1][2], orders.read.slice(4), "what was tried is not listed again");
  assert.equal(out.review.done, 4); assert.equal(out.read.done, 10);
});
test("runStages: nothing starts without the time for the role, and a stage with no progress or a stop ends", async () => {
  const calls = []; let t = 0;
  const deps = { review: async () => { calls.push("review"); return { published: 0, corrected: 0, rejected: 0, parked: 0, cardsFlagged: 0, stopped: "" }; },
    audit: async () => { calls.push("audit"); return { ok: 1, wrong: 0, stopped: "usage limit" }; }, write: async () => { calls.push("write"); return { drafted: 1, stopped: "" }; }, read: async () => { calls.push("read"); return { read: 1, stopped: "" }; } };
  const p = { read: 4, write: 4, review: 4, audit: 4, mode: "steady" };
  await runStages({ plan: { ...p, read: 2 }, orders: { read: [], write: [] }, deps, now: () => t, deadline: reserveMs("library-writer") - 1, chunk: { review: 2, audit: 2, write: 2, read: 2 }, log: () => {} });
  assert.deepEqual(calls, ["read"], "only the reader (a shorter reserve) still fits");
  calls.length = 0;
  await runStages({ plan: p, orders: { read: [], write: [] }, deps, now: () => t, deadline: 1e9, chunk: { review: 2, audit: 2, write: 2, read: 2 }, log: () => {} });
  assert.deepEqual(calls, ["review", "audit", "write", "write", "read", "read"], "review made no progress; the audit stopped on a usage limit");
});
test("runStages: a stage that throws does not stop the others", async () => {
  const calls = [];
  const deps = { review: async () => { throw new Error("boom"); }, audit: async () => ({ ok: 1, stopped: "" }), write: async () => ({ drafted: 1, stopped: "" }), read: async () => ({ read: 1, stopped: "" }) };
  const out = await runStages({ plan: { read: 1, write: 1, review: 1, audit: 1, mode: "steady" }, orders: { read: [], write: [] }, deps: { ...deps, audit: async (o) => { calls.push("audit"); return deps.audit(o); } }, now: () => 0, deadline: 1e9, log: () => {} });
  assert.equal(out.review.error, "Error"); assert.deepEqual(calls, ["audit"]);
});
test("reserveMs: reader 90 s, the Sonnet roles 150 s, never more than the role's own timeout", () => {
  assert.equal(reserveMs("library-reader"), 90000); assert.equal(reserveMs("library-writer"), 150000);
  assert.equal(reserveMs("library-auditor"), 150000); assert.equal(reserveMs("library-reviewer"), 150000);
});

/* ---------- reports ---------- */
const U = (role, model, o = {}) => ({ at: "2026-11-26T03:00:00Z", job: "library", role, model, in: 1000, out: 500, cache_read: 0, cache_write: 0, ok: true, ...o });
test("pilotReport: counts, error rate, tokens and cost per card and per story, and the pilot's story keys", () => {
  const p = { newest: [hx(1), hx(2)], extra: [hx(3)], actors: [{ key: "a-1", name: "Actor A", group: "top" }], loose: [{ key: "s-1", name: "Thing" }], counts: { reports: 3 } };
  const cards = new Map([[hx(1), audited(card(hx(1)))], [hx(2), { ...card(hx(2)), audit: { ok: false, by: "auditor", at: "2026-11-26T02:30:00Z" }, status: "unread", tries: 0 }], [hx(3), { sha1: hx(3), status: "no-text" }]]);
  const stories = new Map([["a-1", { live: { status: "published", headline: "H" }, next: null }]]);
  const usage = [U("library-reader", "haiku"), U("library-reader", "haiku"), U("library-writer", "sonnet"), U("library-reviewer", "sonnet"), U("library-auditor", "sonnet"), { ...U("map-researcher", "sonnet"), job: "sweep" }];
  const s = pilotReport(cards, stories, { pilot: p, usage, cfg: CFG });
  assert.match(s, /3 reports/); assert.match(s, /read 1/); assert.match(s, /no-text 1/); assert.match(s, /unread 1/);
  assert.match(s, /audited 2, wrong 1 \(50\.0%\)/);
  assert.match(s, /library-reader[^\n]*2 call/); assert.doesNotMatch(s, /map-researcher/);
  assert.match(s, /per card \$/); assert.match(s, /per story \$/);
  assert.match(s, /a-1[^\n]*published/); assert.match(s, /s-1[^\n]*no story yet/);
  assert.equal(typeof pilotReport(cards, stories), "string");
});
test("libraryBlock: cards, audit, stories, and tokens and estimated cost by role for the last 7 days", () => {
  const NOW = Date.parse("2026-11-26T12:00:00Z");
  const cards = new Map([[hx(1), audited(card(hx(1)))], [hx(2), { sha1: hx(2), status: "unread", tries: 1 }], [hx(3), { sha1: hx(3), status: "no-text" }]]);
  const stories = new Map([["a-1", { live: { status: "published" }, next: null }], ["a-2", { live: { status: "stale" }, next: { status: "draft" } }], ["a-3", { live: null, next: { status: "parked" } }], ["a-4", { live: null, next: { status: "rejected" } }]]);
  const usage = [U("library-reader", "haiku", { at: "2026-11-25T00:00:00Z" }), U("library-reader", "haiku", { at: "2026-11-01T00:00:00Z" }), U("library-writer", "sonnet", { at: "2026-11-25T00:00:00Z" })];
  const b = libraryBlock({ cards, stories, usage, cfg: CFG, now: NOW });
  assert.deepEqual(b.cards, { read: 1, "no-text": 1, unread: 1, total: 3 });
  assert.equal(b.audit.audited, 1); assert.equal(b.audit.wrong, 0); assert.equal(b.audit.paused, false); assert.equal(b.audit.pct, 0);
  assert.deepEqual(b.stories, { published: 1, stale: 1, draft: 1, rejected: 1, parked: 1 });
  assert.equal(b.usage.days, 7);
  assert.equal(b.usage.by_role["library-reader"].runs, 1, "the line from 25 days ago is outside the window");
  assert.equal(b.usage.by_role["library-reader"].tokens, 1500); assert.ok(b.usage.by_role["library-writer"].est_usd > 0);
});

/* ---------- config, routine, heartbeat, roles ---------- */
test("pipeline.json: the library block ships with backfill off and every dial documented", () => {
  const L = rj("config/pipeline.json").library;
  assert.equal(L.backfill, false); assert.equal(L.enabled, true);
  assert.deepEqual(L.pilot, { reports: 200, top_actors: 10, thin_actors: 5, loose: 5 });
  assert.deepEqual(L.wave, { read: 40, write: 6, review: 6, audit: 4 });
  assert.equal(L.reread, 3); assert.equal(L.audit_pct, 10); assert.equal(L.audit_pause_pct, 5); assert.equal(L.audit_min, 50);
  for (const k of ["enabled", "backfill", "pilot", "wave", "reread", "audit_pct", "audit_pause_pct", "audit_min"]) assert.ok(L._note.includes(k), `_note does not explain ${k}`);
  assert.match(L._note, /owner/);
  assert.deepEqual(deskConfig(join(ROOT, "config", "pipeline.json")), { ...DESK_DEFAULTS });
});
test("pipeline.json: the library job is headless", () => assert.ok(rj("config/pipeline.json").headless_jobs.includes("library")));
test("routines.json: library is an AI routine that ships off, with a heartbeat and a max age longer than its schedule", () => {
  const r = rj("routines.json").routines.find((x) => x.key === "library");
  assert.equal(r.name, "Library reports"); assert.equal(r.tier, "ai"); assert.equal(r.workflow, "claude-task");
  assert.equal(r.cron, "37 * * * *"); assert.equal(r.model, "claude-sonnet-5-5");
  assert.equal(r.status_key, "last_library_at"); assert.equal(r.max_age_hours, 6); assert.equal(r.active, false);
  assert.match(r.does, /Haiku/); assert.match(r.does, /Off until the owner starts the pilot\.$/);
  const orkl = rj("routines.json").routines.find((x) => x.key === "orkl");
  assert.match(orkl.does, /Library reports/);
});
test("stages: the library heartbeat row", () => {
  const s = STAGES.find((x) => x.status === "last_library_at");
  assert.ok(s); assert.equal(s.routine, "library"); assert.equal(s.heal, "");
});
test("models.json: the four Library roles are frozen, on haiku, sonnet, sonnet, sonnet", () => {
  const m = rj("config/models.json");
  assert.deepEqual([...m.frozen].sort(), ["library-auditor", "library-reader", "library-reviewer", "library-writer"]);
  assert.deepEqual(["library-reader", "library-writer", "library-reviewer", "library-auditor"].map((r) => m.roles[r].model), ["haiku", "sonnet", "sonnet", "sonnet"]);
});

/* ---------- pipeline check ---------- */
test("libraryProblems: a paused Library needs attention and names the cards; parked stories and orphan drafts are information", () => {
  const pre = (i) => (i + 1).toString(16).padStart(8, "0"), wrong = Array.from({ length: 14 }, (_, i) => pre(i) + "0".repeat(32));
  const ps = libraryProblems({ paused: true, wrong, parked: 2, orphans: 3 });
  const by = Object.fromEntries(ps.map((p) => [p.id, p]));
  assert.equal(by["library-paused"].level, "warn"); assert.ok(by["library-paused"].text.startsWith("Library reader accuracy below target"));
  assert.ok(by["library-paused"].text.includes(PAUSE_NOTICE.replace(/^Library reader accuracy below target\. /, "")), "how it clears");
  assert.ok(by["library-paused"].text.includes(pre(9)) && !by["library-paused"].text.includes(pre(10)), "at most 10 sha1 prefixes");
  assert.equal(by["library-parked"].level, "info"); assert.equal(by["library-parked"].text, "Library stories parked: 2");
  assert.equal(by["library-orphans"].level, "info"); assert.equal(by["library-orphans"].text, "Library orphan drafts: 3");
  for (const id of ["library-paused", "library-parked", "library-orphans"]) assert.ok(id in THRESHOLD, `${id} has a threshold`);
  assert.deepEqual(libraryProblems({ paused: false, wrong: [], parked: 0, orphans: 0 }), []);
});

/* ---------- the run ---------- */
test("run: chooses and stores the pilot, plans, runs the stages, stamps the heartbeat; waiting still stamps it and starts nothing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "desk-")), pilotFile = join(dir, "pilot.json"), statusFile = join(dir, "status.json");
  const w = withActors(world(200)), calls = [], logs = [];
  const deps = Object.fromEntries(["review", "audit", "write", "read"].map((k) => [k, async (o) => { calls.push([k, o.max]); return { read: o.max, drafted: o.max, ok: o.max, published: o.max, stopped: "" }; }]));
  const cfg = { ...DESK_DEFAULTS, pilot: { reports: 20, top_actors: 2, thin_actors: 1, loose: 1 }, wave: { read: 8, write: 2, review: 2, audit: 2 } };
  try {
    const out = await run({ cfg, library: w, deps, can: false, pilotFile, statusFile, deadline: Date.now() + 1e9, log: (l) => logs.push(l) });
    assert.match(out.note, /^waiting: the pipeline needs the usage window/); assert.deepEqual(calls, []);
    assert.ok(existsSync(pilotFile), "the pilot is chosen even while waiting"); assert.match(JSON.parse(readFileSync(statusFile, "utf8")).last_library_at, /^\d{4}-\d\d-\d\dT/);
    const before = readFileSync(pilotFile, "utf8");
    const out2 = await run({ cfg, library: w, deps, can: true, pilotFile, statusFile, deadline: Date.now() + 1e9, log: (l) => logs.push(l) });
    assert.equal(out2.plan.mode, "pilot"); assert.equal(readFileSync(pilotFile, "utf8"), before, "the stored pilot is not chosen again");
    assert.deepEqual(calls.map((c) => c[0]).filter((v, i, a) => a.indexOf(v) === i), ["write", "read"], "no drafts and nothing to audit yet; the pilot's stories and reports are worked on");
    assert.match(JSON.parse(readFileSync(statusFile, "utf8")).library_note, /^pilot: /);
    assert.ok(logs.some((l) => /^CyberView library: /.test(l)));
    const off = await run({ cfg: { ...cfg, enabled: false }, library: w, deps, can: true, pilotFile, statusFile, log: () => {} });
    assert.match(off.note, /^off/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
