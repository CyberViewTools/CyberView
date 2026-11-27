// The Library desk runner (scripts/library-desk.mjs): the plan (pilot first, backlog only when the owner switches it on, never while the
// pipeline needs the window), the pilot set and its completion predicate, the budget-bound stage loop, the pilot report, the
// efficiency block, and the config, routine, heartbeat and health checks that go with it. No model, no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run as runDesk, plan, selectPilot, latchPilot, describePilot, libraryIdle, pilotSha1s, pilotKeys, pilotLoose, pilotComplete, loadPilot, savePilot, addLoose, backfillOrder, deskState, runStages, pilotReport, libraryBlock, deskConfig, reserveMs, DESK_DEFAULTS } from "../../scripts/library-desk.mjs";
import { STAGES } from "../../scripts/lib/stages.mjs";
import { libraryProblems, THRESHOLD } from "../../scripts/pipecheck.mjs";
import { inventory, problems as aboutProblems, about } from "../../scripts/about.mjs";
import { problems as docsProblems } from "../../scripts/docs-check.mjs";
import { PAUSE_NOTICE } from "../../scripts/lib/library-audit.mjs";
// every desk run in these tests reads cards, stories and read-state from empty folders, never the real data branch (the
// Library writes real cards there since 2026-11-26, which made run tests depend on live data); a test may pass its own
const ISO = mkdtempSync(join(tmpdir(), "desk-iso-"));
const run = (o = {}) => runDesk({ cardsDir: join(ISO, "cards"), storiesDir: join(ISO, "stories"), readStateFile: join(ISO, "read-state.json"), ...o });

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
const MIRROR = { backfill_done: true };   // the ORKL mirror's first full pass is done (B-M5); the run tests never read data/orkl/state.json
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
  // two of the three reports read (the pilot needs at least half read, B-I2)
  const cards = new Map([[hx(1), audited(card(hx(1)))], [hx(2), audited(card(hx(2)))], [hx(3), { sha1: hx(3), status: "unread", tries: 2 }]]);
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
  const { state, orders } = deskState({ reports: [...w.reports, fresh], actors: [], cards, stories: new Map(), pilot: { ...pilot, actors: [], loose: [], completed_at: AT }, cfg: CFG });
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
test("runStages: nothing starts without the time for the role, and a stage with no progress ends", async () => {
  const calls = []; let t = 0;
  const none = { published: 0, corrected: 0, rejected: 0, parked: 0, cardsFlagged: 0, stopped: "" };
  const deps = { review: async () => { calls.push("review"); return none; },
    audit: async () => { calls.push("audit"); return { ok: 1, stopped: "ORKL unreachable" }; }, write: async () => { calls.push("write"); return { drafted: 1, stopped: "" }; }, read: async () => { calls.push("read"); return { read: 1, stopped: "" }; } };
  const p = { read: 4, write: 4, review: 4, audit: 4, mode: "steady" };
  await runStages({ plan: { ...p, read: 2 }, orders: { read: [], write: [] }, deps, now: () => t, deadline: reserveMs("library-writer") - 1, chunk: { review: 2, audit: 2, write: 2, read: 2 }, log: () => {} });
  assert.deepEqual(calls, [], "with the reader on Sonnet (owner, 2026-11-27) every role needs the same reserve, so nothing fits");
  calls.length = 0;
  const out = await runStages({ plan: p, orders: { read: [], write: [] }, deps, now: () => t, deadline: 1e9, chunk: { review: 2, audit: 2, write: 2, read: 2 }, log: () => {} });
  assert.deepEqual(calls, ["review", "audit", "write", "write", "read", "read"], "review made no progress; an unreachable ORKL ends only the audit stage");
  assert.equal(out.halt, undefined);
});
test("runStages: a usage limit ends the whole run, no later stage makes a call", async () => {
  const calls = [];
  const deps = { review: async () => { calls.push("review"); return { published: 1, stopped: "" }; }, audit: async () => { calls.push("audit"); return { ok: 1, stopped: "usage limit" }; },
    write: async () => { calls.push("write"); return { drafted: 1, stopped: "" }; }, read: async () => { calls.push("read"); return { read: 1, stopped: "" }; } };
  const out = await runStages({ plan: { read: 4, write: 4, review: 2, audit: 4, mode: "steady" }, orders: { read: [], write: [] }, deps, now: () => 0, deadline: 1e9, chunk: { review: 2, audit: 2, write: 2, read: 2 }, log: () => {} });
  assert.deepEqual(calls, ["review", "audit"]); assert.match(out.halt, /usage limit/);
});
test("runStages: canStart is asked before every wave and ends the run, with its reason, when it turns false", async () => {
  const calls = []; let asks = 0;
  const ok = (k) => async () => { calls.push(k); return { published: 1, ok: 1, drafted: 1, read: 1, stopped: "" }; };
  const out = await runStages({ plan: { read: 4, write: 4, review: 4, audit: 4, mode: "steady" }, orders: { read: [], write: [] }, deps: { review: ok("review"), audit: ok("audit"), write: ok("write"), read: ok("read") },
    now: () => 0, deadline: 1e9, chunk: { review: 2, audit: 2, write: 2, read: 2 }, canStart: () => ++asks <= 2, log: () => {} });
  assert.deepEqual(calls, ["review", "review"]); assert.equal(out.halt, "the pipeline needs the usage window"); assert.equal(asks, 3);
});
test("runStages: every call gets a timeout of at most the role's own and the time left minus 20 s", async () => {
  const seen = []; let t = 0;
  const deps = { review: async (o) => { seen.push(["review", o.timeoutMs, 1e6 - t]); t += 100000; return { published: 1, stopped: "" }; }, audit: async (o) => { seen.push(["audit", o.timeoutMs, 1e6 - t]); t += 50000; return { ok: 1, stopped: "" }; },
    write: async () => ({ drafted: 1 }), read: async (o) => { seen.push(["read", o.timeoutMs, 1e6 - t]); return { read: 1, stopped: "" }; } };
  await runStages({ plan: { read: 1, write: 0, review: 2, audit: 1, mode: "steady" }, orders: { read: [] }, deps, now: () => t, deadline: 1e6, chunk: { review: 1, audit: 1, write: 1, read: 1 }, log: () => {} });
  assert.equal(seen.length, 4);
  for (const [k, ms, left] of seen) { assert.ok(ms <= left - 20000, `${k}: ${ms} > ${left} - 20000`); assert.ok(ms <= 6 * 60000); assert.ok(ms > 0); }
  const late = []; let t2 = 0;
  await runStages({ plan: { read: 1, write: 0, review: 0, audit: 0, mode: "steady" }, orders: { read: [] }, deps: { read: async (o) => { late.push(o.timeoutMs); return { read: 1 }; } }, now: () => t2, deadline: 160000 + 5, chunk: { read: 1 }, log: () => {} });
  assert.deepEqual(late, [140005], "160 s are left: the Sonnet reader (150 s reserve) may start, with 140 s");
});
test("runStages: a stage that throws does not stop the others", async () => {
  const calls = [];
  const deps = { review: async () => { throw new Error("boom"); }, audit: async () => ({ ok: 1, stopped: "" }), write: async () => ({ drafted: 1, stopped: "" }), read: async () => ({ read: 1, stopped: "" }) };
  const out = await runStages({ plan: { read: 1, write: 1, review: 1, audit: 1, mode: "steady" }, orders: { read: [], write: [] }, deps: { ...deps, audit: async (o) => { calls.push("audit"); return deps.audit(o); } }, now: () => 0, deadline: 1e9, log: () => {} });
  assert.equal(out.review.error, "Error"); assert.deepEqual(calls, ["audit"]);
});
test("reserveMs: 90 s for a Haiku reader, 150 s for every Sonnet role (the reader too), never more than the role's own timeout", () => {
  assert.equal(reserveMs("library-reader"), 150000); assert.equal(reserveMs("library-writer"), 150000);
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
  assert.match(s, /er card \(estimate\) \$/); assert.match(s, /er story \(estimate\) \$/);
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
test("pipeline.json: the library block as the owner set it on 2026-11-26 (backfill on, bigger waves, API only) with every dial documented", () => {
  const L = rj("config/pipeline.json").library;
  assert.equal(L.backfill, true); assert.equal(L.enabled, true);
  assert.deepEqual(L.pilot, { reports: 200, top_actors: 10, thin_actors: 5, loose: 5 });
  assert.deepEqual(L.wave, { read: 150, write: 16, review: 16, audit: 150 });
  assert.deepEqual(L.api, { enabled: true, monthly_usd_cap: 75, month_caps: { "2026-11": 0 } });   // 2026-11-27: parked for the rest of November
  assert.equal(L.reread, 3); assert.equal(L.audit_pct, 20); assert.equal(L.audit_pause_pct, 5); assert.equal(L.audit_min, 50); assert.equal(L.rewrite_hours, 24);
  for (const k of ["enabled", "backfill", "pilot", "wave", "reread", "audit_pct", "audit_pause_pct", "audit_min", "api", "monthly_usd_cap", "concurrency", "run_minutes", "rewrite_hours", "month_caps"]) assert.ok(L._note.includes(k), `_note does not explain ${k}`);
  assert.match(L._note, /owner/);
  const c = deskConfig(join(ROOT, "config", "pipeline.json"));
  assert.equal(c.backfill, true); assert.deepEqual(c.wave, L.wave); assert.deepEqual(c.pilot, DESK_DEFAULTS.pilot);
});
test("pipeline.json: the library job is headless", () => assert.ok(rj("config/pipeline.json").headless_jobs.includes("library")));
test("routines.json: library is an AI routine, switched on, with a heartbeat and a max age longer than its schedule", () => {
  const r = rj("routines.json").routines.find((x) => x.key === "library");
  assert.equal(r.name, "Library reports"); assert.equal(r.tier, "ai"); assert.equal(r.workflow, "claude-task");
  assert.equal(r.cron, "17,37,57 * * * *"); assert.equal(r.model, "claude-sonnet-5-5");
  assert.equal(r.status_key, "last_library_at"); assert.equal(r.max_age_hours, 6); assert.equal(r.active, true);
  assert.match(r.does, /Sonnet reads each report/); assert.match(r.does, /bills only the API key/); assert.match(r.does, /"active": false/);
  const orkl = rj("routines.json").routines.find((x) => x.key === "orkl");
  assert.match(orkl.does, /Library reports/);
});
test("stages: the library heartbeat row", () => {
  const s = STAGES.find((x) => x.status === "last_library_at");
  assert.ok(s); assert.equal(s.routine, "library"); assert.equal(s.heal, "");
});
test("models.json: the four Library roles are frozen, all on sonnet (owner, 2026-11-27: the reader moved off Haiku)", () => {
  const m = rj("config/models.json");
  assert.deepEqual([...m.frozen].sort(), ["library-auditor", "library-reader", "library-reviewer", "library-writer"]);
  assert.deepEqual(["library-reader", "library-writer", "library-reviewer", "library-auditor"].map((r) => m.roles[r].model), ["sonnet", "sonnet", "sonnet", "sonnet"]);
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
  const iso = { cardsDir: join(dir, "cards"), storiesDir: join(dir, "stories"), readStateFile: join(dir, "read-state.json") };   // never the real data branch
  const w = withActors(world(200)), calls = [], logs = [];
  const deps = Object.fromEntries(["review", "audit", "write", "read"].map((k) => [k, async (o) => { calls.push([k, o.max]); return { read: o.max, drafted: o.max, ok: o.max, published: o.max, stopped: "" }; }]));
  const cfg = { ...DESK_DEFAULTS, pilot: { reports: 20, top_actors: 2, thin_actors: 1, loose: 1 }, wave: { read: 8, write: 2, review: 2, audit: 2 } };
  try {
    const out = await run({ cfg, library: w, deps, can: false, pilotFile, statusFile, mirror: MIRROR, ...iso, deadlineMs: Date.now() + 1e9, log: (l) => logs.push(l) });
    assert.match(out.note, /^waiting: the pipeline needs the usage window/); assert.deepEqual(calls, []);
    assert.ok(existsSync(pilotFile), "the pilot is chosen even while waiting"); assert.match(JSON.parse(readFileSync(statusFile, "utf8")).last_library_at, /^\d{4}-\d\d-\d\dT/);
    const before = readFileSync(pilotFile, "utf8");
    const out2 = await run({ cfg, library: w, deps, can: true, pilotFile, statusFile, mirror: MIRROR, ...iso, deadlineMs: Date.now() + 1e9, log: (l) => logs.push(l) });
    assert.equal(out2.plan.mode, "pilot"); assert.equal(readFileSync(pilotFile, "utf8"), before, "the stored pilot is not chosen again");
    assert.deepEqual(calls.map((c) => c[0]).filter((v, i, a) => a.indexOf(v) === i), ["write", "read"], "no drafts and nothing to audit yet; the pilot's stories and reports are worked on");
    assert.match(JSON.parse(readFileSync(statusFile, "utf8")).library_note, /^pilot: /);
    assert.ok(logs.some((l) => /^CyberView library: /.test(l)));
    const off = await run({ cfg: { ...cfg, enabled: false }, library: w, deps, can: true, pilotFile, statusFile, mirror: MIRROR, ...iso, log: () => {} });
    assert.match(off.note, /^off/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

/* ---------- fix round 1 ---------- */
const readOn = (c, at = "2026-11-26T01:00:00Z") => audited(card(c, { read_at: at }));
function steadyWorld() {
  const w = world(10);
  w.reports[0].actors = [w.actors[2].name];                     // Actor C: an old report, read during the pilot, outside it
  const pilot = { ...selectPilot(w.reports, w.actors, { ...PCFG, reports: 3, top_actors: 0, thin_actors: 0 }, AT), completed_at: "2026-11-27T00:00:00Z" };
  const fresh = { sha1: hx(500), created: "2030-01-01T00:00:00Z", actors: [w.actors[3].name] };      // Actor D: a report newer than the pilot's newest
  const reports = [...w.reports, fresh];
  const cards = new Map(reports.filter((r) => pilotSha1s(pilot).includes(r.sha1) || r.sha1 === hx(1) || r.sha1 === hx(500)).map((r) => [r.sha1, readOn(r.sha1)]));
  return { w, pilot, reports, cards };
}
test("deskState: with backfill off the writer's steady queue is the pilot, stories that exist, and subjects with a card from a NEW report", () => {
  const { w, pilot, reports, cards } = steadyWorld();
  const { orders, state } = deskState({ reports, actors: w.actors, cards, stories: new Map(), pilot, cfg: { ...CFG, backfill: false } });
  assert.equal(state.pilotDone, true);
  assert.ok(!orders.write.includes("a-102"), "Actor C: a card read during the pilot is not a new record");
  assert.ok(orders.write.includes("a-103"), "Actor D: its report is newer than the pilot's newest");
  const withStory = deskState({ reports, actors: w.actors, cards, stories: new Map([["a-102", { live: { status: "published", based_on: "old" }, next: null }]]), pilot, cfg: CFG });
  assert.ok(withStory.orders.write.includes("a-102"), "a subject that already has a story is rewritten when stale");
  assert.equal(state.writeNew, orders.write.length);
});
test("deskState: a story written within library.rewrite_hours is not in the write queue or its count; past it, it is", () => {
  const { w, pilot, reports, cards } = steadyWorld();
  const now = Date.parse("2026-11-27T12:00:00Z"), file = (hAgo) => new Map([["a-102", { live: { status: "published", based_on: "old", written_at: new Date(now - hAgo * 3600000).toISOString() }, next: null }]]);
  const held = deskState({ reports, actors: w.actors, cards, stories: file(2), pilot, cfg: { ...CFG, rewrite_hours: 24 }, now });
  assert.ok(!held.orders.write.includes("a-102"), "written 2 hours ago: held back");
  const due = deskState({ reports, actors: w.actors, cards, stories: file(30), pilot, cfg: { ...CFG, rewrite_hours: 24 }, now });
  assert.ok(due.orders.write.includes("a-102"), "written 30 hours ago: rewritten");
  assert.equal(due.state.writeNew - held.state.writeNew, 1, "the plan never counts a held-back story");
});
// owner, 2026-11-27: with backfill on, the plan counted the ~2,000 unwritten subjects but the writer's order (it writes only what is
// in its order) held only stories that already existed, so the backlog was never written and the same stories were rewritten
test("deskState: with backfill on the writer's order is the steady queue first, then every other subject waiting", () => {
  const { w, pilot, reports, cards } = steadyWorld();
  const off = deskState({ reports, actors: w.actors, cards, stories: new Map(), pilot, cfg: { ...CFG, backfill: false } });
  assert.ok(!off.orders.write.includes("a-102"), "backfill off: a subject read during the pilot waits");
  const on = deskState({ reports, actors: w.actors, cards, stories: new Map(), pilot, cfg: { ...CFG, backfill: true } });
  assert.ok(on.orders.write.includes("a-102"), "backfill on: the backlog subject is in the order");
  assert.deepEqual(on.orders.write.slice(0, off.orders.write.length), off.orders.write, "the steady queue comes first");
  assert.equal(on.orders.write.length, on.state.writeNew + on.state.writeBacklog, "the order holds everything the plan counts");
});
test("deskState: the reader's steady queue is the new reports and the audit-failed re-reads only", () => {
  const { w, pilot, reports, cards } = steadyWorld();
  const oldFailed = { sha1: hx(2), status: "unread", tries: 0, audit: { ok: false, by: "auditor", at: "2026-11-26T02:00:00Z" } };
  const c2 = new Map([...cards, [hx(2), oldFailed]]); c2.delete(hx(500));
  const { orders, state } = deskState({ reports, actors: w.actors, cards: c2, stories: new Map(), pilot, cfg: CFG });
  assert.deepEqual([...orders.read].sort(), [hx(2), hx(500)].sort()); assert.equal(state.newRecords, 2);
  assert.ok(!orders.read.includes(hx(3)), "an old unread report is backlog");
});
test("pilot latch: the live predicate does not decide the mode, completed_at does; latchPilot writes it once", () => {
  const { w, pilot, reports, cards } = steadyWorld();
  const open = { ...pilot }; delete open.completed_at;
  const ds = deskState({ reports, actors: w.actors, cards, stories: new Map(), pilot: open, cfg: CFG });
  assert.equal(ds.pilotStatus.done, true); assert.equal(ds.state.pilotDone, false, "not latched yet: the mode stays pilot");
  const dir = mkdtempSync(join(tmpdir(), "latch-")), f = join(dir, "pilot.json");
  try {
    savePilot(f, open);
    assert.equal(latchPilot(f, "2026-11-27T01:00:00Z"), true); assert.equal(loadPilot(f).pilot.completed_at, "2026-11-27T01:00:00Z");
    assert.equal(latchPilot(f, "2030-01-01T00:00:00Z"), false); assert.equal(loadPilot(f).pilot.completed_at, "2026-11-27T01:00:00Z", "never changed");
    // a live predicate that turns false later does not unlatch
    const back = deskState({ reports, actors: w.actors, cards: new Map(), stories: new Map(), pilot: loadPilot(f).pilot, cfg: CFG });
    assert.equal(back.pilotStatus.done, false); assert.equal(back.state.pilotDone, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("pilotComplete: a pilot subject key that no longer resolves does not block, and is named", () => {
  const p = { newest: [], extra: [], actors: [{ key: "a-1" }, { key: "a-gone", name: "Gone" }], loose: [] };
  const stories = new Map([["a-1", { live: { status: "published" }, next: null }]]);
  const r = pilotComplete(p, new Map(), stories, new Set(["a-1"]));
  assert.equal(r.done, true); assert.deepEqual(r.unresolved, ["a-gone"]);
  assert.equal(pilotComplete(p, new Map(), stories, new Set(["a-1", "a-gone"])).done, false, "a resolvable subject without a story still blocks");
});
test("describePilot: the mode, the latch time and, when the live predicate is false, every reason with counts", () => {
  const open = describePilot({ latched: "", live: { done: false, why: ["3 report(s) not read yet", "2 read card(s) without the auditor's verdict"], counts: { unread: 3, unaudited: 2, unfinished: 1, unresolved: 1 }, unresolved: ["a-gone"] } });
  assert.match(open, /mode pilot/); assert.match(open, /not latched/); assert.match(open, /3 report\(s\) not read yet/); assert.match(open, /unresolved pilot subject key\(s\): a-gone/);
  const done = describePilot({ latched: "2026-11-27T00:00:00Z", live: { done: true, why: [], counts: {}, unresolved: [] } });
  assert.match(done, /latched at 2026-11-27T00:00:00Z/); assert.doesNotMatch(done, /not read yet/);
});
test("selectPilot: placeholder catalogue entries (names starting with \"[\") are never thin actors; fewer than wanted is fine", () => {
  const w = world(40);
  w.actors.push({ id: 900, name: "[Unnamed group USA]", aliases: [] });
  const p = selectPilot(w.reports, w.actors.slice(0, 3).concat(w.actors.slice(-1)), { ...PCFG, top_actors: 0, thin_actors: 5 }, AT);
  const thin = p.actors.map((a) => a.name);
  assert.deepEqual(thin, ["Actor A", "Actor B", "Actor C"]); assert.equal(p.counts.thin_actors, 3);
});
test("plan: a null config does not crash the paused branch", () => {
  assert.equal(plan({ ...STATE, pilotDone: true, paused: true, failedCards: 2 }, null, true).read, 2);
});
test("pilotReport: no NaN when a role has no ledger lines, costs are labelled estimates, per-card and per-story count only the pilot's", () => {
  const p = { newest: [hx(1)], extra: [], actors: [{ key: "a-1", name: "Actor A", group: "top" }], loose: [], counts: { reports: 1 } };
  const cards = new Map([[hx(1), audited(card(hx(1)))], [hx(7), audited(card(hx(7)))], [hx(8), audited(card(hx(8)))]]);
  const stories = new Map([["a-1", { live: { status: "published" }, next: null }], ["a-9", { live: { status: "published" }, next: null }]]);
  const s = pilotReport(cards, stories, { pilot: p, usage: [{ ...U("library-reader", "haiku"), in: 1e7, out: 0 }], cfg: CFG });
  assert.doesNotMatch(s, /NaN/); assert.match(s, /Cost per card \(estimate\)/); assert.match(s, /cost per story \(estimate\)/);
  assert.match(s, /Cost per card \(estimate\) \$1\.000/, "$1 over one pilot card, not three");
});
test("libraryIdle: an inactive routine with no cards is idle: nothing loads the whole library", () => {
  const off = [{ key: "library", active: false }], on = [{ key: "library", active: true }];
  assert.equal(libraryIdle(off, new Map()), true); assert.equal(libraryIdle(on, new Map()), false); assert.equal(libraryIdle(off, new Map([["a", {}]])), false);
});
test("run: a deadline that leaves no time for a wave starts nothing, still stamps the heartbeat and says so", async () => {
  const dir = mkdtempSync(join(tmpdir(), "desk-")), pilotFile = join(dir, "pilot.json"), statusFile = join(dir, "status.json"), calls = [];
  const w = withActors(world(200));
  const deps = Object.fromEntries(["review", "audit", "write", "read"].map((k) => [k, async () => { calls.push(k); return {}; }]));
  const cfg = { ...DESK_DEFAULTS, pilot: { reports: 20, top_actors: 2, thin_actors: 1, loose: 1 } };
  try {
    const out = await run({ cfg, library: w, deps, can: true, pilotFile, statusFile, mirror: MIRROR, deadlineMs: Date.now() + 30000, log: () => {} });
    assert.deepEqual(calls, []); assert.match(out.note, /deadline/);
    const st = JSON.parse(readFileSync(statusFile, "utf8")); assert.match(st.last_library_at, /^\d{4}/); assert.match(st.library_note, /deadline/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("run: a usage-ledger check before every wave: canStart false after the first wave ends the run with the window reason", async () => {
  const dir = mkdtempSync(join(tmpdir(), "desk-")), calls = [], w = withActors(world(200)); let asks = 0;
  const deps = Object.fromEntries(["review", "audit", "write", "read"].map((k) => [k, async (o) => { calls.push(k); return { read: o.max, drafted: o.max, ok: o.max, published: o.max }; }]));
  try {
    const out = await run({ cfg: { ...DESK_DEFAULTS, pilot: { reports: 20, top_actors: 2, thin_actors: 1, loose: 1 } }, library: w, deps, canStart: () => ++asks <= 1, pilotFile: join(dir, "p.json"), statusFile: join(dir, "s.json"), mirror: MIRROR, deadlineMs: Date.now() + 1e9, log: () => {} });
    assert.equal(calls.length, 1); assert.match(out.note, /the pipeline needs the usage window/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

/* ---------- activation is one edit ---------- */
test("routines.json: the Library is switched on (active + active_since): about, docs and the jobs tests are satisfied", async () => {
  const real = rj("routines.json").routines, lib = real.find((r) => r.key === "library");
  assert.equal(lib.active, true); assert.ok(lib.active_since);
  const flipped = real;
  const inv = await inventory(), on = { ...inv, routines: flipped.filter((r) => r.active !== false).map((r) => r.key) };
  assert.ok(inv.routines.includes("library"), "an off routine is described too, so the about entry ships now");
  assert.deepEqual(aboutProblems(about(), on), []); assert.deepEqual(aboutProblems(about(), inv), []);
  const jobs = readFileSync(join(ROOT, "docs", "jobs.md"), "utf8");
  assert.deepEqual(docsProblems({ files: [], layout: "", jobs, routines: flipped, figures: [], live: {} }), []);
  const jt = readFileSync(join(ROOT, "tests", "unit", "jobs.test.mjs"), "utf8");
  assert.match(jt, /r\.key === "library"\) continue/, "the jobs test exempts the desk (it has no job-prompt section)");
  const iv = lib.cron.split(" ")[1] === "*" ? 1 : 24; assert.ok(lib.max_age_hours >= iv * 1.15);
  assert.match(lib.does, /"active": false/);
});

// B-I1: the desk passes only:true and, before the latch, the pilot's story keys to the review stage
test("deskState and runStages: before the latch the review stage gets the pilot keys only; drafts outside it are not counted", async () => {
  const w = withActors(world());
  const pilot = selectPilot(w.reports, w.actors, PCFG, AT);
  const pk = pilotKeys(pilot), outside = "a-zz-not-in-pilot";
  const draft = { live: null, next: { status: "draft" } };
  const stories = new Map([[pk[0], draft], [outside, draft]]);
  const { orders } = deskState({ reports: w.reports, actors: w.actors, cards: new Map(), stories, pilot, cfg: CFG });
  assert.deepEqual([...orders.review].sort(), [...pk].sort());
  const seen = [];
  const deps = { review: async (o) => { seen.push(o.order); return { published: 1 }; } };
  await runStages({ plan: { read: 0, write: 0, review: 2, audit: 0, mode: "pilot" }, orders: { ...orders }, deps, now: () => 0, deadline: 1e9, chunk: { review: 1 }, log: () => {} });
  assert.ok(seen.length && seen.every((o) => Array.isArray(o) && !o.includes(outside)));
  const done = deskState({ reports: w.reports, actors: w.actors, cards: new Map(), stories, pilot: { ...pilot, completed_at: AT }, cfg: CFG });
  assert.equal(done.orders.review, null, "after the latch every draft may be reviewed");
});
test("realDeps: the reader and writer are always called with only:true", async () => {
  const src = readFileSync(join(ROOT, "scripts", "library-desk.mjs"), "utf8");
  const block = src.slice(src.indexOf("function realDeps"), src.indexOf("function realDeps") + 2400);
  assert.match(block, /readRun\(\{[^}]*only: true/); assert.match(block, /writeRun\(\{[^}]*only: true/); assert.match(block, /reviewRun\(\{[^}]*keys: order/);
});

// B-I2: the pilot cannot latch with (almost) nothing read, or with a top-actor story that cites no report
test("pilotComplete: at least half the pilot reports read, and every published top-actor story cites a card", () => {
  const p = { newest: [hx(1), hx(2), hx(3), hx(4)], extra: [], actors: [{ key: "a-1", group: "top" }, { key: "a-2", group: "thin" }], loose: [] };
  const nt = (s) => ({ sha1: s, status: "no-text" });
  const cite = (c) => ({ live: { status: "published", sections: [{ h: "who", sentences: [{ t: "x", cites: c }] }] }, next: null });
  const cards = new Map([[hx(1), audited(card(hx(1)))], [hx(2), audited(card(hx(2)))], [hx(3), nt(hx(3))], [hx(4), nt(hx(4))]]);
  const stories = new Map([["a-1", cite([hx(1)])], ["a-2", cite(["catalogue"])]]);
  assert.equal(pilotComplete(p, cards, stories).done, true, "2 of 4 read; the thin actor may be catalogue-only");
  const few = pilotComplete(p, new Map([...cards, [hx(2), nt(hx(2))]]), stories);
  assert.equal(few.done, false); assert.ok(few.why.some((w) => /half/.test(w)), few.why.join("; "));
  const bare = pilotComplete(p, cards, new Map([["a-1", cite(["catalogue"])], ["a-2", cite(["catalogue"])]]));
  assert.equal(bare.done, false); assert.ok(bare.why.some((w) => /cites no report/.test(w)), bare.why.join("; "));
  assert.match(describePilot({ live: few }), /half/);
});

// B-I10: a parked record counts as resolved-unread for the pilot and is named
test("pilotComplete: a parked record is resolved (unread) and named", () => {
  const p = { newest: [hx(1), hx(2), hx(3)], extra: [], actors: [], loose: [] };
  const cards = new Map([[hx(1), audited(card(hx(1)))], [hx(2), audited(card(hx(2)))]]);
  assert.equal(pilotComplete(p, cards, new Map()).done, false);
  const r = pilotComplete(p, cards, new Map(), null, { parked: new Set([hx(3)]) });
  assert.equal(r.done, true); assert.deepEqual(r.parked, [hx(3)]);
  assert.match(describePilot({ live: r }), new RegExp(`parked.*${hx(3).slice(0, 8)}`));
});

// B-M5: the pilot is never chosen from a partial library
test("run: no pilot is chosen until the mirror's first full pass is done; the desk says why and does nothing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "desk-")), pilotFile = join(dir, "pilot.json"), statusFile = join(dir, "status.json"), calls = [];
  const deps = Object.fromEntries(["review", "audit", "write", "read"].map((k) => [k, async () => { calls.push(k); return {}; }]));
  try {
    const out = await run({ cfg: { ...DESK_DEFAULTS, pilot: { reports: 20, top_actors: 2, thin_actors: 1, loose: 1 } }, library: withActors(world(200)), deps, can: true, pilotFile, statusFile, mirror: { backfill_done: false }, deadlineMs: Date.now() + 1e9, log: () => {} });
    assert.match(out.note, /first full pass/); assert.ok(!existsSync(pilotFile)); assert.deepEqual(calls, []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
// B-M4: every desk run leaves a run log: codes and counts only
test("run: writes a run log with counts read, written, reviewed, audited, skipped and the stop reasons", async () => {
  const dir = mkdtempSync(join(tmpdir(), "desk-")), logs = [];
  const deps = { review: async (o) => ({ published: 1, corrected: 0, rejected: 0, parked: 0, skipped: 1 }), audit: async (o) => ({ ok: 2, wrong: 1, skipped: 0 }),
    write: async (o) => ({ drafted: 2, rejected: 1, parked: 0, requeued: 0 }), read: async (o) => ({ read: 3, "no-text": 1, unread: 0, requeued: 2, stopped: "ORKL unreachable" }) };
  const w = withActors(world(200));
  try {
    const out = await run({ cfg: { ...DESK_DEFAULTS, pilot: { reports: 20, top_actors: 2, thin_actors: 1, loose: 1 }, wave: { read: 4, write: 3, review: 2, audit: 3 } }, library: w, deps, can: true,
      pilotFile: join(dir, "p.json"), statusFile: join(dir, "s.json"), mirror: MIRROR, deadlineMs: Date.now() + 1e9, log: () => {}, runLog: (l) => logs.push(l) });
    assert.equal(logs.length, 1);
    const l = logs[0];
    assert.match(l.started_at, /^\d{4}-/); assert.match(l.finished_at, /^\d{4}-/); assert.equal(l.mode, out.plan.mode);
    for (const k of ["read", "written", "reviewed", "audited", "skipped"]) assert.equal(typeof l.counts[k], "number", k);
    assert.ok(l.stopped.includes("read: ORKL unreachable"), JSON.stringify(l.stopped));
    assert.ok(Array.isArray(l.open_leads) && Array.isArray(l.added));
    const waiting = []; await run({ cfg: { ...DESK_DEFAULTS }, library: w, deps, can: false, pilotFile: join(dir, "p.json"), statusFile: join(dir, "s.json"), mirror: MIRROR, log: () => {}, runLog: (x) => waiting.push(x) });
    assert.equal(waiting.length, 1); assert.equal(waiting[0].mode, "wait");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
// B-M2: the routine's reviewed date is not in the future
test("routines.json: the library routine's reviewed date is 2026-11-25", () => {
  assert.equal(rj("routines.json").routines.find((r) => r.key === "library").reviewed, "2026-11-25");
});
// B-M3: the stage CLIs refuse to run outside the desk unless the owner overrides
import { spawnSync } from "node:child_process";
test("CLI: library-read run, library-write run and library-review run|audit refuse without --owner-override", () => {
  for (const [f, cmd] of [["library-read.mjs", "run"], ["library-write.mjs", "run"], ["library-review.mjs", "run"], ["library-review.mjs", "audit"]]) {
    const r = spawnSync(process.execPath, [join(ROOT, "scripts", f), cmd, "--max", "0"], { encoding: "utf8", env: { ...process.env, LIBRARY_DESK: "" } });
    assert.notEqual(r.status, 0, `${f} ${cmd}`); assert.match(r.stderr, /owner-override/, `${f} ${cmd}: ${r.stderr}`);
  }
});

// Fix B (open after the final review, item 2): the reader's "ORKL text missing" guard must fire from the desk, which reads 4 at a time
import { realDeps } from "../../scripts/library-desk.mjs";
import { loadCards as loadCardsIn } from "../../scripts/library-read.mjs";
const lrep = (i) => { const sha1 = hx(0xb000 + i); return { id: "id-" + i, sha1, title: "T " + i, created: `2020-04-${String(i + 1).padStart(2, "0")}`, txt_url: `https://archive.orkl.eu/${sha1}.txt` }; };
const LTEXT = "The group APT-Example, assessed by the vendor to be state-sponsored, exploited CVE-2024-12345 in March 2024 against energy firms. " + "x".repeat(500);
const readStage = async (n, fetch, call) => {
  const dir = mkdtempSync(join(tmpdir(), "lib-desk-read-"));
  const reports = Array.from({ length: n }, (_, i) => lrep(i)), chunks = [];
  const deps = realDeps({ reports, actors: [] }, { read: { dir, fetch: (r) => fetch(r, reports), call, model: "haiku", log: () => {} } });
  const read = deps.read; deps.read = (o) => { chunks.push(o.max); return read(o); };
  const out = await runStages({ plan: { read: n, write: 0, review: 0, audit: 0, mode: "steady" }, orders: { read: reports.map((r) => r.sha1) }, deps, now: () => 0, deadline: 1e9, log: () => {} });
  const cards = [...loadCardsIn(dir).values()];
  rmSync(dir, { recursive: true, force: true });
  return { out, chunks, cards, reports };
};
test("read stage: reader called in chunks of 4, every fetch \"none\": no no-text card is stored and the stage stops with \"ORKL text missing\"", async () => {
  let asked = 0;
  const { out, chunks, cards } = await readStage(12, async () => ({ error: "none" }), async () => { asked++; return { ok: false, json: null, limit: false, error: true }; });
  assert.deepEqual(chunks, [4, 4], "the reader is called 4 at a time and the third chunk never starts");
  assert.equal(out.read.stopped, "ORKL text missing");
  assert.equal(cards.length, 0, "no no-text card is stored");
  assert.equal(asked, 0, "no model call for a report without text");
  assert.equal(out.halt, undefined, "missing text ends the read stage, not the run");
});
test("read stage: no-text cards of a run that never met the rule are written once, at the end of the stage", async () => {
  const { out, chunks, cards } = await readStage(4, async () => ({ error: "none" }), async () => ({ ok: false, json: null, limit: false, error: true }));
  assert.deepEqual(chunks, [4]);
  assert.equal(out.read.stopped, ""); assert.equal(cards.length, 4); assert.ok(cards.every((c) => c.status === "no-text"));
  assert.equal(out.read.tally["no-text"], 4);
});
test("read stage: an earlier \"usage limit\" stop reason is never overwritten by \"ORKL text missing\", and the held cards are not stored", async () => {
  // chunk 1: four without text; chunk 2: three without text and one with text whose model call hits the usage limit (7 of 8 none: the rule is met)
  const { out, cards } = await readStage(12, async (r, reports) => (r.sha1 === reports[7].sha1 ? { text: LTEXT, partial: false } : { error: "none" }), async () => ({ ok: false, json: null, limit: true, error: false }));
  assert.equal(out.read.stopped, "usage limit"); assert.equal(out.halt, "usage limit");
  assert.equal(cards.length, 0, "the rule was met, so no no-text card is stored");
});
test("read stage: a usage limit ends the run but the held no-text cards are still written when the rule was never met", async () => {
  // chunk 1: four without text; chunk 2: four with text, the model call hits the limit (4 of 8 none: not systemic)
  const { out, cards } = await readStage(12, async (r, reports) => (reports.findIndex((x) => x.sha1 === r.sha1) < 4 ? { error: "none" } : { text: LTEXT, partial: false }), async () => ({ ok: false, json: null, limit: true, error: false }));
  assert.equal(out.halt, "usage limit"); assert.equal(cards.length, 4); assert.ok(cards.every((c) => c.status === "no-text"));
});

// Open item 3 (final review): after the pilot latches, its own reports that are due again are still read in steady mode
test("deskState: after the latch a pilot report whose no-text card is due its one retry, or that an audit sent back, is in the steady read queue", () => {
  const { w, pilot, reports, cards } = steadyWorld();
  const [p1, p2, p3] = pilotSha1s(pilot), now = Date.parse("2027-01-15T00:00:00Z");
  const c2 = new Map(cards);
  c2.set(p1, { sha1: p1, status: "no-text", reason: "no text at ORKL", read_at: "2026-11-26T01:00:00Z", model: "haiku" });            // due: 30 days have passed
  c2.set(p2, { sha1: p2, status: "no-text", reason: "no text at ORKL", read_at: "2026-11-26T01:00:00Z", model: "haiku", retried: true }); // already retried: not due
  c2.set(p3, { sha1: p3, status: "unread", tries: 0, audit: { ok: false, by: "auditor", at: "2026-11-26T02:00:00Z" } });               // sent back by an audit
  const { orders, state } = deskState({ reports, actors: w.actors, cards: c2, stories: new Map(), pilot, cfg: { ...CFG, backfill: false }, now });
  assert.equal(state.pilotDone, true);
  assert.ok(orders.read.includes(p1), "the due no-text pilot report is read again"); assert.ok(orders.read.includes(p3), "the audit-failed pilot card is read again");
  assert.ok(!orders.read.includes(p2), "a no-text card already retried is left alone");
  assert.equal(state.newRecords, orders.read.length, "the plan's read count matches the queue");
  assert.equal(plan(state, { ...CFG, backfill: false }, true).read, Math.min(CFG.wave.read, orders.read.length));
});
