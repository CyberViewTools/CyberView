// Unit tests for scripts/outage-desk.mjs: the queue of unchecked outage reports (order, skip rules, leases), plan ids,
// validation of a checker's out file (missing sources, attack wording, decisions outside the set, event ids) and apply.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { powerItems, internetItems, serviceItems, queue, due, dueWhy, heldBack, makePlan, planId, validate, applyResults, entryFor, leadFor, siteCheck, latestFor, stats, officialFor, BY, DECISIONS } from "../../scripts/outage-desk.mjs";

const NOW = Date.parse("2026-11-20T18:00:00Z"), iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
const pub = (name, host, title = "Power cut in the city") => ({ name, url: `https://${host}/news/2026/11/20/power-cut`, title, lang: "en", published: "2026-11-20T10:00:00Z" });
const news = { updated_at: "2026-11-20T17:00:00Z", items: [
  { id: "gn-ua-ukraine-2026111822", country: "UA", place: "Ukraine", figure: { n: 41000, unit: "customers", by: "antikor" }, first_seen: "2026-11-18T22:00:00Z", last_seen: "2026-11-20T09:00:00Z", publishers: [pub("A", "a.example"), pub("B", "b.example")] },
  { id: "gn-au-adelaide-2026111822", country: "AU", place: "Adelaide", figure: { n: 23000, unit: "customers", by: "x" }, first_seen: "2026-11-18T22:00:00Z", last_seen: "2026-11-19T09:00:00Z", publishers: [pub("C", "c.example")] },
  { id: "gn-jp-akita-2026111916", country: "JP", place: "Akita", figure: { n: 300, unit: "homes", by: "y" }, first_seen: "2026-11-19T16:00:00Z", last_seen: "2026-11-19T18:00:00Z", publishers: [pub("D", "d.example"), pub("E", "e.example"), pub("F", "f.example")] },
  { id: "gn-ng-lagos-2026112001", country: "NG", place: "Lagos", figure: null, first_seen: "2026-11-20T01:00:00Z", last_seen: "2026-11-20T02:00:00Z", publishers: [pub("G", "g.example"), pub("H", "h.example"), pub("I", "i.example")] },
  { id: "gn-ng-abuja-2026112001", country: "NG", place: "Abuja", figure: null, first_seen: "2026-11-20T01:00:00Z", last_seen: "2026-11-20T02:00:00Z", publishers: [pub("J", "j.example")] },
  // big, two publishers: the grid desk takes it (newsCandidates), so the outage desk leaves it
  { id: "gn-za-gauteng-2026112003", country: "ZA", place: "Gauteng", figure: { n: 90000, unit: "customers", by: "z" }, first_seen: "2026-11-20T03:00:00Z", last_seen: "2026-11-20T05:00:00Z", publishers: [pub("K", "k.example"), pub("L", "l.example")] },
  // an operator incident is open in Canada: the operator's feed covers it
  { id: "gn-ca-quebec-2026112003", country: "CA", place: "Quebec", figure: { n: 30000, unit: "customers", by: "q" }, first_seen: "2026-11-20T03:00:00Z", last_seen: "2026-11-20T05:00:00Z", publishers: [pub("M", "m.example")] },
] };
const incidents = { open: [{ id: "grid-hydroquebec-quebec-202611200300", source: "hydroquebec", country: "CA" }], closed: [] };
const ioda = { fetched_at: "2026-11-20T17:30:00Z", items: [
  { code: "FI", name: "Finland", map_name: "Finland", score: 57709, events: 1, signals: ["gtr"], url: "https://ioda.inetintel.cc.gatech.edu/country/FI" },
  { code: "VI", name: "Us Virgin Islands", map_name: "", score: 32986844, events: 3, signals: ["ping-slash24", "bgp"], url: "https://ioda.inetintel.cc.gatech.edu/country/VI" },
  { code: "NG", name: "Nigeria", map_name: "Nigeria", score: 698, events: 3, signals: ["bgp"], url: "https://ioda.inetintel.cc.gatech.edu/country/NG" },
  { code: "BE", name: "Belgium", map_name: "Belgium", score: 90000, events: 1, signals: ["bgp", "gtr"], url: "https://ioda.inetintel.cc.gatech.edu/country/BE" },
] };
const events = [{ id: "proximus-mobile-outage-2026-11", category: "outage", country: "Belgium", date: "2026-11-20", org: "Proximus", title: "Proximus mobile network disrupted", sources: [{ name: "La Libre", url: "https://www.lalibre.be/x" }] },
  { id: "github-actions-outage-2026-11", category: "outage", country: "United States", date: "2026-11-20", org: "GitHub", title: "GitHub Actions outage", sources: [{ name: "GitHub", url: "https://www.githubstatus.com/incidents/old" }] }];
const leads = [
  { kind: "status", source: "Cloudflare status", tier: "vendor", title: "Cloudflare outage: Dashboard and API issues in EU region", url: "https://www.cloudflarestatus.com/incidents/iysf3fasf7wn", published: "2026-11-20T17:24:29Z", summary: "major impact" },
  { kind: "status", source: "Cloudflare status", title: "Cloudflare outage: older", url: "https://www.cloudflarestatus.com/incidents/older", published: "2026-11-17T10:00:00Z" },
  { kind: "status", source: "GitHub status", title: "GitHub outage: Actions delayed", url: "https://www.githubstatus.com/incidents/new1", published: "2026-11-20T12:00:00Z" },
  { kind: "news", source: "x", title: "not a status row", url: "https://x.example/a", published: "2026-11-20T12:00:00Z" },
];
const lists = () => ({ power: powerItems(news, incidents, {}, new Set(), {}, { research_customers: 50000 }), internet: internetItems(ioda, events, {}, NOW), service: serviceItems(leads, events, new Set(), {}, NOW) });

test("power: figure first; grid-desk items, covered countries and small stated figures left out", () => {
  const p = lists().power.map((x) => x.id);
  assert.deepEqual(p, ["pw-gn-ua-ukraine-2026111822", "pw-gn-au-adelaide-2026111822", "pw-gn-ng-lagos-2026112001"]);
  assert.ok(!p.includes("pw-gn-za-gauteng-2026112003"), "the grid desk checks this one");
  assert.ok(!p.includes("pw-gn-ca-quebec-2026112003"), "an operator incident covers Canada");
  assert.ok(!p.includes("pw-gn-jp-akita-2026111916"), "300 homes is local news");
  assert.ok(!p.includes("pw-gn-ng-abuja-2026112001"), "one publisher and no figure");
  // a grid-desk result on file also leaves it out, and so does a page an event cites
  assert.ok(!powerItems(news, incidents, { "grid-news-gn-ua-ukraine-2026111822": { decision: "weather" } }, new Set(), {}, {}).some((x) => x.id === "pw-gn-ua-ukraine-2026111822"));
  assert.ok(!powerItems(news, incidents, {}, new Set(["https://c.example/news/2026/11/20/power-cut"]), {}, {}).some((x) => x.id === "pw-gn-au-adelaide-2026111822"));
});
test("internet: strong signals only, strongest first; a country with an outage event is matched already", () => {
  const n = lists().internet;
  assert.deepEqual(n.map((x) => x.id), ["net-vi-20261120", "net-fi-20261120"]);
  assert.equal(n[0].key, "net-vi");
  assert.ok(internetItems(ioda, [], {}, NOW).some((x) => x.id === "net-be-20261120"), "Belgium without its event");
});
test("service: status leads only, last 48 h, newest first; cited pages and same-day provider events left out", () => {
  const s = lists().service;
  assert.deepEqual(s.map((x) => x.url), ["https://www.cloudflarestatus.com/incidents/iysf3fasf7wn"]);
  assert.equal(s[0].provider, "Cloudflare"); assert.match(s[0].id, /^svc-[0-9a-f]{12}$/);
  assert.equal(serviceItems(leads, events, new Set(["https://www.cloudflarestatus.com/incidents/iysf3fasf7wn"]), {}, NOW).length, 0);
});
test("queue: the kinds take turns (service, internet, power), each in its own order", () => {
  const q = queue(lists(), {}, {}, NOW);
  assert.deepEqual(q.map((x) => x.kind), ["service", "internet", "power", "internet", "power", "power"]);
  assert.equal(q[1].id, "net-vi-20261120"); assert.equal(q[2].id, "pw-gn-ua-ukraine-2026111822");
});
test("due: never re-checked within recheck_hours (same key too), final results done, leases respected", () => {
  const it = { id: "net-vi-20261121", key: "net-vi" };
  assert.equal(due(it, { "net-vi-20261120": { key: "net-vi", decision: "not_confirmed", checked_at: iso(NOW - 2 * 36e5), tries: 1 } }, {}, NOW), false, "another day of the same country, 2 h ago");
  assert.equal(due(it, { "net-vi-20261120": { key: "net-vi", decision: "not_confirmed", checked_at: iso(NOW - 13 * 36e5), tries: 1 } }, {}, NOW), true, "13 h ago: due again");
  assert.equal(due(it, { [it.id]: { key: "net-vi", decision: "confirmed", final: true, checked_at: iso(NOW - 48 * 36e5), tries: 1 } }, {}, NOW), false);
  assert.equal(due(it, { [it.id]: { key: "net-vi", decision: "not_confirmed", final: false, checked_at: iso(NOW - 48 * 36e5), tries: 2 } }, {}, NOW), false, "max_tries");
  const lease = (run, min) => ({ [`outage:${it.id}`]: { run, until: iso(NOW + min * 6e4) } });
  assert.equal(due(it, {}, lease("other", 10), NOW), false);
  assert.equal(due(it, {}, lease("other", -1), NOW), true);
  assert.equal(due(it, {}, lease("me", 10), NOW, { run: "me" }), true);
});
test("the recheck gate: a key that keeps coming back not confirmed waits twice as long each time, unless the report is stronger", () => {
  const it = { id: "net-vi-20261123", key: "net-vi", kind: "internet", score: 12000, signals: ["bgp"] }, ago = (hrs) => iso(NOW - hrs * 36e5);
  const nc = (hrs, tries, seen) => ({ key: "net-vi", decision: "not_confirmed", checked_at: ago(hrs), tries, final: tries >= 2, ...(seen ? { seen } : {}) });
  // two days of the same country, each tried twice: 4 not_confirmed in a row -> 12 h x 2^3 = 96 h
  const four = { "net-vi-20261121": nc(60, 2), "net-vi-20261122": nc(30, 2) };
  assert.equal(due(it, four, {}, NOW), false, "30 h after the fourth not_confirmed: not yet (was: due after 12 h)");
  const w = dueWhy(it, four, {}, NOW);
  assert.equal(w.why, "wait"); assert.equal(w.next_at, iso(NOW - 30 * 36e5 + 96 * 36e5)); assert.match(w.reason, /^skipped: nothing new since .*not confirmed 4 times in a row\)$/);
  assert.equal(due(it, { "net-vi-20261121": nc(160, 2), "net-vi-20261122": nc(97, 2) }, {}, NOW), true, "the wait is over");
  assert.equal(due(it, { a: nc(400, 2), b: nc(300, 2), c: nc(200, 2), "net-vi-20261122": nc(169, 2) }, {}, NOW), true, "never longer than recheck_max_hours (7 days)");
  // a confirmed check on the key ends the run: back to the base wait
  assert.equal(due(it, { "net-vi-20261121": nc(60, 2), "net-vi-20261122": { key: "net-vi", decision: "confirmed", checked_at: ago(13), tries: 1, final: true } }, {}, NOW), true);
  // stronger than what the last check saw: at once
  assert.equal(due(it, { "net-vi-20261122": nc(3, 2, { score: 5000, publishers: 0, figure: 0, cyber: false }) }, {}, NOW), true, "the score more than doubled");
  assert.equal(dueWhy(it, { "net-vi-20261122": nc(3, 2, { score: 5000 }) }, {}, NOW).why, "stronger");
  assert.equal(due(it, { "net-vi-20261122": nc(3, 2, { score: 11000, publishers: 0, figure: 0, cyber: false }) }, {}, NOW), false, "about the same signal");
  assert.equal(due(it, { "net-vi-20261122": nc(3, 2) }, {}, NOW), false, "a check from before `seen` existed cannot be compared");
  // held back is counted with the time it is due, and a new check remembers what it saw
  const hb = heldBack({ internet: [it] }, four, {}, NOW);
  assert.equal(hb.waiting.length, 1); assert.equal(hb.next_due_at, w.next_at);
  const e = entryFor({ id: it.id, decision: "not_confirmed", summary: "IODA shows a dip; no operator or government statement was found.", sources: [], read_depth: "secondary" }, it, null, "op-1", NOW);
  assert.deepEqual(e.seen, { score: 12000, publishers: 0, figure: 0, cyber: false, last_seen: "" });
});
test("plan: batches of K for N checkers, stable plan id, a new id on a retry", () => {
  const q = queue(lists(), {}, {}, NOW), p = makePlan(q, {}, 2, 2, "c1");
  assert.equal(p.batches.length, 2); assert.equal(p.batches[0].items.length, 2); assert.equal(p.batches[0].out, "outage-out-c1-1.json");
  assert.match(p.plan_id, /^op-[0-9a-f]{16}$/); assert.equal(makePlan(q, {}, 2, 2, "c1").plan_id, p.plan_id);
  const again = makePlan(q, { [q[0].id]: { decision: "not_confirmed", summary: "s", tries: 1, sources: [] } }, 2, 2, "c1");
  assert.notEqual(again.plan_id, p.plan_id); assert.equal(planId(again.batches), again.plan_id);
  assert.ok(!("rank" in p.batches[0].items[0]));
});

const q0 = queue(lists(), {}, {}, NOW), PLAN = makePlan(q0, {}, 1, 8, "t"), [SVC, NET, PW] = q0;
const ok = (o) => ({ id: PW.id, decision: "confirmed", summary: "Ukrenergo said strikes cut power to 41,000 customers.", publisher: "Ukrenergo", cause: "", figures: "about 41,000 customers", sources: ["https://www.ukrinform.net/rubric-society/1.html", "https://www.kyivindependent.com/power-2/"], read_depth: "full", ...o });
const out = (results, o = {}) => ({ plan_id: PLAN.plan_id, batch: 1, results, ...o });
const rest = (except) => q0.filter((x) => !except.includes(x.id)).map((x) => ({ id: x.id, decision: "not_confirmed", summary: "No report from the operator or national press.", sources: [], read_depth: "summary" }));
const evMap = new Map(events.map((e) => [e.id, e]).concat([["power-event-2026-11", { id: "power-event-2026-11", category: "incident" }]]));

test("validate: a file for another plan, an unplanned id or a repeated id is refused outright", () => {
  assert.match(validate(PLAN, out([], { plan_id: "op-nope" })).errors.join(), /does not match/);
  assert.match(validate(PLAN, out([ok({ id: "pw-gn-xx-nowhere-1" })])).errors.join(), /was not planned/);
  assert.match(validate(PLAN, out([ok(), ok()])).errors.join(), /appears 2 times/);
  assert.match(validate(null, out([])).errors.join(), /no plan/);
});
test("validate: a valid file passes; a missing result is reported", () => {
  const v = validate(PLAN, out([ok(), ...rest([PW.id])]), evMap, NOW); assert.ok(v.ok, JSON.stringify(v.bad)); assert.equal(v.good.length, q0.length);
  const w = validate(PLAN, out([ok()]), evMap, NOW); assert.equal(w.ok, false); assert.match(w.bad[SVC.id][0], /no result/);
});
test("validate: decisions outside the set, missing or bad sources, empty summary, bad times", () => {
  const bad = (o) => validate(PLAN, out([ok(o), ...rest([PW.id])]), evMap, NOW).bad[PW.id] || [];
  assert.match(bad({ decision: "weather" }).join(), /not one of confirmed, not_confirmed, cyber_lead/);
  assert.match(bad({ sources: [] }).join(), /confirmed needs the operator's/);
  assert.match(bad({ sources: ["https://www.ukrinform.net/a"] }).join(), /two independent credible publishers/);
  assert.match(bad({ sources: ["https://www.ukrinform.net/a", "https://ioda.inetintel.cc.gatech.edu/country/UA"] }).join(), /two independent/, "IODA is a measurement, not a confirmation");
  assert.match(bad({ sources: ["https://news.google.com/rss/articles/x", "https://b.example/x"] }).join(), /search-engine redirect/);
  assert.match(bad({ sources: ["https://a.example/", "https://b.example/x"] }).join(), /front page/);
  assert.match(bad({ sources: "https://a.example/x" }).join(), /sources is not an array/);
  assert.match(bad({ summary: " " }).join(), /summary is empty/);
  assert.match(bad({ publisher: "" }).join(), /needs publisher/);
  assert.match(bad({ read_depth: "skimmed" }).join(), /read_depth/);
  assert.match(bad({ started_at: "yesterday" }).join(), /started_at must be a UTC time/);
  assert.match(bad({ ended_at: "2026-11-21T10:00:00Z" }).join(), /ended_at must be a UTC time.*not in the future/);
  assert.deepEqual(bad({ started_at: "2026-11-20T06:10:00Z" }), []);
  // a government page alone is enough
  assert.deepEqual(bad({ sources: ["https://www.energy.gov.ua/en/news/1"] }), []);
});
test("validate: an attack named outside a cyber_lead is refused; a cited denial is allowed", () => {
  const bad = (o) => validate(PLAN, out([ok(o), ...rest([PW.id])]), evMap, NOW).bad[PW.id] || [];
  assert.match(bad({ summary: "A cyberattack on the grid operator cut power to 41,000 customers." }).join(), /names an attack/);
  assert.match(bad({ cause: "hackers" }).join(), /names an attack/);
  assert.deepEqual(bad({ summary: "Ukrenergo said strikes cut power; it ruled out a cyberattack." }), []);
  const nr = validate(PLAN, out([...rest([]).map((r) => (r.id === PW.id ? { ...r, summary: "The operator said it was not a cyberattack." } : r))]), evMap, NOW).bad[PW.id] || [];
  assert.match(nr.join(), /cite the page/);
});
test("validate: a cyber_lead needs a page, who said it, and an official page when said_by is official", () => {
  const lead = (o) => validate(PLAN, out([ok({ decision: "cyber_lead", said_by: "reported", summary: "Kyiv Independent reported a cyberattack on the operator; the operator has not confirmed this.", ...o }), ...rest([PW.id])]), evMap, NOW).bad[PW.id] || [];
  assert.deepEqual(lead({}), []);
  assert.match(lead({ said_by: "official" }).join(), /attack claim said_by official needs a source on a government/);
  assert.deepEqual(lead({ said_by: "official", sources: ["https://cert.gov.ua/article/1"] }), []);
  assert.match(lead({ said_by: undefined }).join(), /needs said_by/);
  assert.match(lead({ summary: "Hackers took the grid down." }).join(), /must say in the summary that it is unconfirmed/);
  assert.match(lead({ sources: [] }).join(), /needs the page that reports the cyber cause/);
});
test("validate: event_id only for a confirmed internet or service outage that is on file as an outage event", () => {
  const svc = (o) => validate(PLAN, out([{ id: SVC.id, decision: "confirmed", summary: "Cloudflare's status page reported a major incident.", publisher: "Cloudflare", sources: [SVC.url], read_depth: "full", ...o }, ...rest([SVC.id])]), evMap, NOW).bad[SVC.id] || [];
  assert.deepEqual(svc({}), [], "the provider's own status page confirms it");
  assert.deepEqual(svc({ event_id: "proximus-mobile-outage-2026-11" }), []);
  assert.match(svc({ event_id: "no-such-event-2026-11" }).join(), /not on file/);
  assert.match(svc({ event_id: "power-event-2026-11" }).join(), /category incident, not outage/);
  assert.match(svc({ decision: "not_confirmed", event_id: "proximus-mobile-outage-2026-11" }).join(), /only with a confirmed/);
  const pw = validate(PLAN, out([ok({ event_id: "proximus-mobile-outage-2026-11" }), ...rest([PW.id])]), evMap, NOW).bad[PW.id] || [];
  assert.match(pw.join(), /power outage is grid context and never an event/);
  assert.ok(officialFor(SVC.url, SVC)); assert.ok(!officialFor("https://www.cloudflarestatus.com/x", NET));
});
test("apply: records each check once (idempotent), a cyber_lead becomes one lead, finality and tries", () => {
  const results = [ok({ decision: "cyber_lead", said_by: "official", sources: ["https://cert.gov.ua/article/1"], summary: "CERT-UA said a cyberattack contributed to the outage." }), ...rest([PW.id])];
  const v = validate(PLAN, out(results), evMap, NOW); assert.ok(v.ok, JSON.stringify(v.bad));
  const r = applyResults({}, PLAN, v.good, new Set(), NOW);
  assert.equal(r.changed.length, q0.length); assert.equal(r.leads.length, 1);
  const l = r.leads[0]; assert.equal(l.via, "outage-desk"); assert.equal(l.tier, "gov"); assert.equal(l.outage_id, PW.id); assert.equal(l.url, "https://cert.gov.ua/article/1");
  assert.match(l.title, /^Outage linked to a cyberattack \(official\): /);
  assert.equal(r.checks[PW.id].final, true); assert.equal(r.checks[PW.id].by, BY); assert.equal(r.checks[SVC.id].final, false, "not_confirmed is checked again later");
  assert.equal(r.checks[NET.id].key, "net-vi");
  const r2 = applyResults(r.checks, PLAN, v.good, new Set([PW.id]), NOW + 6e4); assert.equal(r2.changed.length, 0); assert.equal(r2.leads.length, 0);
  const e = entryFor(ok(), PW, { tries: 1, plan_id: "op-old" }, "op-new", NOW, { max_tries: 2 }); assert.equal(e.tries, 2); assert.equal(e.cause, "cause not stated");
  assert.equal(entryFor({ ...ok(), decision: "not_confirmed" }, PW, { tries: 1, plan_id: "op-old" }, "op-new", NOW, { max_tries: 2 }).final, true, "final at max_tries");
  assert.equal(leadFor(PW, { said_by: "reported", sources: ["https://www.kyivindependent.com/x"], checked_at: iso(NOW), summary: "s" }).tier, "news");
});
test("site and status: what the page shows, the newest IODA check, the queue numbers", () => {
  const c = { decision: "confirmed", summary: "s", publisher: "Ukrenergo", sources: ["https://ioda.inetintel.cc.gatech.edu/country/UA", "https://www.ukrinform.net/a"], checked_at: iso(NOW), key: "net-ua" };
  const v = siteCheck(c); assert.equal(v.by, BY); assert.equal(v.url, "https://www.ukrinform.net/a", "never the measurement page"); assert.equal(v.publisher, "Ukrenergo");
  assert.equal(siteCheck({ decision: "weather" }), null); assert.equal(siteCheck(null), null);
  assert.equal(siteCheck({ ...c, decision: "cyber_lead", said_by: "x" }).said_by, "reported");
  const checks = { a: { ...c, checked_at: iso(NOW - 36e5) }, b: { ...c, decision: "not_confirmed", checked_at: iso(NOW - 2 * 36e5) }, old: { ...c, checked_at: iso(NOW - 72 * 36e5) } };
  assert.equal(latestFor(checks, "net-ua", NOW).checked_at, iso(NOW - 36e5)); assert.equal(latestFor(checks, "net-xx", NOW), null);
  const st = stats(q0, checks, NOW); assert.equal(st.waiting, q0.length); assert.equal(st.checked_24h, 2); assert.equal(st.by_kind.power, 3);
  assert.deepEqual(DECISIONS, ["confirmed", "not_confirmed", "cyber_lead"]);
});

// end to end in a scratch copy: plan (leases), apply, apply again; the second apply changes no file
test("CLI: plan --dry-run writes nothing; plan, apply and apply again; a bad file is refused", () => {
  const here = dirname(fileURLToPath(import.meta.url)), repo = join(here, "..", ".."), t = mkdtempSync(join(tmpdir(), "outage-desk-"));
  for (const d of ["scripts/lib", "data/grid", "data/context", "data/leads", "data/events/2026-11", "config"]) mkdirSync(join(t, d), { recursive: true });
  for (const f of ["scripts/outage-desk.mjs", "scripts/grid-desk.mjs", "scripts/grid.mjs", "scripts/lib/store.mjs", "scripts/lib/lease.mjs", "scripts/lib/net.mjs", "scripts/lib/gates.mjs"]) copyFileSync(join(repo, f), join(t, f));
  const now = Date.now(), day = iso(now).slice(0, 10);
  writeFileSync(join(t, "data", "context", "ioda.json"), JSON.stringify({ ...ioda, fetched_at: iso(now) }));
  writeFileSync(join(t, "data", "leads", `${day}.jsonl`), JSON.stringify({ ...leads[0], published: iso(now - 36e5) }) + "\n");
  writeFileSync(join(t, "data", "status.json"), "{}\n"); writeFileSync(join(t, "config", "pipeline.json"), JSON.stringify({ outage_desk: { recheck_hours: 12 } }));
  const run = (...a) => spawnSync("node", ["scripts/outage-desk.mjs", ...a], { cwd: t, encoding: "utf8", env: { ...process.env, CYBERVIEW_RUN: "run-test" } });
  const d = run("plan", "--dry-run"); assert.equal(d.status, 0, d.stderr); assert.match(d.stdout, /dry run.*4 waiting \(0 power, 3 internet, 1 service\)/);
  assert.ok(!existsSync(join(t, "data", "leases.json")) && !existsSync(join(t, "data", "outage-plan.json")), "a dry run leases and writes nothing");
  const p = run("plan", "--max", "1", "--per", "2", "--file", "outage-plan-t.json"); assert.equal(p.status, 0, p.stderr); assert.match(p.stdout, /2 report\(s\) for 1 outage checker/);
  const pl = JSON.parse(readFileSync(join(t, "data", "outage-plan-t.json"), "utf8")), ids = pl.batches[0].items.map((i) => i.id);
  assert.ok(JSON.parse(readFileSync(join(t, "data", "leases.json"), "utf8"))[`outage:${ids[0]}`]);
  assert.equal(pl.batches[0].out, "outage-out-t-1.json");
  writeFileSync(join(t, "data", pl.batches[0].out), JSON.stringify({ plan_id: pl.plan_id, batch: 1, results: [
    { id: ids[0], decision: "confirmed", summary: "Cloudflare's status page reported dashboard and API errors in the EU region.", publisher: "Cloudflare", sources: [pl.batches[0].items[0].url], read_depth: "full" },
    { id: ids[1], decision: "cyber_lead", said_by: "reported", publisher: "Example News", summary: "Example News reported a DDoS attack; the operator has not confirmed this.", sources: ["https://news.example/2026/ddos"], read_depth: "full" }] }));
  const a1 = run("apply", pl.batches[0].out); assert.equal(a1.status, 0, a1.stderr + a1.stdout); assert.match(a1.stdout, /2 recorded, 0 already on file, 0 rejected, 1 cyber lead/);
  const snap = () => Object.fromEntries(["data/outages/checks.json", "data/status.json", "data/leases.json", ...readdirSync(join(t, "data", "leads")).map((f) => "data/leads/" + f)].map((f) => [f, existsSync(join(t, f)) ? readFileSync(join(t, f), "utf8") : null]));
  const s1 = snap();
  assert.equal(JSON.parse(s1["data/status.json"]).last_outage_at.length, 20);
  assert.ok(!JSON.parse(s1["data/leases.json"])[`outage:${ids[0]}`], "lease released");
  assert.equal(s1[`data/leads/${day}.jsonl`].trim().split("\n").filter((l) => l.includes('"outage-desk"')).length, 1);
  const a2 = run("apply", pl.batches[0].out); assert.equal(a2.status, 0); assert.match(a2.stdout, /0 recorded, 2 already on file/);
  assert.deepEqual(snap(), s1);
  // the checked reports are no longer waiting
  assert.match(run("status").stdout, /^OUTAGE DESK: 2 waiting/);
  writeFileSync(join(t, "data", "outage-out-x.json"), JSON.stringify({ plan_id: "op-nope", batch: 1, results: [] }));
  assert.equal(run("apply", "outage-out-x.json").status, 1);
});
