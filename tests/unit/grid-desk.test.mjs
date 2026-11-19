import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { candidates, planId, makePlan, validate, applyResults, entryFor, badSource, officialHost, leadFor, BY } from "../../scripts/grid-desk.mjs";

const NOW = Date.parse("2026-11-19T18:00:00Z");
const inc = (o) => ({ id: "grid-hydroquebec-quebec-202611191200", source: "hydroquebec", country: "CA", region: "Quebec", kind: "outage", name: "Hydro-Québec: 152,300 customers without power",
  opened_at: "2026-11-19T12:00:00Z", updated_at: "2026-11-19T17:00:00Z", closed_at: "", customers: 120000, peak_customers: 152300, peak_at: "2026-11-19T14:00:00Z", level: null,
  planned_share: 0, causes: [{ cause: "Under investigation", customers: 90000 }], lat: 46.8, lng: -71.2, url: "https://www.hydroquebec.com/outages/", research_needed: true, research_reason: "big", ...o });
const A = inc(), B = inc({ id: "grid-bchydro-bc-202611191300", source: "bchydro", name: "BC Hydro: 60,000 customers without power", peak_customers: 60000, customers: 60000, url: "https://www.bchydro.com/outages" });
const C = inc({ id: "grid-eskom-za-202611190600", source: "eskom", kind: "load_shedding", name: "Eskom: load-shedding stage 4", peak_customers: null, customers: null, level: 4, url: "https://loadshedding.eskom.co.za/" });
const incidents = { updated_at: "2026-11-19T17:00:00Z", open: [B, C], closed: [A] };
const iso = (ms) => new Date(ms).toISOString();

test("candidates: research_needed only, biggest first, open and closed", () => {
  const c = candidates({ open: [B, C, inc({ id: "grid-ukpn-london-202611191000", research_needed: false })], closed: [A] }, {}, {}, NOW);
  assert.deepEqual(c.map((x) => x.id), [A.id, B.id, C.id]);
});
test("candidates: a live lease of another run hides an incident; an expired one or our own does not", () => {
  const lease = (run, min) => ({ [`grid:${A.id}`]: { run, until: iso(NOW + min * 6e4) } });
  assert.ok(!candidates(incidents, {}, lease("other", 10), NOW).some((x) => x.id === A.id));
  assert.ok(candidates(incidents, {}, lease("other", -1), NOW).some((x) => x.id === A.id));
  assert.ok(candidates(incidents, {}, lease("me", 10), NOW, { run: "me" }).some((x) => x.id === A.id));
});
test("candidates: final results are done; not-final ones come back when next_at is due, until max_tries", () => {
  const r = (o) => ({ [A.id]: { decision: "unknown", tries: 1, final: false, next_at: iso(NOW + 36e5), ...o } });
  assert.ok(!candidates(incidents, r({ decision: "weather", final: true, next_at: "" }), {}, NOW).some((x) => x.id === A.id), "final");
  assert.ok(!candidates(incidents, r(), {}, NOW).some((x) => x.id === A.id), "retry not due");
  assert.ok(candidates(incidents, r({ next_at: iso(NOW - 1) }), {}, NOW).some((x) => x.id === A.id), "retry due");
  assert.ok(!candidates(incidents, r({ next_at: iso(NOW - 1), tries: 3 }), {}, NOW, { max_tries: 3 }).some((x) => x.id === A.id), "max tries");
});

test("plan: batches of at most per, plan_id stable for the same assignment and different for another", () => {
  const c = candidates(incidents, {}, {}, NOW), p1 = makePlan(c, {}, 2, 2, "c1"), p2 = makePlan(c, {}, 2, 2, "c2");
  assert.equal(p1.batches.length, 2); assert.equal(p1.batches[0].incidents.length, 2); assert.equal(p1.batches[0].out, "grid-out-c1-1.json");
  assert.equal(p1.plan_id, p2.plan_id);
  assert.equal(planId([[{ id: "grid-a-x-1" }], [{ id: "grid-b-x-1" }]]), planId([[{ id: "grid-a-x-1" }], [{ id: "grid-b-x-1" }]]));
  assert.notEqual(makePlan(c, {}, 1, 4).plan_id, p1.plan_id);
  assert.equal(makePlan([], {}, 2, 4).batches.length, 0);
  assert.equal(p1.batches[0].incidents[0].earlier, null);
});

const plan = { plan_id: "gp-test", batches: [{ batch: 1, out: "grid-out-t-1.json", incidents: [A, B].map((i) => ({ id: i.id, name: i.name, url: i.url })) }] };
const ok = (o) => ({ id: A.id, decision: "equipment", cause_summary: "Hydro-Québec said a transformer failure at a substation caused the outage.", sources: ["https://news.hydroquebec.com/en/press-releases/1234/outage"], read_depth: "full", ...o });
const okB = (o) => ok({ id: B.id, decision: "weather", sources: ["https://www.bchydro.com/news/press_centre/news_releases/2026/storm.html"], ...o });
const out = (results, o) => ({ plan_id: "gp-test", batch: 1, results, ...o });

test("validate: a good out file passes", () => {
  const v = validate(plan, out([ok(), okB()]));
  assert.equal(v.ok, true, JSON.stringify(v)); assert.equal(v.good.length, 2);
});
test("validate: file-level rejections (plan_id, unplanned, duplicate, not an array)", () => {
  assert.match(validate(plan, out([ok(), okB()], { plan_id: "gp-other" })).errors.join(), /plan_id/);
  assert.match(validate(plan, out([ok(), okB(), ok({ id: "grid-x-y-1" })])).errors.join(), /not planned/);
  assert.match(validate(plan, out([ok(), ok(), okB()])).errors.join(), /2 times/);
  assert.match(validate(plan, out("nope")).errors.join(), /not an array/);
  assert.match(validate(null, out([])).errors.join(), /no plan/);
});
test("validate: entry-level rejections, one rule at a time", () => {
  const bad = (r) => validate(plan, out([r, okB()])).bad[A.id]?.join(" ") || "";
  assert.match(validate(plan, out([okB()])).bad[A.id].join(), /no result/);
  assert.match(bad(ok({ decision: "attack" })), /decision/);
  assert.match(bad(ok({ cause_summary: "x".repeat(301) })), /301 characters/);
  assert.match(bad(ok({ cause_summary: " " })), /empty/);
  assert.match(bad(ok({ sources: ["http://news.hydroquebec.com/a"] })), /not https/);
  assert.match(bad(ok({ sources: ["https://www.hydroquebec.com/"] })), /front page/);
  assert.match(bad(ok({ sources: ["https://www.hydroquebec.com"] })), /front page/);
  assert.match(bad(ok({ sources: ["https://news.google.com/rss/articles/abc"] })), /redirect/);
  assert.match(bad(ok({ sources: ["https://www.bing.com/news/apiclick.aspx?x=1"] })), /redirect/);
  assert.match(bad(ok({ sources: [] })), /no sources/);
  assert.equal(bad(ok({ decision: "unknown", sources: [], cause_summary: "No cause statement found on the operator's site or in reporting." })), "");
  assert.match(bad(ok({ read_depth: "skim" })), /read_depth/);
  assert.match(bad(ok({ decision: "cyber_official", sources: ["https://www.example-news.com/2026/grid-hack"] })), /operator, regulator or government/);
  assert.equal(bad(ok({ decision: "cyber_official", sources: ["https://www.example-news.com/2026/grid-hack", "https://www.cisa.gov/news-events/alerts/2026/x"] })), "");
  assert.equal(bad(ok({ decision: "cyber_official", sources: ["https://nouvelles.hydroquebec.com/fr/communiques/1"] })), "", "the operator's own host");
  assert.equal(bad(ok({ decision: "cyber_reported", sources: ["https://www.example-news.com/2026/grid-hack"] })), "");
});
test("badSource and officialHost", () => {
  assert.equal(badSource("https://www.ofgem.gov.uk/press-release/x"), "");
  assert.match(badSource("not a url"), /not a URL/);
  assert.ok(officialHost("https://www.energy.gov/ceser/x")); assert.ok(officialHost("https://www.cyber.gc.ca/en/news/x")); assert.ok(officialHost("https://www.aemo.com.au/newsroom/x"));
  assert.ok(!officialHost("https://www.reuters.com/world/x"));
  assert.ok(!officialHost("https://evil-hydroquebec.example.com/x")); assert.ok(!officialHost("https://hydroquebec.example.com/x"));
  assert.ok(officialHost("https://news.hydroquebec.com/x")); assert.ok(officialHost("https://www.eskom.co.za/x")); assert.ok(officialHost("https://www.ukpowernetworks.co.uk/x"));
});

test("apply: final and retry fields, labelled, idempotent", () => {
  const v = validate(plan, out([ok(), okB({ decision: "under_investigation" })]));
  const r1 = applyResults({}, plan, v.good, new Set(), NOW, { retry_hours: 6, max_tries: 3 });
  assert.deepEqual(r1.changed, [A.id, B.id]);
  assert.equal(r1.research[A.id].final, true); assert.equal(r1.research[A.id].next_at, ""); assert.equal(r1.research[A.id].tries, 1); assert.equal(r1.research[A.id].by, BY);
  assert.equal(r1.research[B.id].final, false); assert.equal(r1.research[B.id].next_at, "2026-11-20T00:00:00Z");
  const r2 = applyResults(r1.research, plan, v.good, new Set(), NOW + 6e4);
  assert.deepEqual(r2.changed, []); assert.deepEqual(r2.research, r1.research); assert.equal(r2.leads.length, 0);
  const third = entryFor(okB({ decision: "unknown" }), { tries: 2, plan_id: "gp-earlier" }, "gp-later", NOW, { max_tries: 3 });
  assert.equal(third.final, true, "final after max_tries"); assert.equal(third.next_at, "");
});
test("apply: a cyber cause becomes ONE lead, with the right label and tier", () => {
  const v = validate(plan, out([ok({ decision: "cyber_official", sources: ["https://news.hydroquebec.com/en/press-releases/9/cyberattack"] }), okB({ decision: "cyber_reported", sources: ["https://www.example-news.com/2026/bc-grid"] })]));
  const ids = new Set(), r1 = applyResults({}, plan, v.good, ids, NOW);
  assert.equal(r1.leads.length, 2);
  const [la, lb] = r1.leads;
  assert.equal(la.title, `Grid outage linked to a cyberattack (official): ${A.name}`); assert.equal(la.tier, "gov"); assert.equal(la.via, "grid-desk"); assert.equal(la.url, "https://news.hydroquebec.com/en/press-releases/9/cyberattack"); assert.equal(la.grid_id, A.id);
  assert.match(lb.title, /\(reported, unconfirmed\): BC Hydro/); assert.equal(lb.tier, "news");
  // a later plan for the same incident (or the same file again) never files a second lead
  const again = applyResults({}, { ...plan, plan_id: "gp-test-2" }, v.good, ids, NOW);
  assert.equal(again.leads.length, 0);
  assert.equal(leadFor(A, { decision: "cyber_reported", sources: ["https://x.example/a"], checked_at: "2026-11-19T18:00:00Z", cause_summary: "s" }).source, "x.example");
});

// end to end in a scratch copy: plan, apply, apply again; the second apply changes no file
test("CLI: plan, apply and apply again changes nothing; one lead", () => {
  const here = dirname(fileURLToPath(import.meta.url)), repo = join(here, "..", ".."), t = mkdtempSync(join(tmpdir(), "grid-desk-"));
  mkdirSync(join(t, "scripts", "lib"), { recursive: true }); mkdirSync(join(t, "data", "grid"), { recursive: true }); mkdirSync(join(t, "config"), { recursive: true });
  for (const f of ["scripts/grid-desk.mjs", "scripts/lib/store.mjs", "scripts/lib/lease.mjs"]) copyFileSync(join(repo, f), join(t, f));
  writeFileSync(join(t, "data", "grid", "incidents.json"), JSON.stringify({ updated_at: iso(Date.now()), open: [B], closed: [A] }));
  writeFileSync(join(t, "data", "status.json"), "{}\n"); writeFileSync(join(t, "config", "grid.json"), JSON.stringify({ retry_hours: 6, max_tries: 3 }));
  const run = (...a) => spawnSync("node", ["scripts/grid-desk.mjs", ...a], { cwd: t, encoding: "utf8", env: { ...process.env, CYBERVIEW_RUN: "run-test" } });
  const p = run("plan", "--max", "1", "--per", "4", "--file", "grid-plan-t.json");
  assert.equal(p.status, 0, p.stderr); assert.match(p.stdout, /2 incident\(s\) for 1 grid worker/);
  const pl = JSON.parse(readFileSync(join(t, "data", "grid-plan-t.json"), "utf8"));
  assert.ok(JSON.parse(readFileSync(join(t, "data", "leases.json"), "utf8"))[`grid:${A.id}`]);
  assert.equal(pl.batches[0].out, "grid-out-t-1.json");
  writeFileSync(join(t, "data", pl.batches[0].out), JSON.stringify({ plan_id: pl.plan_id, batch: 1, results: [
    ok({ decision: "cyber_reported", sources: ["https://www.example-news.com/2026/quebec-grid"] }), okB()] }));
  const a1 = run("apply", pl.batches[0].out); assert.equal(a1.status, 0, a1.stderr + a1.stdout); assert.match(a1.stdout, /2 recorded/);
  const snap = () => Object.fromEntries(["data/grid/research.json", "data/status.json", "data/leases.json", ...readdirSync(join(t, "data", "leads")).map((f) => "data/leads/" + f)].map((f) => [f, existsSync(join(t, f)) ? readFileSync(join(t, f), "utf8") : null]));
  const s1 = snap();
  assert.equal(Object.keys(s1).filter((f) => f.startsWith("data/leads/")).map((f) => s1[f].trim().split("\n").length).reduce((x, y) => x + y, 0), 1);
  assert.equal(JSON.parse(s1["data/status.json"]).last_grid_research_at.length, 20);
  assert.ok(!JSON.parse(s1["data/leases.json"])[`grid:${A.id}`], "lease released");
  const a2 = run("apply", pl.batches[0].out); assert.equal(a2.status, 0); assert.match(a2.stdout, /0 recorded, 2 already on file/);
  assert.deepEqual(snap(), s1);
  // a file for another plan is refused outright
  writeFileSync(join(t, "data", "grid-out-x.json"), JSON.stringify({ plan_id: "gp-nope", batch: 1, results: [] }));
  assert.equal(run("apply", "grid-out-x.json").status, 1);
});
