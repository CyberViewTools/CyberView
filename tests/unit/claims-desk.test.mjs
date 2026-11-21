// Unit tests for scripts/claims-desk.mjs: the queue of leak-site claims (parsing, notability order, skip rules, re-checks,
// leases), plan ids, validation of a claims checker's out file (every refusal: leak sites, .onion, claim trackers, front
// pages, confirmations without the victim's or an official page, events with the wrong status, stolen data in text) and apply.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { parseClaim, coreName, claimKey, claimItems, matchedEvent, reportsOf, trackRecord, due, queue, makePlan, planId, validate, applyResults, entryFor,
  siteCheck, checksByEvent, stats, claimSourceProblem, BY, DECISIONS } from "../../scripts/claims-desk.mjs";

const NOW = Date.parse("2026-11-21T12:00:00Z"), iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z"), h = (n) => iso(NOW - n * 36e5);
const claimLead = (group, victim, cc, sector, hoursAgo, extra = {}) => ({ seen_at: h(hoursAgo - 0.2), source: "ransomware.live", tier: "news", via: "ransomware-live",
  title: `Claim: ${group} lists ${victim}${cc ? ` (${cc})` : ""} on its leak site`, url: `https://www.ransomware.live/id/${Buffer.from(victim + group).toString("base64")}`,
  published: h(hoursAgo), summary: `Unverified attacker claim tracked by ransomware.live. Sector: ${sector}.`, kind: "claim", country: cc, ...extra });
const leads = [
  claimLead("qilin", "Shop & Co Retail Ltd", "GB", "Retail & E-Commerce", 3),
  claimLead("akira", "Riverside General Hospital", "US", "Healthcare", 10),
  claimLead("incransom", "Contoso Water Authority", "US", "Not Found", 20),
  claimLead("SilentRansomGroup", "J... W...", "", "Not Found", 5),                  // a masked private person: never queued
  claimLead("everest", "Fabrikam Logistics", "DE", "Transportation", 30),
  claimLead("everest", "Fabrikam Logistics", "DE", "Transportation", 40),           // the same claim seen twice: one item
  claimLead("rhysida", "Northwind Traders", "US", "Hospitality", 8),               // already on the map as an event
  claimLead("play", "Old Claim Industries", "US", "Manufacturing", 200),           // older than new_hours and never checked
  // two news reports name Fabrikam: corroboration lifts it; a tracker post and a claim never count
  { seen_at: h(25), source: "The Record", tier: "news", title: "Fabrikam Logistics hit by ransomware attack, shipments delayed", url: "https://therecord.media/fabrikam-logistics-ransomware", published: h(25) },
  { seen_at: h(24), source: "redpacketsecurity", tier: "news", title: "Fabrikam Logistics ransomware attack", url: "https://www.redpacketsecurity.com/everest-fabrikam/", published: h(24) },
  { seen_at: h(24), source: "Heise", tier: "news", title: "Cyberangriff: Fabrikam Logistics attack confirmed by police", url: "https://www.heise.de/news/fabrikam-123.html", published: h(24) },
];
const events = [
  { id: "northwind-traders-rhysida-claim-2026-11", category: "incident", status: "claimed", severity: 1, date: "2026-11-21", org: "Northwind Traders", title: "Rhysida claims attack on Northwind Traders", actor: "Rhysida (claimed)", summary: "Rhysida listed Northwind Traders.", sources: [{ name: "x", url: "https://news.example/northwind" }] },
  { id: "everest-past-confirmed-2026-10", category: "incident", status: "confirmed", severity: 2, date: "2026-10-01", org: "Someone Else", title: "Someone Else confirms Everest ransomware attack", actor: "Everest", summary: "x", sources: [] },
  { id: "riverside-hospital-ransomware-2026-11", category: "incident", status: "confirmed", severity: 3, date: "2026-11-01", org: "Riverside Clinic", title: "Placeholder", actor: "akira (claimed)", summary: "Riverside General Hospital confirmed an Akira ransomware attack.", sources: [{ name: "Riverside", url: "https://www.riversidegeneral.org/notice/cyber-incident" }] },
  { id: "riverside-claimed-2026-11", category: "incident", status: "claimed", severity: 1, date: "2026-11-21", org: "Riverside Clinic", title: "Placeholder two", actor: "akira (claimed)", summary: "Akira listed Riverside General Hospital; the hospital has not confirmed it and later denied it.", sources: [{ name: "x", url: "https://news.example/r" }] },
  { id: "riverside-claimed-sev2-2026-11", category: "incident", status: "claimed", severity: 2, date: "2026-11-21", org: "Riverside Clinic", title: "Placeholder three", actor: "akira (claimed)", summary: "x", sources: [] },
  { id: "riverside-no-group-2026-11", category: "incident", status: "confirmed", severity: 3, date: "2026-11-01", org: "Riverside Clinic", title: "Placeholder four", actor: "", summary: "The hospital confirmed an attack.", sources: [{ name: "Riverside", url: "https://www.riversidegeneral.org/notice/cyber-incident" }] },
  { id: "riverside-tracker-2026-11", category: "incident", status: "claimed", severity: 1, date: "2026-11-21", org: "Riverside Clinic", title: "Placeholder five", actor: "akira (claimed)", summary: "Akira listed it.", sources: [{ name: "rl", url: "https://www.ransomware.live/id/abc" }] },
];
const items = () => claimItems(leads, events, {}, {}, NOW);

test("parse: the group, the victim and the country from a ransomware.live title; the core name for matching", () => {
  assert.deepEqual(parseClaim(leads[0]), { group: "qilin", victim: "Shop & Co Retail Ltd", country: "GB" });
  assert.deepEqual(parseClaim({ title: "Claim: Kill Security lists acme.example.com on its leak site", country: "FR" }), { group: "Kill Security", victim: "acme.example.com", country: "FR" });
  assert.equal(parseClaim({ title: "Acme hit by ransomware" }), null);
  assert.equal(coreName("AutoZone, Inc."), "autozone"); assert.equal(coreName("FAIR Health, Inc. (fairhealth.com)"), "fair health"); assert.equal(coreName("www.autozone.com"), "autozone"); assert.equal(coreName("roedentallab.com"), "roedentallab");
  assert.equal(claimKey("Akira", "AutoZone, Inc."), claimKey("akira", "AutoZone Inc")); assert.match(claimKey("a", "b"), /^cl-[0-9a-f]{12}$/);
});
test("queue: most notable first; masked, matched and old unchecked claims left out; one item per group and victim", () => {
  const it = items(), names = it.map((x) => x.victim);
  assert.deepEqual(names, ["Fabrikam Logistics", "Riverside General Hospital", "Contoso Water Authority", "Shop & Co Retail Ltd"]);
  assert.ok(!names.some((n) => /J\.\.\./.test(n)), "a masked private person is never queued");
  assert.ok(!names.includes("Northwind Traders"), "already on the map");
  assert.ok(!names.includes("Old Claim Industries"), "never checked and older than new_hours");
  const fab = it[0];
  assert.equal(fab.claimed_at, h(40), "the first listing"); assert.equal(fab.reports.length, 2, "two news reports; the tracker post left out");
  assert.ok(fab.reports.every((r) => !/redpacketsecurity|ransomware\.live/.test(r.url)));
  assert.ok(fab.track.events >= 1, "Everest's claims have been confirmed before");
  assert.ok(!("url" in fab), "never the leak site's or tracker's link");
  assert.equal(it[2].sector, "", "'Not Found' is no sector"); assert.match(it[2].why.join(), /critical sector/, "the name says water utility");
  // an old claim that was checked before is still re-checked
  const old = claimKey("play", "Old Claim Industries");
  assert.ok(claimItems(leads, events, { [old]: { decision: "unconfirmed", tries: 1, checked_at: h(100) } }, {}, NOW).some((x) => x.id === old));
});
test("matching and corroboration helpers", () => {
  assert.equal(matchedEvent("Northwind Traders", events, h(8)), "northwind-traders-rhysida-claim-2026-11");
  assert.equal(matchedEvent("Northwind Traders", events, iso(NOW + 90 * 864e5)), "", "too far from the event's date");
  assert.equal(matchedEvent("Abc", events, h(1)), "", "a name too short to match");
  assert.deepEqual(reportsOf("Fabrikam Logistics", [leads[0], ...leads.slice(-3)]).map((r) => r.source), ["The Record", "Heise"]);
  assert.deepEqual(trackRecord("Everest", events, { a: { group: "everest", decision: "reported" }, b: { group: "everest", decision: "unconfirmed" } }), { events: 1, confirmed: 1, checked: 2 });
});
test("due: final results done, unconfirmed re-checked after recheck_hours up to max_tries, leases respected", () => {
  const it = items()[0];
  for (const d of ["confirmed_by_victim", "reported", "denied", "not_found"]) assert.equal(due(it, { [it.id]: { decision: d, checked_at: h(100), tries: 1 } }, {}, NOW), false, d);
  assert.equal(due(it, { [it.id]: { decision: "unconfirmed", checked_at: h(5), tries: 1 } }, {}, NOW), false, "checked 5 h ago");
  assert.equal(due(it, { [it.id]: { decision: "unconfirmed", checked_at: h(25), tries: 1 } }, {}, NOW), true, "25 h ago: due again");
  assert.equal(due(it, { [it.id]: { decision: "unconfirmed", checked_at: h(25), tries: 3 } }, {}, NOW), false, "max_tries");
  assert.equal(due(it, { [it.id]: { decision: "unconfirmed", checked_at: h(7), tries: 1 } }, {}, NOW, { recheck_hours: 6 }), true, "config recheck_hours");
  const lease = (run, min) => ({ [`claim:${it.id}`]: { run, until: iso(NOW + min * 6e4) } });
  assert.equal(due(it, {}, lease("other", 10), NOW), false);
  assert.equal(due(it, {}, lease("other", -1), NOW), true);
  assert.equal(due(it, {}, lease("me", 10), NOW, { run: "me" }), true);
  assert.equal(queue(items(), {}, lease("other", 10), NOW).length, 3);
});
test("plan: batches of K for N checkers, stable plan id, a new id on a retry", () => {
  const q = queue(items(), {}, {}, NOW), p = makePlan(q, {}, 2, 2, "c1");
  assert.equal(p.batches.length, 2); assert.equal(p.batches[0].items.length, 2); assert.equal(p.batches[0].out, "claims-out-c1-1.json");
  assert.match(p.plan_id, /^cp-[0-9a-f]{16}$/); assert.equal(makePlan(q, {}, 2, 2, "c1").plan_id, p.plan_id);
  const again = makePlan(q, { [q[0].id]: { decision: "unconfirmed", summary: "s", tries: 1, sources: [] } }, 2, 2, "c1");
  assert.notEqual(again.plan_id, p.plan_id); assert.equal(planId(again.batches), again.plan_id);
  assert.ok(!("rank" in p.batches[0].items[0]));
});

const q0 = queue(items(), {}, {}, NOW), PLAN = makePlan(q0, {}, 1, 8, "t");
const RIV = q0.find((x) => x.victim === "Riverside General Hospital"), FAB = q0.find((x) => x.victim === "Fabrikam Logistics");
const evMap = new Map(events.map((e) => [e.id, e]));
const conf = (o) => ({ id: RIV.id, decision: "confirmed_by_victim", victim: "Riverside General Hospital", confirmed_by: "Riverside General Hospital, in a notice on its website", victim_site: "riversidegeneral.org",
  summary: "Riverside General Hospital said on 20 November that a ransomware attack disrupted its systems; Akira had listed it on 19 November.", sources: ["https://www.riversidegeneral.org/notice/cyber-incident"], read_depth: "full", event_id: "riverside-hospital-ransomware-2026-11", ...o });
const out = (results, o = {}) => ({ plan_id: PLAN.plan_id, batch: 1, results, ...o });
const rest = (except) => q0.filter((x) => !except.includes(x.id)).map((x) => ({ id: x.id, decision: "unconfirmed", summary: "Nothing beyond the leak-site listing was found.", sources: [], read_depth: "summary" }));
const bad = (o) => validate(PLAN, out([conf(o), ...rest([RIV.id])]), evMap).bad[RIV.id] || [];

test("validate: a file for another plan, an unplanned id or a repeated id is refused outright", () => {
  assert.match(validate(PLAN, out([], { plan_id: "cp-nope" })).errors.join(), /does not match/);
  assert.match(validate(PLAN, out([conf({ id: "cl-000000000000" })])).errors.join(), /was not planned/);
  assert.match(validate(PLAN, out([conf(), conf()])).errors.join(), /appears 2 times/);
  assert.match(validate(null, out([])).errors.join(), /no plan/);
  assert.match(validate(PLAN, out([], { batch: 9 })).errors.join(), /batch 9 is not in the plan/);
});
test("validate: a valid file passes; a missing result is reported", () => {
  const v = validate(PLAN, out([conf(), ...rest([RIV.id])]), evMap); assert.ok(v.ok, JSON.stringify(v.bad)); assert.equal(v.good.length, q0.length);
  const w = validate(PLAN, out([conf()]), evMap); assert.equal(w.ok, false); assert.match(w.bad[FAB.id][0], /no result/);
});
test("validate: leak sites, .onion, claim trackers, forums, social media, http, front pages and redirects are never sources", () => {
  for (const [u, re] of [["https://www.ransomware.live/id/abc", /claim tracker/], ["https://akiral2iz6a7qgd3ayp.onion/leaks/riverside", /\.onion/], ["https://ransomlook.io/group/akira", /claim tracker/],
    ["https://x.com/FalconFeedsio/status/1", /social-media/], ["https://t.me/channel/12", /social-media/], ["https://breachforums.st/Thread-riverside", /forum/],
    ["http://www.riversidegeneral.org/notice", /not https/], ["https://www.riversidegeneral.org/", /front page/], ["https://news.google.com/rss/articles/x", /search-engine redirect/], ["not a url", /not a URL/]]) {
    assert.match(bad({ sources: ["https://www.riversidegeneral.org/notice/cyber-incident", u] }).join(), re, u);
    assert.notEqual(claimSourceProblem(u), "", u);
  }
  assert.equal(claimSourceProblem("https://therecord.media/fabrikam-logistics-ransomware"), "");
  assert.match(bad({ sources: "https://www.riversidegeneral.org/notice" }).join(), /sources is not an array/);
  assert.match(bad({ sources: Array.from({ length: 9 }, (_, i) => `https://p${i}.example/a`) }).join(), /more than 8 sources/);
});
test("validate: confirmed_by_victim needs a victim, who confirmed it and the victim's, a regulator's or a government's page", () => {
  assert.deepEqual(bad({}), []);
  assert.match(bad({ victim: "" }).join(), /needs victim/);
  assert.match(bad({ confirmed_by: "" }).join(), /needs confirmed_by/);
  const news = ["https://therecord.media/riverside-hospital-ransomware", "https://www.bleepingcomputer.com/news/security/riverside/"];
  assert.match(bad({ sources: news }).join(), /needs the organisation's own page .* or a regulator's or government's page/);
  assert.match(bad({ sources: news, victim_site: "" }).join(), /needs the organisation's own page/);
  // a government or regulator page is enough (the event must cite it too)
  const ev = new Map(evMap); ev.set("riverside-hospital-ransomware-2026-11", { ...events[2], sources: [{ name: "HHS", url: "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf?id=1" }] });
  assert.deepEqual(validate(PLAN, out([conf({ victim_site: "", sources: ["https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf?id=1"] }), ...rest([RIV.id])]), ev).bad[RIV.id] || [], []);
  ev.set("riverside-hospital-ransomware-2026-11", { ...events[2], sources: [{ name: "ICO", url: "https://ico.org.uk/action-weve-taken/riverside/" }] });
  assert.deepEqual(validate(PLAN, out([conf({ victim_site: "", sources: ["https://ico.org.uk/action-weve-taken/riverside/"] }), ...rest([RIV.id])]), ev).bad[RIV.id] || [], []);
  assert.match(bad({ victim_site: "not a domain" }).join(), /victim_site must be/);
  assert.match(bad({ victim_site: "ransomware.live" }).join(), /victim_site must be/);
});
test("validate: the event a confirmation names must be confirmed, cite the confirming page and name the group's claim", () => {
  assert.match(bad({ event_id: "" }).join(), /needs event_id/);
  assert.match(bad({ event_id: "no-such-event-2026-11" }).join(), /not on file/);
  assert.match(bad({ event_id: "riverside-claimed-2026-11" }).join(), /status claimed: a confirmed claim is status confirmed/);
  assert.match(bad({ event_id: "riverside-claimed-2026-11" }).join(), /does not cite the confirming page/);
  assert.match(bad({ event_id: "riverside-no-group-2026-11" }).join(), /does not name akira's claim/);
  assert.match(bad({ event_id: "Bad Id" }).join(), /not an event id/);
});
test("validate: reported needs two publishers, says it is not confirmed, and names a claimed severity 1 event", () => {
  const rep = (o) => bad({ decision: "reported", confirmed_by: undefined, victim_site: "", summary: "Two outlets reported an attack on the hospital; it has not confirmed it.",
    sources: ["https://therecord.media/riverside-hospital-ransomware", "https://www.bleepingcomputer.com/news/security/riverside/"], event_id: "riverside-claimed-2026-11", ...o });
  assert.deepEqual(rep({}), []);
  assert.match(rep({ sources: ["https://therecord.media/riverside-hospital-ransomware", "https://therecord.media/riverside-update"] }).join(), /two independent credible publishers/);
  assert.match(rep({ summary: "Two outlets reported an attack on the hospital." }).join(), /must say in the summary that the organisation has not confirmed/);
  assert.match(rep({ event_id: "riverside-hospital-ransomware-2026-11" }).join(), /status confirmed: a claim the organisation has not confirmed is status claimed/);
  assert.match(rep({ event_id: "riverside-claimed-sev2-2026-11" }).join(), /severity 2: a claimed event is severity 1/);
  assert.match(rep({ event_id: "riverside-tracker-2026-11" }).join(), /cites a leak site or claim tracker/);
  assert.match(rep({ event_id: undefined }).join(), /reported needs event_id/);
  assert.match(rep({ victim: "" }).join(), /needs victim/);
});
test("validate: denied needs the page and the denial; unconfirmed and not_found never write an event", () => {
  const den = (o) => bad({ decision: "denied", confirmed_by: undefined, summary: "The hospital denied being attacked, in a statement to The Record.", sources: ["https://therecord.media/riverside-denies"], event_id: undefined, ...o });
  assert.deepEqual(den({}), []);
  assert.deepEqual(den({ event_id: "riverside-claimed-2026-11" }), [], "a claimed event that carries the denial");
  assert.match(den({ event_id: "riverside-claimed-sev2-2026-11" }).join(), /severity 2/);
  assert.match(den({ sources: [] }).join(), /needs the page that carries the denial/);
  assert.match(den({ summary: "The hospital spoke to The Record." }).join(), /who denies what/);
  for (const d of ["unconfirmed", "not_found"]) {
    assert.match(bad({ decision: d, event_id: "riverside-claimed-2026-11" }).join(), /never writes an event/, d);
    assert.deepEqual(bad({ decision: d, event_id: undefined, sources: [], victim: undefined, confirmed_by: undefined, summary: "Nothing beyond the leak-site listing was found." }), [], d);
  }
  assert.match(bad({ decision: "unconfirmed", event_id: undefined, summary: "The hospital confirmed the attack on its website." }).join(), /is confirmed_by_victim, not unconfirmed/);
  assert.match(bad({ decision: "breached" }).join(), /not one of confirmed_by_victim, reported, denied, unconfirmed, not_found/);
  assert.match(bad({ read_depth: "skimmed" }).join(), /read_depth/);
  assert.match(bad({ summary: " " }).join(), /summary is empty/);
  assert.match(bad({ summary: "x".repeat(301) }).join(), /at most 300/);
});
test("validate: stolen data, samples, .onion addresses and links in the text are refused", () => {
  for (const [s, re] of [["The listing shows staff e-mails such as jane.doe@riversidegeneral.org.", /e-mail address/], ["Samples include patient records.", /samples or contents/],
    ["The group posted screenshots of invoices.", /samples or contents/], ["Files named payroll_2026.xlsx were listed.", /file name/], ["A record showed 123-45-6789.", /identity number/],
    ["Card 4111 1111 1111 1111 appeared.", /card or account number/], ["Call +1 555 123 4567 for details.", /phone number/], ["password: hunter2 was leaked", /password/],
    ["See the claim at akiral2iz6a7qgd3ayp.onion.", /\.onion/], ["See https://www.riversidegeneral.org/notice.", /a link/], ["IBAN DE89370400440532013000 was listed.", /IBAN/]]) {
    assert.match(bad({ summary: s }).join(), re, s);
  }
  assert.match(bad({ confirmed_by: "jane.doe@riversidegeneral.org" }).join(), /confirmed_by contains an e-mail address/);
  assert.deepEqual(bad({ summary: "Riverside General Hospital said on 2026-11-20 that about 1,200,000 records may be affected; Akira listed it on 19 November." }), [], "dates and stated figures are fine");
});
test("apply: records each check once (idempotent), finality and tries, never the leak site", () => {
  const v = validate(PLAN, out([conf(), ...rest([RIV.id])]), evMap); assert.ok(v.ok, JSON.stringify(v.bad));
  const r = applyResults({}, PLAN, v.good, NOW);
  assert.equal(r.changed.length, q0.length);
  const c = r.checks[RIV.id];
  assert.equal(c.decision, "confirmed_by_victim"); assert.equal(c.final, true); assert.equal(c.by, BY); assert.equal(c.group, "akira"); assert.equal(c.event_id, "riverside-hospital-ransomware-2026-11");
  assert.equal(c.claimed_victim, "Riverside General Hospital"); assert.equal(c.victim_site, "riversidegeneral.org"); assert.equal(c.checked_at, iso(NOW));
  assert.ok(!JSON.stringify(r.checks).includes("ransomware.live"), "the tracker's link is never recorded");
  assert.equal(r.checks[FAB.id].final, false, "unconfirmed is checked again later"); assert.equal(r.checks[FAB.id].event_id, undefined);
  const r2 = applyResults(r.checks, PLAN, v.good, NOW + 6e4); assert.equal(r2.changed.length, 0);
  const e = entryFor({ ...rest([])[0] }, FAB, { tries: 2, plan_id: "cp-old" }, "cp-new", NOW, { max_tries: 3 }); assert.equal(e.tries, 3); assert.equal(e.final, true, "final at max_tries");
});
test("site and status: what an event shows, the newest check per event, the queue numbers", () => {
  const c = { decision: "confirmed_by_victim", group: "akira", claimed_at: h(30), summary: "s", confirmed_by: "Riverside", victim_site: "riversidegeneral.org", event_id: "ev-1",
    sources: ["https://therecord.media/a", "https://www.ransomware.live/id/x", "https://www.riversidegeneral.org/notice/cyber-incident"], checked_at: iso(NOW) };
  const v = siteCheck(c); assert.equal(v.by, BY); assert.equal(v.url, "https://www.riversidegeneral.org/notice/cyber-incident", "the confirming page");
  assert.equal(v.claimed_at, h(30).slice(0, 10)); assert.equal(v.group, "akira");
  assert.equal(siteCheck({ ...c, decision: "reported" }).url, "https://therecord.media/a");
  assert.equal(siteCheck({ ...c, decision: "reported", sources: ["https://www.ransomware.live/id/x"] }).url, "", "never a tracker");
  assert.equal(siteCheck({ decision: "hacked" }), null); assert.equal(siteCheck(null), null);
  const by = checksByEvent({ a: { ...c, checked_at: h(5) }, b: { ...c, decision: "reported", checked_at: h(1) }, x: { decision: "unconfirmed" } });
  assert.deepEqual(Object.keys(by), ["ev-1"]); assert.equal(by["ev-1"].decision, "reported");
  const st = stats(q0, { a: { decision: "confirmed_by_victim", checked_at: h(1) }, b: { decision: "denied", checked_at: h(2) }, c: { decision: "unconfirmed", checked_at: h(30) } }, NOW);
  assert.deepEqual([st.waiting, st.checked_24h, st.confirmed_24h, st.denied_24h, st.unconfirmed_24h], [q0.length, 2, 1, 1, 0]);
  assert.ok(st.oldest_min >= 30 * 60 - 15);
  assert.deepEqual(DECISIONS, ["confirmed_by_victim", "reported", "denied", "unconfirmed", "not_found"]);
});

// end to end in a scratch copy: plan (leases), apply, apply again; the second apply changes no file
test("CLI: plan --dry-run writes nothing; plan, apply and apply again; a bad file is refused", () => {
  const here = dirname(fileURLToPath(import.meta.url)), repo = join(here, "..", ".."), t = mkdtempSync(join(tmpdir(), "claims-desk-"));
  for (const d of ["scripts/lib", "data/leads", "data/events/2026-11", "config"]) mkdirSync(join(t, d), { recursive: true });
  for (const f of ["scripts/claims-desk.mjs", "scripts/grid-desk.mjs", "scripts/grid.mjs", "scripts/triage.mjs", "scripts/lib/store.mjs", "scripts/lib/lease.mjs", "scripts/lib/net.mjs"]) copyFileSync(join(repo, f), join(t, f));
  const now = Date.now(), day = iso(now).slice(0, 10), H = (n) => iso(now - n * 36e5);
  const L = [["akira", "Riverside General Hospital", "US", "Healthcare", 2], ["qilin", "Shop & Co Retail Ltd", "GB", "Retail & E-Commerce", 3], ["everest", "Fabrikam Logistics", "DE", "Transportation", 4]]
    .map(([g, v, cc, s, n]) => ({ ...claimLead(g, v, cc, s, 0), seen_at: H(n), published: H(n) }));
  writeFileSync(join(t, "data", "leads", `${day}.jsonl`), L.map((x) => JSON.stringify(x)).join("\n") + "\n");
  const ev = { title: "Riverside General Hospital confirms Akira ransomware attack", date: day, category: "incident", severity: 2, status: "confirmed", org: "Riverside General Hospital", actor: "Akira (claimed)",
    summary: "Riverside General Hospital confirmed a ransomware attack that Akira had claimed.", sources: [{ name: "Riverside General Hospital", url: "https://www.riversidegeneral.org/notice/cyber-incident" }] };
  writeFileSync(join(t, "data", "status.json"), "{}\n"); writeFileSync(join(t, "config", "pipeline.json"), JSON.stringify({ claims_desk: { recheck_hours: 24 } }));
  const run = (...a) => spawnSync("node", ["scripts/claims-desk.mjs", ...a], { cwd: t, encoding: "utf8", env: { ...process.env, CYBERVIEW_RUN: "run-test" } });
  const d = run("plan", "--dry-run"); assert.equal(d.status, 0, d.stderr); assert.match(d.stdout, /dry run.*3 waiting/); assert.match(d.stdout, /akira claims Riverside General Hospital/);
  assert.ok(!existsSync(join(t, "data", "leases.json")) && !existsSync(join(t, "data", "claims-plan.json")), "a dry run leases and writes nothing");
  const p = run("plan", "--max", "1", "--per", "2", "--file", "claims-plan-t.json"); assert.equal(p.status, 0, p.stderr); assert.match(p.stdout, /2 claim\(s\) for 1 claims checker/);
  const pl = JSON.parse(readFileSync(join(t, "data", "claims-plan-t.json"), "utf8")), its = pl.batches[0].items, ids = its.map((i) => i.id);
  assert.equal(its[0].victim, "Riverside General Hospital", "health first");
  assert.ok(!readFileSync(join(t, "data", "claims-plan-t.json"), "utf8").includes("ransomware.live"), "the plan never carries the tracker's link");
  assert.ok(JSON.parse(readFileSync(join(t, "data", "leases.json"), "utf8"))[`claim:${ids[0]}`]);
  assert.equal(pl.batches[0].out, "claims-out-t-1.json");
  // the checker wrote the event through the checklist; apply checks it
  writeFileSync(join(t, "data", "events", "2026-11", "riverside-akira-2026-11.json"), JSON.stringify(ev));
  writeFileSync(join(t, "data", pl.batches[0].out), JSON.stringify({ plan_id: pl.plan_id, batch: 1, results: [
    { id: ids[0], decision: "confirmed_by_victim", victim: "Riverside General Hospital", confirmed_by: "Riverside General Hospital, on its website", victim_site: "riversidegeneral.org",
      summary: "The hospital said a ransomware attack disrupted its systems; Akira had listed it on its leak site.", sources: ["https://www.riversidegeneral.org/notice/cyber-incident"], read_depth: "full", event_id: "riverside-akira-2026-11" },
    { id: ids[1], decision: "unconfirmed", summary: "Nothing beyond the leak-site listing was found.", sources: [], read_depth: "summary" }] }));
  const a1 = run("apply", pl.batches[0].out); assert.equal(a1.status, 0, a1.stderr + a1.stdout); assert.match(a1.stdout, /2 recorded, 0 already on file, 0 rejected/);
  const snap = () => Object.fromEntries(["data/claims/checks.json", "data/status.json", "data/leases.json"].map((f) => [f, existsSync(join(t, f)) ? readFileSync(join(t, f), "utf8") : null]));
  const s1 = snap();
  assert.equal(JSON.parse(s1["data/status.json"]).last_claims_at.length, 20);
  assert.ok(!JSON.parse(s1["data/leases.json"])[`claim:${ids[0]}`], "lease released");
  assert.equal(JSON.parse(s1["data/claims/checks.json"])[ids[0]].event_id, "riverside-akira-2026-11");
  const a2 = run("apply", pl.batches[0].out); assert.equal(a2.status, 0); assert.match(a2.stdout, /0 recorded, 2 already on file/);
  assert.deepEqual(snap(), s1);
  // the confirmed claim is matched to its event now, the unconfirmed one waits for its re-check: one left
  assert.match(run("status").stdout, /^CLAIMS DESK: 1 waiting, 2 checked in 24 h \(1 confirmed by the victim/);
  // a leak-site source is refused (exit 1) and nothing is recorded for it
  const p2 = run("plan", "--file", "claims-plan-u.json"); assert.equal(p2.status, 0, p2.stderr);
  const pl2 = JSON.parse(readFileSync(join(t, "data", "claims-plan-u.json"), "utf8")), id2 = pl2.batches[0].items[0].id;
  writeFileSync(join(t, "data", "claims-out-u-1.json"), JSON.stringify({ plan_id: pl2.plan_id, batch: 1, results: [{ id: id2, decision: "not_found", summary: "Only the leak site names it.", sources: ["https://www.ransomware.live/id/x"], read_depth: "summary" }] }));
  const a3 = run("apply", "claims-out-u-1.json"); assert.equal(a3.status, 1); assert.match(a3.stdout, /1 rejected/); assert.match(a3.stdout, /claim tracker/);
  assert.ok(!JSON.parse(readFileSync(join(t, "data", "claims", "checks.json"), "utf8"))[id2]);
  writeFileSync(join(t, "data", "claims-out-x.json"), JSON.stringify({ plan_id: "cp-nope", batch: 1, results: [] }));
  assert.equal(run("apply", "claims-out-x.json").status, 1);
});
