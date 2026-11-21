// Unit tests for scripts/status-pages.mjs: one parser per status-page format (fixtures trimmed from the real pages,
// fetched 2026-11-21, in tests/fixtures/status-pages/), the lead rule (stated major/critical impact or min_minutes, never
// maintenance), dedupe across polls by incident id, config/status-pages.json, and the outage desk's service order
// (biggest providers first).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseStatuspage, parseStatuspageAtom, parseGcp, parseAws, parseAzure, parseSlack, parseHeroku, parseSalesforce, parsePaypal, parseIbm, parseFeedPage, feedEntries,
  updateTime, minutesOf, qualifies, leadOf, leadsFor, due, validProvider, shownIncidents, PARSERS, TYPES, CATEGORIES } from "../../scripts/status-pages.mjs";
import { serviceItems, queue } from "../../scripts/outage-desk.mjs";

const HERE = dirname(fileURLToPath(import.meta.url)), FIX = join(HERE, "..", "fixtures", "status-pages"), ROOT = join(HERE, "..", "..");
const F = (f) => readFileSync(join(FIX, f), "utf8"), J = (f) => JSON.parse(F(f));
const at = (s) => Date.parse(s);

test("Statuspage JSON (Cloudflare): impact, components, start and resolve as stated", () => {
  const r = parseStatuspage(J("cloudflare.json"), "https://www.cloudflarestatus.com");
  assert.equal(r.length, 4);
  const eu = r.find((i) => i.id === "iysf3fasf7wn");
  assert.deepEqual([eu.impact, eu.level, eu.status, eu.started_at, eu.resolved_at], ["major", "major", "resolved", "2026-11-20T18:24:29Z", "2026-11-20T18:53:14Z"]);
  assert.equal(eu.url, "https://www.cloudflarestatus.com/incidents/iysf3fasf7wn");   // the incident's own shortlink
  const iad = r.find((i) => i.id === "oz6to8yacrxe");
  assert.deepEqual(iad.components, ["Network"]);
  assert.equal(iad.level, "minor");
  // incident.io pages give no shortlink: the page's /incidents/<id>
  const io = parseStatuspage({ incidents: [{ id: "01M7T8MRF9SDBDNQ62Z6V156ZZ", name: "Elevated errors", impact: "major", status: "resolved", created_at: "2026-11-19T16:01:12Z", resolved_at: "2026-11-19T16:58:04Z" }] }, "https://status.openai.com/");
  assert.equal(io[0].url, "https://status.openai.com/incidents/01M7T8MRF9SDBDNQ62Z6V156ZZ");
  assert.equal(parseStatuspage({ incidents: [{ id: "x1234", name: "m", impact: "maintenance", status: "completed" }] })[0].maintenance, true);
  assert.deepEqual(parseStatuspage(null), []);
});

test("Statuspage Atom (GitHub): update times read from the entry, start = first update, resolved = the Resolved update", () => {
  const r = parseStatuspageAtom(F("github.atom"));
  assert.equal(r.length, 4);
  const pr = r.find((i) => i.id === "31953610");
  assert.equal(pr.title, "Incident with Pull Requests");
  assert.equal(pr.url, "https://www.githubstatus.com/incidents/2zfqmghmg3s3");
  assert.equal(pr.resolved_at, "2026-11-16T16:26:00Z");
  assert.equal(pr.mitigated_at, "2026-11-16T16:07:00Z");
  assert.ok(pr.started_at < pr.resolved_at);
  assert.equal(pr.level, "");             // the feed states no impact
  assert.equal(pr.status, "resolved");
  // Zoom writes Pacific times; a Scheduled update marks maintenance
  const z = parseStatuspageAtom(F("zoom.atom"))[0];
  assert.equal(z.maintenance, true);
  assert.equal(z.started_at, "2026-11-06T08:51:00Z");   // Nov 6, 00:51 PST
});

test("updateTime: time zones, a December update read in January, unknown zone", () => {
  assert.equal(updateTime("Nov", "19", "18:17", "UTC", "2026-11-19T18:17:42Z"), "2026-11-19T18:17:00Z");
  assert.equal(updateTime("Nov", "6", "00:51", "PST", "2026-11-06T08:56:49Z"), "2026-11-06T08:51:00Z");
  assert.equal(updateTime("Dec", "31", "23:50", "UTC", "2027-01-01T00:10:00Z"), "2026-12-31T23:50:00Z");
  assert.equal(updateTime("Nov", "19", "18:17", "XYZ", "2026-11-19T18:17:42Z"), "");
});

test("Google Cloud: severity and status impact as stated, products as components", () => {
  const r = parseGcp(J("gcp.json"));
  assert.equal(r.length, 2);
  assert.equal(r[0].impact, "SERVICE_DISRUPTION, medium");
  assert.equal(r[0].level, "minor");
  assert.ok(r[0].components.includes("Apigee"));
  assert.match(r[0].url, /^https:\/\/status\.cloud\.google\.com\/incidents\/[\w-]+$/);
  assert.equal(parseGcp([{ id: "abcdefg", begin: "2026-11-20T00:00:00Z", status_impact: "SERVICE_OUTAGE", severity: "high", external_desc: "x" }])[0].level, "critical");
  assert.equal(parseGcp([{ id: "abcdefg", begin: "2026-11-20T00:00:00Z", status_impact: "SERVICE_DISRUPTION", severity: "high", external_desc: "x" }])[0].level, "major");
});

test("AWS RSS: updates grouped by event id, AWS's own words as impact, a resolution closes it", () => {
  const r = parseAws(F("aws.rss"));
  assert.ok(r.length >= 3);
  const e = r[0];
  assert.match(e.id, /^[\w-]+_\d+$/);
  assert.equal(e.impact, "Service disruption");
  assert.equal(e.level, "major");
  assert.match(e.url, /^https:\/\/health\.aws\.amazon\.com\/health\/status#/);
  const x = `<rss><channel><item><title>Service disruption: Elevated errors</title><link>https://status.aws.amazon.com/</link><pubDate>Sat, 21 Nov 2026 10:00:00 GMT</pubDate><guid>https://status.aws.amazon.com/#ec2-us-east-1_1795000000</guid><description>x</description></item>
    <item><title>Service is operating normally: [RESOLVED] Elevated errors</title><link>https://status.aws.amazon.com/</link><pubDate>Sat, 21 Nov 2026 11:30:00 GMT</pubDate><guid>https://status.aws.amazon.com/#ec2-us-east-1_1795000000</guid><description>y</description></item></channel></rss>`;
  const one = parseAws(x);
  assert.equal(one.length, 1);
  assert.deepEqual([one[0].status, one[0].started_at, one[0].resolved_at, one[0].level], ["resolved", "2026-11-21T10:00:00Z", "2026-11-21T11:30:00Z", "major"]);
  assert.equal(minutesOf(one[0]), 90);
});

test("Azure RSS: an item is a widespread issue (Azure posts only those); an empty feed is no incident", () => {
  assert.deepEqual(parseAzure(`<rss><channel><title>Azure Status</title></channel></rss>`), []);
  const r = parseAzure(`<rss><channel><item><title>Virtual Machines - West Europe - Mitigated</title><link>https://azure.status.microsoft/en-us/status/history/?trackingId=AB-123</link><guid>AB-123</guid><pubDate>Sat, 21 Nov 2026 10:00:00 Z</pubDate><category>Virtual Machines</category></item></channel></rss>`);
  assert.equal(r.length, 1);
  assert.equal(r[0].level, "major");
  assert.equal(r[0].id, "AB-123");
  assert.deepEqual(r[0].components, ["Virtual Machines"]);
});

test("Slack, Heroku, Salesforce, PayPal, IBM Cloud and a plain Atom feed (Hetzner)", () => {
  const s = parseSlack(J("slack.json"));
  assert.equal(s[0].id, "1583"); assert.equal(s[0].impact, "incident"); assert.equal(s[0].level, "minor"); assert.equal(s[0].resolved_at, "2026-11-11T18:58:05Z");
  assert.ok(s[0].components.includes("Messaging"));
  assert.equal(parseSlack([{ id: 9, type: "outage", status: "active", title: "Slack is down", date_created: "2026-11-21T10:00:00Z", url: "https://slack-status.com/x" }])[0].level, "major");
  const h = parseHeroku(J("heroku.json"));
  assert.equal(h[0].url, "https://status.heroku.com/incidents/2967"); assert.equal(h[0].resolved_at, "2026-11-11T21:15:00Z");
  const sf = parseSalesforce(J("salesforce.json"));
  assert.equal(sf[0].level, "minor"); assert.equal(sf[0].url, "https://status.salesforce.com/incidents/20004546");
  assert.deepEqual([sf[0].started_at, sf[0].resolved_at], ["2026-10-30T02:00:00Z", "2026-10-30T13:38:00Z"]);
  const pp = parsePaypal(J("paypal.json"));
  assert.equal(pp[0].title, "Impact to Checkout and Multiple API's"); assert.equal(pp[0].impact, "Degraded Performance"); assert.equal(pp[0].level, "minor");
  assert.equal(pp[0].url, "https://www.paypal-status.com/history/eventdetails/110644");
  assert.ok(pp.some((x) => x.maintenance));
  const ibm = parseIbm(F("ibm.rss"));
  assert.equal(ibm.length, 1);   // release notes are not incidents
  assert.deepEqual([ibm[0].id, ibm[0].status, ibm[0].resolved_at], ["INC12259399", "resolved", "2026-10-22T15:13:00Z"]);
  const hz = parseFeedPage(F("hetzner.atom"), at("2026-11-21T22:00:00Z"));
  assert.equal(hz.length, 4);
  assert.match(hz[1].id, /^[0-9a-f-]{36}$/);
  assert.equal(minutesOf(hz[1], at("2026-11-21T22:00:00Z")), null);   // a notice with no stated state: length unknown
  assert.equal(feedEntries("<rss><channel><item><title>a</title><category>Maintenance</category></item></channel></rss>")[0].categories[0], "Maintenance");
});

test("lead rule: stated major/critical, or min_minutes long; never maintenance, a stated 'none' or an old incident", () => {
  const NOW = at("2026-11-21T12:00:00Z"), base = { id: "a1", title: "Elevated errors", url: "https://status.example.com/incidents/a1", components: [], status: "resolved", maintenance: false, mitigated_at: "" };
  const mk = (o) => ({ ...base, impact: "", level: "", started_at: "2026-11-21T10:00:00Z", resolved_at: "2026-11-21T10:20:00Z", updated_at: "2026-11-21T10:20:00Z", ...o });
  assert.equal(qualifies(mk({ level: "major", impact: "major" }), {}, NOW), "major impact stated");
  assert.equal(qualifies(mk({ level: "minor" }), {}, NOW), "");                                     // 20 minutes, minor
  assert.equal(qualifies(mk({ level: "minor", resolved_at: "2026-11-21T11:30:00Z" }), {}, NOW), "lasted 90 minutes");
  assert.equal(qualifies(mk({ level: "minor", resolved_at: "2026-11-21T11:30:00Z" }), { min_minutes: 120 }, NOW), "");
  assert.equal(qualifies(mk({ status: "investigating", resolved_at: "" }), {}, NOW), "lasted 120 minutes so far");
  assert.equal(qualifies(mk({ status: "monitoring", resolved_at: "", mitigated_at: "2026-11-21T10:15:00Z" }), {}, NOW), "");   // fixed after 15 minutes, watching
  assert.equal(qualifies(mk({ level: "critical", maintenance: true }), {}, NOW), "");
  assert.equal(qualifies(mk({ level: "none", resolved_at: "2026-11-21T11:30:00Z" }), {}, NOW), "");
  assert.equal(qualifies(mk({ level: "major", started_at: "2026-11-10T10:00:00Z", resolved_at: "2026-11-10T12:00:00Z", updated_at: "2026-11-10T12:00:00Z" }), {}, NOW), "");
  // a feed that states neither impact nor times: the provider's own title must say the service is out
  assert.equal(qualifies(mk({ status: "", resolved_at: "", title: "Object Storage HEL: Creation of new buckets temporarily unavailable" }), {}, NOW), "the provider's title reports an outage");
  assert.equal(qualifies(mk({ status: "", resolved_at: "", title: "Object Storage in location HEL partially degraded" }), {}, NOW), "");
});

test("leads: kind status, provider tier as priority, the provider's words, never 'attack'; deduped across polls", () => {
  const NOW = at("2026-11-21T00:00:00Z"), p = { id: "cloudflare", name: "Cloudflare", tier: 1, category: "cdn" };
  const incs = parseStatuspage(J("cloudflare.json"), "https://www.cloudflarestatus.com"), seen = new Set();
  const first = leadsFor(p, incs, seen, {}, NOW);
  assert.ok(first.length >= 2);
  const eu = first.find((l) => l.status_id === "cloudflare:iysf3fasf7wn");
  assert.ok(eu);
  assert.deepEqual([eu.kind, eu.tier, eu.priority, eu.category, eu.source], ["status", "vendor", 1, "cdn", "Cloudflare status"]);
  assert.match(eu.summary, /Impact as the provider states it: major/);
  assert.match(eu.summary, /not a cyber event/);
  assert.doesNotMatch(eu.title + eu.summary, /attack/i);
  assert.ok(!first.some((l) => l.status_id === "cloudflare:akjr7qn5o622"));   // impact none
  assert.deepEqual(leadsFor(p, incs, seen, {}, NOW), []);                       // the next poll files nothing again
  assert.equal(leadOf({ id: "x", name: "X", tier: 9 }, { ...incs[0] }, "w").priority, 3);
});

test("due: each page at most every poll_minutes", () => {
  const NOW = at("2026-11-21T12:00:00Z");
  assert.equal(due(undefined, {}, NOW), true);
  assert.equal(due({ at: "2026-11-21T11:55:00Z" }, {}, NOW), false);
  assert.equal(due({ at: "2026-11-21T11:49:00Z" }, {}, NOW), true);
});

test("shownIncidents: open first, biggest providers first; resolved ones only for show_resolved_hours", () => {
  const NOW = at("2026-11-21T12:00:00Z"), P = [{ id: "a", name: "A", tier: 3 }, { id: "b", name: "B", tier: 1 }];
  const i = (id, o) => ({ id, title: "t " + id, url: "https://s.example/" + id, components: [], impact: "major", level: "major", status: "investigating", started_at: "2026-11-21T10:00:00Z", resolved_at: "", updated_at: "2026-11-21T11:00:00Z", maintenance: false, ...o });
  const r = shownIncidents({ a: [i("a1"), i("a2", { status: "resolved", resolved_at: "2026-11-21T11:00:00Z" }), i("a3", { status: "resolved", resolved_at: "2026-11-21T01:00:00Z" })], b: [i("b1")] }, P, {}, NOW);
  assert.deepEqual(r.map((x) => x.id), ["b1", "a1", "a2"]);
  assert.equal(r[0].name, "B");
});

test("config/status-pages.json: every provider valid, known type and category, unique ids, robots checked; skipped have reasons", () => {
  const c = JSON.parse(readFileSync(join(ROOT, "config", "status-pages.json"), "utf8"));
  assert.ok(c.providers.length >= 30);
  const ids = new Set();
  for (const p of c.providers) {
    assert.ok(validProvider(p), p.id);
    assert.ok(TYPES.includes(p.type) && PARSERS[p.type], p.id);
    assert.ok(CATEGORIES.includes(p.category), p.id);
    assert.ok([1, 2, 3].includes(p.tier), p.id);
    assert.match(p.robots_checked, /^\d{4}-\d{2}-\d{2}$/);
    assert.ok(!ids.has(p.id), "duplicate " + p.id); ids.add(p.id);
    // Atlassian Statuspage's robots.txt disallows /api/: only pages whose robots.txt allows it are read there
    if (p.type === "statuspage") assert.ok(["cloudflare", "openai", "docker", "hashicorp", "flyio", "gocardless"].includes(p.id), `${p.id}: check robots.txt allows /api/`);
  }
  for (const s of c.skipped) assert.ok(s.provider && s.reason && s.checked);
  for (const k of ["hours", "min_minutes", "poll_minutes"]) assert.ok(Number(c[k]) > 0);
});

test("outage desk: status leads queue biggest providers first (priority), then newest; old leads keep working", () => {
  const NOW = at("2026-11-21T12:00:00Z");
  const L = (src, url, pub, priority) => ({ kind: "status", source: `${src} status`, title: `${src} status page: x`, url, published: pub, seen_at: pub, ...(priority ? { priority, status_id: src + ":1" } : {}) });
  const leads = [
    L("Sinch", "https://status.sinch.com/incidents/a1", "2026-11-21T11:00:00Z", 3),
    L("AWS", "https://health.aws.amazon.com/health/status#ec2-us-east-1_1", "2026-11-21T09:00:00Z", 1),
    L("Zoom", "https://www.zoomstatus.com/incidents/z1", "2026-11-21T10:00:00Z", 2),
    L("Old", "https://status.old.example/incidents/o1", "2026-11-21T11:30:00Z"),          // a lead from before priorities: counts as 3
    L("Cloudflare", "https://www.cloudflarestatus.com/incidents/c1", "2026-11-21T08:00:00Z", 1),
  ];
  const s = serviceItems(leads, [], new Set(), {}, NOW);
  assert.deepEqual(s.map((x) => x.provider), ["AWS", "Cloudflare", "Zoom", "Old", "Sinch"]);
  assert.deepEqual(s.map((x) => x.priority), [1, 1, 2, 3, 3]);
  // a long outage that started before status_hours but was filed recently is still checked
  const late = serviceItems([{ ...L("AWS", "https://health.aws.amazon.com/health/status#x_2", "2026-11-18T00:00:00Z", 1), seen_at: "2026-11-21T11:00:00Z" }], [], new Set(), {}, NOW);
  assert.equal(late.length, 1);
  const q = queue({ service: s, internet: [], power: [] }, {}, {}, NOW);
  assert.equal(q[0].provider, "AWS");
});
