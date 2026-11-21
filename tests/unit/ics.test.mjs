// scripts/ics.mjs (industrial control system and OT advisories) and site/ot-lib.js (the Industrial view's rules).
// Fixtures in tests/fixtures/ics/ are real public advisories and feeds, trimmed (fetched 2026-11-21).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { parseCsaf, parseChangesCsv, parseRolie, parseCisaRss, parseMoxaRss, parseVdeRss, parseMelcoRss, robotsAllows, idDay, exploitFromText, ssvcExploit,
  notable, toLead, mergeRecords, siteRows, siteData, clip, SOURCES } from "../../scripts/ics.mjs";

const F = (f) => readFileSync(new URL(`../fixtures/ics/${f}`, import.meta.url), "utf8");
const J = (f) => JSON.parse(F(f));
const CFG = { lead_cvss: 9, sector_cvss: 8, lifeline_sectors: ["Energy", "Water and Wastewater", "Transportation Systems"] };
const sandbox = { window: {} };
vm.runInNewContext(readFileSync(new URL("../../site/ot-lib.js", import.meta.url), "utf8"), sandbox);
const O = sandbox.window.CVOT;
const plain = (x) => JSON.parse(JSON.stringify(x));

test("CISA CSAF: id, vendor, product, CVE, CVSS, sectors, CISA's exploitation note, the web page", () => {
  const a = parseCsaf(J("cisa-icsa-26-323-03.json"), { source: "cisa", docUrl: "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-323-03.json", srcAt: "2026-11-19T06:00:00Z" });
  assert.equal(a.id, "ICSA-26-323-03");
  assert.equal(a.vendor, "libumqtt");
  assert.deepEqual(a.products, ["libumqtt"]);
  assert.deepEqual(a.cves, ["CVE-2026-125132"]);
  assert.equal(a.cvss, 8.6); assert.equal(a.cvss_version, "3.1"); assert.equal(a.severity, "H");
  assert.deepEqual(a.cve_cvss, { "CVE-2026-125132": 8.6 });
  assert.ok(a.sectors.includes("Energy") && a.sectors.includes("Water and Wastewater"));
  assert.equal(a.exploited, "none");
  assert.match(a.exploit_note, /No known public exploitation/);
  assert.deepEqual(a.remediation, ["none_available"]); assert.equal(a.fix, false);
  assert.equal(a.url, "https://www.cisa.gov/news-events/ics-advisories/icsa-26-323-03");   // the page, never the raw JSON
  assert.equal(a.published, "2026-11-19T06:00:00Z");
  assert.equal(a.hq, "China");
});
test("a CVE on CISA's KEV catalog makes the advisory known exploited", () => {
  const a = parseCsaf(J("abb-4hzk00022.json"), { source: "abb", vendor: "ABB", kev: new Set(["CVE-2025-24813"]) });
  assert.equal(a.exploited, "kev"); assert.deepEqual(a.kev_cves, ["CVE-2025-24813"]);
  assert.equal(a.vendor, "ABB"); assert.equal(a.cvss, 9.8);
  assert.ok(a.fix && a.remediation.includes("workaround"));
  assert.match(a.url, /^https:\/\/search\.abb\.com\//);
});
test("Schneider CSAF: a vendor's own document, its PDF advisory as the page", () => {
  const a = parseCsaf(J("schneider-sevd-2026-314-01.json"), { source: "schneider", vendor: "Schneider Electric" });
  assert.equal(a.id, "SEVD-2026-314-01"); assert.equal(a.cvss, 5.3); assert.equal(a.severity, "M");
  assert.deepEqual(a.products, ["EcoStruxure Power Build Rapsody software"]);
  assert.match(a.url, /SEVD-2026-314-01\.pdf/);
  assert.equal(a.exploited, "");
});
test("a vendor's not-affected notice is marked, never a lead; SSVC exploitation and CVSS v4 are read", () => {
  const doc = { document: { category: "csaf_security_advisory", title: "SSA-1: Flaw in a library", tracking: { id: "SSA-1", initial_release_date: "2026-11-20T00:00:00Z", current_release_date: "2026-11-20T00:00:00Z" },
      references: [{ category: "self", url: "https://vendor.example/ssa-1.html" }], notes: [] },
    product_tree: { branches: [{ category: "vendor", name: "Vendor", branches: [{ category: "product_name", name: "Controller X", branches: [{ category: "product_version", name: "1.0", product: { product_id: "1", name: "Controller X 1.0" } }] }] }] },
    vulnerabilities: [{ cve: "CVE-2026-1", product_status: { known_not_affected: ["1"] }, scores: [{ cvss_v4: { baseScore: 9.3, vectorString: "CVSS:4.0/AV:N", version: "4.0" } }], notes: [{ title: "SSVC", text: "SSVCv2/E:A/A:Y/T:T/" }] }] };
  const a = parseCsaf(doc, { source: "siemens", vendor: "Siemens" });
  assert.equal(a.title, "Flaw in a library");       // the id is not repeated in the title
  assert.equal(a.not_affected, true); assert.deepEqual(a.products, []);
  assert.equal(a.cvss, 9.3); assert.equal(a.cvss_version, "4.0");
  assert.equal(a.exploited, "active");
  assert.equal(notable(a, CFG), "");
  assert.equal(parseCsaf({ document: { title: "x" } }), null);
});
test("exploitation in words: negations first", () => {
  assert.equal(exploitFromText("No known public exploitation specifically targeting this vulnerability has been reported to CISA at this time."), "none");
  assert.equal(exploitFromText("The vulnerability is known to be exploited in the wild."), "active");
  assert.equal(exploitFromText("Public exploit code is available."), "poc");
  assert.equal(exploitFromText("Update to version 2."), "");
  assert.equal(ssvcExploit("SSVCv2/E:P/A:N/T:P/2026-11-12T17:14:36Z/"), "poc");
  assert.equal(ssvcExploit("nothing"), "");
});
test("indexes: changes.csv newest first, ROLIE entries with their CSAF address", () => {
  const c = parseChangesCsv(F("cisa-changes.csv") + "\n\"../evil.json\",\"2026-11-21T00:00:00Z\"\nnot a row");
  assert.equal(c.length, 6); assert.equal(c[0].path, "2026/icsa-26-323-03.json"); assert.ok(c.every((x) => !x.path.includes("..")));
  const r = parseRolie(J("siemens-rolie.json"));
  assert.equal(r.length, 3); assert.match(r[0].url, /^https:\/\/cert-portal\.siemens\.com\/productcert\/csaf\/ssa-\d+\.json$/);
  assert.deepEqual(parseRolie({}), []);
});
test("the publication day an advisory id encodes", () => {
  assert.equal(idDay("2026/icsa-26-323-03.json", SOURCES.cisa.hint), "2026-11-19");
  assert.equal(idDay("2026/icsma-26-295-01.json", SOURCES.cisa.hint), "2026-10-22");
  assert.equal(idDay("2026/sevd-2026-314-01.json", SOURCES.schneider.hint), "2026-11-10");
  assert.equal(idDay("2026/vde-2026-150.json", SOURCES.phoenix.hint), "2026-01-01");
  assert.equal(idDay("other.json", SOURCES.cisa.hint), "");
});
test("CISA RSS (the fallback): id, vendor, CVEs, CVSS, sectors and the exploitation sentence", () => {
  const r = parseCisaRss(F("cisa-ics.xml"));
  assert.equal(r.length, 2);
  assert.equal(r[0].id, "ICSA-26-323-03"); assert.equal(r[0].vendor, "libumqtt"); assert.equal(r[0].cvss, 8.6);
  assert.deepEqual(r[0].cves, ["CVE-2026-125132"]); assert.ok(r[0].sectors.includes("Energy"));
  assert.equal(r[0].exploited, "none"); assert.match(r[0].exploit_note, /^No known public exploitation/);
  assert.equal(r[1].cvss, 9.6); assert.equal(r[1].cves.length, 3);
});
test("Moxa, CERT@VDE and Mitsubishi Electric RSS", () => {
  const m = parseMoxaRss(F("moxa.xml"), new Set(["CVE-2026-129971"]));
  assert.equal(m[0].id, "MPSA-264520"); assert.equal(m[0].title, "Buffer Overflow Vulnerabilities in Ethernet Remote I/Os");
  assert.equal(m[0].cvss, 8.7); assert.equal(m[0].exploited, "kev");
  const v = parseVdeRss(F("vde.xml"));
  assert.deepEqual(v.map((x) => x.id), ["VDE-2026-132", "VDE-2026-122", "VDE-2026-144"]);
  assert.equal(v[0].vendor, "WAGO"); assert.equal(v[0].title, "Multiple Devices affected by PHP2Shell");
  const g = parseMelcoRss(F("melco.xml"));
  assert.equal(g[0].id, "MEL-2025-022"); assert.equal(g[0].published, "");      // an [Update]: not first published then
  assert.equal(g[0].updated, "2026-11-12T03:00:00Z"); assert.match(g[0].url, /^https:\/\/www\.mitsubishielectric\.com\/psirt\/.*\.pdf$/);
  assert.deepEqual(parseMoxaRss("<rss><item><title>x</title><link>javascript:alert(1)</link></item></rss>"), []);
});
test("robots.txt: the group, the longest rule and Allow on a tie decide", () => {
  const r = "User-agent: *\nDisallow: /*.pdf$\nDisallow: /private/\nAllow: /private/ok\n\nUser-agent: BadBot\nDisallow: /";
  assert.equal(robotsAllows(r, "/productcert/csaf/ssa-1.json"), true);
  assert.equal(robotsAllows(r, "/x/advisory.pdf"), false);
  assert.equal(robotsAllows(r, "/x/advisory.pdf?x=1"), true);
  assert.equal(robotsAllows(r, "/private/a"), false);
  assert.equal(robotsAllows(r, "/private/ok"), true);
  assert.equal(robotsAllows(r, "/anything", "badbot/1.0"), false);
  assert.equal(robotsAllows("", "/"), true);
  assert.equal(robotsAllows("User-agent: *\nDisallow:", "/a"), true);
});
test("notable advisories: exploited, CVSS 9 or more, or 8 or more in a lifeline sector", () => {
  const base = { id: "X-1", source: "cisa", vendor: "V", title: "T", summary: "", cves: [], sectors: [], cvss: 7, exploited: "", url: "https://www.cisa.gov/x" };
  assert.equal(notable(base, CFG), "");
  assert.equal(notable({ ...base, exploited: "kev" }, CFG), "known exploited (CISA KEV)");
  assert.equal(notable({ ...base, exploited: "active" }, CFG), "exploited, per the advisory");
  assert.equal(notable({ ...base, cvss: 9 }, CFG), "CVSS 9.0");
  assert.equal(notable({ ...base, cvss: 8.1, sectors: ["Water and Wastewater"] }, CFG), "CVSS 8.1 in Water and Wastewater");
  assert.equal(notable({ ...base, cvss: 8.1, sectors: ["Commercial Facilities"] }, CFG), "");
});
test("a lead: the collectors' shape, kind advisory, wording the backlog rules never close as routine", async () => {
  const { ROUTINE, CRITICAL } = await import("../../scripts/fuse.mjs");
  const a = parseCsaf(J("cisa-icsa-26-323-03.json"), { source: "cisa" });
  const l = toLead(a, "2026-11-21T00:00:00Z", notable(a, CFG));
  assert.equal(l.kind, "advisory"); assert.equal(l.tier, "gov"); assert.equal(l.via, "ics"); assert.equal(l.source, "CISA ICS advisories");
  assert.equal(l.url, "https://www.cisa.gov/news-events/ics-advisories/icsa-26-323-03");
  assert.match(l.title, /^ICSA-26-323-03 libumqtt industrial advisory: libumqtt \(CVSS 8\.6; critical infrastructure: /);
  assert.ok(!ROUTINE.test(l.title) || CRITICAL.test(l.title));
  assert.match(l.summary, /CVE-2026-125132/);
  assert.ok(l.title.length <= 200 && l.summary.length <= 300);
  const v = toLead({ ...a, vendor: "Phoenix Contact", title: "Phoenix Contact: PHP2Shell in FL SWITCH", source: "phoenix", cvss: 9.8 }, "now", "x");
  assert.match(v.title, /Phoenix Contact industrial advisory: PHP2Shell in FL SWITCH \(CVSS 9\.8 critical/);   // the vendor is not named twice
  assert.equal(v.tier, "vendor");
});
test("merge: a failed source keeps its records; the window and the CERT@VDE duplicate rule apply", () => {
  const prev = [{ id: "A-1", source: "cisa", published: "2026-11-01T00:00:00Z", title: "old" }, { id: "S-1", source: "siemens", published: "2026-11-02T00:00:00Z", title: "kept" },
    { id: "A-0", source: "cisa", published: "2024-01-01T00:00:00Z" }];
  const fresh = [{ id: "A-1", source: "cisa", published: "2026-11-01T00:00:00Z", title: "new" }, { id: "S-1", source: "siemens", published: "2026-11-02T00:00:00Z", title: "should not replace" },
    { id: "VDE-2026-1", source: "phoenix", published: "2026-11-03T00:00:00Z" }, { id: "VDE-2026-1", source: "certvde", published: "2026-11-03T00:00:00Z" }];
  const m = mergeRecords(prev, fresh, new Set(["siemens"]), "2025-11-21");
  assert.equal(m.find((a) => a.id === "A-1").title, "new");
  assert.equal(m.find((a) => a.id === "S-1").title, "kept");
  assert.ok(!m.find((a) => a.id === "A-0"));
  assert.deepEqual(m.filter((a) => a.id === "VDE-2026-1").map((a) => a.source), ["phoenix"]);
  assert.equal(m[0].id, "VDE-2026-1");    // newest first
});
test("the page's copy: fields checked, unsafe links and unknown sources dropped, text clipped", () => {
  const a = parseCsaf(J("cisa-icsa-26-323-03.json"), { source: "cisa", docUrl: "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-323-03.json" });
  const rows = siteRows([a, { ...a, source: "evil" }, { ...a, id: "<img>" }, { ...a, id: "X-2", url: "javascript:alert(1)", cves: ["CVE-2026-10001", "nope"] }]);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].published, "2026-11-19");
  assert.equal(rows[0].exploit_note, "");     // the standard "no known exploitation" sentence is said by the page
  assert.equal(rows[1].url, ""); assert.deepEqual(rows[1].cves, ["CVE-2026-10001"]);
  const sd = siteData({ updated_at: "2026-11-21T00:00:00Z", advisories: [a], sources: { cisa: { ok: true, count: 1 } } }, "b", CFG);
  assert.equal(sd.sources.cisa.ok, true); assert.equal(sd.sources.siemens.ok, false); assert.deepEqual(sd.lifeline, CFG.lifeline_sectors);
  assert.equal(siteData({}), null);
  assert.equal(clip("one two three four", 10), "one two…");
  assert.equal(clip("short", 10), "short");
});

/* ---- the browser side: site/ot-lib.js ---- */
const pageData = () => siteData({ updated_at: "2026-11-21T00:00:00Z", window_days: 365, sources: { cisa: { ok: true, count: 2 }, abb: { ok: true, count: 1 } },
  advisories: [parseCsaf(J("cisa-icsa-26-323-03.json"), { source: "cisa" }), parseCsaf(J("abb-4hzk00022.json"), { source: "abb", vendor: "ABB", kev: new Set(["CVE-2025-24813"]) }),
    { id: "BAD", source: "cisa", url: "javascript:x" }] }, "b", CFG);
test("ot-lib: records cleaned, CVE index built, unsafe records dropped", () => {
  const d = O.load(pageData());
  assert.equal(d.list.length, 2);
  assert.equal(d.byCve["CVE-2025-24813"][0].id, "4HZK00022");
  assert.equal(d.list[0].sourceName, "CISA ICS advisories");
  assert.equal(O.clean({ id: "X-1", source: "cisa", url: "http://insecure.example/" }), null);
});
test("ot-lib: rank points, every one listed, at most 100", () => {
  const d = O.load(pageData()), abb = d.list.find((a) => a.source === "abb"), cisa = d.list.find((a) => a.source === "cisa");
  const r = plain(O.rank(abb, { lifeline: d.lifeline, mine: true, today: "2026-11-21" }));
  assert.deepEqual(r.points.map((p) => p[0]), [40, 25, 20, 5]);
  assert.equal(r.total, 90);
  const c = plain(O.rank(cisa, { lifeline: d.lifeline, today: "2026-11-21" }));
  assert.deepEqual(c.points.map((p) => p[0]), [15, 10, 5, 5]);           // CVSS 8.6, Energy, no fix, published in 14 days
  assert.equal(c.total, c.points.reduce((s, p) => s + p[0], 0));
  assert.equal(O.rank({ ...cisa, notAffected: true }).total, 0);
});
test("ot-lib: filters and the software list match stay in the browser's data", () => {
  const d = O.load(pageData()), f = (o) => plain(O.filter(d.list, { lifeline: d.lifeline, today: "2026-11-21", ...o }).map((x) => x.a.id));
  assert.deepEqual(f({}), ["4HZK00022", "ICSA-26-323-03"]);
  assert.deepEqual(f({ show: "exploited" }), ["4HZK00022"]);
  assert.deepEqual(f({ show: "critical" }), ["4HZK00022"]);
  assert.deepEqual(f({ show: "lifeline" }), ["ICSA-26-323-03"]);
  assert.deepEqual(f({ show: "nofix" }), ["ICSA-26-323-03"]);
  assert.deepEqual(f({ q: "CVE-2026-125132" }), ["ICSA-26-323-03"]);
  assert.deepEqual(f({ vendor: "abb" }), ["4HZK00022"]);
  assert.deepEqual(f({ source: "cisa" }), ["ICSA-26-323-03"]);
  assert.deepEqual(f({ show: "mine", inv: [{ name: "APCA Model Builder", vendor: "ABB", version: "1" }] }), ["4HZK00022"]);
  assert.deepEqual(f({ show: "mine", inv: [{ name: "Excel", vendor: "", version: "1" }] }), []);
  assert.equal(O.fixText(d.list.find((a) => a.source === "cisa")), "No fix available");
  assert.match(O.fixText(d.list.find((a) => a.source === "abb")), /vendor fix, mitigation, workaround/);
});
