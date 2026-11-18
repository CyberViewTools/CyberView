import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { parseAffected, parseCvss } from "../../scripts/lib/affected.mjs";
import { checkGuide, checkHunt } from "../../scripts/lib/validate.mjs";
// the browser file attaches itself to window; run it in a sandbox with a stand-in window
const sandbox = { window: {} };
vm.runInNewContext(readFileSync(new URL("../../site/workbench-lib.js", import.meta.url), "utf8"), sandbox);
const W = sandbox.window.CVWorkbench;
const plain = (x) => JSON.parse(JSON.stringify(x));

test("versions compare piece by piece", () => {
  assert.equal(W.cmp("7.2.4", "7.2.10"), -1);
  assert.equal(W.cmp("7.2", "7.2.0"), 0);
  assert.equal(W.cmp("22.7R2", "22.7R1"), 1);
  assert.equal(W.cmp("2.3.20.1", "2.3.20.3"), -1);
  assert.equal(W.cmp("v1.10", "1.9"), 1);
  assert.equal(W.cmp("7.2.1", "7.2.rc"), 1);
});
test("ranges: start, end, exact and all-versions", () => {
  const r = { from: "6.4.0", from_incl: true, to: "7.4.10", to_incl: false };
  assert.equal(W.inRange("7.2.4", r), true);
  assert.equal(W.inRange("7.4.10", r), false);
  assert.equal(W.inRange("6.2.9", r), false);
  assert.equal(W.inRange("26.2.3", { to: "26.2.3", to_incl: true }), true);
  assert.equal(W.inRange("39", { exact: "39" }), true);
  assert.equal(W.inRange("1.0", {}), true);
  assert.equal(W.inRange("", r), null);
});
test("names: product words must all be present; generic words need the vendor", () => {
  assert.ok(W.nameHit("Fortinet FortiOS", "fortinet", "fortios"));
  assert.ok(W.nameHit("FortiOS", "fortinet", "fortios"));
  assert.ok(W.nameHit("BeyondTrust Remote Support", "beyondtrust", "remote support"));
  assert.ok(W.nameHit("Palo Alto PAN-OS", "paloaltonetworks", "pan-os"));
  assert.ok(!W.nameHit("Windows Server 2022", "acme", "server"));
  assert.ok(W.nameHit("Microsoft Edge", "microsoft", "edge"));
  assert.ok(!W.nameHit("EdgeRouter", "microsoft", "edge"));
  assert.ok(!W.nameHit("SAP NetWeaver", "apple", "safari"));
});
test("inventory: plain lines, with versions and device counts", () => {
  const r = W.parseInventory("x.txt", "FortiOS 7.2.4, 12\nGoogle Chrome, 126.0.6478.61\n# note\nIvanti Connect Secure 22.7R2\nSlack");
  assert.equal(r.items.length, 4);
  assert.deepEqual(plain(r.items[0]), { name: "FortiOS", vendor: "", version: "7.2.4", count: 12 });
  assert.equal(r.items[1].version, "126.0.6478.61");
  assert.equal(r.items[2].version, "22.7R2");
  assert.equal(r.items[3].version, "");
});
test("inventory: CSV with headers, CycloneDX and SPDX", () => {
  const csv = W.parseInventory("apps.csv", 'DisplayName,DisplayVersion,Publisher,Device Count\n"Chrome, Google",126.0.1,Google LLC,40\nZoom,6.1.0,Zoom,3\nZoom,6.1.0,Zoom,2\n');
  assert.equal(csv.kind, "table"); assert.equal(csv.items.length, 2);
  assert.deepEqual(plain(csv.items[0]), { name: "Chrome, Google", vendor: "Google LLC", version: "126.0.1", count: 40 });
  assert.equal(csv.items[1].count, 5);
  const cdx = W.parseInventory("bom.json", JSON.stringify({ bomFormat: "CycloneDX", components: [{ name: "struts", version: "2.3.20.1", publisher: "Apache", components: [{ name: "log4j-core", version: "2.14.1" }] }] }));
  assert.equal(cdx.kind, "CycloneDX"); assert.equal(cdx.items.length, 2);
  const spdx = W.parseInventory("s.json", JSON.stringify({ packages: [{ name: "openssl", versionInfo: "3.0.1", supplier: "Organization: OpenSSL" }] }));
  assert.deepEqual(plain(spdx.items[0]), { name: "openssl", vendor: "OpenSSL", version: "3.0.1", count: 1 });
  assert.equal(W.parseInventory("x.json", "{broken").kind, "unreadable JSON");
});
test("inventory: markup is stripped from names", () => {
  const r = W.parseInventory("x", "<img src=x onerror=alert(1)> 1.0");
  assert.ok(!/[<>]/.test(r.items.map((i) => i.name).join("")));
});
const flaw = { vendor: "Fortinet", product: "Multiple Products", affected: [{ vendor: "fortinet", product: "fortios", from: "6.4.0", from_incl: true, to: "7.4.10", to_incl: false }] };
test("match: affected, fixed, needs a version, not on the list", () => {
  assert.equal(W.match(flaw, [{ name: "FortiOS", vendor: "", version: "7.2.4", count: 12 }]).state, "affected");
  assert.deepEqual(plain(W.match(flaw, [{ name: "FortiOS", vendor: "", version: "7.2.4", count: 1 }]).fixed), ["7.4.10"]);
  assert.equal(W.match(flaw, [{ name: "FortiOS", vendor: "", version: "7.4.10", count: 1 }]).state, "clear");
  assert.equal(W.match(flaw, [{ name: "FortiOS", vendor: "", version: "", count: 1 }]).state, "check");
  assert.equal(W.match(flaw, [{ name: "Slack", vendor: "", version: "4.0", count: 1 }]).state, "none");
  assert.equal(W.match(flaw, [{ name: "FortiOS", vendor: "", version: "7.4.10", count: 1 }, { name: "FortiOS", vendor: "", version: "7.0.1", count: 2 }]).state, "affected");
});
test("score: every point is listed and the total is capped", () => {
  const s = W.score({ kev: true, ransomware: true, epss: 0.97, exploit_public: true, exposure: "internet", due: "2026-11-01", vendor: "Fortinet", product: "FortiOS" }, { state: "affected" }, "2026-11-18");
  assert.equal(s.total, 100);
  assert.equal(s.points.reduce((a, p) => a + p[0], 0), 35 + 10 + 15 + 5 + 10 + 5 + 20);
  const k = W.score({ kev: true, epss: 0.1, vendor: "Fortinet", product: "FortiOS", av: "N" }, null, "2026-11-18");
  assert.ok(k.points.some((p) => /by product keyword/.test(p[1])));
  const local = W.score({ kev: true, vendor: "Fortinet", product: "FortiOS", av: "L" }, null, "2026-11-18");
  assert.ok(!local.points.some((p) => /internet/i.test(p[1])));
  assert.equal(W.score({ kev: false, severity: 3 }, null, "2026-11-18").total, 15);
});

test("NVD record -> affected ranges and CVSS", () => {
  const cve = { metrics: { cvssMetricV31: [{ type: "Primary", cvssData: { baseScore: 9.8, attackVector: "NETWORK" } }] }, configurations: [{ nodes: [{ cpeMatch: [
    { vulnerable: true, criteria: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", versionStartIncluding: "6.4.0", versionEndExcluding: "7.4.10" },
    { vulnerable: true, criteria: "cpe:2.3:a:onlyoffice:document_server:5.6.2:*:*:*:*:*:*:*" },
    { vulnerable: false, criteria: "cpe:2.3:h:fortinet:fortigate:-:*:*:*:*:*:*:*" },
    { vulnerable: true, criteria: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", versionStartIncluding: "6.4.0", versionEndExcluding: "7.4.10" } ] }] }] };
  const a = parseAffected(cve);
  assert.equal(a.length, 2);
  assert.deepEqual(a[0], { vendor: "fortinet", product: "fortios", part: "o", from: "6.4.0", from_incl: true, to: "7.4.10", to_incl: false });
  assert.deepEqual(a[1], { vendor: "onlyoffice", product: "document server", part: "a", exact: "5.6.2" });
  assert.deepEqual(parseCvss(cve), { score: 9.8, av: "N" });
  assert.deepEqual(parseAffected({}), []);
});

const guide = () => ({ cve: "CVE-2026-1234", advisory: { name: "Vendor PSIRT", url: "https://vendor.example/psirt/FG-IR-26-001" }, read_at: "2026-11-18T22:00:00Z", read_depth: "full",
  check: ["Run 'get system status' and compare the version."], fixed: ["7.4.10 or later"], exposure: "internet", exploit_public: true,
  hunt: [{ name: "Indicators (STIX)", format: "stix", url: "https://www.cisa.gov/sites/default/files/x.stix.json", publisher: "CISA" }] });
test("guide: a complete guide passes; weak ones are refused", () => {
  assert.deepEqual(checkGuide(guide(), "CVE-2026-1234"), []);
  assert.ok(checkGuide(guide(), "CVE-2026-9999").some((m) => /file name/.test(m)));
  assert.ok(checkGuide({ ...guide(), read_depth: "secondary" }).some((m) => /read_depth/.test(m)));
  assert.ok(checkGuide({ ...guide(), check: [], fixed: [], workaround: [] }).some((m) => /at least one/.test(m)));
  assert.ok(checkGuide({ ...guide(), advisory: { name: "x", url: "https://vendor.example/" } }).some((m) => /advisory/.test(m)));
});
test("hunt: known formats and https links only", () => {
  assert.ok(checkHunt([{ name: "x", format: "exe", url: "https://a.example/b" }])[0].includes("format"));
  assert.ok(checkHunt([{ name: "x", format: "yara", url: "javascript:alert(1)" }])[0].includes("url"));
});
