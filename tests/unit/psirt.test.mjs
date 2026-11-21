// Unit tests for the vendor advisory parsers and rules (scripts/lib/psirt.mjs; node --test, no dependencies) and the
// vendor's exploited statement in the CyberView rating (site/cvedb-lib.js). Fixtures in tests/fixtures/psirt/ are real
// replies saved on 2026-11-21 and trimmed (fewer items, shorter texts); variants built inside a test say so.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import * as P from "../../scripts/lib/psirt.mjs";

const FX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "psirt");
const txt = (f) => readFileSync(join(FX, f), "utf8");
const json = (f) => JSON.parse(txt(f));
const sandbox = { window: {} };
vm.runInNewContext(readFileSync(new URL("../../site/cvedb-lib.js", import.meta.url), "utf8"), sandbox);
const D = sandbox.window.CVDB;
const plain = (x) => JSON.parse(JSON.stringify(x));

test("exploited statements: the vendors' own words count, denials, hypotheticals and PoC-only notes do not", () => {
  const yes = [
    "Google is aware that an exploit for CVE-2026-125350 exists in the wild.",
    "The Cisco PSIRT is aware of limited exploitation of this vulnerability.",
    "In September 2026, the Cisco PSIRT became aware of active exploitation of this vulnerability.",
    "Cisco PSIRT is aware of attempted malicious use of the vulnerability described in this advisory.",
    "At the time of disclosure, we are aware of very limited exploitation of CVE-2026-6973, which requires admin authentication for successful exploitation.",
    "At the time of disclosure, we are aware of a very limited number of customers whose solution has been exploited.",
    "Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals.",
    "There are indications that the following may be under limited, targeted exploitation.",
    "We are aware of reports of this vulnerability being exploited in the wild.",
    "Fortinet has observed this to be exploited in the wild.",
  ];
  const no = [
    "The Cisco Product Security Incident Response Team (PSIRT) is not aware of any public announcements or malicious use of the vulnerabilities that are described in this advisory.",
    "We have no evidence of these vulnerabilities being exploited in the wild.",
    "At the time of this publication, we are not aware of any customers being exploited through the vulnerability disclosed today.",
    "During active exploitation of this vulnerability, administrators may notice increased CPU usage.",
    "While the vulnerability described in this advisory is being actively exploited, the output of show conn will show a large number of connections.",
    "The risk of the vulnerability being exploited also depends on the accessibility of the interface to the attacker.",
    "The vulnerabilities are all variants of the same attack and differ in the way that speculative execution is exploited.",
    "The Cisco PSIRT is aware that proof-of-concept exploit code is available for the vulnerability.",
    "AI is compressing the time-to-exploit, and Ivanti uses leading technologies to proactively find and fix issues.",
    "Oracle continues to periodically receive reports of attempts to maliciously exploit vulnerabilities for which Oracle has already released security patches.",
  ];
  for (const s of yes) assert.equal(P.exploitedSentences(s).length, 1, s);
  for (const s of no) assert.deepEqual(P.exploitedSentences(s), [], s);
  // a statement names the CVEs it covers; an unnamed one covers the advisory's only CVE, or none of several
  assert.deepEqual(P.exploitation(["Google is aware that an exploit for CVE-2026-1002 exists in the wild."], ["CVE-2026-1001", "CVE-2026-1002"]).exploited_cves, ["CVE-2026-1002"]);
  assert.deepEqual(P.exploitation(["We are aware of limited exploitation in the wild."], ["CVE-2026-1001"]).exploited_cves, ["CVE-2026-1001"]);
  const many = P.exploitation(["We are aware of limited exploitation in the wild."], ["CVE-2026-1001", "CVE-2026-1002"]);
  assert.ok(many.exploited); assert.deepEqual(many.exploited_cves, []);
});

test("Microsoft: CVRF release list and the monthly document (exploit status, severity, fixed builds, Linux packages and cloud fixes)", () => {
  assert.deepEqual(P.msrcReleases(json("msrc-updates.json")), ["2026-Nov", "2026-Oct"]);
  const list = P.parseMsrc(json("msrc-cvrf.json")), by = Object.fromEntries(list.map((a) => [a.id, a]));
  assert.equal(list.length, 3, "the Azure Linux (Mariner) package is left out");
  const x = by["CVE-2026-124194"];
  assert.equal(x.vendor, "Microsoft"); assert.equal(x.url, "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-124194");
  assert.ok(x.exploited); assert.deepEqual(x.exploited_cves, ["CVE-2026-124194"]); assert.match(x.exploited_text, /Exploited:Yes/);
  assert.equal(x.severity, "Moderate"); assert.equal(x.cvss, 6.5); assert.ok(!/E:H/.test(x.vector), "temporal metrics dropped from the vector");
  assert.ok(x.fixed.includes("16.0.14334.21048") && x.fixed.every((f) => !/^https?:/.test(f)), x.fixed);
  const sp = by["CVE-2026-70193"];
  assert.equal(sp.severity, "Critical"); assert.ok(sp.no_action, "Customer Action Required: No"); assert.ok(!sp.exploited);
  assert.ok(!P.leadWorthy({ ...sp, published: new Date().toISOString() }), "a cloud fix with no customer action is never a lead");
});

test("CSAF: Cisco (exploited and not), Fortinet, Palo Alto Networks, Red Hat", () => {
  const cx = P.parseCsaf(json("cisco-csaf-exploited.json"), { vendor: "Cisco", vkey: "cisco" });
  assert.equal(cx.id, "cisco-sa-sdwan-rpa-EHchtZk"); assert.ok(cx.exploited); assert.deepEqual(cx.exploited_cves, ["CVE-2026-20127"]);
  assert.equal(cx.exploited_text, "The Cisco PSIRT is aware of limited exploitation of this vulnerability.");
  assert.equal(cx.cvss, 10); assert.equal(cx.severity, "Critical"); assert.match(cx.url, /^https:\/\/sec\.cloudapps\.cisco\.com\/security\/center\/content\/CiscoSecurityAdvisory\//);
  const c = P.parseCsaf(json("cisco-csaf.json"), { vendor: "Cisco", vkey: "cisco" });
  assert.ok(!c.exploited, "'not aware of any ... malicious use' is a denial"); assert.deepEqual(c.cves, ["CVE-2026-20340", "CVE-2026-20341"]);
  // variant: a detail section describing what an attack looks like is not read as a statement that one happened
  const v = json("cisco-csaf.json"); v.document.notes.push({ category: "general", title: "Details", text: "This vulnerability has been exploited in the wild in lab conditions." });
  assert.ok(!P.parseCsaf(v, { vendor: "Cisco", vkey: "cisco" }).exploited);
  const f = P.parseCsaf(json("fortinet-csaf.json"), { vendor: "Fortinet", vkey: "fortinet" });
  assert.equal(f.id, "FG-IR-26-271"); assert.equal(f.severity, "Critical"); assert.equal(f.url, "https://fortiguard.fortinet.com/psirt/FG-IR-26-271");
  assert.deepEqual(f.fixed, ["FortiAuthenticator 8.0: Upgrade to 8.0.4 or above", "FortiAuthenticator 6.6: Upgrade to 6.6.11 or above"]);
  const pan = P.parseCsaf(json("paloalto-csaf.json"), { vendor: "Palo Alto Networks", vkey: "paloalto" });
  assert.deepEqual(pan.cves, ["CVE-2024-3400"]); assert.equal(pan.cvss, 10); assert.match(pan.vector, /^CVSS:4\.0\//);
  assert.ok(pan.fixed.length && pan.fixed.every((x) => /PAN-OS >=\d/.test(x) && !/vers:/.test(x)), pan.fixed);
  const rh = P.parseCsaf(json("redhat-csaf.json"), { vendor: "Red Hat", vkey: "redhat" });
  assert.equal(rh.id, "RHSA-2026:53806"); assert.equal(rh.severity, "Important"); assert.equal(rh.url, "https://access.redhat.com/errata/RHSA-2026:53806");
  assert.deepEqual(rh.fixed, ["Red Hat JBoss Enterprise Application Platform 7.4.25"]);
  assert.equal(P.parseCsaf({ nope: 1 }, { vendor: "X", vkey: "x" }), null);
});

test("Cisco RSS and CSAF index; Red Hat new advisories by number", () => {
  const items = P.parseCiscoRss(txt("cisco-rss.xml"));
  assert.equal(items.length, 2); assert.equal(items[0].id, "cisco-sa-nginx-nov-2026-e8jska2s"); assert.equal(items[0].updated, "2026-11-21T17:52:10Z");
  assert.ok(!items[0].url.includes("?"), "tracking parameters dropped");
  const paths = P.ciscoCsafPaths(txt("cisco-index.txt"));
  assert.equal(paths.get("cisco-sa-nov2026-java-rce-eca6ss9z"), "2026/cisco-sa-nov2026-java-rce-eca6ss9z.json");
  const base = "https://security.access.redhat.com/data/csaf/v2/advisories/", all = P.parseChanges(txt("redhat-changes.csv"), base);
  assert.equal(all.length, 6); assert.ok(all.every((c) => c.url.startsWith(base) && /Z$/.test(c.at)));
  const fresh = P.redhatNew(all, 20260070228);
  assert.deepEqual(fresh.map((c) => c.url.split("/").pop()), ["rhsa-2026_70229.json", "rhsa-2026_70230.json", "rhsa-2026_70277.json"]);
  assert.deepEqual(P.parseChanges('"../x.json","2026-11-21T00:00:00Z"\njunk', base), [], "no path outside the directory");
});

test("Fortinet, Palo Alto Networks, Oracle and Ivanti feeds", () => {
  const ft = P.parseFortinetRss(txt("fortinet-rss.xml"));
  assert.equal(ft.length, 3); assert.equal(ft[0].id, "FG-IR-26-279"); assert.match(ft[0].csaf, /^https:\/\/filestore\.fortinet\.com\/fortiguard\/psirt\/csaf_/);
  const fa = P.fortinetFromRss(ft[0]); assert.equal(fa.cvss, 8.1); assert.equal(fa.severity, "High"); assert.ok(fa.cves.includes("CVE-2026-123007"));
  const pan = P.parsePanRss(txt("paloalto-rss.xml"));
  assert.deepEqual(pan.map((x) => [x.id, x.severity]), [["CVE-2026-123633", "CRITICAL"], ["CVE-2026-114938", "CRITICAL"], ["CVE-2026-0328", "LOW"]]);
  assert.ok(!/Severity/.test(pan[2].title));
  const or = P.parseOracleRss(txt("oracle-rss.xml"));
  assert.deepEqual(or.map((x) => [x.id, x.alert]), [["CSPUNov2026", false], ["CPUOct2026", false], ["alertcve202635273", true]]);
  assert.deepEqual(or[2].cves, ["CVE-2026-35273"]);
  const iv = P.parseIvantiRss(txt("ivanti-rss.xml"));
  const epmm = iv.find((a) => a.id === "may-2026-epmm-security-update");
  assert.ok(epmm.exploited); assert.deepEqual(epmm.exploited_cves, ["CVE-2026-6973"]);
  const nov = iv.find((a) => a.id === "november-2026-security-update");
  assert.ok(nov && !nov.exploited, "'no evidence of these vulnerabilities being exploited' is a denial");
  const oct = iv.find((a) => a.id === "october-2026-security-update");
  if (oct) assert.ok(oct.exploited && oct.exploited_cves.length <= oct.cves.length);
});

test("Debian, Ubuntu, Chrome, Apple and Mozilla", () => {
  const dsa = P.parseDebianRdf(txt("debian-dsa.rdf"));
  assert.deepEqual(dsa.map((d) => d.id), ["DSA-6646-1", "DSA-6645-1", "DSA-6644-1"]); assert.equal(dsa[0].url, "https://security-tracker.debian.org/tracker/DSA-6646-1");
  assert.deepEqual(P.parseDebianTracker(txt("debian-tracker.html")), { cves: ["CVE-2026-129975"], fixed: ["gpgme1.0 1.24.2-3+deb13u1 (trixie)"] });
  const ub = P.parseUbuntu(json("ubuntu-notices.json"));
  assert.equal(ub[0].id, "USN-9184-1"); assert.equal(ub[0].url, "https://ubuntu.com/security/notices/USN-9184-1"); assert.deepEqual(ub[0].fixed, ["linux-nvidia-tegra-igx 5.15.0-1061.61 (jammy)"]);
  const ch = P.parseChromeAtom(txt("chrome-atom.xml"));
  const d = ch.find((a) => a.id === "chrome-157.0.8103.50-desktop");
  assert.ok(d && d.exploited); assert.deepEqual(d.exploited_cves, ["CVE-2026-125350"]); assert.equal(d.severity, "High");
  assert.deepEqual(d.fixed, ["Chrome 157.0.8103.50 (Desktop)"]); assert.match(d.url, /^https:\/\/chromereleases\.googleblog\.com\/2026\/11\//);
  assert.ok(!ch.some((a) => /Beta/.test(a.title)), "beta channel posts are not security releases");
  const ai = P.parseAppleIndex(txt("apple-index.html"));
  assert.deepEqual(ai[0], { url: "https://support.apple.com/en-us/149721", name: "tvOS 27.2.1", date: "2026-11-13T12:00:00Z" });
  assert.ok(!ai.some((r) => /HomeView Software Version 27\.2\.1/.test(r.name)), "a release with no CVE entries has no page");
  const ap = P.parseApplePage(txt("apple-page.html"), "https://support.apple.com/en-us/149715", "iOS 27.2.1 and iPadOS 27.2.1");
  assert.equal(ap.id, "apple-149715"); assert.ok(ap.cves.includes("CVE-2026-113968")); assert.ok(!ap.exploited); assert.equal(ap.published, "2026-11-09T12:00:00Z");
  // variant: Apple's own note on one entry marks that entry's CVE only
  const v = txt("apple-page.html").replace("Impact: An attacker in Bluetooth range may be able to corrupt process memory", "Impact: An attacker in Bluetooth range may be able to corrupt process memory. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals.");
  const apx = P.parseApplePage(v, "https://support.apple.com/en-us/149715", "iOS 27.2.1 and iPadOS 27.2.1");
  assert.ok(apx.exploited); assert.deepEqual(apx.exploited_cves, ["CVE-2026-113970"]);
  const mi = P.parseMozillaIndex(txt("mozilla-index.html"));
  assert.deepEqual(mi[0], { id: "MFSA 2026-130", url: "https://www.mozilla.org/en-US/security/advisories/mfsa2026-130/", severity: "high", title: "Security Vulnerabilities fixed in Firefox 160.0.1", published: "2026-11-17T12:00:00Z" });
  const mp = P.parseMozillaPage(txt("mozilla-page.html"), mi[0]);
  assert.deepEqual(mp.cves, ["CVE-2026-130020", "CVE-2026-130021"]); assert.deepEqual(mp.fixed, ["Firefox 160.0.1"]); assert.equal(mp.severity, "High"); assert.ok(!mp.exploited);
});

test("records: checked, merged with caps, joined on CVE, and leads only for exploited or critical", () => {
  assert.equal(P.advisory({ vkey: "x", id: "1", url: "javascript:alert(1)" }), null);
  const a = P.advisory({ vendor: "V", vkey: "v", id: "A-1", url: "https://v.example/a1", cves: ["cve-2026-1001", "bad"], severity: "CRITICAL", cvss: 11, exploited: false, exploited_text: "x", published: "2026-11-20T00:00:00Z" });
  assert.deepEqual(a.cves, ["CVE-2026-1001"]); assert.equal(a.severity, "Critical"); assert.equal(a.cvss, null); assert.equal(a.exploited_text, "");
  const now = Date.parse("2026-11-21T00:00:00Z"), mk = (i, o = {}) => P.advisory({ vendor: "V", vkey: "ubuntu", id: "U-" + i, url: "https://v.example/" + i, cves: ["CVE-2026-" + (1000 + i)], published: new Date(now - i * 36e5).toISOString(), ...o });
  const many = Array.from({ length: 450 }, (_, i) => mk(i));
  const old = mk(449, { exploited: true, exploited_cves: ["CVE-2026-1449"], exploited_text: "We are aware of exploitation in the wild." });
  const kept = P.merge([old], many, now);
  assert.equal(kept.length, 401, "newest 400, plus the exploited one carried from the last run"); assert.ok(kept.find((k) => k.id === "U-449" && k.exploited), "an exploited statement is never lost when a later read misses it");
  assert.ok(kept.every((k) => k.first_seen));
  const j = P.byCve([P.advisory({ vendor: "V", vkey: "v", id: "A", url: "https://v.example/a", cves: ["CVE-2026-1001", "CVE-2026-1002"], exploited: true, exploited_cves: ["CVE-2026-1002"], exploited_text: "exploited in the wild", fixed: ["1.2"] })]);
  assert.equal(j["CVE-2026-1001"][0][4], ""); assert.equal(j["CVE-2026-1002"][0][4], "exploited in the wild"); assert.deepEqual(j["CVE-2026-1002"][0][5], ["1.2"]);
  const recent = new Date().toISOString();
  assert.ok(P.leadWorthy({ ...a, published: recent, exploited: true }));
  assert.ok(P.leadWorthy({ ...a, vkey: "microsoft", severity: "Critical", cvss: 9.8, published: recent }));
  assert.ok(!P.leadWorthy({ ...a, vkey: "microsoft", severity: "Critical", cvss: 8.8, published: recent }), "Microsoft's many Critical 8.8s are not leads");
  assert.ok(!P.leadWorthy({ ...a, vkey: "ubuntu", severity: "Critical", published: recent }), "distribution rebuilds only when exploited");
  assert.ok(!P.leadWorthy({ ...a, exploited: true, published: "2026-01-01T00:00:00Z", updated: "2026-01-01T00:00:00Z" }), "older than a week");
  const l = P.toLead({ ...a, exploited: true, exploited_cves: ["CVE-2026-1001"], exploited_text: "We are aware of exploitation in the wild." }, "2026-11-21T00:00:00Z");
  assert.equal(l.kind, "advisory"); assert.equal(l.tier, "vendor"); assert.equal(l.via, "psirt"); assert.match(l.title, /^V says exploited in the wild: .*CVE-2026-1/); assert.equal(l.url, "https://v.example/a1");
});

test("rating: the vendor's own exploited statement is Exploit Code Maturity High, labelled, and only for the CVE it covers", () => {
  const idx = D.cleanVendorIndex({ cve: {
    "CVE-2026-7001": [["Acme", "ACME-1", "https://vendor.example/a1", "Critical", "Acme is aware of limited exploitation in the wild.", ["2.4.1"]]],
    "CVE-2026-7002": [["Acme", "ACME-1", "https://vendor.example/a1", "Critical", "", []]],
    "CVE-2026-7003": [["Bad", "B-1", "javascript:alert(1)", "", "x", []]], "not-an-id": [["A", "1", "https://x.example", "", "", []]] } });
  assert.deepEqual(Object.keys(idx).sort(), ["CVE-2026-7001", "CVE-2026-7002"]);
  const x = D.exploitation({ id: "CVE-2026-7001", cvss: 9.8, adv: idx["CVE-2026-7001"] });
  assert.equal(x.value, "active"); assert.equal(x.source, "vendor"); assert.match(x.basis, /^Acme's own advisory \(ACME-1\) says it is exploited in the wild \(the vendor's statement; CISA has not confirmed it\)$/);
  const sc = D.score({ id: "CVE-2026-7001", cvss: 9.8, ver: "3.1", adv: idx["CVE-2026-7001"] });
  assert.equal(sc.score, 9.8); assert.equal(sc.e.label, "High"); assert.match(sc.confidenceWhy, /vendor's own advisory/);
  assert.equal(D.score({ id: "CVE-2026-7002", cvss: 9.8, ver: "3.1", adv: idx["CVE-2026-7002"] }).score, 9.0, "an advisory without an exploited statement changes nothing");
  // CISA's catalog stays first; the vendor's statement only ever raises the answer
  assert.equal(D.exploitation({ id: "CVE-2026-7001", kev: "2026-11-01", adv: idx["CVE-2026-7001"] }).source, "cisa-kev");
  assert.equal(D.exploitation({ id: "CVE-2026-7001", expl: "poc", adv: idx["CVE-2026-7001"] }).source, "vendor");
  assert.equal(D.rate({ id: "CVE-2026-7001", cvss: 9.8, vec: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", adv: idx["CVE-2026-7001"] }).inputs[0].source, "vendor");
  // a lookup-file row picks up the join the page loaded
  D.vendorIndex = idx;
  const r = D.cleanRow(["id", "state", "cvss"], ["CVE-2026-7001", "P", 9.8]);
  assert.equal(plain(r.adv)[0].id, "ACME-1");
  D.vendorIndex = {};
});
