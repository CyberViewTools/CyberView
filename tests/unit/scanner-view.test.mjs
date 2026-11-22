// site/scanner-lib.js: the Scanner page's report viewer and scope-file builder (browser only). The viewer's counts and diff
// must agree with the scanner's own summarize() and diff.mjs, and a scope file the page builds must pass the scanner's own
// checkScope and its `check` command. The page's mirrors of scope.mjs are compared with the real thing input by input.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { isIP } from "node:net";
import vm from "node:vm";
import { checkScope, parseTarget, classify, STATEMENT, PUBLIC_FLAG, LIMITS, template } from "../../scanner/lib/scope.mjs";
import { diffReports, cleanReport as diffClean } from "../../scanner/lib/diff.mjs";
import { summarize } from "../../scanner/lib/report.mjs";
import { parsePorts } from "../../scanner/lib/scan.mjs";
import { DEFAULT_PORTS } from "../../scanner/lib/probe.mjs";
import { DEFAULT_SOURCE } from "../../scanner/lib/data.mjs";
import { main } from "../../scanner/cyberview-scan.mjs";

const ROOT = new URL("../../", import.meta.url).pathname;
const sb = { window: {}, URL };
vm.runInNewContext(readFileSync(join(ROOT, "site", "scanner-lib.js"), "utf8"), sb);
const V = sb.window.CVScanView;
const FIX = join(ROOT, "tests", "fixtures", "scanner", "viewer");
const A = readFileSync(join(FIX, "report-a.json"), "utf8"), Bt = readFileSync(join(FIX, "report-b.json"), "utf8");
const plain = (x) => JSON.parse(JSON.stringify(x));
const io = () => { const out = [], err = []; return { out: (s) => out.push(s), err: (s) => err.push(s), lines: { out, err }, fetchImpl: () => { throw new Error("no network"); } }; };
const TODAY = new Date().toISOString().slice(0, 10);

test("the page's constants are the scanner's own", () => {
  assert.equal(V.STATEMENT, STATEMENT);
  assert.equal(V.PUBLIC_FLAG, PUBLIC_FLAG);
  for (const k of Object.keys(V.SCOPE_LIMITS)) assert.equal(V.SCOPE_LIMITS[k], LIMITS[k], k);
  assert.equal(template(TODAY).attestation.statement, V.STATEMENT);
  assert.deepEqual(plain(V.DEFAULT_PORTS), DEFAULT_PORTS);
  assert.ok(V.BASE_HOSTS.includes(new URL(DEFAULT_SOURCE).hostname), "CyberView's own site is an allowed link host");
});

test("viewer: a real report parses, and the tiles use summarize()'s definitions", () => {
  for (const text of [A, Bt]) {
    const p = V.parse(text); assert.ok(p.report, p.error);
    const raw = JSON.parse(text), c = V.counts(p.report), s = summarize(raw.hosts, raw.findings);
    for (const k of ["hosts_up", "open_ports", "known_exploited", "critical", "act", "overdue", "observations"]) assert.equal(c[k], s[k], k);
    assert.equal(c.services, s.services_identified); assert.equal(c.findings, s.findings); assert.equal(c.low_confidence, s.low_confidence);
  }
  const r = V.parse(A).report;
  assert.equal(r.scope.owner, "Example lab"); assert.equal(r.scope.attestation.name, "Test Operator"); assert.equal(r.coverage.complete, false);
  assert.deepEqual(plain(r.coverage.unreachable), ["10.0.0.7"]);
  assert.ok(r.run.sends.some((x) => x.what === "http"));
  const f = r.findings.find((x) => x.cve === "CVE-2026-90101");
  assert.ok(f.points.list.length >= 3 && f.points.list.every((p) => p.why && Number.isInteger(p.points)), "every rating point is kept");
  assert.match(f.rating.text, /Exploit Code Maturity/);
});

test("viewer: low-confidence findings are listed but not counted, like the scanner", () => {
  const raw = JSON.parse(A);
  raw.findings[0].confidence = "low";
  const c = V.counts(V.cleanReport(raw)), s = summarize(raw.hosts, raw.findings);
  assert.equal(c.known_exploited, s.known_exploited); assert.equal(c.low_confidence, 1);
});

test("viewer: untrusted input is refused or cut to size", () => {
  assert.match(V.parse("").error, /empty/);
  assert.match(V.parse("{nope").error, /not valid JSON/);
  assert.match(V.parse(JSON.stringify({ tool: { name: "other" }, hosts: [], findings: [] })).error, /not a CyberView Scanner report/);
  assert.match(V.parse(JSON.stringify([1, 2])).error, /not a CyberView/);
  const r = V.parse(JSON.stringify({ tool: { name: "CyberView Scanner", version: "<b>x</b>".repeat(10) }, run: { ports: [22, "x", 99999], started_at: "<img>" },
    scope: { owner: "A".repeat(5000), sha256: "javascript:alert(1)" },
    hosts: [{ address: "10.0.0.5", up: true, ports: [{ port: 22, state: "open" }, { port: "22" }], services: [{ port: 22, product: "P".repeat(500), evidence: "\u0007bell" }],
      observations: [{ port: 22, kind: "k", severity: "evil", text: "t" }], __proto__: { polluted: true } }, "junk", null],
    findings: [{ cve: "not-a-cve" }, { cve: "CVE-2026-90101", rating: { score: 99, band: "Critical" }, seen_on: [{ host: "10.0.0.5", port: 22, confidence: "certain" }] }] })).report;
  assert.deepEqual(plain(r.run.ports), [22]); assert.equal(r.run.started_at, ""); assert.equal(r.tool.version.length, 20);
  assert.equal(r.scope.owner.length, 160); assert.equal(r.scope.sha256, "");
  assert.equal(r.hosts.length, 1); assert.equal(r.hosts[0].ports.length, 1); assert.equal(r.hosts[0].services[0].product.length, 120); assert.equal(r.hosts[0].services[0].evidence, " bell");
  assert.equal(r.hosts[0].observations[0].severity, "info");
  assert.equal(r.findings.length, 1); assert.equal(r.findings[0].rating.score, null); assert.equal(r.findings[0].rating.band, "Not scored"); assert.equal(r.findings[0].seen_on[0].confidence, "low");
  assert.equal({}.polluted, undefined);
  assert.match(V.parse("x".repeat(V.LIMITS.maxBytes + 1)).error, /larger than 64 MB/);
});

test("viewer: filters by host, rating, known exploited and confidence", () => {
  const rows = V.rows(V.parse(A).report);
  assert.equal(rows.length, 3);
  assert.deepEqual(plain(V.filterRows(rows, { host: "10.0.0.6" }).map((x) => x.f.cve)), ["CVE-2026-90104"]);
  assert.deepEqual(plain(V.filterRows(rows, { band: "Critical" }).map((x) => x.f.cve)), ["CVE-2026-90102"]);
  assert.equal(V.filterRows(rows, { band: "High" }).length, 2);
  assert.equal(V.filterRows(rows, { kev: true }).length, 3);
  assert.equal(V.filterRows(rows, { confidence: "high" }).length, 3);
  rows[0].s.confidence = "low";
  assert.equal(V.filterRows(rows, { confidence: "medium" }).length, 2);
  assert.equal(V.filterRows(rows, {}).length, 3);
});

test("viewer: links only https, on an allowed host, without credentials", () => {
  const allow = V.allowSet(V.hostsIn({ a: ["https://vendor.example/adv", { b: "https://Hunt.Example:443/x" }], c: "http://plain.example/", d: "javascript:alert(1)" }));
  assert.equal(V.safeUrl("https://vendor.example/adv?x=1", allow), "https://vendor.example/adv?x=1");
  assert.equal(V.safeUrl("https://hunt.example/y", allow), "https://hunt.example/y");
  assert.equal(V.safeUrl("https://xanderhutch.github.io/CyberView/vulnerabilities.html#CVE-2026-90101", allow), "https://xanderhutch.github.io/CyberView/vulnerabilities.html#CVE-2026-90101");
  for (const bad of ["http://vendor.example/adv", "https://evil.example/", "javascript:alert(1)", "https://user:pw@vendor.example/", "https://vendor.example:8443/", "https://vendor.example/a b", "data:text/html,x", "", null, 5])
    assert.equal(V.safeUrl(bad, allow), "", String(bad));
  assert.equal(allow["plain.example"], undefined);
});

test("diff: the page's mirror gives exactly what scanner/lib/diff.mjs gives", () => {
  const a = JSON.parse(A), b = JSON.parse(Bt);
  const mine = plain(V.diffReports(a, b)), theirs = plain(diffReports(a, b));
  assert.deepEqual(mine, theirs);
  assert.ok(mine.findings.fixed.some((x) => x.cve === "CVE-2026-90101"), "OpenSSH upgraded: fixed");
  assert.ok(mine.findings.gone.some((x) => x.cve === "CVE-2026-90102"), "the web port closed: gone, not fixed");
  assert.equal(mine.certificates.issuer_changed.length, 1);
  assert.deepEqual(plain(V.diffReports(b, a)), plain(diffReports(b, a)));
  // the synthetic cases of the scanner's own diff test, with a not-checked host, a down host and UDP
  const rep = (o) => ({ tool: { name: "CyberView Scanner" }, run: { started_at: o.at || "2026-11-01T00:00:00Z", ports: o.ports || [22, 80, 443], interrupted: !!o.int, udp: o.udp || [] }, scope: { sha256: o.sha || "abc" },
    coverage: { ports_not_checked: o.notChecked || [] }, hosts: o.hosts, findings: o.findings || [] });
  const H = (address, ports, extra = {}) => ({ address, names: [], up: true, ports: ports.map((port) => ({ port, state: "open" })), services: [], tls: [], observations: [], ...extra });
  const F = (cve, host, port, v = "") => ({ cve, title: cve, kev: true, seen_on: [{ host, port, product: "x", shown_version: v, confidence: "high" }] });
  const prev = rep({ hosts: [H("10.0.0.5", [22, 80, 443], { services: [{ port: 22, label: "OpenSSH", product: "OpenSSH", shown_version: "9.6p1" }], tls: [{ port: 443, cert: { fingerprint256: "AA", issuer: "CN=Old CA", spki_sha256: "K1" } }],
    observations: [{ port: 443, kind: "tls-expiring", severity: "medium", text: "x" }] }), H("10.0.0.6", [22]), H("10.0.0.7", [22]), H("10.0.0.9", [8080])],
  findings: [F("CVE-2026-90101", "10.0.0.5", 22, "9.6p1"), F("CVE-2026-90102", "10.0.0.5", 80), F("CVE-2026-90103", "10.0.0.6", 22), F("CVE-2026-90104", "10.0.0.7", 22), F("CVE-2026-90105", "10.0.0.5", 443), F("CVE-2026-90106", "10.0.0.9", 8080)] });
  const cur = rep({ at: "2026-11-22T00:00:00Z", sha: "def", udp: ["dns", "bogus"], notChecked: [{ address: "10.0.0.7", not_checked: 5 }], hosts: [
    H("10.0.0.5", [22, 443], { services: [{ port: 22, label: "OpenSSH", product: "OpenSSH", shown_version: "9.9" }], tls: [{ port: 443, cert: { fingerprint256: "BB", issuer: "CN=New CA", spki_sha256: "K2" } }], udp: [{ port: 53, state: "open" }] }),
    { ...H("10.0.0.6", []), up: false }, H("10.0.0.7", []), H("10.0.0.8", [3389]), H("10.0.0.9", [])], findings: [F("CVE-2026-90105", "10.0.0.5", 443), F("CVE-2026-90199", "10.0.0.8", 3389)] });
  assert.deepEqual(plain(V.diffReports(prev, cur)), plain(diffReports(prev, cur)));
  assert.deepEqual(plain(V.diffReports(cur, prev)), plain(diffReports(cur, prev)));
  assert.deepEqual(plain(V.diffReports(rep({ int: true, hosts: [] }), cur)), plain(diffReports(rep({ int: true, hosts: [] }), cur)));
  // the cleaned shapes agree too (the Set of not-checked hosts is an object of keys here)
  const dc = diffClean(cur), vc = V.diffClean(cur);
  assert.deepEqual(plain(vc.hosts), plain(dc.hosts)); assert.deepEqual(plain(vc.findings), plain(dc.findings)); assert.deepEqual(plain(vc.ports), plain(dc.ports));
  assert.deepEqual(Object.keys(vc.not_checked), [...dc.not_checked]);
});

test("scope mirror: isIP, parseTarget and classify agree with the scanner's", () => {
  const inputs = ["10.0.0.5", "10.0.0.5/24", "192.168.1.0/16", "8.8.8.8", "8.8.8.0/24", "8.8.0.0/16", "0.0.0.0", "0.0.0.0/8", "127.0.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255", "240.0.0.1",
    "01.2.3.4", "1.2.3", "256.1.1.1", "1.2.3.4/33", "1.2.3.4/x", "1.2.3.4/", "::1", "::", "fe80::1", "fd00::1", "fd00::/120", "fd00::/64", "2001:db8::1", "2001:DB8:0:0:0:0:0:1", "::ffff:10.0.0.1",
    "::ffff:8.8.8.8", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "1::2::3", ":::1", "1:", ":1", "1:2:3:4:5:6:7::", "::1:2:3:4:5:6:7", "12345::1", "g::1", "1.2.3.4::", "::1.2.3.4", "ff02::1",
    "example.org", "Host.Example.ORG.", "-bad.example", "bad-.example", "a..b", "localhost", "host_name.example", "a".repeat(64) + ".example", "x".repeat(300), "", "  10.0.0.1  ", "10.0.0.1 /24", "abc/24"];
  for (const s of inputs) {
    assert.equal(V.isIP(s.trim()), isIP(s.trim()), `isIP ${s}`);
    const a = parseTarget(s), b = V.parseTarget(s);
    assert.equal(b.error ? "error" : b.kind, a.error ? "error" : a.kind, `parseTarget kind ${s}`);
    if (!a.error) { assert.equal(b.text, a.text, `parseTarget text ${s}`); if (a.kind !== "host") assert.equal(V.classify(b.kind === "ip" ? b.text : b.text.split("/")[0]), classify(a.kind === "ip" ? a.text : a.text.split("/")[0]), `classify ${s}`); }
    else assert.equal(b.error, a.error, `parseTarget error ${s}`);
  }
  for (const p of ["22", "22,80", "8000-8010", "0", "1-70000", "80-22", "x", "", "1-1025"]) {
    const a = parsePorts(p), b = V.parsePorts(p);
    if (a.error) assert.equal(b.error, a.error, p); else assert.deepEqual(plain(b.ports), a.ports, p);
  }
});

const FORM = { owner: "Example lab", contact: "lab@example.org", name: "Test Operator", targets: "10.0.0.5\n10.0.1.0/24\n# a comment\nfiles.lab.example\n10.0.0.5", exclude: "10.0.1.1", ports: "default", agreed: true };

test("scope builder: no file without the attestation, and the scanner's own problems", () => {
  const r = V.buildScope({ ...FORM, agreed: false }, TODAY);
  assert.equal(r.ok, false); assert.equal(r.text, ""); assert.equal(r.scope, null); assert.ok(r.problems.some((p) => /Attestation: tick the box/.test(p)));
  assert.equal(V.buildScope({ ...FORM, agreed: "true" }, TODAY).ok, false, "only a real tick counts");
  const bad = V.buildScope({ owner: "", name: "", targets: "0.0.0.0\n10.0.0.0/8\n8.8.0.0/16\nnot a host!\nff02::1", exclude: "???", ports: "custom", customPorts: "1-70000", agreed: true, expires: "2000-01-01" }, TODAY);
  assert.equal(bad.ok, false); assert.equal(bad.text, "");
  for (const re of [/Owner/, /Your name/, /unspecified address/, /wider than a \/16/, /public range wider than a \/24/, /is not an address, a CIDR range or a host name/, /multicast/, /Exclude:/, /Ports: "1-70000" is outside/, /Valid until: the date has passed/])
    assert.ok(bad.problems.some((p) => re.test(p)), String(re));
  assert.match(V.buildScope({ ...FORM, targets: "" }, TODAY).problems.join(" "), /at least one host/);
  assert.match(V.buildScope({ ...FORM, targets: Array.from({ length: 5 }, (_, i) => `8.8.${i}.0/24`).join("\n") }, TODAY).problems.join(" "), /public addresses; at most 1024/);
});

test("scope builder: the file passes the scanner's checkScope and `check` command", async () => {
  const r = V.buildScope(FORM, TODAY);
  assert.equal(r.ok, true, r.problems.join("; "));
  assert.equal(r.needsPublic, false); assert.deepEqual(plain(r.hosts), ["files.lab.example"]);
  const c = checkScope(r.text, { today: TODAY });
  assert.equal(c.ok, true, c.problems.join("; "));
  assert.deepEqual(c.scope.targets.map((t) => t.text), ["10.0.0.5", "10.0.1.0/24", "files.lab.example"]);
  assert.deepEqual(c.scope.exclude.map((t) => t.text), ["10.0.1.1"]);
  assert.equal(c.scope.attestation.statement, STATEMENT); assert.equal(c.scope.attestation.agreed, true); assert.equal(c.scope.attestation.date, TODAY);
  assert.equal(c.scope.ports, null, "the default preset leaves the scanner's default ports");
  assert.equal(c.scope.addressCount, r.addressCount); assert.equal(c.scope.publicCount, r.publicCount);
  const d = mkdtempSync(join(tmpdir(), "cvscope-")), p = join(d, "scope.json");
  writeFileSync(p, r.text);
  const x = io(); assert.equal(await main(["check", "--scope", p], x), 0, x.lines.err.join("\n"));
  assert.deepEqual(plain(V.commands(r)), ["node scanner/cyberview-scan.mjs check --scope scope.json", "node scanner/cyberview-scan.mjs scan --scope scope.json --online"]);
  // ports presets and a custom list are written as the scanner reads them
  const w = V.buildScope({ ...FORM, ports: "web" }, TODAY); assert.deepEqual(checkScope(w.text, { today: TODAY }).scope.ports, [80, 443, 8000, 8008, 8080, 8443, 8888, 9443]);
  const cu = V.buildScope({ ...FORM, ports: "custom", customPorts: "22, 8000-8002" }, TODAY); assert.deepEqual(checkScope(cu.text, { today: TODAY }).scope.ports, [22, 8000, 8001, 8002]);
});

test("scope builder: public addresses carry the scanner's flag in the commands, and `check` refuses them without it", async () => {
  const r = V.buildScope({ ...FORM, targets: "203.0.113.0/28\n10.0.0.5", expires: "2099-12-31", ref: "contract 42" }, TODAY);
  assert.equal(r.ok, true, r.problems.join("; "));
  assert.equal(r.needsPublic, true); assert.equal(r.publicCount, 16); assert.deepEqual(plain(r.publicTargets), ["203.0.113.0/28"]);
  const c = checkScope(r.text, { today: TODAY }); assert.equal(c.ok, true); assert.equal(c.scope.publicCount, 16); assert.equal(c.scope.attestation.authorization_ref, "contract 42");
  const cmds = V.commands(r); assert.ok(cmds.every((s) => s.endsWith(" " + PUBLIC_FLAG)));
  const d = mkdtempSync(join(tmpdir(), "cvscope-")), p = join(d, "scope.json"); writeFileSync(p, r.text);
  const x = io(); assert.equal(await main(["check", "--scope", p], x), 2); assert.match(x.lines.err.join("\n"), /public/);
  const y = io(); assert.equal(await main(["check", "--scope", p, PUBLIC_FLAG], y), 0, y.lines.err.join("\n"));
});
