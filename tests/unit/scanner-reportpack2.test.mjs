// The scanner's second report pack (scan-report-pack-2): the relationship / dependency map (depmap.mjs), imports of the
// operator's own files (imports.mjs), and the offline rematch of an old report (rematch.mjs). Everything is computed from a
// report.json, local files and a local data snapshot: these tests prove no extra request is made (scan --depmap sends the
// same probes as a plain scan; import, depmap and rematch never call the probe, the resolver or fetch, and with the
// process's own socket, DNS and fetch functions replaced by traps nothing reaches them). Import files are treated as
// hostile. No real host is ever contacted.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, cpSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { parseSbom, parsePackages, parseManifest, parseZeek, parseSurvey, parseConnections, parseCloudInventory, parseImports, matchInventory, readImportFiles, dpkgUpstream, IMPORT_LIMITS } from "../../scanner/lib/imports.mjs";
import { buildDepmap, toMermaid, depmapHtml, depmapText, scopeFromReport, RISK, RISK_FORMULA } from "../../scanner/lib/depmap.mjs";
import { loadOldReport } from "../../scanner/lib/rematch.mjs";
import { cleanFlaws } from "../../scanner/lib/match.mjs";
import { W } from "../../scanner/lib/shared.mjs";
import { STATEMENT } from "../../scanner/lib/scope.mjs";
import { main } from "../../scanner/cyberview-scan.mjs";

const FIX = new URL("../fixtures/scanner/", import.meta.url).pathname, SNAP = join(FIX, "snapshot"), P2 = join(FIX, "reportpack2");
const F = (f) => readFileSync(join(P2, f), "utf8");
const FLAWS = cleanFlaws(JSON.parse(readFileSync(join(SNAP, "data", "workbench.json"), "utf8")));
const tmp = () => mkdtempSync(join(tmpdir(), "cvpack2-"));
const io = (extra = {}) => { const out = [], err = [], calls = { probe: 0, udp: 0, fetch: 0, resolve: 0 }; return { out: (s) => out.push(s), err: (s) => err.push(s), sleep: async () => {}, publicWaitMs: 0, lines: { out, err }, calls,
  probe: async () => { calls.probe++; return { state: "closed" }; }, udpProbe: async () => { calls.udp++; return {}; },
  fetchImpl: () => { calls.fetch++; throw new Error("no network in this test"); }, resolve: async () => { calls.resolve++; throw Object.assign(new Error("no DNS"), { code: "ENOTFOUND" }); }, ...extra }; };
const writeScope = (dir, targets, discover) => { const p = join(dir, "scope.json"); writeFileSync(p, JSON.stringify({ cyberview_scope: 1, owner: "Example lab", contact: "lab@example.org",
  attestation: { statement: STATEMENT, agreed: true, name: "Test Operator", date: "2026-11-20", expires: "", authorization_ref: "test" }, targets, exclude: [], ...(discover ? { discover } : {}) })); return p; };

/* ---- package inventories: dpkg -l, rpm -qa, Windows Get-Package CSV ---- */
test("dpkg -l: installed packages only, epoch and Debian revision removed, marked as distribution builds", () => {
  const p = parsePackages(F("dpkg.txt"));
  assert.equal(p.kind, "dpkg -l");
  assert.deepEqual(p.items.map((x) => [x.name, x.version]), [["adduser", "3.118ubuntu5"], ["nginx", "1.22.1"], ["openssh-server", "8.9p1"], ["libc6", "2.35"]]);
  assert.ok(!p.items.some((x) => x.name.startsWith("php")), "rc (removed) packages are not inventory");
  assert.ok(p.items.every((x) => /dpkg/.test(x.distro)));
  assert.equal(dpkgUpstream("1:2.4.52-1ubuntu4.6"), "2.4.52"); assert.equal(dpkgUpstream("9.2.0+dfsg-1"), "9.2.0"); assert.equal(dpkgUpstream("<script>"), "");
});

test("rpm -qa and Windows Get-Package CSV (with the PowerShell #TYPE line)", () => {
  const r = parsePackages(F("rpm.txt"));
  assert.equal(r.kind, "rpm -qa");
  assert.deepEqual(r.items.map((x) => [x.name, x.version]), [["bash", "5.1.8"], ["php-cli", "8.1.27"], ["vsftpd", "3.0.3"], ["tzdata", "2024a"]]);
  const w = parsePackages(F("get-package.csv"));
  assert.equal(w.kind, "Windows package list (CSV)");
  assert.deepEqual(w.items.map((x) => [x.name, x.version]), [["nginx", "1.24.0"], ["=cmd|' /C calc'!A0", "1.0"], ["Microsoft Edge", "131.0.2903.70"]]);
  assert.equal(w.items[0].distro, "");
});

test("package and SBOM matching is the page's own \"My software\" judgement: W.matchFlaw state, W.score points, every point listed", () => {
  for (const file of ["dpkg.txt", "rpm.txt", "get-package.csv"]) {
    const items = parsePackages(F(file)).items, m = matchInventory(items, FLAWS, { today: "2026-11-22" });
    assert.ok(m.length > 0, file);
    for (const x of m) {
      const f = FLAWS.find((y) => y.cve === x.cve), inv = items.map((i) => ({ name: i.name, vendor: i.vendor, version: i.version, count: 1 })), page = W.matchFlaw(f, inv);
      assert.equal(x.state, page.state); assert.deepEqual(x.points.list.map((p) => [p.points, p.why]), JSON.parse(JSON.stringify(W.score(f, page, "2026-11-22").points)));
      assert.equal(x.points.total, W.score(f, page, "2026-11-22").total);
    }
  }
  const deb = matchInventory(parsePackages(F("dpkg.txt")).items, FLAWS, { today: "2026-11-22" });
  assert.deepEqual(deb.map((x) => x.cve).sort(), ["CVE-2026-90101", "CVE-2026-90102"]);
  assert.ok(deb.every((x) => x.confidence === "medium" && /backported/.test(x.confidence_why)), "distribution builds carry the backport caveat");
  const rpm = matchInventory(parsePackages(F("rpm.txt")).items, FLAWS, { today: "2026-11-22" });
  assert.deepEqual(rpm.map((x) => x.cve).sort(), ["CVE-2026-90103", "CVE-2026-90104"]);
  const win = matchInventory(parsePackages(F("get-package.csv")).items, FLAWS, { today: "2026-11-22" });
  assert.deepEqual(win.map((x) => [x.cve, x.confidence]), [["CVE-2026-90102", "high"]]);
  assert.deepEqual(matchInventory([], FLAWS), []);
});

/* ---- SBOM relationships ---- */
test("SBOM: CycloneDX dependencies and nested components, SPDX relationships from a fixed table only", () => {
  const c = parseSbom(F("cyclonedx.json"));
  assert.equal(c.kind, "CycloneDX");
  assert.deepEqual(c.edges.map((e) => `${e.from} ${e.kind} ${e.to}`).sort(), ["sbom:app depends on sbom:pkg:nginx", "sbom:app depends on sbom:pkg:php", "sbom:pkg:php contains sbom:pkg:php-json", "sbom:pkg:php depends on sbom:pkg:php-json"]);
  assert.deepEqual(c.items.map((x) => x.name), ["nginx", "php", "php-json"]);
  assert.deepEqual(matchInventory(c.items, FLAWS).map((x) => x.cve).sort(), ["CVE-2026-90102", "CVE-2026-90103"]);
  const s = parseSbom(F("spdx.json"));
  assert.equal(s.kind, "SPDX");
  assert.deepEqual(s.edges.map((e) => `${e.from} ${e.kind} ${e.to}`).sort(), ["sbom:SPDXRef-fw contains sbom:SPDXRef-ssh", "sbom:SPDXRef-fw depends on sbom:SPDXRef-ssh"]);   // DESCRIBES and unknown types ignored
  assert.deepEqual(matchInventory(s.items, FLAWS).map((x) => x.cve), ["CVE-2026-90101"]);
});

/* ---- manifests: JSON only ---- */
test("compose and Kubernetes manifests (JSON): declared edges only between objects that exist; YAML is refused, not guessed", () => {
  const c = parseManifest(F("compose.json"));
  assert.deepEqual(c.edges.map((e) => `${e.from} ${e.kind} ${e.to}`), ["compose:web depends on compose:app", "compose:app depends on compose:db", "compose:app depends on compose:cache", "compose:app links to compose:db"]);
  assert.ok(c.edges.every((e) => e.declared));
  assert.equal(c.nodes.find((n) => n.id === "compose:web").image, "nginx:1.24.0");
  const k = parseManifest(F("k8s.json"));
  assert.deepEqual(k.edges.map((e) => `${e.from} ${e.kind} ${e.to}`), ["k8s:Ingress/shop/shop-in routes to k8s:Service/shop/web-svc", "k8s:Service/shop/web-svc selects k8s:Deployment/shop/web"]);
  assert.ok(!JSON.stringify(k).includes("c2VjcmV0"), "a Secret's data is never copied");
  const y = parseManifest("services:\n  web:\n    image: nginx\n");
  assert.equal(y.nodes.length, 0); assert.match(y.problems[0], /only JSON is read \(YAML is not parsed\)/);
});

/* ---- Zeek, survey, connections, cloud ---- */
test("Zeek conn.log (TSV and JSON lines) becomes observed edges; bad rows are counted and skipped", () => {
  const z = parseZeek(F("conn.log"));
  assert.deepEqual(z.edges.map((e) => [e.from, e.to, e.port, e.proto, e.count]), [["ip:10.0.0.5", "ip:10.0.0.6", 5432, "tcp", 2], ["ip:10.0.0.7", "ip:10.0.0.53", 53, "udp", 1]]);
  assert.match(z.problems.join(" "), /1 line\(s\) skipped/);
  const j = parseZeek('{"id.orig_h":"10.1.1.1","id.resp_h":"10.1.1.2","id.resp_p":443,"proto":"tcp","service":"ssl"}\n{"id.orig_h":"evil","id.resp_h":"10.1.1.2","id.resp_p":1,"proto":"tcp"}\n');
  assert.equal(j.edges.length, 1); assert.equal(j.edges[0].service, "ssl");
});

test("Wi-Fi / Bluetooth survey: inventory only, MACs validated", () => {
  const s = parseSurvey(F("wigle.csv"));
  assert.deepEqual(s.counts, { wifi: 2, bluetooth: 1 });
  assert.deepEqual(s.radios.map((r) => [r.kind, r.id, r.name]), [["wifi", "aa:bb:cc:dd:ee:01", "LabNet"], ["wifi", "aa:bb:cc:dd:ee:02", "Guest"], ["bluetooth", "11:22:33:44:55:66", "Printer-BT"]]);
  assert.match(s.note, /never drives a radio/); assert.match(s.problems[0], /1 row\(s\) skipped/);
  assert.match(parseSurvey("a,b\n1,2").problems[0], /no header/);
});

test("local connections: ss, /proc/net/tcp (hex, little-endian) and Windows netstat from the operator's own file", () => {
  const ss = parseConnections(F("ss.txt"));
  assert.equal(ss.kind, "ss");
  assert.deepEqual(ss.listening.map((l) => [l.proto, l.port, l.process]), [["tcp", 22, "sshd"], ["tcp", 443, "nginx"], ["udp", 123, "chronyd"]]);
  assert.deepEqual(ss.peers, [{ proto: "tcp", local: "10.0.0.5", local_port: 51000, peer: "10.0.0.6", peer_port: 5432, process: "php-fpm" }]);
  const pr = parseConnections(F("proc-net-tcp.txt"));
  assert.equal(pr.kind, "/proc/net/tcp");
  assert.deepEqual(pr.listening.map((l) => [l.address, l.port]), [["0.0.0.0", 22]]);
  assert.deepEqual(pr.peers.map((p) => [p.local, p.local_port, p.peer, p.peer_port]), [["10.0.0.5", 51000, "10.0.0.6", 5432]]);
  const v6 = parseConnections("   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 0 0 0 0 0\n");
  assert.deepEqual(v6.listening.map((l) => [l.address, l.port]), [["::1", 22]]);
  const nw = parseConnections(F("netstat-win.txt"));
  assert.equal(nw.kind, "netstat (Windows)");
  assert.deepEqual(nw.listening.map((l) => [l.proto, l.port]), [["tcp", 135], ["udp", 123]]); assert.equal(nw.peers[0].peer, "10.0.0.6");
  const nl = parseConnections("tcp        0      0 0.0.0.0:22   0.0.0.0:*   LISTEN   812/sshd\n");
  assert.equal(nl.kind, "netstat"); assert.deepEqual(nl.listening, [{ proto: "tcp", address: "0.0.0.0", port: 22, process: "sshd" }]);
  assert.match(parseConnections("hello world\n").problems[0], /not \/proc\/net\/tcp, ss or netstat/);
});

test("cloud inventory: declared resources and relationships; the addresses come from discover.mjs's own parser", () => {
  const c = parseCloudInventory(F("aws-ec2.json"), "aws-ec2");
  assert.ok(c.edges.some((e) => e.from === "cloud:instance:i-0abc" && e.kind === "has address" && e.to === "ip:10.0.0.6"));
  assert.ok(c.edges.some((e) => e.kind === "in network" && e.to === "cloud:network:vpc-1"));
  assert.deepEqual(c.addresses, ["203.0.113.10"]);
  const g = parseCloudInventory(JSON.stringify([{ name: "vm1", networkInterfaces: [{ network: "projects/p/global/networks/default", networkIP: "10.2.0.2", accessConfigs: [{ natIP: "198.51.100.7" }] }] }]), "gcp");
  assert.deepEqual(g.edges.map((e) => `${e.kind} ${e.to}`), ["in network cloud:network:default", "has address ip:10.2.0.2", "has address ip:198.51.100.7"]);
  assert.match(parseCloudInventory("{bad", "aws-ec2").problems[0], /not valid JSON/);
});

/* ---- hostile import files ---- */
test("hostile import files: bad JSON, deep nesting, prototype keys, huge strings, control characters and wrong types never throw or pollute", () => {
  const deep = "[".repeat(200000) + "]".repeat(200000);
  const huge = "A".repeat(100000), ctl = "evil\u0000\u001b[31m\nname";
  const cases = [
    () => parseSbom(deep), () => parseSbom("{nope"), () => parseSbom("null"), () => parseSbom('"x"'), () => parseSbom(JSON.stringify({ components: [null, 1, "x", { name: huge, version: ctl }, { __proto__: { polluted: true }, name: "p" }], dependencies: [{ ref: { a: 1 }, dependsOn: "x" }, { ref: "a", dependsOn: [null, 5] }] })),
    () => parseSbom(JSON.stringify({ components: [JSON.parse('{"name":"x","components":' + "[".repeat(50) + '{"name":"deep"}' + "]".repeat(50) + "}")] })),
    () => parseSbom(JSON.stringify({ packages: [{ SPDXID: "a", name: "a" }], relationships: [{ spdxElementId: "a", relationshipType: "__proto__", relatedSpdxElement: "b" }, { spdxElementId: "a", relationshipType: "constructor", relatedSpdxElement: "b" }] })),
    () => parseManifest(deep), () => parseManifest(JSON.stringify({ services: { __proto__: { image: "x" }, a: null, b: { depends_on: 5, links: [{}] } } })), () => parseManifest(JSON.stringify({ kind: "List", items: [1, null, { kind: "Service", metadata: { name: huge }, spec: { selector: { constructor: "x" } } }] })),
    () => parsePackages("\u0000\u0001\u0002"), () => parsePackages(huge), () => parsePackages(JSON.stringify({ components: "x" })),
    () => parseZeek("#fields\t" + "f\t".repeat(10000) + "\n" + "x\t".repeat(10000)), () => parseZeek("{\"__proto__\":{\"polluted\":1}}\n{bad json\n"),
    () => parseSurvey("MAC\n" + '"'.repeat(5000)), () => parseConnections("tcp LISTEN 0 0 999.1.1.1:99999 *:* \n" + ctl), () => parseCloudInventory(deep, "azure"), () => parseCloudInventory(JSON.stringify({ Reservations: [{ Instances: [{ InstanceId: { x: 1 } }, null] }] }), "aws-ec2"),
    () => parseCloudInventory("[]", "not-a-provider"),
  ];
  for (const [i, c] of cases.entries()) { let r; assert.doesNotThrow(() => { r = c(); }, `case ${i}`); assert.ok(r && typeof r === "object", `case ${i}`); }
  assert.equal({}.polluted, undefined); assert.equal(Object.prototype.image, undefined);
  const big = parseSbom(JSON.stringify({ components: [{ name: huge, version: ctl }] }));
  assert.ok(big.nodes.every((n) => n.name.length <= 120 && !/[\u0000-\u001f]/.test(n.name + n.version)));
  // node and edge caps hold and are reported
  const many = parseZeek(Array.from({ length: 30000 }, (_, i) => JSON.stringify({ "id.orig_h": `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`, "id.resp_h": "10.255.255.254", "id.resp_p": 80, proto: "tcp" })).join("\n"));
  assert.ok(many.nodes.length <= IMPORT_LIMITS.nodes && many.dropped > 0);
});

test("import files are size-checked before they are read, and bad flags are refused", () => {
  let read = 0;
  const readFile = () => { read++; return "x"; };
  assert.match(readImportFiles({ sbom: "big.json" }, { readFile, sizeOf: () => IMPORT_LIMITS.maxBytes + 1 }).error, /over the 16 MB import cap/);
  assert.equal(read, 0, "an oversized file is never read");
  assert.ok(!readImportFiles({ zeek: "conn.log" }, { readFile, sizeOf: () => IMPORT_LIMITS.maxBytes + 1 }).error, "conn.log has its own, larger cap");
  assert.match(readImportFiles({ sbom: true }, { readFile, sizeOf: () => 1 }).error, /needs a file name/);
  assert.match(readImportFiles({ sbom: "missing" }, { readFile, sizeOf: () => { throw new Error("ENOENT"); } }).error, /cannot read/);
  assert.match(readImportFiles({ "cloud-provider": "aws-shell" }, { readFile, sizeOf: () => 1 }).error, /--cloud-provider/);
  assert.match(readImportFiles({ "connections-host": "host; rm -rf" }, { readFile, sizeOf: () => 1 }).error, /--connections-host/);
});

/* ---- the map ---- */
const cert = (dns, ip = [], fp = "AA") => ({ subject: "CN=x", issuer: "CN=CA", san_dns: dns, san_ip: ip, fingerprint256: fp });
const REPORT = () => ({
  tool: { name: "CyberView Scanner" }, run: { started_at: "2026-11-22T10:00:00Z" },
  scope: { targets: ["10.0.0.0/24", "203.0.113.5", "www.example.org"], exclude: [] },
  hosts: [
    { address: "10.0.0.5", names: ["www.example.org"], public: false, up: true, ports: [{ port: 22, state: "open" }, { port: 80, state: "open" }, { port: 443, state: "open" }],
      services: [{ port: 22, vendor: "OpenBSD", product: "OpenSSH", version: "9.6p1", shown_version: "9.6p1" }, { port: 80, vendor: "F5", product: "nginx", version: "1.22.1" }],
      http: [{ port: 80, status: 301, redirect: "https://www.example.org/" }, { port: 443, status: 302, redirect: "https://login.partner.example.net/sso" }],
      tls: [{ port: 443, cert: cert(["www.example.org", "api.example.org", "cdn.thirdparty.example"], ["10.0.0.99"], "F1") }],
      observations: [{ port: 443, kind: "tls-name-mismatch", severity: "medium", text: "The TLS certificate does not name x" }, { port: 22, kind: "k", severity: "high", text: "t" }] },
    { address: "10.0.0.6", names: [], public: false, up: true, ports: [{ port: 443, state: "open" }, { port: 5432, state: "open" }], services: [], http: [{ port: 443, status: 302, redirect: "http://10.0.0.5/" }],
      tls: [{ port: 443, cert: cert(["www.example.org", "api.example.org", "cdn.thirdparty.example"], ["10.0.0.99"], "F2") }], observations: [] },
    { address: "203.0.113.5", names: ["www.example.org"], public: true, up: true, ports: [{ port: 443, state: "open" }], services: [], http: [], tls: [], observations: [] },
  ],
  findings: [
    { cve: "CVE-2026-90101", state: "affected", kev: true, ransomware: true, overdue: true, cisa_due: "2026-01-01", confidence: "high", rating: { band: "High" }, seen_on: [{ host: "10.0.0.5", port: 22, state: "affected", confidence: "high" }] },
    { cve: "CVE-2026-90105", state: "check", kev: true, confidence: "low", rating: { band: "Critical" }, seen_on: [{ host: "10.0.0.6", port: 443, state: "check", confidence: "low" }] },
  ],
});

test("depmap: co-location low, certificate SAN and in-scope redirects medium, all labelled inferred; nothing outside the scope is a node to scan", () => {
  const inScope = (h) => /^10\.0\.0\.\d+$/.test(h) || h === "203.0.113.5" || h === "www.example.org" || h.endsWith(".example.org");
  const m = buildDepmap(REPORT(), { inScope });
  const E = (kind) => m.edges.filter((e) => e.kind === kind);
  assert.equal(E("co-located").length, 3 + 1); assert.ok(E("co-located").every((e) => e.confidence === "low" && e.inferred));
  const san = E("share a certificate SAN list"); assert.equal(san.length, 1); assert.equal(san[0].confidence, "medium"); assert.ok(san[0].inferred);
  assert.deepEqual([san[0].from, san[0].to], ["host:10.0.0.5", "host:10.0.0.6"]);
  const red = E("redirects to").map((e) => `${e.from} -> ${e.to} ${e.confidence}`).sort();
  assert.deepEqual(red, ["svc:10.0.0.5:80 -> svc:10.0.0.5:443 medium", "svc:10.0.0.6:443 -> svc:10.0.0.5:80 medium"]);
  // out of scope: listed as mentioned, never scanned
  assert.deepEqual(m.mentions.map((x) => x.name).sort(), ["cdn.thirdparty.example", "login.partner.example.net"]);
  assert.ok(m.mentions.every((x) => x.scanned === false && /NOT scanned/.test(x.note)));
  assert.deepEqual(m.mentions.find((x) => x.name === "login.partner.example.net").seen_in[0], { host: "10.0.0.5", port: 443, field: "Location" });
  // shadow IT: in scope, not in the starting inventory, listed only
  assert.deepEqual(m.shadow_it.map((x) => x.name), ["api.example.org", "10.0.0.99"]);
  assert.ok(m.shadow_it.every((x) => x.scanned === false));
  // NAT / split horizon from collected answers and SANs only
  const kinds = m.name_mismatch.map((x) => x.kind).sort();
  assert.deepEqual(kinds, ["certificate-address-mismatch", "certificate-address-mismatch", "certificate-names-other-address", "certificate-names-other-address", "name-private-and-public", "tls-name-mismatch"]);
  assert.match(m.name_mismatch.find((x) => x.kind === "name-private-and-public").text, /www\.example\.org resolved to both private and public/);
  // without a scope file the in-scope test comes from report.scope only (exact names, addresses and ranges)
  const off = buildDepmap(REPORT());
  assert.deepEqual(off.mentions.map((x) => x.name).sort(), ["api.example.org", "cdn.thirdparty.example", "login.partner.example.net"]);
  assert.deepEqual(off.shadow_it.map((x) => x.name), ["10.0.0.99"]);
  assert.equal(scopeFromReport(REPORT()).inScope("10.0.0.99"), true); assert.equal(scopeFromReport(REPORT()).inScope("8.8.8.8"), false);
});

test("per-host risk score: every point listed, formula printed, low-confidence findings never earn KEV points", () => {
  const m = buildDepmap(REPORT());
  assert.equal(m.risk.formula, RISK_FORMULA);
  const h5 = m.risk.hosts.find((r) => r.host === "10.0.0.5"), h6 = m.risk.hosts.find((r) => r.host === "10.0.0.6");
  assert.deepEqual(h5.points.map((p) => p.points), [RISK.kev, RISK.ransomware, RISK.overdue, RISK.obs.medium + RISK.obs.high]);
  assert.equal(h5.score, h5.points.reduce((s, p) => s + p.points, 0));
  assert.deepEqual(h6.points, [{ points: RISK.check, why: "CVE-2026-90105: product seen, version to check" }]);
  assert.ok(!m.risk.hosts.some((r) => r.host === "203.0.113.5"), "a host with nothing to score is not listed");
  assert.ok(m.risk.hosts.every((r) => r.score >= 0 && r.score <= 100));
});

test("blast radius: same host, same certificate and imported relationships (Zeek, connections, cloud)", () => {
  const imports = parseImports({ zeek: F("conn.log"), cloud: F("aws-ec2.json"), connections: F("ss.txt"), manifest: F("compose.json") }, { cloudProvider: "aws-ec2", connectionsHost: "10.0.0.5" });
  const m = buildDepmap(REPORT(), { imports });
  const b = m.blast_radius.find((x) => x.cve === "CVE-2026-90101");
  const via = Object.fromEntries(b.radius.map((r) => [r.node, r.via]));
  assert.equal(via["svc:10.0.0.5:80"], "same host (co-located)");
  assert.match(via["host:10.0.0.6"], /same certificate|imported \(zeek\)|imported \(connections\)/);
  assert.equal(via["cloud:instance:i-0def"], "imported (cloud): has address");
  assert.ok(b.radius.some((r) => r.node === "listen:tcp:22"));
  // imported edges attach to scanned hosts by address and say where they came from
  const z = m.edges.find((e) => e.imported === "zeek" && e.from === "host:10.0.0.5" && e.to === "host:10.0.0.6");
  assert.equal(z.confidence, "observed"); assert.equal(z.inferred, false); assert.equal(z.count, 2);
  assert.ok(m.edges.some((e) => e.imported === "manifest" && e.confidence === "declared" && e.from === "compose:web"));
  assert.equal(m.counts.declared > 0, true);
  // outputs: Mermaid with syntax characters stripped, HTML escaped, text summary
  const mmd = toMermaid(m); assert.match(mmd, /^graph LR\n/); assert.ok(!/<script/i.test(mmd));
  const html = depmapHtml(buildDepmap({ ...REPORT(), hosts: [{ ...REPORT().hosts[0], http: [{ port: 443, redirect: "https://<script>x.example.net/" }] }] }));
  assert.ok(!html.includes("<script")); assert.match(html, /Relationship map/);
  assert.match(depmapText(m), /risk \d+\/100 10\.0\.0\.5/);
});

/* ---- the command line ---- */
const stubProbe = (calls) => async (ip, port) => {
  calls.push(`${ip}:${port}`);
  if (port === 22) return { port, state: "open", banner: "SSH-2.0-OpenSSH_9.6p1\r\n" };
  if (port === 80) return { port, state: "open", http: { status: 301, headers: { server: "nginx/1.22.1", location: "https://partner.example.net/" }, body: "" } };
  return { port, state: "closed" };
};
const PORTS = ["--ports", "22,80,443"];

test("scan --depmap --html with import files: the same probes as a plain scan; depmap.json, depmap.mmd and a report.html section", async () => {
  const d = tmp(), scope = writeScope(d, ["10.0.0.5", "10.0.0.6"]);
  const plain = [];
  assert.equal(await main(["scan", "--scope", scope, "--data", SNAP, ...PORTS, "--out", join(d, "a")], io({ probe: stubProbe(plain) })), 0);
  const withMap = [], x = io({ probe: stubProbe(withMap) });
  assert.equal(await main(["scan", "--scope", scope, "--data", SNAP, ...PORTS, "--out", join(d, "b"), "--depmap", "--html", "--zeek", join(P2, "conn.log"), "--sbom", join(P2, "cyclonedx.json")], x), 0);
  assert.deepEqual(withMap.slice().sort(), plain.slice().sort(), "the map sends nothing: same host:port probes");
  assert.equal(x.calls.fetch + x.calls.resolve + x.calls.udp, 0);
  assert.deepEqual(readdirSync(join(d, "b")).sort(), ["depmap.json", "depmap.mmd", "findings.csv", "inventory.csv", "report.html", "report.json", "report.sarif", "summary.txt"]);
  const m = JSON.parse(readFileSync(join(d, "b", "depmap.json"), "utf8"));
  assert.deepEqual(m.mentions.map((y) => y.name), ["partner.example.net"]);
  assert.ok(m.edges.some((e) => e.imported === "zeek" && e.from === "host:10.0.0.5" && e.to === "host:10.0.0.6"));
  assert.ok(m.risk.hosts.length >= 1);
  assert.match(readFileSync(join(d, "b", "report.html"), "utf8"), /<h2 id="depmap">Relationship map<\/h2>[\s\S]*<\/main>/);
  assert.match(x.lines.out.join("\n"), /Dependency map: \d+ node\(s\)/);
  // an import flag without --depmap is refused before anything is scanned
  const none = [], y = io({ probe: stubProbe(none) });
  assert.equal(await main(["scan", "--scope", scope, "--data", SNAP, "--zeek", join(P2, "conn.log")], y), 1);
  assert.match(y.lines.err.join("\n"), /import files on scan feed --depmap/); assert.equal(none.length, 0);
  const z = io({ probe: stubProbe(none) });
  assert.equal(await main(["scan", "--scope", scope, "--data", SNAP, "--depmap", "--sbom", join(d, "missing.json")], z), 1); assert.equal(none.length, 0);
});

// every socket, DNS and fetch entry point of the process is replaced by a trap while the offline commands run
async function withNetworkTraps(fn) {
  const require = createRequire(import.meta.url);
  const net = require("node:net"), tls = require("node:tls"), dgram = require("node:dgram"), dns = require("node:dns"), http = require("node:http"), https = require("node:https");
  const hits = [], saved = [];
  const trap = (mod, name, label) => { saved.push([mod, name, mod[name]]); mod[name] = (...args) => { hits.push(label); throw new Error(`network call in an offline command: ${label}`); }; };
  trap(net, "connect", "net.connect"); trap(net, "createConnection", "net.createConnection"); trap(tls, "connect", "tls.connect"); trap(dgram, "createSocket", "dgram.createSocket");
  trap(dns, "lookup", "dns.lookup"); trap(dns, "resolve", "dns.resolve"); trap(dns.promises, "lookup", "dns.promises.lookup"); trap(http, "request", "http.request"); trap(http, "get", "http.get"); trap(https, "request", "https.request"); trap(https, "get", "https.get");
  trap(globalThis, "fetch", "fetch");
  syncBuiltinESMExports();
  try { return { result: await fn(), hits }; } finally { for (const [m, n, v] of saved) m[n] = v; syncBuiltinESMExports(); }
}

test("import, depmap and rematch never probe, resolve or fetch: with every network entry point trapped, nothing is called", async () => {
  const d = tmp(), scope = writeScope(d, ["10.0.0.5", "10.0.0.6"]);
  assert.equal(await main(["scan", "--scope", scope, "--data", SNAP, ...PORTS, "--out", join(d, "scan")], io({ probe: stubProbe([]) })), 0);
  const x = io();
  const { result, hits } = await withNetworkTraps(async () => [
    await main(["import", "--data", SNAP, "--packages", join(P2, "dpkg.txt"), "--sbom", join(P2, "spdx.json"), "--manifest", join(P2, "k8s.json"), "--zeek", join(P2, "conn.log"), "--survey", join(P2, "wigle.csv"),
      "--connections", join(P2, "proc-net-tcp.txt"), "--connections-host", "10.0.0.5", "--cloud", join(P2, "aws-ec2.json"), "--out", join(d, "imp")], x),
    await main(["depmap", "--report", join(d, "scan", "report.json"), "--zeek", join(P2, "conn.log"), "--out", join(d, "map")], x),
    await main(["rematch", "--report", join(d, "scan", "report.json"), "--data", SNAP, "--out", join(d, "re")], x),
  ]);
  assert.deepEqual(result, [0, 0, 0], x.lines.err.join("\n"));
  assert.deepEqual(hits, [], "no socket, DNS lookup or fetch was attempted");
  assert.deepEqual(x.calls, { probe: 0, udp: 0, fetch: 0, resolve: 0 });
  const imp = JSON.parse(readFileSync(join(d, "imp", "imports.json"), "utf8"));
  assert.deepEqual(imp.given, ["sbom", "packages", "manifest", "zeek", "survey", "connections", "cloud"]);
  assert.deepEqual(imp.matched.findings.map((f) => f.cve).sort(), ["CVE-2026-90101", "CVE-2026-90102"]);
  assert.equal(imp.survey.counts.wifi, 2); assert.equal(imp.connections.listening[0].port, 22);
  assert.match(imp.network, /none/);
  assert.deepEqual(readdirSync(join(d, "map")).sort(), ["depmap.json", "depmap.mmd"]);
  assert.deepEqual(readdirSync(join(d, "re")).sort(), ["rematch.json", "rematch.txt"]);
  assert.ok(x.lines.out.every((l) => !/REFUSED/.test(l)));
});

test("offline commands refuse a network source and missing inputs", async () => {
  const x = io();
  assert.equal(await main(["rematch", "--report", "r.json", "--data", SNAP, "--online"], x), 1); assert.match(x.lines.err.join("\n"), /offline only/);
  assert.equal(await main(["rematch", "--report", "r.json"], x), 1); assert.match(x.lines.err.join("\n"), /--data DIR is required/);
  assert.equal(await main(["import"], x), 1); assert.match(x.lines.err.join("\n"), /at least one import file/);
  assert.equal(await main(["depmap"], x), 1); assert.match(x.lines.err.join("\n"), /--report R\/report.json is required/);
  const d = tmp(); writeFileSync(join(d, "other.json"), JSON.stringify({ tool: { name: "nmap" }, hosts: [] }));
  assert.equal(await main(["depmap", "--report", join(d, "other.json")], x), 1); assert.match(x.lines.err.join("\n"), /not a CyberView Scanner report/);
  assert.equal(await main(["rematch", "--report", join(d, "other.json"), "--data", SNAP], x), 1);
  assert.equal(x.calls.probe + x.calls.fetch + x.calls.resolve, 0);
});

/* ---- offline rematch ---- */
test("rematch: an old report against a newer snapshot names newly matched and no-longer-matched CVEs", async () => {
  const d = tmp(), scope = writeScope(d, ["10.0.0.5"]);
  assert.equal(await main(["scan", "--scope", scope, "--data", SNAP, ...PORTS, "--out", join(d, "old")], io({ probe: stubProbe([]) })), 0);
  const old = JSON.parse(readFileSync(join(d, "old", "report.json"), "utf8"));
  assert.deepEqual(old.findings.map((f) => f.cve).sort(), ["CVE-2026-90101", "CVE-2026-90102"]);
  // the newer snapshot: OpenSSH's range was corrected (no longer matches 9.6p1) and a new KEV entry names it
  const snap = join(d, "newer"); cpSync(SNAP, snap, { recursive: true });
  const wb = JSON.parse(readFileSync(join(snap, "data", "workbench.json"), "utf8"));
  const ssh = wb.kev.find((k) => k.cve === "CVE-2026-90101"); ssh.affected = [{ vendor: "openbsd", product: "openssh", part: "a", to: "9.0", to_incl: false }];
  wb.kev.push({ ...ssh, cve: "CVE-2026-90199", name: "OpenSSH test flaw", affected: [{ vendor: "openbsd", product: "openssh", part: "a", from: "9.5", from_incl: true, to: "9.9", to_incl: false }] });
  wb.built_at = "2026-11-22T12:00:00Z";
  writeFileSync(join(snap, "data", "workbench.json"), JSON.stringify(wb));
  const x = io();
  assert.equal(await main(["rematch", "--report", join(d, "old", "report.json"), "--data", snap, "--out", join(d, "re")], x), 0);
  const r = JSON.parse(readFileSync(join(d, "re", "rematch.json"), "utf8"));
  assert.deepEqual(r.changes.newly_matched.map((f) => f.cve), ["CVE-2026-90199"]);
  assert.deepEqual(r.changes.no_longer_matched, ["CVE-2026-90101"]);
  assert.deepEqual(r.changes.still_matched, ["CVE-2026-90102"]);
  assert.equal(r.rematch.data_workbench_built_at, "2026-11-22T12:00:00Z"); assert.match(r.rematch.network, /^none/);
  assert.ok(r.findings.find((f) => f.cve === "CVE-2026-90199").points.list.length > 0, "every point listed, as in a scan");
  assert.match(readFileSync(join(d, "re", "rematch.txt"), "utf8"), /1 newly matched, 1 no longer matched, 1 still matched/);
  assert.equal(x.calls.probe + x.calls.fetch + x.calls.resolve, 0);
});

test("rematch: the old report is untrusted: only a CyberView report, only the fields matching needs, clipped", () => {
  assert.match(loadOldReport("").error, /empty/); assert.match(loadOldReport("{x").error, /not JSON/);
  assert.match(loadOldReport(JSON.stringify({ tool: { name: "other" }, hosts: [] })).error, /not a CyberView Scanner report/);
  const r = loadOldReport(JSON.stringify({ tool: { name: "CyberView Scanner" }, hosts: [{ address: "not-an-ip" }, { address: "10.0.0.5", services: [{ product: "P".repeat(5000), version: "1.0<script>", body: "secret", port: 99999 }, null, { product: 7 }], __proto__: { polluted: true } }],
    findings: [{ cve: "CVE-2026-90101" }, { cve: "nope" }] }));
  assert.equal(r.report.hosts.length, 1); const s = r.report.hosts[0].services;
  assert.equal(s.length, 1); assert.equal(s[0].product.length, 120); assert.equal(s[0].version, "1.0script"); assert.equal(s[0].port, 0); assert.equal("body" in s[0], false);
  assert.deepEqual(r.report.findings, ["CVE-2026-90101"]); assert.equal({}.polluted, undefined);
});
