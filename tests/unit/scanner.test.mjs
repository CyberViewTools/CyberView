// The downloadable scanner (scanner/): the authorization gate, the fingerprint parsers, matching and rating against the
// site's own code, the exporters, the politeness limits, and offline and online data. No real host is ever contacted:
// probes are stand-ins or stand-in services on 127.0.0.1 (tests/fixtures/scanner/servers.mjs).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import vm from "node:vm";
import { checkScope, gate, hostInScope, classify, parseTarget, listAddresses, template, STATEMENT, LIMITS } from "../../scanner/lib/scope.mjs";
import { settings, Limiter, CAPS, PRIVATE_CAPS } from "../../scanner/lib/limits.mjs";
import { fromSsh, fromGreeting, fromMysql, fromHttp, fromCert, fromUdp, certInfo, observations, udpObservations } from "../../scanner/lib/fingerprint.mjs";
import { cleanFlaws, findings, toItem } from "../../scanner/lib/match.mjs";
import { dirSource, webSource, ALLOWED, checkBase } from "../../scanner/lib/data.mjs";
import { parsePorts, resolveScope, probeAll, servicesOf, allPorts } from "../../scanner/lib/scan.mjs";
import { toCsv, toSarif, toInventory, CSV_HEAD, coverage, isTruncatedBanner, summaryText } from "../../scanner/lib/report.mjs";
import { USER_AGENT, SSH_IDENT, probePort } from "../../scanner/lib/probe.mjs";
import { dnsVersionQuery, parseDnsVersion, ntpReadVarQuery, parseNtpReadVar, snmpGetSysDescr, parseSnmpSysDescr, SNMP_COMMUNITY, UDP_SERVICES } from "../../scanner/lib/udp-codec.mjs";
import { udpProbe } from "../../scanner/lib/udp.mjs";
import { parseAssetFile, parseCloud, parseCtJson, ctSubdomains, runDiscovery } from "../../scanner/lib/discover.mjs";
import { main } from "../../scanner/cyberview-scan.mjs";
import { NOCODE } from "../../scripts/lib/validate.mjs";
import { startServers } from "../fixtures/scanner/servers.mjs";

const FIX = new URL("../fixtures/scanner/", import.meta.url).pathname, SNAP = join(FIX, "snapshot");
const BANNERS = JSON.parse(readFileSync(join(FIX, "banners.json"), "utf8"));
const TODAY = "2026-11-22";
// the site's libraries loaded on their own, exactly as the browser runs them, to compare with what the scanner computes
const site = (f, k) => { const sb = { window: {} }; vm.runInNewContext(readFileSync(new URL(`../../site/${f}`, import.meta.url), "utf8"), sb); return sb.window[k]; };
const SW = site("workbench-lib.js", "CVWorkbench"), SD = site("cvedb-lib.js", "CVDB");

const scopeText = (o = {}) => JSON.stringify({ cyberview_scope: 1, owner: "Example lab", contact: "lab@example.org",
  attestation: { statement: STATEMENT, agreed: true, name: "Test Operator", date: "2026-11-20", expires: "", authorization_ref: "test", ...(o.attestation || {}) },
  targets: ["127.0.0.1"], exclude: [], ...o, ...(o.attestation ? { attestation: { statement: STATEMENT, agreed: true, name: "Test Operator", date: "2026-11-20", ...o.attestation } } : {}) });
const tmp = () => mkdtempSync(join(tmpdir(), "cvscan-"));
const io = (extra = {}) => { const out = [], err = []; return { out: (s) => out.push(s), err: (s) => err.push(s), sleep: async () => {}, publicWaitMs: 0, lines: { out, err },
  fetchImpl: () => { throw new Error("no network in this test"); }, resolve: async () => { throw Object.assign(new Error("no DNS in this test"), { code: "ENOTFOUND" }); }, ...extra }; };
const writeScope = (dir, o) => { const p = join(dir, "scope.json"); writeFileSync(p, scopeText(o)); return p; };
const walkFiles = (dir) => { const out = []; for (const f of readdirSync(dir, { withFileTypes: true })) { const q = join(dir, f.name); if (f.isDirectory()) out.push(...walkFiles(q)); else if (/\.(mjs|js)$/.test(f.name)) out.push(q); } return out; };

/* ---- the authorization gate ---- */
test("scan refuses to run without a scope file, and there is no default target", async () => {
  const x = io();
  assert.equal(await main(["scan", "--data", SNAP], x), 2);
  assert.match(x.lines.err.join("\n"), /scope file is required.*no default target/s);
  const d = tmp(), p = join(d, "scope.json"); writeFileSync(p, JSON.stringify(template(TODAY)));
  const y = io(); assert.equal(await main(["scan", "--scope", p, "--data", SNAP], y), 2);
  assert.match(y.lines.err.join("\n"), /agreed" must be true/); assert.match(y.lines.err.join("\n"), /"targets" must list at least one/);
});
test("the attestation must be the exact statement, agreed, named, dated and current", () => {
  assert.equal(checkScope(scopeText(), { today: TODAY }).ok, true);
  const bad = (a, re) => { const r = checkScope(scopeText({ attestation: a }), { today: TODAY }); assert.equal(r.ok, false); assert.ok(r.problems.some((p) => re.test(p)), r.problems.join("; ")); };
  bad({ statement: "I think it is fine" }, /must be exactly/);
  bad({ agreed: "yes" }, /agreed" must be true/);
  bad({ name: "" }, /must name the person/);
  bad({ date: "2026-12-30" }, /in the future/);
  bad({ date: "2025-01-01" }, /more than 365 days old/);
  bad({ expires: "2026-11-01" }, /expired on 2026-11-01/);
  assert.equal(checkScope("not json").ok, false);
});
test("targets: refused kinds, ranges too wide, public ranges capped", () => {
  const probs = (targets) => checkScope(scopeText({ targets }), { today: TODAY }).problems.join("; ");
  assert.match(probs(["0.0.0.0/0"]), /unspecified|wider/);
  assert.match(probs(["10.0.0.0/8"]), /wider than a \/16/);
  assert.match(probs(["224.0.0.1"]), /multicast/);
  assert.match(probs(["255.255.255.255"]), /reserved or broadcast/);
  assert.match(probs(["203.0.113.0/23"]), /public range wider than a \/24/);
  assert.match(probs(["2001:db8::/64"]), /wider than a \/120/);
  assert.match(probs(["not a host!"]), /not an address/);
  assert.match(probs(Array.from({ length: 5 }, (_, i) => `198.51.${i}.0/24`)), /at most 1024/);
  const ok = checkScope(scopeText({ targets: ["192.168.10.0/24", "fd00::/126", "intranet.example.lan"] }), { today: TODAY });
  assert.equal(ok.ok, true); assert.equal(ok.scope.needsPublic, false); assert.equal(ok.scope.addressCount, 260);
  assert.equal(checkScope(scopeText({ targets: ["198.51.100.7"] }), { today: TODAY }).scope.needsPublic, true);
});
test("address kinds: RFC 1918, loopback, link-local and IPv6 unique local are private; the rest is public", () => {
  for (const ip of ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.1", "127.0.0.1", "169.254.1.1", "::1", "fd12::1", "fe80::1", "::ffff:192.168.1.1"]) assert.ok(["private", "loopback", "link-local"].includes(classify(ip)), ip);
  for (const ip of ["172.32.0.1", "8.8.8.8", "100.64.0.1", "2001:db8::1"]) assert.equal(classify(ip), "public", ip);
});
test("the gate refuses an address outside the scope, an excluded one, and a public one without the confirmation", () => {
  const { scope } = checkScope(scopeText({ targets: ["192.168.1.0/30", "198.51.100.7", "intranet.example.lan"], exclude: ["192.168.1.2"] }), { today: TODAY });
  assert.equal(gate(scope, "192.168.1.1").ok, true);
  assert.match(gate(scope, "192.168.1.2").why, /not in the scope/);
  assert.match(gate(scope, "10.0.0.1").why, /not in the scope/);
  assert.match(gate(scope, "198.51.100.7").why, /i-am-authorized-for-public-ranges/);
  assert.equal(gate(scope, "198.51.100.7", { allowPublic: true }).ok, true);
  assert.equal(gate(scope, "203.0.113.9", { allowPublic: true }).ok, false);
  assert.equal(gate(scope, "10.9.9.9", { viaHost: "intranet.example.lan" }).ok, true);
  assert.deepEqual(listAddresses(scope), ["192.168.1.1", "198.51.100.7"]);
});
test("a host name resolving to a public address needs the confirmation; one that does not resolve is skipped", async () => {
  const { scope } = checkScope(scopeText({ targets: ["intranet.example.lan", "gone.example.lan"] }), { today: TODAY });
  const resolve = async (h) => { if (h === "gone.example.lan") throw Object.assign(new Error("x"), { code: "ENOTFOUND" }); return [{ address: "10.0.0.5" }, { address: "198.51.100.20" }]; };
  const r = await resolveScope(scope, { resolve });
  assert.deepEqual(r.targets.map((t) => t.address), ["10.0.0.5"]);
  assert.ok(r.refused.some((x) => /198\.51\.100\.20/.test(x.target) && /public/.test(x.why)));
  assert.ok(r.refused.some((x) => /gone/.test(x.target) && /could not be resolved/.test(x.why)));
});
test("public addresses: refused without the flag, then a prominent warning and a wait before starting", async () => {
  const d = tmp(), p = writeScope(d, { targets: ["198.51.100.7"] });
  const x = io(); assert.equal(await main(["check", "--scope", p], x), 2);
  assert.match(x.lines.err.join("\n"), /public.*--i-am-authorized-for-public-ranges/s);
  const y = io(); assert.equal(await main(["check", "--scope", p, "--i-am-authorized-for-public-ranges"], y), 0);
  assert.match(y.lines.out.join("\n"), /confirmed with --i-am-authorized-for-public-ranges/);
  let waited = 0; const z = io({ sleep: async (ms) => { waited = ms; }, publicWaitMs: 10000, probe: async (ip, port) => ({ port, state: "filtered" }) });
  // every port filtered -> the host answered nowhere -> incomplete coverage, exit 2 (not a false clean; see COVERAGE)
  assert.equal(await main(["scan", "--scope", p, "--data", SNAP, "--i-am-authorized-for-public-ranges", "--out", join(d, "o")], z), 2);
  assert.equal(waited, 10000); assert.match(z.lines.err.join("\n"), /WARNING: this scan includes 1 PUBLIC address/);
  assert.match(readFileSync(join(d, "o", "summary.txt"), "utf8"), /COVERAGE —[\s\S]*answered on no port/);
});
test("check prints the attestation and the scope, and sends nothing", async () => {
  const d = tmp(), p = writeScope(d, {}), x = io({ probe: () => { throw new Error("must not probe"); } });
  assert.equal(await main(["check", "--scope", p], x), 0);
  const t = x.lines.out.join("\n");
  assert.match(t, /Attested by: Test Operator on 2026-11-20/); assert.ok(t.includes(STATEMENT)); assert.match(t, /Targets:\s+127\.0\.0\.1/); assert.match(t, /Nothing was scanned/);
});

/* ---- limits ---- */
test("limits can be lowered, never raised or switched off", () => {
  assert.deepEqual(settings({}).settings, { rate: 20, concurrency: 8, hostConcurrency: 2, hostBudget: 300, budget: 20000, minutes: 60 });
  assert.equal(settings({ rate: 5, concurrency: 2 }).ok, true);
  for (const [k, v] of [["rate", 21], ["concurrency", 9], ["hostConcurrency", 3], ["hostBudget", 301], ["budget", 20001], ["minutes", 481], ["rate", 0], ["concurrency", -1], ["rate", "fast"]]) assert.equal(settings({ [k]: v }).ok, false, `${k}=${v}`);
  assert.equal(CAPS.rate, 20); assert.ok(Object.isFrozen(CAPS));
});
test("the limiter keeps the rate, the open-connection caps and the budgets", async () => {
  const clock = { t: 0, now() { return this.t; }, sleep(ms) { this.t += ms; return Promise.resolve(); } };
  const lim = new Limiter({ rate: 20, concurrency: 8, hostConcurrency: 2, hostBudget: 300, budget: 20000, minutes: 60 }, clock);
  for (let i = 0; i < 10; i++) (await lim.acquire("h" + i))();
  assert.ok(clock.t >= 450, `10 connections at 20/s took ${clock.t} ms`);
  // concurrency: 30 tasks, real timers
  const real = new Limiter({ rate: 20, concurrency: 3, hostConcurrency: 2, hostBudget: 300, budget: 20000, minutes: 1 });
  let open = 0, maxOpen = 0, maxHost = 0; const per = {};
  await Promise.all(Array.from({ length: 12 }, async (_, i) => { const h = "host" + (i % 2), rel = await real.acquire(h); open++; per[h] = (per[h] || 0) + 1; maxOpen = Math.max(maxOpen, open); maxHost = Math.max(maxHost, per[h]);
    await new Promise((r) => setTimeout(r, 20)); open--; per[h]--; rel(); }));
  assert.ok(maxOpen <= 3, `max open ${maxOpen}`); assert.ok(maxHost <= 2, `max per host ${maxHost}`);
  const b = new Limiter({ rate: 20, concurrency: 8, hostConcurrency: 2, hostBudget: 2, budget: 3, minutes: 1 }, clock);
  assert.ok(await b.acquire("a")); assert.ok(await b.acquire("a")); assert.equal(await b.acquire("a"), null);   // per-host budget
  assert.ok(await b.acquire("b")); assert.equal(await b.acquire("c"), null);                                     // global budget
  const s = new Limiter({ rate: 20, concurrency: 8, hostConcurrency: 2, hostBudget: 9, budget: 9, minutes: 1 }, clock); s.stop("interrupted"); assert.equal(await s.acquire("a"), null);
  const t = new Limiter({ rate: 20, concurrency: 8, hostConcurrency: 2, hostBudget: 9, budget: 9, minutes: 1 }, clock); clock.t += 61e3; assert.equal(await t.acquire("a"), null); assert.match(t.stats().stopped, /time limit/);
});
test("ports: lists and ranges, capped at 1024", () => {
  assert.deepEqual(parsePorts("443,22,8000-8002").ports, [22, 443, 8000, 8001, 8002]);
  assert.match(parsePorts("1-2000").error, /1024/); assert.match(parsePorts("70000").error, /outside/); assert.match(parsePorts("ssh").error, /not a port/);
});

/* ---- fingerprints ---- */
test("SSH banners: OpenSSH (portable suffix and distribution builds), Dropbear, libssh, unknown", () => {
  const u = fromSsh(BANNERS.ssh_openssh_ubuntu)[0];
  assert.deepEqual([u.product, u.vendor, u.version, u.shown_version, u.distro], ["OpenSSH", "OpenBSD", "9.6", "9.6p1", "Ubuntu"]);
  assert.equal(fromSsh(BANNERS.ssh_openssh_plain)[0].distro, "");
  assert.equal(fromSsh(BANNERS.ssh_openssh_debian)[0].distro, "Debian");
  assert.deepEqual([fromSsh(BANNERS.ssh_dropbear)[0].product, fromSsh(BANNERS.ssh_dropbear)[0].version], ["Dropbear SSH", "2022.83"]);
  assert.equal(fromSsh(BANNERS.ssh_libssh)[0].version, "0.9.6");
  const c = fromSsh(BANNERS.ssh_cisco)[0]; assert.equal(c.product, ""); assert.match(c.label, /Cisco-1\.25/);
  assert.deepEqual(fromSsh("HTTP/1.1 400 Bad Request"), []);
});
test("FTP, SMTP, IMAP, POP3 and VNC greetings", () => {
  const g = (k, port) => fromGreeting(BANNERS[k], port)[0];
  assert.deepEqual([g("ftp_vsftpd", 21).product, g("ftp_vsftpd", 21).version], ["vsftpd", "3.0.3"]);
  assert.deepEqual([g("ftp_proftpd", 21).version, g("ftp_proftpd", 21).distro], ["1.3.8", "Debian"]);
  assert.equal(g("ftp_proftpd_hidden", 21).guessed, true); assert.equal(g("ftp_proftpd_hidden", 21).version, "");
  assert.equal(g("ftp_filezilla", 21).version, "1.8.0");
  assert.equal(g("smtp_exim", 25).version, "4.96"); assert.equal(g("smtp_sendmail", 25).version, "8.15.2");
  assert.equal(g("smtp_postfix", 25).product, "Postfix"); assert.equal(g("smtp_exchange", 25).product, "Exchange Server");
  assert.equal(g("imap_dovecot", 143).product, "Dovecot"); assert.equal(g("pop_dovecot", 110).distro, "Debian");
  assert.equal(g("vnc", 5900).label, "VNC server");
});
test("MySQL and MariaDB handshakes; a refusal packet gives no version", () => {
  const pkt = (body) => Buffer.concat([Buffer.from([body.length & 255, (body.length >> 8) & 255, 0, 0]), body]);
  const hs = (v) => pkt(Buffer.concat([Buffer.from([0x0a]), Buffer.from(v, "latin1"), Buffer.from([0, 1, 0, 0, 0])]));
  assert.deepEqual([fromMysql(hs("8.0.35"))[0].product, fromMysql(hs("8.0.35"))[0].version], ["MySQL", "8.0.35"]);
  const m = fromMysql(hs("5.5.5-10.11.6-MariaDB-0+deb12u1"))[0]; assert.deepEqual([m.product, m.version, m.distro], ["MariaDB", "10.11.6", "Debian"]);
  const refused = fromMysql(pkt(Buffer.concat([Buffer.from([0xff, 0x6a, 0x04]), Buffer.from("Host is not allowed to connect", "latin1")])))[0];
  assert.equal(refused.version, ""); assert.equal(refused.product, "");
  assert.deepEqual(fromMysql(Buffer.from([1, 2])), []);
});
test("HTTP headers and the generator tag", () => {
  const h = (k) => fromHttp({ headers: BANNERS[k], body: "" });
  const ap = h("http_apache"); assert.deepEqual(ap.map((s) => [s.product, s.version, s.shown_version, s.distro]), [["HTTP Server", "2.4.58", "2.4.58", "Ubuntu"], ["PHP", "8.1.2", "8.1.2-1ubuntu2.19", "Ubuntu"]]);
  assert.deepEqual(h("http_nginx").map((s) => [s.vendor, s.product, s.version]), [["F5", "nginx", "1.24.0"]]);
  assert.equal(h("http_iis")[0].product, "Internet Information Services");
  assert.equal(h("http_jetty")[0].version, "9.4.51");
  assert.equal(h("http_coyote")[0].version, ""); assert.equal(h("http_coyote")[0].guessed, true);
  assert.deepEqual(h("http_owa").map((s) => s.product), ["Internet Information Services", "Exchange Server"]);
  assert.equal(h("http_lighttpd")[0].version, "1.4.69"); assert.equal(h("http_openresty")[0].version, "1.21.4.1");
  const wp = fromHttp({ headers: {}, body: BANNERS.http_wordpress_body }); assert.deepEqual([wp[0].product, wp[0].version], ["WordPress", "6.4.2"]);
});
test("TLS certificates: expiry, self-signed, appliance hint without a version", () => {
  const cert = { subject: { CN: "FortiGate", O: "Fortinet" }, issuer: { CN: "FortiGate", O: "Fortinet" }, valid_from: "Jan  1 00:00:00 2020 GMT", valid_to: "Jan  1 00:00:00 2025 GMT" };
  const i = certInfo(cert, Date.parse("2026-11-22")); assert.equal(i.expired, true); assert.equal(i.self_signed, true); assert.equal(i.valid_to, "2025-01-01");
  const s = fromCert(cert)[0]; assert.deepEqual([s.vendor, s.product, s.version, s.guessed], ["Fortinet", "FortiOS", "", true]);
  assert.deepEqual(observations(443, { cert, now: Date.parse("2026-11-22") }).map((o) => o.kind), ["tls-expired", "tls-self-signed"]);
  assert.deepEqual(fromCert({ subject: { CN: "intranet.example.lan" }, issuer: { CN: "Example CA" } }), []);
  // a stated product wins over the same product guessed from the certificate
  assert.equal(servicesOf({ port: 443, tls: { cert }, http: { headers: { server: "nginx/1.24.0" }, body: "" } }).length, 2);
});

/* ---- matching and the rating: the same answers as the site ---- */
const wb = JSON.parse(readFileSync(join(SNAP, "data", "workbench.json"), "utf8"));
const rowsFile = JSON.parse(readFileSync(join(SNAP, "data", "cve", "2026", "90.json"), "utf8"));
const svc = (o) => ({ port: 22, proto: "ssh", vendor: "", product: "", label: "", version: "", shown_version: "", distro: "", source: "test", evidence: "test", guessed: false, ...o });
test("matching uses the site's matchFlaw; the Vulnerabilities page uses the same function", () => {
  const page = readFileSync(new URL("../../site/vulnerabilities.js", import.meta.url), "utf8");
  assert.match(page, /W\.matchFlaw\(f, inv\)/); assert.match(page, /cleanRange = W\.cleanRange/);
  const flaws = cleanFlaws(wb), hosts = [{ address: "10.0.0.5", names: [], services: [svc({ vendor: "F5", product: "nginx", version: "1.22.1", shown_version: "1.22.1", port: 80 }), svc({ vendor: "F5", product: "nginx", version: "1.26.0", shown_version: "1.26.0", port: 8080 }), svc({ vendor: "Apache", product: "HTTP Server", version: "2.4.58", shown_version: "2.4.58", port: 81 })] }];
  const f = findings(hosts, flaws, new Map(), { today: TODAY });
  const ng = f.find((x) => x.cve === "CVE-2026-90102");
  assert.deepEqual(ng.seen_on.map((s) => s.port), [80]);   // 1.26.0 is past the fix: clear, not reported
  assert.equal(ng.state, "affected");
  const ap = f.find((x) => x.cve === "CVE-2026-90201"); assert.equal(ap.state, "check"); assert.equal(ap.confidence, "low");   // name-only flaw
  // the site's page logic on the same list gives the same states
  for (const fl of flaws) for (const s of hosts[0].services) {
    const mine = SW.matchFlaw(JSON.parse(JSON.stringify(fl)), [toItem(s)]), want = SW.matchFlaw(JSON.parse(JSON.stringify(fl)), [{ name: s.product, vendor: s.vendor, version: s.version, count: 1 }]);
    assert.deepEqual(JSON.parse(JSON.stringify(mine)), JSON.parse(JSON.stringify(want)));
  }
});
test("the rating and the priority equal the site's cvedb-lib for the same row, with every point listed", () => {
  const flaws = cleanFlaws(wb), rows = new Map();
  for (const a of rowsFile.rows) { const r = SD.cleanRow(rowsFile.fields, a); rows.set(r.id, r); }
  const hosts = [{ address: "10.0.0.5", names: [], services: [svc({ vendor: "OpenBSD", product: "OpenSSH", version: "9.6", shown_version: "9.6p1" }), svc({ port: 80, vendor: "F5", product: "nginx", version: "1.22.1", shown_version: "1.22.1" })] }];
  const f = findings(hosts, flaws, rows, { today: TODAY });
  for (const x of f) {
    const r = SD.cleanRow(rowsFile.fields, rowsFile.rows.find((a) => a[0] === x.cve)), s = SD.score(r), p = SD.rate(r, { today: TODAY, exposed: false });
    assert.equal(x.rating.score, s.score); assert.equal(x.rating.band, s.band); assert.equal(x.rating.text, s.text);
    assert.equal(x.priority.decision, p.decision); assert.deepEqual(JSON.parse(JSON.stringify(x.priority.inputs.map((i) => i.value))), JSON.parse(JSON.stringify(p.inputs.map((i) => i.value))));
    const fl = flaws.find((y) => y.cve === x.cve), q = SW.score(JSON.parse(JSON.stringify(fl)), { state: x.state }, TODAY);
    assert.equal(x.points.total, q.total); assert.deepEqual(JSON.parse(JSON.stringify(x.points.list.map((y) => [y.points, y.why]))), JSON.parse(JSON.stringify(q.points)));
    assert.ok(x.points.list.length >= 2 && x.points.list.every((y) => y.points > 0 && y.why));
  }
  // a Ubuntu build inside the range: medium confidence (backports), never high
  const ssh = f.find((x) => x.cve === "CVE-2026-90101"); assert.equal(ssh.confidence, "high");
  const ub = findings([{ address: "10.0.0.6", names: [], services: [svc({ vendor: "OpenBSD", product: "OpenSSH", version: "9.6", shown_version: "9.6p1", distro: "Ubuntu" })] }], flaws, rows, { today: TODAY })[0];
  assert.equal(ub.confidence, "medium"); assert.match(ub.confidence_why, /backported/);
  // ranking: known exploited first, past CISA's deadline next, then the rating
  assert.deepEqual(f.map((x) => x.cve), ["CVE-2026-90101", "CVE-2026-90102"]);
  // a missing lookup row falls back to the KEV entry and says so
  const fb = findings([{ address: "10.0.0.7", names: [], services: [svc({ port: 21, vendor: "", product: "vsftpd", version: "3.0.3", shown_version: "3.0.3" })] }], flaws, rows, { today: TODAY })[0];
  assert.equal(fb.cve, "CVE-2026-90104"); assert.match(fb.rating.from, /KEV entry/); assert.equal(fb.rating.score, 6.5);
  // fix: the vendor's fixed versions and advisory are given; signs of compromise are linked, not copied
  assert.deepEqual(ssh.fix.vendor_fixed, ["OpenSSH 9.8 or later"]); assert.equal(ssh.fix.advisory.url, "https://advisories.example.com/fixture-openssh");
  assert.ok(!JSON.stringify(ssh).includes("unexpected child processes")); assert.match(ssh.fix.details, /vulnerabilities\.html#CVE-2026-90101$/);
  assert.equal(ssh.fix.analysis.by, "CyberView AI (a Claude model)");
});

/* ---- exporters ---- */
function sampleReport() {
  const flaws = cleanFlaws(wb), rows = new Map(rowsFile.rows.map((a) => { const r = SD.cleanRow(rowsFile.fields, a); return [r.id, r]; }));
  const hosts = [{ address: "10.0.0.5", names: ["intranet.example.lan"], up: true, ports: [], services: [svc({ vendor: "F5", product: "nginx", label: "F5 nginx", version: "1.22.1", shown_version: "1.22.1", port: 80 }), svc({ vendor: "OpenBSD", product: "OpenSSH", label: "OpenBSD OpenSSH", version: "9.6", shown_version: "9.6p1" })], observations: [] }];
  return { run: { interrupted: false, started_at: "2026-11-22T00:00:00Z", finished_at: "2026-11-22T00:01:00Z" }, scope: { owner: "Example lab", attestation: { name: "Test Operator" } }, summary: {}, hosts, findings: findings(hosts, flaws, rows, { today: TODAY }), notes: [] };
}
test("CSV: one row per CVE and place, every point listed, formulas never run in a spreadsheet", () => {
  const rep = sampleReport(), csv = toCsv(rep), lines = csv.trim().split("\r\n");
  assert.equal(lines[0], CSV_HEAD.join(",")); assert.equal(lines.length, 1 + rep.findings.reduce((n, f) => n + f.seen_on.length, 0));
  assert.match(csv, /Known exploited \(CISA\) \+35/);
  rep.findings[0].title = "=HYPERLINK(1)"; assert.match(toCsv(rep), /,'=HYPERLINK\(1\),/);
});
test("SARIF 2.1.0: rules, results with locations and levels", () => {
  const s = toSarif(sampleReport());
  assert.equal(s.version, "2.1.0"); assert.equal(s.runs[0].tool.driver.name, "CyberView Scanner");
  const r = s.runs[0].results; assert.ok(r.length >= 2);
  for (const x of r) { assert.match(x.ruleId, /^CVE-/); assert.equal(s.runs[0].tool.driver.rules[x.ruleIndex].id, x.ruleId); assert.match(x.locations[0].physicalLocation.artifactLocation.uri, /^tcp:\/\/10\.0\.0\.5:\d+$/); assert.ok(["error", "warning", "note"].includes(x.level)); }
  assert.equal(r.find((x) => x.ruleId === "CVE-2026-90102").level, "error");
  assert.ok(s.runs[0].tool.driver.rules.every((x) => /^\d+\.\d$/.test(x.properties["security-severity"])));
});
test("inventory CSV: the site's My software import reads it back", () => {
  const inv = SW.parseInventory("inventory.csv", toInventory(sampleReport()));
  assert.equal(inv.kind, "table"); assert.deepEqual(JSON.parse(JSON.stringify(inv.items.map((i) => [i.name, i.version, i.vendor]))), [["nginx", "1.22.1", "F5"], ["OpenSSH", "9.6p1", "OpenBSD"]]);
});

/* ---- data: offline and online ---- */
test("offline mode: a whole scan from a snapshot, no data request, report files written privately", async () => {
  const d = tmp(), p = writeScope(d, { targets: ["10.0.0.5"] });
  let fetched = 0;
  const probe = async (ip, port) => port === 22 ? { port, state: "open", banner: BANNERS.ssh_openssh_plain } : port === 80 ? { port, state: "open", http: { status: 200, headers: BANNERS.http_nginx, body: "" } } : { port, state: "closed" };
  const x = io({ probe, fetchImpl: () => { fetched++; throw new Error("offline"); } });
  assert.equal(await main(["scan", "--scope", p, "--data", SNAP, "--ports", "22,80,443", "--out", join(d, "out")], x), 0);
  assert.equal(fetched, 0);
  assert.deepEqual(readdirSync(join(d, "out")).sort(), ["findings.csv", "inventory.csv", "report.json", "report.sarif", "summary.txt"]);
  const rep = JSON.parse(readFileSync(join(d, "out", "report.json"), "utf8"));
  assert.equal(rep.run.data.mode, "offline"); assert.equal(rep.scope.attestation.name, "Test Operator"); assert.equal(rep.scope.owner, "Example lab");
  assert.deepEqual(rep.findings.map((f) => f.cve), ["CVE-2026-90102"]);   // OpenSSH 9.9 is past the fix
  assert.equal(rep.summary.known_exploited, 1); assert.equal(rep.summary.hosts_up, 1);
  assert.match(x.lines.out.join("\n"), /Attested by: Test Operator/);
  assert.equal((await import("node:fs")).statSync(join(d, "out", "report.json")).mode & 0o077, 0);
});
test("a scan needs an explicit data source; a folder that is not a snapshot is refused", async () => {
  const d = tmp(), p = writeScope(d, {});
  const x = io(); assert.equal(await main(["scan", "--scope", p], x), 1); assert.match(x.lines.err.join("\n"), /choose the data source/);
  const y = io(); assert.equal(await main(["scan", "--scope", p, "--data", d], y), 1); assert.match(y.lines.err.join("\n"), /not a CyberView snapshot/);
});
test("online mode reads only CyberView's published data files, with GET, and can make a snapshot", async () => {
  const asked = [];
  const fetchImpl = async (url, opts) => {
    asked.push([opts.method, url, opts.headers["User-Agent"]]);
    const rel = url.replace("https://cyberview.example/", ""), p = join(SNAP, rel);
    return existsSync(p) ? new Response(readFileSync(p), { status: 200 }) : new Response("no", { status: 404 });
  };
  const src = webSource("https://cyberview.example/", { fetchImpl });
  await assert.rejects(src.json("data/../../etc/passwd"), /not a CyberView data file/);
  await assert.rejects(src.json("data/events/x.json"), /not a CyberView data file/);
  const d = tmp(), x = io({ fetchImpl });
  assert.equal(await main(["data", "--out", join(d, "snap"), "--source", "https://cyberview.example/"], x), 0);
  assert.ok(asked.every(([m, u, ua]) => m === "GET" && ALLOWED.test(u.replace("https://cyberview.example/", "")) && ua === USER_AGENT));
  assert.ok(existsSync(join(d, "snap", "data", "cve", "2026", "90.json")));
  assert.ok(dirSource(join(d, "snap")).manifest.fetched_at);
  assert.equal(checkBase("http://cyberview.example/"), ""); assert.equal(checkBase("http://127.0.0.1:8000/"), "http://127.0.0.1:8000/"); assert.equal(checkBase("https://u:p@x.example/"), "");
});

/* ---- on loopback, end to end ---- */
test("loopback: real probes against stand-in services; only the identification line and one root-page request are sent", async () => {
  const srv = await startServers();
  try {
    const d = tmp(), p = writeScope(d, { targets: ["127.0.0.1"], ports: [srv.ports.ssh, srv.ports.ftp, srv.ports.http, srv.closed] });
    const x = io({ probe: undefined });
    delete x.probe;
    assert.equal(await main(["scan", "--scope", p, "--data", SNAP, "--http-ports", String(srv.ports.http), "--out", join(d, "out")], x), 0);
    const rep = JSON.parse(readFileSync(join(d, "out", "report.json"), "utf8"));
    assert.deepEqual(rep.hosts[0].ports.map((q) => q.port).sort(), [srv.ports.ssh, srv.ports.ftp, srv.ports.http].sort());
    assert.deepEqual(rep.findings.map((f) => f.cve).sort(), ["CVE-2026-90101", "CVE-2026-90102", "CVE-2026-90103", "CVE-2026-90104"]);
    assert.equal(rep.findings[0].cve, "CVE-2026-90101");
    // what the services received from the scanner. The scan closes the scanner's socket before the loopback server's
    // "data" event fires, so wait for the SSH ident to arrive before asserting it is the only thing sent.
    for (let i = 0; i < 100 && !srv.got.ssh.length; i++) await new Promise((r) => setTimeout(r, 10));
    assert.deepEqual(srv.got.ftp, []);
    assert.deepEqual(srv.got.ssh, [SSH_IDENT + "\r\n"]);
    assert.equal(srv.got.http.length, 1);
    assert.deepEqual([srv.got.http[0].method, srv.got.http[0].url, srv.got.http[0].headers["user-agent"]], ["GET", "/", USER_AGENT]);
    assert.ok(rep.run.network.connections <= 4 && rep.run.network.max_open_at_once <= 8);
  } finally { await srv.close(); }
});
test("Ctrl-C (an abort) stops new connections and still writes a report marked interrupted", async () => {
  const d = tmp(), p = writeScope(d, { targets: ["10.0.0.0/29"] }), ac = new AbortController();
  let n = 0;
  const probe = async (ip, port) => { if (++n === 3) ac.abort("interrupted (Ctrl-C)"); return { port, state: "closed" }; };
  const x = io({ probe, signal: ac.signal });
  assert.equal(await main(["scan", "--scope", p, "--data", SNAP, "--out", join(d, "out"), "--concurrency", "1"], x), 3);
  const rep = JSON.parse(readFileSync(join(d, "out", "report.json"), "utf8"));
  assert.equal(rep.run.interrupted, true); assert.match(rep.run.stop_reason, /Ctrl-C/); assert.ok(rep.run.network.connections < 6 * 22);
});
test("probePort reports a refused port as closed and never throws", async () => {
  const srv = await startServers();
  try { const r = await probePort("127.0.0.1", srv.closed); assert.equal(r.state, "closed"); } finally { await srv.close(); }
});

/* ---- depth: --all-ports and the private budget scaling ---- */
test("all-ports: the full TCP range, and the budgets scale only for owned private ranges", () => {
  const ap = allPorts();
  assert.equal(ap.length, 65535); assert.equal(ap[0], 1); assert.equal(ap[65534], 65535);
  // private-only (no --i-am-authorized-for-public-ranges): per-host and total budgets scale up, the rate/concurrency ceilings do not
  const priv = settings({ budget: 500000, hostBudget: 60000 }, { hasPublic: false });
  assert.equal(priv.ok, true); assert.equal(priv.settings.budget, 500000); assert.equal(priv.settings.hostBudget, 60000);
  assert.equal(settings({}, { hasPublic: false }).settings.budget, PRIVATE_CAPS.budget);   // default high for a private sweep
  assert.equal(settings({}, { hasPublic: true }).settings.budget, 20000);                   // strict for any public scan
  // the same high budget is refused as soon as a public address is in scope
  assert.equal(settings({ budget: 500000 }, { hasPublic: true }).ok, false);
  assert.equal(settings({ hostBudget: 60000 }, { hasPublic: true }).ok, false);
  // the rate and open-at-once ceilings never scale, public or private
  assert.equal(settings({ rate: 21 }, { hasPublic: false }).ok, false);
  assert.equal(settings({ concurrency: 9 }, { hasPublic: false }).ok, false);
  assert.ok(!("rate" in PRIVATE_CAPS) && !("concurrency" in PRIVATE_CAPS) && !("hostConcurrency" in PRIVATE_CAPS));
});
test("--all-ports is refused with a public scope or alongside --ports", async () => {
  const d = tmp();
  const pub = writeScope(d, { targets: ["198.51.100.7"] });
  const x = io(); assert.equal(await main(["scan", "--scope", pub, "--data", SNAP, "--all-ports", "--i-am-authorized-for-public-ranges", "--out", join(d, "o1")], x), 2);
  assert.match(x.lines.err.join("\n"), /all-ports.*owned private ranges/s);
  const prv = writeScope(d, { targets: ["10.0.0.5"] });
  const y = io({ probe: async () => ({ port: 0, state: "closed" }) });
  assert.equal(await main(["scan", "--scope", prv, "--data", SNAP, "--all-ports", "--ports", "22,80", "--out", join(d, "o2")], y), 2);
  assert.match(y.lines.err.join("\n"), /either --all-ports or --ports/);
});

/* ---- depth: the UDP checks (one benign read-only query per service per host) ---- */
const dnsResponse = (txt) => { const h = Buffer.alloc(12); h.writeUInt16BE(0x8180, 2); h.writeUInt16BE(1, 4); h.writeUInt16BE(1, 6);
  const q = Buffer.concat([Buffer.from([7]), Buffer.from("version"), Buffer.from([4]), Buffer.from("bind"), Buffer.from([0, 0, 16, 0, 3])]);
  const t = Buffer.from(txt), rl = Buffer.alloc(2); rl.writeUInt16BE(t.length + 1);
  return Buffer.concat([h, q, Buffer.from([0xc0, 0x0c, 0, 16, 0, 3, 0, 0, 0, 0]), rl, Buffer.from([t.length]), t]); };
const snmpResponse = (desc) => { const oct = (s) => { const b = Buffer.from(s); return Buffer.concat([Buffer.from([4, b.length]), b]); }; const seq = (b) => Buffer.concat([Buffer.from([0x30, b.length]), b]);
  return seq(Buffer.concat([Buffer.from([2, 1, 0]), oct("public"), seq(oct(desc))])); };
test("UDP query builders: version.bind (CHAOS TXT), NTP mode-6 read, SNMP GET sysDescr with only the public community", () => {
  const dq = dnsVersionQuery();
  assert.equal(dq.readUInt16BE(2), 0x0100); assert.equal(dq.readUInt16BE(4), 1);                 // RD=1, one question
  assert.match(dq.toString("latin1"), /version.bind/); assert.equal(dq[dq.length - 2], 0); assert.equal(dq[dq.length - 1], 3);   // QTYPE TXT(16), QCLASS CHAOS(3)
  const nq = ntpReadVarQuery();
  assert.equal(nq.length, 12); assert.equal(nq[0] & 7, 6); assert.equal(nq[1], 2);                // mode 6 (control), op 2 (read)
  assert.equal(SNMP_COMMUNITY, "public");
  const sq = snmpGetSysDescr();
  assert.equal(sq[0], 0x30); assert.match(sq.toString("latin1"), /public/);                       // one SNMP message carrying the community "public"
  assert.ok(sq.includes(Buffer.from([0x2b, 6, 1, 2, 1, 1, 1, 0])));                               // OID 1.3.6.1.2.1.1.1.0 (sysDescr.0)
  assert.equal((snmpGetSysDescr().toString("latin1").match(/public/g) || []).length, 1);          // the one and only community
});
test("UDP response parsers: BIND version, ntpd version, sysDescr, and a fingerprint from each", () => {
  assert.equal(parseDnsVersion(dnsResponse("9.18.1-Debian")).version, "9.18.1-Debian");
  assert.equal(parseNtpReadVar(Buffer.concat([ntpReadVarQuery(), Buffer.from('version="ntpd 4.2.8p15@1.3728-o", system="Linux/5.15"')])).version, "ntpd 4.2.8p15@1.3728-o");
  assert.equal(parseSnmpSysDescr(snmpResponse("Linux fw01 5.15 x86_64")).sysdescr, "Linux fw01 5.15 x86_64");
  // fromUdp turns the parsed answers into matchable service records (DNS->BIND, NTP->NTP); SNMP stays an observation
  const dns = fromUdp({ state: "open", port: 53, proto: "dns", parsed: parseDnsVersion(dnsResponse("9.16.1-Ubuntu")) })[0];
  assert.deepEqual([dns.vendor, dns.product, dns.version, dns.distro], ["ISC", "BIND", "9.16.1", "Ubuntu"]);
  const ntp = fromUdp({ state: "open", port: 123, proto: "ntp", parsed: parseNtpReadVar(Buffer.concat([ntpReadVarQuery(), Buffer.from('version="4.2.8p15"')])) })[0];
  assert.deepEqual([ntp.product, ntp.version, ntp.shown_version], ["NTP", "4.2.8", "4.2.8p15"]);   // version is the comparable core, shown_version is as stated
  const obs = udpObservations({ state: "open", port: 161, proto: "snmp", parsed: { sysdescr: "Linux fw01" } })[0];
  assert.equal(obs.kind, "snmp-public"); assert.match(obs.text, /default "public" community/);
  assert.deepEqual(parseDnsVersion(Buffer.from([1, 2])), { version: "", text: "" });   // defensive: never throws on junk
});
test("udpProbe sends one datagram, never throws, and reports no answer as filtered (loopback, nothing listening on 53)", async () => {
  // the real udpProbe always targets the standard service port; on loopback with nothing bound to 53 it must send its one
  // benign datagram, get no reply, and report "filtered" without throwing. (A positive end-to-end UDP read is demonstrated
  // separately against a stand-in on an ephemeral port; here we prove the single-datagram, never-throw contract.)
  const none = await udpProbe("127.0.0.1", "dns");
  assert.equal(none.state, "filtered"); assert.equal(none.service, "dns"); assert.equal(none.port, 53); assert.equal(none.parsed, null);
});
test("udpProbe reads a real reply from a loopback DNS stand-in and parses the BIND version", async () => {
  const dgram = await import("node:dgram");
  const srv = dgram.createSocket("udp4");
  let seen = 0;
  srv.on("message", (m, r) => { seen++; assert.match(m.toString("latin1"), /version.bind/); srv.send(dnsResponse("9.16.1-Ubuntu"), r.port, r.address); });
  await new Promise((r) => srv.bind(0, "127.0.0.1", r));
  try {
    const r = await udpProbe("127.0.0.1", "dns", { port: srv.address().port });
    assert.equal(r.state, "open"); assert.equal(r.parsed.version, "9.16.1-Ubuntu"); assert.equal(seen, 1);   // exactly one datagram received
  } finally { srv.close(); }
});

/* ---- discovery: parse asset lists, cloud inventory and CT; re-check every host against the scope ---- */
const DISC = join(FIX, "discover");
const rf = (name) => readFileSync(join(DISC, name), "utf8");
test("import parsers: plain list, CSV and nmap -oX XML; URLs, ports and CIDRs handled", () => {
  const list = parseAssetFile(rf("assets.txt"), "list").candidates;
  assert.deepEqual(list.map((c) => c.ip || c.host || c.cidr), ["10.20.0.5", "intranet.example.lan", "10.20.0.0/30", "web.example.lan"]);
  const csv = parseAssetFile(rf("assets.csv"), "csv").candidates;
  assert.ok(csv.some((c) => c.ip === "10.20.0.9") && csv.some((c) => c.host === "web1") && csv.some((c) => c.ip === "203.0.113.77"));
  const xml = parseAssetFile(rf("scan.nmap.xml"), "auto").candidates;   // auto-detects nmap XML
  assert.deepEqual(xml.map((c) => c.ip || c.host), ["10.20.0.5", "10.20.0.11", "203.0.113.5", "ssh.example.lan", "public.example.net"]);
});
test("cloud parsers: read-only aws/gcp/azure inventory JSON for public IPs and DNS names", () => {
  const aws = parseCloud(rf("aws-ec2.json"), "aws-ec2").candidates.map((c) => c.ip || c.host);
  assert.deepEqual(aws, ["203.0.113.20", "ec2-203-0-113-20.compute-1.amazonaws.com", "203.0.113.21"]);   // private IPs are not pulled
  assert.deepEqual(parseCloud(rf("gcp-instances.json"), "gcp").candidates.map((c) => c.ip), ["198.51.100.30"]);
  assert.deepEqual(parseCloud(rf("azure-ip.json"), "azure").candidates.map((c) => c.ip), ["198.51.100.40"]);
  assert.match(parseCloud("not json", "aws-ec2").problems[0], /not valid JSON/);
  assert.match(parseCloud("{}", "digitalocean").problems[0], /unknown cloud provider/);
});
test("Certificate Transparency: parse crt.sh JSON to the domain's own subdomains; a fetch is a read-only GET", async () => {
  const subs = parseCtJson(rf("crtsh.json"), "example.com");
  assert.deepEqual(subs.sort(), ["mail.example.com", "vpn.example.com", "www.example.com"]);   // wildcard dropped, duplicate removed, other domain excluded
  let asked = null;
  const fetchImpl = async (url, opts) => { asked = { url, method: opts.method, redirect: opts.redirect }; return new Response(rf("crtsh.json"), { status: 200 }); };
  const r = await ctSubdomains("example.com", { fetchImpl });
  assert.deepEqual(r.subdomains.sort(), ["mail.example.com", "vpn.example.com", "www.example.com"]);
  assert.equal(asked.method, "GET"); assert.equal(asked.redirect, "error"); assert.match(asked.url, /^https:\/\/crt\.sh\/\?q=/);
});
test("the scope's discover block is parsed and validated; ct needs domains", () => {
  const ok = checkScope(scopeText({ discover: { cidr: true, domains: ["example.com"], ct: true, import: [{ file: "a.csv" }], cloud: [{ file: "ec2.json", provider: "aws-ec2" }] } }), { today: TODAY });
  assert.equal(ok.ok, true); assert.deepEqual(ok.scope.discover.domains, ["example.com"]); assert.equal(ok.scope.discover.ct, true);
  assert.equal(ok.scope.discover.import[0].file, "a.csv"); assert.equal(ok.scope.discover.cloud[0].provider, "aws-ec2");
  assert.match(checkScope(scopeText({ discover: { domains: ["not a domain!"] } }), { today: TODAY }).problems.join(";"), /not a domain name/);
  assert.match(checkScope(scopeText({ discover: { ct: true, domains: [] } }), { today: TODAY }).problems.join(";"), /ct needs discover.domains/);
  // an attested domain puts its subdomains in scope
  const { scope } = checkScope(scopeText({ targets: ["10.20.0.5"], discover: { domains: ["example.com"] } }), { today: TODAY });
  assert.equal(hostInScope(scope, "vpn.example.com"), true); assert.equal(hostInScope(scope, "example.com"), true); assert.equal(hostInScope(scope, "evil.test"), false);
});
test("every discovered host is re-checked against the scope: out-of-scope and public ones are dropped and logged", async () => {
  const { scope } = checkScope(scopeText({ targets: ["10.20.0.9"], discover: { domains: ["example.com"] } }), { today: TODAY });
  const discovered = { hosts: [{ host: "vpn.example.com", source: "CT log" }], ips: [{ ip: "10.20.0.9", source: "import:csv" }, { ip: "203.0.113.77", source: "import:csv" }, { ip: "10.99.0.1", source: "import:csv" }], ranges: [] };
  const resolve = async (h) => (h === "vpn.example.com" ? [{ address: "10.20.0.50" }, { address: "203.0.113.9" }] : []);
  const r = await resolveScope(scope, { allowPublic: false, resolve, discovered });
  const addrs = r.targets.map((t) => t.address).sort();
  assert.deepEqual(addrs, ["10.20.0.50", "10.20.0.9"]);   // 10.20.0.9 listed, 10.20.0.50 in scope via the attested domain; private only
  assert.ok(r.refused.some((x) => /203\.0\.113\.77/.test(x.target) && /not in the scope/.test(x.why) && /import:csv/.test(x.why)));
  assert.ok(r.refused.some((x) => /10\.99\.0\.1/.test(x.target) && /not in the scope/.test(x.why)));
  assert.ok(r.refused.some((x) => /203\.0\.113\.9/.test(x.target) && /public address/.test(x.why)));   // in scope via domain but public without the flag
  assert.equal(r.stop, "");
});
test("the public cap is the hard stop for public space: a gated set over the cap stops, it does not scan fewer", async () => {
  // discovery can push the public count past the cap (e.g. many attested-domain subdomains on distinct public IPs); resolveScope
  // enforces the stop AFTER gating. A hand-built scope of 2046 public addresses stands in for that gated result.
  const scope = { targets: [parseTarget("203.0.113.0/21")], exclude: [], hosts: [], discover: null };
  const r = await resolveScope(scope, { allowPublic: true });
  assert.ok(r.publicCount > LIMITS.maxPublicAddresses);
  assert.match(r.stop, /over the hard cap of 1024.*Nothing was scanned/s);
  // under the cap, no stop; the same scope with --i-am-authorized would scan
  const under = await resolveScope({ targets: [parseTarget("203.0.113.0/23")], exclude: [], hosts: [], discover: null }, { allowPublic: true });
  assert.equal(under.stop, ""); assert.ok(under.publicCount <= LIMITS.maxPublicAddresses);
  // the CLI surfaces resolveScope's stop as a refusal (exit 2); the scan-body guard is: if (stop) { err; return 2; }
  assert.match(readFileSync(new URL("../../scanner/cyberview-scan.mjs", import.meta.url), "utf8"), /if \(stop\) \{ io\.err\("REFUSED: " \+ stop\); return 2;/);
});
test("runDiscovery gathers candidates from every source with provenance, reading files and CT through injected hooks", async () => {
  const scope = { targets: [parseTarget("10.20.0.0/24")], discover: { cidr: true, domains: ["example.com"], ct: true, import: [{ file: "assets.csv" }], cloud: [{ file: "aws-ec2.json", provider: "aws-ec2" }] } };
  const readFile = (f) => rf(f);
  const fetchImpl = async () => new Response(rf("crtsh.json"), { status: 200 });
  const r = await runDiscovery(scope, { readFile, fetchImpl });
  assert.ok(r.hosts.some((h) => h.host === "example.com" && h.source === "domain"));
  assert.ok(r.hosts.some((h) => h.host === "vpn.example.com" && h.source === "CT log"));
  assert.ok(r.ips.some((i) => i.ip === "10.20.0.9" && /import/.test(i.source)));
  assert.ok(r.ips.some((i) => i.ip === "203.0.113.20" && /cloud:aws/.test(i.source)));
  assert.ok(r.notes.some((n) => /import/.test(n)) && r.notes.some((n) => /cloud/.test(n)));
});

/* ---- the security-check's scanner rules (section 7): what they catch ---- */
test("security-check section 7: UDP is confined to udp.mjs, one datagram, no community iteration, ceilings fixed", () => {
  const sec = readFileSync(new URL("../../scripts/security-check.mjs", import.meta.url), "utf8");
  // the rules exist in the check
  assert.match(sec, /opens a UDP socket \(dgram\) outside scanner\/lib\/udp\.mjs/);
  assert.match(sec, /must send exactly ONE datagram/);
  assert.match(sec, /iterates SNMP community strings/);
  assert.match(sec, /PRIVATE_CAPS may scale only hostBudget\/budget/);
  // udp.mjs itself obeys the flood guard: exactly one send, no loop or timer
  const udp = readFileSync(new URL("../../scanner/lib/udp.mjs", import.meta.url), "utf8");
  assert.equal((udp.match(/\.send\s*\(/g) || []).length, 1);
  assert.equal(/\b(for|while|do)\s*\(|\bsetInterval\b|\.forEach\s*\(/.test(udp), false);
  // dgram appears only in udp.mjs across the scanner
  for (const f of walkFiles(new URL("../../scanner/", import.meta.url).pathname)) {
    if (f.endsWith("udp.mjs")) continue;
    assert.equal(/node:dgram|from\s+["']dgram["']/.test(readFileSync(f, "utf8")), false, f);
  }
});

/* ---- nothing that attacks ---- */
test("no attack strings in the scanner, its docs or its fixtures (the NOCODE rule's attack patterns)", () => {
  // NOCODE without the parts that ordinary code and command examples need (backticks, ${...}, a shell command with flags)
  const ATTACK = /<\/?(script|iframe|object|embed)\b|\.\.\/\.\.|%2e%2e|%00|\\x[0-9a-f]{2}|\b(payload|shellcode|proof[- ]of[- ]concept code|exploit code)\s*:|\bUNION\s+SELECT\b|\bOR\s+1\s*=\s*1\b|\/bin\/(ba)?sh\b|\bcmd\.exe\s*\/c\b|\bjndi:|\bchmod\s+\+x\b|\b(msfconsole|sqlmap|hydra|medusa)\b|\b(GET|POST|PUT|PATCH|DELETE)\s+\/\S/i;
  assert.ok(ATTACK.source.length > 50 && NOCODE.test("UNION SELECT") && ATTACK.test("UNION SELECT"));
  const files = [];
  const walk = (dir) => { for (const f of readdirSync(dir, { withFileTypes: true })) { const q = join(dir, f.name); if (f.isDirectory()) walk(q); else files.push(q); } };
  walk(new URL("../../scanner/", import.meta.url).pathname); walk(FIX);
  files.push(new URL("../../docs/scanner.md", import.meta.url).pathname);
  for (const f of files) { const t = readFileSync(f, "utf8"); const m = ATTACK.exec(t); assert.equal(m, null, `${f}: ${m && m[0]}`); }
  for (const [k, v] of Object.entries(BANNERS)) if (typeof v === "string") assert.equal(NOCODE.test(v), false, k);
});

/* ---- coverage: a scan with blind spots must never read as clean (Grok brief #82, silent-failure fixes) ---- */
test("isTruncatedBanner flags a cut banner, not a full one", () => {
  for (const b of ["SSH-2.0-", "S", "SS", "220", "HTTP"]) assert.ok(isTruncatedBanner(b), b);
  for (const b of ["SSH-2.0-OpenSSH_9.6p1", "220 mail.example.com ESMTP Postfix", ""]) assert.ok(!isTruncatedBanner(b), b);
});
test("coverage: up host with closed ports is complete; filtered/down/unchecked are gaps", () => {
  const up = { address: "10.0.0.1", up: true, outcomes: [{ port: 22, state: "open" }, { port: 80, state: "closed" }] };
  assert.equal(coverage([up], { ports: [22, 80] }).complete, true);
  const down = { address: "10.0.0.2", up: false, outcomes: [{ port: 22, state: "filtered" }, { port: 80, state: "filtered" }] };
  const c = coverage([down], { ports: [22, 80] });
  assert.equal(c.complete, false); assert.deepEqual(c.hosts_unreachable, ["10.0.0.2"]); assert.equal(c.ports_filtered, 2);
  const partial = { address: "10.0.0.3", up: true, outcomes: [{ port: 22, state: "open" }] };
  assert.equal(coverage([partial], { ports: [22, 80, 443] }).ports_not_checked[0].not_checked, 2);
  const trunc = { address: "10.0.0.4", up: true, outcomes: [{ port: 22, state: "open", truncated: true }] };
  assert.equal(coverage([trunc], { ports: [22] }).truncated_banners[0].count, 1);
});
test("probeAll: a host firewalled on the first ports is still probed, and the gaps are recorded", async () => {
  const { settings: st } = settings({});
  const targets = [{ address: "203.0.113.9", names: [], kind: "public", public: true }];
  // the discovery ports (22/80/443) all drop; only a later port answers, with a cut banner
  const probe = async (ip, port) => (port === 8080 ? { port, state: "open", banner: "SSH-2.0-" } : { port, state: "filtered" });
  const res = await probeAll(targets, { ports: [22, 80, 443, 8080], settings: st, probe });
  const h = res.hosts[0];
  assert.ok(h.up, "found the open port past the dropped discovery ports");
  assert.equal(h.outcomes.length, 4, "every probe outcome recorded, not just the open one");
  const cov = coverage(res.hosts, { ports: [22, 80, 443, 8080] });
  assert.equal(cov.ports_filtered, 3);
  assert.equal(cov.truncated_banners.reduce((n, t) => n + t.count, 0), 1);
  assert.equal(cov.complete, false);
});

test("probeAll: a host that resets after answering is backed off and re-probed, recovering hidden services (#82 item 2)", async () => {
  const { settings: st } = settings({});
  const targets = [{ address: "203.0.113.5", names: [], kind: "public", public: true }];
  const resetPorts = new Set([8000, 8080, 8888]), seen = new Map();
  const probe = async (ip, port) => {
    const n = (seen.get(port) || 0) + 1; seen.set(port, n);
    if (port === 22) return { port, state: "open", banner: "SSH-2.0-OpenSSH_9.6p1" };               // host answers -> up
    if (resetPorts.has(port)) return n === 1 ? { port, state: "filtered", error: "ECONNRESET" }     // reset on first pass
      : { port, state: "open", banner: "220 (vsFTPd 3.0.3)" };                                       // answers after back-off
    return { port, state: "closed" };
  };
  const clock = { now: () => 1000, sleep: async () => {} };                                          // instant back-off
  const res = await probeAll(targets, { ports: [22, 8000, 8080, 8888], settings: st, probe, clock });
  const h = res.hosts[0];
  assert.ok(h.up);
  assert.equal(h.throttled, 3);                     // 3 resets detected after the host answered
  assert.equal(h.throttle_recovered, 3);            // all three found on the retry
  const cov = coverage(res.hosts, { ports: [22, 8000, 8080, 8888] });
  assert.equal(cov.throttled.length, 1);
  assert.equal(cov.throttled[0].recovered, 3);
  assert.equal(cov.ports_filtered, 0);              // a recovered port counts by its LAST (open) outcome, not the reset
  assert.equal(cov.complete, false);                // throttling stays a coverage note even after recovery
});
