// The downloadable scanner (scanner/): the authorization gate, the fingerprint parsers, matching and rating against the
// site's own code, the exporters, the politeness limits, and offline and online data. No real host is ever contacted:
// probes are stand-ins or stand-in services on 127.0.0.1 (tests/fixtures/scanner/servers.mjs).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
import vm from "node:vm";
import { checkScope, gate, hostInScope, classify, parseTarget, listAddresses, template, STATEMENT, LIMITS } from "../../scanner/lib/scope.mjs";
import { settings, Limiter, CAPS, PRIVATE_CAPS } from "../../scanner/lib/limits.mjs";
import { fromSsh, fromGreeting, fromMysql, fromHttp, fromCert, fromUdp, certInfo, observations, udpObservations, parseKexinit, sshKexObservations } from "../../scanner/lib/fingerprint.mjs";
import { cleanFlaws, findings, toItem } from "../../scanner/lib/match.mjs";
import { dirSource, webSource, ALLOWED, checkBase } from "../../scanner/lib/data.mjs";
import { parsePorts, resolveScope, probeAll, servicesOf, allPorts } from "../../scanner/lib/scan.mjs";
import { toCsv, toSarif, toInventory, CSV_HEAD, coverage, isTruncatedBanner, summaryText, summarize } from "../../scanner/lib/report.mjs";
import { USER_AGENT, SSH_IDENT, probePort, probeHttpPath } from "../../scanner/lib/probe.mjs";
import { selectPaths, PATH_CAP } from "../../scanner/lib/paths.mjs";
import { citationsFor, huntLinks } from "../../scanner/lib/cite.mjs";
import { dnsVersionQuery, parseDnsVersion, ntpReadVarQuery, parseNtpReadVar, snmpGetSysDescr, parseSnmpSysDescr, SNMP_COMMUNITY, UDP_SERVICES } from "../../scanner/lib/udp-codec.mjs";
import { udpProbe } from "../../scanner/lib/udp.mjs";
import { parseAssetFile, parseCloud, parseCtJson, ctSubdomains, runDiscovery } from "../../scanner/lib/discover.mjs";
import { main } from "../../scanner/cyberview-scan.mjs";
import { readInventory, parseCpe, parsePurl, MAX_BYTES } from "../../scanner/lib/inputs.mjs";
import { toHtml } from "../../scanner/lib/html.mjs";
import { diffReports } from "../../scanner/lib/diff.mjs";
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
  // OpenSSH with the version stripped is still OpenSSH (low confidence), not an anonymous "SSH server"
  const vl = fromSsh("SSH-2.0-OpenSSH")[0]; assert.deepEqual([vl.product, vl.vendor, vl.version, vl.guessed], ["OpenSSH", "OpenBSD", "", true]);
  const win = fromSsh("SSH-2.0-OpenSSH_for_Windows")[0]; assert.deepEqual([win.product, win.version], ["OpenSSH", ""]);
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
  // a bare 220 greeting is typed by its words, not the port: an unbranded FTP on a non-21 port is FTP, not SMTP
  assert.equal(fromGreeting("220 Welcome to the FTP service", 2121)[0].proto, "ftp");
  assert.equal(fromGreeting("220 mail.example.com ESMTP ready", 2525)[0].proto, "smtp");
  assert.equal(fromGreeting("220 service ready", 21)[0].proto, "ftp");          // silent banner: fall back to the port
  assert.equal(fromGreeting("220 service ready", 587)[0].proto, "smtp");
  assert.deepEqual(fromGreeting("220 service ready", 9999), []);                 // bare 220 on an unrelated port: no guess
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
  assert.deepEqual(readdirSync(join(d, "out")).sort(), ["findings.csv", "inventory.csv", "report.html", "report.json", "report.sarif", "summary.txt"]);
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

test("summarize: low-confidence findings are listed but kept out of the headline counts (#82 item 5)", () => {
  const hosts = [{ up: true, services: [{}], ports: [{ state: "open" }], observations: [] }];
  const f = (conf, over) => ({ confidence: conf, state: "affected", kev: true, rating: { band: "Critical" }, priority: { decision: "act" }, overdue: over });
  const s = summarize(hosts, [f("high", true), f("medium", false), f("low", true), f("low", false)]);
  assert.equal(s.findings, 4);
  assert.equal(s.low_confidence, 2);                 // the two low-confidence rows are counted as such
  assert.equal(s.known_exploited, 2);                // but excluded from the headline KEV / Critical / Act / overdue counts
  assert.equal(s.critical, 2);
  assert.equal(s.act, 2);
  assert.equal(s.overdue, 1);                        // only the high-confidence overdue row, not the low one
  assert.equal(s.version_confirmed, 4);              // version_confirmed stays a plain state count (all four are "affected")
  assert.match(summaryText({ summary: s, coverage: null, findings: [], hosts: [], notes: [], run: {} }), /2 low-confidence, listed but not in the counts below/);
});

test("probePort: plain HTTP on a TLS-by-convention port falls back to plain, and --http-ports overrides TLS (#82 item 4)", async () => {
  const s = await startServers();
  try {
    // a PLAIN HTTP server, but we force TLS on its port -> the handshake fails -> fall back to plain and read it
    const a = await probePort("127.0.0.1", s.ports.http, { httpsPorts: [s.ports.http] });
    assert.equal(a.state, "open");
    assert.equal(a.tls_failed, true);
    assert.ok(a.http && a.http.status, "read the plain HTTP response after the TLS fallback");
    // --http-ports forces plain from the start (even though it is also in the forced-TLS list): no TLS attempt
    const b = await probePort("127.0.0.1", s.ports.http, { httpPorts: [s.ports.http], httpsPorts: [s.ports.http] });
    assert.equal(b.state, "open");
    assert.ok(!b.tls_failed, "plain from the start, no fallback");
    assert.ok(b.http && b.http.status);
  } finally { await s.close(); }
});

/* ---- tk-hygiene: TLS and certificate hygiene from the handshake already made (no extra connection) ---- */
import { certAlgorithms, tlsInfo, nameMatches, certNames, TLS_RULES } from "../../scanner/lib/fingerprint.mjs";
import { startTlsServer } from "../fixtures/scanner/servers.mjs";
import { fixtureCerts } from "../fixtures/scanner/certgen.mjs";
import { X509Certificate } from "node:crypto";
const derOf = (which) => new X509Certificate(fixtureCerts()[which].cert).raw;

test("certAlgorithms reads the signature and public-key algorithm from the certificate's DER", () => {
  assert.deepEqual(certAlgorithms(derOf("weak")), { sig_alg: "sha1WithRSAEncryption", sig_hash: "SHA-1", key_type: "RSA" });
  assert.deepEqual(certAlgorithms(derOf("good")), { sig_alg: "ecdsa-with-SHA256", sig_hash: "SHA-256", key_type: "EC" });
  // garbage, truncation and absurd lengths never throw
  for (const bad of [null, Buffer.alloc(0), Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff]), derOf("weak").subarray(0, 40)]) assert.equal(typeof certAlgorithms(bad).sig_alg, "string");
});

test("TLS observations: expiry window, not-yet-valid, weak key and signature, name mismatch", () => {
  const now = Date.parse("2026-11-22T00:00:00Z");
  const base = { subject: { CN: "a.example.lan" }, issuer: { CN: "Example CA" }, valid_from: "Jan 1 00:00:00 2026 GMT", subjectaltname: "DNS:a.example.lan, DNS:*.apps.example.lan" };
  const kinds = (c, o = {}) => observations(443, { cert: c, now, ...o }).map((x) => x.kind);
  assert.deepEqual(kinds({ ...base, valid_to: "Dec 10 00:00:00 2026 GMT", bits: 2048, raw: derOf("good") }), ["tls-expiring"]);
  assert.deepEqual(kinds({ ...base, valid_to: "Dec 10 00:00:00 2027 GMT", bits: 2048 }), []);
  assert.deepEqual(kinds({ ...base, valid_from: "Dec 1 00:00:00 2026 GMT", valid_to: "Dec 1 00:00:00 2027 GMT" }), ["tls-not-yet-valid"]);
  assert.deepEqual(kinds({ ...base, valid_to: "Dec 1 00:00:00 2030 GMT", bits: 1024, raw: derOf("weak") }), ["tls-weak-key", "tls-weak-signature"]);
  // a P-256 key is not "weak" just because its bit count is under the RSA minimum
  assert.deepEqual(kinds({ ...base, valid_to: "Dec 1 00:00:00 2030 GMT", bits: 256, curve: "P-256", raw: derOf("good") }), []);
  // names: only when the scan used a name; wildcard covers one label; an IP literal is never compared
  const c = { ...base, valid_to: "Dec 1 00:00:00 2030 GMT", bits: 2048 };
  assert.deepEqual(kinds(c, { names: [] }), []);
  assert.deepEqual(kinds(c, { names: ["a.example.lan"] }), []);
  assert.deepEqual(kinds(c, { names: ["x.apps.example.lan"] }), []);
  assert.deepEqual(kinds(c, { names: ["y.x.apps.example.lan"] }), ["tls-name-mismatch"]);
  assert.deepEqual(kinds(c, { names: ["b.example.lan"] }), ["tls-name-mismatch"]);
  assert.deepEqual(kinds(c, { names: ["10.0.0.5"] }), []);
  assert.ok(nameMatches(certNames({ subject: "CN=only-cn.lan", san: "" }), "only-cn.lan"));
  for (const o of observations(443, { cert: { ...base, valid_to: "Dec 1 00:00:00 2030 GMT", bits: 1024, raw: derOf("weak") }, now })) assert.ok(["high", "medium", "low", "info"].includes(o.severity));
});

test("TLS observations: retired protocol, weak cipher, weak DH, no forward secrecy; an unreported group is not read as anything", () => {
  const kinds = (t) => observations(443, { tls: t }).map((x) => x.kind);
  assert.deepEqual(kinds({ protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", cipher_std: "TLS_AES_256_GCM_SHA384", kex: { type: "ECDH", name: "X25519", size: 253 } }), []);
  assert.deepEqual(kinds({ protocol: "TLSv1", cipher: "ECDHE-RSA-AES128-SHA", cipher_std: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" }), ["tls-old-protocol"]);
  assert.deepEqual(kinds({ protocol: "TLSv1.2", cipher: "DES-CBC3-SHA", cipher_std: "TLS_RSA_WITH_3DES_EDE_CBC_SHA" }), ["tls-weak-cipher", "tls-no-forward-secrecy"]);
  assert.deepEqual(kinds({ protocol: "TLSv1.2", cipher: "RC4-MD5", cipher_std: "TLS_RSA_WITH_RC4_128_MD5" }), ["tls-weak-cipher", "tls-no-forward-secrecy"]);
  assert.deepEqual(kinds({ protocol: "TLSv1.2", cipher: "ECDHE-RSA-AES256-GCM-SHA384", cipher_std: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" }), []);
  assert.deepEqual(kinds({ protocol: "TLSv1.2", cipher: "DHE-RSA-AES128-SHA", cipher_std: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", kex: { type: "DH", size: 1024 } }), ["tls-weak-dh"]);
  const u = tlsInfo({ protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", kex: {} });
  assert.equal(u.pqc, false); assert.equal(u.kex_group, ""); assert.match(u.kex_note, /not reported/);
  assert.equal(tlsInfo({ protocol: "TLSv1.3", kex: { type: "ECDH", name: "X25519MLKEM768", size: 0 } }).pqc, true);
  assert.equal(tlsInfo({ protocol: "TLSv1.2", kex: {} }).kex_note, "");
  assert.ok(TLS_RULES.minRsaBits === 2048 && TLS_RULES.expiringDays === 30);
});

test("probePort on a loopback TLS service: hygiene comes from the one handshake (still one connection)", async () => {
  const s = await startTlsServer("weak");
  try {
    const r = await probePort("127.0.0.1", s.port, { httpsPorts: [s.port] });
    assert.equal(r.state, "open");
    assert.ok(r.tls && r.tls.protocol && r.tls.cert && Buffer.isBuffer(r.tls.cert.raw));
    assert.equal(r.tls.cert.bits, 1024);
    const kinds = observations(s.port, { cert: r.tls.cert, tls: r.tls, names: ["other.fixture.test"] }).map((x) => x.kind);
    for (const k of ["tls-weak-key", "tls-weak-signature", "tls-self-signed", "tls-name-mismatch"]) assert.ok(kinds.includes(k), `${k} in ${kinds}`);
    const info = certInfo(r.tls.cert);
    assert.equal(info.sig_hash, "SHA-1"); assert.equal(info.key_type, "RSA"); assert.match(info.fingerprint256, /^[0-9A-F:]{95}$/);
    assert.equal(s.connections(), 1, "the hygiene checks must not open another connection");
  } finally { await s.close(); }
  // a TLS 1.2 DHE server with a 1024-bit group
  const d = await startTlsServer("weak", { maxVersion: "TLSv1.2", ciphers: "DHE-RSA-AES128-SHA:@SECLEVEL=0", dhparam: "auto" });
  try {
    const r = await probePort("127.0.0.1", d.port, { httpsPorts: [d.port] });
    assert.equal(r.tls.kex.type, "DH");
    assert.ok(observations(d.port, { tls: r.tls }).some((o) => o.kind === "tls-weak-dh"));
    assert.equal(d.connections(), 1);
  } finally { await d.close(); }
});

test("summary text lists observations most severe first and the negotiated TLS", () => {
  const rep = { tool: {}, run: { settings: {}, network: { sends: {} }, data: {} }, scope: { refused: [] }, summary: summarize([], []), coverage: coverage([], {}), findings: [], named: [], notes: [],
    hosts: [{ address: "10.0.0.5", names: [], up: true, ports: [], services: [], tls: [{ port: 443, ...tlsInfo({ protocol: "TLSv1.3", cipher_std: "TLS_AES_128_GCM_SHA256", kex: {} }), cert: { key_type: "RSA", key_bits: 1024, sig_alg: "sha1WithRSAEncryption", valid_to: "2030-01-01" } }],
      observations: [{ port: 443, kind: "tls-self-signed", severity: "low", text: "The TLS certificate is self-signed" }, { port: 443, kind: "tls-weak-key", severity: "high", text: "The TLS certificate's RSA key is 1024 bits" }] }] };
  const txt = summaryText(rep);
  assert.ok(txt.indexOf("[high]") < txt.indexOf("[low]"));
  assert.match(txt, /key-exchange group not reported/);
});

/* ---- tk-hygiene PR 2: HTTP and mail hygiene from the one GET / and the greeting already read ---- */
import { httpObservations, mailObservations, HTTP_RULES } from "../../scanner/lib/fingerprint.mjs";
const page = (headers = {}, body = "<!doctype html><title>App</title><p>hi</p>", status = 200) => ({ status, headers: { "content-type": "text/html", ...headers }, body });
const GOOD = { "strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "permissions-policy": "camera=()" };
const hk = (res, o = {}) => httpObservations(443, res, { tls: true, now: Date.parse("2026-11-22T12:00:00Z"), ...o }).map((x) => x.kind);

test("HTTP hygiene: security headers, HSTS, CSP, Referrer-Policy", () => {
  assert.deepEqual(hk(page(GOOD)), []);
  const miss = httpObservations(443, page({}), { tls: true });
  assert.deepEqual(miss.map((x) => x.kind), ["http-missing-headers"]);
  assert.equal(miss[0].severity, "medium"); assert.match(miss[0].text, /Strict-Transport-Security.*Content-Security-Policy.*X-Content-Type-Options.*X-Frame-Options.*Referrer-Policy.*Permissions-Policy/);
  // plain HTTP: no HSTS demanded, but "no redirect to HTTPS" is noted
  const plain = httpObservations(80, page({ ...GOOD, "strict-transport-security": undefined }), { tls: false }).map((x) => x.kind);
  assert.deepEqual(plain, ["http-no-https"]);
  assert.deepEqual(hk(page({ ...GOOD, "strict-transport-security": "max-age=600" })), ["http-weak-hsts"]);
  assert.deepEqual(hk(page({ ...GOOD, "content-security-policy": "script-src 'self' 'unsafe-inline'; frame-ancestors 'self'" })), ["http-weak-csp"]);
  assert.deepEqual(hk(page({ ...GOOD, "referrer-policy": "unsafe-url" })), ["http-weak-referrer-policy"]);
  // a redirect or an error page is not judged on page headers
  assert.deepEqual(hk(page({}, "", 404)), []);
  assert.ok(HTTP_RULES.maxSkewSeconds === 300);
});

test("HTTP hygiene: cookies by name only, CORS, redirects recorded not followed", () => {
  const c = httpObservations(443, page({ ...GOOD, "set-cookie": ["sid=SECRETVALUE; Path=/", "pref=1; Secure; HttpOnly"] }), { tls: true });
  assert.deepEqual(c.map((x) => x.kind), ["http-cookie-not-secure", "http-cookie-not-httponly"]);
  assert.ok(c.every((x) => !x.text.includes("SECRETVALUE")), "cookie values are never copied");
  assert.match(c[0].text, /sid/);
  assert.deepEqual(hk(page({ ...GOOD, "access-control-allow-origin": "*" })), ["http-cors-wildcard"]);
  assert.deepEqual(hk({ status: 302, headers: { location: "http://intranet.example.lan/" } }, { inScope: (h) => h === "intranet.example.lan" }), ["http-downgrade-redirect"]);
  assert.deepEqual(hk({ status: 301, headers: { location: "https://login.other.example/" } }), ["http-redirect-out-of-scope"]);
  assert.deepEqual(hk({ status: 301, headers: { location: "/login" } }), []);
});

test("HTTP hygiene: default, setup, debug pages and directory listings name the marker, never copy the page", () => {
  assert.deepEqual(hk(page(GOOD, "<html><title>Welcome to nginx!</title>")), ["http-default-page"]);
  assert.deepEqual(hk(page(GOOD, "<html><title>Apache2 Ubuntu Default Page: It works</title>")), ["http-default-page"]);
  assert.deepEqual(hk(page(GOOD, "<html><title>WordPress &rsaquo; Setup Configuration File</title>")), ["http-setup-page"]);
  assert.deepEqual(hk(page(GOOD, "<html><title>Index of /</title>")), ["http-directory-listing"]);
  const dj = httpObservations(443, page(GOOD, "<html><title>Error</title>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file. SECRET_KEY = 'abc'"), { tls: true });
  assert.deepEqual(dj.map((x) => x.kind), ["http-debug-page"]);
  assert.match(dj[0].text, /Django debug page/); assert.ok(!dj[0].text.includes("SECRET_KEY"));
  assert.deepEqual(hk(page(GOOD, "<html><title>x</title>Traceback (most recent call last):\n  File")), ["http-debug-page"]);
  assert.deepEqual(hk(page({ ...GOOD, "x-debug-token": "abc123" })), ["http-debug-header"]);
  assert.deepEqual(hk(page(GOOD, "<html><title>x</title><script>//# sourceMappingURL=app.js.map</script>")), ["http-source-map"]);
});

test("HTTP hygiene: advertised methods, Alt-Svc, CDN front, clock skew, Server version disclosure", () => {
  assert.deepEqual(hk(page({ ...GOOD, allow: "GET, HEAD, TRACE" })), ["http-trace-allowed"]);
  assert.deepEqual(hk(page({ ...GOOD, dav: "1,2" })), ["http-webdav"]);
  assert.deepEqual(hk(page({ ...GOOD, "alt-svc": 'h3=":443"; ma=86400, h2=":443"' })), ["http-alt-svc"]);
  assert.deepEqual(hk(page({ ...GOOD, "cf-ray": "8a1b2c3d4e5f-AMS" })), ["http-cdn-front"]);
  assert.deepEqual(hk(page({ ...GOOD, date: "Sun, 22 Nov 2026 11:40:00 GMT" })), ["http-clock-skew"]);
  assert.deepEqual(hk(page({ ...GOOD, date: "Sun, 22 Nov 2026 12:02:00 GMT" })), []);
  assert.deepEqual(hk(page({ ...GOOD, server: "Apache/2.4.52 (Ubuntu)" })), ["http-server-patch-level"]);
  assert.deepEqual(hk(page({ ...GOOD, server: "nginx/1.22.1" })), ["http-server-version"]);
  assert.deepEqual(hk(page({ ...GOOD, server: "nginx" })), []);
  for (const o of httpObservations(443, page({ allow: "TRACE", "set-cookie": "a=1" }), { tls: true })) assert.ok(["high", "medium", "low", "info"].includes(o.severity));
});

test("mail hygiene: cleartext POP3, IMAP and SMTP submission greetings", () => {
  assert.deepEqual(mailObservations(110, "+OK Dovecot ready.").map((x) => x.kind), ["cleartext-mail"]);
  assert.deepEqual(mailObservations(143, "* OK [CAPABILITY IMAP4rev1] ready").map((x) => x.kind), ["cleartext-mail"]);
  assert.deepEqual(mailObservations(587, "220 mail.example.lan ESMTP Postfix").map((x) => x.kind), ["cleartext-submission"]);
  assert.deepEqual(mailObservations(993, "* OK ready", { tls: true }), []);
  assert.deepEqual(mailObservations(25, "220 mail ESMTP"), []);
});

test("probeAll end to end: HTTP hygiene comes from the one GET / (no extra request)", async () => {
  const s = await startServers();
  try {
    const t = [{ address: "127.0.0.1", names: [], kind: "loopback", public: false }];
    const r = await probeAll(t, { ports: [s.ports.http], httpPorts: [s.ports.http], settings: settings({}).settings, assumeUp: true });
    const kinds = r.hosts[0].observations.map((o) => o.kind);
    assert.ok(kinds.includes("http-no-https") && kinds.includes("http-missing-headers"), kinds.join(","));
    assert.deepEqual(s.got.http.map((x) => `${x.method} ${x.url}`), ["GET /"]);
  } finally { await s.close(); }
});

/* ---- tk-matchers, scan-html, tk-diff: offline match, HTML report, scan diff (no target contacted) ---- */
const NMAP_XML = `<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/>
<address addr="10.1.2.3" addrtype="ipv4"/>
<hostnames><hostname name="ssh.internal" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2p1" extrainfo="Ubuntu Linux"/></port>
<port protocol="tcp" portid="80"><state state="closed"/><service name="http" product="ignored"/></port>
</ports>
</host>
<host><status state="up"/>
<address addr="203.0.113.9" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/><service name="http" product="nginx" version="1.22.1"><cpe>cpe:/a:f5:nginx:1.22.1</cpe></service></port></ports>
</host>
</nmaprun>`;

test("inputs: CPE and purl parse, CycloneDX and SPDX prefer them, a list stays a list", () => {
  assert.equal(parseCpe("cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*").product, "openssh");
  assert.equal(parseCpe("cpe:/a:f5:nginx:1.22.1").version, "1.22.1");
  assert.equal(parseCpe("not-a-cpe"), null);
  assert.equal(parsePurl("pkg:generic/openbsd/openssh@9.2").name, "openssh");
  const cdx = readInventory(JSON.stringify({ bomFormat: "CycloneDX", components: [
    { name: "OpenSSH portable", version: "0", cpe: "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*" },
    { name: "nested-parent", components: [{ name: "nginx", version: "1.22.1", purl: "pkg:generic/f5/nginx@1.22.1" }] },
  ] }), { file: "app.cdx.json", format: "sbom" });
  assert.equal(cdx.format, "CycloneDX");
  assert.equal(cdx.hosts.length, 1);
  assert.equal(cdx.hosts[0].public, false);
  assert.equal(cdx.hosts[0].services[0].product, "openssh");
  assert.equal(cdx.hosts[0].services[0].version, "9.2");
  assert.equal(cdx.hosts[0].services[0].guessed, false);
  const exposed = readInventory("OpenSSH 9.2\n", { file: "sw.txt", format: "list", assumeExposed: true });
  assert.equal(exposed.hosts[0].public, true);
  assert.equal(exposed.hosts[0].services[0].product, "OpenSSH");
  const spdx = readInventory(JSON.stringify({ packages: [{ name: "nginx", versionInfo: "0", supplier: "Organization: F5", externalRefs: [{ referenceType: "cpe23Type", referenceLocator: "cpe:2.3:a:f5:nginx:1.22.1:*:*:*:*:*:*:*" }] }] }), { format: "sbom" });
  assert.equal(spdx.format, "SPDX");
  assert.equal(spdx.hosts[0].services[0].product, "nginx");
  assert.equal(spdx.hosts[0].services[0].version, "1.22.1");
  const capped = readInventory(JSON.stringify({ components: Array.from({ length: 10 }, (_, i) => ({ name: "widget-" + i, version: "1.0.0" })) }), { format: "sbom", limit: 3 });
  assert.equal(capped.hosts[0].services.length, 3);
});

test("inputs: nmap XML keeps open services, classifies public and private, and skips closed ports", () => {
  const n = readInventory(NMAP_XML, { format: "nmap" });
  assert.equal(n.format, "nmap");
  assert.equal(n.hosts.length, 2);
  const priv = n.hosts.find((h) => h.address === "10.1.2.3");
  assert.equal(priv.public, false);
  assert.equal(priv.kind, "private");
  assert.equal(priv.services.length, 1);
  assert.equal(priv.services[0].product, "OpenSSH");
  assert.equal(priv.services[0].version, "9.2");
  assert.equal(priv.services[0].distro, "Ubuntu");
  const pub = n.hosts.find((h) => h.address === "203.0.113.9");
  assert.equal(pub.public, true);
  assert.equal(pub.services[0].vendor, "f5");
  assert.equal(pub.services[0].product, "nginx");
});

test("match: findings from a local list, report.html included, the probe is never called", async () => {
  const d = tmp();
  writeFileSync(join(d, "sw.txt"), "OpenSSH 9.2\n");
  let probed = 0;
  const x = io({ probe: async () => { probed++; return { port: 22, state: "closed" }; }, udpProbe: async () => { probed++; } });
  assert.equal(await main(["match", "--list", join(d, "sw.txt"), "--data", SNAP, "--out", join(d, "out")], x), 0);
  assert.equal(probed, 0);
  assert.match(x.lines.out.join("\n"), /No target was contacted|Nothing was contacted/);
  const rep = JSON.parse(readFileSync(join(d, "out", "report.json"), "utf8"));
  assert.equal(rep.run.network.sends.match.startsWith("nothing"), true);
  assert.equal(rep.run.network.connections, 0);
  assert.ok(rep.findings.some((f) => f.cve === "CVE-2026-90101" && f.state === "affected"));
  const html = readFileSync(join(d, "out", "report.html"), "utf8");
  assert.match(html, /Distribution packages can backport a fix/);
  assert.equal(/<script\b/i.test(html), false);
  const nasty = toHtml({ summary: {}, findings: [{ rank: 1, cve: "CVE-2026-90101", title: "<b>x</b>", rating: { text: "n" }, confidence: "high", seen_on: [], fix: { details: "javascript:alert(1)" } }], hosts: [{ services: [{ distro: "Ubuntu" }] }], notes: [], coverage: { complete: true } });
  assert.match(nasty, /&lt;b&gt;x&lt;\/b&gt;/);
  assert.equal(nasty.includes("javascript:"), false);
  assert.match(nasty, /This report includes at least one distribution package build/);
  const big = io({ readFile: () => "x".repeat(MAX_BYTES + 1) });
  assert.equal(await main(["match", "--list", join(d, "sw.txt"), "--data", SNAP], big), 1);
});

test("diff: new, resolved, still open and a watch list, with no network", () => {
  const place = (cve, host, extra = {}) => ({ cve, title: cve, kev: !!extra.kev, priority: extra.act ? { decision: "act" } : null, seen_on: [{ host, port: 22, product: "OpenSSH", shown_version: extra.version || "9.2", state: extra.state || "affected", confidence: "high" }] });
  const before = { run: { started_at: "2026-11-01T00:00:00Z" }, findings: [place("CVE-2026-90101", "10.0.0.5"), place("CVE-2026-90102", "10.0.0.5", { version: "1.22.1" })] };
  const after = { run: { started_at: "2026-11-22T00:00:00Z" }, findings: [place("CVE-2026-90101", "10.0.0.5"), place("CVE-2026-90999", "10.0.0.8", { kev: true, act: true })] };
  const d = diffReports(before, after);
  assert.deepEqual(d.new.map((x) => x.cve), ["CVE-2026-90999"]);
  assert.deepEqual(d.resolved.map((x) => x.cve), ["CVE-2026-90102"]);
  assert.deepEqual(d.still.map((x) => x.cve), ["CVE-2026-90101"]);
  assert.equal(d.watch.length, 1);
  assert.match(d.note, /not proof/);
});

test("diff command writes diff.json and contacts nothing", async () => {
  const d = tmp();
  const rep = (cve, host) => JSON.stringify({ run: { started_at: "2026-11-22T00:00:00Z" }, findings: [{ cve, title: "t", kev: true, priority: { decision: "act" }, seen_on: [{ host, port: 22, product: "OpenSSH", shown_version: "9.2", state: "affected" }] }] });
  writeFileSync(join(d, "a.json"), rep("CVE-2026-90101", "10.0.0.5"));
  writeFileSync(join(d, "b.json"), rep("CVE-2026-90102", "10.0.0.6"));
  let probed = 0;
  const x = io({ probe: async () => { probed++; } });
  assert.equal(await main(["diff", "--before", join(d, "a.json"), "--after", join(d, "b.json"), "--out", join(d, "out")], x), 0);
  assert.equal(probed, 0);
  const diff = JSON.parse(readFileSync(join(d, "out", "diff.json"), "utf8"));
  assert.equal(diff.counts.new, 1);
  assert.equal(diff.counts.resolved, 1);
  assert.match(readFileSync(join(d, "out", "diff.html"), "utf8"), /Resolved is not proof of a patch/);
  assert.match(readFileSync(join(d, "out", "diff.txt"), "utf8"), /WATCH/);
});

/* ---- sprint 1: path rail, CMS/JS on the root page, citations, hunt links, SSH KEXINIT ---- */
function listenHttp(handler) {
  const srv = http.createServer(handler);
  return new Promise((resolve) => srv.listen(0, "127.0.0.1", () => resolve({ port: srv.address().port, close: () => new Promise((r) => srv.close(() => r())) })));
}
function nameList(names) {
  const s = Buffer.from(names.join(","));
  const b = Buffer.alloc(4 + s.length);
  b.writeUInt32BE(s.length, 0); s.copy(b, 4); return b;
}
function kexPacket(kex, hostKey, cipher, mac) {
  const body = Buffer.concat([Buffer.from([20]), Buffer.alloc(16), nameList(kex), nameList(hostKey), nameList(cipher), nameList(cipher), nameList(mac), nameList(mac), nameList(["none"]), nameList(["none"]), nameList([]), nameList([]), Buffer.from([0, 0, 0, 0, 0])]);
  let pad = 8 - ((1 + body.length) % 8); if (pad < 4) pad += 8;
  const packetLen = 1 + body.length + pad;
  const out = Buffer.alloc(4 + packetLen);
  out.writeUInt32BE(packetLen, 0); out[4] = pad; body.copy(out, 5);
  return out;
}

test("CMS and JS versions come from the root page only", () => {
  const body = `<html><meta name="generator" content="WordPress 6.4.2"><script src="/wp-content/plugins/akismet/akismet.js?ver=5.3.1"></script><script src="/js/jquery-3.4.1.min.js"></script></html>`;
  const rows = fromHttp({ headers: {}, body });
  const wp = rows.find((s) => s.product === "WordPress");
  const plug = rows.find((s) => s.product === "akismet");
  const jq = rows.find((s) => s.product === "jquery");
  assert.equal(wp.version, "6.4.2"); assert.equal(wp.guessed, false);
  assert.equal(plug.version, "5.3.1"); assert.match(plug.evidence, /root page/);
  assert.equal(jq.version, "3.4.1"); assert.equal(jq.guessed, false);
  const bare = fromHttp({ headers: {}, body: `<meta name="generator" content="WordPress">` });
  assert.equal(bare[0].guessed, true); assert.equal(bare[0].version, "");
  const craft = fromHttp({ headers: { "x-powered-by": "Craft CMS" }, body: "" });
  assert.equal(craft[0].product, "Craft CMS"); assert.equal(craft[0].guessed, true);
});

test("path rail is hint-gated and capped, and an off-rail path is not connected", () => {
  const nginx = selectPaths({ headers: { server: "nginx/1.24.0" }, body: "" });
  assert.deepEqual(nginx.map((p) => p.path), ["/nginx_status", "/stub_status"]);
  assert.deepEqual(selectPaths({ headers: { server: "intranet" }, body: "<title>x</title>" }), []);
  const all = selectPaths({ headers: { server: "nginx", "x-application-context": "app" }, body: "" }, { wellKnown: true });
  // server "nginx" is not apache; spring header plus nginx plus well-known
  assert.equal(all.length <= PATH_CAP, true);
  const both = selectPaths({ headers: { server: "Apache/2.4.58 nginx", "x-application-context": "app" } }, { wellKnown: true });
  assert.equal(both.length, PATH_CAP);
  assert.equal(both.some((p) => p.path === "/.svn/entries"), false);
});

test("path rail on loopback requests only the hinted paths", async () => {
  const seen = { nginx: [], plain: [] };
  const nginx = await listenHttp((req, res) => { seen.nginx.push(req.url); res.writeHead(200, { Server: "nginx", "Content-Type": "text/plain" }); res.end("ok"); });
  const plain = await listenHttp((req, res) => { seen.plain.push(req.url); res.writeHead(200, { Server: "intranet", "Content-Type": "text/plain" }); res.end("ok"); });
  try {
    const st = settings({}).settings;
    const host = (port) => [{ address: "127.0.0.1", names: [], kind: "loopback", public: false }];
    await probeAll(host(), { ports: [nginx.port], httpPorts: [nginx.port], settings: st, assumeUp: true, paths: true });
    await probeAll(host(), { ports: [plain.port], httpPorts: [plain.port], settings: st, assumeUp: true, paths: true });
    assert.deepEqual(seen.nginx, ["/", "/nginx_status", "/stub_status"]);
    assert.deepEqual(seen.plain, ["/"]);
    const before = seen.plain.length;
    const skipped = await probeHttpPath("127.0.0.1", plain.port, "/not-on-the-rail");
    assert.equal(skipped.state, "skipped");
    assert.equal(seen.plain.length, before);
  } finally { await nginx.close(); await plain.close(); }
});

test("SSH KEXINIT is read on the same connection and only the identification line is sent", async () => {
  const weak = kexPacket(["diffie-hellman-group14-sha1", "mlkem768x25519-sha256"], ["ssh-ed25519"], ["aes128-cbc", "aes128-gcm@openssh.com"], ["hmac-sha1"]);
  const got = [];
  const srv = net.createServer((s) => {
    s.on("data", (d) => got.push(d.toString("latin1")));
    s.write("SSH-2.0-OpenSSH_9.9\r\n");
    s.once("data", () => s.write(weak));
  });
  const port = await new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
  try {
    const r = await probePort("127.0.0.1", port);
    assert.equal(r.state, "open");
    assert.match(r.banner, /OpenSSH_9.9/);
    const parsed = parseKexinit(r.kexRaw);
    assert.ok(parsed.kex.includes("mlkem768x25519-sha256"));
    const kinds = sshKexObservations(port, parsed).map((o) => o.kind);
    assert.ok(kinds.includes("ssh-weak-kex") && kinds.includes("ssh-weak-cipher") && kinds.includes("ssh-weak-mac") && kinds.includes("ssh-pqc-kex"));
    assert.deepEqual(got, [SSH_IDENT + "\r\n"]);
  } finally { srv.close(); }
  const quiet = net.createServer((s) => { s.write("SSH-2.0-OpenSSH_9.9\r\n"); s.end(); });
  const p2 = await new Promise((r) => quiet.listen(0, "127.0.0.1", () => r(quiet.address().port)));
  try {
    const r = await probePort("127.0.0.1", p2);
    assert.equal(r.kexRaw, undefined);
    assert.equal(parseKexinit(Buffer.alloc(0)), null);
    assert.equal(parseKexinit(Buffer.from("not a packet")), null);
  } finally { quiet.close(); }
});

test("incident citations keep every corroborated event and omit claimed ones", () => {
  const index = { events: [
    { id: "a", cves: ["CVE-2026-90101"], status: "confirmed", review: { state: "passed" }, title: "Official notice", url: "https://example.gov/a", attribution: "CISA" },
    { id: "b", cves: ["CVE-2026-90101"], status: "official", review: "corrected", title: "Second notice", url: "https://example.gov/b", attribution: "the investigating firm" },
    { id: "c", cves: ["CVE-2026-90101"], status: "claimed", review: "passed", title: "A claim", url: "https://example.com/claim" },
  ] };
  const c = citationsFor(index, "CVE-2026-90101");
  assert.deepEqual(c.kept.map((x) => x.id), ["a", "b"]);
  assert.equal(c.claimed_omitted, 1);
  assert.equal(c.kept.some((x) => /claim/i.test(x.url)), false);
  const text = summaryText({ summary: { hosts_in_scope: 1, hosts_up: 1, open_ports: 1, services_identified: 1, findings: 1, version_confirmed: 1, low_confidence: 0, known_exploited: 1, critical: 0, act: 0, overdue: 0, observations: 0 }, coverage: { complete: true }, run: {}, hosts: [], notes: [], hunt: [],
    findings: [{ rank: 1, cve: "CVE-2026-90101", title: "t", seen_on: [{ host: "10.0.0.5", port: 22, product: "OpenSSH", shown_version: "9.2", confidence: "high" }], kev: true, kev_added: "2026-10-20", cisa_due: "", overdue: false, priority: { label: "Act", fix_by: null }, rating: { text: "8.1 High" }, points: { total: 1, list: [{ points: 1, why: "x" }] }, confidence: "high", confidence_why: "stated", fix: { fixed_in: [], vendor_fixed: [], cisa_required_action: "", advisory: null, details: "https://example.gov/cve" }, citations: c.kept, claimed_omitted: c.claimed_omitted }] });
  assert.match(text, /https:\/\/example.gov\/a/);
  assert.match(text, /https:\/\/example.gov\/b/);
  assert.match(text, /claimed event/);
  assert.equal(text.includes("example.com/claim"), false);
});

test("hunt links are publisher URLs and a rule body is not copied", () => {
  const wb = { guides: { "CVE-2026-90101": { hunt: [
    { name: "Vendor rule", format: "sigma", url: "https://vendor.example/rule", publisher: "Vendor" },
    { name: "with a body", format: "sigma", url: "https://vendor.example/body", publisher: "Vendor", body: "detection: {}" },
  ] } }, hunt: [] };
  const links = huntLinks(wb, ["CVE-2026-90101"]);
  assert.deepEqual(links.map((h) => h.url), ["https://vendor.example/rule"]);
  assert.equal(JSON.stringify(links).includes("detection"), false);
  const text = summaryText({ summary: { hosts_in_scope: 0, hosts_up: 0, findings: 0, version_confirmed: 0, low_confidence: 0, known_exploited: 0, critical: 0, act: 0, overdue: 0, observations: 0, open_ports: 0, services_identified: 0 }, coverage: { complete: true }, run: {}, hosts: [], notes: [], findings: [], hunt: links });
  assert.match(text, /publisher links only/);
  assert.match(text, /https:\/\/vendor.example\/rule/);
});
