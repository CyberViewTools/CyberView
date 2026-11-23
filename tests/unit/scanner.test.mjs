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
import { toCsv, toSarif, toInventory, CSV_HEAD, coverage, isTruncatedBanner, summaryText, summarize } from "../../scanner/lib/report.mjs";
import { USER_AGENT, SSH_IDENT, probePort } from "../../scanner/lib/probe.mjs";
import { dnsVersionQuery, parseDnsVersion, ntpReadVarQuery, parseNtpReadVar, snmpGetSysDescr, parseSnmpSysDescr, SNMP_COMMUNITY, UDP_SERVICES } from "../../scanner/lib/udp-codec.mjs";
import { udpProbe } from "../../scanner/lib/udp.mjs";
import { parseAssetFile, parseCloud, parseCtJson, ctSubdomains, runDiscovery } from "../../scanner/lib/discover.mjs";
import { parseCpe, parsePurl, mergeName, parseNmapXml, inventoryHost, INPUT_LIMITS } from "../../scanner/lib/inputs.mjs";
import { sbomIdentity, parseSbom } from "../../scanner/lib/imports.mjs";
import { cveId, versionVerdict, detectionFor } from "../../scanner/lib/lookup.mjs";
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
  // dgram appears only in udp.mjs across the scanner (and the opt-in identify hellos, hello.mjs, under their own section-7 rules)
  for (const f of walkFiles(new URL("../../scanner/", import.meta.url).pathname)) {
    if (f.endsWith("udp.mjs") || f.endsWith("hello.mjs")) continue;
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

/* ---- inputs.mjs: the operator's own files (nmap -oX, CPE/purl, an inventory with no address) ---- */

test("CPE 2.2 and 2.3 give the vendor, product and version NVD's ranges use", () => {
  assert.deepEqual(parseCpe("cpe:/a:openbsd:openssh:8.2p1"), { kind: "a", vendor: "openbsd", product: "openssh", version: "8.2p1" });
  assert.deepEqual(parseCpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"), { kind: "a", vendor: "apache", product: "http server", version: "2.4.49" });
  assert.equal(parseCpe("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*").version, "");   // * and - are "any", not a version
  assert.equal(parseCpe("cpe:/o:microsoft:windows_server_2019").kind, "o");
  for (const bad of ["", "not a cpe", "cpe:2.3:a:vendor", "cpe:/a:vendor:", null, 42]) assert.equal(parseCpe(bad), null);
});

test("purl gives the namespace as the vendor and the name as the product", () => {
  assert.deepEqual(parsePurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"), { type: "maven", vendor: "org.apache.logging.log4j", product: "log4j-core", version: "2.14.1" });
  assert.deepEqual(parsePurl("pkg:npm/%40scope/pkg@1.2.3"), { type: "npm", vendor: "scope", product: "pkg", version: "1.2.3" });
  assert.equal(parsePurl("pkg:npm/lodash@4.17.21?arch=x64#sub").version, "4.17.21");   // qualifiers and subpath are not the version
  assert.equal(parsePurl("pkg:deb/debian/curl").version, "");
  for (const bad of ["", "log4j-core@2.14.1", "pkg:npm/", null]) assert.equal(parsePurl(bad), null);
});

test("the matched name keeps nmap's product and adds CPE words it is missing", () => {
  assert.equal(mergeName("Apache httpd", "http server"), "Apache httpd http server");   // "http server" ranges match too
  assert.equal(mergeName("OpenSSH", "openssh"), "OpenSSH");                              // same word: nothing appended
  assert.equal(mergeName("", "fortios"), "fortios");
  assert.equal(mergeName("nginx", ""), "nginx");
});

test("nmap -oX: open ports with a service line become service records, down hosts and closed ports do not", () => {
  const r = parseNmapXml(readFileSync(join(FIX, "nmap.xml"), "utf8"));
  assert.deepEqual(r.stats, { hosts: 2, services: 4, skipped_down: 1 });
  assert.match(r.problems.join(" "), /1 host\(s\) nmap reported as down were skipped/);
  const [priv, pub] = r.hosts;
  assert.equal(priv.address, "10.0.0.4");
  assert.deepEqual(priv.names, ["web01.corp.example"]);
  assert.equal(priv.public, false);                        // RFC 1918: rated as internal
  assert.deepEqual(priv.ports.map((p) => p.port), [22, 80, 8080]);   // 443 closed and 3389 filtered are not open ports
  assert.deepEqual(priv.ports.map((p) => p.state), ["open", "open", "open"]);   // the shape scan.mjs builds, so report.mjs counts them
  assert.deepEqual(priv.services.map((s) => s.port), [22, 80]);   // 8080 is open but nmap named the port only
  assert.equal(pub.public, true);                           // 203.0.113.10 is a public address
  const ssh = priv.services[0];
  assert.equal(ssh.version, "8.2");                         // compared with the ranges
  assert.equal(ssh.shown_version, "8.2p1");                 // shown to the operator
  assert.equal(ssh.distro, "Ubuntu");                       // "8.2p1 Ubuntu 4ubuntu0.5": a distribution build
  assert.equal(ssh.vendor, "openbsd");
  assert.equal(ssh.guessed, false);
  assert.match(ssh.source, /nmap -oX/);
  const udp = pub.services.find((s) => s.proto === "udp");
  assert.equal(udp.port, 161);                              // open|filtered UDP with a probed service line counts
  assert.equal(pub.services[0].guessed, true);              // FortiGate with no version: inferred, so never high confidence
});

test("nmap -oX: crafted input is bounded and refused safely", () => {
  assert.deepEqual(parseNmapXml("").hosts, []);
  assert.match(parseNmapXml("hello").problems[0], /not nmap -oX XML/);
  assert.match(parseNmapXml("<nmaprun></nmaprun>").problems[0], /no host with an open port/);
  assert.match(parseNmapXml('<host><status state="up"/><address addr="not-an-ip" addrtype="ipv4"/></host>').problems[0], /no usable IP address/);
  // entities are unescaped and control characters stripped; nothing is executed or interpreted
  const ent = parseNmapXml('<host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Acme &amp; Co &lt;Web&gt;" version="1.0" method="probed" conf="10"/></port></ports></host>');
  assert.equal(ent.hosts[0].services[0].label, "Acme & Co <Web>");
  const many = `<nmaprun>${'<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host>'.repeat(INPUT_LIMITS.hosts + 5)}</nmaprun>`;
  const capped = parseNmapXml(many);
  assert.equal(capped.hosts.length, INPUT_LIMITS.hosts);
  assert.match(capped.problems.join(" "), /over the caps/);
});

test("an inventory with no address becomes one pseudo-host, rated internal unless the operator says otherwise", () => {
  const items = [{ name: "log4j-core", version: "2.14.1", from: "sbom" }, { name: "nginx", from: "packages" }, { name: "", version: "1" }];
  const h = inventoryHost(items, { file: "app.cdx.json" });
  assert.equal(h.address, "app.cdx.json");
  assert.equal(h.public, false);
  assert.match(h.source, /--assume-exposed/);               // the default is stated, not silent
  assert.equal(h.services.length, 2);                       // the nameless row is dropped
  assert.equal(h.services[0].port, null);                   // nothing was contacted, so there is no port
  assert.equal(h.services[1].guessed, true);                // no version stated
  const ex = inventoryHost(items, { file: "app.cdx.json", assumeExposed: true });
  assert.equal(ex.public, true);
  assert.equal(ex.kind, "public");
  assert.match(ex.source, /operator states it is internet-facing/);
});

test("nmap hosts go through findings() unchanged, with the backport caveat and no high confidence without a version", () => {
  const flaws = cleanFlaws(wb), rows = new Map();
  for (const a of rowsFile.rows) { const r = SD.cleanRow(rowsFile.fields, a); rows.set(r.id, r); }
  const { hosts } = parseNmapXml(readFileSync(join(FIX, "nmap.xml"), "utf8"));
  const f = findings(hosts, flaws, rows, { today: TODAY });
  const ssh = f.find((x) => x.cve === "CVE-2026-90101");
  assert.equal(ssh.state, "affected");                      // OpenSSH 8.2 is below 9.8
  assert.equal(ssh.confidence, "medium");                   // Ubuntu package build: the fix may be backported
  assert.match(ssh.confidence_why, /backported/);
  assert.equal(ssh.seen_on[0].host, "10.0.0.4");
  assert.equal(ssh.priority.exposure, "private address");   // nmap gave a real address, so exposure is not assumed
  const forti = f.find((x) => x.cve === "CVE-2026-90105");
  assert.equal(forti.state, "check");                       // FortiGate stated no version
  assert.equal(forti.confidence, "low");
  // the same inventory with no address is rated as internet-facing only when the operator says so
  const inv = findings([inventoryHost([{ name: "OpenSSH", vendor: "OpenBSD", version: "8.2p1", from: "sbom" }], { file: "sbom.json", assumeExposed: true })], flaws, rows, { today: TODAY });
  assert.equal(inv.find((x) => x.cve === "CVE-2026-90101").priority.exposure, "public address");
});

/* ---- the match command: a report from files the operator already holds, with nothing contacted ---- */

const CDX = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", metadata: { component: { name: "payments-api", version: "3.1.0", "bom-ref": "root" } },
  components: [{ "bom-ref": "c1", name: "OpenSSH", version: "8.2p1", purl: "pkg:generic/openbsd/openssh@8.2p1" },
    { "bom-ref": "c2", name: "nginx", version: "1.22.1", purl: "pkg:generic/f5/nginx@1.22.1" }],
  dependencies: [{ ref: "root", dependsOn: ["c1", "c2"] }] });

test("an SBOM's purl and CPE give the vendor the matcher needs, which parseInventory alone does not carry", () => {
  const id = sbomIdentity(JSON.parse(CDX));
  assert.equal(id.get("openssh").vendor, "openbsd");
  assert.equal(id.get("nginx").vendor, "f5");
  const spdx = sbomIdentity({ packages: [{ SPDXID: "p1", name: "log4j-core", versionInfo: "2.14.1", externalRefs: [{ referenceType: "purl", referenceLocator: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }] },
    { SPDXID: "p2", name: "httpd", externalRefs: [{ referenceType: "cpe23Type", referenceLocator: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" }] },
    { SPDXID: "p3", name: "thing", supplier: "Organization: Example Ltd" }] });
  assert.equal(spdx.get("log4j-core").vendor, "org.apache.logging.log4j");
  assert.equal(spdx.get("httpd").vendor, "apache");
  assert.equal(spdx.get("httpd").alias, "http server");     // the CPE product name is matched as well as the SBOM's
  assert.equal(spdx.get("thing").vendor, "Example Ltd");    // no purl or cpe: the stated supplier, prefix stripped
  // the vendor reaches the inventory items, so a range naming the vendor matches
  const parsed = parseSbom(CDX);
  assert.equal(parsed.items.find((x) => /openssh/i.test(x.name)).vendor, "openbsd");
});

test("match refuses without a local snapshot or an input, and never goes online", async () => {
  const d = tmp();
  const a = io(); assert.equal(await main(["match", "--nmap", join(FIX, "nmap.xml")], a), 1);
  assert.match(a.lines.err.join("\n"), /--data DIR is required/);
  const b = io(); assert.equal(await main(["match", "--data", SNAP], b), 1);
  assert.match(b.lines.err.join("\n"), /give --nmap scan\.xml .* or an inventory/);
  const c = io(); assert.equal(await main(["match", "--data", SNAP, "--online", "--nmap", join(FIX, "nmap.xml")], c), 1);
  assert.match(c.lines.err.join("\n"), /works offline only/);
  const e = io(); assert.equal(await main(["match", "--data", SNAP, "--nmap", join(d, "missing.xml")], e), 1);
  assert.match(e.lines.err.join("\n"), /cannot read/);
  const g = join(d, "junk.xml"); writeFileSync(g, "<html>not nmap</html>");
  const h = io(); assert.equal(await main(["match", "--data", SNAP, "--nmap", g], h), 1);
  assert.match(h.lines.err.join("\n"), /not nmap -oX XML/);
});

test("match writes the five report files from an nmap file, and the report says nothing was contacted", async () => {
  const d = tmp(), x = io();
  assert.equal(await main(["match", "--data", SNAP, "--nmap", join(FIX, "nmap.xml"), "--out", d], x), 0);
  assert.deepEqual(readdirSync(d).sort(), ["findings.csv", "inventory.csv", "report.json", "report.sarif", "summary.txt"]);
  const r = JSON.parse(readFileSync(join(d, "report.json"), "utf8"));
  assert.equal(r.tool.command, "match");
  assert.equal(r.run.network.sent, 0);
  assert.match(r.run.network.note, /^none:/);
  assert.deepEqual(r.run.network.sends, {});                 // no send is listed, because none was made
  assert.equal(r.coverage.from, "files");
  assert.equal(r.coverage.complete, false);                  // a file list is never full coverage
  assert.equal(r.match.has_inventory, false);
  assert.match(r.notes[0], /Nothing was contacted/);
  assert.equal(r.scope.attestation, null);                   // no host is contacted, so no attestation is required
  const ssh = r.findings.find((f) => f.cve === "CVE-2026-90101");
  assert.equal(ssh.confidence, "medium");
  assert.equal(ssh.priority.exposure, "private address");
  const out = x.lines.out.join("\n");
  assert.match(out, /Nothing was sent to any host/);
  assert.match(out, /COVERAGE — nothing was contacted/);
  assert.doesNotMatch(out, /Exposure was not stated/);        // no address-less input in this run
  assert.doesNotMatch(out, /:null/);                          // every finding here has a real port
  // SARIF stays valid: a real socket location for a scanned port
  const s = JSON.parse(readFileSync(join(d, "report.sarif"), "utf8"));
  assert.equal(s.version, "2.1.0");
  assert.match(s.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, /^tcp:\/\/10\.0\.0\.4:22$/);
});

test("an SBOM with no address is rated internal, and --assume-exposed only moves CISA's deadline", async () => {
  const d = tmp(), f = join(d, "app.cdx.json"); writeFileSync(f, CDX);
  const a = io(), outA = tmp();
  assert.equal(await main(["match", "--data", SNAP, "--sbom", f, "--out", outA], a), 0);
  const ra = JSON.parse(readFileSync(join(outA, "report.json"), "utf8"));
  assert.equal(ra.match.has_inventory, true);
  assert.equal(ra.match.assume_exposed, false);
  assert.equal(ra.hosts[0].public, false);
  assert.match(a.lines.out.join("\n"), /Exposure was not stated/);
  assert.doesNotMatch(a.lines.out.join("\n"), /:null/);       // an inventory finding has no port and must not print one
  const ssh = ra.findings.find((x) => x.cve === "CVE-2026-90101");
  assert.equal(ssh.confidence, "high");                       // the SBOM states the version outright
  assert.equal(ssh.priority.exposure, "private address");
  const b = io(), outB = tmp();
  assert.equal(await main(["match", "--data", SNAP, "--sbom", f, "--assume-exposed", "--out", outB], b), 0);
  const rb = JSON.parse(readFileSync(join(outB, "report.json"), "utf8"));
  const sshB = rb.findings.find((x) => x.cve === "CVE-2026-90101");
  assert.equal(sshB.priority.exposure, "public address");
  assert.equal(sshB.rating.score, ssh.rating.score);          // the CyberView rating does not depend on exposure
  // the SARIF location for an inventory finding is the file, not a socket
  const s = JSON.parse(readFileSync(join(outB, "report.sarif"), "utf8"));
  assert.match(s.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, /^file:\/\/\//);
  assert.equal(s.runs[0].results[0].locations[0].logicalLocations[0].kind, "resource");
});

/* ---- the lookup command: one CVE from a local snapshot, read-only ---- */

test("a CVE number is required, and only a CVE number is taken", () => {
  assert.equal(cveId("cve-2026-90101"), "CVE-2026-90101");
  assert.equal(cveId(" CVE-2026-1234 "), "CVE-2026-1234");
  for (const bad of ["", "2026-90101", "CVE-2026", "CVE-20260-90101", "../../etc/passwd", "CVE-2026-90101; rm -rf /", null, 7]) assert.equal(cveId(bad), "");
});

test("a version the operator holds is judged against the flaw's own ranges, with the backport caveat", () => {
  const flaws = cleanFlaws(wb);
  const ssh = flaws.find((f) => f.cve === "CVE-2026-90101");
  assert.equal(versionVerdict(ssh, "8.2p1").state, "affected");
  assert.deepEqual(versionVerdict(ssh, "8.2p1").fixed_in, ["9.8"]);
  assert.match(versionVerdict(ssh, "8.2p1").caveat, /backported/);
  assert.equal(versionVerdict(ssh, "9.9").state, "clear");            // compared and outside every range
  assert.match(versionVerdict(ssh, "9.9").says, /outside all of them/);
  assert.equal(versionVerdict(ssh, ""), null);
  const forti = flaws.find((f) => f.cve === "CVE-2026-90105");
  assert.equal(versionVerdict(forti, "7.2.0").state, "affected");    // 7.0.0 <= 7.2.0 < 7.4.9
  assert.equal(versionVerdict(forti, "7.6.1").state, "clear");        // 7.6.1 is past 7.4.9
  const named = flaws.find((f) => f.cve === "CVE-2026-90201");       // name-only, no range
  assert.equal(versionVerdict(named, "1.0").state, "check");
  assert.match(versionVerdict(named, "1.0").says, /no comparable range/);
});

test("lookup says whether this scanner could find the product at all, and never overstates it", () => {
  const flaws = cleanFlaws(wb);
  const ssh = detectionFor(flaws.find((f) => f.cve === "CVE-2026-90101"));
  assert.equal(ssh.can_name, true);
  assert.equal(ssh.reads_version, true);
  assert.match(ssh.how.join(" "), /OpenSSH \(SSH banner\)/);
  assert.match(ssh.what_it_means, /version-confirmed/);
  const php = detectionFor(flaws.find((f) => f.cve === "CVE-2026-90103"));   // PHP: no scanner fingerprint reads it by name alone
  assert.equal(typeof php.can_name, "boolean");
  if (!php.can_name) assert.match(php.what_it_means, /detection gap, not evidence the product is absent/);
});

test("lookup reads one CVE from the snapshot: the rating, both exposure deadlines, the ranges and the fix", async () => {
  const d = tmp(), x = io();
  assert.equal(await main(["lookup", "CVE-2026-90101", "--data", SNAP, "--version", "8.2p1", "--out", d], x), 0);
  assert.deepEqual(readdirSync(d).sort(), ["lookup.json", "lookup.txt"]);
  const r = JSON.parse(readFileSync(join(d, "lookup.json"), "utf8"));
  assert.equal(r.known, true);
  assert.equal(r.tool.command, "lookup");
  assert.match(r.network, /^none:/);
  assert.equal(r.flaw.known_exploited, true);
  assert.equal(r.rating.score, 8.1);
  assert.ok(r.priority.internet_facing && r.priority.internal);       // no inventory, so both answers are given
  assert.notEqual(r.priority.internet_facing.label, r.priority.internal.label);
  assert.deepEqual(r.affected, ["openbsd openssh before 9.8"]);
  assert.equal(r.your_version.state, "affected");
  assert.equal(r.detection.reads_version, true);
  // anything CyberView wrote is labelled, and the analysis is linked, never copied
  assert.equal(r.fix.analysis.by, "CyberView AI (a Claude model)");
  assert.equal(r.fix.guide_by, "CyberView AI (a Claude model)");
  assert.match(r.fix.details_note, /linked, never copied/);
  const text = readFileSync(join(d, "lookup.txt"), "utf8");
  assert.match(text, /CyberView rating: CVSS 8\.1/);
  assert.doesNotMatch(text, /= 8\.1 High = 8\.1 High/);               // the rating text already carries score and band
  assert.match(text, /Nothing was contacted/);
});

test("lookup says plainly when a CVE is not in the catalog, and refuses a bad call", async () => {
  const x = io();
  assert.equal(await main(["lookup", "CVE-2019-11111", "--data", SNAP], x), 0);
  const out = x.lines.out.join("\n");
  assert.match(out, /not in CyberView's catalog/);
  assert.match(out, /known-exploited flaws .* and recent high-risk flaws/);
  assert.doesNotMatch(out, /CyberView rating: CVSS/);                  // nothing is invented for a CVE it does not hold
  const a = io(); assert.equal(await main(["lookup", "--data", SNAP], a), 1);
  assert.match(a.lines.err.join("\n"), /give the CVE number/);
  const b = io(); assert.equal(await main(["lookup", "not-a-cve", "--data", SNAP], b), 1);
  assert.match(b.lines.err.join("\n"), /is not one/);
  const c = io(); assert.equal(await main(["lookup", "CVE-2026-90101"], c), 1);
  assert.match(c.lines.err.join("\n"), /--data DIR is required/);
  const e = io(); assert.equal(await main(["lookup", "CVE-2026-90101", "--data", SNAP, "--online"], e), 1);
  assert.match(e.lines.err.join("\n"), /works offline only/);
});
