// The downloadable scanner (scanner/): the authorization gate, the fingerprint parsers, matching and rating against the
// site's own code, the exporters, the politeness limits, and offline and online data. No real host is ever contacted:
// probes are stand-ins or stand-in services on 127.0.0.1 (tests/fixtures/scanner/servers.mjs).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import vm from "node:vm";
import { checkScope, gate, classify, parseTarget, listAddresses, template, STATEMENT, LIMITS } from "../../scanner/lib/scope.mjs";
import { settings, Limiter, CAPS } from "../../scanner/lib/limits.mjs";
import { fromSsh, fromGreeting, fromMysql, fromHttp, fromCert, certInfo, observations } from "../../scanner/lib/fingerprint.mjs";
import { cleanFlaws, findings, toItem } from "../../scanner/lib/match.mjs";
import { dirSource, webSource, ALLOWED, checkBase } from "../../scanner/lib/data.mjs";
import { parsePorts, resolveScope, probeAll, servicesOf } from "../../scanner/lib/scan.mjs";
import { toCsv, toSarif, toInventory, CSV_HEAD } from "../../scanner/lib/report.mjs";
import { USER_AGENT, SSH_IDENT, probePort } from "../../scanner/lib/probe.mjs";
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
  assert.equal(await main(["scan", "--scope", p, "--data", SNAP, "--i-am-authorized-for-public-ranges", "--out", join(d, "o")], z), 0);
  assert.equal(waited, 10000); assert.match(z.lines.err.join("\n"), /WARNING: this scan includes 1 PUBLIC address/);
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
    // what the services received from the scanner
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
