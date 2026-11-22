// The scanner's report pack (scan-cert-inventory, scan-mail-starttls, scan-kev-coverage, tk-diff): certificate inventory,
// mail STARTTLS from greetings already read, the KEV fingerprint coverage gap, and a diff against a previous report.json.
// All of it works on data the scan already holds or on local files: these tests prove no extra request is made (the stand-in
// probe sees the same calls with and without the new flags; the loopback TLS service sees one connection; the coverage
// command never probes or fetches). No real host is ever contacted.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { certDer, certRecord, certInventory, toCertsCsv, internalName, internalIp, CERTS_HEAD, CERT_RULES } from "../../scanner/lib/cert-inventory.mjs";
import { mailProtocol, starttlsFromGreeting, mailInventory, toMailCsv, STARTTLS } from "../../scanner/lib/mail-starttls.mjs";
import { kevCoverage, fingerprintProducts, INLINE, toCoverageCsv } from "../../scanner/lib/kev-coverage.mjs";
import { loadPrevious, diffReports, diffText, cleanReport } from "../../scanner/lib/diff.mjs";
import { fromSsh, fromMysql, fromHttp, fromUdp } from "../../scanner/lib/fingerprint.mjs";
import { probePort } from "../../scanner/lib/probe.mjs";
import { STATEMENT } from "../../scanner/lib/scope.mjs";
import { main } from "../../scanner/cyberview-scan.mjs";
import { startTlsServer } from "../fixtures/scanner/servers.mjs";
import { makeDer, newSpki, probeCert } from "../fixtures/scanner/reportpack/der.mjs";

const FIX = new URL("../fixtures/scanner/", import.meta.url).pathname, SNAP = join(FIX, "snapshot");
const BANNERS = JSON.parse(readFileSync(join(FIX, "banners.json"), "utf8"));
const tmp = () => mkdtempSync(join(tmpdir(), "cvpack-"));
const fp = (der) => createHash("sha256").update(der).digest("hex").toUpperCase().match(/../g).join(":");
const io = (extra = {}) => { const out = [], err = []; return { out: (s) => out.push(s), err: (s) => err.push(s), sleep: async () => {}, publicWaitMs: 0, lines: { out, err },
  fetchImpl: () => { throw new Error("no network in this test"); }, resolve: async () => { throw Object.assign(new Error("no DNS"), { code: "ENOTFOUND" }); }, ...extra }; };
const writeScope = (dir, targets) => { const p = join(dir, "scope.json"); writeFileSync(p, JSON.stringify({ cyberview_scope: 1, owner: "Example lab", contact: "lab@example.org",
  attestation: { statement: STATEMENT, agreed: true, name: "Test Operator", date: "2026-11-20", expires: "", authorization_ref: "test" }, targets, exclude: [] })); return p; };

/* ---- certificate inventory ---- */
test("certDer reads serial, key hash, SAN names and addresses, embedded SCTs and must-staple from the DER only", () => {
  const spki = newSpki();
  const der = makeDer({ serial: "01ab", spki, dns: ["www.example.org", "*.apps.example.org", "db01.corp"], ip: ["10.1.2.3", "fd00:0:0:0:0:0:0:1", "8.8.8.8"], sct: true, mustStaple: true });
  const d = certDer(der);
  assert.equal(d.serial, "01:AB");
  assert.equal(d.spki_sha256, fp(spki));
  assert.deepEqual(d.san_dns, ["www.example.org", "*.apps.example.org", "db01.corp"]);
  assert.deepEqual(d.san_ip, ["10.1.2.3", "fd00::1", "8.8.8.8"]);
  assert.equal(d.sct, true); assert.equal(d.must_staple, true);
  const plain = certDer(makeDer({ dns: ["a.example.org"] }));
  assert.equal(plain.sct, false); assert.equal(plain.must_staple, false);
  // unreadable input: unknown (null), never "no"
  for (const bad of [null, Buffer.from([1, 2, 3]), Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff]), "text"]) { const x = certDer(bad); assert.equal(x.sct, null); assert.equal(x.must_staple, null); assert.equal(x.serial, ""); }
});

test("certRecord keeps certInfo's fields and adds the identifiers; internal names and addresses", () => {
  const der = makeDer({ dns: ["a.example.org"] });
  const r = certRecord(probeCert(der, { fingerprint: fp(der), san: "DNS:a.example.org" }), Date.parse("2026-11-22"));
  assert.equal(r.fingerprint256, fp(der)); assert.equal(r.issuer, "CN=Fixture CA"); assert.equal(r.valid_to, "2027-01-01"); assert.ok(r.spki_sha256 && r.serial);
  assert.equal(certRecord(null), null);
  assert.equal(internalName("db01"), "single-label name"); assert.equal(internalName("nas.local"), ".local name"); assert.equal(internalName("*.svc.internal"), ".internal name");
  assert.equal(internalName("printer.home.arpa"), ".home.arpa name"); assert.equal(internalName("www.example.org"), ""); assert.equal(internalName("local.example.org"), "");
  assert.match(internalIp("192.168.1.10"), /private/); assert.match(internalIp("fd00::1"), /private/); assert.match(internalIp("127.0.0.1"), /loopback/); assert.equal(internalIp("8.8.8.8"), ""); assert.equal(internalIp("not-an-ip"), "");
});

const certHost = (address, names, port, der, o = {}) => ({ address, names, up: true, ports: [{ port, state: "open" }], services: [], observations: [],
  tls: [{ port, protocol: "TLSv1.3", cert: certRecord(probeCert(der, { fingerprint: fp(der), ...o }), Date.parse("2026-11-22")) }] });

test("certificate inventory: reuse across addresses, same key in different certificates, wildcards and names only when the host's names are known", () => {
  const shared = makeDer({ dns: ["www.example.org"], ip: ["10.0.0.9"] }), key = newSpki();
  const k1 = makeDer({ serial: "01", spki: key, dns: ["*.apps.example.org", "intranet"] }), k2 = makeDer({ serial: "02", spki: key, dns: ["b.example.org"] });
  const short = makeDer({ serial: "77", dns: ["s.example.org"], sct: true });
  const rep = { hosts: [
    certHost("10.0.0.5", ["www.example.org"], 443, shared), certHost("10.0.0.6", ["www.example.org"], 443, shared),
    certHost("10.0.0.7", ["x.apps.example.org"], 8443, k1), certHost("10.0.0.8", [], 443, k2),
    certHost("10.0.0.10", [], 443, short, { from: "Nov 16 00:00:00 2026 GMT", to: "Nov 22 00:00:00 2026 GMT" }),
  ] };
  const inv = certInventory(rep);
  assert.equal(inv.rows.length, 5);
  const same = inv.reuse.find((g) => g.kind === "same certificate");
  assert.equal(same.addresses, 2); assert.equal(same.one_name, true);           // both scanned as www.example.org: likely one host
  const keyg = inv.reuse.find((g) => g.kind.startsWith("same public key"));
  assert.deepEqual(keyg.seen_on.map((x) => x.host), ["10.0.0.7", "10.0.0.8"]); assert.equal(keyg.one_name, false);
  assert.ok(!inv.reuse.some((g) => g.kind.startsWith("same public key") && g.seen_on.some((x) => x.host === "10.0.0.5")), "same certificate is not also reported as same key");
  const r7 = inv.rows.find((r) => r.host === "10.0.0.7"), r8 = inv.rows.find((r) => r.host === "10.0.0.8"), r5 = inv.rows.find((r) => r.host === "10.0.0.5");
  assert.deepEqual(r7.wildcards, [{ name: "*.apps.example.org", covers_attested: ["x.apps.example.org"] }]);
  assert.deepEqual(r7.internal_names, [{ name: "intranet", why: "single-label name" }]);
  assert.deepEqual(r7.beyond_attested, ["intranet"]);
  assert.equal(r8.beyond_attested, null, "no attested names: nothing is compared");
  assert.deepEqual(r5.internal_names.map((x) => x.name), ["10.0.0.9"]);
  assert.equal(r5.reused_on, 1); assert.equal(r7.reused_on, 1);
  const s = inv.rows.find((r) => r.host === "10.0.0.10");
  assert.equal(s.validity_days, 6); assert.equal(s.short_lived, true); assert.equal(s.sct, true); assert.ok(CERT_RULES.shortLivedDays === 10);
  assert.equal(r5.short_lived, false);
  assert.equal(inv.summary.reused_groups, 2); assert.equal(inv.summary.short_lived, 1); assert.equal(inv.summary.with_sct, 1);
  const csv = toCertsCsv(inv).split("\r\n");
  assert.equal(csv[0], CERTS_HEAD.join(",")); assert.equal(csv.length, 7);
  // an older record (no DER fields) still yields its SAN from the text form
  const old = certInventory({ hosts: [{ address: "10.0.0.1", names: [], tls: [{ port: 443, cert: { subject: "CN=x", issuer: "CN=x", san: "DNS:nas.local, IP Address:192.168.0.2" } }] }] });
  assert.deepEqual(old.rows[0].internal_names.map((x) => x.name), ["nas.local", "192.168.0.2"]); assert.equal(old.rows[0].sct, null);
});

test("certs.csv quotes a cell a spreadsheet would run", () => {
  const inv = certInventory({ hosts: [certHost("10.0.0.5", [], 443, makeDer({ dns: ["=hyperlink(1)"] }))] });
  assert.match(toCertsCsv(inv), /,'=hyperlink\(1\) \(single-label name\),/);
});

test("on a loopback TLS service the identifiers come from the one handshake (one connection, nothing else sent)", async () => {
  const s = await startTlsServer("good");
  try {
    const r = await probePort("127.0.0.1", s.port, { httpsPorts: [s.port] });
    const c = certRecord(r.tls.cert);
    assert.match(c.serial, /^[0-9A-F]{2}(:[0-9A-F]{2})+$/); assert.match(c.spki_sha256, /^[0-9A-F:]{95}$/);
    assert.deepEqual(c.san_dns, ["good.fixture.test", "*.apps.fixture.test"]); assert.equal(c.sct, false); assert.equal(c.must_staple, false);
    assert.equal(s.connections(), 1, "the inventory must not open another connection");
  } finally { await s.close(); }
});

/* ---- mail: STARTTLS from the greeting already read ---- */
test("mail STARTTLS from the greeting only: IMAP capability list read, SMTP and POP3 never guessed", () => {
  assert.equal(mailProtocol(BANNERS.imap_dovecot, 143), "imap"); assert.equal(mailProtocol(BANNERS.pop_dovecot, 110), "pop3");
  assert.equal(mailProtocol(BANNERS.smtp_postfix, 25), "smtp"); assert.equal(mailProtocol(BANNERS.ftp_vsftpd, 21, "ftp"), ""); assert.equal(mailProtocol("220 hello", 2525), "");
  assert.equal(starttlsFromGreeting("imap", BANNERS.imap_dovecot), STARTTLS.advertised);
  assert.equal(starttlsFromGreeting("imap", "* OK [CAPABILITY IMAP4rev1 LOGINDISABLED] ready"), STARTTLS.notListed);
  assert.equal(starttlsFromGreeting("imap", "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REF"), STARTTLS.cut);
  assert.equal(starttlsFromGreeting("imap", "* OK IMAP ready"), STARTTLS.notChecked);
  assert.equal(starttlsFromGreeting("smtp", BANNERS.smtp_exim), STARTTLS.notChecked);
  assert.equal(starttlsFromGreeting("pop3", BANNERS.pop_dovecot), STARTTLS.notChecked);
  assert.equal(starttlsFromGreeting("imap", "* OK ready", { tls: true }), STARTTLS.implicit);
  const host = (address, ports) => ({ address, names: [], ports: ports.map(([port, banner]) => ({ port, state: "open", banner })), services: [], tls: ports.filter(([p]) => p === 993).map(([port]) => ({ port })) });
  const rows = mailInventory({ run: { ports: [25, 143, 465, 587, 993] }, hosts: [host("10.0.0.5", [[25, BANNERS.smtp_postfix.trim()], [143, BANNERS.imap_dovecot.trim()], [993, "* OK ready"]]), host("10.0.0.6", [[25, BANNERS.smtp_exim.trim()], [587, "220 sub ESMTP"]])] });
  const r = (h, p) => rows.find((x) => x.host === h && x.port === p);
  assert.match(r("10.0.0.5", 25).submission, /port 25 only/); assert.equal(r("10.0.0.5", 143).starttls, STARTTLS.advertised); assert.equal(r("10.0.0.5", 993).starttls, STARTTLS.implicit);
  assert.match(r("10.0.0.6", 25).submission, /answers on 587/);
  assert.match(mailInventory({ run: { ports: [25] }, hosts: [host("10.0.0.5", [[25, "220 mx ESMTP"]])] })[0].submission, /not both scanned/);
  assert.equal(toMailCsv(rows).split("\r\n")[0], "host,names,port,protocol,product,implicit_tls,starttls,submission");
});

/* ---- KEV coverage ---- */
test("KEV coverage: every inline fingerprint is really produced by its parser (the list cannot drift from the code)", () => {
  const made = [...fromSsh("SSH-2.0-OpenSSH_9.6"), ...fromSsh("SSH-2.0-dropbear_2022.83"), ...fromSsh("SSH-2.0-libssh_0.9.6"),
    ...fromMysql(Buffer.from("4a0000000a31302e362e31322d4d617269614442000100", "hex")), ...fromMysql(Buffer.from("4a0000000a382e302e333500", "hex")),
    ...fromHttp({ headers: { server: "Jetty(9.4.51.v20230217)", "x-owa-version": "15.2.1258.12" }, body: '<meta name="generator" content="WordPress 6.4.2">' }),
    ...fromHttp({ headers: {}, body: '<meta name="generator" content="Drupal 10">' }), ...fromHttp({ headers: {}, body: '<meta name="generator" content="Joomla! 4">' }),
    ...fromUdp({ state: "open", proto: "dns", port: 53, parsed: { version: "9.18.24" } }), ...fromUdp({ state: "open", proto: "ntp", port: 123, parsed: { version: "ntpd 4.2.8p15" } })];
  for (const x of INLINE) {
    const m = made.find((s) => s.vendor === x.vendor && s.product === x.product);
    assert.ok(m, `${x.vendor} ${x.product} is produced by fingerprint.mjs`);
    assert.equal(!!m.shown_version, x.version, `${x.product}: version flag matches what the parser reads`);
  }
  const all = fingerprintProducts();
  assert.ok(all.some((p) => p.product === "Exim" && p.version) && all.some((p) => p.product === "FortiOS" && !p.version) && all.some((p) => p.product === "Tomcat" && !p.version));
});

test("KEV coverage: the fixture snapshot is fully named; a product with no fingerprint is a gap", () => {
  const wb = JSON.parse(readFileSync(join(SNAP, "data", "workbench.json"), "utf8"));
  const c = kevCoverage(wb);
  assert.equal(c.kev_total, 5); assert.equal(c.gaps.length, 0);
  assert.equal(c.covered.find((g) => g.product === "FortiOS").coverage, "name only");
  assert.equal(c.covered.find((g) => g.product === "OpenSSH").coverage, "version");
  const wb2 = { ...wb, kev: [...wb.kev, { cve: "CVE-2026-90199", vendor: "Example Corp", product: "Widget Gateway", added: "2026-11-01", due: "2026-11-21", ransomware: true, affected: [] }] };
  const c2 = kevCoverage(wb2);
  assert.deepEqual(c2.gaps.map((g) => [g.vendor, g.product, g.kev_cves, g.ransomware_cves]), [["Example Corp", "Widget Gateway", 1, 1]]);
  assert.match(toCoverageCsv(c2).split("\r\n")[1], /^Example Corp,Widget Gateway,1,1,none,,CVE-2026-90199$/);
});

test("coverage command: offline only, no probe, no fetch, CSV only where asked", async () => {
  const d = tmp(); let probed = 0, fetched = 0;
  const x = io({ probe: async () => { probed++; return {}; }, udpProbe: async () => { probed++; return {}; }, fetchImpl: () => { fetched++; throw new Error("no"); } });
  assert.equal(await main(["coverage", "--data", SNAP, "--out", join(d, "kev-coverage.csv")], x), 0);
  assert.equal(probed, 0); assert.equal(fetched, 0);
  assert.match(x.lines.out.join("\n"), /KEV coverage: 5 known-exploited/);
  assert.match(readFileSync(join(d, "kev-coverage.csv"), "utf8"), /^vendor,product,kev_cves/);
  const y = io(); assert.equal(await main(["coverage"], y), 1); assert.match(y.lines.err.join("\n"), /--data DIR is required/);
  const z = io(); assert.equal(await main(["coverage", "--online"], z), 1);
});

/* ---- diff ---- */
const rep = (o) => ({ tool: { name: "CyberView Scanner" }, run: { started_at: o.at || "2026-11-01T00:00:00Z", ports: o.ports || [22, 80, 443], interrupted: false }, scope: { sha256: "abc" },
  coverage: { ports_not_checked: o.notChecked || [] }, hosts: o.hosts, findings: o.findings || [] });
const H = (address, ports, extra = {}) => ({ address, names: [], up: true, ports: ports.map((port) => ({ port, state: "open" })), services: [], tls: [], observations: [], ...extra });
const F = (cve, host, port, v = "") => ({ cve, title: cve, kev: true, seen_on: [{ host, port, product: "x", shown_version: v, confidence: "high" }] });

test("diff: new, fixed only when the port answered again, gone with its port, not rechecked, issuer change flagged for review", () => {
  const prev = rep({ hosts: [
    H("10.0.0.5", [22, 80, 443], { services: [{ port: 22, label: "OpenSSH", product: "OpenSSH", shown_version: "9.6p1" }], tls: [{ port: 443, cert: { fingerprint256: "AA", issuer: "CN=Old CA", spki_sha256: "K1" } }],
      observations: [{ port: 443, kind: "tls-expiring", severity: "medium", text: "x" }] }),
    H("10.0.0.6", [22]), H("10.0.0.7", [22]) ],
    findings: [F("CVE-2026-90101", "10.0.0.5", 22, "9.6p1"), F("CVE-2026-90102", "10.0.0.5", 80), F("CVE-2026-90103", "10.0.0.6", 22), F("CVE-2026-90104", "10.0.0.7", 22), F("CVE-2026-90105", "10.0.0.5", 443)] });
  const cur = rep({ at: "2026-11-22T00:00:00Z", notChecked: [{ address: "10.0.0.7", not_checked: 5 }], hosts: [
    H("10.0.0.5", [22, 443], { services: [{ port: 22, label: "OpenSSH", product: "OpenSSH", shown_version: "9.9" }], tls: [{ port: 443, cert: { fingerprint256: "BB", issuer: "CN=New CA", spki_sha256: "K2" } }] }),
    { ...H("10.0.0.6", []), up: false }, H("10.0.0.7", []), H("10.0.0.8", [3389]) ],
    findings: [F("CVE-2026-90105", "10.0.0.5", 443), F("CVE-2026-90199", "10.0.0.8", 3389)] });
  const d = diffReports(prev, cur);
  assert.deepEqual(d.findings.new.map((x) => x.cve), ["CVE-2026-90199"]);
  assert.deepEqual(d.findings.still_open.map((x) => x.cve), ["CVE-2026-90105"]);
  assert.deepEqual(d.findings.fixed.map((x) => x.cve), ["CVE-2026-90101"]); assert.match(d.findings.fixed[0].why, /OpenSSH 9\.9/);
  assert.deepEqual(d.findings.gone.map((x) => x.cve), ["CVE-2026-90102"]); assert.match(d.findings.gone[0].why, /not proof of a fix/);
  assert.deepEqual(d.findings.not_rechecked.map((x) => [x.cve, x.why]), [["CVE-2026-90103", "the host did not answer in this scan"], ["CVE-2026-90104", "a limit or an interruption left this host's ports partly unchecked"]]);
  assert.deepEqual(d.services.changed, [{ host: "10.0.0.5", port: 22, product: "OpenSSH", before: "9.6p1", after: "9.9" }]);
  assert.equal(d.certificates.changed.length, 1); assert.equal(d.certificates.issuer_changed[0].after, "CN=New CA"); assert.match(d.certificates.issuer_changed[0].note, /not evidence of compromise/);
  assert.deepEqual(d.certificates.key_changed, [{ host: "10.0.0.5", port: 443 }]);
  assert.deepEqual(d.observations.resolved.map((x) => x.kind), ["tls-expiring"]);
  assert.deepEqual(d.hosts.new_up, ["10.0.0.8"]); assert.deepEqual(d.hosts.no_longer_up.map((x) => x.host), ["10.0.0.6"]);
  assert.deepEqual(d.ports.no_longer_open, [{ host: "10.0.0.5", port: 80, why: "the port no longer answers (closed or filtered): not proof of a fix" }]);
  assert.equal(d.same_scope, true); assert.equal(d.counts["findings.fixed"], 1);
  const t = diffText(d); assert.match(t, /Findings: 1 new, 1 fixed, 1 still open, 1 gone with their port, 2 not rechecked/); assert.match(t, /Certificate issuer changed/);
});

test("diff: the previous file is untrusted input: only a CyberView report is accepted, and only compared fields are kept", () => {
  assert.match(loadPrevious("").error, /empty/); assert.match(loadPrevious("{nope").error, /not JSON/);
  assert.match(loadPrevious(JSON.stringify({ tool: { name: "other" }, hosts: [], findings: [] })).error, /not a CyberView Scanner report/);
  const r = loadPrevious(JSON.stringify({ tool: { name: "CyberView Scanner" }, run: { ports: [22, "x", 99999] }, hosts: [{ address: "10.0.0.5", up: true, ports: [{ port: 22 }, { port: "22" }],
    services: [{ port: 22, product: "A".repeat(5000), shown_version: "1", body: "secret" }], observations: [{ port: 22, kind: "k", text: "\u0007bell" }], __proto__: { polluted: true } }, "junk"],
    findings: [{ cve: "not-a-cve" }, { cve: "CVE-2026-90101", seen_on: [{ host: "10.0.0.5", port: 22 }] }] }));
  assert.ok(r.report); assert.deepEqual(r.report.ports, [22]); assert.equal(r.report.hosts.length, 1); assert.deepEqual(r.report.hosts[0].ports, [22]);
  assert.equal(r.report.hosts[0].services[0].product.length, 120); assert.equal("body" in r.report.hosts[0].services[0], false);
  assert.equal(r.report.hosts[0].observations[0].text, " bell"); assert.equal(r.report.findings.length, 1); assert.equal({}.polluted, undefined);
  assert.ok(cleanReport(null).hosts.length === 0);
});

/* ---- the command line: opt-in files, and the same probes with and without the new flags ---- */
const SHARED = makeDer({ dns: ["shared.example.org", "intranet.corp"] });
const stubProbe = (calls, { sshv = "9.6p1", web = true } = {}) => async (ip, port) => {
  calls.push(`${ip}:${port}`);
  if (port === 22) return { port, state: "open", banner: `SSH-2.0-OpenSSH_${sshv}\r\n` };
  if (port === 80 && web) return { port, state: "open", http: { status: 200, headers: { server: "nginx/1.22.1" }, body: "" } };
  if (port === 143) return { port, state: "open", banner: BANNERS.imap_dovecot };
  if (port === 25) return { port, state: "open", banner: BANNERS.smtp_postfix };
  if (port === 443) return { port, state: "open", tls: { protocol: "TLSv1.3", cipher: "TLS_AES_128_GCM_SHA256", cipher_std: "TLS_AES_128_GCM_SHA256", kex: {}, cert: probeCert(SHARED, { fingerprint: fp(SHARED), cn: "shared.example.org", san: "DNS:shared.example.org, DNS:intranet.corp" }) }, http: { status: 404, headers: {}, body: "" } };
  return { port, state: "closed" };
};
const PORTS = ["--ports", "22,25,80,143,443,465,587"];

test("scan with --certs --mail --compare: extra files only when asked, and exactly the same probes as without them", async () => {
  const d = tmp(), scope = writeScope(d, ["10.0.0.5", "10.0.0.6"]);
  const plainCalls = [];
  assert.equal(await main(["scan", "--scope", scope, "--data", SNAP, ...PORTS, "--out", join(d, "first")], io({ probe: stubProbe(plainCalls) })), 0);
  assert.deepEqual(readdirSync(join(d, "first")).sort(), ["findings.csv", "inventory.csv", "report.json", "report.sarif", "summary.txt"]);
  const first = JSON.parse(readFileSync(join(d, "first", "report.json"), "utf8"));
  assert.match(first.hosts[0].tls[0].cert.spki_sha256, /^[0-9A-F:]{95}$/);   // the identifiers ride in report.json from the existing handshake
  assert.deepEqual(first.findings.map((f) => f.cve).sort(), ["CVE-2026-90101", "CVE-2026-90102"]);
  // second scan: OpenSSH upgraded, the web port closed; with every new flag
  const packCalls = [], x = io({ probe: stubProbe(packCalls, { sshv: "9.9", web: false }) });
  assert.equal(await main(["scan", "--scope", scope, "--data", SNAP, ...PORTS, "--out", join(d, "second"), "--certs", "--mail", "--compare", join(d, "first", "report.json")], x), 0);
  assert.deepEqual(packCalls.slice().sort(), plainCalls.slice().sort(), "the report pack sends nothing: the same host:port probes as a plain scan");
  assert.deepEqual(readdirSync(join(d, "second")).sort(), ["certs.csv", "diff.json", "diff.txt", "findings.csv", "inventory.csv", "mail.csv", "report.json", "report.sarif", "summary.txt"]);
  const certs = readFileSync(join(d, "second", "certs.csv"), "utf8");
  assert.match(certs, /10\.0\.0\.5,,443,/); assert.match(certs, /intranet\.corp \(\.corp name\)/);
  assert.match(x.lines.out.join("\n"), /same certificate on 2 addresses/);
  const mail = readFileSync(join(d, "second", "mail.csv"), "utf8");
  assert.match(mail, /10\.0\.0\.5,,143,imap,.*advertised in the greeting/); assert.match(mail, /10\.0\.0\.5,,25,smtp,.*not checked.*port 25 only/);
  const diff = JSON.parse(readFileSync(join(d, "second", "diff.json"), "utf8"));
  assert.deepEqual(diff.findings.fixed.map((f) => f.cve).sort(), ["CVE-2026-90101", "CVE-2026-90101"]);
  assert.deepEqual(diff.findings.gone.map((f) => f.cve), ["CVE-2026-90102", "CVE-2026-90102"]);
  assert.equal(diff.findings.new.length, 0); assert.equal(diff.same_scope, true);
  assert.match(readFileSync(join(d, "second", "diff.txt"), "utf8"), /Findings: 0 new, 2 fixed/);
  assert.match(x.lines.out.join("\n"), /\(report\.json, findings\.csv, report\.sarif, inventory\.csv, summary\.txt, certs\.csv, mail\.csv, diff\.json, diff\.txt\)/);
});

test("a bad --compare file is refused before anything is scanned", async () => {
  const d = tmp(), scope = writeScope(d, ["10.0.0.5"]), calls = [];
  writeFileSync(join(d, "bad.json"), JSON.stringify({ hello: "world" }));
  const x = io({ probe: stubProbe(calls) });
  assert.equal(await main(["scan", "--scope", scope, "--data", SNAP, "--compare", join(d, "bad.json"), "--out", join(d, "o")], x), 1);
  assert.match(x.lines.err.join("\n"), /not a CyberView Scanner report/); assert.equal(calls.length, 0);
  const y = io({ probe: stubProbe(calls) });
  assert.equal(await main(["scan", "--scope", scope, "--data", SNAP, "--compare", join(d, "missing.json")], y), 1); assert.match(y.lines.err.join("\n"), /cannot read/); assert.equal(calls.length, 0);
});
