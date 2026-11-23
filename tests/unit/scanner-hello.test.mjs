// Identify hellos (--identify, scanner/lib/hello.mjs) and DNS records (--dns-records, scanner/lib/dns-records.mjs).
// Loopback only: every fixture server here (TCP and UDP on 127.0.0.1, ephemeral ports) records every byte it receives, so
// the tests prove the exact bytes sent with the flags, and that nothing is sent without them. No public host is contacted.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import dgram from "node:dgram";
import { readFileSync, mkdtempSync, writeFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateKeyPairSync } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { parseRdp, parseSmb, parseLdap, ldapDone } from "../../scanner/lib/hello.mjs";
import { parseKafka, parseRedis, parseConnack, parseMongo, bsonFields } from "../../scanner/lib/hello.mjs";
import { HELLO, HELLO_SENDS, wire,parseEhlo, parseCapa, parseHead, parseMdns, parseAsfPong, tcpHello, udpHello, helloPlan, helloRecord, helloFindings, identifyHost, identifyHeaderText } from "../../scanner/lib/hello.mjs";
import { QUERIES, dnsPlanArgs, dnsQueries, interpret, dnsRecords, toDnsCsv, DNS_SENDS } from "../../scanner/lib/dns-records.mjs";
import { mailInventory, toMailCsv, STARTTLS } from "../../scanner/lib/mail-starttls.mjs";
import { probeAll } from "../../scanner/lib/scan.mjs";
import { settings } from "../../scanner/lib/limits.mjs";
import { USER_AGENT } from "../../scanner/lib/probe.mjs";
import { STATEMENT } from "../../scanner/lib/scope.mjs";
import { main } from "../../scanner/cyberview-scan.mjs";
import { helloProblems, REVIEWED_HEX } from "../../scripts/lib/scanner-hello-check.mjs";

const ROOT = new URL("../../", import.meta.url).pathname;
const SNAP = new URL("../fixtures/scanner/snapshot", import.meta.url).pathname;
const LOCAL = [{ address: "127.0.0.1", names: [], kind: "loopback", public: false }];
const FAST = { connectMs: 1500, readMs: 1500, maxBytes: 16384 };

/* ---- loopback fixtures ---- */
/** A line-protocol TCP server: greets with `greet`, answers each received chunk with reply(text); records every byte. */
async function tcpServer(greet, reply = () => "") {
  const got = [], conns = [];
  const srv = net.createServer((s) => {
    conns.push(s); const mine = []; got.push(mine);
    if (greet) s.write(greet);
    s.on("data", (d) => { mine.push(d.toString("latin1")); const r = reply(d.toString("latin1")); if (r) s.write(r); if (/^QUIT\r\n/m.test(d.toString("latin1"))) s.end(); });
    s.on("error", () => {});
  });
  const port = await new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
  return { port, got, bytes: () => got.map((c) => c.join("")).join(""), close: () => new Promise((r) => { conns.forEach((c) => c.destroy()); srv.close(() => r()); }) };
}
/** A UDP server on 127.0.0.1 answering each datagram with answer(msg); records every datagram. */
async function udpServer(answer = () => null) {
  const got = [], s = dgram.createSocket("udp4");
  s.on("message", (m, r) => { got.push(Buffer.from(m)); const a = answer(m); if (a) s.send(a, r.port, r.address); });
  const port = await new Promise((r) => s.bind(0, "127.0.0.1", () => r(s.address().port)));
  return { port, got, close: () => new Promise((r) => s.close(() => r())) };
}
const SMTP_EHLO = "250-mail.example.org Hello\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-AUTH PLAIN LOGIN\r\n250-STARTTLS\r\n250 8BITMIME\r\n";
const smtpReply = (t) => (/^EHLO /.test(t) ? SMTP_EHLO : /^QUIT/.test(t) ? "221 bye\r\n" : "");
const pop3Reply = (t) => (/^CAPA/.test(t) ? "+OK Capability list follows\r\nTOP\r\nUSER\r\nSASL PLAIN\r\nIMPLEMENTATION Dovecot\r\n.\r\n" : /^QUIT/.test(t) ? "+OK bye\r\n" : "");

/* DNS wire helpers for the fixtures */
const enc = (name) => Buffer.concat([...name.split(".").filter(Boolean).map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, "latin1")])), Buffer.from([0])]);
const rr = (nameBuf, type, rdata) => { const h = Buffer.alloc(10); h.writeUInt16BE(type, 0); h.writeUInt16BE(1, 2); h.writeUInt32BE(60, 4); h.writeUInt16BE(rdata.length, 8); return Buffer.concat([nameBuf, h, rdata]); };
const txtData = (...strs) => Buffer.concat(strs.map((s) => Buffer.concat([Buffer.from([Buffer.byteLength(s)]), Buffer.from(s)])));
function readQ(m) { let o = 12; const labels = []; while (m[o]) { labels.push(m.subarray(o + 1, o + 1 + m[o]).toString("latin1")); o += 1 + m[o]; } o++; return { name: labels.join("."), type: m.readUInt16BE(o), qEnd: o + 4 }; }
function dnsAnswer(m, answers) {
  const q = readQ(m), h = Buffer.alloc(12); m.copy(h, 0, 0, 2); h.writeUInt16BE(0x8180, 2); h.writeUInt16BE(1, 4); h.writeUInt16BE(answers.length, 6);
  return Buffer.concat([h, m.subarray(12, q.qEnd), ...answers.map(([t, d]) => rr(Buffer.from([0xc0, 0x0c]), t, d))]);
}

/* ---- the frozen table and the exact bytes ---- */
test("HELLO is frozen literals; wire() gives the exact bytes, fills only {target} (an IP) and {ua}", () => {
  assert.ok(Object.isFrozen(HELLO) && Object.values(HELLO).every(Object.isFrozen));
  assert.deepEqual(Object.keys(HELLO).sort(), ["ipmi", "kafka", "ldap", "mdns", "mongodb", "mqtt", "pop3", "rdp", "redis", "rtsp", "sip-tcp", "sip-udp", "smb", "smtp"]);
  assert.equal(wire("smtp").toString(), "EHLO cyberview-scanner.invalid\r\n");
  assert.equal(wire("pop3").toString(), "CAPA\r\n");
  assert.equal(wire("rtsp").toString(), `OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: ${USER_AGENT}\r\n\r\n`);
  const sip = wire("sip-udp", "10.0.0.9").toString();
  assert.match(sip, /^OPTIONS sip:10\.0\.0\.9 SIP\/2\.0\r\n/); assert.match(sip, /\r\nTo: <sip:10\.0\.0\.9>\r\n/); assert.match(sip, /\r\nMax-Forwards: 0\r\n/); assert.match(sip, /;rport;/);
  assert.match(wire("sip-tcp", "fd00::1").toString(), /^OPTIONS sip:\[fd00::1\] SIP\/2\.0/);
  assert.equal(wire("sip-tcp", "not-an-ip"), null, "no host name or other text is ever put into a request");
  assert.equal(wire("ipmi").toString("hex"), "0600ff06000011be80000000");
  assert.equal(wire("mdns").toString("hex"), REVIEWED_HEX.mdns);
  assert.equal(readQ(wire("mdns")).name, "_services._dns-sd._udp.local"); assert.equal(readQ(wire("mdns")).type, 12);
  for (const v of Object.values(HELLO_SENDS)) assert.match(v, /^only with --identify/);
  assert.match(identifyHeaderText({ enabled: false }), /^off/); assert.match(identifyHeaderText({ enabled: true, bmc: true }), /--identify-bmc/);
});

test("reply parsers keep names and tokens only", () => {
  const e = parseEhlo(SMTP_EHLO);
  assert.equal(e.code, 250); assert.equal(e.starttls, true); assert.equal(e.size, 10240000); assert.deepEqual(e.auth, ["PLAIN", "LOGIN"]);
  assert.ok(!e.keywords.includes("MAIL.EXAMPLE.ORG"), "the server's name on the first line is not kept");
  assert.equal(parseEhlo("250-x\r\n250 SIZE 1\r\n").starttls, false); assert.equal(parseEhlo("502 no\r\n").code, 502);
  const c = parseCapa("+OK\r\nTOP\r\nUSER\r\nSTLS\r\nSASL PLAIN SCRAM-SHA-256\r\nIMPLEMENTATION Dovecot\r\n.\r\n");
  assert.equal(c.starttls, true); assert.deepEqual(c.sasl, ["PLAIN", "SCRAM-SHA-256"]); assert.equal(c.implementation, "Dovecot");
  const r = parseHead("RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: GStreamer RTSP server\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n", "rtsp");
  assert.deepEqual([r.code, r.server, r.methods.length], [200, "GStreamer RTSP server", 4]);
  const s = parseHead("SIP/2.0 200 OK\r\nUser-Agent: Asterisk PBX 20.1.0\r\nAllow: INVITE, ACK, OPTIONS\r\n\r\n", "sip");
  assert.equal(s.user_agent, "Asterisk PBX 20.1.0");
  assert.equal(parseHead("HTTP/1.1 200 OK\r\n\r\n", "sip").code, 0);
  assert.deepEqual(parseAsfPong(Buffer.from("0600ff06")), { pong: false, ipmi: false });
});

/* ---- exact bytes on loopback ---- */
test("SMTP: greeting read, then exactly EHLO and QUIT; STARTTLS, SIZE and AUTH names read", async () => {
  const s = await tcpServer("220 mail.example.org ESMTP Postfix\r\n", smtpReply);
  try {
    const r = await tcpHello("127.0.0.1", s.port, "smtp", { timeouts: FAST });
    assert.equal(r.state, "answered"); assert.deepEqual(r.sent, ["EHLO", "QUIT"]);
    await new Promise((x) => setTimeout(x, 100));
    assert.equal(s.bytes(), "EHLO cyberview-scanner.invalid\r\nQUIT\r\n", "exactly these bytes, nothing else (no AUTH, MAIL, RCPT, VRFY, EXPN, STARTTLS)");
    const rec = helloRecord(r); assert.equal(rec.read.starttls, true); assert.deepEqual(rec.read.auth, ["PLAIN", "LOGIN"]);
    assert.ok(!("reply" in rec) && !("greeting" in rec), "the raw reply is not stored");
  } finally { await s.close(); }
});

test("SMTP: a service that does not greet 220 is sent nothing", async () => {
  const s = await tcpServer("554 go away\r\n", smtpReply);
  try { const r = await tcpHello("127.0.0.1", s.port, "smtp", { timeouts: FAST }); assert.equal(r.state, "not-sent"); await new Promise((x) => setTimeout(x, 100)); assert.equal(s.bytes(), ""); }
  finally { await s.close(); }
});

test("POP3: exactly CAPA and QUIT; never USER, PASS or APOP", async () => {
  const s = await tcpServer("+OK Dovecot ready.\r\n", pop3Reply);
  try {
    const r = await tcpHello("127.0.0.1", s.port, "pop3", { timeouts: FAST });
    await new Promise((x) => setTimeout(x, 100));
    assert.equal(s.bytes(), "CAPA\r\nQUIT\r\n");
    const rec = helloRecord(r); assert.equal(rec.read.starttls, false); assert.equal(rec.read.implementation, "Dovecot");
    assert.deepEqual(helloFindings([rec]).observations.map((o) => o.kind), ["pop3-no-stls"]);
  } finally { await s.close(); }
});

test("RTSP and SIP over TCP: exactly one OPTIONS each, nothing after", async () => {
  const rt = await tcpServer("", (t) => (/^OPTIONS/.test(t) ? "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hipcam RealServer/V1.0\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n" : ""));
  const sp = await tcpServer("", (t) => (/^OPTIONS/.test(t) ? "SIP/2.0 200 OK\r\nServer: FPBX-16.0.40(18.12.1)\r\nAllow: INVITE, OPTIONS\r\nContent-Length: 0\r\n\r\n" : ""));
  try {
    const a = helloRecord(await tcpHello("127.0.0.1", rt.port, "rtsp", { timeouts: FAST }));
    const b = helloRecord(await tcpHello("127.0.0.1", sp.port, "sip-tcp", { timeouts: FAST }));
    await new Promise((x) => setTimeout(x, 100));
    assert.equal(rt.bytes(), wire("rtsp").toString("latin1")); assert.equal(sp.bytes(), wire("sip-tcp", "127.0.0.1").toString("latin1"));
    assert.equal(a.read.server, "Hipcam RealServer/V1.0"); assert.equal(b.read.server, "FPBX-16.0.40(18.12.1)");
    const f = helloFindings([{ ...a, port: 554 }, { ...b, port: 5060 }]);
    assert.ok(f.services.every((x) => x.guessed && !x.version), "no version is claimed from these replies");
  } finally { await rt.close(); await sp.close(); }
});

test("UDP: SIP, unicast mDNS and the ASF ping are one datagram each, byte for byte, to the host's own address", async () => {
  const sip = await udpServer(() => Buffer.from("SIP/2.0 200 OK\r\nUser-Agent: Yealink SIP-T46S 66.86.0.15\r\nAllow: INVITE, OPTIONS\r\n\r\n"));
  const mdns = await udpServer((m) => {
    const q = readQ(m), h = Buffer.alloc(12); h.writeUInt16BE(0x8400, 2); h.writeUInt16BE(1, 4); h.writeUInt16BE(2, 6); h.writeUInt16BE(1, 10);
    return Buffer.concat([h, m.subarray(12, q.qEnd), rr(Buffer.from([0xc0, 0x0c]), 12, enc("_ndi._tcp.local")), rr(Buffer.from([0xc0, 0x0c]), 12, enc("_ssh._tcp.local")), rr(enc("cam._ndi._tcp.local"), 16, txtData("Name=PTZ-Cam-1"))]);
  });
  const pong = Buffer.from("0600ff06000011be40000010000011be00000000810000000000000000", "hex");
  const bmc = await udpServer(() => pong);
  try {
    const s = helloRecord(await udpHello("127.0.0.1", "sip-udp", { port: sip.port, timeouts: FAST }));
    const m = helloRecord(await udpHello("127.0.0.1", "mdns", { port: mdns.port, timeouts: FAST }));
    const b = helloRecord(await udpHello("127.0.0.1", "ipmi", { port: bmc.port, timeouts: FAST }));
    assert.equal(sip.got.length, 1); assert.equal(sip.got[0].toString("latin1"), wire("sip-udp", "127.0.0.1").toString("latin1"));
    assert.equal(mdns.got.length, 1); assert.equal(mdns.got[0].toString("hex"), HELLO.mdns.hex);
    assert.equal(bmc.got.length, 1); assert.equal(bmc.got[0].toString("hex"), "0600ff06000011be80000000");
    assert.equal(s.read.user_agent, "Yealink SIP-T46S 66.86.0.15");
    assert.deepEqual(m.read, { services: ["_ndi._tcp.local", "_ssh._tcp.local"], name: "PTZ-Cam-1" });
    assert.deepEqual(b.read, { pong: true, ipmi: true });
    const f = helloFindings([m, b]);
    const ptz = f.services.find((x) => x.vendor === "PTZOptics");
    assert.ok(ptz && ptz.guessed && ptz.version === "", "PTZOptics is product only, guessed");
    assert.ok(f.observations.some((o) => o.kind === "ipmi-exposed") && f.observations.some((o) => o.kind === "mdns-unicast"));
  } finally { await sip.close(); await mdns.close(); await bmc.close(); }
});

test("udpHello ignores a reply from any other address and never sends to a name", async () => {
  const r = await udpHello("localhost", "mdns", { timeouts: FAST });
  assert.equal(r.state, "not-sent");
});

/* ---- planning, gating, budgets ---- */
const host = (extra = {}) => ({ address: "127.0.0.1", names: [], ports: [], services: [], tls: [], ...extra });
test("helloPlan: one hello per service per host, from what the probes found; IPMI only with bmc", () => {
  const h = host({ ports: [{ port: 25, state: "open", banner: "220 mx ESMTP Postfix" }, { port: 587, state: "open", banner: "220 mx ESMTP Postfix" }, { port: 110, state: "open", banner: "+OK ready" },
    { port: 995, state: "open", banner: "" }, { port: 554, state: "open", banner: "" }, { port: 5060, state: "open", banner: "" }], tls: [{ port: 995 }] });
  assert.deepEqual(helloPlan(h, { ports: [25, 110, 554, 587, 995, 5060] }).map((x) => `${x.key}:${x.port}`), ["smtp:25", "pop3:110", "rtsp:554", "sip-tcp:5060", "sip-udp:5060", "mdns:5353"]);
  assert.deepEqual(helloPlan(host(), { ports: [80] }).map((x) => x.key), ["mdns"]);
  assert.deepEqual(helloPlan(host(), { ports: [80], bmc: true }).map((x) => x.key), ["mdns", "ipmi"]);
});

test("identifyHost refuses unless enabled, and every exchange takes a Limiter slot (none left: nothing sent)", async () => {
  const calls = [], tcp = async (...a) => { calls.push(a); return { service: a[2], port: a[1], proto: "tcp", state: "answered", reply: "" }; }, udp = async (...a) => { calls.push(a); return { service: a[1], port: 5353, proto: "udp", state: "no-answer" }; };
  assert.deepEqual(await identifyHost(host(), { acquire: async () => () => {}, tcp, udp }), []);
  assert.deepEqual(await identifyHost(host(), { enabled: "yes", acquire: async () => () => {}, tcp, udp }), []);
  assert.equal(calls.length, 0);
  const none = await identifyHost(host(), { enabled: true, bmc: true, acquire: async () => null, tcp, udp });
  assert.deepEqual(none.map((r) => r.state), ["not-sent: budget or time", "not-sent: budget or time"]); assert.equal(calls.length, 0);
  const acq = [];
  await identifyHost(host(), { enabled: true, acquire: async (a) => { acq.push(a); return () => {}; }, tcp, udp });
  assert.deepEqual(acq, ["127.0.0.1"]); assert.equal(calls.length, 1);
});

test("probeAll without --identify: an SMTP service gets nothing (greeting read only); with it: exactly EHLO and QUIT on a second connection", async () => {
  const s = await tcpServer("220 mail.example.org ESMTP Postfix\r\n", smtpReply);
  const udpCalls = [];
  try {
    const st = settings({}).settings;
    const a = await probeAll(LOCAL, { ports: [s.port], settings: st, assumeUp: true });
    await new Promise((x) => setTimeout(x, 100));
    assert.equal(s.bytes(), "", "no --identify: not one byte is sent to the mail server");
    assert.equal(a.hosts[0].identify, undefined); assert.deepEqual(a.identify, { enabled: false });
    const udp = async (ip, key) => { udpCalls.push(key); return { service: key, port: 5353, proto: "udp", state: "no-answer", sent: [] }; };
    const b = await probeAll(LOCAL, { ports: [s.port], settings: st, assumeUp: true, identify: { enabled: true, udp } });
    await new Promise((x) => setTimeout(x, 100));
    assert.equal(s.bytes(), "EHLO cyberview-scanner.invalid\r\nQUIT\r\n");
    assert.equal(s.got.length, 3, "three connections: the probe's own, and one for the hello");
    const smtp = b.hosts[0].identify.find((r) => r.service === "smtp");
    assert.equal(smtp.read.starttls, true); assert.deepEqual(udpCalls, ["mdns"]);
    assert.ok(b.stats.connections >= 3, "the hello exchanges went through the Limiter");
    assert.ok(b.hosts[0].observations.some((o) => o.kind === "smtp-auth-cleartext"));
  } finally { await s.close(); }
});

test("mail.csv: STARTTLS from the EHLO/CAPA reply when --identify ran, 'not checked' otherwise", () => {
  const rep = { run: { ports: [25, 110] }, hosts: [{ address: "10.0.0.5", names: [], ports: [{ port: 25, state: "open", banner: "220 mx ESMTP Postfix" }, { port: 110, state: "open", banner: "+OK ready" }],
    services: [{ port: 25, proto: "smtp", product: "Postfix" }], tls: [],
    identify: [{ service: "smtp", port: 25, proto: "tcp", state: "answered", read: { code: 250, starttls: true, auth: [] } }, { service: "pop3", port: 110, proto: "tcp", state: "answered", read: { ok: true, starttls: false } }] }] };
  const rows = mailInventory(rep);
  assert.equal(rows[0].starttls, STARTTLS.helloListed); assert.equal(rows[1].starttls, STARTTLS.helloNotListed);
  delete rep.hosts[0].identify;
  assert.ok(mailInventory(rep).every((r) => r.starttls === STARTTLS.notChecked));
  assert.match(toMailCsv(rows), /advertised in the EHLO\/CAPA reply/);
});

/* ---- DNS records ---- */
const SCOPE = { hosts: ["example.org", "mail.example.org"] };
test("--dns-records: only names listed in the scope's targets; selectors only as given", () => {
  assert.equal(dnsPlanArgs(SCOPE, "example.org", "").ok, true);
  assert.match(dnsPlanArgs(SCOPE, "example.org,examp1e.org", "").problems.join(), /examp1e\.org" is not a host name listed/);
  assert.match(dnsPlanArgs(SCOPE, "sub.example.org", "").problems.join(), /not a host name listed/, "a subdomain of an attested name is not attested");
  assert.match(dnsPlanArgs(SCOPE, "example.org", "a b").problems.join(), /not a DKIM selector/);
  assert.match(dnsPlanArgs(SCOPE, "", "").problems.join(), /at least one domain/);
  assert.deepEqual(dnsQueries("example.org", ["s1"]).map((q) => `${q.type} ${q.name}`),
    ["TXT example.org", "TXT _dmarc.example.org", "CAA example.org", "TXT default._bimi.example.org", "TXT _mta-sts.example.org", "TXT s1._domainkey.example.org"]);
  assert.ok(Object.isFrozen(QUERIES) && QUERIES.every((q) => ["TXT", "CAA"].includes(q.type)));
  assert.match(DNS_SENDS["dns-records"], /^only with --dns-records/);
});

test("DNS observations: SPF +all, missing DMARC, p=none, no CAA, weak DKIM key; the key itself is not stored", () => {
  const q = (check, extra = {}) => ({ check, name: "x", type: check === "caa" ? "CAA" : "TXT", ...extra });
  assert.equal(interpret(q("spf"), { records: [["v=spf1 include:x +all"]] }, "example.org").obs[0].kind, "spf-pass-all");
  assert.equal(interpret(q("spf"), { records: [["v=spf1 -all"]] }, "example.org").obs.length, 0);
  assert.equal(interpret(q("spf"), { records: [["v=spf1 a"], ["v=spf1 mx"]] }, "example.org").obs[0].kind, "spf-multiple");
  assert.equal(interpret(q("dmarc"), { error: "ENODATA" }, "example.org").obs[0].kind, "dmarc-missing");
  assert.equal(interpret(q("dmarc"), { records: [["v=DMARC1; p=none; rua=mailto:d@example.org"]] }, "example.org").obs[0].kind, "dmarc-p-none");
  assert.equal(interpret(q("caa"), { records: [] }, "example.org").obs[0].kind, "caa-missing");
  assert.equal(interpret(q("caa"), { error: "ESERVFAIL" }, "example.org").rows[0].status, "error");
  const weak = generateKeyPairSync("rsa", { modulusLength: 512 }).publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const r = interpret(q("dkim", { selector: "s1" }), { records: [[`v=DKIM1; k=rsa; p=${weak}`]] }, "example.org");
  assert.equal(r.obs[0].kind, "dkim-weak-key"); assert.equal(r.rows[0].value, "k=rsa; 512 bits"); assert.ok(!r.rows[0].value.includes(weak.slice(0, 20)));
  assert.match(interpret(q("mta-sts"), { records: [["v=STSv1; id=2026"]] }, "example.org").rows[0].observation, /not fetched/);
});

test("dnsRecords on a loopback DNS server: exactly the planned queries, one each; nothing for an unattested name", async () => {
  const zone = { "example.org/16": [txtData("v=spf1 +all")], "_dmarc.example.org/16": [txtData("v=DMARC1; p=reject")], "example.org/257": [Buffer.concat([Buffer.from([0, 5]), Buffer.from("issueletsencrypt.org")])] };
  const srv = await udpServer((m) => { const q = readQ(m); return dnsAnswer(m, (zone[`${q.name}/${q.type}`] || []).map((d) => [q.type, d])); });
  try {
    const resolver = new Resolver({ timeout: 1000, tries: 1 }); resolver.setServers([`127.0.0.1:${srv.port}`]);
    const refused = await dnsRecords(SCOPE, ["evil.example"], [], { resolver });
    assert.ok(refused.error); assert.equal(srv.got.length, 0, "an unattested name is refused before any query");
    const res = await dnsRecords(SCOPE, ["example.org"], ["sel1"], { resolver });
    const asked = srv.got.map((m) => { const q = readQ(m); return `${q.type} ${q.name}`; });
    assert.deepEqual(asked, ["16 example.org", "16 _dmarc.example.org", "257 example.org", "16 default._bimi.example.org", "16 _mta-sts.example.org", "16 sel1._domainkey.example.org"]);
    assert.deepEqual(res.observations.map((o) => o.kind), ["spf-pass-all"]);
    assert.equal(res.records.find((r) => r.check === "caa").status, "present");
    assert.ok(res.not_checked.some((n) => /DNSSEC/.test(n)));
    assert.match(toDnsCsv(res), /^domain,check,name,type,status,value,observation\r\nexample\.org,spf,example\.org,TXT,present,v=spf1 \+all,/);
  } finally { await srv.close(); }
});

/* ---- the command line ---- */
const tmp = () => mkdtempSync(join(tmpdir(), "cvhello-"));
const io = (extra = {}) => { const out = [], err = []; return { out: (s) => out.push(s), err: (s) => err.push(s), sleep: async () => {}, publicWaitMs: 0, lines: { out, err },
  fetchImpl: () => { throw new Error("no network in this test"); }, resolve: async () => [{ address: "127.0.0.1", family: 4 }], ...extra }; };
const writeScope = (dir, targets) => { const p = join(dir, "scope.json"); writeFileSync(p, JSON.stringify({ cyberview_scope: 1, owner: "Example lab", contact: "lab@example.org",
  attestation: { statement: STATEMENT, agreed: true, name: "Test Operator", date: "2026-11-20", expires: "", authorization_ref: "test" }, targets, exclude: [] })); return p; };

test("CLI: flags are refused when misused; the header says identify and DNS records are off by default", async () => {
  const d = tmp(), scope = writeScope(d, ["127.0.0.1", "example.org"]);
  let x = io(); assert.equal(await main(["check", "--scope", scope, "--identify-bmc"], x), 2); assert.match(x.lines.err.join("\n"), /--identify-bmc needs --identify/);
  x = io(); assert.equal(await main(["check", "--scope", scope, "--dkim-selectors", "a"], x), 2);
  x = io(); assert.equal(await main(["check", "--scope", scope, "--dns-records", "other.example"], x), 2); assert.match(x.lines.err.join("\n"), /not a host name listed/);
  x = io(); assert.equal(await main(["check", "--scope", scope], x), 0);
  const h = x.lines.out.join("\n");
  assert.match(h, /Identify: +off/); assert.match(h, /DNS records: off/); assert.match(h, /identify-smtp +only with --identify/); assert.match(h, /dns-records +only with --dns-records/);
  x = io(); assert.equal(await main(["check", "--scope", scope, "--identify", "--identify-bmc", "--dns-records", "example.org", "--dkim-selectors", "s1"], x), 0);
  assert.match(x.lines.out.join("\n"), /Identify: +on .*BMC \(IPMI RMCP ping\) on/); assert.match(x.lines.out.join("\n"), /DNS records: on .*example\.org; DKIM selectors s1/);
});

test("CLI scan: without the flags no hello and no DNS query; with them, report fields and dns.csv", async () => {
  const d = tmp(), scope = writeScope(d, ["127.0.0.1", "example.org"]);
  const probe = async (ip, port) => (port === 25 ? { port, state: "open", banner: "220 mx.example.org ESMTP Postfix\r\n" } : { port, state: "closed" });
  const hello = { tcp: [], udp: [] }, dnsAsked = [];
  const helloTcp = async (ip, port, key) => { hello.tcp.push(`${key}:${port}`); return { service: key, port, proto: "tcp", state: "answered", sent: ["EHLO", "QUIT"], reply: SMTP_EHLO }; };
  const helloUdp = async (ip, key) => { hello.udp.push(key); return { service: key, port: HELLO[key].port, proto: "udp", state: "no-answer", sent: [] }; };
  const dnsResolver = { resolveTxt: async (n) => { dnsAsked.push(n); throw Object.assign(new Error("x"), { code: "ENODATA" }); }, resolveCaa: async (n) => { dnsAsked.push(n); return []; } };
  assert.equal(await main(["scan", "--scope", scope, "--data", SNAP, "--ports", "25", "--out", join(d, "a"), "--mail"], io({ probe, helloTcp, helloUdp, dnsResolver })), 0);
  assert.deepEqual([hello.tcp, hello.udp, dnsAsked], [[], [], []], "nothing is sent without --identify / --dns-records");
  const a = JSON.parse(readFileSync(join(d, "a", "report.json"), "utf8"));
  assert.deepEqual([a.run.identify, a.run.dns_records], [{ enabled: false }, { enabled: false }]);
  assert.match(a.run.network.sends["identify-smtp"], /^only with --identify/);
  assert.match(readFileSync(join(d, "a", "mail.csv"), "utf8"), /not checked/);
  assert.equal(await main(["scan", "--scope", scope, "--data", SNAP, "--ports", "25", "--out", join(d, "b"), "--mail", "--identify", "--dns-records", "example.org"], io({ probe, helloTcp, helloUdp, dnsResolver })), 0);
  assert.deepEqual(hello.tcp, ["smtp:25"], "one SMTP hello: the attested name resolves to the same loopback address (one host)");
  assert.deepEqual([...new Set(hello.udp)], ["mdns"]);
  assert.equal(dnsAsked.length, 5);
  const b = JSON.parse(readFileSync(join(d, "b", "report.json"), "utf8"));
  assert.deepEqual(b.run.identify, { enabled: true, bmc: false }); assert.equal(b.run.dns_records.enabled, true);
  assert.ok(b.hosts[0].identify.some((r) => r.service === "smtp" && r.read.starttls === true));
  assert.ok(b.dns.observations.some((o) => o.kind === "spf-missing"));
  assert.ok(readdirSync(join(d, "b")).includes("dns.csv"));
  assert.match(readFileSync(join(d, "b", "mail.csv"), "utf8"), /advertised in the EHLO\/CAPA reply/);
});

/* ---- security-check section 7: the hello and DNS rules fire ---- */
const SRC = (f) => readFileSync(join(ROOT, f), "utf8");
test("security check: the real modules pass; AUTH/USER/PASS/VRFY/EXPN/REGISTER/INVITE/AXFR, a second write, multicast or an ungated run fail", async () => {
  const helloSrc = SRC("scanner/lib/hello.mjs"), scanSrc = SRC("scanner/lib/scan.mjs"), dnsSrc = SRC("scanner/lib/dns-records.mjs");
  const mod = await import("../../scanner/lib/hello.mjs"), dnsMod = await import("../../scanner/lib/dns-records.mjs");
  const base = { helloSrc, mod, scanSrc, dnsSrc, dnsMod, otherSrcs: [] };
  assert.deepEqual(helloProblems(base), []);
  // a forbidden verb as a request literal in the source
  for (const v of ["AUTH PLAIN", "USER admin", "PASS x", "VRFY root", "EXPN staff", "REGISTER sip:x", "INVITE sip:x"]) {
    const bad = helloSrc.replace('request: "CAPA\\r\\n"', `request: "${v}\\r\\n"`);
    assert.notEqual(bad, helloSrc);
    assert.ok(helloProblems({ ...base, helloSrc: bad }).some((p) => /forbidden verb/.test(p)), v);
  }
  // the same in a loaded table (as if built some other way)
  for (const v of ["AUTH LOGIN\r\n", "USER a\r\n", "PASS b\r\n", "VRFY a\r\n", "EXPN a\r\n", "REGISTER sip:x SIP/2.0\r\n", "INVITE sip:x SIP/2.0\r\n", "OPTIONS x\r\nAUTH PLAIN\r\n"]) {
    const H = Object.freeze({ ...mod.HELLO, pop3: Object.freeze({ ...mod.HELLO.pop3, request: v }) });
    assert.ok(helloProblems({ ...base, mod: { ...mod, HELLO: H } }).some((p) => /pop3 request/.test(p)), v);
  }
  // a changed binary request, a second write, multicast, an ungated identifyHost, a call from elsewhere
  const H2 = Object.freeze({ ...mod.HELLO, ipmi: Object.freeze({ ...mod.HELLO.ipmi, hex: "0600ff0700000000000000000000000000000000" }) });
  assert.ok(helloProblems({ ...base, mod: { ...mod, HELLO: H2 } }).some((p) => /reviewed byte sequence/.test(p)));
  assert.ok(helloProblems({ ...base, helloSrc: helloSrc.replace("function say(sock, bytes) { sock.write(bytes); }", "function say(sock, bytes) { sock.write(bytes); sock.write(bytes); }") }).some((p) => /one \.write\(/.test(p)));
  assert.ok(helloProblems({ ...base, helloSrc: helloSrc + "\nconst g = \"224.0.0.251\";" }).some((p) => /multicast/.test(p)));
  assert.ok(helloProblems({ ...base, helloSrc: helloSrc.replace("if (!opts || opts.enabled !== true) return [];", "") }).some((p) => /refuse to run/.test(p)));
  assert.ok(helloProblems({ ...base, scanSrc: scanSrc.replace("if (identify && identify.enabled === true) {", "if (true) {") }).some((p) => /identifyHost may be called/.test(p)));
  assert.ok(helloProblems({ ...base, otherSrcs: [{ file: "scanner/lib/x.mjs", src: "tcpHello(ip, 25, 'smtp')" }] }).some((p) => /only scanner\/lib\/scan\.mjs/.test(p)));
  // DNS: AXFR, ANY or another record type fail; a changed prefix fails
  assert.ok(helloProblems({ ...base, dnsSrc: dnsSrc + "\nconst t = \"AXFR\";" }).some((p) => /TXT and CAA/.test(p)));
  assert.ok(helloProblems({ ...base, dnsSrc: dnsSrc.replace("resolveCaa(n)", "resolveAny(n)") }).some((p) => /TXT and CAA/.test(p)));
  const Q = Object.freeze([...dnsMod.QUERIES, Object.freeze({ check: "x", prefix: "www.", type: "NS" })]);
  assert.equal(helloProblems({ ...base, dnsMod: { ...dnsMod, QUERIES: Q } }).filter((p) => /not allowed|reviewed record name/.test(p)).length, 2);
  assert.ok(helloProblems({ ...base, otherSrcs: [{ file: "scanner/lib/x.mjs", src: "new Resolver()" }] }).some((p) => /only scanner\/lib\/dns-records\.mjs/.test(p)));
});

/* ---- lead decision: RDP, SMB2 and LDAP identify reads (one frozen binary message each) ---- */
const ber = (tag, ...parts) => { const v = Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(p)))); const l = v.length < 128 ? Buffer.from([v.length]) : v.length < 256 ? Buffer.from([0x81, v.length]) : Buffer.from([0x82, v.length >> 8, v.length & 255]); return Buffer.concat([Buffer.from([tag]), l, v]); };
const os = (s) => ber(0x04, s);
const RDP_TLS = Buffer.from("030000130ed00000123400021f080001000000", "hex");
function smbResponse(mode, dialect) {
  const h = Buffer.alloc(64); h.writeUInt32BE(0xfe534d42, 0); h.writeUInt16LE(64, 4); h.writeUInt16LE(1, 14); h.writeUInt32LE(1, 16);
  const b = Buffer.alloc(64); b.writeUInt16LE(65, 0); b.writeUInt16LE(mode, 2); b.writeUInt16LE(dialect, 4);
  const nb = Buffer.alloc(4); nb.writeUInt32BE(128); return Buffer.concat([nb, h, b]);
}
const LDAP_ENTRY = Buffer.concat([
  ber(0x30, ber(0x02, Buffer.from([1])), ber(0x64, os(""), ber(0x30, ber(0x30, os("objectClass"), ber(0x31, os("top"), os("OpenLDAProotDSE"))), ber(0x30, os("supportedLDAPVersion"), ber(0x31, os("3")))))),
  ber(0x30, ber(0x02, Buffer.from([1])), ber(0x65, ber(0x0a, Buffer.from([0])), os(""), os(""))),
]);

test("RDP, SMB and LDAP requests decode to exactly what the specs and the lead decision state", () => {
  const rdp = wire("rdp");
  assert.equal(rdp.length, 19); assert.equal(rdp.readUInt16BE(2), 19, "TPKT length"); assert.equal(rdp[5], 0xe0, "X.224 Connection Request");
  assert.equal(rdp[11], 0x01, "RDP_NEG_REQ"); assert.equal(rdp.readUInt32LE(15), 3, "requestedProtocols TLS|CredSSP");
  const smb = wire("smb");
  assert.equal(smb.readUInt32BE(0), smb.length - 4); assert.equal(smb.readUInt32BE(4), 0xfe534d42, "SMB2, never SMB1 (0xff 'SMB')");
  assert.equal(smb.readUInt16LE(16), 0, "Command NEGOTIATE"); assert.equal(smb.readUInt16LE(68), 36); assert.equal(smb.readUInt16LE(70), 4);
  assert.deepEqual([0, 1, 2, 3].map((i) => smb.readUInt16LE(104 + i * 2).toString(16)), ["202", "210", "300", "302"]);
  const ldap = wire("ldap");
  assert.equal(ldap[0], 0x30); assert.equal(ldap[5], 0x63, "SearchRequest, not a BindRequest (0x60)");
  assert.deepEqual([...ldap.subarray(7, 18)], [0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x01], "baseObject \"\", scope base, never deref, sizeLimit 1");
  const attrs = ldap.subarray(ldap.indexOf(Buffer.from("303e", "hex")) + 2);
  const names = []; for (let o = 0; o < attrs.length; o += 2 + attrs[o + 1]) names.push(attrs.subarray(o + 2, o + 2 + attrs[o + 1]).toString());
  assert.deepEqual(names, ["supportedLDAPVersion", "vendorName", "vendorVersion", "objectClass"]);
  assert.equal(Buffer.from(HELLO.ldap.closeHex, "hex")[5], 0x42, "the close is an UnbindRequest");
});

test("RDP, SMB and LDAP on loopback: exactly one request each (plus LDAP's unbind), nothing after", async () => {
  const rd = await tcpServer("", () => RDP_TLS), sm = await tcpServer("", () => smbResponse(1, 0x0302)), ld = await tcpServer("", (t) => (t.charCodeAt(5) === 0x63 ? LDAP_ENTRY : ""));
  try {
    const a = helloRecord(await tcpHello("127.0.0.1", rd.port, "rdp", { timeouts: FAST }));
    const b = helloRecord(await tcpHello("127.0.0.1", sm.port, "smb", { timeouts: FAST }));
    const c = helloRecord(await tcpHello("127.0.0.1", ld.port, "ldap", { timeouts: FAST }));
    await new Promise((x) => setTimeout(x, 100));
    assert.equal(Buffer.from(rd.bytes(), "latin1").toString("hex"), HELLO.rdp.hex, "no TLS, CredSSP or MCS after the Connection Confirm");
    assert.equal(Buffer.from(sm.bytes(), "latin1").toString("hex"), HELLO.smb.hex, "no SESSION_SETUP after the NEGOTIATE");
    assert.equal(Buffer.from(ld.bytes(), "latin1").toString("hex"), HELLO.ldap.hex + HELLO.ldap.closeHex, "the search, then the unbind; never a bind");
    assert.deepEqual(a.read, { confirm: true, selected: 1, protocol: "TLS", failure: "", nla: false });
    assert.deepEqual(b.read, { smb2: true, status: 0, dialect: "3.0.2", signing_enabled: true, signing_required: false });
    assert.deepEqual(c.read, { ok: true, versions: ["3"], vendor_name: "", vendor_version: "", object_classes: ["top", "OpenLDAProotDSE"] });
    const f = helloFindings([{ ...a, port: 3389 }, { ...b, port: 445 }, { ...c, port: 389 }]);
    assert.deepEqual(f.observations.map((o) => o.kind), ["rdp-no-nla", "smb-signing-not-required", "ldap-anonymous-rootdse"]);
    const ol = f.services.find((x) => x.product === "OpenLDAP"); assert.ok(ol && ol.guessed && ol.version === "");
  } finally { await rd.close(); await sm.close(); await ld.close(); }
});

test("RDP/SMB/LDAP parsers: NLA required, signing required, failures and junk", () => {
  assert.equal(parseRdp(Buffer.from("030000130ed00000123400021f080002000000", "hex")).nla, true);
  assert.deepEqual(parseRdp(Buffer.from("030000130ed000001234000300080005000000", "hex")), { confirm: true, selected: null, protocol: "", failure: "HYBRID_REQUIRED_BY_SERVER", nla: true });
  assert.equal(parseRdp(Buffer.from("0300000b06d00000123400", "hex")).protocol, "standard RDP security");
  assert.equal(parseRdp(Buffer.from("HTTP/1.1 400")).confirm, false);
  assert.equal(parseSmb(smbResponse(3, 0x0300)).signing_required, true);
  assert.equal(parseSmb(Buffer.from("00000010ff534d42", "hex")).smb2, false, "an SMB1 answer is not parsed");
  assert.equal(parseLdap(Buffer.from("300c02010165070a010004000400", "hex")).ok, false);
  assert.equal(ldapDone(LDAP_ENTRY), true); assert.equal(ldapDone(LDAP_ENTRY.subarray(0, 20)), false);
  assert.deepEqual(helloPlan(host({ ports: [{ port: 389, state: "open", banner: "" }, { port: 445, state: "open", banner: "" }, { port: 3389, state: "open", banner: "" }] }), { ports: [] }).map((x) => x.key), ["ldap", "smb", "rdp", "mdns"]);
});

test("security check: a changed RDP/SMB/LDAP byte, an LDAP bind or a non-unbind close fail", async () => {
  const mod = await import("../../scanner/lib/hello.mjs"), dnsMod = await import("../../scanner/lib/dns-records.mjs");
  const base = { helloSrc: SRC("scanner/lib/hello.mjs"), mod, scanSrc: SRC("scanner/lib/scan.mjs"), dnsSrc: SRC("scanner/lib/dns-records.mjs"), dnsMod, otherSrcs: [] };
  assert.deepEqual(helloProblems(base), []);
  const swap = (k, patch) => ({ ...base, mod: { ...mod, HELLO: Object.freeze({ ...mod.HELLO, [k]: Object.freeze({ ...mod.HELLO[k], ...patch }) }) } });
  const bind = "300c020101600702010304000400";   // an LDAP simple BindRequest (anonymous): refused
  assert.ok(helloProblems(swap("ldap", { hex: bind })).some((p) => /ldap binary request is not the reviewed/.test(p)));
  assert.ok(helloProblems(swap("ldap", { closeHex: bind })).some((p) => /ldap closeHex is not the reviewed/.test(p)));
  assert.ok(helloProblems(swap("rdp", { hex: HELLO.rdp.hex.replace(/03000000$/, "0b000000") })).some((p) => /rdp binary request/.test(p)));
  assert.ok(helloProblems(swap("smb", { hex: "00000054ff534d4272" })).some((p) => /smb binary request/.test(p)), "SMB1 negotiate refused");
});

/* ---- wave 4 (decision 24): Kafka ApiVersions, Redis PING, MQTT CONNECT, MongoDB hello ----
   Each is a frozen byte sequence built from the protocol's own published specification. The fixtures below answer the
   way the real service does, and every one records the exact bytes received, so the tests prove what goes on the wire. */

/** Wait until the fixture has actually recorded `want` bytes (the close packet lands just after tcpHello returns). */
async function until(fn, ms = 2000) {
  for (let i = 0; i < ms / 10; i++) { if (fn()) return true; await new Promise((r) => setTimeout(r, 10)); }
  return false;
}
/** A binary TCP server: answers each received Buffer with answer(buf); records every byte. */
async function binServer(answer = () => null) {
  const got = [], conns = [];
  const srv = net.createServer((s) => {
    conns.push(s); const mine = []; got.push(mine);
    s.on("data", (d) => { mine.push(Buffer.from(d)); const a = answer(Buffer.from(d), mine.length); if (a) s.write(a); });
    s.on("error", () => {});
  });
  const port = await new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
  return { port, got, first: () => Buffer.concat(got[0] || []), all: () => got.map((c) => Buffer.concat(c)), close: () => new Promise((r) => { conns.forEach((c) => c.destroy()); srv.close(() => r()); }) };
}

/* fixture encoders, built from the same specs as the requests */
const bsonDoc = (fields) => {   // bsonspec.org 1.1: int32 length (counting itself and the terminator), elements, 0x00
  const parts = [];
  for (const [k, v] of Object.entries(fields)) {
    const key = Buffer.concat([Buffer.from(k, "latin1"), Buffer.from([0])]);
    if (typeof v === "number" && Number.isInteger(v)) { const b = Buffer.alloc(4); b.writeInt32LE(v); parts.push(Buffer.concat([Buffer.from([0x10]), key, b])); }
    else if (typeof v === "boolean") parts.push(Buffer.concat([Buffer.from([0x08]), key, Buffer.from([v ? 1 : 0])]));
    else if (typeof v === "string") { const sv = Buffer.concat([Buffer.from(v, "utf8"), Buffer.from([0])]); const n = Buffer.alloc(4); n.writeInt32LE(sv.length); parts.push(Buffer.concat([Buffer.from([0x02]), key, n, sv])); }
  }
  const body = Buffer.concat(parts), out = Buffer.alloc(4 + body.length + 1);
  out.writeInt32LE(out.length, 0); body.copy(out, 4);
  return out;
};
const opMsgReply = (fields) => {   // MsgHeader (16, little-endian) + flagBits 0 + kind 0 + one BSON document
  const doc = bsonDoc(fields), h = Buffer.alloc(16);
  h.writeInt32LE(16 + 4 + 1 + doc.length, 0); h.writeInt32LE(7, 4); h.writeInt32LE(1, 8); h.writeInt32LE(2013, 12);
  return Buffer.concat([h, Buffer.alloc(4), Buffer.from([0]), doc]);
};
const kafkaReply = (apis, { correlation = 1, error = 0 } = {}) => {   // Response Header v0 + error_code + api_keys array
  const body = Buffer.concat([Buffer.alloc(4), Buffer.alloc(2), Buffer.alloc(4), ...apis.map(([k, lo, hi]) => { const b = Buffer.alloc(6); b.writeInt16BE(k, 0); b.writeInt16BE(lo, 2); b.writeInt16BE(hi, 4); return b; })]);
  body.writeInt32BE(correlation, 0); body.writeInt16BE(error, 4); body.writeInt32BE(apis.length, 6);
  const out = Buffer.alloc(4 + body.length); out.writeInt32BE(body.length, 0); body.copy(out, 4);
  return out;
};

test("the four wave-4 requests are the reviewed byte sequences, declared in SENDS and off by default", () => {
  for (const k of ["kafka", "redis", "mqtt", "mongodb"]) {
    const e = HELLO[k];
    assert.equal(e.hex, REVIEWED_HEX[k], `${k} must be the reviewed sequence`);
    assert.equal(e.flag, "--identify");
    assert.match(e.sends, /^only with --identify \(off by default\)/);
    assert.equal(HELLO_SENDS[`identify-${k}`], e.sends);
    assert.equal(wire(k).toString("hex"), REVIEWED_HEX[k]);   // no substitution: these carry no {target} or {ua}
    assert.ok(Object.isFrozen(e));
  }
  assert.equal(HELLO.mqtt.closeHex, REVIEWED_HEX["mqtt-close"]);
  // the MQTT client id must be inside the 1-23 bytes of 0-9a-zA-Z a broker MUST accept ([MQTT-3.1.3-5]): never a MAY
  const c = wire("mqtt"), idLen = c.readUInt16BE(12);
  assert.equal(idLen, 16);
  assert.match(c.subarray(14, 14 + idLen).toString("latin1"), /^[0-9a-zA-Z]{1,23}$/);
  assert.equal(c[0], 0x10);                                    // CONNECT, reserved flags 0
  assert.equal(c[1], c.length - 2);                            // remaining length does not count itself (2.2.3)
  assert.equal(c.subarray(2, 8).toString("hex"), "00044d515454");   // 00 04 "MQTT" (3.1.2.1)
  assert.equal(c[8], 0x04);                                    // protocol level 4 = MQTT 3.1.1 (3.1.2.2)
  assert.equal(c[9], 0x02);                                    // Clean Session only: no user name, password or will
  assert.equal(c.readUInt16BE(10), 0);                         // keep-alive off (3.1.2.10)
  // Kafka: size does not count itself; ApiVersions is api_key 18, version 0, client_id null (-1)
  const k = wire("kafka");
  assert.equal(k.readInt32BE(0), k.length - 4);
  assert.equal(k.readInt16BE(4), 18);
  assert.equal(k.readInt16BE(6), 0);
  assert.equal(k.readInt16BE(12), -1);
  // MongoDB: messageLength includes itself, opCode is OP_MSG, flagBits 0 (so no checksum), one Kind 0 body
  const m = wire("mongodb");
  assert.equal(m.readInt32LE(0), m.length);
  assert.equal(m.readInt32LE(12), 2013);
  assert.equal(m.readUInt32LE(16), 0);
  assert.equal(m[20], 0x00);
  assert.equal(m.readInt32LE(21), m.length - 21);              // the body document's own length is the section length
  // Redis: one RESP array of one bulk string, and nothing else
  assert.equal(wire("redis").toString("latin1"), "*1\r\n$4\r\nPING\r\n");
});

test("Kafka: ApiVersions is answered and counted, and a mismatched correlation id is not believed", async () => {
  const srv = await binServer(() => kafkaReply([[18, 0, 3], [0, 0, 9], [1, 0, 13]]));
  try {
    const r = await tcpHello("127.0.0.1", srv.port, "kafka", { timeouts: FAST });
    assert.equal(r.state, "answered");
    assert.equal(srv.first().toString("hex"), REVIEWED_HEX.kafka);   // exactly the reviewed bytes, nothing more
    const d = helloRecord(r).read;
    assert.equal(d.kafka, true);
    assert.equal(d.error_code, 0);
    assert.equal(d.apis, 3);
    assert.equal(d.api_versions_max, 3);
    const f = helloFindings([helloRecord(r)]);
    assert.equal(f.services[0].product, "Kafka");
    assert.equal(f.services[0].version, "");                         // no release is claimed from an API set
    assert.equal(f.services[0].guessed, true);
    assert.match(f.services[0].evidence, /no release number is published/);
    assert.deepEqual(f.observations.map((o) => o.kind), ["kafka-reachable"]);
    assert.match(f.observations[0].text, /before authentication by design/);
  } finally { await srv.close(); }
  // a reply whose correlation id is not the one sent is not a Kafka broker as far as this parser is concerned
  assert.equal(parseKafka(kafkaReply([[18, 0, 3]], { correlation: 99 })).kafka, false);
  assert.equal(parseKafka(Buffer.from("not kafka at all padding padding")).kafka, false);
  assert.equal(parseKafka(Buffer.alloc(0)).kafka, false);
});

test("Redis: +PONG is reported as no password at all; an error reply is reported as a password being set", async () => {
  const open = await binServer(() => Buffer.from("+PONG\r\n", "latin1"));
  try {
    const r = await tcpHello("127.0.0.1", open.port, "redis", { timeouts: FAST });
    assert.equal(open.first().toString("latin1"), "*1\r\n$4\r\nPING\r\n");
    const d = helloRecord(r).read;
    assert.deepEqual(d, { redis: true, pong: true, auth_required: false, error: "" });
    const f = helloFindings([helloRecord(r)]);
    assert.equal(f.observations[0].kind, "redis-no-auth");
    assert.equal(f.observations[0].severity, "high");
    assert.match(f.observations[0].text, /no password at all/);
    assert.equal(f.services[0].version, "");                         // PING carries no version, and none is guessed
  } finally { await open.close(); }
  // a server with requirepass refuses the command; the error is matched by its prefix, not by a remembered message
  const shut = await binServer(() => Buffer.from("-NOAUTH Authentication required.\r\n", "latin1"));
  try {
    const r = await tcpHello("127.0.0.1", shut.port, "redis", { timeouts: FAST });
    const d = helloRecord(r).read;
    assert.equal(d.redis, true);
    assert.equal(d.pong, false);
    assert.equal(d.auth_required, true);
    assert.equal(d.error, "NOAUTH");
    const f = helloFindings([helloRecord(r)]);
    assert.equal(f.observations[0].kind, "redis-auth-required");
    assert.equal(f.observations[0].severity, "info");
  } finally { await shut.close(); }
  // any other error prefix works the same way, which is the point of not matching a fixed string
  assert.equal(parseRedis("-ERR unknown command\r\n").auth_required, true);
  assert.equal(parseRedis("-WRONGPASS invalid\r\n").error, "WRONGPASS");
  assert.equal(parseRedis("random junk\r\n").redis, false);
  assert.equal(parseRedis("").redis, false);
});

test("MQTT: an accepted anonymous CONNECT is a high finding, a refusal is not, and DISCONNECT always follows", async () => {
  const accept = await binServer(() => Buffer.from([0x20, 0x02, 0x00, 0x00]));
  try {
    const r = await tcpHello("127.0.0.1", accept.port, "mqtt", { timeouts: FAST });
    assert.ok(await until(() => accept.first().length >= 32), "the DISCONNECT should reach the broker");
    assert.equal(accept.first().toString("hex"), REVIEWED_HEX.mqtt + REVIEWED_HEX["mqtt-close"]);   // CONNECT then DISCONNECT, nothing else
    assert.deepEqual(r.sent, ["mqtt request (30 bytes)", "mqtt close"]);
    const d = helloRecord(r).read;
    assert.equal(d.mqtt, true);
    assert.equal(d.code, 0);
    assert.equal(d.anonymous, true);
    assert.equal(d.session_present, false);
    const f = helloFindings([helloRecord(r)]);
    assert.equal(f.observations[0].kind, "mqtt-anonymous");
    assert.equal(f.observations[0].severity, "high");
    assert.match(f.observations[0].text, /no user name and no password/);
  } finally { await accept.close(); }
  const refuse = await binServer(() => Buffer.from([0x20, 0x02, 0x00, 0x05]));
  try {
    const r = await tcpHello("127.0.0.1", refuse.port, "mqtt", { timeouts: FAST });
    const d = helloRecord(r).read;
    assert.equal(d.code, 5);
    assert.equal(d.meaning, "not authorized");
    assert.equal(d.anonymous, false);
    const f = helloFindings([helloRecord(r)]);
    assert.equal(f.observations[0].kind, "mqtt-auth-required");
    assert.equal(f.observations[0].severity, "info");
  } finally { await refuse.close(); }
  // every code of Table 3.1 is named, and a reserved code is reported as reserved rather than guessed
  assert.equal(parseConnack(Buffer.from([0x20, 0x02, 0x00, 0x01])).meaning, "unacceptable protocol version");
  assert.equal(parseConnack(Buffer.from([0x20, 0x02, 0x00, 0x02])).meaning, "identifier rejected");
  assert.equal(parseConnack(Buffer.from([0x20, 0x02, 0x00, 0x03])).meaning, "server unavailable");
  assert.equal(parseConnack(Buffer.from([0x20, 0x02, 0x00, 0x04])).anonymous, false);
  assert.equal(parseConnack(Buffer.from([0x20, 0x02, 0x00, 0x09])).meaning, "reserved (9)");
  assert.equal(parseConnack(Buffer.from([0x20, 0x02, 0x01, 0x00])).session_present, true);
  assert.equal(parseConnack(Buffer.from([0x30, 0x02, 0x00, 0x00])).mqtt, false);   // not a CONNACK
  assert.equal(parseConnack(Buffer.from([0x20])).mqtt, false);
});

test("MongoDB: the hello reply is read for what it states, and no release number is inferred from the wire version", async () => {
  const srv = await binServer(() => opMsgReply({ isWritablePrimary: true, maxWireVersion: 21, minWireVersion: 0, readOnly: false, ok: 1 }));
  try {
    const r = await tcpHello("127.0.0.1", srv.port, "mongodb", { timeouts: FAST });
    assert.equal(srv.first().toString("hex"), REVIEWED_HEX.mongodb);
    const d = helloRecord(r).read;
    assert.equal(d.mongodb, true);
    assert.equal(d.ok, true);
    assert.equal(d.max_wire, 21);
    assert.equal(d.min_wire, 0);
    assert.equal(d.writable_primary, true);
    assert.equal(d.kind, "standalone or unknown");
    const f = helloFindings([helloRecord(r)]);
    assert.equal(f.services[0].vendor, "MongoDB");
    assert.equal(f.services[0].version, "");                        // the wire version is NOT turned into a release
    assert.match(f.services[0].label, /maxWireVersion 21/);
    assert.match(f.services[0].evidence, /no published mapping to a MongoDB release/);
    assert.equal(f.observations[0].kind, "mongodb-reachable");
    assert.match(f.observations[0].text, /does NOT mean the database is open/);
  } finally { await srv.close(); }
  // a mongos names itself; a replica set member gives its set name
  const mongos = await binServer(() => opMsgReply({ msg: "isdbgrid", maxWireVersion: 17, ok: 1 }));
  try {
    const d = helloRecord(await tcpHello("127.0.0.1", mongos.port, "mongodb", { timeouts: FAST })).read;
    assert.equal(d.kind, "mongos router");
  } finally { await mongos.close(); }
  const rs = await binServer(() => opMsgReply({ setName: "rs0", isWritablePrimary: false, maxWireVersion: 17, ok: 1 }));
  try {
    const d = helloRecord(await tcpHello("127.0.0.1", rs.port, "mongodb", { timeouts: FAST })).read;
    assert.equal(d.kind, "replica set member");
    assert.equal(d.set_name, "rs0");
    assert.equal(d.writable_primary, false);
  } finally { await rs.close(); }
  assert.equal(parseMongo(Buffer.alloc(30)).mongodb, false);        // not an OP_MSG
  assert.equal(parseMongo(Buffer.from("junk")).mongodb, false);
});

test("the BSON reader is bounded and refuses crafted input instead of trusting its lengths", () => {
  const good = bsonDoc({ a: 1, b: "two", c: true });
  assert.deepEqual(bsonFields(good), { a: 1, b: "two", c: true });
  // a length that claims more than the buffer holds
  const big = Buffer.from(good); big.writeInt32LE(0x7fffffff, 0);
  assert.deepEqual(bsonFields(big), {});
  // a negative and an absurd length
  const neg = Buffer.from(good); neg.writeInt32LE(-1, 0);
  assert.deepEqual(bsonFields(neg), {});
  // a string element whose length prefix runs past the document end: read nothing rather than past the buffer
  const s = bsonDoc({ k: "value" }); s.writeInt32LE(9999, 4 + 1 + 2);
  assert.deepEqual(bsonFields(s), {});
  // truncation at every offset must neither throw nor invent a field
  for (let i = 0; i <= good.length; i++) assert.doesNotThrow(() => bsonFields(good.subarray(0, i)));
  // an unknown element type stops the read instead of guessing a width
  const unk = Buffer.from(good); unk[4] = 0x6e;
  assert.deepEqual(bsonFields(unk), {});
  for (const junk of [Buffer.alloc(0), Buffer.alloc(4), Buffer.from([5, 0, 0, 0, 0]), "not a buffer", null, undefined]) assert.doesNotThrow(() => bsonFields(junk));
  assert.deepEqual(bsonFields(Buffer.from([5, 0, 0, 0, 0])), {});   // the empty document
  // a field name with no terminator
  assert.deepEqual(bsonFields(Buffer.concat([(() => { const b = Buffer.alloc(4); b.writeInt32LE(12); return b; })(), Buffer.from([0x10]), Buffer.from("abcdef", "latin1"), Buffer.from([0])])), {});
});

test("the new hellos are planned only on their own ports, only when the port is open", () => {
  const h = (ports) => ({ address: "10.0.0.5", ports: ports.map((port) => ({ port, state: "open" })), services: [], tls: [] });
  const keys = (host, opts = {}) => helloPlan(host, opts).map((x) => `${x.key}:${x.port}`);
  assert.ok(keys(h([9092])).includes("kafka:9092"));
  assert.ok(keys(h([6379])).includes("redis:6379"));
  assert.ok(keys(h([1883])).includes("mqtt:1883"));
  assert.ok(keys(h([27017])).includes("mongodb:27017"));
  assert.ok(keys(h([27019])).includes("mongodb:27019"));
  // a closed port gets nothing, and a port none of them claims gets nothing
  assert.deepEqual(keys({ address: "10.0.0.5", ports: [{ port: 6379, state: "closed" }], services: [], tls: [] }).filter((x) => x.startsWith("redis")), []);
  assert.deepEqual(keys(h([12345])).filter((x) => /kafka|redis|mqtt|mongodb/.test(x)), []);
  // a TLS port is skipped: these are cleartext hellos
  assert.deepEqual(helloPlan({ address: "10.0.0.5", ports: [{ port: 6379, state: "open" }], services: [], tls: [{ port: 6379 }] }).filter((x) => x.key === "redis"), []);
  // one entry per service even when several of its ports are open
  assert.equal(keys(h([27017, 27018, 27019])).filter((x) => x.startsWith("mongodb")).length, 1);
});

test("probeAll end to end: an open Redis port gets zero bytes without --identify, and exactly PING with it", async () => {
  // the service answers +PONG the way an unprotected Redis does; the scan reaches it on its real port
  const s = await binServer(() => Buffer.from("+PONG\r\n", "latin1"));
  try {
    const st = settings({}).settings;
    const off = await probeAll(LOCAL, { ports: [s.port], settings: st, assumeUp: true });
    await new Promise((x) => setTimeout(x, 100));
    assert.equal(Buffer.concat(s.all()).length, 0, "no --identify: not one byte is written to the Redis port");
    assert.equal(off.hosts[0].identify, undefined);
    // the hello is planned by port number, so the fixture's ephemeral port is mapped onto Redis's own
    const plan = helloPlan({ address: "127.0.0.1", ports: [{ port: 6379, state: "open" }], services: [], tls: [] });
    assert.ok(plan.some((p) => p.key === "redis" && p.port === 6379));
    const r = await tcpHello("127.0.0.1", s.port, "redis", { timeouts: FAST });
    await new Promise((x) => setTimeout(x, 50));
    assert.equal(Buffer.concat(s.all()).toString("hex"), REVIEWED_HEX.redis, "with --identify: exactly the reviewed PING, nothing else");
    assert.equal(helloRecord(r).read.pong, true);
  } finally { await s.close(); }
});
