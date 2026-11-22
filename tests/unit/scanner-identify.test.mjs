// Passive identify pack (scanner/lib/fp-identify.mjs): products named from data the scan already collected — the greeting,
// the one GET / response (title, headers, cookie names, recorded Location, body markers) and the TLS certificate. No real
// host is contacted: pure fixtures, and loopback stand-ins that record every byte the scanner sends them.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import http from "node:http";
import { readFileSync } from "node:fs";
import { RULES, CATALOG_IDS, identify, facts } from "../../scanner/lib/fp-identify.mjs";
import { servicesOf, probeAll } from "../../scanner/lib/scan.mjs";
import { probePort } from "../../scanner/lib/probe.mjs";
import { cleanFlaws, findings } from "../../scanner/lib/match.mjs";
import { summarize } from "../../scanner/lib/report.mjs";
import { settings } from "../../scanner/lib/limits.mjs";

const TODAY = "2026-11-22";
const page = (body, headers = {}, status = 200) => ({ port: 80, state: "open", banner: "", raw: null, tls: null, http: { status, headers: { "content-type": "text/html", ...headers }, body } });
const titled = (t, extra = "", headers = {}) => page(`<!doctype html><html><head><title>${t}</title></head><body>${extra}</body></html>`, headers);
const greet = (banner, port = 25) => ({ port, state: "open", banner, raw: null, http: null, tls: null });
const one = (r) => { const s = identify(r); assert.equal(s.length, 1, JSON.stringify(s)); return s[0]; };
const none = (r) => assert.deepEqual(identify(r).map((s) => s.label), []);

// an OpenWire WireFormatInfo frame as a broker sends it on connect (loose encoding: size, type 1, magic, a property map)
function openwire(version) {
  const str = (s) => { const b = Buffer.from(s, "latin1"), l = Buffer.alloc(2); l.writeUInt16BE(b.length); return Buffer.concat([l, b]); };
  const prop = (k, v) => Buffer.concat([str(k), Buffer.from([0x09]), str(v)]);
  const props = Buffer.concat([prop("ProviderName", "ActiveMQ"), prop("ProviderVersion", version), prop("PlatformDetails", "JVM: 17")]);
  const body = Buffer.concat([Buffer.from([0x01]), Buffer.from("ActiveMQ"), Buffer.from([0, 0, 0, 12, 1]), props]);
  const size = Buffer.alloc(4); size.writeUInt32BE(body.length);
  return Buffer.concat([size, body]);
}

/* ---- the table ---- */
const BUILT = ["gitlab-community-and-enterprise-editions", "gitlab-community-edition-and-enterprise-edition", "apache-activemq", "apache-rocketmq", "pi-hole-adminlte",
  "adminer-adminer", "apache-couchdb", "elasticsearch-root-document", "mongodb-mongo-express", "opensearch-root-document", "phpmyadmin-phpmyadmin",
  "broadcom-vmware-aria-operations", "broadcom-vmware-esx", "broadcom-vmware-vcenter", "dell-recoverpoint-for-virtual-machines-rp4vms", "vmware-vrealize-operations-manager-api",
  "hikvision-security-cameras-web-server", "papercut-mf-ng", "reolink-multiple-ip-cameras", "reolink-rlc-410w-ip-camera", "solarview-compact",
  "vmware-workspace-one-access-and-identity-manager", "opensmtpd", "qmail", "cwp-control-web-panel", "cyberpersons-cyberpanel", "hewlett-packard-enterprise-hpe-oneview",
  "alcatel-omnipcx-enterprise", "grandstream-ucm6200", "ignite-realtime-openfire", "mitel-sip-phones", "unrealircd"];
// rows that need a new request, port, hello or datagram (or have no sourced signal): never in the passive table
const SKIPPED = ["puppet-server", "postgresql-handshake", "xenserver-or-xcp-ng", "ietf-service-location-protocol-slp", "verifone-or-ingenico-terminal-service"];

test("identify table: every built catalog ID is covered once, the skipped rows are absent, every rule is well formed", () => {
  assert.deepEqual([...CATALOG_IDS].sort(), [...BUILT].sort());
  for (const id of SKIPPED) assert.ok(!CATALOG_IDS.includes(id), id);
  const ids = new Set();
  for (const r of RULES) {
    assert.ok(!ids.has(r.id), `duplicate rule ${r.id}`); ids.add(r.id);
    assert.ok(r.catalog.length && r.signals.length && r.vendor, r.id);
    for (const s of r.signals) assert.ok(typeof s.why === "string" && s.why.length > 5 && s.why.length < 120, `${r.id}: fixed evidence wording`);
  }
});

test("identify module is pure: no network module, no path, no request", () => {
  const src = readFileSync(new URL("../../scanner/lib/fp-identify.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(src, /node:(net|tls|http|https|dgram|child_process)|\bfetch\s*\(|\.request\s*\(|\.connect\s*\(/);
  assert.doesNotMatch(src, /from\s+["']\.\/(probe|udp)\.mjs["']/);
});

/* ---- web root page: titles, body markers, headers, cookie names, redirects ---- */
test("GitLab: cookie _gitlab_session or the about.gitlab.com marker; a bare /users/sign_in redirect (Devise) is not enough", () => {
  const a = one(page("<html><body>You are being redirected.</body></html>", { location: "http://git.lab/users/sign_in", "set-cookie": ["_gitlab_session=deadbeefcafe; path=/; HttpOnly"] }, 302));
  assert.equal(a.product, "GitLab"); assert.equal(a.guessed, true); assert.equal(a.version, "");
  assert.doesNotMatch(JSON.stringify(a), /deadbeefcafe/, "cookie values are never kept");
  const b = one(titled("Sign in · GitLab", '<a href="https://about.gitlab.com/">About GitLab</a>'));
  assert.equal(b.product, "GitLab");
  none(page("redirect", { location: "/users/sign_in", "set-cookie": "_myapp_session=1" }, 302));
});

test("ActiveMQ: OpenWire frame read on connect gives the stated ProviderVersion; the console title alone is version-less", () => {
  const s = one(greet(openwire("5.15.15").toString("latin1"), 61616));
  assert.equal(s.product, "ActiveMQ"); assert.equal(s.vendor, "Apache"); assert.equal(s.version, "5.15.15"); assert.equal(s.guessed, false); assert.equal(s.proto, "openwire");
  const c = one(titled("Apache ActiveMQ"));
  assert.equal(c.product, "ActiveMQ"); assert.equal(c.guessed, true);
  assert.equal(one(page("<h2>Welcome to the Apache ActiveMQ!</h2>")).product, "ActiveMQ");
});

test("web consoles named by their root title only (RocketMQ, Pi-hole, mongo-express, CyberPanel, PaperCut, Reolink): no version, guessed", () => {
  const cases = [["RocketMq-console-ng", "RocketMQ"], ["Pi-hole - raspberrypi", "Pi-hole AdminLTE"], ["Home - Mongo Express", "mongo-express"],
    ["Login - CyberPanel", "CyberPanel"], ["PaperCut Login for ACME", "PaperCut MF/NG"], ["Reolink", "Reolink IP camera"]];
  for (const [t, p] of cases) { const s = one(titled(t)); assert.equal(s.product, p, t); assert.equal(s.guessed, true, t); assert.equal(s.shown_version, "", t); }
  assert.equal(one(page('<meta name="description" content="PaperCut NG print management">')).product, "PaperCut MF/NG");
  assert.equal(one(page("<p>Pi-hole: A black hole for Internet advertisements</p>")).product, "Pi-hole AdminLTE");
  none(titled("Reolink fan club news"));   // the title must END with Reolink
  none(titled("My blog about Mongo Express"));
});

test("versions only where the page states them: Adminer, Aria Operations / vRealize, HPE OneView, Openfire", () => {
  const ad = one(titled("Login - Adminer", '<span class="version">4.7.8</span>'));
  assert.deepEqual([ad.product, ad.version, ad.guessed], ["Adminer", "4.7.8", false]);
  assert.equal(one(titled("Login - Adminer")).guessed, true);
  const vr = one(titled("vRealize Operations Manager", '<script src="js/SessionProvider.js?version=8.6.2.19081814"></script>'));
  assert.deepEqual([vr.product, vr.shown_version, vr.version, vr.guessed], ["Aria Operations (vRealize Operations Manager)", "8.6.2.19081814", "8.6.2.19081814", false]);
  assert.equal(one(titled("VMware Aria Operations")).guessed, true);
  const ov = one(titled("OneView", '<script>var artifactVersion = "8.90.0";</script>'));
  assert.deepEqual([ov.vendor, ov.product, ov.version, ov.guessed], ["HPE", "OneView", "8.90.0", false]);
  const of = one(titled("Openfire Admin Console", "<p>Openfire, Version: 4.7.4</p>"));
  assert.deepEqual([of.product, of.version, of.guessed], ["Openfire", "4.7.4", false]);
});

test("CouchDB: Server header or welcome JSON; Elasticsearch and OpenSearch from the root JSON document, told apart by distribution", () => {
  const h = one(page('{"error":"unauthorized"}', { server: "CouchDB/3.2.1 (Erlang OTP/23)", "content-type": "application/json" }));
  assert.deepEqual([h.product, h.version, h.guessed], ["CouchDB", "3.2.1", false]);
  const w = one(page('{"couchdb":"Welcome","version":"3.3.2","git_sha":"11a234070","uuid":"x","features":[],"vendor":{"name":"The Apache Software Foundation"}}', { "content-type": "application/json" }));
  assert.deepEqual([w.product, w.version, w.source], ["CouchDB", "3.3.2", "passive identify (root JSON document)"]);
  const doc = (v) => JSON.stringify({ name: "node-1", cluster_name: "prod search", cluster_uuid: "abc", version: v, tagline: "You Know, for Search" });
  const es = one(page(doc({ number: "7.10.2", build_flavor: "default" }), { "content-type": "application/json" }));
  assert.deepEqual([es.vendor, es.product, es.version, es.guessed], ["Elastic", "Elasticsearch", "7.10.2", false]);
  assert.match(es.evidence, /cluster prod\?search/);
  const os = one(page(doc({ distribution: "opensearch", number: "2.11.0" }), { "content-type": "application/json" }));
  assert.deepEqual([os.product, os.version], ["OpenSearch", "2.11.0"]);
  none(page('{"cluster_name":"x"}'));
  none(page("{not json"));
});

test("phpMyAdmin from the title or the reviewed login markers; CWP from Server, cookie name or title", () => {
  assert.equal(one(titled("phpMyAdmin")).product, "phpMyAdmin");
  for (const m of ['<img alt="phpMyAdmin" src="logo.png">', '<input name="pma_username">', '<link href="themes/pmahomme/css/theme.css">']) assert.equal(one(page(m)).product, "phpMyAdmin", m);
  assert.equal(one(page("x", { server: "cwpsrv" })).product, "Control Web Panel");
  const ck = one(page("x", { "set-cookie": ["cwpsrv-0123456789abcdef0123456789abcdef=SECRETVALUE; path=/"] }));
  assert.equal(ck.product, "Control Web Panel"); assert.doesNotMatch(JSON.stringify(ck), /SECRETVALUE/);
  assert.equal(one(titled("Login | CentOS WebPanel")).label, "CWP Control Web Panel (CentOS Web Panel)");
  none(page("x", { "set-cookie": "cwpsrv-short=1" }));
});

test("VMware: ESXi from esxUiApp / ID_ESX_Welcome, vCenter from /ui or /websso/ plus vSphere strings (never on an ESXi page), Workspace ONE from /SAAS/", () => {
  assert.equal(one(page('<html ng-app="esxUiApp">')).product, "ESXi");
  assert.equal(one(page("<script>document.write(ID_EESX_Welcome)</script>")).product, "ESXi");
  none(page('<meta http-equiv="refresh" content="0;URL=\'/ui\'">'));   // a bare refresh to /ui is not used alone
  assert.equal(one(page('<a href="/ui/">Launch vSphere Client</a> VMware vSphere')).product, "vCenter Server");
  assert.equal(one(page("<p>VMware vCenter</p>", { location: "https://vc.lab/websso/SAML2/SSO" }, 302)).product, "vCenter Server");
  const esx = identify(page('<html ng-app="esxUiApp"><a href="/ui/">VMware vSphere</a>'));
  assert.deepEqual(esx.map((s) => s.product), ["ESXi"]);
  assert.equal(one(page("", { location: "/SAAS/apps/" }, 302)).product, "Workspace ONE Access (Identity Manager)");
  assert.equal(one(page('<form action="/SAAS/auth/login">')).product, "Workspace ONE Access (Identity Manager)");
  none(page("", { location: "/saas/" }, 302));
});

test("cameras, solar and building-adjacent devices: identification only from what was collected (Hikvision, SolarView, RecoverPoint)", () => {
  for (const sv of ["Hikvision-Webs", "DNVRS-Webs", "DVRDVS-Webs"]) assert.equal(one(page("", { server: sv }, 401)).vendor, "Hikvision", sv);
  assert.equal(one(page("", { "www-authenticate": 'Digest realm="Hikvision", nonce="x"' }, 401)).vendor, "Hikvision");
  const cert = { subject: { CN: "www.hikvision.com", OU: "DVRNVR", O: "HIKVISION" }, issuer: { CN: "www.hikvision.com", OU: "DVRNVR", O: "HIKVISION" }, valid_from: "Jan 1 00:00:00 2020 GMT", valid_to: "Jan 1 00:00:00 2030 GMT" };
  const t = one({ port: 443, state: "open", banner: "", http: null, tls: { cert } });
  assert.deepEqual([t.vendor, t.proto, t.source, t.guessed], ["Hikvision", "https", "passive identify (TLS certificate)", true]);
  none({ port: 443, state: "open", banner: "", http: null, tls: { cert: { subject: { CN: "x", O: "HIKVISION FANS LTD" }, issuer: {} } } });
  const sv = one(page("<h1>SolarView Compact</h1>"));
  assert.deepEqual([sv.vendor, sv.product, sv.guessed], ["Contec", "SolarView Compact", true]);
  const rp = one(page("<div>RecoverPoint Wizard</div>"));
  assert.deepEqual([rp.vendor, rp.guessed], ["Dell", true]);
});

test("VoIP and chat: OmniPCX FTP greeting, Grandstream UCM6200 only with a UCM marker, Mitel generic (never matched to a product), Openfire", () => {
  const ftp = "220 Alize Session Manager FTP Server\r\n";
  const s = servicesOf(greet(ftp, 21));
  assert.ok(s.some((x) => x.product === "OmniPCX Enterprise" && x.proto === "ftp" && x.guessed), JSON.stringify(s));
  assert.equal(one(titled("Grandstream Device Configuration", '<script src="js/tl.account.ucm.js"></script>')).product, "UCM6200 series");
  assert.equal(one(titled("Grandstream Device Configuration", "<p>UCM6208</p>")).product, "UCM6200 series");
  none(titled("Grandstream Device Configuration", "<p>GXP2170</p>"));
  assert.equal(one(greet("\xff\xfb\x01Grandstream UCM6204 Command Shell\r\nPassword: ", 23)).proto, "telnet");
  none(greet("Grandstream GXW4216 Command Shell\r\n", 23));
  const m = one(page("<footer>Copyright Mitel Networks Corporation</footer>"));
  assert.deepEqual([m.vendor, m.product], ["Mitel", ""]);
});

test("mail and IRC greetings: OpenSMTPD, qmail, UnrealIRCd named, version-less; the greeting parser still runs first", () => {
  const o = servicesOf(greet("220 mx.example.lan ESMTP OpenSMTPD\r\n"));
  assert.ok(o.some((x) => x.label === "SMTP server"), "the existing greeting parse is kept");
  const os = o.find((x) => x.product === "OpenSMTPD"); assert.ok(os); assert.deepEqual([os.vendor, os.proto, os.guessed], ["OpenBSD", "smtp", true]);
  assert.equal(one(greet("220 mail.example.lan ESMTP qmail\r\n")).product, "qmail");
  assert.equal(one(greet(":irc.example.lan NOTICE * :*** UnrealIRCd here, looking up your hostname...\r\n", 6667)).product, "UnrealIRCd");
  none(greet("220 mx.example.lan ESMTP Postfix\r\n"));
  none(greet("SSH-2.0-OpenSSH_9.6\r\n", 22));
});

test("nothing is identified from nothing, and a product already named on the port is not added twice", () => {
  assert.deepEqual(identify(null), []); assert.deepEqual(identify({ port: 80 }), []);
  none(titled("Fixture intranet")); none(page(""));
  const r = titled("Login - Adminer", '<span class="version">4.8.1</span>');
  assert.deepEqual(identify(r, [{ product: "Adminer" }]), []);
  assert.equal(facts(page("x", { "set-cookie": ["a=1", "b=2; Secure"] })).cookies.join(","), "a,b");
});

test("evidence is fixed rule wording and the version read: never the body or a cookie value", () => {
  const secret = "s3cr3t-token-in-the-page";
  const s = one(titled("Openfire Admin Console", `<p>${secret}</p><p>Openfire, Version: 4.7.5</p>`, { "set-cookie": `JSESSIONID=${secret}` }));
  assert.doesNotMatch(JSON.stringify(s), new RegExp(secret));
  assert.ok(s.evidence.length <= 200); assert.match(s.evidence, /passive: data already collected/);
});

/* ---- findings: a stated version can be a headline; an identification without one stays low confidence ---- */
test("findings: a stated version inside a range is high confidence; a version-less identification stays out of the headline counts", () => {
  const wb = { kev: [
    { cve: "CVE-2026-90951", vendor: "Apache", product: "ActiveMQ", name: "fixture ActiveMQ flaw", added: "2026-11-01", due: "2026-11-21", cvss: 9.8, av: "N", affected: [{ vendor: "apache", product: "activemq", to: "5.15.16" }] },
    { cve: "CVE-2026-90952", vendor: "Pi-hole", product: "AdminLTE", name: "fixture Pi-hole flaw", added: "2026-11-01", due: "2026-11-21", cvss: 9.1, av: "N", affected: [{ vendor: "pi-hole", product: "pi-hole", to: "4.4" }] },
  ] };
  const flaws = cleanFlaws(wb);
  const host = { address: "127.0.0.1", names: [], up: true, ports: [], services: [...identify(greet(openwire("5.15.15").toString("latin1"), 61616)), ...identify(titled("Pi-hole"))] };
  const f = findings([host], flaws, new Map(), { today: TODAY });
  const amq = f.find((x) => x.cve === "CVE-2026-90951"), ph = f.find((x) => x.cve === "CVE-2026-90952");
  assert.equal(amq.state, "affected"); assert.equal(amq.confidence, "high");
  assert.equal(ph.state, "check"); assert.equal(ph.confidence, "low");
  const sum = summarize([host], f);
  assert.equal(sum.low_confidence, 1); assert.equal(sum.known_exploited, 1);
});

/* ---- the scan path, and the bytes on the wire ---- */
test("probeAll: identification comes from the one probe result per port (probe called exactly once per port)", async () => {
  const calls = [];
  const probe = async (ip, port) => { calls.push(port); return port === 80 ? { ...titled("Home - Mongo Express"), port } : port === 25 ? { ...greet("220 mx ESMTP OpenSMTPD\r\n"), port } : { port, state: "closed", banner: "", http: null, tls: null }; };
  const st = settings({}).settings;
  const out = await probeAll([{ address: "127.0.0.1", names: [], kind: "loopback", public: false }], { ports: [25, 80, 443], settings: st, probe, assumeUp: true });
  assert.deepEqual(calls.sort((a, b) => a - b), [25, 80, 443]);
  const prods = out.hosts[0].services.map((s) => s.product);
  assert.ok(prods.includes("mongo-express") && prods.includes("OpenSMTPD"), prods.join(","));
});

function recorder(handler) {
  const got = { connections: 0, bytes: [] };
  const srv = net.createServer((s) => { got.connections++; s.on("data", (d) => got.bytes.push(d)); s.on("error", () => {}); handler(s); });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ port: srv.address().port, got, close: () => new Promise((q) => srv.close(() => q())) })));
}

test("loopback: a greeting service (OpenWire, SMTP) receives zero bytes and is identified from what it sent", async () => {
  const amq = await recorder((s) => { s.write(openwire("5.18.2")); setTimeout(() => s.end(), 1500); });
  const smtp = await recorder((s) => { s.write("220 mx.example.lan ESMTP OpenSMTPD\r\n"); setTimeout(() => s.end(), 1500); });
  try {
    const a = await probePort("127.0.0.1", amq.port);
    const id = servicesOf(a).find((x) => x.product === "ActiveMQ");
    assert.ok(id); assert.equal(id.version, "5.18.2");
    const b = await probePort("127.0.0.1", smtp.port);
    assert.ok(servicesOf(b).some((x) => x.product === "OpenSMTPD"));
    for (const g of [amq.got, smtp.got]) { assert.equal(g.connections, 1); assert.equal(Buffer.concat(g.bytes).length, 0, "nothing was sent to a greeting service"); }
  } finally { await amq.close(); await smtp.close(); }
});

test("loopback: a web service sees exactly one connection and one GET / (no extra path, no redirect followed)", async () => {
  const reqs = []; let conns = 0;
  const srv = http.createServer((req, res) => {
    reqs.push(`${req.method} ${req.url}`);
    res.writeHead(302, { Location: "/users/sign_in", "Set-Cookie": "_gitlab_session=abc123; path=/; HttpOnly", "Content-Type": "text/html" });
    res.end("<html><body>You are being redirected.</body></html>");
  });
  srv.on("connection", () => { conns++; });
  const port = await new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
  try {
    const r = await probePort("127.0.0.1", port, { httpPorts: [port] });
    const g = servicesOf(r).find((x) => x.product === "GitLab");
    assert.ok(g); assert.equal(g.guessed, true); assert.doesNotMatch(JSON.stringify(g), /abc123/);
    assert.deepEqual(reqs, ["GET /"]); assert.equal(conns, 1);
  } finally { await new Promise((q) => { if (srv.closeAllConnections) srv.closeAllConnections(); srv.close(() => q()); }); }
});
