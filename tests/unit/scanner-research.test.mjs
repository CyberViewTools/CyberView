// Research pack (scanner/lib/fp-research.mjs, scan-research-pack): fingerprints from public references (Recog, Nmap, Wappalyzer,
// nuclei, the products' own source), read ONLY from data the scan already collects: the greeting, the one root-page response,
// the TLS certificate and the existing DNS version.bind answer. Plus the one rail row the lead accepted on 2026-11-22
// (ivanti-connect-secure-version-path). No real host is contacted: pure fixtures and loopback stand-ins that record every byte.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import http from "node:http";
import { RULES, DNS_RULES, RESEARCH_IDS, research, withResearch, withResearchUdp } from "../../scanner/lib/fp-research.mjs";
import { servicesOf, probeAll } from "../../scanner/lib/scan.mjs";
import { RAIL, RAIL_PATHS, railEvidence, railPlan, railResult } from "../../scanner/lib/paths.mjs";
import { settings } from "../../scanner/lib/limits.mjs";

const LOCAL = [{ address: "127.0.0.1", names: [], kind: "loopback", public: false }];
const page = (body, headers = {}, port = 80) => ({ port, state: "open", banner: "", raw: null, tls: null, http: { status: 200, headers: { "content-type": "text/html", ...headers }, body } });
const titled = (t, extra = "", headers = {}) => page(`<!doctype html><html><head><title>${t}</title></head><body>${extra}</body></html>`, headers);
const hdr = (headers, body = "<p>ok</p>") => page(body, headers);
const greet = (banner, port = 25) => ({ port, state: "open", banner, raw: null, http: null, tls: null });
const withCert = (subject, issuer = subject, port = 443) => ({ port, state: "open", banner: "", raw: null, http: null, tls: { protocol: "TLSv1.3", cert: { subject, issuer, valid_from: "Jan 1 00:00:00 2025 GMT", valid_to: "Jan 1 00:00:00 2030 GMT", subjectaltname: "" } } });
const one = (r) => { const s = research(r); assert.equal(s.length, 1, JSON.stringify(s)); return s[0]; };
const none = (r) => assert.deepEqual(research(r).map((s) => s.label), []);
const bin = (bytes, tail = "") => Buffer.from(bytes).toString("latin1") + tail;

// the rows that need a reply to a message the scanner does not send: never built here (listed under "needs a hello")
const NEEDS_HELLO = ["apache-kafka-protocol-identification", "mqtt-connect-identification", "redis-ping-identification", "acme-http-01-or-tls-alpn-challenge-leftover",
  "microsoft-sql-server-handshake", "oracle-database-tns-listener", "jetdirect-identification", "rdp-protocol-identification", "smb-protocol-identification", "ldap-root-dse"];

/* ---- the table ---- */
test("the table: frozen, every rule cites a public https source, 55 research rows built, hello-only rows absent", () => {
  assert.ok(Object.isFrozen(RULES) && Object.isFrozen(DNS_RULES) && RULES.every((r) => Object.isFrozen(r) && Object.isFrozen(r.signals)));
  for (const r of [...RULES, ...DNS_RULES]) { assert.match(r.src, /^https:\/\/[a-z0-9.-]+\/\S+$/, r.id); assert.ok(r.vendor && r.product, r.id); }
  assert.equal(RESEARCH_IDS.length, 55);
  for (const id of NEEDS_HELLO) assert.equal(RESEARCH_IDS.includes(id), false, id);
  // signals read only collected fields
  const allowed = new Set(["title", "body", "server", "location", "banner", "cookie", "header", "subject", "issuer", "why", "model"]);
  for (const r of RULES) for (const s of r.signals) { for (const k of Object.keys(s)) assert.ok(allowed.has(k), `${r.id}: ${k}`); assert.ok(s.why, r.id); }
});

/* ---- one positive fixture per built rule (the research output's quoted tokens) ---- */
const POS = [
  ["Notebook", titled("Jupyter Notebook")], ["JupyterLab", titled("JupyterLab")], ["Jupyter Server", titled("Jupyter Server")], ["JupyterHub", titled("JupyterHub")],
  ["Langflow", titled("Langflow")], ["MLflow", titled("MLflow")], ["Ray", titled("Ray Dashboard")], ["GeoServer", titled("GeoServer: Welcome")],
  ["OFBiz", hdr({ "set-cookie": ["OFBiz.Visitor=10000; Path=/"] })],
  ["n8n", page('<html><head><meta name="n8n:config:rest-endpoint" content="cmVzdA=="></head></html>')], ["n8n", hdr({ "set-cookie": ["n8n-auth=x; Path=/"] })],
  ["NetWeaver", hdr({ server: "SAP NetWeaver Application Server 7.45 / ICM 745" })], ["NetWeaver", hdr({ server: "SAP J2EE Engine/7.00" })], ["NetWeaver", hdr({ server: "SAP NetWeaver Application Server (ICM)" })],
  ["Bitbucket", hdr({ "set-cookie": ["BITBUCKETSESSIONID=abc; Path=/"] })], ["Bitbucket", titled("Log in - Bitbucket")],
  ["Confluence", hdr({ "x-confluence-request-time": "1732270000000" })], ["Confluence", titled("Log In - Confluence")],
  ["Jira", page('<meta name="application-name" content="JIRA" data-name="jira" data-version="9.12.2">')],
  ["Gogs", hdr({ "set-cookie": ["i_like_gogits=abc; Path=/"] })],
  ["Boundary", page('<meta name="description" content="Simple and secure remote access with HashiCorp Boundary.">')], ["Consul", titled("Consul by HashiCorp")],
  ["Rocket.Chat", hdr({ "x-rocket-chat-version": "6.5.2" })], ["Rocket.Chat", page('<meta name="application-name" content="Rocket.Chat">')], ["Rocket.Chat", titled("Rocket.Chat")],
  ["Distribution registry", hdr({ "docker-distribution-api-version": "registry/2.0" })],
  ["Harbor", page("<body><harbor-app></harbor-app></body>")], ["Harbor", titled("Harbor")],
  ["Data ONTAP", hdr({ server: "NetApp/7.3.4P1" })], ["Data ONTAP", greet("SSH-2.0-Data ONTAP SSH 1.0\r\n", 22)],
  ["DiskStation Manager", page('<meta name="application-name" content="Synology DiskStation">')], ["DiskStation Manager", titled("nas01 - Synology DiskStation")], ["DiskStation Manager", hdr({ server: "Synology/DSM/192.168.1.2" })],
  ["FreeNAS", titled("FreeNAS")],
  ["Commvault", greet(bin([0, 0, 0, 9, 0, 0, 0, 0x7c, 0, 0, 0, 0x3d, 1, 2]), 8400)],
  ["Backup Exec", greet(bin([0x80, 0, 0, 0x24, 0, 0, 0, 1, 0x5f, 0x12, 0x33, 0x44, 0, 0, 0, 0, 0, 0, 5, 2, 0, 0]), 10000)],
  ["MongoDB", page("It looks like you are trying to access MongoDB over HTTP on the native driver port.\n")],
  ["network camera", titled("AXIS")], ["network camera", hdr({ server: "Linux/4.9.94-axis5, UPnP/1.0, Portable SDK for UPnP devices/1.6.18" })],
  ["printer", hdr({ server: "HP HTTP Server; HP LaserJet Pro M404 - W1A52A; Serial Number: PHBQX12345; Built:Thu Mar 05, 2020 11:10:23AM {002_2008A}" })],
  ["printer", hdr({ server: "HP-ChaiSOE/1.0" })], ["printer", titled("HP Color LaserJet MFP M477fdw")],
  ["CUPS", hdr({ server: "CUPS/2.4 IPP/2.1" })], ["CUPS", titled("Home - CUPS 2.4.7")],
  ["Authelia", titled("Login - Authelia")], ["Access Gateway", titled("Duo Access Gateway")], ["Network Gateway", titled("Login - Duo Network Gateway")],
  ["FreeIPA", { ...page("", { location: "https://ipa.example.test/ipa/ui" }), http: { status: 301, headers: { location: "https://ipa.example.test/ipa/ui" }, body: "" } }],
  ["Identity Provider", titled("Shibboleth IdP")],
  ["Email Security Gateway", greet("220 mx.example.test ESMTP (0123456789abcdef0123456789abcdef)\r\n")],
  ["FortiMail", withCert({ CN: "FortiMail", OU: "FortiMail", O: "Fortinet", L: "Sunnyvale", ST: "California", C: "US" })],
  ["mailcow", page('<img class="main-logo" alt="mailcow-logo" src="/img/cow_mailcow.svg">')],
  ["Protection Server", titled("Proofpoint Protection Server - Login")], ["Protection Server", hdr({ "set-cookie": ["PPSAUTH=abc; Path=/"] })],
  ["Cacti", titled("Login to Cacti", "<div class='versionInfo'>Version 1.2.24 | (c) 2004-2023 - The Cacti Group</div>")],
  ["Jaeger", titled("Jaeger UI")], ["Jaeger", page('<div id="jaeger-ui-root"></div>')], ["LibreNMS", titled("LibreNMS")],
  ["PRTG Network Monitor", hdr({ server: "PRTG/23.4.90.1299" })], ["PRTG Network Monitor", titled("Welcome | PRTG Network Monitor (HOST01)")],
  ["Sentry", page('<link rel="mask-icon" href="/_static/sentry/images/logos/logo-sentry.svg">')],
  ["Wazuh", withCert({ C: "US", L: "California", O: "Wazuh", OU: "Wazuh", CN: "wazuh-dashboard" }, { OU: "Wazuh", O: "Wazuh", L: "California" })],
  ["Netdata", hdr({ server: "NetData Embedded HTTP Server v1.16.1-146-g2f5e36ef" })],
  ["Guacamole", page('<body ng-app="index"><guac-modal><guac-login></guac-login></guac-modal></body>')],
  ["ScreenConnect", hdr({ server: "ScreenConnect/6.3.13446.6374-4039728469 Microsoft-HTTPAPI/2.0" })],
  ["SimpleHelp", titled("Welcome to SimpleHelp")], ["Jitsi Meet", page('<script src="libs/lib-jitsi-meet.min.js?v=139"></script>')],
  ["Enterprise Server", titled("GitHub Enterprise")], ["Enterprise Server", titled("Setup GitHub Enterprise")],
  ["iDRAC", withCert({ CN: "iDRACdefault001122334455", OU: "iDRAC Group", O: "Dell Inc.", L: "Round Rock", C: "US" })],
  ["iDRAC", withCert({ CN: "idrac-ABC1234", OU: "Remote Access Group", O: "Dell Inc.", L: "Round Rock", ST: "Texas", C: "US" })],
  ["iDRAC", withCert({ CN: "iDRAC default certificate", OU: "Server Firmware Group", O: "Dell Inc.", L: "Round Rock", C: "US" })],
  ["iRMC", titled("ServerView Remote Management iRMC S4 Web Server")],
  ["Integrated Lights-Out", hdr({ server: "HP-iLO-Server/1.30" })], ["Integrated Lights-Out", titled("iLO 4")],
  ["Active Management Technology Firmware", hdr({ server: "Intel(R) Active Management Technology 7.1.86" })], ["Active Management Technology Firmware", hdr({ server: "AMT" })],
  ["Active Management Technology Firmware", hdr({ server: "Intel(R) Standard Manageability 11.8.50" })],
  ["BMC", titled("Supermicro BMC Login")],
];
test("every built rule fires on its quoted token, once, with fixed evidence and a cited source", () => {
  const covered = new Set();
  for (const [product, r] of POS) {
    const s = one(r);
    assert.equal(s.product, product, `${product}: ${JSON.stringify(s)}`);
    assert.match(s.source, /^research pack \(/); assert.match(s.src, /^https:\/\//); assert.match(s.evidence, /passive: data already collected/);
    covered.add(`${s.catalog[0]}|${s.product}`);
  }
  for (const r of RULES) assert.ok(covered.has(`${r.id}|${r.product}`), `no positive fixture for ${r.id} (${r.product})`);
});

/* ---- near-misses ---- */
test("near-misses: similar but not the quoted token never fires", () => {
  for (const r of [titled("Jupyter Notebook docs"), titled("MLflow Tracking Guide"), titled("Langflow tutorial"), titled("Not GeoServer"), titled("Harbor Freight"),
    hdr({ server: "NetApp" }), hdr({ server: "SAP NetWeaver Application Server Java" }), hdr({ server: "ScreenConnect/6.3.13446.6374" }), hdr({ server: "PRTG Probe" }),
    hdr({ server: "NetData" }), hdr({ server: "HP-iLO-Server" }), hdr({ server: "HP-ChaiServer/1" }), hdr({ server: "Intel(R) Something" }), hdr({ server: "cupsd" }),
    hdr({ "docker-distribution-api-version": "registry/3.0" }), hdr({ "x-rocket-chat-version": "unknown" }), hdr({ "set-cookie": ["OFBiz.Visitor2=1"] }), hdr({ "set-cookie": ["my_i_like_gogits=1"] }),
    page("<p>the word mailcow appears</p>"), page("<p>harbor-app without brackets</p>"), page("<guac-login>"), page('<meta name="application-name" content="JIRA2">'),
    page("MongoDB is great"), titled("Login to Cacti Plus"), titled("AXIS cameras"), titled("Supermicro BMC"), titled("iLO 6"), titled("GitHub"),
    { ...page(""), http: { status: 301, headers: { location: "https://h.example.test/ipa/uix" }, body: "" } },
    greet("220 mx.example.test ESMTP (0123456789abcdef0123456789abcde)\r\n"), greet("220 mx.example.test ESMTP Postfix\r\n"),
    greet(bin([0, 0, 0, 9, 0, 0, 0, 0x7b, 0, 0, 0])), greet(bin([0x80, 0, 0, 0x24, 0, 0, 0, 2, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 5, 2])), greet("SSH-2.0-OpenSSH_9.6\r\n", 22),
    withCert({ CN: "FortiMail", OU: "FortiMail", O: "Fortinet", L: "Elsewhere", ST: "California", C: "US" }), withCert({ CN: "FortiGate", O: "Fortinet" }),
    withCert({ O: "Wazuh", OU: "Wazuh", L: "California", C: "US" }, { O: "Other CA" }), withCert({ CN: "iDRACdefault0011", OU: "iDRAC Group", O: "Dell Inc.", L: "Round Rock", C: "US" }),
    withCert({ CN: "idrac-abc1234", OU: "Remote Access Group", O: "Dell Inc.", L: "Round Rock", ST: "Texas", C: "US" })]) none(r);
});

/* ---- versions ---- */
test("versions only from stated captures; family rules and markers stay guessed", () => {
  const v = (r) => { const s = one(r); return `${s.version}|${s.shown_version}|${s.guessed}`; };
  assert.equal(v(hdr({ "x-rocket-chat-version": "6.5.2" })), "6.5.2|6.5.2|false");
  assert.equal(v(hdr({ server: "ScreenConnect/23.9.8.8811-1234567890" })), "23.9.8.8811|23.9.8.8811|false");
  assert.equal(v(hdr({ server: "NetData Embedded HTTP Server v1.16.1-146-g2f5e36ef" })), "1.16.1|1.16.1-146-g2f5e36ef|false");
  assert.equal(v(hdr({ server: "HP-iLO-Server/1.30" })), "1.30|1.30|false");
  assert.equal(v(hdr({ server: "Intel(R) Active Management Technology 7.1.86" })), "7.1.86|7.1.86|false");
  assert.equal(v(hdr({ server: "PRTG/23.4.90.1299" })), "23.4.90.1299|23.4.90.1299|false");
  assert.equal(v(hdr({ server: "NetApp/7.3.4P1" })), "7.3.4|7.3.4P1|false");
  assert.equal(v(page('<meta name="application-name" content="JIRA" data-name="jira" data-version="9.12.2">')), "9.12.2|9.12.2|false");
  assert.equal(v(titled("Login to Cacti", "<div class='versionInfo'>Version 1.2.24 | (c)</div>")), "1.2.24|1.2.24|false");
  assert.equal(v({ ...hdr({ "set-cookie": ["i_like_gogits=x"] }, "<div class=\"ui left\"> © 2024 Gogs Version: 0.13.0 Page: <strong>1ms</strong></div>") }), "0.13.0|0.13.0|false");
  assert.equal(v(hdr({ "set-cookie": ["BITBUCKETSESSIONID=x"] }, '<li>Atlassian Bitbucket <span title="abc" id="product-version" data-system-build-number="abc"> v8.9.4</span></li>')), "8.9.4|8.9.4|false");
  assert.equal(v(hdr({ "x-confluence-request-time": "1" }, '<li class="print-only">Printed by Atlassian Confluence 7.19.16</li>')), "7.19.16|7.19.16|false");
  // CUPS: only major.minor stated -> shown, never compared; a full version is compared
  assert.equal(v(hdr({ server: "CUPS/2.4 IPP/2.1" })), "|2.4|true");
  assert.equal(v(hdr({ server: "CUPS/2.4.7 IPP/2.1" })), "2.4.7|2.4.7|false");
  assert.match(one(hdr({ server: "CUPS/2.4 IPP/2.1" })).evidence, /only the major\.minor line/);
  // SAP: the kernel/ICM number is shown, never compared
  assert.equal(v(hdr({ server: "SAP NetWeaver Application Server 7.45 / ICM 745" })), "|7.45|true");
  assert.equal(v(hdr({ server: "SAP J2EE Engine/7.00" })), "|7.00|true");
  // no version on the page: guessed
  for (const r of [titled("JupyterLab"), titled("AXIS"), hdr({ "docker-distribution-api-version": "registry/2.0" }), hdr({ server: "AMT" }), hdr({ server: "HP-ChaiSOE/1.0" }),
    titled("ServerView Remote Management iRMC S4 Web Server"), page('<script src="libs/lib-jitsi-meet.min.js?v=139"></script>')]) assert.equal(v(r).split("|")[2], "true");
  // a version on a page that is not the product is never read (the rule must match first)
  none(page('<li class="print-only">Printed by Atlassian Confluence 7.19.16</li>'));
});

/* ---- no identifiers kept ---- */
test("serial numbers, per-device tokens and certificate CNs are matched but never stored", () => {
  const cases = [
    [hdr({ server: "HP HTTP Server; HP LaserJet Pro M404 - W1A52A; Serial Number: PHBQX12345; Built:Thu Mar 05, 2020" }), ["PHBQX12345", "Serial Number:", "W1A52A", "Built"]],
    [hdr({ server: "ScreenConnect/6.3.13446.6374-4039728469 Microsoft-HTTPAPI/2.0" }), ["4039728469"]],
    [greet("220 mx.example.test ESMTP (0123456789abcdef0123456789abcdef)\r\n"), ["0123456789abcdef0123456789abcdef", "mx.example.test"]],
    [withCert({ CN: "iDRACdefault001122334455", OU: "iDRAC Group", O: "Dell Inc.", L: "Round Rock", C: "US" }), ["001122334455"]],
    [withCert({ CN: "idrac-ABC1234", OU: "Remote Access Group", O: "Dell Inc.", L: "Round Rock", ST: "Texas", C: "US" }), ["ABC1234"]],
    [withCert({ C: "US", L: "California", O: "Wazuh", OU: "Wazuh", CN: "wazuh-node-7" }, { OU: "Wazuh", O: "Wazuh", L: "California" }), ["wazuh-node-7"]],
    [hdr({ "set-cookie": ["PPSAUTH=SECRETVALUE; Path=/"] }), ["SECRETVALUE"]],
  ];
  for (const [r, secrets] of cases) {
    const s = JSON.stringify(research(r)), all = JSON.stringify(servicesOf(r).filter((x) => /^research pack/.test(x.source)));
    assert.ok(s.length > 2, JSON.stringify(r));
    for (const x of secrets) { assert.equal(s.includes(x), false, `${x} in ${s}`); assert.equal(all.includes(x), false, `${x} in ${all}`); }
  }
  // the HP printer keeps its model family only (not an identifier)
  assert.equal(one(cases[0][0]).label, "HP printer (LaserJet Pro)");
  // bodies are never stored either
  assert.equal(JSON.stringify(research(page('<img alt="mailcow-logo"> private-body-text'))).includes("private-body-text"), false);
});

/* ---- dedupe and replacement in servicesOf ---- */
test("servicesOf: one record per product, FortiMail replaces the FortiOS guess, a named greeting replaces the generic one", () => {
  const forti = servicesOf(withCert({ CN: "FortiMail", OU: "FortiMail", O: "Fortinet", L: "Sunnyvale", ST: "California", C: "US" }));
  assert.deepEqual(forti.map((s) => s.product), ["FortiMail"]);
  const fg = servicesOf(withCert({ CN: "FortiGate", O: "Fortinet" }));   // a FortiGate certificate keeps the FortiOS guess
  assert.deepEqual(fg.map((s) => s.product), ["FortiOS"]);
  const bar = servicesOf(greet("220 mx.example.test ESMTP (0123456789abcdef0123456789abcdef)\r\n"));
  assert.deepEqual(bar.map((s) => `${s.proto}|${s.product}`), ["smtp|Email Security Gateway"]);
  // a product another module already named on the port is not added twice (Ray Dashboard: fp-apps.mjs names Ray)
  const ray = servicesOf(titled("Ray Dashboard"));
  assert.equal(ray.filter((s) => s.product === "Ray").length, 1);
  // withResearch keeps the existing list and adds only new products
  const existing = [{ port: 80, proto: "http", vendor: "Netdata", product: "Netdata", version: "1.40.0", shown_version: "1.40.0", guessed: false, source: "x" }];
  assert.deepEqual(withResearch(existing, hdr({ server: "NetData Embedded HTTP Server v1.16.1" })), existing);
});

/* ---- DNS version.bind ---- */
test("DNS: the existing version.bind answer names dnsmasq, Knot, NSD, Unbound and CoreDNS; the generic record gives way", () => {
  const udp = (version) => ({ port: 53, proto: "dns", state: "open", parsed: { version, text: version } });
  const generic = (version) => [{ port: 53, proto: "dns", vendor: "", product: "", label: "DNS server", version: "", shown_version: "", distro: "", source: "DNS version.bind", evidence: `DNS version.bind: ${version}`, guessed: true }];
  const v = (version) => withResearchUdp(udp(version), generic(version)).map((s) => `${s.product}|${s.version}|${s.shown_version}|${s.guessed}`);
  assert.deepEqual(v("dnsmasq-2.80"), ["dnsmasq|2.80|2.80|false"]);
  assert.deepEqual(v("dnsmasq-pi-hole-2.87"), ["dnsmasq|2.87|2.87|false"]);
  assert.deepEqual(v("dnsmasq-2.78-ubnt"), ["dnsmasq|2.78|2.78|false"]);
  assert.deepEqual(v("Knot DNS 3.2.6"), ["Knot DNS|3.2.6|3.2.6|false"]);
  assert.deepEqual(v("NSD 4.7.0"), ["Name Server Daemon|4.7.0|4.7.0|false"]);
  assert.deepEqual(v("unbound 1.17.1"), ["Unbound|1.17.1|1.17.1|false"]);
  assert.deepEqual(v("unbound"), ["Unbound|||true"]);
  assert.deepEqual(v("CoreDNS-1.11.1"), ["CoreDNS|1.11.1|1.11.1|false"]);
  // near-misses keep the generic record
  for (const x of ["dnsmasq", "my unbound 1.2", "Knot Resolver 5.7.0", "NSD4", "CoreDNS", "none of your business"]) assert.deepEqual(v(x), ["|||true"], x);
  // BIND (fromUdp's own parser) is untouched; a closed or non-DNS answer passes through
  const bind = [{ port: 53, proto: "dns", vendor: "ISC", product: "BIND", version: "9.18.24", shown_version: "9.18.24", guessed: false }];
  assert.deepEqual(withResearchUdp(udp("9.18.24-1-Debian"), bind), bind);
  assert.deepEqual(withResearchUdp({ port: 123, proto: "ntp", state: "open", parsed: { version: "dnsmasq-2.80" } }, []), []);
  assert.deepEqual(withResearchUdp({ port: 53, proto: "dns", state: "filtered", parsed: null }, []), []);
});

/* ---- loopback: nothing beyond today's sends ---- */
async function web(root, routes = {}) {
  const got = [];
  const srv = http.createServer((req, res) => {
    got.push(`${req.method} ${req.url}`);
    const r = req.url === "/" ? root : routes[req.url] || { status: 404, body: "not found" };
    res.writeHead(r.status || 200, { "Content-Type": "text/html", ...(r.headers || {}) }); res.end(r.body || "");
  });
  const port = await new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
  return { port, got, close: () => new Promise((r) => { srv.closeAllConnections(); srv.close(() => r()); }) };
}
const scan = (port, extra = {}) => probeAll(LOCAL, { ports: [port], httpPorts: [port], settings: settings({}).settings, assumeUp: true, ...extra });

test("loopback web: the research pack adds no request — the server sees exactly one GET /", async () => {
  const s = await web({ headers: { Server: "NetData Embedded HTTP Server v1.16.1-146-g2f5e36ef", "X-Rocket-Chat-Version": "6.5.2" }, body: "<title>Login to Cacti</title>" });
  try {
    const r = await scan(s.port), h = r.hosts[0];
    assert.deepEqual(s.got, ["GET /"]);
    assert.equal(r.stats.connections, 1);
    const prods = h.services.map((x) => `${x.product}|${x.shown_version}`).sort();
    assert.deepEqual(prods, ["Cacti|", "Netdata|1.16.1-146-g2f5e36ef", "Rocket.Chat|6.5.2"]);
    assert.equal(JSON.stringify(h).includes("<title>Login to Cacti"), false);   // no body in the result
  } finally { await s.close(); }
});

test("loopback greeting: the scanner reads the Barracuda and NDMP greetings and sends zero bytes", async () => {
  for (const [banner, product] of [[Buffer.from("220 mx.example.test ESMTP (0123456789abcdef0123456789abcdef)\r\n"), "Email Security Gateway"],
    [Buffer.from([0x80, 0, 0, 0x24, 0, 0, 0, 1, 0x5f, 0x12, 0x33, 0x44, 0, 0, 0, 0, 0, 0, 5, 2, 0, 0, 0, 0]), "Backup Exec"]]) {
    const received = []; const socks = new Set();
    const srv = net.createServer((c) => { socks.add(c); c.on("data", (d) => received.push(d)); c.on("error", () => {}); c.write(banner); });
    const port = await new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
    try {
      const r = await probeAll(LOCAL, { ports: [port], settings: settings({}).settings, assumeUp: true });
      assert.deepEqual(r.hosts[0].services.map((x) => x.product), [product]);
      assert.equal(Buffer.concat(received).length, 0, "the scanner wrote to a greeting service");
    } finally { for (const c of socks) c.destroy(); await new Promise((r) => srv.close(() => r())); }
  }
});

test("UDP: the DNS answer is read from the existing one query; no extra datagram", async () => {
  let calls = 0;
  const udpProbe = async (ip, key) => { calls++; return { port: 53, proto: "dns", state: "open", parsed: { version: "dnsmasq-2.89", text: "dnsmasq-2.89" } }; };
  const r = await probeAll(LOCAL, { ports: [], settings: settings({}).settings, assumeUp: true, udp: ["dns"], udpProbe });
  assert.equal(calls, 1);
  assert.deepEqual(r.hosts[0].services.map((s) => `${s.product}|${s.version}`), ["dnsmasq|2.89"]);
});

/* ---- the one rail row the lead accepted (2026-11-22) ---- */
const rev = (port, { headers = {}, body = "", status = 200 } = {}) => railEvidence(port, { http: { status, headers, body } });
test("rail: ivanti-connect-secure-version-path is one frozen row on the existing literal path, hinted by a /dana-na/ redirect", () => {
  const e = RAIL.find((x) => x.id === "ivanti-connect-secure-version-path");
  assert.ok(e && Object.isFrozen(e)); assert.deepEqual([...e.paths], ["/dana-na/nc/nc_gina_ver.txt"]);
  assert.ok(RAIL_PATHS.includes("/dana-na/nc/nc_gina_ver.txt")); assert.equal(RAIL_PATHS.length, 39);   // no new path
  const ids = (evs) => railPlan(evs).plan.flatMap((x) => x.ids);
  assert.deepEqual(ids([rev(443, { status: 302, headers: { location: "/dana-na/auth/url_default/welcome.cgi" } })]), ["ivanti-connect-secure-version-path", "pulse-secure-pulse-connect-secure"]);
  assert.deepEqual(ids([rev(443, { status: 302, headers: { location: "https://vpn.example.test/dana-na/home/starter.cgi" } })]), ["ivanti-connect-secure-version-path"]);
  assert.deepEqual(ids([rev(443, { body: '<link href="/dana-na/css/ds.css">' })]), ["ivanti-connect-secure-version-path", "pulse-secure-pulse-connect-secure"]);
  // one request for the shared path
  assert.equal(railPlan([rev(443, { status: 302, headers: { location: "/dana-na/auth/x" } })]).plan.length, 1);
  // near-misses: not hinted
  for (const loc of ["/dana-nax/", "/login?next=/dana-na/", "https://h.example.test/other/dana-na/"]) assert.deepEqual(ids([rev(443, { status: 302, headers: { location: loc } })]), [], loc);
  // parse: a dotted ProductVersion is stated (guessed false) but shown only; anything else stays guessed; one service per path
  const item = { port: 443, tls: true, path: "/dana-na/nc/nc_gina_ver.txt", ids: ["ivanti-connect-secure-version-path", "pulse-secure-pulse-connect-secure"] };
  const res = (body) => ({ status: 200, headers: { "content-type": "text/plain" }, body });
  const got = railResult(item, res('<PARAM NAME="ProductVersion" VALUE="9.1.11.10541">')).services;
  assert.deepEqual(got.map((s) => `${s.vendor}|${s.product}|${s.version}|${s.shown_version}|${s.guessed}`), ["Ivanti|Connect Secure||9.1.11.10541|false"]);
  const odd = railResult({ ...item, ids: ["ivanti-connect-secure-version-path"] }, res('<PARAM NAME="ProductVersion" VALUE="9.1R11">')).services;
  assert.deepEqual(odd.map((s) => `${s.shown_version}|${s.guessed}`), ["|true"]);
  assert.deepEqual(railResult({ ...item, ids: ["ivanti-connect-secure-version-path"] }, res("no version here")).services, []);
  assert.deepEqual(railResult(item, { status: 404, headers: {}, body: "" }).services, []);
});

test("rail loopback: the Ivanti path is requested only when hinted and only with --paths", async () => {
  const routes = { "/dana-na/nc/nc_gina_ver.txt": { headers: { "Content-Type": "text/plain" }, body: '<PARAM NAME="ProductVersion" VALUE="22.7.2.2615">' } };
  const hinted = await web({ status: 302, headers: { Location: "/dana-na/auth/url_default/welcome.cgi" } }, routes);
  try {
    await scan(hinted.port);   // flag off
    assert.deepEqual(hinted.got, ["GET /"]);
    hinted.got.length = 0;
    const r = await scan(hinted.port, { paths: { enabled: true } });
    assert.deepEqual(hinted.got, ["GET /", "GET /dana-na/nc/nc_gina_ver.txt"]);
    const s = r.hosts[0].services.filter((x) => x.product === "Connect Secure");
    assert.deepEqual(s.map((x) => `${x.shown_version}|${x.version}|${x.guessed}`), ["22.7.2.2615||false"]);
    assert.deepEqual((r.hosts[0].rail || []).map((x) => x.for), [["ivanti-connect-secure-version-path", "pulse-secure-pulse-connect-secure"]]);
  } finally { await hinted.close(); }
  const plain = await web({ body: "<title>Intranet</title>" }, routes);
  try {
    await scan(plain.port, { paths: { enabled: true } });
    assert.deepEqual(plain.got, ["GET /"]);
  } finally { await plain.close(); }
});
