// scan-app-versions passive pack 2 (scanner/lib/fp-apps2.mjs): application fingerprints from data the scan already collected
// (root page title/headers/body markers/cookie names, recorded redirect Location, a greeting). Fixtures are invented text in
// the shape each product sends; CVE ids are invented (CVE-2026-90xxx). Network tests use loopback servers made here only.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import http from "node:http";
import { readFileSync } from "node:fs";
import { RULES, appsPack2, withPack2, evidenceOf } from "../../scanner/lib/fp-apps2.mjs";
import { fromGreeting } from "../../scanner/lib/fingerprint.mjs";
import { servicesOf, probeAll } from "../../scanner/lib/scan.mjs";
import { cleanFlaws, findings } from "../../scanner/lib/match.mjs";
import { summarize } from "../../scanner/lib/report.mjs";
import { settings } from "../../scanner/lib/limits.mjs";

const TODAY = "2026-11-22";
const page = (o = {}) => ({ port: o.port || 80, http: { status: o.status || 200, headers: { "content-type": "text/html", ...(o.headers || {}) }, body: o.body || "" }, ...(o.tls ? { tls: { cert: null } } : {}) });
const greet = (port, banner) => ({ port, banner });
const one = (r, product) => appsPack2(r).find((s) => s.product === product);

const BUILT = ["micro-focus-micro-focus-access-manager", "omnissa-workspace-one-uem", "cisco-secure-email-gateway", "mdaemon-email-server", "playsms-playsms",
  "roundcube-webmail~kev-auto", "smartertools-smartermail", "apache-superset", "hewlett-packard-hp-openview-network-node-manager", "progress-whatsup-gold", "sciencelogic-sl1",
  "solarwinds-orion", "splunk-enterprise~kev-auto", "tibco-jasperreports", "ivanti-endpoint-manager-epm", "microsoft-remote-desktop-services", "n-able-n-central",
  "solarwinds-serv-u", "wing-ftp-server", "kaseya-virtual-system-server-administrator-vsa", "trend-micro-apex-one", "trend-micro-officescan", "zoho-manageengine",
  "apache-apisix", "apache-traffic-server", "embedthis-goahead", "envoy-proxy", "haproxy", "microsoft-http-protocol-stack", "microsoft-http-sys", "nostromo-nhttpd",
  "squid-caching-proxy", "traefik", "varnish-cache"];

test("rules table: data only, every rule names its catalog id, product, NVD CPE and at least one matcher", () => {
  const ids = new Set();
  for (const r of RULES) {
    assert.ok(Array.isArray(r.ids) && r.ids.length, "catalog id(s)"); r.ids.forEach((i) => ids.add(i));
    assert.ok(r.vendor && r.product && r.cpe, `${r.ids}: vendor, product and cpe`);
    assert.ok(Array.isArray(r.any) && r.any.length, `${r.ids}: matchers`);
    for (const m of r.any) {
      assert.ok(m.re instanceof RegExp && !m.re.global && !m.re.sticky, `${r.ids}: a stateless regex`);
      assert.match(m.field, /^(title|body|location|server|via|www-authenticate|headers|cookie-name|cookie:[\w-]+|header:[\w-]+|banner)$/, `${r.ids}: field ${m.field}`);
      assert.ok(m.label, `${r.ids}: a marker label for the evidence`);
      if (m.field === "banner") assert.match(m.proto, /^(ftp|smtp|imap|pop3)$/);
    }
  }
  assert.deepEqual([...ids].sort(), [...BUILT].sort());
});

test("the module is passive: no network, process or timer code", () => {
  const src = readFileSync(new URL("../../scanner/lib/fp-apps2.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(src, /node:(net|tls|http|https|dgram|child_process)|\bfetch\s*\(|\.connect\s*\(|\.request\s*\(|setTimeout|setInterval/);
  assert.doesNotMatch(src, /^import .* from "\.\/(probe|udp|scan)\.mjs"/m);
});

test("web root page: titles, body markers, Location and headers identify the product; no version unless the data states one", () => {
  const cases = [
    [page({ status: 302, headers: { location: "https://idp.example.lan/nidp/app/login?id=1" } }), "Access Manager"],
    [page({ body: '<a href="/nidp/app">Sign in</a>' }), "Access Manager"],
    [page({ body: "<title>Workspace ONE</title><a>About VMware AirWatch</a>" }), "Workspace ONE UEM"],
    [page({ body: "<h1>Self-Service Portal</h1><img src=x alt=AirWatch>" }), "Workspace ONE UEM"],
    [page({ body: '<a href="index.php?app=page&amp;inc=forgot">Forgot password</a>' }), "playSMS"],
    [page({ body: '<link href="/plugin/themes/km2/css/x.css">' }), "playSMS"],
    [page({ body: "<title>Roundcube Webmail :: Welcome to Roundcube Webmail</title>" }), "Roundcube Webmail"],
    [page({ body: '<input name="_user" id="rcmloginuser">' }), "Roundcube Webmail"],
    [page({ body: "<title>Superset</title>" }), "Superset"],
    [page({ body: "<title>WhatsUp Gold</title>" }), "WhatsUp Gold"],
    [page({ status: 401, headers: { "www-authenticate": 'Basic realm="WhatsUp Gold"' } }), "WhatsUp Gold"],
    [page({ body: "<title>ScienceLogic EM7</title>" }), "SL1"],
    [page({ body: '<script src="login.em7"></script><link href="css.em7">' }), "SL1"],
    [page({ body: "<title>SolarWinds Orion</title>" }), "Orion Platform"],
    [page({ body: '<link rel=stylesheet href="/SolarWinds.css">' }), "Orion Platform"],
    [page({ headers: { server: "Splunkd" } }), "Splunk Enterprise"],
    [page({ body: "<title>Login - Splunk</title>" }), "Splunk Enterprise"],
    [page({ body: "<title>TIBCO Jaspersoft: Login</title>" }), "JasperReports Server"],
    [page({ body: "<p>Ivanti Endpoint Manager</p>" }), "Endpoint Manager"],
    [page({ body: "<p>LANDesk(R) Management Suite</p>" }), "Endpoint Manager"],
    [page({ headers: { "set-cookie": ["TSWAFeatureCheckCookie=true; path=/RDWeb/"] } }), "Remote Desktop Services"],
    [page({ body: "<title>N-central Login</title>" }), "N-central"],
    [page({ body: '<form action="/vsapres/web20/core/login.aspx">' }), "VSA"],
    [page({ body: "<title>OfficeScan</title>" }), "Apex One (OfficeScan)"],
    [page({ body: "Trend Micro <input name=TMlogonEncrypted>" }), "Apex One (OfficeScan)"],
    [page({ body: "<title>ManageEngine ServiceDesk Plus</title>" }), "ManageEngine ServiceDesk Plus"],
    [page({ body: "<title>ManageEngine ServiceDesk Plus - MSP</title>" }), "ManageEngine ServiceDesk Plus MSP"],
    [page({ body: "<title>ADAudit Plus</title>" }), "ManageEngine ADAudit Plus"],
    [page({ body: "<title>Apache APISIX Dashboard</title>" }), "APISIX"],
    [page({ headers: { via: "http/1.1 cache (ApacheTrafficServer/9.2.0)" } }), "Traffic Server"],
    [page({ headers: { server: "GoAhead-Webs" } }), "GoAhead"],
    [page({ headers: { server: "envoy" } }), "Envoy"],
    [page({ headers: { server: "HAProxy" } }), "HAProxy"],
    [page({ headers: { via: "1.1 proxy (squid/4.10)" } }), "Squid"],
    [page({ headers: { server: "traefik" } }), "Traefik"],
    [page({ headers: { "x-varnish": "32770" } }), "Varnish Cache"],
    [page({ headers: { via: "1.1 varnish (Varnish/7.1)" } }), "Varnish Cache"],
  ];
  for (const [r, product] of cases) {
    const s = one(r, product);
    assert.ok(s, `${product} from ${JSON.stringify(r.http).slice(0, 120)}`);
    assert.equal(s.proto, "http"); assert.equal(s.version, "", `${product}: no version stated`); assert.equal(s.guessed, true, `${product}: version-less is guessed`);
    assert.ok(s.catalog.length && s.catalog.every((i) => BUILT.includes(i)));
  }
  // the same page over TLS is https
  assert.equal(one(page({ tls: true, headers: { server: "envoy" } }), "Envoy").proto, "https");
});

test("versions only where the collected data states one; component numbers are recorded, never compared", () => {
  const v = (r, product) => { const s = one(r, product); return s && [s.version, s.shown_version, s.guessed]; };
  assert.deepEqual(v(page({ headers: { server: "APISIX/3.2.1" } }), "APISIX"), ["3.2.1", "3.2.1", false]);
  assert.deepEqual(v(page({ headers: { server: "WhatsUp_Gold/8.0" } }), "WhatsUp Gold"), ["8.0", "8.0", false]);
  assert.deepEqual(v(page({ headers: { server: "GoAhead/2.5.0" } }), "GoAhead"), ["2.5.0", "2.5.0", false]);
  assert.deepEqual(v(page({ headers: { server: "nostromo 1.9.6" } }), "nhttpd"), ["1.9.6", "1.9.6", false]);
  assert.deepEqual(v(page({ headers: { server: "nostromo" } }), "nhttpd"), ["", "", true]);
  assert.deepEqual(v(page({ headers: { "set-cookie": ["ncentral_version=2024.6.0.20; path=/; Secure"] } }), "N-central"), ["2024.6.0.20", "2024.6.0.20", false]);
  assert.deepEqual(v(page({ body: "<title>Superset</title><script>{&#34;version_string&#34;: &#34;2.0.1&#34;}</script>" }), "Superset"), ["2.0.1", "2.0.1", false]);
  // stated numbers that are not the product's release: shown, but never compared with affected ranges
  assert.deepEqual(v(page({ headers: { server: "Microsoft-HTTPAPI/2.0" } }), "HTTP.sys (HTTP Protocol Stack)"), ["", "2.0", true]);
  assert.deepEqual(v(page({ headers: { server: "BBC 11.14.014; ovbbccb 11.14.014" } }), "OpenView Network Node Manager"), ["", "11.14.014", true]);
  assert.deepEqual(v(page({ headers: { server: "coda 11.00.044" } }), "OpenView Network Node Manager"), ["", "11.00.044", true]);
  assert.deepEqual(v(page({ headers: { server: "WDaemon/23.5.1" } }), "MDaemon Email Server"), ["", "23.5.1", true]);
  assert.deepEqual(v(page({ body: '<script>rcmail.set_env({"rcversion":10603});</script><div id="rcmloginuser"></div>' }), "Roundcube Webmail"), ["", "10603", true]);
  // a version-like token outside an identified page is not read
  assert.equal(one(page({ body: "<script>{&#34;version_string&#34;: &#34;2.0.1&#34;}</script>" }), "Superset"), undefined);
});

test("greetings already read: IronPort, MDaemon, SmarterMail, Serv-U, Wing FTP (and Exim/ProFTPD stay with fingerprint.mjs)", () => {
  const g = (port, b, product) => one(greet(port, b), product);
  const ftp = g(21, "220 esa.example.lan Cisco IronPort FTP server (V14.2.0-620) ready", "Secure Email Gateway");
  assert.deepEqual([ftp.proto, ftp.version, ftp.shown_version, ftp.guessed], ["ftp", "14.2.0", "14.2.0-620", false]);
  const smtp = g(25, "220 esa.example.lan ESMTP IronPort AsyncOS", "Secure Email Gateway");
  assert.deepEqual([smtp.proto, smtp.version, smtp.guessed], ["smtp", "", true]);
  assert.deepEqual([g(143, "* OK mail.example.lan IMAP4rev1 MDaemon 23.5.1 ready", "MDaemon Email Server").version, g(110, "+OK mail.example.lan POP3 MDaemon 23.5.1 ready <MDAEMON-F1@x>", "MDaemon Email Server").proto], ["23.5.1", "pop3"]);
  assert.deepEqual([g(143, "* OK IMAP4rev1 SmarterMail", "SmarterMail").proto, g(143, "* OK IMAP4rev1 SmarterMail", "SmarterMail").guessed], ["imap", true]);
  assert.equal(g(21, "220 Serv-U FTP Server v15.4 ready...", "Serv-U").version, "");
  assert.equal(g(21, "220 Wing FTP Server ready...", "Wing FTP Server").guessed, true);
  // Exim and ProFTPD: the existing greeting parser already reads them, with their version
  assert.deepEqual(fromGreeting("220 mx.example.lan ESMTP Exim 4.92.2 #89 Sun, 22 Nov 2026 10:00:00 +0000", 25).map((s) => [s.product, s.version]), [["Exim", "4.92.2"]]);
  assert.deepEqual(fromGreeting("220 ProFTPD 1.3.5rc3 Server (Debian) [::ffff:10.0.0.2]", 21).map((s) => [s.product, s.shown_version]), [["ProFTPD", "1.3.5rc3"]]);
  assert.deepEqual(appsPack2(greet(25, "220 mx.example.lan ESMTP Exim 4.92.2")), []);
});

test("near misses do not match", () => {
  const none = (r) => assert.deepEqual(appsPack2(r).map((s) => s.product), [], JSON.stringify(r).slice(0, 160));
  none(page({ body: "<title>Intranet</title><p>Welcome</p>" }));
  none(page({ body: "<title>Superset of tools</title>" }));                     // Recog: the title is exactly Superset
  none(page({ body: "<p>Self-Service Portal</p>" }));                            // needs AirWatch as well
  none(page({ body: '<script src="login.em7"></script>' }));                     // needs css.em7 as well
  none(page({ body: "<p>Trend Micro</p>" }));                                    // needs TMlogonEncrypted as well
  none(page({ body: "<p>LANDesk Management Agent</p>" }));                       // the agent, not the EPM console
  none(page({ headers: { server: "LANDesk Management Agent/1.0" } }));
  none(page({ body: '<input name="_user">' }));                                  // generic login field without Roundcube
  none(page({ body: "<title>ManageEngine Desktop Central 10</title>" }));        // left to the zoho-desktop-central row
  none(page({ headers: { server: "nginx/1.25.3", via: "1.1 google" } }));
  none(page({ headers: { "set-cookie": ["ncentral=abc"] } }));
  none(greet(21, "220 (vsFTPd 3.0.3)"));
  none(greet(25, "220 mail.example.lan ESMTP Postfix"));
  none(greet(21, "220 IronPort FTP server ready"));                              // FTP rule needs the (V...) form; SMTP rule refuses FTP
  none({ port: 80 });
  none(null);
});

test("evidence carries markers and header lines only: never body text or a cookie value", () => {
  const secret = "S3cr3tSessionValue", body = `<title>Login - Splunk</title><p>Internal note: ${secret}</p><a href="/nidp/app">x</a>`;
  const r = page({ body, headers: { "set-cookie": [`TSWAFeatureCheckCookie=${secret}; path=/RDWeb/`, `ncentral_version=12.3.0.274; path=/`] } });
  const all = appsPack2(r);
  assert.ok(all.length >= 3);
  for (const s of all) { assert.ok(!JSON.stringify(s).includes(secret), s.product); assert.ok(!JSON.stringify(s).includes("Internal note"), s.product); assert.ok(s.evidence.length <= 200); }
  // evidenceOf keeps cookie names; values are reachable only by an exact cookie name a rule declares
  const ev = evidenceOf(r);
  assert.deepEqual(ev.cookieNames, ["TSWAFeatureCheckCookie", "ncentral_version"]);
});

test("hooked into servicesOf: added once, and a product-less greeting record gives way to the product", () => {
  const smtp = servicesOf(greet(25, "220 esa.example.lan ESMTP IronPort AsyncOS"));
  assert.deepEqual(smtp.map((s) => [s.proto, s.product]), [["smtp", "Secure Email Gateway"]]);
  const web = servicesOf(page({ headers: { server: "Microsoft-HTTPAPI/2.0" }, body: "<title>ManageEngine OpManager</title>" }));
  assert.deepEqual(web.map((s) => s.product).sort(), ["HTTP.sys (HTTP Protocol Stack)", "ManageEngine OpManager"]);
  // an already-named product on the port is not added twice
  const have = [{ port: 80, proto: "http", vendor: "Envoy Proxy", product: "Envoy", version: "", guessed: true }];
  assert.equal(withPack2(have, page({ headers: { server: "envoy" } })).length, 1);
  // existing parsers keep working alongside
  assert.deepEqual(servicesOf(page({ headers: { server: "nginx/1.24.0" } })).map((s) => s.product), ["nginx"]);
});

/* ---- matching: a title alone can only say "check" (low confidence, out of the headline counts) ---- */
const wb = { kev: [
  { cve: "CVE-2026-90701", vendor: "Progress", product: "WhatsUp Gold", name: "WhatsUp Gold test flaw", added: "2026-11-01", due: "2026-11-21", cvss: 9.8, av: "N", affected: [{ vendor: "progress", product: "whatsup gold", to: "8.1" }] },
  { cve: "CVE-2026-90702", vendor: "Microsoft", product: "HTTP Protocol Stack", name: "HTTP.sys test flaw", added: "2026-11-01", due: "2026-11-21", cvss: 9.8, av: "N", affected: [{ vendor: "microsoft", product: "http.sys", to: "10.0" }] },
] };
test("a login-page title alone never yields affected; a stated version inside the range does", () => {
  const flaws = cleanFlaws(wb);
  const run = (r) => { const hosts = [{ address: "10.0.0.9", names: [], up: true, services: servicesOf(r), ports: [{ port: 80, state: "open" }] }]; const f = findings(hosts, flaws, new Map(), { today: TODAY }); return { f, sum: summarize(hosts, f) }; };
  const title = run(page({ body: "<title>WhatsUp Gold</title>" }));
  assert.deepEqual(title.f.map((x) => [x.cve, x.state, x.confidence]), [["CVE-2026-90701", "check", "low"]]);
  assert.equal(title.sum.known_exploited, 0); assert.equal(title.sum.low_confidence, 1); assert.equal(title.sum.version_confirmed, 0);
  const stated = run(page({ headers: { server: "WhatsUp_Gold/8.0" } }));
  assert.deepEqual(stated.f.map((x) => [x.cve, x.state, x.confidence]), [["CVE-2026-90701", "affected", "high"]]);
  assert.equal(stated.sum.known_exploited, 1);
  // HTTPAPI/2.0 is not a Windows build: never compared, so never affected
  const api = run(page({ headers: { server: "Microsoft-HTTPAPI/2.0" } }));
  assert.deepEqual(api.f.map((x) => [x.cve, x.state, x.confidence]), [["CVE-2026-90702", "check", "low"]]);
  assert.equal(api.sum.known_exploited, 0);
});

/* ---- no extra bytes: loopback services; the scanner sends exactly what it sent before (one GET /, nothing to a greeting) ---- */
test("probeAll on loopback: pack 2 identifies from the one GET / and the greeting, with no extra request or byte", async () => {
  const got = { http: [], ftp: [] }, servers = [];
  const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => { servers.push(srv); r(srv.address().port); }));
  const web = http.createServer((req, res) => {
    got.http.push(`${req.method} ${req.url}`);
    res.writeHead(200, { Server: "APISIX/3.2.1", "Content-Type": "text/html", "Set-Cookie": "ncentral_version=12.3.0.274; path=/; HttpOnly" });
    res.end("<!doctype html><title>N-central Login</title><p>fixture</p>");
  });
  const socks = new Set();
  const ftp = net.createServer((s) => { socks.add(s); s.on("close", () => socks.delete(s)); s.on("data", (d) => got.ftp.push(d.toString("latin1"))); s.on("error", () => {}); s.write("220 esa.example.lan Cisco IronPort FTP server (V14.2.0-620) ready\r\n"); setTimeout(() => s.end(), 3000); });
  try {
    const hp = await listen(web), fp = await listen(ftp);
    const t = [{ address: "127.0.0.1", names: [], kind: "loopback", public: false }];
    const r = await probeAll(t, { ports: [hp, fp], httpPorts: [hp], settings: settings({}).settings, assumeUp: true });
    const prods = r.hosts[0].services.map((s) => `${s.port === hp ? "web" : "ftp"}:${s.product}:${s.version}`).sort();
    assert.deepEqual(prods, ["ftp:Secure Email Gateway:14.2.0", "web:APISIX:3.2.1", "web:N-central:12.3.0.274"]);
    await new Promise((res) => setTimeout(res, 100));
    assert.deepEqual(got.http, ["GET /"]);   // the one root-page request, as before
    assert.deepEqual(got.ftp, []);           // nothing sent to a greeting service
  } finally {
    for (const s of socks) s.destroy();
    await Promise.all(servers.map((s) => new Promise((res) => { if (s.closeAllConnections) s.closeAllConnections(); s.close(() => res()); })));
  }
});
