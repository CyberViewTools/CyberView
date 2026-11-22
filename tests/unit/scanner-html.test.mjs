// scan-html: report.html, one self-contained page. Escaping of attacker-controlled text, https-only links, no external
// resources, the backport caveat, coverage blind spots, low-confidence grouping, and the file written by a real loopback scan.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import http from "node:http";
import { toHtml, esc, safeHref, backportOf, explain, truncatedBodies, scanProfile, scopeCoaching, staleData, STALE_DAYS } from "../../scanner/lib/html-report.mjs";
import { TIMEOUTS } from "../../scanner/lib/limits.mjs";
import { coverage, summarize } from "../../scanner/lib/report.mjs";
import { STATEMENT, checkScope } from "../../scanner/lib/scope.mjs";
import { SSH_IDENT, USER_AGENT, probePort } from "../../scanner/lib/probe.mjs";
import { main } from "../../scanner/cyberview-scan.mjs";
import { startServers } from "../fixtures/scanner/servers.mjs";

const SNAP = new URL("../fixtures/scanner/snapshot", import.meta.url).pathname;
/** every tag in a page (data is escaped, so "<" only ever starts one of ours) */
const tags = (h) => h.match(/<[a-z!][^>]*>/gi).filter((t) => !t.startsWith("<!"));
const EVIL = `<script>alert("x")</script><img src=x onerror='y'>`;

const finding = (o = {}) => ({
  rank: 1, cve: "CVE-2026-90101", title: "Fixture flaw " + EVIL, vendor: "OpenBSD", product: "OpenSSH", state: "affected",
  kev: true, kev_added: "2026-10-20", cisa_due: "2026-11-10", overdue: true, ransomware: false, epss: 0.42,
  rating: { score: 9.1, band: "Critical", text: "Base 8.1; known exploited +1" },
  priority: { decision: "act", label: "Act", rank: 3, fix_by: { text: "within 3 days" }, exposure: "private address" },
  points: { total: 60, list: [{ points: 35, why: "Known exploited (CISA)" }] },
  confidence: "medium", confidence_why: "version 9.6p1 is inside the affected range, but it is a Ubuntu package build: the distribution may have backported the fix; check the package's own changelog",
  seen_on: [{ host: "10.0.0.6", names: ["evil" + EVIL + ".lab"], public: false, port: 22, proto: "ssh", product: "OpenBSD OpenSSH", version: "9.6", shown_version: "9.6p1", distro: "Ubuntu",
    evidence: "SSH banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu " + EVIL, state: "affected", confidence: "medium", confidence_why: "backport" }],
  fix: { fixed_in: ["9.8"], vendor_fixed: [], workaround: [], cisa_required_action: "Apply updates " + EVIL,
    advisory: { name: "Advisory " + EVIL, url: "https://advisories.example.com/a?x=1&y=2" },
    references: ["javascript:alert(1)", "http://plain.example.com/ref", "https://user:pw@creds.example.com/", "https://ok.example.com/ref"],
    details: "https://xanderhutch.github.io/CyberView/vulnerabilities.html#CVE-2026-90101", details_note: "linked, not copied", analysis: null },
  ...o,
});
const report = (o = {}) => {
  const hosts = [{ address: "10.0.0.6", names: [], up: true, ports: [{ port: 22, state: "open" }], services: [{}], http: [{ body: "SECRET-BODY", set_cookie: "session=SECRET-COOKIE" }],
    observations: [{ port: 80, kind: "http-title", severity: "medium", text: "Title " + EVIL }, { port: 443, kind: "tls-expired", severity: "high", text: "expired" }] }];
  const findings = o.findings || [finding()];
  return {
    run: { started_at: "2026-11-22T10:00:00Z", finished_at: "2026-11-22T10:01:00Z", interrupted: false, stop_reason: "", ports: [22, 80, 443],
      settings: { rate: 5, concurrency: 4, hostConcurrency: 2, hostBudget: 300, budget: 20000, minutes: 60 },
      network: { connections: 3, max_open_at_once: 2, sends: { tcp: "one connect per port", http: "one GET / per web port" } }, data: { mode: "offline", source: "/snap", snapshot: { fetched_at: "2026-11-21" } } },
    scope: { file: "scope.json", sha256: "ab".repeat(32), owner: "Owner " + EVIL, contact: "c@example.org", attestation: { statement: STATEMENT, name: "Op " + EVIL, date: "2026-11-20", authorization_ref: "REF-1" },
      targets: ["10.0.0.0/24"], exclude: [], public_addresses: 0, public_confirmed: false, refused: [] },
    summary: summarize(hosts, findings), coverage: o.coverage || coverage(hosts.map((h) => ({ ...h, outcomes: [22, 80, 443].map((port) => ({ port, state: "open" })) })), { ports: [22, 80, 443] }),
    hosts, findings, named: [], notes: ["A note " + EVIL],
  };
};

test("esc and safeHref: text is escaped, only credential-free https URLs become links", () => {
  assert.equal(esc(`<a href="x">'&\``), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#96;");
  assert.equal(esc(null), ""); assert.equal(esc("a\u0000b"), "a�b");
  assert.equal(safeHref("https://ok.example.com/x"), "https://ok.example.com/x");
  for (const bad of ["http://x.example.com/", "javascript:alert(1)", "data:text/html,x", "https://u:p@x.example.com/", " https://x.example.com/\"onmouseover=1", "//x.example.com/", ""]) assert.equal(safeHref(bad), "", bad);
});

test("attacker-controlled banners, titles, names and owner text are escaped; no script, no raw tag from data", () => {
  const h = toHtml(report());
  assert.ok(!/<script/i.test(h), "no <script in the page");
  assert.ok(!/<img/i.test(h), "no raw <img from data");
  assert.ok(h.includes("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"), "the banner is shown, escaped");
  assert.ok(h.includes("&lt;img src=x onerror=&#39;y&#39;&gt;"));
  // every attribute value in the page is one we wrote: class/id/href/rel/role/content/charset/name/lang/http-equiv/scope
  // escaped data can never open a tag, so every tag in the page is ours; each attribute is name="value" with no quote inside
  const attrs = tags(h).flatMap((t) => { const rest = t.replace(/^<[a-z][a-z0-9]*/i, "").replace(/\s*\/?>$/, ""); const pairs = [...rest.matchAll(/\s([a-z-]+)="[^"<>]*"/gi)];
    assert.equal(pairs.map((x) => x[0]).join(""), rest, `tag ${t} has only quoted attributes`); return pairs.map((x) => x[1].toLowerCase()); });
  assert.deepEqual([...new Set(attrs)].filter((a) => !["class", "id", "href", "rel", "role", "content", "charset", "name", "lang", "http-equiv", "scope"].includes(a)), []);
  // response bodies and cookie values are never shown even if a report carried them
  assert.ok(!h.includes("SECRET-BODY") && !h.includes("SECRET-COOKIE"));
});

test("self-contained: no script, no src=, no <link>, no @import or url(); links are https anchors with rel=noopener noreferrer", () => {
  const h = toHtml(report());
  assert.ok(!tags(h).some((t) => /\ssrc\s*=/i.test(t)), "no src= attribute");
  assert.ok(!/<link\b/i.test(h), "no <link>");
  assert.ok(!/<(script|iframe|object|embed|img|video|audio|form|base)\b/i.test(h));
  assert.ok(!/@import|url\(/i.test(h), "CSS loads nothing");
  assert.match(h, /<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'/);
  const anchors = [...h.matchAll(/<a\s([^>]*)>/g)].map((m) => m[1]);
  assert.ok(anchors.length >= 3);
  for (const a of anchors) assert.match(a, /^href="https:\/\/[^"]+" rel="noopener noreferrer"$/);
  assert.ok(!/href="(?!https:)/i.test(h), "only https hrefs");
  assert.ok(!h.includes("creds.example.com"), "a URL with credentials is not linked");
  assert.ok(h.includes('href="https://advisories.example.com/a?x=1&amp;y=2"'), "an href is escaped too");
});

test("run header: what was sent, limits, attestation wording and scope hash", () => {
  const h = toHtml(report());
  assert.ok(h.includes(esc(STATEMENT)), "the attestation statement as recorded");
  assert.ok(h.includes("ab".repeat(32)), "the full scope hash");
  assert.ok(h.includes(esc(USER_AGENT)) && h.includes("one GET / per web port"));
  assert.match(h, /5 new connections\/s, 4 open at once \(2 per host\), at most 300 per host and 20000 in all, stop after 60 min/);
  assert.match(h, /offline snapshot \/snap/);
});

test("the backport caveat is hard to miss on a medium-capped distribution finding, and absent otherwise", () => {
  const h = toHtml(report());
  assert.equal(backportOf(finding()).length, 1);
  assert.match(h, /1 finding\(s\) may already be fixed by a distribution backport/);
  assert.match(h, /Possibly already fixed: distribution package build \(Ubuntu\)/);
  assert.match(h, /Ubuntu may have backported the fix without changing the version number/);
  const plain = finding({ confidence: "high", seen_on: [{ ...finding().seen_on[0], distro: "", confidence: "high" }] });
  assert.ok(!/class="backport"/.test(toHtml(report({ findings: [plain] }))));
});

test("coverage blind spots are listed; a complete scan says so", () => {
  const cov = coverage([{ address: "10.0.0.7", up: false, outcomes: [{ port: 22, state: "filtered" }] },
    { address: "10.0.0.8", up: true, outcomes: [{ port: 22, state: "open", truncated: true }], throttled: 2, throttle_recovered: 1 }], { ports: [22, 80], interrupted: true, stop_reason: "time limit" });
  const h = toHtml(report({ coverage: cov }));
  assert.match(h, /Coverage: blind spots/);
  assert.match(h, /A clean result does NOT cover these blind spots/);
  assert.match(h, /1 host\(s\) answered on no port[^<]*10\.0\.0\.7/);
  assert.match(h, /banner\(s\) were cut off/);
  assert.match(h, /ports left unchecked/);
  assert.match(h, /reset connections after answering/);
  assert.match(h, /stopped early \(time limit\)/);
  assert.match(toHtml(report()), /Every host answered and every port in the list was checked/);
});

test("ranked findings carry rating, SSVC priority, KEV deadline, confidence and fix; low-confidence ones are grouped and out of the counts", () => {
  const low = (cve, i) => finding({ rank: i, cve, kev: false, cisa_due: "", overdue: false, confidence: "low", confidence_why: "the product was seen but it did not state its version",
    seen_on: [{ ...finding().seen_on[0], product: "PHP", distro: "", state: "check", confidence: "low" }] });
  const rep = report({ findings: [finding(), low("CVE-2026-90201", 2), low("CVE-2026-90202", 3)] });
  assert.equal(rep.summary.low_confidence, 2); assert.equal(rep.summary.known_exploited, 1);
  const h = toHtml(rep);
  assert.match(h, /#1 CVE-2026-90101/);
  assert.match(h, /9\.1 Critical/); assert.match(h, /Act \(BOD 26-04: fix within 3 days\)/);
  assert.match(h, /Known exploited \(CISA KEV since 2026-10-20\)/); assert.match(h, /CISA due 2026-11-10 \(OVERDUE\)/);
  assert.match(h, /<strong>medium<\/strong>: version 9\.6p1 is inside the affected range/);
  assert.match(h, /Fixed in<\/th><td>9\.8/);
  assert.match(h, /Low confidence \(not in the counts\): 2/);
  assert.match(h, /<details><summary>PHP: 2 CVE\(s\)<\/summary>/);
  assert.ok(h.indexOf("CVE-2026-90101") < h.indexOf("CVE-2026-90201"), "the confident finding comes first");
  // observations most severe first
  assert.ok(h.indexOf(">expired<") < h.indexOf("Title &lt;script"));
});

test("loopback end to end: --html writes report.html beside the other outputs, sends nothing extra, escapes a hostile Server header", async () => {
  const srv = await startServers({ server: `nginx/1.22.1 <script>alert("x")</script>` });
  try {
    const d = mkdtempSync(join(tmpdir(), "cvscan-html-")), p = join(d, "scope.json");
    writeFileSync(p, JSON.stringify({ cyberview_scope: 1, owner: "Example lab", contact: "lab@example.org",
      attestation: { statement: STATEMENT, agreed: true, name: "Test Operator", date: "2026-11-20", expires: "", authorization_ref: "test" },
      targets: ["127.0.0.1"], exclude: [], ports: [srv.ports.ssh, srv.ports.ftp, srv.ports.http, srv.closed] }));
    const out = [], io = { out: (s) => out.push(s), err: () => {}, sleep: async () => {}, publicWaitMs: 0,
      fetchImpl: () => { throw new Error("no network in this test"); }, resolve: async () => { throw Object.assign(new Error("no DNS"), { code: "ENOTFOUND" }); } };
    assert.equal(await main(["scan", "--scope", p, "--data", SNAP, "--http-ports", String(srv.ports.http), "--out", join(d, "out"), "--html"], io), 0);
    assert.deepEqual(readdirSync(join(d, "out")).sort(), ["findings.csv", "inventory.csv", "report.html", "report.json", "report.sarif", "summary.txt"]);
    assert.equal(statSync(join(d, "out", "report.html")).mode & 0o077, 0, "written privately like the others");
    assert.match(out.join("\n"), /report\.html\)/);
    const h = readFileSync(join(d, "out", "report.html"), "utf8"), rep = JSON.parse(readFileSync(join(d, "out", "report.json"), "utf8"));
    assert.equal(h, toHtml(rep), "report.html is exactly toHtml(report.json)");
    assert.ok(!/<script/i.test(h) && h.includes("nginx/1.22.1 &lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"));
    assert.ok(!tags(h).some((t) => /\ssrc\s*=|^<link\b/i.test(t)));
    // the Ubuntu OpenSSH build in the fixture is capped at medium and carries the caveat
    assert.equal(rep.findings.find((f) => f.cve === "CVE-2026-90101").confidence, "medium");
    assert.match(h, /Possibly already fixed: distribution package build \(Ubuntu\)/);
    // the HTML report is written from report data only: the services got exactly what a scan without --html sends
    for (let i = 0; i < 100 && !srv.got.ssh.length; i++) await new Promise((r) => setTimeout(r, 10));
    assert.deepEqual(srv.got.ftp, []);
    assert.deepEqual(srv.got.ssh, [SSH_IDENT + "\r\n"]);
    assert.equal(srv.got.http.length, 1);
    assert.deepEqual([srv.got.http[0].method, srv.got.http[0].url], ["GET", "/"]);
    assert.equal(rep.run.network.connections <= 4, true);
    // without --html the output folder is unchanged
    const io2 = { ...io, out: () => {} };
    assert.equal(await main(["scan", "--scope", p, "--data", SNAP, "--http-ports", String(srv.ports.http), "--out", join(d, "out2")], io2), 0);
    assert.deepEqual(readdirSync(join(d, "out2")).sort(), ["findings.csv", "inventory.csv", "report.json", "report.sarif", "summary.txt"]);
  } finally { await srv.close(); }
});

/* ---- catalog rows owned by scan-html: explain-mode-evidence, http-body-truncation-recorded, scan-profile-used,
   scope-typo-or-attestation-coaching, stale-snapshot-warning. All computed from data already in hand. ---- */
test("explain-mode-evidence: each finding says which banner/header supported the match, the version and the range", () => {
  const f = finding(), s = f.seen_on[0];
  const t = explain(f, s);
  assert.match(t, /^Evidence: SSH banner: SSH-2\.0-OpenSSH_9\.6p1 Ubuntu/);
  assert.match(t, /stated version 9\.6p1 \(compared as 9\.6\)/);
  assert.match(t, /inside CVE-2026-90101's affected range for OpenBSD OpenSSH/);
  assert.match(t, /Confidence medium: /);
  assert.match(explain(f, { ...s, state: "check", shown_version: "", version: "", evidence: "" }), /No banner or header text was recorded\. .*did not state a version\. .*no version range could be compared/);
  const h = toHtml(report());
  assert.match(h, /Why it matched<\/th><td><ul><li><code>10\.0\.0\.6:22<\/code> Evidence: SSH banner: SSH-2\.0-OpenSSH_9\.6p1 Ubuntu &lt;script&gt;/);
});

test("http-body-truncation-recorded: a root page cut at the size cap is listed; the probe records it and sends nothing more", async () => {
  const rep = report(); rep.hosts[0].http = [{ port: 8080, status: 200, title: "", redirect: "", body_truncated: true }, { port: 80, status: 200 }];
  assert.deepEqual(truncatedBodies(rep), [{ address: "10.0.0.6", port: 8080 }]);
  const h = toHtml(rep);
  assert.match(h, /1 root page\(s\) were cut at the scanner's size cap \(16384 bytes\)<\/strong>: generator tags or library names past that point were not seen/);
  assert.match(h, /<code>10\.0\.0\.6:8080<\/code>/);
  assert.ok(!/size cap/.test(toHtml(report())));
  // real probe on loopback: a page longer than the cap is marked truncated; one GET / per port, nothing else
  const got = [];
  const big = http.createServer((req, res) => { got.push([req.method, req.url]); res.writeHead(200, { "Content-Type": "text/html" }); res.end("<html>" + "x".repeat(TIMEOUTS.maxBytes * 2)); });
  const small = http.createServer((req, res) => { got.push([req.method, req.url]); res.writeHead(200, { "Content-Type": "text/html" }); res.end("<html>ok</html>"); });
  const listen = (s) => new Promise((r) => s.listen(0, "127.0.0.1", () => r(s.address().port)));
  const pb = await listen(big), ps = await listen(small);
  try {
    const rb = await probePort("127.0.0.1", pb, { httpPorts: [pb] }), rs = await probePort("127.0.0.1", ps, { httpPorts: [ps] });
    assert.equal(rb.http.truncated, true); assert.ok(rb.http.body.length <= TIMEOUTS.maxBytes);
    assert.equal(rs.http.truncated, false);
    assert.deepEqual(got, [["GET", "/"], ["GET", "/"]], "exactly one GET / per port");
  } finally { big.closeAllConnections(); small.closeAllConnections(); big.close(); small.close(); }
});

test("scan-profile-used: the profile and what it does not cover", () => {
  const d = scanProfile({ ports: [22, 80, 443], dataMode: "offline" });
  assert.equal(d.name, "default ports");
  assert.match(d.limits.join("\n"), /Only the 3 listed TCP port\(s\) were checked/);
  assert.match(d.limits.join("\n"), /UDP was not checked/);
  assert.match(d.limits.join("\n"), /reported as unreachable, not as clean/);
  const u = scanProfile({ ports: [], allPorts: true, udp: ["dns", "ntp"], assumeUp: true, discover: true });
  assert.equal(u.name, "all TCP ports + UDP on + discovery on + assume up");
  assert.match(u.limits.join("\n"), /UDP: only dns, ntp/);
  const rep = report(); rep.run.profile = scanProfile({ ports: [22], customPorts: true, httpPorts: [8081] });
  const h = toHtml(rep);
  assert.match(h, /<h3>Scan profile: custom ports<\/h3>/); assert.match(h, /Extra web ports: 8081/);
});

test("scope-typo-or-attestation-coaching: likely typos and gaps in a passing scope file, advice only", () => {
  const raw = { cyberview_scope: 1, owner: "Lab", contact: "", attestation: { statement: STATEMENT, agreed: true, name: "Op", date: "2026-11-20", expires: "2026-11-30", expiry: "2027-01-01" },
    targets: ["10.0.0.0/24", "10.0.0.0/24", "lab.example.org"], exclude: ["10.0.0.9", "10.0.0.0/24"], target: ["10.0.1.1"] };
  const text = JSON.stringify(raw), r = checkScope(text, { today: "2026-11-22" });
  assert.equal(r.ok, true, r.problems.join("; "));
  const c = scopeCoaching(text, r.scope, { today: "2026-11-22" }).join("\n");
  assert.match(c, /Unknown key "target" is ignored \(did you mean "targets"\?\)/);
  assert.match(c, /Unknown key "attestation\.expiry" is ignored \(did you mean "expires"\?\)/);
  assert.match(c, /Target "10\.0\.0\.0\/24" is listed more than once/);
  assert.match(c, /"10\.0\.0\.0\/24" is both a target and excluded/);
  assert.match(c, /expires in 8 day\(s\)/);
  assert.match(c, /authorization_ref" is empty/); assert.match(c, /"contact" is empty/);
  // an excluded address outside every listed range (no host-name target, which might resolve inside one)
  const t2 = JSON.stringify({ ...raw, target: undefined, targets: ["10.0.0.0/24"], exclude: ["10.0.0.9", "192.168.5.1"] }), r2 = checkScope(t2, { today: "2026-11-22" });
  const c2 = scopeCoaching(t2, r2.scope, { today: "2026-11-22" }).join("\n");
  assert.match(c2, /Exclude "192\.168\.5\.1" is outside every target/); assert.ok(!/Exclude "10\.0\.0\.9"/.test(c2));
  // a clean scope gets no advice, and advice is shown escaped in the page
  const clean = JSON.stringify({ cyberview_scope: 1, owner: "Lab", contact: "a@example.org", attestation: { statement: STATEMENT, agreed: true, name: "Op", date: "2026-11-20", authorization_ref: "T-1" }, targets: ["10.0.0.0/24"], exclude: ["10.0.0.9"] });
  assert.deepEqual(scopeCoaching(clean, checkScope(clean, { today: "2026-11-22" }).scope, { today: "2026-11-22" }), []);
  const rep = report(); rep.scope.coaching = ['Unknown key "<b>" is ignored.'];
  assert.match(toHtml(rep), /Scope file advice[\s\S]*Unknown key &quot;&lt;b&gt;&quot; is ignored/);
});

test("stale-snapshot-warning: KEV/NVD data older than the threshold at scan time is flagged", () => {
  const rep = report();
  assert.deepEqual(staleData(rep), []);   // fixture data fetched 1 day before the scan
  rep.run.started_at = "2026-12-20T00:00:00Z"; rep.run.data.workbench_built_at = "2026-11-21T12:00:00Z";
  const w = staleData(rep).join("\n");
  assert.equal(STALE_DAYS, 7);
  assert.match(w, /offline snapshot was fetched 29 day\(s\) before this scan/);
  assert.match(w, /KEV\/NVD data was built 28 day\(s\) before this scan/);
  assert.match(toHtml(rep), /Old data: matches may be missing/);
  rep.run.data.snapshot = {}; assert.match(staleData(rep).join("\n"), /does not record when it was fetched/);
});

test("loopback: the CLI prints scope advice before scanning, records the profile and the advice in report.json", async () => {
  const srv = await startServers();
  try {
    const d = mkdtempSync(join(tmpdir(), "cvscan-html-")), p = join(d, "scope.json");
    writeFileSync(p, JSON.stringify({ cyberview_scope: 1, owner: "Example lab", contact: "", target: [],
      attestation: { statement: STATEMENT, agreed: true, name: "Test Operator", date: "2026-11-20" }, targets: ["127.0.0.1"], exclude: [], ports: [srv.ports.ssh] }));
    const out = [], err = [], io = { out: (s) => out.push(s), err: (s) => err.push(s), sleep: async () => {}, publicWaitMs: 0, fetchImpl: () => { throw new Error("no network"); } };
    assert.equal(await main(["check", "--scope", p], io), 0);
    assert.match(out.join("\n"), /SCOPE FILE ADVICE[\s\S]*Unknown key "target"/);
    assert.equal(await main(["scan", "--scope", p, "--data", SNAP, "--out", join(d, "out"), "--html"], io), 0);
    const rep = JSON.parse(readFileSync(join(d, "out", "report.json"), "utf8"));
    assert.equal(rep.run.profile.name, "custom ports"); assert.equal(rep.run.profile.port_count, 1); assert.equal(rep.run.profile.data, "offline");
    assert.ok(rep.scope.coaching.some((c) => /Unknown key "target"/.test(c)));
    const h = readFileSync(join(d, "out", "report.html"), "utf8");
    assert.match(h, /Scan profile: custom ports/); assert.match(h, /Why it matched/);
  } finally { await srv.close(); }
});
