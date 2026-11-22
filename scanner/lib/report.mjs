// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// The report and its exports: JSON (everything), CSV (one row per CVE and place seen), SARIF 2.1.0 (for code-scanning
// dashboards), an inventory CSV (the Vulnerabilities page's "My software" view reads it), and a plain-text summary.
// Written to the operator's own disk only; nothing here sends anything anywhere.
import { VERSION, INFO_URL, USER_AGENT } from "./probe.mjs";

export function summarize(hosts, findings) {
  const up = hosts.filter((h) => h.up), services = up.reduce((n, h) => n + (h.services || []).length, 0);
  return {
    hosts_in_scope: hosts.length, hosts_up: up.length, open_ports: up.reduce((n, h) => n + (h.ports || []).filter((p) => p.state === "open").length, 0), services_identified: services,
    findings: findings.length, version_confirmed: findings.filter((f) => f.state === "affected").length, known_exploited: findings.filter((f) => f.kev).length,
    critical: findings.filter((f) => f.rating && f.rating.band === "Critical").length, act: findings.filter((f) => f.priority && f.priority.decision === "act").length,
    overdue: findings.filter((f) => f.overdue).length, observations: up.reduce((n, h) => n + (h.observations || []).length, 0),
  };
}

/** Every queue point with its reason: "Known exploited (CISA) +35; ..." */
export const pointList = (f) => f.points.list.map((p) => `${p.why} +${p.points}`).join("; ");

/* ---- CSV ---- */
const cell = (v) => { let s = v == null ? "" : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };   // a leading = + - @ is quoted so a spreadsheet never runs it
export const CSV_HEAD = ["rank", "cve", "title", "host", "names", "port", "service", "version_seen", "match", "confidence", "known_exploited", "cisa_due", "overdue", "ransomware", "epss",
  "cyberview_rating", "rating_band", "rating_points", "ssvc_priority", "fix_by", "queue_points", "queue_point_list", "fixed_in", "vendor_fixed", "advisory", "details"];
export function toCsv(report) {
  const rows = [CSV_HEAD];
  for (const f of report.findings) for (const s of f.seen_on) rows.push([f.rank, f.cve, f.title, s.host, s.names.join(" "), s.port, s.product, s.shown_version, s.state === "affected" ? "version in affected range" : "product seen, version to check",
    s.confidence, f.kev ? "yes" : "no", f.cisa_due, f.overdue ? "yes" : "no", f.ransomware ? "yes" : "no", f.epss == null ? "" : f.epss,
    f.rating.score == null ? "" : f.rating.score.toFixed(1), f.rating.band, f.rating.text, f.priority ? f.priority.label : "", f.priority && f.priority.fix_by ? f.priority.fix_by.text : "",
    f.points.total, pointList(f), f.fix.fixed_in.join(" "), f.fix.vendor_fixed.join("; "), f.fix.advisory ? f.fix.advisory.url : "", f.fix.details]);
  return rows.map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}

/** The detected software as the inventory CSV the Vulnerabilities page's "My software" view imports. */
export function toInventory(report) {
  const m = new Map();
  for (const h of report.hosts) for (const s of h.services || []) if (s.product) { const k = `${s.vendor}|${s.product}|${s.version}`; m.set(k, { vendor: s.vendor, name: s.product, version: s.shown_version || s.version, count: ((m.get(k) || {}).count || 0) + 1 }); }
  return [["name", "version", "vendor", "count"], ...[...m.values()].map((x) => [x.name, x.version, x.vendor, x.count])].map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}

/* ---- SARIF 2.1.0 ---- */
const LEVEL = (f) => (f.kev || (f.priority && f.priority.rank >= 3) || f.rating.band === "Critical" ? "error" : f.rating.band === "High" || f.rating.band === "Medium" ? "warning" : "note");
export function toSarif(report) {
  const rules = report.findings.map((f) => ({
    id: f.cve, name: f.cve, shortDescription: { text: (f.title || f.cve).slice(0, 200) },
    fullDescription: { text: `${f.vendor} ${f.product}: ${f.title}`.slice(0, 1000) }, helpUri: f.fix.details,
    help: { text: [f.fix.cisa_required_action, f.fix.fixed_in.length ? `Fixed in: ${f.fix.fixed_in.join(", ")}` : "", f.fix.advisory ? `Vendor advisory: ${f.fix.advisory.url}` : "", `Details: ${f.fix.details}`].filter(Boolean).join("\n") },
    properties: { "security-severity": f.rating.score == null ? "0.0" : f.rating.score.toFixed(1), tags: ["security", "vulnerability", ...(f.kev ? ["known-exploited"] : [])] },
  }));
  const results = [];
  report.findings.forEach((f, i) => f.seen_on.forEach((s) => results.push({
    ruleId: f.cve, ruleIndex: i, level: LEVEL(f), rank: Math.max(0, Math.min(100, (f.rating.score ?? 0) * 10)),
    message: { text: `${f.cve} ${s.state === "affected" ? "affects" : "may affect"} ${s.product} ${s.shown_version || "(version not stated)"} on ${s.host}:${s.port}. CyberView rating ${f.rating.score == null ? "not scored" : f.rating.score.toFixed(1) + " " + f.rating.band}${f.priority ? `; priority ${f.priority.label}` : ""}${f.kev ? "; known exploited (CISA)" : ""}. Confidence ${s.confidence}: ${s.confidence_why}.` },
    locations: [{ physicalLocation: { artifactLocation: { uri: `tcp://${/:/.test(s.host) ? `[${s.host}]` : s.host}:${s.port}` } }, logicalLocations: [{ name: `${s.host}:${s.port}`, kind: "module" }] }],
    partialFingerprints: { "cyberviewFinding/v1": `${f.cve}|${s.host}|${s.port}` },
    properties: { confidence: s.confidence, evidence: s.evidence, rating: f.rating.text, queue_points: pointList(f), known_exploited: f.kev, cisa_due: f.cisa_due || null },
  })));
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0",
    runs: [{ tool: { driver: { name: "CyberView Scanner", version: VERSION, informationUri: INFO_URL, rules } }, results,
      invocations: [{ executionSuccessful: !report.run.interrupted, startTimeUtc: report.run.started_at, endTimeUtc: report.run.finished_at }],
      properties: { scope_owner: report.scope.owner, attestation: report.scope.attestation, summary: report.summary } }],
  };
}

/* ---- the run header and the text summary ---- */
export function header({ scope, scopeFile, scopeHash, settings, allowPublic, ports, allPorts = false, udp = [], udpSends = {}, data, sends }) {
  const a = scope.attestation, L = [];
  L.push("CyberView Scanner " + VERSION + " - detection only: it reads versions and matches them with published data; it never exploits, logs in or changes anything.");
  L.push("");
  L.push("AUTHORIZATION (from the scope file)");
  L.push(`  Scope file:  ${scopeFile} (sha256 ${scopeHash.slice(0, 16)})`);
  L.push(`  Owner:       ${scope.owner}${scope.contact ? ` (${scope.contact})` : ""}`);
  L.push(`  Attested by: ${a.name} on ${a.date}${a.expires ? `, valid until ${a.expires}` : ""}${a.authorization_ref ? `, authorization ${a.authorization_ref}` : ""}`);
  L.push(`  Statement:   "${a.statement}"`);
  L.push("");
  L.push("SCOPE");
  L.push(`  Targets:     ${scope.targets.map((t) => t.text).join(", ")}`);
  if (scope.exclude.length) L.push(`  Excluded:    ${scope.exclude.map((t) => t.text).join(", ")}`);
  L.push(`  Addresses:   ${scope.addressCount}${scope.hosts.length ? ` plus ${scope.hosts.length} host name(s)` : ""}; public addresses: ${scope.publicCount}${scope.needsPublic ? (allowPublic ? " (confirmed with --i-am-authorized-for-public-ranges)" : "") : ""}`);
  L.push(`  Ports:       ${allPorts ? "all 65535 TCP ports (--all-ports; owned private ranges only)" : ports.length > 40 ? `${ports.length} TCP ports ${ports[0]}-${ports[ports.length - 1]}` : ports.join(", ")}`);
  if (scope.discover) L.push(`  Discovery:   ${[scope.discover.cidr ? "cidr sweep" : "", scope.discover.domains.length ? `${scope.discover.domains.length} owned domain(s)${scope.discover.ct ? " + Certificate Transparency" : ""}` : "", scope.discover.import.length ? `${scope.discover.import.length} import file(s)` : "", scope.discover.cloud.length ? `${scope.discover.cloud.length} cloud inventory file(s)` : ""].filter(Boolean).join(", ") || "configured"} (every host re-checked against this scope)`);
  if (udp.length) L.push(`  UDP:         ${udp.join(", ")} (one benign read-only query each)`);
  L.push("");
  L.push("LIMITS");
  L.push(`  ${settings.rate} new connections/s, ${settings.concurrency} open at once (${settings.hostConcurrency} per host), at most ${settings.hostBudget} per host and ${settings.budget} in all, stop after ${settings.minutes} min`);
  L.push("");
  L.push("WHAT IS SENT");
  L.push(`  User-Agent:  ${USER_AGENT}`);
  for (const [k, v] of Object.entries(sends)) L.push(`  ${k.padEnd(9)} ${v}`);
  for (const k of udp) L.push(`  ${("udp-" + k).padEnd(9)} ${udpSends[k]}`);
  L.push(`  Data:        ${data}`);
  L.push("  Results are written to this machine only; nothing is uploaded.");
  return L.join("\n");
}

export function summaryText(report) {
  const s = report.summary, L = [];
  L.push(`Hosts in scope ${s.hosts_in_scope}, up ${s.hosts_up}; open ports ${s.open_ports}; services identified ${s.services_identified}.`);
  L.push(`Findings ${s.findings} (${s.version_confirmed} with the version inside an affected range): ${s.known_exploited} known exploited (CISA), ${s.critical} rated Critical, ${s.act} at priority Act, ${s.overdue} past CISA's deadline.`);
  if (report.run.interrupted) L.push(`The scan stopped early (${report.run.stop_reason}): the results cover only what was checked.`);
  for (const f of report.findings.slice(0, 25)) {
    L.push("");
    L.push(`#${f.rank} ${f.cve} ${f.title}`.slice(0, 160));
    L.push(`   Seen on: ${f.seen_on.slice(0, 4).map((x) => `${x.host}:${x.port} ${x.product} ${x.shown_version || "(no version)"} [${x.confidence}]`).join("; ")}${f.seen_on.length > 4 ? ` and ${f.seen_on.length - 4} more` : ""}`);
    L.push(`   ${f.kev ? `KNOWN EXPLOITED (CISA KEV since ${f.kev_added || "?"})${f.cisa_due ? `, CISA due ${f.cisa_due}${f.overdue ? " (OVERDUE)" : ""}` : ""}; ` : ""}priority ${f.priority ? f.priority.label : "-"}${f.priority && f.priority.fix_by ? ` (BOD 26-04: fix ${f.priority.fix_by.text})` : ""}`);
    L.push(`   CyberView rating: ${f.rating.text || f.rating.band}`);
    L.push(`   Queue points ${f.points.total}: ${pointList(f)}`);
    L.push(`   Confidence ${f.confidence}: ${f.confidence_why}`);
    if (f.fix.fixed_in.length || f.fix.vendor_fixed.length) L.push(`   Fixed in: ${(f.fix.vendor_fixed.length ? f.fix.vendor_fixed : f.fix.fixed_in).join("; ")}`);
    if (f.fix.cisa_required_action) L.push(`   CISA required action: ${f.fix.cisa_required_action.slice(0, 300)}`);
    if (f.fix.advisory) L.push(`   Vendor advisory: ${f.fix.advisory.url}`);
    L.push(`   Details: ${f.fix.details}`);
  }
  if (report.findings.length > 25) L.push(`\n... and ${report.findings.length - 25} more in report.json and findings.csv.`);
  const obs = report.hosts.flatMap((h) => (h.observations || []).map((o) => `${h.address}:${o.port} ${o.text}`));
  if (obs.length) { L.push(""); L.push("Observations (not CVEs):"); obs.slice(0, 30).forEach((o) => L.push(`   ${o}`)); }
  if ((report.named || []).length) { L.push(""); L.push("Also named in the CVE List (versions not checked; compare with the vendor's advisory):"); report.named.forEach((n) => L.push(`   ${n.product} ${n.version_seen || ""}: ${n.cves_naming_it} CVE(s), ${n.exploited} exploited`)); }
  L.push(""); report.notes.forEach((n) => L.push(`Note: ${n}`));
  return L.join("\n");
}
