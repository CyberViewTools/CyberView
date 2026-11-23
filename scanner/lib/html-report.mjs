// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// report.html: the same report as report.json and summary.txt, as ONE self-contained page for people who do not read JSON.
// Pure: toHtml(report) -> string. No script, no external stylesheet, font, image or request: inline CSS only, and a
// Content-Security-Policy that forbids everything else, so a page opened from disk cannot reach anything.
// Every value from the report is escaped (banners, titles, host names and certificate names come from the targets and
// are attacker-controlled); links are only https URLs from the report data, as plain anchors.
// No response bodies or cookie values: the report does not hold them, and nothing here reads hosts[].http raw.
import { VERSION, USER_AGENT } from "./probe.mjs";
import { TIMEOUTS } from "./limits.mjs";
import { contains } from "./scope.mjs";
import { icsDevices } from "./report.mjs";

const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };
/** HTML-escape any value as text (also safe inside a double-quoted attribute). */
export const esc = (v, n = 2000) => String(v == null ? "" : v).slice(0, n).replace(/[&<>"'`]/g, (c) => ESC[c])
  .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "�");   // control bytes from a banner shown as a placeholder
/** An https URL without credentials, or "" (http, javascript:, data: and anything unparsable are dropped). */
export function safeHref(u) {
  const s = typeof u === "string" ? u.trim() : "";
  if (!/^https:\/\/[^\s"'<>`]+$/i.test(s) || s.length > 1000) return "";
  try { const x = new URL(s); return x.protocol === "https:" && !x.username && !x.password ? x.href : ""; } catch { return ""; }
}
/** A plain anchor to an https URL, or the text alone when the URL is not one. */
export const link = (u, text) => { const h = safeHref(u); return h ? `<a href="${esc(h)}" rel="noopener noreferrer">${esc(text || h, 300)}</a>` : esc(text || "", 300); };

const arr = (v) => (Array.isArray(v) ? v : []);
const row = (k, v) => `<tr><th scope="row">${esc(k)}</th><td>${v}</td></tr>`;
const SEV = { high: 0, medium: 1, low: 2, info: 3 };

/** A finding capped at medium confidence because the version came from a distribution's package build. */
export const backportOf = (f) => arr(f.seen_on).filter((s) => s.distro && s.state === "affected" && s.confidence === "medium");

/* ---- computed notes (catalog rows owned by scan-html); all pure, from data already in hand, no network ---- */

/** Catalog scan-profile-used: which profile ran, from the invocation, and what that profile does not cover. */
export function scanProfile({ ports = [], allPorts = false, customPorts = false, udp = [], httpPorts = [], httpsPorts = [], assumeUp = false, discover = false, dataMode = "" } = {}) {
  const name = [allPorts ? "all TCP ports" : customPorts ? "custom ports" : "default ports", udp.length ? "UDP on" : "", discover ? "discovery on" : "", assumeUp ? "assume up" : ""].filter(Boolean).join(" + ");
  const limits = [
    allPorts ? "Every TCP port 1-65535 was in the list." : `Only the ${ports.length} listed TCP port(s) were checked; a service on any other port was not seen.`,
    udp.length ? `UDP: only ${udp.join(", ")} (one read-only query each); other UDP services were not checked.` : "UDP was not checked (run with --udp for the DNS, NTP and SNMP checks).",
    `Web: one GET / per web port; no other path was requested, so an application under another path was not seen.${httpPorts.length || httpsPorts.length ? ` Extra web ports: ${[...httpPorts, ...httpsPorts].join(", ")}.` : ""}`,
    "TLS: one handshake per TLS port; a different client may negotiate different parameters.",
    assumeUp ? "Hosts were treated as up even if they answered on no port (--assume-up)." : "A host that answered on none of the listed ports is reported as unreachable, not as clean.",
  ];
  return { name, all_ports: !!allPorts, custom_ports: !!customPorts, port_count: allPorts ? 65535 : ports.length, udp: [...udp], http_ports: [...httpPorts], https_ports: [...httpsPorts], assume_up: !!assumeUp, discover: !!discover, data: dataMode, limits };
}

const SCOPE_KEYS = new Set(["cyberview_scope", "owner", "contact", "attestation", "targets", "exclude", "ports", "discover"]);
const ATT_KEYS = new Set(["statement", "agreed", "name", "date", "expires", "authorization_ref"]);
/** Catalog scope-typo-or-attestation-coaching: likely typos and gaps in a scope file that PASSED its checks. Advice only,
 *  never a refusal (checkScope decides that). text: the scope file as read; scope: checkScope(...).scope. */
export function scopeCoaching(text, scope, { today = new Date().toISOString().slice(0, 10) } = {}) {
  const out = [];
  let j = null; try { j = JSON.parse(String(text)); } catch { return out; }
  if (!j || typeof j !== "object" || !scope) return out;
  for (const k of Object.keys(j)) if (!SCOPE_KEYS.has(k) && !k.startsWith("_")) out.push(`Unknown key "${k}" is ignored${k === "target" ? ' (did you mean "targets"?)' : k === "excludes" || k === "excluded" ? ' (did you mean "exclude"?)' : ""}.`);
  const a = j.attestation && typeof j.attestation === "object" ? j.attestation : {};
  for (const k of Object.keys(a)) if (!ATT_KEYS.has(k)) out.push(`Unknown key "attestation.${k}" is ignored${/^expir/i.test(k) ? ' (did you mean "expires"?)' : /ref/i.test(k) ? ' (did you mean "authorization_ref"?)' : ""}.`);
  const seen = new Set();
  for (const t of scope.targets || []) { const k = String(t.text).toLowerCase(); if (seen.has(k)) out.push(`Target "${t.text}" is listed more than once.`); seen.add(k); }
  for (const x of scope.exclude || []) {
    if (seen.has(String(x.text).toLowerCase())) { out.push(`"${x.text}" is both a target and excluded: it will not be scanned.`); continue; }
    // an address or range outside every listed range is a likely typo (host names are skipped: they may resolve inside one)
    if (x.kind !== "host" && !(scope.targets || []).some((t) => t.kind === "host" || contains(t, String(x.text).split("/")[0])))
      out.push(`Exclude "${x.text}" is outside every target, so it changes nothing; check it for a typo.`);
  }
  const att = scope.attestation || {};
  if (att.expires && /^\d{4}-\d{2}-\d{2}$/.test(att.expires)) { const left = Math.round((Date.parse(att.expires) - Date.parse(today)) / 864e5); if (left >= 0 && left <= 14) out.push(`The attestation expires in ${left} day(s), on ${att.expires}: renew it before the next scan.`); }
  if (!att.authorization_ref) out.push(`"attestation.authorization_ref" is empty: record the reference of the written permission (ticket, contract or letter).`);
  if (!scope.contact) out.push(`"contact" is empty: name who to call if a scanned service misbehaves.`);
  return out.slice(0, 30);
}

export const STALE_DAYS = 7;
/** Catalog stale-snapshot-warning: the KEV/NVD data used is older than STALE_DAYS at scan time. -> [warning text] */
export function staleData(report, { maxDays = STALE_DAYS } = {}) {
  const run = (report && report.run) || {}, data = run.data || {}, at = Date.parse(run.started_at || "");
  if (!isFinite(at)) return [];
  const age = (s) => { const t = Date.parse(s || ""); return isFinite(t) ? Math.floor((at - t) / 864e5) : null; };
  const out = [], snap = data.snapshot && data.snapshot.fetched_at, built = data.workbench_built_at || (data.snapshot && data.snapshot.workbench_built_at);
  const sa = data.mode === "offline" ? age(snap) : null, ba = age(built);
  if (sa != null && sa > maxDays) out.push(`The offline snapshot was fetched ${sa} day(s) before this scan (${snap}); flaws added to CISA's KEV list or NVD since then are not matched. Refresh it with the data command.`);
  if (ba != null && ba > maxDays) out.push(`CyberView's KEV/NVD data was built ${ba} day(s) before this scan (${built}); newer flaws and deadlines are missing.`);
  if (data.mode === "offline" && !snap) out.push("The offline snapshot does not record when it was fetched; its age is unknown.");
  return out;
}

/** Catalog http-body-truncation-recorded: web ports whose root page was cut at the size cap. */
export const truncatedBodies = (report) => arr(report && report.hosts).flatMap((h) => arr(h.http).filter((x) => x.body_truncated).map((x) => ({ address: h.address, port: x.port })));

/** Catalog explain-mode-evidence: why one place matched, in words, from the evidence the probe already recorded. */
export function explain(f, s) {
  const ev = s.evidence ? `Evidence: ${s.evidence}.` : "No banner or header text was recorded.";
  const ver = s.shown_version ? `The service stated version ${s.shown_version}${s.version && s.version !== s.shown_version ? ` (compared as ${s.version})` : ""}.` : "The service did not state a version.";
  const m = s.state === "affected" ? `That version is inside ${f.cve}'s affected range for ${[f.vendor, f.product].filter(Boolean).join(" ")}.` : `The product matches ${f.cve}, but no version range could be compared.`;
  return `${ev} It was identified as ${s.product}. ${ver} ${m} Confidence ${s.confidence}: ${s.confidence_why}.`;
}

const CSS = `:root{--bg:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--card:#f6f8fa;--warn-bg:#fff4d6;--warn-line:#b07d00;--bad:#b42318;--note-bg:#eef4ff}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9aa4af;--line:#30363d;--card:#161b22;--warn-bg:#3a2e05;--warn-line:#d4a72c;--bad:#ff7b72;--note-bg:#10213f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1000px;margin:0 auto;padding:16px}h1{font-size:1.5em;margin:.2em 0}h2{font-size:1.2em;margin:1.6em 0 .5em;border-bottom:1px solid var(--line);padding-bottom:.2em}h3{font-size:1.05em;margin:0 0 .4em}
.muted{color:var(--muted)}table{border-collapse:collapse;width:100%;margin:.3em 0}th,td{text-align:left;vertical-align:top;padding:4px 8px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}th[scope=row]{width:11em;color:var(--muted);font-weight:600}
.counts{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px}.count{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px}.count b{display:block;font-size:1.4em}
.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px;margin:10px 0}.tag{display:inline-block;border:1px solid var(--line);border-radius:4px;padding:0 6px;margin:0 4px 4px 0;font-size:.85em}
.kev{border-color:var(--bad);color:var(--bad);font-weight:700}.overdue{background:var(--bad);color:var(--bg);border-color:var(--bad);font-weight:700}
.backport{background:var(--warn-bg);border:2px solid var(--warn-line);border-radius:6px;padding:10px 12px;margin:8px 0}.backport strong{display:block}
.gaps{background:var(--warn-bg);border-left:4px solid var(--warn-line);padding:8px 12px}.ok{background:var(--note-bg);padding:8px 12px;border-radius:6px}
ul{margin:.3em 0;padding-left:1.4em}code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em;overflow-wrap:anywhere}details{margin:6px 0}summary{cursor:pointer;font-weight:600}
@media print{.card,.backport{break-inside:avoid}details{display:block}}`;

function headerSection(r) {
  const run = r.run || {}, sc = r.scope || {}, a = sc.attestation || {}, st = run.settings || {}, net = run.network || {}, data = run.data || {};
  const ports = arr(run.ports);
  const sends = Object.entries(net.sends || {}).map(([k, v]) => `<li><code>${esc(k)}</code> ${esc(v)}</li>`).join("");
  const dataLine = data.mode === "offline" ? `offline snapshot ${data.source || ""} (fetched ${(data.snapshot && data.snapshot.fetched_at) || "?"}); no data request was made`
    : data.mode ? `online: read-only GET requests to ${data.source || "?"} for CyberView's data files (${data.requests || 0} request(s))` : "none";
  return `<h2 id="run">Run</h2><table>
${row("Scanner", esc(`CyberView Scanner ${VERSION}`) + ` <span class="muted">detection only: it reads versions and matches them with published data; it never exploits, logs in or changes anything.</span>`)}
${row("Started", esc(run.started_at))}${row("Finished", esc(run.finished_at) + (run.interrupted ? ` <span class="tag overdue">stopped early: ${esc(run.stop_reason || "limit reached")}</span>` : ""))}
</table>
<h2 id="authorization">Authorization (from the scope file)</h2><table>
${row("Scope file", `<code>${esc(sc.file)}</code>`)}${row("Scope sha256", `<code>${esc(sc.sha256)}</code>`)}
${row("Owner", esc(sc.owner) + (sc.contact ? ` (${esc(sc.contact)})` : ""))}
${row("Attested by", `${esc(a.name)} on ${esc(a.date)}${a.expires ? `, valid until ${esc(a.expires)}` : ""}${a.authorization_ref ? `, authorization ${esc(a.authorization_ref)}` : ""}`)}
${row("Statement", `“${esc(a.statement)}”`)}
</table><p class="muted">The attestation is the operator's recorded statement and the scope file's hash, not a signature.</p>
<h2 id="scope">Scope and limits</h2><table>
${row("Targets", esc(arr(sc.targets).join(", ")))}${arr(sc.exclude).length ? row("Excluded", esc(sc.exclude.join(", "))) : ""}
${row("Public addresses", esc(sc.public_addresses || 0) + (sc.public_confirmed ? " (confirmed with --i-am-authorized-for-public-ranges)" : ""))}
${arr(sc.refused).length ? row("Skipped", esc(sc.refused.slice(0, 50).map((x) => `${x.target}: ${x.why}`).join("; "))) : ""}
${row("TCP ports", esc(ports.length > 40 ? `${ports.length} ports ${ports[0]}-${ports[ports.length - 1]}` : ports.join(", ")))}
${arr(run.udp).length ? row("UDP", esc(run.udp.join(", ")) + " (one benign read-only query each)") : ""}
${row("Limits", esc(`${st.rate} new connections/s, ${st.concurrency} open at once (${st.hostConcurrency} per host), at most ${st.hostBudget} per host and ${st.budget} in all, stop after ${st.minutes} min`))}
${row("Connections made", esc(net.connections ?? "?") + (net.max_open_at_once != null ? `, at most ${esc(net.max_open_at_once)} open at once` : ""))}
</table>
${profileRows(run.profile)}
<h3>What was sent</h3><ul><li>User-Agent: <code>${esc(USER_AGENT)}</code></li>${sends}<li>Data: ${esc(dataLine)}</li></ul>
<p class="muted">Results are written to this machine only; nothing is uploaded.</p>
${arr(sc.coaching).length ? `<h3>Scope file advice (it passed its checks; these look like typos or gaps)</h3><ul>${sc.coaching.map((c) => `<li>${esc(c, 400)}</li>`).join("")}</ul>` : ""}`;
}

function profileRows(p) {
  if (!p || typeof p !== "object") return "";
  return `<h3>Scan profile: ${esc(p.name)}</h3><p class="muted">What this profile does not cover:</p><ul>${arr(p.limits).map((l) => `<li>${esc(l, 400)}</li>`).join("")}</ul>`;
}

function staleSection(r) {
  const w = staleData(r);
  return w.length ? `<div class="gaps" role="note"><p><strong>Old data: matches may be missing.</strong></p><ul>${w.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>` : "";
}

function summarySection(r) {
  const s = r.summary || {}, c = (n, label) => `<div class="count"><b>${esc(n ?? 0)}</b>${esc(label)}</div>`;
  return `<h2 id="summary">Summary</h2><div class="counts">
${c(s.hosts_in_scope, "hosts in scope")}${c(s.hosts_up, "hosts up")}${c(s.open_ports, "open ports")}${c(s.services_identified, "services identified")}
${c(s.known_exploited, "known exploited (CISA)")}${c(s.critical, "rated Critical")}${c(s.act, "at priority Act")}${c(s.overdue, "past CISA's deadline")}
</div><p>Findings ${esc(s.findings ?? 0)} (${esc(s.version_confirmed ?? 0)} with the version inside an affected range${s.low_confidence ? `; ${esc(s.low_confidence)} low-confidence, listed at the end but not in the counts above` : ""}).</p>`;
}

function coverageSection(r) {
  const tb = truncatedBodies(r);
  const cut = tb.length ? `<div class="gaps"><p><strong>${esc(tb.length)} root page(s) were cut at the scanner's size cap (${esc(TIMEOUTS.maxBytes)} bytes)</strong>: generator tags or library names past that point were not seen.</p><ul>${tb.slice(0, 50).map((t) => `<li><code>${esc(t.address)}:${esc(t.port)}</code></li>`).join("")}</ul></div>` : "";
  return coverageCore(r) + cut;
}
function coverageCore(r) {
  const cov = r.coverage;
  if (!cov) return `<h2 id="coverage">Coverage</h2><p class="gaps">This report does not record coverage; treat a clean result with care.</p>`;
  if (cov.complete) return `<h2 id="coverage">Coverage</h2><p class="ok">Every host answered and every port in the list was checked. A clean result still covers only the ports and services listed above.</p>`;
  const L = [];
  if (arr(cov.hosts_unreachable).length) L.push(`${cov.hosts_unreachable.length} host(s) answered on no port (filtered/dropped, possibly firewalled or down): ${cov.hosts_unreachable.slice(0, 50).join(", ")}${cov.hosts_unreachable.length > 50 ? ", ..." : ""}`);
  if (cov.ports_filtered) L.push(`${cov.ports_filtered} port probe(s) were filtered/dropped (no answer): not confirmed closed.`);
  if (arr(cov.truncated_banners).length) L.push(`${cov.truncated_banners.reduce((n, t) => n + (Number(t.count) || 0), 0)} banner(s) were cut off before a version was seen on: ${cov.truncated_banners.slice(0, 20).map((t) => t.address).join(", ")}; the service may be present but unread.`);
  if (arr(cov.ports_not_checked).length) L.push(`${cov.ports_not_checked.length} host(s) had ports left unchecked when a limit was hit: ${cov.ports_not_checked.slice(0, 20).map((t) => `${t.address} (${t.not_checked})`).join(", ")}.`);
  if (arr(cov.throttled).length) L.push(`${cov.throttled.length} host(s) reset connections after answering (possible IPS/fail2ban throttling); the scanner backed off and retried: ${cov.throttled.slice(0, 20).map((t) => `${t.address} (${t.recovered} found on retry)`).join(", ")}. If any still look thin, re-scan slower (--rate 0.1).`);
  if (cov.interrupted) L.push(`The scan stopped early (${cov.stop_reason || (r.run && r.run.stop_reason) || "limit reached"}).`);
  return `<h2 id="coverage">Coverage: blind spots</h2><div class="gaps"><p><strong>The scan could not see everything below. A clean result does NOT cover these blind spots.</strong></p><ul>${L.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>`;
}

function backportBox(f) {
  const bp = backportOf(f);
  if (!bp.length) return "";
  const distros = [...new Set(bp.map((s) => s.distro))];
  return `<div class="backport" role="note"><strong>Possibly already fixed: distribution package build (${esc(distros.join(", "))})</strong>
The version was read from a distribution package build (${esc(distros.join(", "))}). ${esc(distros.join(" or "))} may have backported the fix without changing the version number, so this match is capped at medium confidence. Check the installed package's own changelog or the distribution's security tracker for ${esc(f.cve)} before acting.
<ul>${bp.slice(0, 10).map((s) => `<li><code>${esc(s.host)}:${esc(s.port)}</code> ${esc(s.product)} ${esc(s.shown_version)}</li>`).join("")}</ul></div>`;
}

function findingCard(f) {
  const pr = f.priority, fix = f.fix || {}, rt = f.rating || {};
  const tags = [f.kev ? `<span class="tag kev">Known exploited (CISA KEV${f.kev_added ? ` since ${esc(f.kev_added)}` : ""})</span>` : "",
    f.cisa_due ? `<span class="tag${f.overdue ? " overdue" : ""}">CISA due ${esc(f.cisa_due)}${f.overdue ? " (OVERDUE)" : ""}</span>` : "",
    f.ransomware ? `<span class="tag">used in ransomware</span>` : "", f.epss != null ? `<span class="tag">EPSS ${esc(f.epss)}</span>` : "",
    f.state === "affected" ? `<span class="tag">version in affected range</span>` : `<span class="tag">product seen, version to check</span>`].join("");
  const seen = arr(f.seen_on);
  const refs = arr(fix.references).map((u) => safeHref(u)).filter(Boolean);
  const fixedIn = arr(fix.vendor_fixed).length ? fix.vendor_fixed : arr(fix.fixed_in);
  return `<article class="card" id="${esc(f.cve)}"><h3>#${esc(f.rank)} ${esc(f.cve)} ${esc(f.title, 200)}</h3>
<div>${tags}</div>${backportBox(f)}<table>
${row("Product", esc([f.vendor, f.product].filter(Boolean).join(" ")))}
${row("CyberView rating", rt.score == null ? esc(rt.band || "Not scored") : esc(`${Number(rt.score).toFixed(1)} ${rt.band}`) + (rt.text ? `<br><span class="muted">${esc(rt.text)}</span>` : ""))}
${row("SSVC priority", pr ? esc(pr.label) + (pr.fix_by && pr.fix_by.text ? ` (BOD 26-04: fix ${esc(pr.fix_by.text)})` : "") + (pr.exposure ? ` <span class="muted">${esc(pr.exposure)}</span>` : "") : "-")}
${row("Queue points", `${esc(f.points && f.points.total)}: ${esc(arr(f.points && f.points.list).map((p) => `${p.why} +${p.points}`).join("; "))}`)}
${row("Confidence", `<strong>${esc(f.confidence)}</strong>: ${esc(f.confidence_why)}`)}
${row("Seen on", `<ul>${seen.slice(0, 25).map((s) => `<li><code>${esc(s.host)}:${esc(s.port)}</code>${arr(s.names).length ? ` (${esc(s.names.slice(0, 5).join(", "))})` : ""} ${esc(s.product)} ${esc(s.shown_version || "(no version)")} [${esc(s.confidence)}]</li>`).join("")}</ul>${seen.length > 25 ? `<span class="muted">and ${esc(seen.length - 25)} more in report.json</span>` : ""}`)}
${row("Why it matched", `<ul>${seen.slice(0, 10).map((s) => `<li><code>${esc(s.host)}:${esc(s.port)}</code> ${esc(explain(f, s), 900)}</li>`).join("")}</ul>`)}
${fixedIn.length ? row("Fixed in", esc(fixedIn.join("; "))) : ""}
${arr(fix.workaround).length ? row("Workaround (vendor)", `<ul>${fix.workaround.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>`) : ""}
${fix.cisa_required_action ? row("CISA required action", esc(fix.cisa_required_action, 700)) : ""}
${fix.advisory && safeHref(fix.advisory.url) ? row("Vendor advisory", link(fix.advisory.url, fix.advisory.name || fix.advisory.url)) : ""}
${refs.length ? row("References", `<ul>${refs.slice(0, 6).map((u) => `<li>${link(u)}</li>`).join("")}</ul>`) : ""}
${safeHref(fix.details) ? row("Details", link(fix.details, "CyberView's page for this CVE") + (fix.details_note ? `<br><span class="muted">${esc(fix.details_note)}</span>` : "")) : ""}
${fix.analysis && safeHref(fix.analysis.url) ? row("Exploitation analysis", link(fix.analysis.url, "on CyberView") + ` <span class="muted">written by ${esc(fix.analysis.by || "CyberView AI (a Claude model)")}</span>`) : ""}
</table></article>`;
}

function findingsSection(r) {
  const all = arr(r.findings), strong = all.filter((f) => f.confidence !== "low"), low = all.filter((f) => f.confidence === "low");
  const bp = strong.filter((f) => backportOf(f).length);
  const L = [`<h2 id="findings">Findings, ranked (patch first at the top)</h2>`];
  L.push(`<p class="muted">Same order as findings.csv: known exploited (CISA KEV) first, then exploited by other evidence, past CISA's deadline, version-confirmed, then the CyberView rating, the SSVC priority, the nearest deadline and EPSS.</p>`);
  if (bp.length) L.push(`<div class="backport" role="note"><strong>${esc(bp.length)} finding(s) may already be fixed by a distribution backport.</strong>They rest on a version read from a Linux distribution's package build (for example Ubuntu or Debian). Distributions often backport security fixes without changing the upstream version number, so these are capped at medium confidence and marked below. Check the package changelog before patching or reporting them as open.</div>`);
  if (!strong.length) L.push(`<p>No finding at medium or high confidence.${r.coverage && !r.coverage.complete ? " See the blind spots above: a clean result does not cover them." : ""}</p>`);
  strong.forEach((f) => L.push(findingCard(f)));
  if (low.length) {
    // low-confidence rows (no version read, or no range to compare) grouped per product and collapsed, so they never bury the real ones
    const by = new Map();
    for (const f of low) { const k = (arr(f.seen_on)[0] && f.seen_on[0].product) || [f.vendor, f.product].filter(Boolean).join(" ") || "unknown"; if (!by.has(k)) by.set(k, []); by.get(k).push(f); }
    L.push(`<h2 id="low">Low confidence (not in the counts): ${esc(low.length)}</h2><p class="muted">The product was seen but its version could not be compared. Check the version by hand; each is in report.json and findings.csv with its reason.</p>`);
    for (const [k, list] of by) L.push(`<details><summary>${esc(k)}: ${esc(list.length)} CVE(s)${list.some((f) => f.kev) ? ", some known exploited" : ""}</summary>${list.map((f) => findingCard(f)).join("")}</details>`);
  }
  return L.join("\n");
}

function industrialSection(r) {
  const ics = icsDevices(r);
  if (!ics.length) return "";
  const L = [`<h2 id="industrial">Industrial (ICS/OT) devices</h2>`];
  L.push(`<p class="muted">Identified by <code>--ics</code> read-only identification. Inventory only, low confidence; not in the counts above and never matched to CVEs.</p>`);
  L.push(`<table><thead><tr><th>Where</th><th>Protocol</th><th>Vendor</th><th>Product</th><th>Model</th><th>Firmware</th></tr></thead><tbody>`);
  ics.forEach((d) => L.push(`<tr><td><code>${esc(d.host)}:${esc(d.port)}</code></td><td>${esc(d.name)}</td><td>${esc(d.vendor)}</td><td>${esc(d.product)}</td><td>${esc(d.model)}</td><td>${esc(d.firmware || d.version)}</td></tr>`));
  L.push(`</tbody></table>`);
  return L.join("\n");
}

function observationsSection(r) {
  const obs = arr(r.hosts).flatMap((h) => arr(h.observations).map((o) => ({ h, o }))).sort((a, b) => (SEV[a.o.severity] ?? 3) - (SEV[b.o.severity] ?? 3));
  const dropped = arr(r.hosts).reduce((n, h) => n + (Number(h.observations_dropped) || 0), 0);
  const L = [];
  if (obs.length) {
    L.push(`<h2 id="observations">Observations (not CVEs; most severe first)</h2><table><thead><tr><th>Where</th><th>Severity</th><th>What</th></tr></thead><tbody>`);
    obs.slice(0, 300).forEach(({ h, o }) => L.push(`<tr><td><code>${esc(h.address)}:${esc(o.port)}</code></td><td>${esc(o.severity || "info")}</td><td>${esc(o.text, 400)}</td></tr>`));
    L.push(`</tbody></table>`);
    if (obs.length > 300 || dropped) L.push(`<p class="muted">${obs.length > 300 ? `${esc(obs.length - 300)} more in report.json. ` : ""}${dropped ? `${esc(dropped)} over the per-host cap were counted, not listed.` : ""}</p>`);
  }
  if (arr(r.named).length) {
    L.push(`<h2 id="named">Also named in the CVE List (versions not checked)</h2><p class="muted">Compare each with the vendor's advisory.</p><ul>`);
    r.named.forEach((n) => L.push(`<li>${esc(n.product)} ${esc(n.version_seen || "")}: ${esc(n.cves_naming_it)} CVE(s), ${esc(n.exploited)} exploited</li>`));
    L.push(`</ul>`);
  }
  if (arr(r.notes).length) L.push(`<h2 id="notes">Notes</h2><ul>${r.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>`);
  return L.join("\n");
}

/** The whole report as one self-contained HTML page (no script, no external resource). Pure. */
export function toHtml(report) {
  const r = report || {};
  const sum = r.summary || {};
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>CyberView scan report</title>
<style>${CSS}</style></head>
<body><main>
<h1>CyberView scan report</h1>
<p class="muted">${esc((r.scope && r.scope.owner) || "")} · ${esc((r.run && r.run.started_at) || "")} · ${esc(sum.findings ?? 0)} finding(s). Detection only. This file was written on the scanning machine; it loads nothing from the network.</p>
${headerSection(r)}
${staleSection(r)}
${summarySection(r)}
${coverageSection(r)}
${findingsSection(r)}
${industrialSection(r)}
${observationsSection(r)}
<p class="muted">Generated by CyberView Scanner ${esc(VERSION)}. Same data as report.json, findings.csv, report.sarif and summary.txt.</p>
</main></body></html>
`;
}
