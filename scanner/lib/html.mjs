// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// A self-contained HTML report. No external resources and no executable markup: the operator opens one file.
// Every value is escaped. The distribution-backport caveat is in the page header so a medium-confidence
// package build cannot be read as proof the fix is missing.
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const https = (u) => (/^https:\/\/[^\s"'<>]+$/.test(String(u || "")) ? String(u) : "");

const CSS = `
body { font: 15px/1.45 system-ui, sans-serif; margin: 0; color: #1c1917; background: #fafaf9; }
header, main { max-width: 960px; margin: 0 auto; padding: 1.2rem 1.4rem; }
header { background: #1c1917; color: #fafaf9; }
h1 { font-size: 1.35rem; margin: 0 0 .3rem; }
.muted { color: #57534e; }
header .muted { color: #d6d3d1; }
.banner { background: #fef3c7; border: 1px solid #d97706; padding: .8rem 1rem; margin: 1rem 0; }
.banner strong { display: block; margin-bottom: .25rem; }
table { border-collapse: collapse; width: 100%; background: #fff; }
th, td { text-align: left; vertical-align: top; border-bottom: 1px solid #e7e5e4; padding: .45rem .5rem; }
th { font-size: .8rem; letter-spacing: .02em; }
.low { color: #57534e; }
a { color: #1d4ed8; }
`;

function row(cells, tag = "td") { return "<tr>" + cells.map((c) => `<${tag}>${c}</${tag}>`).join("") + "</tr>"; }

/** report.json's object -> one HTML document. */
export function toHtml(report) {
  const r = report || {}, s = r.summary || {}, findings = r.findings || [], hosts = r.hosts || [];
  const distroSeen = hosts.some((h) => (h.services || []).some((x) => x.distro)) || findings.some((f) => (f.seen_on || []).some((x) => x.distro));
  const counts = `Hosts in scope ${s.hosts_in_scope ?? 0}, up ${s.hosts_up ?? 0}. Findings ${s.findings ?? findings.length}`
    + ` (${s.version_confirmed ?? 0} with a version inside an affected range). Known exploited ${s.known_exploited ?? 0}, Critical ${s.critical ?? 0}.`;
  const findingRows = findings.slice(0, 200).map((f) => {
    const where = (f.seen_on || []).slice(0, 6).map((x) => `${esc(x.host)}:${x.port == null ? "" : esc(x.port)} ${esc(x.product)} ${esc(x.shown_version || "(no version)")} [${esc(x.confidence)}${x.distro ? ", " + esc(x.distro) : ""}]`).join("<br>");
    const link = https(f.fix && f.fix.details);
    const cve = link ? `<a href="${esc(link)}">${esc(f.cve)}</a>` : esc(f.cve);
    return row([esc(f.rank), cve, esc(f.title), where, esc(f.rating && f.rating.text || f.rating && f.rating.band || ""), esc(f.confidence) + (f.confidence === "low" ? " (not in the headline counts)" : "")]);
  }).join("\n");
  const obs = hosts.flatMap((h) => (h.observations || []).slice(0, 40).map((o) => `${esc(h.address)}:${esc(o.port)} ${esc(o.text)}`)).slice(0, 40);
  const notes = (r.notes || []).map((n) => `<li>${esc(n)}</li>`).join("");
  const cov = r.coverage;
  const covLine = cov && cov.complete === false ? `<p class="banner"><strong>Coverage is incomplete.</strong> A clean result does not cover hosts or ports the scan could not see. Read the coverage section of summary.txt.</p>` : "";
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberView Scanner report</title>
<style>${CSS}</style>
</head>
<body>
<header>
<h1>CyberView Scanner</h1>
<p class="muted">Detection only. Versions were read from what each service stated. Nothing was exploited, and nothing in this file was uploaded.</p>
</header>
<main>
<p>${esc(counts)}</p>
<section class="banner" id="backports">
<strong>Distribution packages can backport a fix.</strong>
${distroSeen ? "This report includes at least one distribution package build. " : ""}
A version inside an affected range on Ubuntu, Debian, Red Hat and the other named builds is medium confidence, not proof the package is vulnerable. The distribution may have patched it under the old version number. Check that package's own changelog before you treat it as unfixed.
</section>
${covLine}
<h2>Findings</h2>
<table>
<thead>${row(["#", "CVE", "Title", "Seen on", "Rating", "Confidence"], "th")}</thead>
<tbody>
${findingRows || row(["", "", "No findings.", "", "", ""])}
</tbody>
</table>
${obs.length ? `<h2>Observations</h2><ul>${obs.map((o) => `<li>${o}</li>`).join("")}</ul>` : ""}
${notes ? `<h2>Notes</h2><ul>${notes}</ul>` : ""}
</main>
</body>
</html>
`;
}

/** A diff object from diff.mjs -> one HTML document. */
export function diffHtml(diff) {
  const d = diff || {}, c = d.counts || {};
  const list = (title, rows) => {
    const body = (rows || []).slice(0, 200).map((x) => row([esc(x.cve), esc(x.host), esc(x.port), esc(x.product), esc(x.version), esc(x.state)])).join("");
    return `<h2>${esc(title)}</h2><table><thead>${row(["CVE", "Host", "Port", "Product", "Version", "State"], "th")}</thead><tbody>${body || row(["", "", "", "None.", "", ""])}</tbody></table>`;
  };
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>CyberView Scanner diff</title><style>${CSS}</style></head>
<body>
<header><h1>Scan diff</h1><p class="muted">New ${c.new ?? 0}, resolved ${c.resolved ?? 0}, still open ${c.still ?? 0}, changed ${c.changed ?? 0}. Watch ${c.watch ?? 0}.</p></header>
<main>
<section class="banner"><strong>Resolved is not proof of a patch.</strong> ${esc(d.note || "")}</section>
${list("New", d.new)}
${list("Resolved (no longer reported)", d.resolved)}
${list("Changed", (d.changed || []).map((x) => x.after || x))}
${list("Still open", d.still)}
<h2>Worth a look</h2>
<ul>${(d.watch || []).slice(0, 50).map((x) => `<li>${esc(x.cve)} on ${esc(x.host)}:${esc(x.port)} ${esc(x.product)} ${esc(x.version)}</li>`).join("") || "<li>None.</li>"}</ul>
</main>
</body>
</html>
`;
}
