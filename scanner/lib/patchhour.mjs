// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// [scan-patch-hour] a link sheet from a report the operator already has. No network, no new facts.
// It is not a calendar and it does not change a host.

const https = (u) => (/^https:\/\/[^\s"'<>]+$/.test(String(u || "")) ? String(u) : "");

export function patchHour(report) {
  const lines = ["Patch-hour sheet. Links only. This file does not scan and does not assert that a host was patched."];
  for (const f of (report && report.findings) || []) {
    const links = [https(f.fix && f.fix.details), https(f.fix && f.fix.advisory && f.fix.advisory.url)].filter(Boolean);
    lines.push([f.cve, f.cisa_due ? `due ${f.cisa_due}` : "no CISA date", ...links].join(" "));
  }
  if (((report && report.findings) || []).length === 0) lines.push("No findings in this report.");
  return lines.join("\n") + "\n";
}
