// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Thin incident citations and hunt links. No probe. Citations come from an opt-in incidents index
// (not the first-wins event_of map). Hunt entries are publisher URLs only: no rule body, no indicator list.

const isCve = (s) => /^CVE-\d{4}-\d{4,}$/.test(s || "");
const https = (u) => (/^https:\/\/[^\s"'<>]+$/.test(String(u || "")) ? String(u).slice(0, 600) : "");
const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").slice(0, n);
const KEEP_STATUS = new Set(["confirmed", "official"]);
const KEEP_REVIEW = new Set(["passed", "corrected"]);
const FORMATS = new Set(["stix", "sigma", "yara", "snort", "suricata", "kql", "spl", "csv", "json", "misp", "openioc", "text", "pdf"]);

/**
 * incidents index: { events: [{ id, cves, status, review, title, url, attribution }] }
 * A citation is kept only when status is confirmed or official and review is passed or corrected.
 * Claimed (and anything else) is counted, not listed. Every kept event for the CVE is returned.
 */
export function citationsFor(index, cve) {
  const events = index && Array.isArray(index.events) ? index.events : [];
  const kept = [], claimed = [];
  for (const e of events) {
    if (!e || typeof e !== "object") continue;
    const cves = Array.isArray(e.cves) ? e.cves : (e.cve ? [e.cve] : []);
    if (!cves.includes(cve)) continue;
    const status = String(e.status || "");
    const review = e.review && typeof e.review === "object" ? String(e.review.state || "") : String(e.review || "");
    const row = { id: clip(e.id, 80), title: clip(e.title, 180), url: https(e.url), status, review, attribution: clip(e.attribution, 120) };
    if (status === "claimed") { claimed.push(row); continue; }
    if (KEEP_STATUS.has(status) && KEEP_REVIEW.has(review) && row.url) kept.push(row);
  }
  return { kept: kept.slice(0, 12), claimed_omitted: claimed.length };
}

/** Publisher hunt URLs for the given CVEs. Drops any field that is not a link. */
export function huntLinks(wb, cves) {
  const want = new Set((cves || []).filter(isCve));
  const out = [], seen = new Set();
  const take = (h, cve) => {
    if (!h || typeof h !== "object" || !FORMATS.has(h.format)) return;
    const url = https(h.url);
    if (!url || seen.has(url)) return;
    if (/csaf|cvrf|\bvex\b/i.test(url + " " + (h.name || ""))) return;
    if (h.body || h.rule || h.content || h.indicators) return; // a record that carries a body is not links-only
    seen.add(url);
    out.push({ cve: isCve(cve) ? cve : (isCve(h.cve) ? h.cve : ""), name: clip(h.name, 100) || h.format, format: h.format, url, publisher: clip(h.publisher, 80) });
  };
  const guides = wb && wb.guides && typeof wb.guides === "object" ? wb.guides : {};
  for (const [cve, g] of Object.entries(guides)) {
    if (!want.has(cve) || !g) continue;
    for (const h of Array.isArray(g.hunt) ? g.hunt : []) take(h, cve);
  }
  for (const h of Array.isArray(wb && wb.hunt) ? wb.hunt : []) {
    const cve = isCve(h && h.cve) ? h.cve : "";
    if (cve && !want.has(cve)) continue;
    if (!cve && want.size) continue;
    take(h, cve);
  }
  return out.slice(0, 40);
}

export function huntText(links) {
  return (links || []).map((h) => `${h.cve ? h.cve + " " : ""}${h.publisher ? h.publisher + ": " : ""}${h.url}`).join("\n");
}
