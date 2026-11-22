// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// [scan-dep-map] a map of links inside one report, plus an optional connections file the operator
// captured. Nothing here opens a connection. Co-location is not proof a service depends on another.
// A name that is not in the report is "mentioned, not scanned" and is not contacted.

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").slice(0, n);
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function id(host, port, product) { return clip(`${host}|${port == null ? "" : port}|${product || ""}`, 180); }

/** Stage A: edges inferred from one report. */
export function inferGraph(report) {
  const nodes = [], edges = [], mentioned = [];
  const hosts = (report && report.hosts) || [];
  const inScope = new Set();
  for (const h of hosts) {
    inScope.add(String(h.address).toLowerCase());
    for (const n of h.names || []) inScope.add(String(n).toLowerCase());
  }
  for (const h of hosts) {
    const services = (h.services || []).filter((s) => s.product);
    for (const s of services) nodes.push({ id: id(h.address, s.port, s.product), host: h.address, port: s.port, product: s.product, version: s.version || "" });
    // co-location is low confidence and is not a dependency
    for (let i = 0; i < services.length; i++) for (let j = i + 1; j < services.length && j < i + 6; j++) {
      edges.push({ from: id(h.address, services[i].port, services[i].product), to: id(h.address, services[j].port, services[j].product), kind: "co-location", confidence: "low", label: "same host" });
    }
    for (const page of h.http || []) {
      const loc = String(page.redirect || "");
      const host = (/^https?:\/\/([^/:\s]+)/i.exec(loc) || [])[1];
      if (!host) continue;
      const key = host.toLowerCase();
      if (inScope.has(key)) edges.push({ from: id(h.address, page.port, "http"), to: key, kind: "redirect", confidence: "medium", label: "redirect to an in-scope name" });
      else mentioned.push({ host: h.address, name: clip(host, 200), why: "redirect target is not in this report" });
    }
    for (const t of h.tls || []) for (const m of String(t.cert && t.cert.san || "").matchAll(/DNS:([^,\s]+)/gi)) {
      const name = m[1].toLowerCase();
      if (!inScope.has(name)) mentioned.push({ host: h.address, name: clip(m[1], 200), why: "certificate name is not in this report" });
    }
  }
  return { nodes: nodes.slice(0, 400), edges: edges.slice(0, 800), mentioned: mentioned.slice(0, 200),
    note: "Co-location is not a dependency. A mentioned name was not scanned." };
}

/** Stage C: "local dest port" lines, or a JSON list of {local, dest, port}. The file is not a login. */
export function connectionsFrom(text) {
  const raw = String(text || "").slice(0, 1024 * 1024);
  const out = [];
  const t = raw.trim();
  if (t.startsWith("[") || t.startsWith("{")) {
    try {
      const j = JSON.parse(t);
      for (const row of (Array.isArray(j) ? j : j.connections || []).slice(0, 2000)) {
        if (row && row.local && row.dest) out.push({ local: clip(row.local, 80), dest: clip(row.dest, 80), port: Number(row.port) || 0, kind: "imported" });
      }
      return out;
    } catch { /* fall through to lines */ }
  }
  for (const line of raw.split(/\r?\n/).slice(0, 2000)) {
    const m = /^(\S+)\s+(\S+)\s+(\d{1,5})\s*$/.exec(line.trim());
    if (m) out.push({ local: clip(m[1], 80), dest: clip(m[2], 80), port: Number(m[3]), kind: "imported" });
  }
  return out;
}

export function toMermaid(graph) {
  const lines = ["flowchart LR"];
  const safe = (s) => "n" + Buffer.from(String(s)).toString("hex").slice(0, 24);
  // Buffer is available. Avoid huge ids.
  for (const n of graph.nodes || []) lines.push(`  ${safe(n.id)}["${clip(n.product, 40)} ${clip(n.host, 40)}"]`);
  for (const e of graph.edges || []) lines.push(`  ${safe(e.from)} -->|${clip(e.confidence, 12)}| ${safe(e.to)}`);
  return lines.join("\n") + "\n";
}

export function toDot(graph) {
  const q = (s) => `"${String(s).replace(/"/g, "")}"`;
  const lines = ["digraph g {"];
  for (const n of graph.nodes || []) lines.push(`  ${q(n.id)} [label=${q(n.product + " " + n.host)}];`);
  for (const e of graph.edges || []) lines.push(`  ${q(e.from)} -> ${q(e.to)} [label=${q(e.kind)}];`);
  lines.push("}");
  return lines.join("\n") + "\n";
}

export function graphHtml(graph) {
  const rows = (graph.edges || []).slice(0, 200).map((e) => `<tr><td>${esc(e.kind)}</td><td>${esc(e.confidence)}</td><td>${esc(e.from)}</td><td>${esc(e.to)}</td><td>${esc(e.label)}</td></tr>`).join("");
  const ment = (graph.mentioned || []).slice(0, 50).map((m) => `<li>${esc(m.name)} ${esc(m.why)}</li>`).join("");
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>CyberView dependency map</title></head><body>
<h1>Dependency map</h1>
<p>${esc(graph.note || "")}</p>
<table><thead><tr><th>Kind</th><th>Confidence</th><th>From</th><th>To</th><th>Label</th></tr></thead><tbody>${rows}</tbody></table>
<h2>Mentioned, not scanned</h2><ul>${ment || "<li>None.</li>"}</ul>
</body></html>`;
}
