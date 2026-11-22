// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// [scan-cert-inventory] certificate inventory from handshakes already made. No extra connection.
// A name is called internal when it is a single label or ends in a private suffix the operator
// would not publish (.local, .lan, .internal, .home, .corp). That is a label, not a proof of ownership.

const INTERNAL = /\.(?:local|lan|internal|home|corp|localdomain)$/i;
const cell = (v) => { let s = v == null ? "" : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };

export function nameTokens(san, subject) {
  const out = [];
  for (const m of String(san || "").matchAll(/DNS:([^,]+)/gi)) out.push(m[1].trim());
  const cn = /CN=([^,/]+)/.exec(String(subject || ""));
  if (cn) out.push(cn[1].trim());
  return [...new Set(out.map((n) => n.replace(/^\*\./, "").slice(0, 200)))].slice(0, 32);
}
export function isInternalName(name) {
  const n = String(name || "").trim();
  if (!n || n.length > 200) return false;
  if (!n.includes(".")) return true;
  return INTERNAL.test(n);
}

/** hosts with tls[].cert.fingerprint256 -> rows, including reuse and internal names. */
export function certRows(hosts) {
  const rows = [];
  for (const h of hosts || []) for (const t of h.tls || []) {
    const c = t.cert; if (!c) continue;
    const names = nameTokens(c.san, c.subject);
    rows.push({
      host: h.address, port: t.port, fingerprint: c.fingerprint256 || "",
      subject: c.subject || "", issuer: c.issuer || "", not_after: c.valid_to || "",
      san: c.san || "", internal: names.filter(isInternalName),
    });
  }
  const byFp = new Map();
  for (const r of rows) if (r.fingerprint) { if (!byFp.has(r.fingerprint)) byFp.set(r.fingerprint, []); byFp.get(r.fingerprint).push(`${r.host}:${r.port}`); }
  for (const r of rows) {
    const peers = (byFp.get(r.fingerprint) || []).filter((p) => p !== `${r.host}:${r.port}`);
    r.reused_on = peers.slice(0, 20);
  }
  return rows;
}

export function toCertsCsv(hosts) {
  const head = ["host", "port", "fingerprint_sha256", "subject", "issuer", "not_after", "internal_names", "reused_on"];
  const lines = [head.join(",")];
  for (const r of certRows(hosts)) lines.push([r.host, r.port, r.fingerprint, r.subject, r.issuer, r.not_after, r.internal.join(" "), r.reused_on.join(" ")].map(cell).join(","));
  return lines.join("\r\n") + "\r\n";
}
