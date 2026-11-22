// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Compare two scanner reports the operator already has. No network and no re-scan: a schedule, if any,
// is the operator's own. "Resolved" means the later report does not list that CVE on that host and port.
// It is not proof the software was patched. `watch` lists new known-exploited or Act findings for whatever
// alerting the operator already runs; this module sends nothing.

const clip = (s, n) => String(s == null ? "" : s).slice(0, n);
const keyOf = (cve, host, port) => `${cve}|${host}|${port == null ? "" : port}`;

function places(report) {
  const out = new Map();
  const findings = report && Array.isArray(report.findings) ? report.findings : [];
  for (const f of findings) {
    const cve = clip(f.cve, 32);
    if (!cve) continue;
    for (const s of (Array.isArray(f.seen_on) ? f.seen_on : []).slice(0, 200)) {
      const row = {
        cve, title: clip(f.title, 200), host: clip(s.host, 200), port: s.port == null ? null : s.port,
        product: clip(s.product, 120), version: clip(s.shown_version || s.version || "", 40),
        state: clip(s.state, 20), confidence: clip(s.confidence, 16),
        kev: !!f.kev, priority: f.priority && f.priority.decision ? clip(f.priority.decision, 16) : "",
      };
      out.set(keyOf(row.cve, row.host, row.port), row);
    }
  }
  return out;
}

/** Two report objects -> { counts, new, resolved, still, changed, watch, note, compared }. */
export function diffReports(before, after) {
  const A = places(before), B = places(after);
  const added = [], removed = [], still = [], changed = [];
  for (const [k, v] of B) {
    if (!A.has(k)) added.push(v);
    else {
      const p = A.get(k);
      if (p.version !== v.version || p.state !== v.state) changed.push({ before: p, after: v });
      else still.push(v);
    }
  }
  for (const [k, v] of A) if (!B.has(k)) removed.push(v);
  const byCve = (a, b) => (a.cve < b.cve ? -1 : a.cve > b.cve ? 1 : 0);
  added.sort(byCve); removed.sort(byCve); still.sort(byCve);
  const watch = added.filter((x) => x.kev || x.priority === "act");
  const started = (r) => (r && r.run && r.run.started_at) || "";
  return {
    compared: { before: clip(started(before), 40), after: clip(started(after), 40) },
    counts: { new: added.length, resolved: removed.length, still: still.length, changed: changed.length, watch: watch.length },
    new: added, resolved: removed, still, changed, watch,
    note: "Resolved means the later report does not list that CVE on that host and port. It is not proof the software was patched. A host that was down, or a service that hid its version, looks the same.",
  };
}

export function diffText(diff) {
  const d = diff || { counts: {}, new: [], resolved: [], still: [], changed: [], watch: [], note: "" };
  const c = d.counts || {};
  const L = [];
  L.push(`New ${c.new || 0}, resolved ${c.resolved || 0}, still open ${c.still || 0}, changed ${c.changed || 0}. Watch ${c.watch || 0}.`);
  L.push(d.note || "");
  const block = (title, rows, line) => {
    L.push(""); L.push(title);
    if (!rows || !rows.length) { L.push("  none"); return; }
    rows.slice(0, 40).forEach((x) => L.push("  " + line(x)));
    if (rows.length > 40) L.push(`  ... and ${rows.length - 40} more in diff.json`);
  };
  block("NEW", d.new, (x) => `${x.cve} ${x.host}:${x.port == null ? "" : x.port} ${x.product} ${x.version}`.trim());
  block("RESOLVED (no longer reported)", d.resolved, (x) => `${x.cve} ${x.host}:${x.port == null ? "" : x.port} ${x.product} ${x.version}`.trim());
  block("CHANGED", d.changed, (x) => `${x.after.cve} ${x.after.host}: ${x.before.version || "?"} -> ${x.after.version || "?"} (${x.before.state} -> ${x.after.state})`);
  block("STILL OPEN", d.still, (x) => `${x.cve} ${x.host}:${x.port == null ? "" : x.port}`);
  block("WATCH (new known-exploited or Act)", d.watch, (x) => `${x.cve} ${x.host}:${x.port == null ? "" : x.port} ${x.product}`);
  return L.join("\n");
}
