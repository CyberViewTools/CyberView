// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Relationship / dependency map (scan-dep-map Stage A, plus the Stage B/C imports from imports.mjs). PURE: computed from
// report.json (what the scan already read: services, the one TLS certificate per port, the one recorded redirect per web
// port, the names the scope resolved) and from files the operator supplied. No packet, DNS query or request is made here:
// names mentioned outside the attested scope are LISTED as "mentioned, not scanned" and never contacted; in-scope names that
// were not in the starting inventory (shadow IT) are listed for the operator to add to the scope, never scanned by this.
// A remote scan can only INFER: co-location is low confidence, certificate SAN and in-scope redirect links medium; only an
// imported file can declare (manifest, SBOM, cloud inventory) or show observed traffic (Zeek, a connections file).
import { isIP } from "node:net";
import { parseTarget, hostInScope, inScope as ipInScope, classify, isPrivateKind } from "./scope.mjs";
import { esc } from "./html-report.mjs";

export const DEPMAP_LIMITS = Object.freeze({ servicesPerHost: 24, groupHosts: 50, radius: 200, mentions: 2000, mermaidEdges: 300, sanNames: 100 });
// the per-host risk score: a published formula over this report's findings and observations only (not a prediction)
export const RISK = Object.freeze({
  kev: 25, critical: 15, high: 8, other: 4,   // per finding confirmed on the host (version inside the range; high or medium confidence)
  ransomware: 5, overdue: 5,                  // added to a confirmed finding that CISA marks as used by ransomware / past CISA's due date
  check: 2,                                   // per finding where the product was seen but the version is to check (low confidence)
  public: 10,                                 // the host has a public address and at least one finding
  obs: { high: 4, medium: 2, low: 1 }, obsCap: 15,   // observations (configuration findings), capped in total
  cap: 100,
});
export const RISK_FORMULA = `score = min(${RISK.cap}, sum of points): each confirmed finding +${RISK.kev} if known exploited (CISA KEV), else +${RISK.critical} Critical / +${RISK.high} High / +${RISK.other} other rating; +${RISK.ransomware} if used by ransomware; +${RISK.overdue} if past CISA's due date; each version-to-check finding +${RISK.check}; +${RISK.public} for a public address with any finding; observations +${RISK.obs.high} high / +${RISK.obs.medium} medium / +${RISK.obs.low} low, at most +${RISK.obsCap}. From this report only; not a prediction.`;

const clip = (s, n = 200) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n);
const arr = (x) => (Array.isArray(x) ? x : []);
const low = (s) => clip(s, 253).toLowerCase().replace(/\.$/, "");

/** An in-scope test for names and addresses from report.scope (offline use, when the scope file is not given). */
export function scopeFromReport(report) {
  const sc = (report && report.scope) || {}, parse = (list) => arr(list).slice(0, 10000).map((t) => parseTarget(clip(t, 260))).filter((t) => !t.error);
  const targets = parse(sc.targets), exclude = parse(sc.exclude);
  const scope = { targets, exclude, hosts: targets.filter((t) => t.kind === "host").map((t) => t.text), discover: null };
  return { scope, inScope: (h) => (isIP(h) ? ipInScope(scope, h) : hostInScope(scope, h)) };
}

function sanOf(c) {
  const dns = Array.isArray(c.san_dns) ? c.san_dns : [...String(c.san || "").matchAll(/DNS:([^,\s]+)/g)].map((m) => m[1]);
  const ip = Array.isArray(c.san_ip) ? c.san_ip : [...String(c.san || "").matchAll(/IP Address:([^,\s]+)/g)].map((m) => m[1]);
  return { dns: dns.slice(0, DEPMAP_LIMITS.sanNames).map(low).filter(Boolean), ip: ip.slice(0, 50).map((x) => clip(x, 45)).filter((x) => isIP(x)) };
}

/**
 * report (+ imports from imports.parseImports, + inScope(host) -> bool) -> the map:
 * { nodes, edges, mentions, shadow_it, name_mismatch, risk, blast_radius, imports, counts, notes }
 */
export function buildDepmap(report, { imports = null, inScope = null } = {}) {
  const isIn = inScope || scopeFromReport(report).inScope;
  const hosts = arr(report && report.hosts).filter((h) => h && typeof h === "object" && isIP(String(h.address || "")));
  const nodes = new Map(), edges = new Map(), notes = [];
  const node = (id, n) => { if (!nodes.has(id)) nodes.set(id, { id, ...n }); return id; };
  const edge = (from, to, kind, confidence, evidence, extra = {}) => {
    if (!from || !to || from === to) return; const k = `${from}\u0000${to}\u0000${kind}`;
    if (!edges.has(k)) edges.set(k, { from, to, kind, confidence, inferred: confidence === "low" || confidence === "medium", evidence: clip(evidence, 300), ...extra });
  };
  const byAddr = new Map(), byName = new Map();
  for (const h of hosts) {
    byAddr.set(h.address, h);
    for (const n of arr(h.names).map(low)) { if (!byName.has(n)) byName.set(n, []); byName.get(n).push(h); }
  }
  const startNames = new Set([...byName.keys(), ...arr(report && report.scope && report.scope.targets).map(low)]);
  const hostId = (h) => node(`host:${h.address}`, { kind: "host", address: h.address, names: arr(h.names).slice(0, 10).map(low), public: !!h.public });
  const svcId = (h, port) => {
    const svcs = arr(h.services).filter((s) => s && s.port === port);
    return node(`svc:${h.address}:${port}`, { kind: "service", address: h.address, port, product: clip(svcs.map((s) => [s.label || [s.vendor, s.product].filter(Boolean).join(" "), s.shown_version || s.version].filter(Boolean).join(" ")).filter(Boolean).join("; "), 200) });
  };

  // 1. hosts, their services, and co-location (low confidence: sharing a host is not proof of a dependency)
  let coDropped = 0;
  for (const h of hosts.filter((x) => x.up !== false)) {
    const hid = hostId(h), ports = [...new Set(arr(h.ports).filter((p) => p && p.state === "open").map((p) => Number(p.port)).filter((p) => p > 0 && p < 65536))];
    ports.forEach((p) => edge(svcId(h, p), hid, "runs on", "observed", "open port found by this scan"));
    const list = ports.slice(0, DEPMAP_LIMITS.servicesPerHost); coDropped += Math.max(0, ports.length - list.length);
    for (let i = 0; i < list.length; i++) for (let j = i + 1; j < list.length; j++) edge(svcId(h, list[i]), svcId(h, list[j]), "co-located", "low", `both on ${h.address}; co-location is not proof of a dependency`);
  }
  if (coDropped) notes.push(`${coDropped} service(s) over ${DEPMAP_LIMITS.servicesPerHost} per host were left out of the co-location edges.`);

  // mentions (out of scope, never scanned) and shadow IT (in scope, absent from the starting inventory, never scanned)
  const mentions = new Map(), shadow = new Map();
  const mention = (map, name, seen) => { if (!map.has(name)) { if (map.size >= DEPMAP_LIMITS.mentions) return; map.set(name, { name, seen_in: [] }); } const m = map.get(name); if (m.seen_in.length < 20) m.seen_in.push(seen); };
  const classifyName = (n, seen) => {
    if (!n || n.startsWith("*.")) return "wildcard";
    if (byAddr.has(n) || byName.has(n)) return "scanned";
    if (!isIn(n)) { mention(mentions, n, seen); return "out"; }
    if (!startNames.has(n)) { mention(shadow, n, seen); return "shadow"; }
    return "in";
  };

  // 2. certificate SAN relationships (medium): hosts whose certificates carry the same SAN list; SAN names of other hosts
  const sanGroups = new Map(), mismatch = [];
  for (const h of hosts) for (const t of arr(h.tls)) {
    const c = t && t.cert; if (!c || typeof c !== "object") continue;
    const san = sanOf(c), key = [...san.dns, ...san.ip].sort().join(" ");
    if (key) { if (!sanGroups.has(key)) sanGroups.set(key, []); sanGroups.get(key).push({ h, port: t.port }); }
    const mine = new Set(arr(h.names).map(low));
    for (const n of [...san.dns, ...san.ip]) {
      const seen = { host: h.address, port: t.port, field: "certificate SAN" }, where = classifyName(n, seen);
      if (where !== "scanned") continue;
      const others = [...(byName.get(n) || []), ...(byAddr.has(n) ? [byAddr.get(n)] : [])].filter((o) => o.address !== h.address);
      for (const o of others) if (!mine.has(n)) {
        edge(svcId(h, t.port), hostId(o), "certificate names", "medium", `the certificate on ${h.address}:${t.port} names ${n}, which this scan reached at ${o.address}`);
        if (byName.has(n)) mismatch.push({ kind: "certificate-names-other-address", host: h.address, port: t.port, name: n, other_addresses: [...new Set(others.map((x) => x.address))].slice(0, 10),
          text: `The certificate served at ${h.address}:${t.port} names ${n}, which resolved to ${others.map((x) => x.address).slice(0, 3).join(", ")}: NAT, split-horizon DNS or a shared certificate; review` });
      }
    }
    if (san.ip.length && !san.ip.includes(h.address)) mismatch.push({ kind: "certificate-address-mismatch", host: h.address, port: t.port, san_ip: san.ip.slice(0, 10),
      text: `The certificate served at ${h.address}:${t.port} lists address(es) ${san.ip.slice(0, 3).join(", ")} but not ${h.address}: NAT or split-horizon; review` });
  }
  for (const [key, list] of sanGroups) {
    const distinct = [...new Map(list.map((x) => [x.h.address, x])).values()].slice(0, DEPMAP_LIMITS.groupHosts);
    for (let i = 0; i < distinct.length; i++) for (let j = i + 1; j < distinct.length; j++) edge(hostId(distinct[i].h), hostId(distinct[j].h), "share a certificate SAN list", "medium", `same SAN list: ${clip(key, 200)}`);
  }
  // names the scope resolved to both private and public addresses (collected DNS answers; no new query)
  for (const [n, hs] of byName) {
    const kinds = new Set(hs.map((h) => (isPrivateKind(classify(h.address)) ? "private" : "public")));
    if (kinds.size > 1) mismatch.push({ kind: "name-private-and-public", name: n, addresses: hs.map((h) => h.address).slice(0, 10), text: `${n} resolved to both private and public addresses (${hs.map((h) => h.address).slice(0, 4).join(", ")}): split-horizon DNS or NAT; review` });
  }
  for (const h of hosts) for (const o of arr(h.observations)) if (o && o.kind === "tls-name-mismatch") mismatch.push({ kind: "tls-name-mismatch", host: h.address, port: o.port, text: clip(o.text, 300) });

  // 3. redirects already recorded (never followed): in-scope ones are edges, out-of-scope ones are mentions
  for (const h of hosts) for (const w of arr(h.http)) {
    const loc = clip(w && w.redirect, 300); if (!loc) continue;
    let u; try { u = new URL(loc, `http://${h.address.includes(":") ? `[${h.address}]` : h.address}:${w.port}/`); } catch { continue; }   // parsed, never fetched
    if (u.protocol !== "http:" && u.protocol !== "https:") continue;
    const target = low(u.hostname.replace(/^\[|\]$/g, "")), tport = Number(u.port) || (u.protocol === "https:" ? 443 : 80);
    const seen = { host: h.address, port: w.port, field: "Location" };
    const same = target === h.address || arr(h.names).map(low).includes(target);
    if (same) { if (tport !== w.port) edge(svcId(h, w.port), svcId(h, tport), "redirects to", "medium", `Location ${clip(u.origin, 120)} (recorded, not followed)`); continue; }
    const where = classifyName(target, seen);
    if (where === "scanned") { const o = byAddr.get(target) || (byName.get(target) || [])[0]; edge(svcId(h, w.port), arr(o.ports).some((p) => p.port === tport) ? svcId(o, tport) : hostId(o), "redirects to", "medium", `Location ${clip(u.origin, 120)} (recorded, not followed)`); }
    else if (where === "in" || where === "shadow") edge(svcId(h, w.port), node(`name:${target}`, { kind: "name", name: target, scanned: false }), "redirects to", "medium", `Location ${clip(u.origin, 120)} (recorded, not followed; this name was not scanned)`);
  }

  // 4. imported graphs (declared by the operator's files, or observed traffic): attached to scanned hosts by address
  const importGraphs = [];
  for (const g of arr(imports && imports.graphs)) {
    for (const n of arr(g.nodes)) { const addr = n.kind === "address" ? n.address : ""; if (addr && byAddr.has(addr)) continue; node(n.id, { ...n, imported: g.source }); }
    const map = (id) => { const a = id.startsWith("ip:") ? id.slice(3) : ""; return a && byAddr.has(a) ? hostId(byAddr.get(a)) : id; };
    for (const e of arr(g.edges)) edge(map(e.from), map(e.to), e.kind, e.observed ? "observed" : "declared", `from the operator's ${g.source} file (${clip(g.kind, 60)})`, { imported: g.source, ...(e.port != null ? { port: e.port } : {}), ...(e.proto ? { proto: e.proto } : {}), ...(e.count > 1 ? { count: e.count } : {}) });
    importGraphs.push({ source: g.source, kind: g.kind, nodes: arr(g.nodes).length, edges: arr(g.edges).length, dropped: g.dropped || 0 });
  }

  // 5. per-host risk score (every point listed) and the findings' blast radius
  const risk = [];
  const findings = arr(report && report.findings);
  for (const h of hosts) {
    const pts = [], add = (n, why) => { if (n > 0) pts.push({ points: n, why }); };
    let any = false;
    for (const f of findings) {
      const seen = arr(f && f.seen_on).filter((s) => s && s.host === h.address); if (!seen.length) continue;
      any = true;
      const confirmed = f.state === "affected" && seen.some((s) => s.state === "affected" && s.confidence !== "low");
      if (!confirmed) { add(RISK.check, `${f.cve}: product seen, version to check`); continue; }
      const band = f.rating && f.rating.band;
      if (f.kev) add(RISK.kev, `${f.cve}: known exploited (CISA KEV), version in the affected range`);
      else add(band === "Critical" ? RISK.critical : band === "High" ? RISK.high : RISK.other, `${f.cve}: ${band || "unrated"} rating, version in the affected range`);
      if (f.ransomware) add(RISK.ransomware, `${f.cve}: used by ransomware (CISA)`);
      if (f.overdue) add(RISK.overdue, `${f.cve}: past CISA's due date ${clip(f.cisa_due, 10)}`);
    }
    if (any && h.public) add(RISK.public, "public address");
    let o = 0; for (const ob of arr(h.observations)) o += RISK.obs[ob && ob.severity] || 0;
    if (o) add(Math.min(RISK.obsCap, o), `${arr(h.observations).length} observation(s) (high +${RISK.obs.high}, medium +${RISK.obs.medium}, low +${RISK.obs.low}; at most +${RISK.obsCap})`);
    const total = Math.min(RISK.cap, pts.reduce((s, p) => s + p.points, 0));
    if (pts.length) risk.push({ host: h.address, names: arr(h.names).slice(0, 5), score: total, points: pts });
  }
  risk.sort((a, b) => b.score - a.score || (a.host < b.host ? -1 : 1));

  const E = [...edges.values()];
  const blast = [];
  for (const f of findings) {
    const where = [...new Set(arr(f && f.seen_on).map((s) => s && s.host).filter((a) => byAddr.has(a)))];
    if (!where.length) continue;
    const radius = new Map(), add = (id, via) => { if (radius.size < DEPMAP_LIMITS.radius && !radius.has(id)) radius.set(id, via); };
    for (const a of where) {
      const hid = `host:${a}`, mine = new Set([hid, ...E.filter((e) => e.kind === "runs on" && e.to === hid).map((e) => e.from)]);
      for (const id of mine) if (id !== hid) add(id, "same host (co-located)");
      for (const e of E) {
        if (e.kind === "runs on" || e.kind === "co-located") continue;
        const a1 = mine.has(e.from), a2 = mine.has(e.to); if (a1 === a2) continue;
        const other = a1 ? e.to : e.from;
        if (mine.has(other)) continue;
        add(other, e.imported ? `imported (${e.imported}): ${e.kind}` : e.kind === "share a certificate SAN list" || e.kind === "certificate names" ? `same certificate: ${e.kind}` : e.kind);
      }
    }
    blast.push({ cve: f.cve, confidence: f.confidence, kev: !!f.kev, hosts: where, radius: [...radius].map(([id, via]) => ({ node: id, via })) });
  }

  const count = (p) => E.filter(p).length;
  const kinds = {}; for (const e of E) kinds[e.kind] = (kinds[e.kind] || 0) + 1;
  return {
    generated_from: { report_started_at: clip(report && report.run && report.run.started_at, 40), hosts: hosts.length, imports: importGraphs },
    counts: { nodes: nodes.size, edges: E.length, inferred: count((e) => e.inferred), declared: count((e) => e.confidence === "declared"), observed_imported: count((e) => e.imported && e.confidence === "observed"),
      by_kind: kinds, mentions_not_scanned: mentions.size, shadow_it: shadow.size, name_mismatch: mismatch.length, hosts_scored: risk.length },
    nodes: [...nodes.values()], edges: E,
    mentions: [...mentions.values()].map((m) => ({ ...m, scanned: false, note: "outside the attested scope: mentioned in collected data, NOT scanned or contacted" })),
    shadow_it: [...shadow.values()].map((m) => ({ ...m, scanned: false, note: "inside the attested scope but not in this scan's starting inventory: add it to the scope file to check it; not scanned by this map" })),
    name_mismatch: mismatch.slice(0, 2000),
    risk: { formula: RISK_FORMULA, hosts: risk },
    blast_radius: blast,
    notes: [
      "Computed from report.json and the operator's own files only; no packet, DNS query or request was sent to build it.",
      "Confidence: co-location is low (sharing a host is not proof of a dependency); certificate SAN and in-scope redirect links are medium (inferred); declared edges come from the operator's manifest, SBOM or cloud inventory; observed edges from their Zeek or connections file.",
      "Out-of-scope names are listed as mentioned and never contacted. Shadow-IT names are in scope but were not in the starting inventory: they are listed, not scanned.",
      ...notes,
    ],
  };
}

/* ---- outputs ---- */
const mm = (s) => clip(s, 80).replace(/["[\]{}()<>|#&;`]/g, " ");
/** Mermaid flowchart text (graph LR); capped, labels stripped of Mermaid syntax characters. */
export function toMermaid(map) {
  const ids = new Map(), id = (k) => { if (!ids.has(k)) ids.set(k, `n${ids.size + 1}`); return ids.get(k); };
  const label = (n) => (n ? mm(n.kind === "host" ? `${n.address}${n.names && n.names.length ? " " + n.names[0] : ""}` : n.kind === "service" ? `${n.address}:${n.port} ${n.product || ""}` : n.name || n.address || n.id) : "");
  const byId = new Map(map.nodes.map((n) => [n.id, n]));
  const E = map.edges.filter((e) => e.kind !== "co-located").slice(0, DEPMAP_LIMITS.mermaidEdges);
  const L = ["graph LR"];
  for (const e of E) L.push(`  ${id(e.from)}["${label(byId.get(e.from)) || "?"}"] ${e.inferred ? "-.->" : "-->"}|${mm(e.kind)} ${e.confidence}| ${id(e.to)}["${label(byId.get(e.to)) || "?"}"]`);
  if (map.edges.length > E.length) L.push(`  %% ${map.edges.length - E.length} more edge(s) (co-location and over the cap) are in depmap.json`);
  return L.join("\n") + "\n";
}

export function depmapText(map) {
  const c = map.counts, L = [`Dependency map: ${c.nodes} node(s), ${c.edges} edge(s) (${c.inferred} inferred, ${c.declared} declared by imported files); ${c.mentions_not_scanned} out-of-scope name(s) mentioned, not scanned; ${c.shadow_it} shadow-IT name(s); ${c.name_mismatch} name/address mismatch(es) for review.`];
  for (const r of map.risk.hosts.slice(0, 10)) L.push(`   risk ${r.score}/100 ${r.host}${r.names.length ? ` (${r.names.join(", ")})` : ""}: ${r.points.map((p) => `${p.why} +${p.points}`).join("; ")}`);
  if (map.risk.hosts.length) L.push(`   formula: ${map.risk.formula}`);
  return L.join("\n");
}

/** A section for report.html (inserted before </main>): text only, escaped, no script. */
export function depmapHtml(map) {
  const c = map.counts, li = (x) => `<li>${x}</li>`;
  const list = (title, items, f, n = 50) => (items.length ? `<h3>${esc(title)} (${esc(items.length)})</h3><ul>${items.slice(0, n).map((x) => li(f(x))).join("")}</ul>${items.length > n ? `<p class="muted">${esc(items.length - n)} more in depmap.json</p>` : ""}` : "");
  return `<h2 id="depmap">Relationship map</h2>
<p class="muted">From this report and the files you supplied only; nothing was sent to build it. ${esc(c.nodes)} node(s), ${esc(c.edges)} edge(s): ${esc(c.inferred)} inferred (co-location low confidence; certificate SAN and in-scope redirects medium), ${esc(c.declared)} declared by imported files. Full map in depmap.json and depmap.mmd.</p>
${list("Per-host risk score (0-100)", map.risk.hosts, (r) => `<code>${esc(r.host)}</code> <b>${esc(r.score)}</b>: ${esc(r.points.map((p) => `${p.why} +${p.points}`).join("; "), 1200)}`)}
${map.risk.hosts.length ? `<p class="muted">${esc(map.risk.formula, 1000)}</p>` : ""}
${list("Finding blast radius", map.blast_radius, (b) => `${esc(b.cve)} on <code>${esc(b.hosts.join(", "))}</code> [${esc(b.confidence)}]: ${esc(b.radius.length)} related node(s)${b.radius.length ? ": " + esc(b.radius.slice(0, 8).map((r) => `${r.node} (${r.via})`).join("; "), 800) : ""}`)}
${list("Mentioned outside the scope, not scanned", map.mentions, (m) => `<code>${esc(m.name)}</code> <span class="muted">${esc(m.seen_in.slice(0, 3).map((s) => `${s.field} at ${s.host}:${s.port}`).join("; "))}</span>`)}
${list("Shadow IT: in scope, not in the starting inventory (not scanned)", map.shadow_it, (m) => `<code>${esc(m.name)}</code> <span class="muted">${esc(m.seen_in.slice(0, 3).map((s) => `${s.field} at ${s.host}:${s.port}`).join("; "))}</span>`)}
${list("Name or address mismatch (NAT or split-horizon; review)", map.name_mismatch, (m) => esc(m.text, 400))}
`;
}
