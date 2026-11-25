// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Detected services -> findings: matched against CyberView's flaws with the site's own matchFlaw, rated with the site's own
// CyberView rating and SSVC priority, and ranked. No network here: rows are handed in by the caller.
import { W, D } from "./shared.mjs";
import { DEFAULT_SOURCE } from "./data.mjs";

const str = (v, n) => (typeof v === "string" ? v.slice(0, n) : "");
const strs = (a, k, n) => (Array.isArray(a) ? a : []).map((x) => str(x, n).trim()).filter(Boolean).slice(0, k);
const num = (v, lo, hi) => (typeof v === "number" && isFinite(v) && v >= lo && v <= hi ? v : null);
const isDay = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s || "");
const isCve = (s) => /^CVE-\d{4}-\d{4,}$/.test(s || "");
const https = (u) => (/^https:\/\/[^\s"'<>]+$/.test(u || "") ? u : "");
export const pageFor = (cve) => `${DEFAULT_SOURCE}vulnerabilities.html#${cve}`;

/* A fix guide (from the vendor's own advisory) as the scanner uses it: the advisory link, the fixed versions, the workarounds.
   Check steps, signs of compromise and detection resources are linked (CyberView's page for the CVE), never copied. */
function cleanGuide(g) {
  if (!g || typeof g !== "object") return null;
  const a = g.advisory && typeof g.advisory === "object" ? { name: str(g.advisory.name, 100), url: https(str(g.advisory.url, 600)) } : null;
  if (!a || !a.url) return null;
  return { advisory: a, fixed: strs(g.fixed, 8, 160), workaround: strs(g.workaround, 5, 320), exposure: ["internet", "internal", "local"].includes(g.exposure) ? g.exposure : "", exploit: g.exploit_public === true, has_signs: strs(g.compromise_signs, 6, 320).length > 0 };
}

/** workbench.json -> the flaws the page lists (KEV entries with ranges, then recent high-risk flaws named by products). */
export function cleanFlaws(wb) {
  const guides = {}, raw = wb && wb.guides && typeof wb.guides === "object" ? wb.guides : {};
  Object.keys(raw).slice(0, 2000).forEach((k) => { if (isCve(k)) { const g = cleanGuide(raw[k]); if (g) guides[k] = g; } });
  const analyses = new Set(Object.keys((wb && wb.analyses) || {}).filter(isCve));
  const repos = (r) => (r && typeof r === "object" ? num(r.repos, 0, 1e5) || 0 : 0);
  const kev = (Array.isArray(wb && wb.kev) ? wb.kev : []).slice(0, 3000).map((k) => {
    if (!k || typeof k !== "object" || !isCve(k.cve)) return null;
    const g = guides[k.cve] || null;
    return { cve: k.cve, kev: true, vendor: str(k.vendor, 80), product: str(k.product, 120), name: str(k.name, 200), added: isDay(k.added) ? k.added : "", due: isDay(k.due) ? k.due : "", ransomware: k.ransomware === true,
      desc: str(k.desc, 300), cvss: num(k.cvss, 0, 10), epss: num(k.epss, 0, 1), av: /^[NALP]$/.test(k.av || "") ? k.av : "", required: str(k.required, 700),
      refs: strs(k.refs, 4, 600).map(https).filter(Boolean), affected: (Array.isArray(k.affected) ? k.affected : []).slice(0, 60).map(W.cleanRange).filter(Boolean),
      guide: g, analysis: analyses.has(k.cve), exposure: g ? g.exposure : "", exploit_public: !!(g && g.exploit), severity: 3, repos: repos(k.repo) };
  }).filter(Boolean);
  const vulns = (Array.isArray(wb && wb.vulns) ? wb.vulns : []).slice(0, 80).map((v) => {
    if (!v || typeof v !== "object" || !isCve(v.cve)) return null;
    const g = guides[v.cve] || null, prods = strs(v.products, 6, 60);
    return { cve: v.cve, kev: false, vendor: str(v.vendor, 80), product: prods.join(", "), name: str(v.title, 160), added: isDay(v.date) ? v.date : "", due: "", ransomware: false, desc: str(v.desc, 300),
      cvss: num(v.cvss, 0, 10), epss: num(v.epss, 0, 1), av: "", required: str(v.action, 300), refs: [], affected: prods.map((p) => ({ vendor: str(v.vendor, 60), product: p, from: "", to: "", exact: "", nameOnly: true })),
      guide: g, analysis: analyses.has(v.cve), exposure: g ? g.exposure : "", exploit_public: !!(g && g.exploit), severity: v.severity === 3 ? 3 : 2, repos: repos(v.repo) };
  }).filter(Boolean);
  return kev.concat(vulns);
}

/** A detected service as an inventory line, the shape the page's "My software" list uses. */
/** The version to match with: the one the service stated in full when it is the bare number plus a patch suffix (OpenSSH 9.8p1,
 *  ProFTPD 1.3.5a, OpenSSL 1.0.2k), because the suffix decides whether a fix is in. Anything less tidy falls back to the number. */
export const matchVersion = (s) => { const v = s.version || "", full = String(s.shown_version || "").trim(); return v && full !== v && full.startsWith(v) && /^[a-z]{1,2}\d{0,2}$/i.test(full.slice(v.length)) ? full : v; };
export const toItem = (s) => ({ name: s.product, vendor: s.vendor, version: matchVersion(s), count: 1 });

/* ---- soundness rules on top of the site's matcher, applied to every finding ----
   The site's name test only asks for the vendor when the product name is short or generic, so "IBM HTTP Server" ranges would
   match an Apache HTTP Server. A scan knows the vendor of what it detected, so a range only counts when its vendor agrees. */
const NOISE = new Set(["project", "software", "foundation", "group", "inc", "corporation", "corp", "ltd", "llc", "the", "team", "technologies", "systems", "labs"]);
const wordsOf = (x) => W.norm(x).split(" ").filter((w) => w.length > 1 && !NOISE.has(w));
const squash = (x) => W.norm(x).replace(/ /g, "");
export function vendorAgrees(s, r) {
  const rv = wordsOf(r.vendor); if (!rv.length) return false;
  if (!String(s.vendor || "").trim()) return true;                    // an imported package list states no vendor: the site's name rule is all there is
  const mine = new Set([...wordsOf(s.vendor), ...wordsOf(s.product)]);
  if (rv.some((w) => mine.has(w)) || (squash(s.vendor).length > 3 && squash(r.vendor) === squash(s.vendor))) return true;                       // openbsd ~ OpenBSD, apache ~ Apache Software Foundation, f5 ~ F5
  return squash(rv.join(" ")) === squash(r.product) && squash(s.product) === squash(r.product);   // self-named projects: nginx/nginx, exim/exim
}
const bounded = (r) => !!(r.exact || r.from || r.to);
const nameOf = (s) => (s.vendor ? s.vendor + " " : "") + s.product;
/** For one service and one flaw: is there a range that names this product, from an agreeing vendor? With inRange: and holds the version. */
export function soundFor(s, f, { inRange = false } = {}) {
  const rs = Array.isArray(f.affected) ? f.affected : []; if (!rs.length) return !inRange;
  const v = matchVersion(s);
  return rs.some((r) => W.nameHit(nameOf(s), r.vendor, r.product) && vendorAgrees(s, r) && (!inRange || ((bounded(r) || f.kev) && !!v && W.inRange(v, r) === true)));   // a known-exploited entry listing every version (end-of-life devices) counts
}

/** Confidence for one place a flaw was seen, with the reason. */
export function confidenceOf(state, s) {
  if (state === "affected" && s.distro) return ["medium", `version ${s.shown_version} is inside the affected range, but it is a ${s.distro} package build: the distribution may have backported the fix; check the package's own changelog`];
  if (state === "affected" && !s.guessed) return ["high", `version ${s.shown_version} stated by the service (${s.source}) is inside the affected range`];
  if (state === "affected") return ["medium", "the version is inside the affected range, but the product was inferred"];
  return ["low", s.version ? "the product was seen, but CyberView has no version range to compare yet; check the version by hand" : "the product was seen but it did not state its version; check the version by hand"];
}
const CONF = { high: 3, medium: 2, low: 1 };

/** A lookup row (cvedb-lib cleanRow) for a CVE, or a stand-in built from the flaw when the lookup file is not available. */
export function rowFor(f, rows) {
  if (rows && rows.get(f.cve)) return { row: rows.get(f.cve), from: "CVE lookup file" };
  const row = { id: f.cve, rejected: false, pub: "", upd: "", cvss: f.cvss, sev: "", ver: "", cwe: "", vendor: f.vendor, product: f.product, title: f.name, desc: f.desc, cna: "",
    expl: "", kev: f.kev ? f.added || "yes" : "", epss: f.epss, pct: null, auto: "", ti: "", vec: "", due: f.due, ransom: f.ransomware, ncvss: null, nsev: "", nvec: "", n3: "", n3c: false };
  if (Object.prototype.hasOwnProperty.call(D.vendorIndex, f.cve)) row.adv = D.vendorIndex[f.cve];
  return { row, from: "KEV entry (the CVE lookup file was not available, so CISA's SSVC assessment is not used)" };
}

/**
 * hosts: [{ address, names[], kind, services: [service records from fingerprint.mjs] }]
 * flaws: cleanFlaws(...); rows: Map(cve -> cleanRow) for the CVEs that matched (see candidates()); today: YYYY-MM-DD
 * -> findings ranked, each listing every rating point
 */
export function findings(hosts, flaws, rows, { today = new Date().toISOString().slice(0, 10), affectedOnly = false, source = "" } = {}) {
  const byCve = new Map();
  for (const h of hosts) for (const s of h.services || []) {
    if (!s.product) continue;
    const inv = [toItem(s)];
    for (const f of flaws) {
      const m = W.matchFlaw(f, inv);
      if (!m || (m.state !== "affected" && m.state !== "check")) continue;
      if (affectedOnly && m.state !== "affected") continue;
      // A finding from the whole CVE index needs a bounded range, from a vendor that agrees with the detected one, that holds the
      // version. The known-exploited set keeps the site's own rule: its fingerprints were written against those entries, and
      // vendors there change names (Kemp/Progress, Pulse/Ivanti) in ways a word test would wrongly refuse.
      if (affectedOnly && !soundFor(s, f, { inRange: true })) continue;
      const [conf, why] = confidenceOf(m.state, s);
      if (!byCve.has(f.cve)) byCve.set(f.cve, { f, seen: [], fixed: new Set() });
      const g = byCve.get(f.cve);
      g.seen.push({ host: h.address, names: h.names || [], public: !!h.public, port: s.port, proto: s.proto, product: s.label || [s.vendor, s.product].filter(Boolean).join(" "), version: s.version, shown_version: s.shown_version, distro: s.distro, evidence: s.evidence, state: m.state, confidence: conf, confidence_why: why });
      m.fixed.forEach((v) => g.fixed.add(v));
    }
  }
  const out = [];
  for (const { f, seen, fixed } of byCve.values()) {
    const state = seen.some((x) => x.state === "affected") ? "affected" : "check";
    const exposed = seen.some((x) => x.public);
    const { row, from } = rowFor(f, rows);
    const sc = D.score(row), pr = D.rate(row, { today, exposed });
    const pts = W.score(f, { state }, today);
    const best = seen.slice().sort((a, b) => CONF[b.confidence] - CONF[a.confidence])[0];
    const g = f.guide;
    out.push({
      ...(source ? { source } : {}),
      cve: f.cve, title: f.name || f.desc.slice(0, 120), vendor: f.vendor, product: f.product, state,
      kev: f.kev, kev_added: f.added && f.kev ? f.added : "", cisa_due: f.due, overdue: !!(f.due && f.due < today), ransomware: f.ransomware, epss: f.epss,
      exploitation: D.exploitation(row),
      rating: sc ? { score: sc.score, band: sc.band, text: sc.text, base: sc.base, e: sc.e ? { label: sc.e.label, value: sc.e.value } : null, notes: sc.notes, confidence: sc.confidence, confidence_why: sc.confidenceWhy, from } : { score: null, band: "Not scored", text: "", from },
      priority: pr ? { decision: pr.decision, label: pr.label, rank: pr.rank || 0, does: pr.does, inputs: pr.inputs, signals: pr.signals.map((x) => x.text), fix_by: pr.fixFor ? pr.fixBy[pr.fixFor] : pr.fixBy.internal, exposure: exposed ? "public address" : "private address", deadline: pr.deadline, overdue: pr.overdue } : null,
      points: { total: pts.total, list: pts.points.map(([n, why]) => ({ points: n, why })) },
      confidence: best.confidence, confidence_why: best.confidence_why,
      seen_on: seen.slice(0, 200),
      fix: {
        fixed_in: [...fixed].sort(W.cmp).slice(-6), vendor_fixed: g ? g.fixed : [], workaround: g ? g.workaround : [], cisa_required_action: f.required,
        advisory: g ? g.advisory : null, references: f.refs, details: pageFor(f.cve),
        details_note: "Check steps, signs of compromise and detection resources are on CyberView's page for this CVE (linked, not copied).",
        analysis: f.analysis ? { url: pageFor(f.cve), by: "CyberView AI (a Claude model)" } : null,
      },
    });
  }
  return rank(out);
}

/** Ranked by the CyberView rating, with CISA's evidence first: known exploited (KEV), then exploited by other evidence, then past
 *  CISA's deadline; within those, version-confirmed before unconfirmed, then the rating, the SSVC priority, the nearest
 *  deadline and EPSS. */
export function rank(list) {
  const ex = (x) => (x.exploitation && x.exploitation.value === "active" ? 2 : x.exploitation && x.exploitation.value === "poc" ? 1 : 0);
  const due = (x) => x.cisa_due || "9999-12-31";
  list.sort((a, b) => (b.kev - a.kev) || ex(b) - ex(a) || (b.overdue - a.overdue) || (a.state === b.state ? 0 : a.state === "affected" ? -1 : 1)
    || ((b.rating.score ?? -1) - (a.rating.score ?? -1)) || ((b.priority && b.priority.rank) || 0) - ((a.priority && a.priority.rank) || 0)
    || (due(a) < due(b) ? -1 : due(a) > due(b) ? 1 : 0) || (b.epss ?? -1) - (a.epss ?? -1) || (a.cve < b.cve ? -1 : 1));
  list.forEach((x, i) => { x.rank = i + 1; });
  return list;
}

/* ---- the whole CVE index (full snapshot only): every CVE whose lookup row carries NVD's affected-version ranges ---- */
const words = (s) => W.norm(s).split(" ").filter(Boolean);
/** A lookup row with ranges -> the flaw shape matchFlaw and the rating code take. No fix guide: those exist for workbench flaws only. */
export function flawFromRow(r) {
  return { cve: r.id, kev: !!r.kev, vendor: r.vendor, product: r.product, name: r.title, added: isDay(r.kev) ? r.kev : "", due: r.due || "", ransomware: r.ransom === true,
    desc: str(r.desc, 300), cvss: r.cvss != null ? r.cvss : r.ncvss, epss: r.epss, av: "", required: "", refs: [], affected: r.affected,
    guide: null, analysis: false, exposure: "", exploit_public: r.expl === "poc" || r.expl === "active", severity: 2, repos: 0 };
}
/**
 * allRows: every cleaned lookup row of a full snapshot. Returns the flaws worth matching for these hosts, and their rows.
 * A row is a candidate when one of its ranges names a product some detected service names: the first word of the range's
 * product must be a word of the service's vendor+product name (a cheap pre-filter; matchFlaw then decides, with the same
 * name and range rules as the Vulnerabilities page). Rejected CVEs, rows without ranges and CVEs in `skip` are left out.
 * Only a version INSIDE a range becomes a finding (the caller passes affectedOnly): a name-only hit stays a lead in `named`.
 */
export function indexFlaws(hosts, allRows, { skip = new Set() } = {}) {
  const have = new Set();
  for (const h of hosts) for (const s of h.services || []) if (s.product && s.version) words(`${s.vendor || ""} ${s.product}`).forEach((w) => have.add(w));
  const flaws = [], rows = new Map(); let ranged = 0;
  if (!have.size) return { flaws, rows, ranged: allRows.filter((r) => !r.rejected && r.affected && r.affected.length).length };
  for (const r of allRows) {
    if (r.rejected || !r.affected || !r.affected.length) continue;
    ranged++;
    if (skip.has(r.id)) continue;
    if (!r.affected.some((a) => { const w = words(a.product)[0]; return w && have.has(w); })) continue;
    flaws.push(flawFromRow(r)); rows.set(r.id, r);
  }
  return { flaws, rows, ranged };
}

/**
 * A cheap test used while reading a full snapshot bucket by bucket, so the whole CVE List is never held in memory: can this
 * row matter to these hosts at all, as a range candidate (indexFlaws) or as a name-only lead (named)? Deliberately loose.
 */
export function relevance(hosts) {
  const have = new Set(), squashed = [];
  for (const h of hosts) for (const s of h.services || []) if (s.product) { const n = `${s.vendor || ""} ${s.product}`; words(n).forEach((w) => have.add(w)); squashed.push(W.norm(n).replace(/ /g, "")); }
  return (r) => {
    if (r.rejected || !have.size) return false;
    const pw = words(r.product);
    if (pw[0] && have.has(pw[0])) return true;
    const sq = pw.join(""); if (sq.length >= 5 && squashed.some((n) => n.includes(sq))) return true;
    return !!(r.affected && r.affected.some((a) => { const w = words(a.product)[0]; return w && have.has(w); }));
  };
}

/** The CVEs worth loading lookup rows for: every flaw some service matches. */
export function candidates(hosts, flaws) {
  const set = new Set();
  for (const h of hosts) for (const s of h.services || []) if (s.product) for (const f of flaws) { const m = W.matchFlaw(f, [toItem(s)]); if (m && (m.state === "affected" || m.state === "check")) set.add(f.cve); }
  return [...set];
}

/**
 * Other CVEs in the CVE List that name a detected product (full snapshot only). The CVE List's rows carry no version ranges,
 * so these are leads to check by hand, never findings: counted per product with the highest-rated few listed.
 */
export function named(hosts, allRows, { per = 10, skip = new Set(), ranged = false } = {}) {
  const prods = new Map();
  for (const h of hosts) for (const s of h.services || []) if (s.product && !s.guessed) { const k = `${s.vendor} ${s.product}`.trim(); if (!prods.has(k)) prods.set(k, { product: k, version: s.shown_version, checked: false, services: [], hosts: new Set() }); const p = prods.get(k); p.hosts.add(h.address); if (s.version) { p.checked = true; if (p.services.length < 4) p.services.push(s); } }
  const out = [];
  for (const p of prods.values()) {
    // ranged: the caller matched every row that has ranges against the version seen, so for a product with a version those
    // rows are settled (a finding, or the version is outside the range) and only rows with no range are still leads
    const hits = allRows.filter((r) => !r.rejected && r.product && !skip.has(r.id) && !(ranged && p.checked && r.affected && r.affected.some((a) => bounded(a) && p.services.some((s) => W.nameHit(nameOf(s), a.vendor, a.product) && vendorAgrees(s, a)))) && (W.nameHit(p.product, r.vendor, r.product) || (ranged && r.affected && r.affected.length >= 16 && p.services.some((s) => squash(s.product).length > 4 && (r.hay || "").replace(/[^a-z0-9]/g, "").includes(squash(s.product))))));   // a row whose range list was cut off at the cap and whose text names the product: a lead, since its own range may be missing
    if (!hits.length) continue;
    const top = hits.map((r) => ({ r, s: D.score(r) })).sort((a, b) => ((b.s && b.s.score) ?? -1) - ((a.s && a.s.score) ?? -1)).slice(0, per)
      .map(({ r, s }) => ({ cve: r.id, title: r.title || r.desc.slice(0, 120), rating: s && s.score != null ? `${s.score.toFixed(1)} ${s.band}` : "Not scored", exploited: D.exploitation(r).value === "active" }));
    out.push({ product: p.product, version_seen: p.version, hosts: [...p.hosts].slice(0, 50), cves_naming_it: hits.length, exploited: hits.filter((r) => D.exploitation(r).value === "active").length, top,
      note: ranged ? "Named in the CVE List, versions not checked: no affected-version range is published for these (or no version was read from the service). Compare each with the vendor's advisory."
        : "Named in the CVE List, versions not checked: CyberView's lookup files hold no version ranges for these. Compare each with the vendor's advisory." });
  }
  return out;
}
