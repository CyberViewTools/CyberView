// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
//
// `lookup <CVE>`: what CyberView knows about one flaw, read from a local snapshot. A reader, not a matcher — it
// contacts nothing and adds no data path: the same `data/workbench.json`, `data/psirt.json` and CVE lookup file the
// scan and `match` already read, through the same `dirSource`. For an analyst in a change freeze or an air-gapped SOC
// who has a CVE number from a bulletin and wants the rating, the deadline, the affected ranges and the fix in one
// place, with a version they hold checked against the ranges.
//
// It PRINTS nothing it has not read. Exploitation analyses, hunt guidance and indicators of compromise stay on
// CyberView's own page, linked and never copied (CLAUDE.md rule 11), and anything CyberView wrote is labelled as
// written by CyberView AI, a Claude model (rule 15).
import { cleanFlaws, rowFor, pageFor } from "./match.mjs";
import { fingerprintProducts } from "./kev-coverage.mjs";
import { W, D } from "./shared.mjs";

export const AI_BY = "CyberView AI (a Claude model)";
const isCve = (s) => /^CVE-\d{4}-\d{4,7}$/i.test(String(s || "").trim());

/** The CVE id as the data files spell it, or "" when it is not a CVE number. */
export function cveId(s) {
  const t = String(s || "").trim().toUpperCase();
  return isCve(t) ? t : "";
}

/** Can this scanner name the product, and does it read a version the ranges can be compared against? */
export function detectionFor(flaw, products = fingerprintProducts()) {
  const hit = products.filter((p) => {
    const r = W.matchFlaw(JSON.parse(JSON.stringify(flaw)), [{ name: p.product, vendor: p.vendor, version: "", count: 1 }]);
    return r && r.state !== "none";
  });
  const reads = hit.filter((p) => p.version);
  return {
    can_name: hit.length > 0,
    reads_version: reads.length > 0,
    how: hit.slice(0, 6).map((p) => `${[p.vendor, p.product].filter(Boolean).join(" ")} (${p.via})`),
    what_it_means: reads.length
      ? "a scan can read this product's version, so a finding can be version-confirmed"
      : hit.length
        ? "a scan can name this product but does not read its version, so a finding stays low confidence and the version must be checked by hand"
        : "this scanner has no fingerprint for this product, so a scan will not report it; that is a detection gap, not evidence the product is absent",
  };
}

/** A version the operator holds, against the flaw's own ranges. */
export function versionVerdict(flaw, version) {
  const v = String(version || "").trim();
  if (!v) return null;
  const m = W.matchFlaw(JSON.parse(JSON.stringify(flaw)), [{ name: flaw.product, vendor: flaw.vendor, version: v, count: 1 }]);
  // the engine's own states: affected, check (named but no comparable range), clear (compared and outside), none (not named)
  const state = m ? m.state : "none";
  const SAYS = {
    affected: "the version you gave is inside an affected range",
    check: "CyberView has no comparable range for this product yet, so the version could not be judged: check the vendor's advisory",
    clear: "the version you gave was compared with every range CyberView holds and is outside all of them",
    none: "this flaw's ranges do not name this product, so there was nothing to compare the version with",
  };
  return {
    version: v.slice(0, 40), state,
    says: Object.prototype.hasOwnProperty.call(SAYS, state) ? SAYS[state] : SAYS.none,
    fixed_in: m ? [...m.fixed].sort(W.cmp).slice(-6) : [],
    caveat: "A Linux distribution's package can carry a backported fix under an old version number, and a vendor can change how it numbers builds; the vendor's own advisory decides.",
  };
}

const range = (r) => {
  const who = [r.vendor, r.product].filter(Boolean).join(" ");
  if (r.nameOnly) return `${who}: named, no version range yet`;
  if (r.exact) return `${who} exactly ${r.exact}`;
  const lo = r.from ? `${r.from_incl ? "from" : "after"} ${r.from}` : "";
  const hi = r.to ? `${r.to_incl ? "up to and including" : "before"} ${r.to}` : "";
  return `${who} ${[lo, hi].filter(Boolean).join(" ") || "all versions"}`.trim();
};

/**
 * src: dirSource(dir); id: a CVE number; version: optional, a version the operator holds.
 * -> the lookup document. `known` false means CyberView's snapshot does not list this CVE, which is said plainly
 *    rather than guessed at: the catalog holds the known-exploited flaws and recent high-risk ones, not every CVE.
 */
export async function lookup(src, id, { version = "", today = new Date().toISOString().slice(0, 10), products } = {}) {
  const cve = cveId(id);
  const wb = await src.json("data/workbench.json");
  const ps = await src.json("data/psirt.json", { optional: true });
  D.vendorIndex = ps ? D.cleanVendorIndex(ps) : {};
  const flaws = cleanFlaws(wb);
  const f = flaws.find((x) => x.cve === cve) || null;
  const base = {
    tool: { name: "CyberView Scanner", command: "lookup", detection_only: true },
    at: new Date().toISOString(), network: "none: read from a local snapshot only",
    query: { cve, version: String(version || "").trim().slice(0, 40) || null },
    data: { mode: src.kind, source: src.where, workbench_built_at: (wb && wb.built_at) || "" },
  };
  if (!f) {
    // the CVE lookup file may still hold the row even when the flaw is not in the catalog
    const bucket = D.bucketFile(cve) ? `data/cve/${D.bucketFile(cve)}` : "";
    const file = bucket ? await src.json(bucket, { optional: true }).then((j) => (j ? D.parseFile(j) : []), () => []) : [];
    const row = file.find((x) => x.id === cve) || null;
    const sc = row ? D.score(row) : null;
    return { ...base, known: false,
      why: "CyberView's catalog does not list this CVE. It holds CISA's known-exploited flaws with NVD's affected-version ranges, and recent high-risk flaws; a CVE outside them is not tracked here"
        + (row ? ", but the CVE lookup file in this snapshot has its row" : ". The snapshot may also be older than the CVE"),
      row: row ? { id: row.id, vendor: row.vendor, product: row.product, title: row.title, cvss: row.cvss, published: row.pub, kev: !!row.kev,
        rating: sc ? { score: sc.score, band: sc.band, text: sc.text, notes: sc.notes, confidence: sc.confidence } : null } : null,
      details: pageFor(cve) };
  }
  const { row, from } = rowFor(f, new Map(await (async () => {
    const bucket = D.bucketFile(cve) ? `data/cve/${D.bucketFile(cve)}` : "";
    const file = bucket ? await src.json(bucket, { optional: true }).then((j) => (j ? D.parseFile(j) : []), () => []) : [];
    const r = file.find((x) => x.id === cve);
    return r ? [[cve, r]] : [];
  })()));
  const sc = D.score(row);
  const prInt = D.rate(row, { today, exposed: false }), prPub = D.rate(row, { today, exposed: true });
  const g = f.guide;
  return {
    ...base, known: true,
    flaw: { cve: f.cve, vendor: f.vendor, product: f.product, title: f.name, summary: f.desc,
      known_exploited: f.kev, kev_added: f.kev ? f.added : "", cisa_due: f.due || "", overdue: !!(f.due && f.due < today),
      ransomware: f.ransomware, epss: f.epss, exploit_public: f.exploit_public, exposure: f.exposure || "" },
    rating: sc ? { score: sc.score, band: sc.band, text: sc.text, base: sc.base, notes: sc.notes, confidence: sc.confidence, confidence_why: sc.confidenceWhy, from }
      : { score: null, band: "Not scored", text: "", from },
    priority: { internal: prInt ? { decision: prInt.decision, label: prInt.label, does: prInt.does, fix_by: prInt.fixBy.internal, deadline: prInt.deadline, overdue: prInt.overdue } : null,
      internet_facing: prPub ? { decision: prPub.decision, label: prPub.label, does: prPub.does, fix_by: prPub.fixFor ? prPub.fixBy[prPub.fixFor] : prPub.fixBy.internal, deadline: prPub.deadline, overdue: prPub.overdue } : null,
      note: "No inventory was given, so both of CISA's exposure answers are shown; the CyberView rating itself does not depend on exposure" },
    affected: f.affected.map(range),
    your_version: versionVerdict(f, version),
    detection: detectionFor(f, products),
    fix: { vendor_fixed: g ? g.fixed : [], workaround: g ? g.workaround : [], cisa_required_action: f.required,
      advisory: g ? g.advisory : null, references: f.refs, details: pageFor(f.cve),
      details_note: "Check steps, signs of compromise and detection resources are on CyberView's page for this CVE: linked, never copied here.",
      analysis: f.analysis ? { url: pageFor(f.cve), by: AI_BY } : null,
      guide_by: g ? AI_BY : "" },
  };
}

/** The lookup document as text. */
export function lookupText(doc) {
  const L = [];
  if (!doc.known) {
    L.push(`${doc.query.cve}: not in CyberView's catalog.`);
    L.push(`   ${doc.why}.`);
    if (doc.row) {
      L.push("");
      L.push(`From the CVE lookup file in this snapshot: ${[doc.row.vendor, doc.row.product].filter(Boolean).join(" ") || "(product not stated)"} — ${doc.row.title || "(no title)"}`);
      if (doc.row.rating && doc.row.rating.score != null) L.push(`   CyberView rating: ${doc.row.rating.text} = ${doc.row.rating.score.toFixed(1)} ${doc.row.rating.band}`);
      if (doc.row.published) L.push(`   Published ${doc.row.published}.`);
    }
    L.push("");
    L.push(`Details: ${doc.details}`);
    L.push(`Read from ${doc.data.source} (data built ${doc.data.workbench_built_at || "?"}). Nothing was contacted.`);
    return L.join("\n");
  }
  const f = doc.flaw;
  L.push(`${f.cve} ${[f.vendor, f.product].filter(Boolean).join(" ")} — ${f.title || "(no title)"}`);
  if (f.summary) L.push(`   ${f.summary}`);
  L.push("");
  if (f.known_exploited) L.push(`KNOWN EXPLOITED (CISA KEV since ${f.kev_added || "?"})${f.cisa_due ? `, CISA due ${f.cisa_due}${f.overdue ? " (OVERDUE)" : ""}` : ""}${f.ransomware ? "; used in ransomware campaigns" : ""}.`);
  else L.push("Not on CISA's known-exploited list; listed by CyberView as a recent high-risk flaw.");
  if (f.epss != null) L.push(`EPSS: ${Math.round(f.epss * 100)}% chance of exploitation in the next 30 days.`);
  if (f.exploit_public) L.push("Public exploit code has been reported.");
  L.push("");
  // rating.text already ends with the score and the band, exactly as report.mjs prints it
  L.push(`CyberView rating: ${doc.rating.text || doc.rating.band} (${doc.rating.from})`);
  (doc.rating.notes || []).forEach((n) => L.push(`   ${n}`));
  L.push("");
  L.push("CISA SSVC priority (BOD 26-04), both exposure answers — no inventory was given:");
  for (const [k, p] of [["internet-facing", doc.priority.internet_facing], ["internal", doc.priority.internal]]) {
    if (!p) continue;
    L.push(`   ${k}: ${p.label}${p.fix_by && p.fix_by.text ? ` — ${p.fix_by.text}` : ""}${p.deadline ? ` (by ${p.deadline}${p.overdue ? ", OVERDUE" : ""})` : ""}`);
    if (p.does) L.push(`      ${p.does}`);
  }
  if (doc.affected.length) {
    L.push("");
    L.push("Affected versions (from NVD, as the Vulnerabilities page holds them):");
    doc.affected.slice(0, 20).forEach((r) => L.push(`   ${r}`));
    if (doc.affected.length > 20) L.push(`   and ${doc.affected.length - 20} more`);
  } else {
    L.push("");
    L.push("Affected versions: CyberView holds no version range for this flaw yet; the vendor's advisory decides.");
  }
  if (doc.your_version) {
    const v = doc.your_version;
    L.push("");
    const VERDICT = { affected: "AFFECTED", check: "CANNOT BE JUDGED", clear: "not affected", none: "NOT COMPARABLE" };
    L.push(`Version ${v.version}: ${VERDICT[v.state] || VERDICT.none} — ${v.says}.`);
    if (v.fixed_in.length) L.push(`   Fixed in: ${v.fixed_in.join(", ")}`);
    L.push(`   ${v.caveat}`);
  }
  L.push("");
  L.push(`Can this scanner find it? ${doc.detection.reads_version ? "Yes, with the version" : doc.detection.can_name ? "The product only, not its version" : "No"} — ${doc.detection.what_it_means}.`);
  doc.detection.how.forEach((h) => L.push(`   ${h}`));
  L.push("");
  if (doc.fix.cisa_required_action) L.push(`CISA required action: ${doc.fix.cisa_required_action}`);
  if (doc.fix.vendor_fixed.length) L.push(`Vendor fixed versions: ${doc.fix.vendor_fixed.join("; ")}`);
  if (doc.fix.workaround.length) { L.push("Workarounds the vendor states:"); doc.fix.workaround.slice(0, 5).forEach((w) => L.push(`   ${w}`)); }
  if (doc.fix.advisory) L.push(`Vendor advisory: ${doc.fix.advisory.url}`);
  (doc.fix.references || []).slice(0, 4).forEach((r) => L.push(`Reference: ${r}`));
  if (doc.fix.guide_by) L.push(`The fix guide above was written by ${doc.fix.guide_by}.`);
  if (doc.fix.analysis) L.push(`An exploitation analysis written by ${doc.fix.analysis.by} is on the page: ${doc.fix.analysis.url}`);
  L.push(doc.fix.details_note);
  L.push(`Details: ${doc.fix.details}`);
  L.push("");
  L.push(`Read from ${doc.data.source} (data built ${doc.data.workbench_built_at || "?"}). Nothing was contacted.`);
  return L.join("\n");
}
