// Vendor security advisories (PSIRTs) as structured data: the pure parsers and rules behind scripts/psirt.mjs, kept apart
// so unit tests can run them on saved replies (tests/fixtures/psirt/). No network, no AI model.
//
// One advisory, whatever the source:
//   { vendor, vkey, id, title, url, cves: [], severity (the vendor's own word: "Critical", "Important", "High" ...),
//     cvss (highest base score the vendor gives) | null, vector, exploited (bool), exploited_cves: [], exploited_text,
//     fixed: [fixed versions or builds as the vendor states them], published, updated (ISO), source ("csaf" | "cvrf" |
//     "rss" | "html" | "json"), csaf (the CSAF document's url, when there is one), no_action (Microsoft: a cloud service it
//     fixed itself, "Customer Action Required: No"; only when true) }
// exploited is true only when the vendor itself says the flaw is exploited (in the wild, limited or targeted attacks);
// exploited_cves lists the CVEs that statement covers: named in it, or the advisory's only CVE. A statement that names no
// CVE in a several-CVE advisory leaves exploited_cves empty, so it is shown on the advisory but never moves a CVE's rating.

export const ID = /^CVE-\d{4}-\d{4,}$/;
const CVE_G = /CVE-\d{4}-\d{4,}/g;
const ENT = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", "#39": "'", "#034": '"', "#34": '"', "#038": "&" };

export const txt = (s, n = 300) => String(s == null ? "" : s).replace(/\s+/g, " ").trim().slice(0, n);
export function decode(s) {
  return String(s || "").replace(/&(#x[0-9a-f]+|#\d+|[a-z]+\d*);/gi, (m, e) => {
    const k = e.toLowerCase();
    if (ENT[k] != null) return ENT[k];
    if (k[0] === "#") { const n = k[1] === "x" ? parseInt(k.slice(2), 16) : parseInt(k.slice(1), 10); return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : ""; }
    return m;
  });
}
/** HTML -> plain text with line breaks at block ends (scripts and styles dropped) */
export function plain(html) {
  return decode(String(html || "").replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, " ")
    .replace(/<(br|\/p|\/li|\/tr|\/h\d|\/div|\/dd|\/dt|\/section|li|p)\b[^>]*>/gi, "\n").replace(/<[^>]+>/g, " "))
    .replace(/[ \t\r\f\v ]+/g, " ").replace(/ *\n[\n ]*/g, "\n").trim();
}
/** the blocks of one XML tag (item, entry) */
export const blocks = (xml, tag) => String(xml || "").split(new RegExp(`<${tag}[\\s>]`)).slice(1).map((b) => b.split(new RegExp(`</${tag}>`))[0]);
/** text of the first <name> in a block, CDATA unwrapped, entities decoded */
export function tag(b, name) {
  const m = new RegExp(`<${name.replace(/[:]/g, "\\:")}(?:\\s[^>]*)?>([\\s\\S]*?)</${name.replace(/[:]/g, "\\:")}>`).exec(b || "");
  if (!m) return "";
  const v = m[1].replace(/^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/, "$1");
  return decode(v).trim();
}
export const cvesIn = (s) => [...new Set(String(s || "").toUpperCase().match(CVE_G) || [])].filter((c) => ID.test(c));
export function iso(s) {
  const t = Date.parse(String(s || "").trim().replace(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(\.\d+)?$/, "$1T$2Z"));
  return isFinite(t) ? new Date(t).toISOString().replace(/\.\d+Z$/, "Z") : "";
}
const SEV_RANK = { critical: 5, important: 4, high: 4, moderate: 3, medium: 3, low: 2, none: 1, informational: 1 };
export const sevWord = (s) => { const t = txt(s, 20).toLowerCase(); return SEV_RANK[t] ? t[0].toUpperCase() + t.slice(1) : ""; };
export const sevRank = (s) => SEV_RANK[String(s || "").toLowerCase()] || 0;
const maxSev = (list) => list.map(sevWord).filter(Boolean).sort((a, b) => sevRank(b) - sevRank(a))[0] || "";

// ---------- the vendor's own exploitation statement ----------
const POS = new RegExp([
  "exploited in the wild", "exploitation in the wild", "exists in the wild", "in-the-wild exploitation",
  "(?:has|have) been (?:actively )?exploited", "(?:is|are) being actively exploited", "actively exploited in",
  "under (?:limited, targeted |limited |active |targeted )?exploitation", "limited,? targeted exploitation",
  "aware of (?:[\\w,'’-]+ ){0,8}?(?:exploitation|exploited|exploits?|malicious use|attacks?|customers? (?:whose|being|that have been))",
  "may have been exploited", "exploitation (?:has been |was )?(?:observed|detected)", "exploitation detected",
].join("|"), "i");
const NEG = /\b(?:not aware|unaware|no evidence|no known|no indication|no reports?|not (?:been |being |currently )?(?:actively )?exploited|has not been|have not been|is not being|are not being|not seen|not observed|no active)\b/i;
// a sentence about what exploitation would look like, or how likely it is, is not a statement that it happened
const HYPO = /\b(?:while|during|if|whether|risk of|could|might|would|should|can be|in order to|to detect|indicators? of)\b/i;
const POC_ONLY = /proof[- ]of[- ]concept|\bPoC\b|exploit code (?:is|has been) (?:publicly )?(?:available|published|released)/i;
/** the sentences in which the vendor says a flaw is exploited (never one that says it is not, or only that a PoC exists) */
export function exploitedSentences(text) {
  return String(text || "").split(/(?<=[.!?])\s+|\n+/).map((s) => txt(s, 400)).filter((s) => s.length > 12 && POS.test(s) && !NEG.test(s) && !HYPO.test(s)
    && !(POC_ONLY.test(s) && !/in the wild|exploited|exploitation/i.test(s.replace(POC_ONLY, ""))));
}
/** statement(s) + the advisory's CVEs -> { exploited, exploited_cves, exploited_text } */
export function exploitation(sentences, cves) {
  const ss = [...new Set(sentences)].slice(0, 4);
  if (!ss.length) return { exploited: false, exploited_cves: [], exploited_text: "" };
  const named = cvesIn(ss.join(" ")).filter((c) => cves.includes(c));
  return { exploited: true, exploited_cves: named.length ? named : cves.length === 1 ? [cves[0]] : [], exploited_text: txt(ss.join(" "), 400) };
}

// ---------- one record, checked ----------
const httpsUrl = (u) => { const s = txt(u, 600); return /^https:\/\/[^\s"'<>]+$/.test(s) ? s : ""; };
export function advisory(o) {
  const cves = [...new Set((o.cves || []).map((c) => String(c).toUpperCase()).filter((c) => ID.test(c)))].slice(0, 2000);
  const url = httpsUrl(o.url);
  if (!o.vkey || !o.id || !url) return null;
  const cvss = typeof o.cvss === "number" && isFinite(o.cvss) && o.cvss >= 0 && o.cvss <= 10 ? Math.round(o.cvss * 10) / 10 : null;
  const xc = (o.exploited_cves || []).filter((c) => cves.includes(c));
  return {
    vendor: txt(o.vendor, 40), vkey: txt(o.vkey, 20), id: txt(o.id, 80), title: txt(o.title, 200), url, cves,
    severity: sevWord(o.severity), cvss, vector: /^CVSS:[0-9.]+\/[A-Za-z0-9:\/.]{8,200}$/.test(o.vector || "") ? o.vector : "",
    exploited: !!o.exploited, exploited_cves: o.exploited ? xc : [], exploited_text: o.exploited ? txt(o.exploited_text, 400) : "",
    fixed: [...new Set((o.fixed || []).map((f) => txt(f, 120)).filter(Boolean))].slice(0, 8),
    published: iso(o.published) || iso(o.updated), updated: iso(o.updated) || iso(o.published), source: txt(o.source, 10), csaf: httpsUrl(o.csaf),
    ...(o.no_action ? { no_action: true } : {}),
  };
}

// ---------- CSAF 2.0 (Cisco, Fortinet, Palo Alto Networks, Red Hat ...) ----------
function products(tree) {
  // a version branch's product name sometimes leaves the version out (Palo Alto Networks): add it from the branch
  const m = new Map(), walk = (b) => { for (const x of b || []) { if (x.product && x.product.product_id) { const n = x.product.name || ""; m.set(x.product.product_id, /version/.test(x.category || "") && x.name && !n.includes(x.name) ? `${n} ${x.name}` : n); } walk(x.branches); } };
  walk(tree && tree.branches);
  for (const r of (tree && tree.relationships) || []) if (r.full_product_name) m.set(r.full_product_name.product_id, r.full_product_name.name || "");
  for (const p of (tree && tree.full_product_names) || []) m.set(p.product_id, p.name || "");
  return m;
}
function bestScore(scores) {
  let best = null;
  for (const s of scores || []) for (const k of ["cvss_v4", "cvss_v3"]) { const c = s && s[k]; if (c && typeof c.baseScore === "number" && (!best || c.baseScore > best.score)) best = { score: c.baseScore, vector: c.vectorString || "", sev: c.baseSeverity || "" }; }
  return best;
}
/** a CSAF 2.0 document -> one advisory (null when it is not one) */
export function parseCsaf(d, { vendor, vkey, csaf = "" } = {}) {
  const doc = d && d.document; if (!doc || !doc.tracking) return null;
  const vulns = Array.isArray(d.vulnerabilities) ? d.vulnerabilities : [];
  const cves = [...new Set(vulns.map((v) => v.cve).filter((c) => ID.test(c || "")))];
  const refs = (doc.references || []).concat(...vulns.map((v) => v.references || []));
  const self = (doc.references || []).find((r) => r.category === "self" && /^https:\/\//.test(r.url || "") && !/\.json$/.test(r.url)) || refs.find((r) => /^https:\/\//.test(r.url || "") && !/\.json$/.test(r.url || ""));
  const said = [];
  // the document's own notes: only the summary and the vendor's exploitation section (Cisco: "Exploitation and Public
  // Announcements"); the detail sections describe what an attack would look like, which is not a statement that one happened
  for (const n of doc.notes || []) if (n.category === "summary" || /exploit|public announcement/i.test(n.title || "")) said.push(...exploitedSentences(n.text));
  const xc = new Set(); let perVuln = false;
  for (const v of vulns) {
    const s = [];
    for (const t of v.threats || []) if (t.category === "exploit_status") { if (/Exploited:\s*Yes/i.test(t.details || "")) s.push(`${vendor}: exploited (exploit status "${txt(t.details, 120)}")`); else s.push(...exploitedSentences(t.details)); }
    for (const n of v.notes || []) s.push(...exploitedSentences(n.text));
    if (s.length && ID.test(v.cve || "")) { xc.add(v.cve); perVuln = true; said.push(...s); }
  }
  const ex = exploitation(said, cves);
  if (perVuln) ex.exploited_cves = [...new Set([...xc, ...ex.exploited_cves])];
  const sc = vulns.map((v) => bestScore(v.scores)).filter(Boolean).sort((a, b) => b.score - a.score)[0] || null;
  const names = products(d.product_tree), fixed = [];
  for (const v of vulns) for (const id of (v.product_status && v.product_status.fixed) || []) if (names.get(id)) fixed.push(names.get(id).replace(/\s*vers:[a-z]+\/[^<>=!]*?(?=[<>=!])/, " "));   // a version range (vers:generic/PAN-OS>=10.2.0-h3) reads as ">=10.2.0-h3"
  if (!fixed.length) for (const v of vulns) for (const r of v.remediations || []) if (r.category === "vendor_fix" && r.details) fixed.push(...String(r.details).split(/\n+/).filter((l) => /\d/.test(l)));
  const fortiTitle = vulns.map((v) => (/ - (CRITICAL|HIGH|MEDIUM|LOW) - /.exec(v.title || "") || [])[1]).filter(Boolean);
  return advisory({
    vendor, vkey, id: doc.tracking.id, title: doc.title, url: self ? self.url : csaf, cves, csaf,
    severity: (doc.aggregate_severity && doc.aggregate_severity.text) || maxSev(fortiTitle) || (sc && sc.sev) || "",
    cvss: sc ? sc.score : null, vector: sc ? sc.vector : "", ...ex, fixed,
    published: doc.tracking.initial_release_date, updated: doc.tracking.current_release_date, source: "csaf",
  });
}
/** a CSAF provider's changes.csv ("path","time" per line, newest first) -> [{ url, at }] */
export function parseChanges(csv, base) {
  const out = [];
  for (const l of String(csv || "").split(/\r?\n/)) {
    const m = /^"?([^",]+\.json)"?\s*,\s*"?([0-9T:.+\-Z]+)"?\s*$/.exec(l.trim()); if (!m || m[1].includes("..")) continue;
    out.push({ url: new URL(m[1], base.endsWith("/") ? base : base + "/").href, at: iso(m[2]) });
  }
  return out;
}

// ---------- Microsoft: the MSRC CVRF API (one document per monthly release) ----------
const MS_SKIP = /^(Mariner|Azure Linux|Microsoft Edge \(Chromium-based\))$/i;   // third-party code Microsoft ships: Chromium (the Chrome parser has it) and Linux packages
const val = (x) => (x && typeof x === "object" ? x.Value : x) || "";
/** the updates list -> the monthly release ids to read (the newest by first release, at most n) */
export function msrcReleases(j, n = 2) {
  return ((j && j.value) || []).filter((x) => /^\d{4}-[A-Z][a-z]{2}$/.test(x.ID || "")).sort((a, b) => String(b.InitialReleaseDate).localeCompare(String(a.InitialReleaseDate))).slice(0, n).map((x) => x.ID);
}
export function parseMsrc(doc) {
  const out = [];
  for (const v of (doc && doc.Vulnerability) || []) {
    const cve = v.CVE; if (!ID.test(cve || "")) continue;
    const fam = (v.Notes || []).filter((n) => n.Type === 7).map((n) => val(n));
    if (fam.length && fam.every((f) => MS_SKIP.test(f))) continue;
    const th = v.Threats || [], status = th.filter((t) => t.Type === 1).map((t) => val(t.Description)).join(" ");
    const exploited = /Exploited:\s*Yes/i.test(status);
    const sc = (v.CVSSScoreSets || []).filter((s) => typeof s.BaseScore === "number").sort((a, b) => b.BaseScore - a.BaseScore)[0];
    const fixed = [];
    for (const r of v.Remediations || []) {
      const kb = /^\d{6,8}$/.test(val(r.Description)) ? "KB" + val(r.Description) : "", build = /^[\w.+-]{1,40}$/.test(r.FixedBuild || "") ? r.FixedBuild : "";
      if (r.Type === 2 && (kb || build)) fixed.push([kb, build].filter(Boolean).join(" build "));
    }
    const rev = (v.RevisionHistory || []).map((r) => iso(r.Date)).filter(Boolean).sort();
    const a = advisory({
      vendor: "Microsoft", vkey: "microsoft", id: cve, title: val(v.Title), url: `https://msrc.microsoft.com/update-guide/vulnerability/${cve}`, cves: [cve],
      severity: maxSev(th.filter((t) => t.Type === 3).map((t) => val(t.Description))), cvss: sc ? sc.BaseScore : null, vector: sc ? String(sc.Vector || "").replace(/\/(E|RL|RC):[A-Z]+/g, "") : "",
      exploited, exploited_cves: exploited ? [cve] : [], exploited_text: exploited ? `Microsoft's exploitability assessment: ${txt(status.replace(/;/g, "; "), 200)}` : "",
      fixed, published: rev[0], updated: rev[rev.length - 1], source: "cvrf",
      // a cloud service Microsoft fixed itself ("Customer Action Required: No"): kept for the join, never a lead
      no_action: (v.Notes || []).some((n) => n.Type === 6 && /^No$/i.test(String(val(n)).trim())),
    });
    if (a) out.push(a);
  }
  return out;
}

// ---------- RSS-listed vendors ----------
/** Fortinet's FortiGuard PSIRT RSS: [{ id, url, csaf, title, published, cves, cvss, text }] */
export function parseFortinetRss(xml) {
  return blocks(xml, "item").map((b) => {
    const url = tag(b, "link"), desc = plain(tag(b, "description")), id = (/FG-IR-\d{2}-\d+/.exec(url) || [])[0];
    const cvss = Number((/CVSSv3 Score:\s*([\d.]+)/i.exec(desc) || [])[1]);
    return id ? { id, url, csaf: tag(b, "csaf:link"), title: tag(b, "title"), published: iso(tag(b, "pubDate")), cves: cvesIn(desc + " " + tag(b, "title")), cvss: isFinite(cvss) ? cvss : null, text: desc } : null;
  }).filter(Boolean);
}
export function fortinetFromRss(it) {
  const sev = (/\((critical|high|medium|low)\)/i.exec(it.text) || [])[1] || "";
  return advisory({ vendor: "Fortinet", vkey: "fortinet", id: it.id, title: it.title, url: it.url, cves: it.cves, severity: sev, cvss: it.cvss, ...exploitation(exploitedSentences(it.text), it.cves),
    fixed: (it.text.match(/[^.]*\bversions? [\d.]+[^.]*(?:fix|upgrade)[^.]*/gi) || []).slice(0, 3), published: it.published, updated: it.published, source: "rss", csaf: it.csaf });
}
/** Palo Alto Networks' advisory RSS: [{ id, url, title, severity, published }] (the item's CSAF is at /csaf/<id>) */
export function parsePanRss(xml) {
  return blocks(xml, "item").map((b) => {
    const url = tag(b, "link"), t = tag(b, "title"), id = (/security\.paloaltonetworks\.com\/((?:CVE|PAN-SA)-\d{4}-\d+)/.exec(url) || [])[1];
    return id ? { id, url: `https://security.paloaltonetworks.com/${id}`, title: t.replace(/\s*\(Severity: \w+\)\s*$/, "").replace(new RegExp("^" + id + "\\s+"), ""), severity: (/\(Severity: (\w+)\)/.exec(t) || [])[1] || "", published: iso(tag(b, "pubDate")), cves: cvesIn(t) } : null;
  }).filter(Boolean);
}
/** Cisco's advisory RSS: [{ id, url, title, updated }] (the CSAF document is <year>/<id in lower case>.json in Cisco's CSAF
 *  directory; ciscoCsafPaths maps an id to it from the directory's index.txt) */
export function parseCiscoRss(xml) {
  return blocks(xml, "item").map((b) => {
    const id = (/\/CiscoSecurityAdvisory\/(cisco-sa-[\w-]+)/.exec(tag(b, "link")) || [])[1];
    return id ? { id, url: `https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/${id}`, title: tag(b, "title"), updated: iso(tag(b, "pubDate").replace(" ", "T").replace(/\.0$/, "")) } : null;
  }).filter(Boolean);
}
export function ciscoCsafPaths(indexTxt) {
  const m = new Map();
  for (const l of String(indexTxt || "").split(/\r?\n/)) { const p = /^(\d{4}\/(cisco-sa-[\w-]+)\.json)$/.exec(l.trim()); if (p) m.set(p[2].toLowerCase(), p[1]); }
  return m;
}
/** Red Hat's changes.csv -> RHSA documents numbered above `after` (new advisories; a regenerated old one keeps its number),
 *  oldest first: [{ url, n }] */
export function redhatNew(changes, after = 0) {
  const seen = new Set(), out = [];
  for (const c of changes) { const m = /\/rhsa-(\d{4})_(\d+)\.json$/.exec(c.url); if (!m) continue; const n = Number(m[1]) * 1e7 + Number(m[2]); if (n > after && !seen.has(n)) { seen.add(n); out.push({ url: c.url, n }); } }
  return out.sort((a, b) => a.n - b.n);
}
/** Oracle's security-alerts RSS: [{ id, url, title, published, alert }] (alert: an out-of-band Security Alert, not a scheduled patch update) */
export function parseOracleRss(xml) {
  return blocks(xml, "item").map((b) => {
    const url = tag(b, "link").trim(), title = txt(tag(b, "title"), 200), id = txt(tag(b, "guid"), 60) || (/\/([\w-]+)\.html$/.exec(url) || [])[1];
    return /^https:\/\/www\.oracle\.com\/security-alerts\//.test(url) && id ? { id, url, title, published: iso(tag(b, "pubDate")), alert: /Security Alert/i.test(title), cves: cvesIn(title) } : null;
  }).filter(Boolean);
}
/** Ivanti's security advisory posts (blog RSS, full text in the description) -> advisories */
export function parseIvantiRss(xml) {
  return blocks(xml, "item").map((b) => {
    // the post links each product's advisory, whose address names its CVEs: read them from the links too
    const url = tag(b, "link"), html = tag(b, "description"), text = plain(html), cves = cvesIn(html), id = (/\/blog\/([\w-]+)$/.exec(url) || [])[1];
    if (!id || !cves.length) return null;
    const crit = /\bcritical\b/i.test(text) ? "Critical" : /\bhigh\b/i.test(text) ? "High" : "";
    return advisory({ vendor: "Ivanti", vkey: "ivanti", id, title: tag(b, "title"), url, cves, severity: crit, ...exploitation(exploitedSentences(text), cves), published: tag(b, "pubDate"), updated: tag(b, "pubDate"), source: "rss" });
  }).filter(Boolean);
}
/** Debian's DSA list (RDF): [{ id, url, title, published }] */
export function parseDebianRdf(xml) {
  return blocks(xml, "item").map((b) => { const t = tag(b, "title"), id = (/^(DSA-\d+-\d+)/.exec(t) || [])[1];
    return id ? { id, title: t, url: `https://security-tracker.debian.org/tracker/${id}`, published: iso(tag(b, "dc:date")) } : null; }).filter(Boolean);
}
/** a Debian security tracker DSA page -> the CVEs and fixed versions it lists */
export function parseDebianTracker(html) {
  const refs = (/<b>References<\/b><\/td><td>([\s\S]*?)<\/td>/.exec(html || "") || [])[1] || "";
  const fixed = [], tbl = String(html || "").split(/based on the following data on fixed versions/)[1] || "";
  for (const m of tbl.matchAll(/<tr><td>(?:<a[^>]*>)?([\w.+-]+)(?:<\/a>)?<\/td><td>source<\/td><td>([\w-]+)<\/td><td>([^<]+)<\/td>/g)) fixed.push(`${m[1]} ${m[3]} (${m[2]})`);
  return { cves: cvesIn(refs), fixed };
}

// ---------- Ubuntu security notices (JSON API) ----------
export function parseUbuntu(j) {
  return ((j && j.notices) || []).map((n) => {
    const fixed = [];
    for (const [rel, pk] of Object.entries(n.release_packages || {})) for (const p of pk || []) if (p.is_source) fixed.push(`${p.name} ${p.version} (${rel})`);
    return advisory({ vendor: "Ubuntu", vkey: "ubuntu", id: n.id, title: n.title, url: `https://ubuntu.com/security/notices/${n.id}`, cves: n.cves_ids || (n.cves || []).map((c) => c.id), fixed, published: n.published, updated: n.published, source: "json" });
  }).filter(Boolean);
}

// ---------- Google Chrome release notes (Blogger Atom feed) ----------
export function parseChromeAtom(xml) {
  return blocks(xml, "entry").map((b) => {
    const title = tag(b, "title"); if (!/Stable Channel Update|Chrome for Android Update|Extended Stable/i.test(title)) return null;
    const text = plain(tag(b, "content")), link = (/<link rel=['"]alternate['"][^>]*href=['"]([^'"]+)['"]/.exec(b) || [])[1] || "";
    // the release's fix list, plus a CVE Google says is exploited in the wild (stated in this release, fixed by it)
    const rows = [...text.matchAll(/\b(Critical|High|Medium|Low)\s+(CVE-\d{4}-\d{4,})/g)], wild = exploitedSentences(text);
    const cves = [...new Set([...rows.map((m) => m[2]), ...cvesIn(wild.join(" "))])];
    if (!cves.length) return null;
    const ver = (/Chrome (?:\d+ )?(?:is )?(?:\w+ )*?(\d+\.\d+\.\d+\.\d+)/.exec(text) || /\b(\d{3}\.\d+\.\d{4,}\.\d+)\b/.exec(text) || [])[1] || "";
    const plat = /Android/i.test(title) ? "Android" : /ChromeOS/i.test(title) ? "ChromeOS" : /Extended/i.test(title) ? "Extended Stable" : "Desktop";
    return advisory({ vendor: "Google Chrome", vkey: "chrome", id: `chrome-${ver || iso(tag(b, "published")).slice(0, 10)}-${plat.toLowerCase().replace(/\s+/g, "-")}`, title: `${title}${ver ? " (" + ver + ")" : ""}`, url: link, cves,
      severity: maxSev(rows.map((m) => m[1])), ...exploitation(wild, cves), fixed: ver ? [`Chrome ${ver} (${plat})`] : [], published: tag(b, "published"), updated: tag(b, "updated"), source: "rss" });
  }).filter(Boolean);
}

// ---------- Apple security releases (HTML) ----------
/** support.apple.com/en-us/100100 -> [{ url, name, date }] (releases with a page; "no published CVE entries" rows have none) */
export function parseAppleIndex(html) {
  const out = [];
  for (const row of String(html || "").split(/<tr[\s>]/).slice(1)) {
    const a = /<a href="(https:\/\/support\.apple\.com\/(?:en-us\/)?\d+)"[^>]*>([\s\S]*?)<\/a>/.exec(row); if (!a) continue;
    const cells = row.split(/<\/td>/).map(plain), date = iso((cells[2] || "").replace(/^(\d{1,2}) (\w{3}) (\d{4})$/, "$2 $1, $3") + " 12:00 UTC");
    out.push({ url: a[1], name: plain(a[2]), date });
  }
  return out;
}
/** one Apple release page -> advisory: each "Impact:" block's CVEs; a block where Apple says it may have been exploited marks its CVEs */
export function parseApplePage(html, url, name = "") {
  const text = plain(html), title = name || txt((/<h1[^>]*>([\s\S]*?)<\/h1>/.exec(html || "") || [])[1] ? plain(/<h1[^>]*>([\s\S]*?)<\/h1>/.exec(html)[1]) : "", 160);
  const rel = (/Released (\w+ \d{1,2}, \d{4})/.exec(text) || [])[1] || "";
  const body = text.split(/Released \w+ \d{1,2}, \d{4}/).slice(1).join(" ") || text, said = [], xc = new Set();
  for (const blk of body.split(/\n(?=Available for:)/)) {
    const c = cvesIn(blk), s = exploitedSentences(blk.replace(/\n/g, " "));
    if (c.length && s.length) { c.forEach((x) => xc.add(x)); said.push(...s); }
  }
  const cves = cvesIn(body);
  if (!cves.length) return null;
  const id = "apple-" + ((/\/(\d+)$/.exec(url) || [])[1] || "");
  return advisory({ vendor: "Apple", vkey: "apple", id, title: `About the security content of ${title}`, url, cves, exploited: xc.size > 0, exploited_cves: [...xc], exploited_text: txt([...new Set(said)].join(" "), 400),
    fixed: title ? [title] : [], published: rel ? rel + " 12:00 UTC" : "", updated: rel ? rel + " 12:00 UTC" : "", source: "html" });
}

// ---------- Mozilla Foundation Security Advisories (HTML) ----------
export function parseMozillaIndex(html) {
  const out = []; let date = "";
  for (const m of String(html || "").matchAll(/<h2>([^<]+)<\/h2>|<a href="(\/en-US\/security\/advisories\/(mfsa\d{4}-\d+)\/)"><span class="level (\w+)">[^<]*<\/span>\s*([^<]+)<\/a>/g)) {
    if (m[1]) { date = iso(m[1] + " 12:00 UTC"); continue; }
    out.push({ id: m[3].toUpperCase().replace("MFSA", "MFSA "), url: "https://www.mozilla.org" + m[2], severity: m[4], title: txt(decode(m[5]), 200), published: date });
  }
  return out;
}
export function parseMozillaPage(html, it) {
  const sections = String(html || "").split(/<section class="cve">/).slice(1), cves = [], said = [], xc = new Set();
  for (const s of sections) {
    const c = (/<h4 id="(CVE-\d{4}-\d{4,})"/.exec(s) || [])[1]; if (!c) continue; cves.push(c);
    const e = exploitedSentences(plain(s.split("</section>")[0]).replace(/\n/g, " "));
    if (e.length) { xc.add(c); said.push(...e); }
  }
  const fixedIn = [...String((/<dt>Fixed in<\/dt>\s*<dd>([\s\S]*?)<\/dd>/.exec(html || "") || [])[1] || "").matchAll(/<li>([^<]+)<\/li>/g)].map((m) => decode(m[1]).trim());
  return advisory({ vendor: "Mozilla", vkey: "mozilla", id: it.id, title: it.title, url: it.url, cves, severity: (/<dt>Impact<\/dt>\s*<dd><span class="level (\w+)">/.exec(html || "") || [])[1] || it.severity,
    exploited: xc.size > 0, exploited_cves: [...xc], exploited_text: txt(said.join(" "), 400), fixed: fixedIn, published: it.published, updated: it.published, source: "html" });
}

// ---------- the store ----------
const CAP = { microsoft: 1500, redhat: 800 }, CAP_DEFAULT = 400, KEEP_DAYS = 3 * 365;
/** existing advisories + this run's -> the list to keep: newest per vendor up to its cap, every exploited one (3 years) */
export function merge(old, fresh, now = Date.now()) {
  const m = new Map();
  for (const a of old || []) if (a && a.vkey && a.id) m.set(a.vkey + "|" + a.id, a);
  for (const a of fresh || []) if (a) { const k = a.vkey + "|" + a.id, p = m.get(k); m.set(k, { ...a, first_seen: (p && p.first_seen) || a.first_seen || new Date(now).toISOString().replace(/\.\d+Z$/, "Z"), ...(p && p.exploited && !a.exploited ? { exploited: true, exploited_cves: p.exploited_cves, exploited_text: p.exploited_text } : {}) }); }
  const by = new Map();
  for (const a of m.values()) { if (!by.has(a.vkey)) by.set(a.vkey, []); by.get(a.vkey).push(a); }
  const out = [];
  for (const [k, list] of by) {
    list.sort((a, b) => String(b.updated).localeCompare(String(a.updated)) || String(b.id).localeCompare(String(a.id)));
    const cap = CAP[k] || CAP_DEFAULT;
    list.forEach((a, i) => { if (i < cap || (a.exploited && now - Date.parse(a.updated || a.published || 0) < KEEP_DAYS * 864e5)) out.push(a); });
  }
  return out.sort((a, b) => a.vkey.localeCompare(b.vkey) || String(b.updated).localeCompare(String(a.updated)) || String(b.id).localeCompare(String(a.id)));
}

/** the site's join on CVE: { CVE: [[vendor, id, url, severity, exploited text for this CVE or "", fixed (first two)]] } */
export function byCve(advs) {
  const m = {};
  for (const a of advs || []) {
    if (a.cves.length > 300) continue;   // a whole patch update's risk matrix (Oracle): too broad to say anything per CVE
    for (const c of a.cves) {
      const row = [a.vendor, a.id, a.url, a.severity || "", a.exploited_cves.includes(c) ? a.exploited_text : "", a.cves.length <= 3 ? a.fixed.slice(0, 2) : []];
      (m[c] ||= []).push(row);
    }
  }
  for (const c of Object.keys(m)) m[c] = m[c].sort((a, b) => (b[4] ? 1 : 0) - (a[4] ? 1 : 0)).slice(0, 4);
  return m;
}

// ---------- leads for the research loop ----------
export const WIDELY_USED = new Set(["microsoft", "cisco", "fortinet", "paloalto", "apple", "chrome", "mozilla", "oracle", "ivanti"]);
/** a vendor's own "exploited" statement (any vendor), or a critical advisory from a vendor whose products are widely used
 *  (the vendor rates it Critical and, where it gives a CVSS score, 9.0 or more; an Oracle Security Alert), published in the
 *  last week -> a lead; never an event. Microsoft rates dozens of flaws Critical every month at CVSS 7.5 to 8.8; the 9.0 bar
 *  keeps the leads to the ones a defender has to hear about. */
export function leadWorthy(a, now = Date.now()) {
  if (!a) return false;
  if (a.no_action || now - Date.parse(a.published || a.updated || 0) > 7 * 864e5) return false;
  return a.exploited || (WIDELY_USED.has(a.vkey) && ((a.severity === "Critical" && (a.cvss == null || a.cvss >= 9)) || (a.vkey === "oracle" && /Security Alert/i.test(a.title))));
}
export function toLead(a, seenAt) {
  const c = (a.exploited_cves.length ? a.exploited_cves : a.cves).slice(0, 3).join(", ");
  return {
    seen_at: seenAt, source: `${a.vendor} security advisory`, tier: "vendor", via: "psirt", kind: "advisory",
    title: txt(`${a.vendor}${a.exploited ? " says exploited in the wild" : a.severity ? ` (${a.severity})` : ""}: ${a.title}${c && !a.title.includes(c) ? " (" + c + ")" : ""}`, 200),
    url: a.url, published: a.published || seenAt, summary: txt(a.exploited ? a.exploited_text : `${a.vendor} advisory ${a.id}${a.cvss != null ? ", CVSS " + a.cvss : ""}; ${a.cves.length} CVE(s)`, 300),
    ...(a.exploited ? { exploited: true } : {}),
  };
}
