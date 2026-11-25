// Distribution fix data (Debian, Ubuntu): did the distribution already fix a CVE in the package build this computer has?
// A Linux distribution usually fixes a flaw by patching its own build, without changing the upstream version number, so an
// upstream range ("OpenSSH before 9.8") cannot answer it. The distribution's own record can: for each release and source
// package, the build that fixed each CVE (scripts/distro.mjs reduces OSV's Debian and Ubuntu records into these files).
//
// data/distro/index.json            { built_at, releases: { "ubuntu-22.04": { file, cves, packages } } }
// data/distro/<distro>-<release>.json { distro, release, built_at, src: { "<source package>": [["CVE-...", "<fixed build>" or ""], ...] } }
//   "" = the distribution lists the package as affected and has not released a fix.

/* ---- Debian version comparison (deb-version(7), as dpkg --compare-versions) ---- */
const order = (c) => (c === "~" ? -1 : /\d/.test(c) ? 0 : !c ? 0 : /[A-Za-z]/.test(c) ? c.charCodeAt(0) : c.charCodeAt(0) + 256);
function cmpPart(a, b) {
  let i = 0, j = 0;
  while (i < a.length || j < b.length) {
    let first = 0;
    while ((i < a.length && !/\d/.test(a[i])) || (j < b.length && !/\d/.test(b[j]))) {
      const ac = order(a[i]), bc = order(b[j]);
      if (ac !== bc) return ac < bc ? -1 : 1;
      i++; j++;
    }
    while (a[i] === "0") i++;
    while (b[j] === "0") j++;
    while (i < a.length && /\d/.test(a[i]) && j < b.length && /\d/.test(b[j])) { if (!first) first = a.charCodeAt(i) - b.charCodeAt(j); i++; j++; }
    if (i < a.length && /\d/.test(a[i])) return 1;
    if (j < b.length && /\d/.test(b[j])) return -1;
    if (first) return first < 0 ? -1 : 1;
  }
  return 0;
}
const split = (v) => { v = String(v || "").trim(); const c = v.indexOf(":"); const epoch = c > 0 && /^\d+$/.test(v.slice(0, c)) ? +v.slice(0, c) : 0; const rest = c > 0 ? v.slice(c + 1) : v; const d = rest.lastIndexOf("-"); return [epoch, d > 0 ? rest.slice(0, d) : rest, d > 0 ? rest.slice(d + 1) : ""]; };
/** -1, 0 or 1, as dpkg --compare-versions */
export function debCompare(a, b) {
  const [ea, ua, ra] = split(a), [eb, ub, rb] = split(b);
  if (ea !== eb) return ea < eb ? -1 : 1;
  return cmpPart(ua, ub) || cmpPart(ra, rb);
}

/* ---- the operating system a package list came from ---- */
const DISTROS = { ubuntu: "ubuntu", debian: "debian" };
/** "#os ubuntu 22.04 jammy" (written by the signed-in check) -> "ubuntu-22.04"; Debian keeps its major version */
export function releaseKey(id, versionId) {
  const d = DISTROS[String(id || "").toLowerCase()]; if (!d) return "";
  const v = String(versionId || "").trim(); if (!/^\d+(\.\d+)?$/.test(v)) return "";
  return d === "debian" ? `debian-${v.split(".")[0]}` : `ubuntu-${v}`;
}
/** OSV ecosystem -> release key ("Ubuntu:22.04:LTS" -> "ubuntu-22.04", "Debian:12" -> "debian-12"); Ubuntu Pro/ESM records are kept apart */
export function ecosystemKey(eco) {
  const p = String(eco || "").split(":");
  if (p[0] === "Debian" && /^\d+$/.test(p[1] || "")) return `debian-${p[1]}`;
  if (p[0] === "Ubuntu" && p[1] === "Pro") return /^\d+\.\d+$/.test(p[2] || "") ? `ubuntu-pro-${p[2]}` : "";
  if (p[0] === "Ubuntu" && /^\d+\.\d+$/.test(p[1] || "")) return `ubuntu-${p[1]}`;
  return "";
}

/* ---- OSV records -> per-release files (used by scripts/distro.mjs; kept here so the reducer and the reader share one shape) ---- */
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
export function cvesOf(rec) {
  const ids = [rec && rec.id, ...((rec && rec.aliases) || []), ...((rec && rec.upstream) || [])].map((x) => String(x || "").replace(/^(UBUNTU|DEBIAN)-/, ""));
  return [...new Set(ids.filter((x) => CVE_RE.test(x)))];
}
/** add one OSV record to acc: { "<release>": { "<src>": Map(cve -> fixed) } } */
export function addOsv(acc, rec) {
  const cves = cvesOf(rec); if (!cves.length || rec.withdrawn) return;
  for (const a of rec.affected || []) {
    const key = ecosystemKey(a && a.package && a.package.ecosystem), src = String((a && a.package && a.package.name) || "").trim();
    if (!key || !/^[a-z0-9][a-z0-9+.-]{0,100}$/.test(src)) continue;
    let fixed = "", ranged = false;
    for (const r of a.ranges || []) { if (r.type !== "ECOSYSTEM") continue; ranged = true; for (const e of r.events || []) if (e.fixed && (!fixed || debCompare(e.fixed, fixed) > 0)) fixed = String(e.fixed); }
    if (!ranged && !(a.versions || []).length) continue;
    const rel = (acc[key] = acc[key] || {}), m = (rel[src] = rel[src] || new Map());
    for (const c of cves) { const had = m.get(c); if (had === undefined || (fixed && (!had || debCompare(fixed, had) > 0))) m.set(c, fixed); }
  }
}
export function releaseFiles(acc, builtAt) {
  const index = { built_at: builtAt, source: "OSV (Debian and Ubuntu security records)", releases: {} }, files = {};
  for (const [key, rel] of Object.entries(acc).sort()) {
    const src = {}; let n = 0;
    for (const [p, m] of Object.entries(rel).sort()) { src[p] = [...m].sort().map(([c, f]) => [c, f]); n += m.size; }
    const [distro, ...r] = key.split("-");
    files[`${key}.json`] = { distro, release: r.join("-"), built_at: builtAt, src };
    index.releases[key] = { file: `${key}.json`, packages: Object.keys(src).length, entries: n };
  }
  return { index, files };
}

/* ---- the verdict for one installed package build and one CVE ---- */
/**
 * rel: a release file; item: { src or name, raw_version }. ->
 *   { state: "fixed", fixed } the build on this computer has the distribution's fix
 *   { state: "affected", fixed } an older build: the fix exists in `fixed`
 *   { state: "no-fix" } the distribution lists it as affected and has no fix yet
 *   null — the distribution's record does not mention this package and CVE (the upstream answer stands)
 */
export function verdict(rel, item, cve) {
  if (!rel || !rel.src || !item || !item.raw_version) return null;
  for (const p of [item.src, item.name].filter(Boolean)) {
    const list = rel.src[p]; if (!Array.isArray(list)) continue;
    const e = list.find((x) => x[0] === cve); if (!e) continue;
    if (!e[1]) return { state: "no-fix", pkg: p };
    return debCompare(item.raw_version, e[1]) >= 0 ? { state: "fixed", fixed: e[1], pkg: p } : { state: "affected", fixed: e[1], pkg: p };
  }
  return null;
}
