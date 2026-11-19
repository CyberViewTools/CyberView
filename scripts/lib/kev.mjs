// Which entries of CISA's known-exploited catalog scripts/feeds.mjs writes to data/kev/<CVE>.json. Pure; no network.
const CVE = /^CVE-\d{4}-\d{4,}$/;

/**
 * Entries to import: everything CISA added since `since` (YYYY-MM-DD), plus any older entry for a CVE that an event on
 * file names (onFile: Set of CVE ids). The second part closes the gap where an event cites a flaw CISA listed months ago:
 * the map and the workbench must still know it is known exploited. Files are never deleted, so the history only grows.
 */
export function kevToImport(vulns, since, onFile = new Set()) {
  return (Array.isArray(vulns) ? vulns : []).filter((v) => v && CVE.test(v.cveID || "") && ((v.dateAdded || "") >= since || onFile.has(v.cveID)));
}
