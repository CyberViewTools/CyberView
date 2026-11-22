// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// The site's own matching and rating code, loaded here unchanged so the scanner and the Vulnerabilities page cannot disagree:
//   site/workbench-lib.js  version comparison, affected ranges, product names, matchFlaw, the patch-queue points
//   site/cvedb-lib.js      the CVE lookup rows, the CyberView rating (score) and CISA's SSVC priority (rate)
// (scripts/cve.mjs loads cvedb-lib.js the same way.) The scanner therefore runs from a copy of the CyberView repository.
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// the repository root: scanner/lib/shared.mjs -> scanner/lib -> scanner -> root
const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));

function load(file, key) {
  const sb = { window: {} };
  vm.runInNewContext(readFileSync(join(ROOT, "site", file), "utf8"), sb, { filename: file });
  return sb.window[key];
}
export const W = load("workbench-lib.js", "CVWorkbench");
export const D = load("cvedb-lib.js", "CVDB");
