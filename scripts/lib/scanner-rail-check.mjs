// Section 7 of scripts/security-check.mjs, the scanner's HTTP path rail (scanner/lib/paths.mjs): the rules that keep it a
// small frozen table of reviewed literal paths, requested with GET only, at most 16 per host, and never a login,
// management or exploit-class path. Pure: the caller hands in the source texts and the loaded module; returns problems.

/** Paths the rail may never contain, whatever a review says (login, management, debug, search/admin APIs, RPC, secrets). */
export const FORBIDDEN_PATH = /login|signin|logon|\.cgi|actuator|heapdump|phpinfo|console|server-status|_cat|_search|_all_dbs|graphql|xmlrpc|soap|\.env/i;
/** A literal rail path: plain characters only (no query string, no traversal, no percent-encoding, no host). */
export const SAFE_PATH = /^(?:\/[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)*)+\/?$/;
export const MAX_PATHS_PER_HOST = 16;

/**
 * { pathsSrc, probeSrc, scanSrc, otherSrcs: [{ file, src }], mod } -> [problem strings]
 * mod: the imported scanner/lib/paths.mjs ({ RAIL, RAIL_PATHS, PATHS_PER_HOST }) or null when it could not be loaded.
 */
export function railProblems({ pathsSrc = "", probeSrc = "", scanSrc = "", otherSrcs = [], mod = null } = {}) {
  const P = [], F = "scanner/lib/paths.mjs";
  // (a) every path is a literal in a "paths: [ ... ]" array of plain double-quoted strings; nothing computed
  const uses = (pathsSrc.match(/\bpaths\s*:/g) || []).length, literals = [];
  let arrays = 0;
  for (const m of pathsSrc.matchAll(/\bpaths\s*:\s*\[([^\]]*)\]/g)) {
    arrays++;
    for (const el of m[1].split(",").map((x) => x.trim()).filter(Boolean)) {
      const q = /^"([^"\\`$]*)"$/.exec(el);
      if (!q) { P.push(`${F}: a rail path is not a plain string literal (${el.slice(0, 60)}); paths must be literals, never built from data`); continue; }
      literals.push(q[1]);
    }
  }
  if (uses !== arrays) P.push(`${F}: every "paths:" must be a literal array of strings (${uses} found, ${arrays} literal)`);
  if (!literals.length) P.push(`${F}: no literal rail paths found`);
  // any other string literal that looks like a path is checked too, so a path cannot be smuggled in elsewhere in the file
  const stray = [...pathsSrc.matchAll(/"(\/[^"\s()[\]{}|\\^$*+]{1,200})"/g)].map((m) => m[1]);
  for (const p of new Set([...literals, ...stray])) {
    if (!SAFE_PATH.test(p)) P.push(`${F}: "${p.slice(0, 80)}" is not a plain literal path (no query, traversal, encoding or host)`);
    // (d) never a login, management or exploit-class path
    if (FORBIDDEN_PATH.test(p)) P.push(`${F}: "${p.slice(0, 80)}" is a login, management or exploit-class path; the rail may never request it`);
  }
  // (b) GET only: the rail table names no method; probe.mjs sends nothing but GET
  if (/\bmethod\s*:|["'](POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)["']/i.test(pathsSrc)) P.push(`${F}: names an HTTP method; the rail is GET only (method lives in probe.mjs)`);
  const methods = [...probeSrc.matchAll(/\bmethod\s*:\s*([^,}\s]+)/g)].map((m) => m[1]);
  if (!methods.length || methods.some((m) => !/^["']GET["']$/.test(m))) P.push(`scanner/lib/probe.mjs: every request must be method "GET" (found ${methods.join(", ") || "none"})`);
  // (a) the network layer refuses any path that is not in the frozen table, before connecting; the request path is the
  //     root or a frozen literal, never anything else
  if (!/import\s*\{[^}]*\bRAIL_PATHS\b[^}]*\}\s*from\s*["']\.\/paths\.mjs["']/.test(probeSrc)) P.push("scanner/lib/probe.mjs: must import RAIL_PATHS from ./paths.mjs");
  if (!/export async function getPath\(ip, port, path\b[^)]*\)\s*\{\s*if \(typeof path !== "string" \|\| !RAIL_PATHS\.includes\(path\)\) return\b/.test(probeSrc))
    P.push("scanner/lib/probe.mjs: getPath must first refuse any path that is not in RAIL_PATHS (the frozen table)");
  const reqPaths = [...probeSrc.matchAll(/\bpath\s*:\s*([^,}]+)/g)].map((m) => m[1].trim());
  if (reqPaths.length !== 1 || reqPaths[0] !== 'railPath && RAIL_PATHS.includes(railPath) ? railPath : "/"') P.push(`scanner/lib/probe.mjs: the request path must be "/" or a RAIL_PATHS literal (found ${reqPaths.join(" | ") || "none"})`);
  // scan.mjs is the only caller, and only with a planned item's path (from railPlan over the frozen table)
  const calls = [...scanSrc.matchAll(/\bgetPath\(([^)]{0,120})/g)].map((m) => m[1]);
  if (calls.some((c) => !/^h\.address, item\.port, item\.path,/.test(c))) P.push("scanner/lib/scan.mjs: getPath may only be called with a planned rail item's frozen path (item.path from railPlan)");
  for (const { file, src } of otherSrcs) if (/\bgetPath\b/.test(src)) P.push(`${file}: only scanner/lib/scan.mjs may call the path rail (getPath)`);
  // (c) the per-host cap
  const cap = Number((/export const PATHS_PER_HOST\s*=\s*(\d+)\s*;/.exec(pathsSrc) || [])[1]);
  if (!(cap >= 1 && cap <= MAX_PATHS_PER_HOST)) P.push(`${F}: PATHS_PER_HOST must be a literal from 1 to ${MAX_PATHS_PER_HOST} (found ${Number.isFinite(cap) ? cap : "none"})`);
  // the loaded table must be exactly the literals in the source, frozen, within the cap
  if (mod) {
    const rp = Array.isArray(mod.RAIL_PATHS) ? mod.RAIL_PATHS : [];
    if (!Object.isFrozen(mod.RAIL) || !Object.isFrozen(mod.RAIL_PATHS) || (mod.RAIL || []).some((e) => !Object.isFrozen(e) || !Object.isFrozen(e.paths))) P.push(`${F}: RAIL, its entries, their paths and RAIL_PATHS must be frozen`);
    const lit = new Set(literals);
    for (const p of rp) {
      if (typeof p !== "string" || !lit.has(p)) P.push(`${F}: RAIL_PATHS holds "${String(p).slice(0, 80)}", which is not a literal in the source`);
      else if (FORBIDDEN_PATH.test(p) || !SAFE_PATH.test(p)) P.push(`${F}: RAIL_PATHS holds a forbidden path "${p.slice(0, 80)}"`);
    }
    if (!(mod.PATHS_PER_HOST >= 1 && mod.PATHS_PER_HOST <= MAX_PATHS_PER_HOST)) P.push(`${F}: PATHS_PER_HOST ${mod.PATHS_PER_HOST} is above ${MAX_PATHS_PER_HOST}`);
  }
  return P;
}
