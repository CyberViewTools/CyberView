// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// The bounded HTTP path rail (scan-http-paths). Frozen literal paths only. A host is offered a path
// only when a hint from the root page, a header, or --well-known says so. Cap 8 per host.
// Nothing here is a wordlist, a login, a management API, or a debug/secret path.
// Status-style paths are recorded by status code; their bodies are discarded by the probe.

export const PATH_CAP = 8;
export const PATH_SEND = "up to 8 extra requests (method GET) of frozen hint-gated paths; a host with no hint is not asked; status-page bodies are discarded";

/** hint: which already-collected signal selects this path. group well-known waits for --well-known. */
export const PATH_RAIL = Object.freeze([
  { id: "nginx-stub", path: "/nginx_status", hint: "nginx", keep: "status" },
  { id: "nginx-stub-alt", path: "/stub_status", hint: "nginx", keep: "status" },
  { id: "apache-status", path: "/server-status", hint: "apache", keep: "status" },
  { id: "apache-info", path: "/server-info", hint: "apache", keep: "status" },
  // Spring Boot's health document only. /actuator/env and heapdump are not on this list.
  // https://docs.spring.io/spring-boot/reference/actuator/endpoints.html
  { id: "spring-health", path: "/actuator/health", hint: "spring", keep: "status" },
  { id: "robots", path: "/robots.txt", hint: "well-known", keep: "text" },
  { id: "security-txt", path: "/.well-known/security.txt", hint: "well-known", keep: "text" },
  { id: "sitemap", path: "/sitemap.xml", hint: "well-known", keep: "status" },
  // one file, no object walk. A body is kept only when it is a git HEAD line.
  { id: "git-head", path: "/.git/HEAD", hint: "well-known", keep: "git" },
  { id: "svn-entries", path: "/.svn/entries", hint: "well-known", keep: "status" },
]);

const BY_PATH = new Map(PATH_RAIL.map((p) => [p.path, p]));
export const isRailPath = (path) => BY_PATH.has(path);
export const railEntry = (path) => BY_PATH.get(path) || null;

function header(headers, name) {
  if (!headers || typeof headers !== "object") return "";
  const v = headers[name] ?? headers[name.toLowerCase()];
  return String(Array.isArray(v) ? v[0] : v || "").slice(0, 300);
}

/** Hints from the one root response. No network. */
export function hintsFrom(http) {
  const h = (http && http.headers) || {};
  const server = header(h, "server");
  const powered = header(h, "x-powered-by");
  const app = header(h, "x-application-context");
  const set = new Set();
  if (/nginx/i.test(server)) set.add("nginx");
  if (/apache/i.test(server) && !/coyote/i.test(server)) set.add("apache");
  if (app || /spring/i.test(powered)) set.add("spring");
  return set;
}

/**
 * Paths to request for one host. wellKnown adds the published well-known group.
 * Returns at most PATH_CAP entries, each from PATH_RAIL.
 */
export function selectPaths(http, { wellKnown = false } = {}) {
  const hints = hintsFrom(http);
  if (wellKnown) hints.add("well-known");
  const out = [];
  for (const row of PATH_RAIL) {
    if (out.length >= PATH_CAP) break;
    if (hints.has(row.hint)) out.push(row);
  }
  return out;
}

/** What a rail response is allowed to contribute. Bodies of status paths are dropped. */
export function railEvidence(entry, http) {
  if (!entry || !http) return null;
  const status = Number(http.status) || 0;
  if (status < 200 || status >= 300) return { id: entry.id, path: entry.path, status, present: false, text: "" };
  if (entry.keep === "text") return { id: entry.id, path: entry.path, status, present: true, text: String(http.body || "").replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").slice(0, 500) };
  if (entry.keep === "git") {
    const line = String(http.body || "").split(/\r?\n/)[0].slice(0, 80);
    const ok = /^ref:\s+\S+$/.test(line);
    return { id: entry.id, path: entry.path, status, present: ok, text: ok ? line : "" };
  }
  return { id: entry.id, path: entry.path, status, present: true, text: "" };
}
