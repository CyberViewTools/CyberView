// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// The bounded HTTP path rail (scan-http-paths). OFF by default; on only with --paths.
//
// A FROZEN TABLE, not a wordlist: each entry is one reviewed catalog id, the literal path(s) it may request, a hint over
// evidence the scan ALREADY collected on that port (the root page's title, headers, cookie NAMES, body markers, a recorded
// redirect Location, the TLS certificate, the port number) and a parser that keeps at most a product and version token.
// A host whose own evidence matches no hint gets nothing beyond the root page request. Every request is a GET from scanner/lib/probe.mjs
// (getPath), which refuses any path not in RAIL_PATHS, goes through the Limiter and its budgets, records redirects without
// following them, and caps the body; only the parsed token is kept, never the body.
// No logins, no management or exploit-class paths, no operator-supplied URLs (scripts/security-check.mjs section 7).
// Pure: no network here.
import { cleanVersion } from "./fingerprint.mjs";

/** Extra GETs per host, all ports together. A hard cap: settings may lower it (--paths-per-host), never raise it. */
export const PATHS_PER_HOST = 8;

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ").slice(0, n);
const core = (v) => (/^\d+(?:\.\d+)*/.exec(v) || [""])[0];

/* ---- hint helpers: tests over one port's already-collected evidence (see railEvidence) ---- */
const T = (re) => (ev) => re.test(ev.title);
const B = (re) => (ev) => re.test(ev.body);
const L = (re) => (ev) => re.test(ev.location);
const S = (re) => (ev) => re.test(ev.server);
const R = (re) => (ev) => re.test(ev.realm);
const G = (re) => (ev) => re.test(ev.generator) || re.test(ev.headers["x-generator"] || "");
const HN = (re) => (ev) => Object.keys(ev.headers).some((k) => re.test(k));
const CK = (re) => (ev) => ev.cookies.some((c) => re.test(c));
const CERT = (re) => (ev) => re.test(ev.cert);
const P = (...ports) => (ev) => ports.includes(ev.port);
const any = (...fs) => (ev) => fs.some((f) => f(ev));
const all = (...fs) => (ev) => fs.every((f) => f(ev));
const WP = any(G(/^WordPress/i), B(/\/wp-content\/|\/wp-includes\//));
const NETGEAR = any(T(/NETGEAR/i), R(/NETGEAR/i));

/* ---- parse helpers: a response context { status, headers, body, raw, json() } -> one token or null ---- */
const tok = (vendor, product, version, extra = {}) => ({ vendor, product, version: clip(version, 60), guessed: !!extra.guessed || !cleanVersion(version), ...(extra.matchVersion !== undefined ? { matchVersion: extra.matchVersion } : {}), evidence: clip(extra.evidence || "", 160) });
const J = (c) => { const j = c.json(); return j && typeof j === "object" && !Array.isArray(j) ? j : null; };
const str = (v) => (typeof v === "string" || typeof v === "number" ? String(v) : "");
const jsonVersion = (vendor, product, need = []) => (path, c) => {
  const j = J(c); if (!j || !need.every((k) => k in j)) return null;
  const v = str(j.version); return v ? tok(vendor, product, v, { evidence: `"version": "${clip(v, 40)}"` }) : null;
};
const stableTag = (vendor, product) => (path, c) => {
  const m = /Stable tag:\s*([\w.]+)/i.exec(c.body);
  return m ? tok(vendor, product, m[1], { evidence: `Stable tag: ${m[1]}` }) : null;
};
const kubeVersion = (path, c) => {
  const j = J(c); const g = j ? str(j.gitVersion) : "";
  return j && "major" in j && /^v?\d+\.\d+/.test(g) ? tok("Kubernetes", "Kubernetes", g.replace(/^v/, "").replace(/\+.*$/, ""), { evidence: `gitVersion: ${clip(g, 40)}` }) : null;
};
const currentSetting = (want) => (path, c) => {
  if (!/^\s*Firmware=/m.test(c.body) && !/^\s*Model=/m.test(c.body)) return null;
  const model = clip((/^\s*Model=([^\r\n]{1,40})/m.exec(c.body) || [])[1], 40).trim(), fw = clip((/^\s*Firmware=([^\r\n]{1,40})/m.exec(c.body) || [])[1], 40).trim();
  if (!model || (want && !want.test(model))) return null;
  return tok("NETGEAR", `${model} Firmware`, fw.replace(/^V(?=\d)/i, ""), { evidence: `Model=${model}${fw ? ` Firmware=${fw}` : ""}` });
};
const isStatus200 = (c) => c.status === 200;

/** murmur3 x86 32-bit (seed 0), signed, over a byte buffer: the favicon hash convention (base64 with newlines, as Python's
 *  base64.encodebytes). Used only to compare with a published hash; the icon itself is never kept. */
export function mmh3(buf) {
  const n = buf.length, nb = n & ~3, c1 = 0xcc9e2d51, c2 = 0x1b873593; let h = 0, k = 0;
  for (let i = 0; i < nb; i += 4) {
    k = buf[i] | (buf[i + 1] << 8) | (buf[i + 2] << 16) | (buf[i + 3] << 24);
    k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2);
    h ^= k; h = (h << 13) | (h >>> 19); h = (Math.imul(h, 5) + 0xe6546b64) | 0;
  }
  k = 0;
  const tail = n & 3;
  if (tail === 3) k ^= buf[nb + 2] << 16;
  if (tail >= 2) k ^= buf[nb + 1] << 8;
  if (tail >= 1) { k ^= buf[nb]; k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2); h ^= k; }
  h ^= n; h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
  return h | 0;
}
export const faviconHash = (raw) => mmh3(Buffer.from((Buffer.from(raw).toString("base64").match(/.{1,76}/g) || []).map((l) => l + "\n").join(""), "latin1"));

/**
 * THE FROZEN TABLE (reviewed in Design: 50 catalog rows, 39 distinct paths; one more row on an existing path by the lead, 2026-11-22). Every path is a literal; adding one needs a new
 * Design review, and section 7 of scripts/security-check.mjs refuses login, management and exploit-class paths.
 * group "bmc": baseboard management controllers stay opt-in even with --paths (--paths-bmc).
 * hint null: no reviewed marker, so the entry is never requested.
 */
export const RAIL = Object.freeze([
  { id: "apache-airflow", paths: ["/api/v1/version"], hint: any(T(/\bAirflow\b/i), L(/airflow/i)),
    parse: (p, c) => { const j = J(c); return j && "git_version" in j ? jsonVersion("Apache", "Airflow")(p, c) : null; } },
  { id: "apache-flink", paths: ["/config"], hint: any(T(/Apache Flink Web Dashboard/i), all(P(8081), B(/flink-logo\.png|alt="apache flink dashboard"/i))),
    parse: (p, c) => { const j = J(c); const v = j ? str(j["flink-version"]) : ""; return v ? tok("Apache", "Flink", v, { evidence: `flink-version: ${v}${j["flink-revision"] ? ` (${clip(j["flink-revision"], 40)})` : ""}` }) : null; } },
  { id: "apache-tomcat-version-path", paths: ["/docs"], hint: any(S(/Apache-Coyote/i), B(/Apache Tomcat\/\d/i)),
    parse: (p, c) => { const m = /<title>\s*Apache Tomcat \d+[^<(]*\((\d+\.\d+\.\d+)\)/i.exec(c.body) || /\bVersion (\d+\.\d+\.\d+),/.exec(c.body); return m ? tok("Apache", "Tomcat", m[1], { evidence: `documentation index: ${m[1]}` }) : null; } },
  { id: "berriai-litellm", paths: ["/health/liveliness"], hint: any(T(/LiteLLM API - Swagger UI/i), P(4000)),
    parse: (p, c) => (/I'm alive!/.test(c.body) ? tok("BerriAI", "LiteLLM", "", { evidence: "liveliness: I'm alive!" }) : null) },
  { id: "chroma", paths: ["/api/v1/heartbeat"], hint: any(B(/\bchroma(?:db)?\b/i), S(/chroma/i)),
    parse: (p, c) => { const j = J(c); const k = j && Object.keys(j).find((x) => /heartbeat/i.test(x)); return k && typeof j[k] === "number" ? tok("Chroma", "Chroma", "", { evidence: `heartbeat document (${clip(k, 40)})` }) : null; } },
  { id: "collabora-collabora-online-built-in-code-server", paths: ["/hosting/capabilities"], hint: any(P(9980), T(/Collabora/i), S(/Collabora/i)),
    parse: (p, c) => { const j = J(c); const n = j ? str(j.productName) : "", v = j ? str(j.productVersion) : ""; return n && /collabora/i.test(n) ? tok("Collabora", "Collabora Online", v, { evidence: `${clip(n, 60)} ${clip(v, 30)}` }) : null; } },
  { id: "docker-engine-api", paths: ["/version"], hint: P(2375, 2376),
    parse: (p, c) => { const j = J(c); return j && "ApiVersion" in j && str(j.Version) ? tok("Docker", "Docker Engine", str(j.Version), { evidence: `Version ${clip(j.Version, 30)}, API ${clip(j.ApiVersion, 10)}` }) : null; } },
  { id: "etcd-version", paths: ["/version"], hint: P(2379),
    parse: (p, c) => { const j = J(c); const v = j ? str(j.etcdserver) : ""; return v ? tok("etcd", "etcd", v, { evidence: `etcdserver ${v}` }) : null; } },
  { id: "gitea", paths: ["/api/v1/version"], hint: any(B(/\bGitea\b/), CK(/^i_like_gitea$/)),
    parse: (p, c) => { const j = J(c); return j && Object.keys(j).length === 1 ? jsonVersion("Gitea", "Gitea")(p, c) : null; } },
  { id: "gpustack-gpustack", paths: ["/version"], hint: T(/^GPUStack$/),
    parse: (p, c) => { const j = J(c); return j && "git_commit" in j ? jsonVersion("GPUStack", "GPUStack")(p, c) : null; } },
  { id: "grafana-login-or-health-path", paths: ["/api/health"], hint: any(T(/Grafana/i), L(/grafana/i)),
    parse: (p, c) => { const j = J(c); return j && "database" in j ? jsonVersion("Grafana", "Grafana")(p, c) : null; } },
  { id: "hashicorp-vault", paths: ["/v1/sys/health"], hint: any(L(/^\/ui\/?$/), T(/\bVault\b/), B(/\bvault-ui\b|HashiCorp Vault/i)),
    parse: (p, c) => { const j = J(c); return j && "sealed" in j && "initialized" in j ? jsonVersion("HashiCorp", "Vault")(p, c) : null; } },
  { id: "ibm-langflow", paths: ["/api/v1/version"], hint: any(T(/^Langflow$/i), P(7860)),
    parse: (p, c) => { const j = J(c); if (!j || !("main_version" in j || /langflow/i.test(str(j.package)))) return null; const v = str(j.version) || str(j.main_version); return v ? tok("Langflow", "Langflow", v, { evidence: `version ${clip(v, 30)}` }) : null; } },
  { id: "jfrog-artifactory", paths: ["/artifactory/api/system/version"], hint: any(L(/artifactory/i), HN(/^x-artifactory-|^x-jfrog-version$/), T(/Artifactory/i)),
    parse: (p, c) => { const j = J(c); return j && "revision" in j ? jsonVersion("JFrog", "Artifactory")(p, c) : null; } },
  { id: "kibana-login-or-status-path", paths: ["/api/status"], hint: any(L(/kibana|spaces\/enter/i), HN(/^kbn-name$|^kbn-license-sig$/)),
    parse: (p, c) => { const j = J(c); const v = j && j.version && typeof j.version === "object" ? str(j.version.number) : ""; return v ? tok("Elastic", "Kibana", v, { evidence: `version.number ${v}` }) : null; } },
  { id: "kubernetes-api-version", paths: ["/version"], hint: any(CERT(/CN=kube-apiserver\b|kubernetes\.default/i), P(6443)), parse: kubeVersion },
  { id: "kubernetes-insecure-api-port", paths: ["/version"], hint: all(P(8080), B(/"paths"\s*:\s*\[[^\]]*"\/api"/)), parse: kubeVersion },
  { id: "minio", paths: ["/minio/health/live"], hint: S(/MinIO/i),
    parse: (p, c) => (/MinIO/i.test(str(c.headers.server)) ? tok("MinIO", "MinIO", "", { evidence: `health live ${c.status}, Server: ${clip(c.headers.server, 40)}` }) : null) },
  { id: "mlflow-mlflow", paths: ["/health", "/version"], hint: T(/MLflow/i),
    parse: (p, c) => { const t = c.body.trim(); if (p === "/health") return t === "OK" ? tok("MLflow", "MLflow", "", { evidence: "health: OK" }) : null; return /^\d+\.\d+(?:\.\d+)*$/.test(t) && t.length < 30 ? tok("MLflow", "MLflow", t, { evidence: `version ${t}` }) : null; } },
  { id: "nextcloud", paths: ["/status.php"], hint: any(B(/Nextcloud/i), T(/Nextcloud/i), HN(/^x-nextcloud-/)),
    parse: (p, c) => { const j = J(c); return j && /nextcloud/i.test(str(j.productname)) ? tok("Nextcloud", "Nextcloud Server", str(j.versionstring) || str(j.version), { evidence: `status.php ${clip(j.versionstring || j.version, 30)}` }) : null; } },
  { id: "ollama", paths: ["/api/version"], hint: any(B(/^Ollama is running/), P(11434)),
    parse: (p, c) => { const j = J(c); return j && Object.keys(j).length === 1 ? jsonVersion("Ollama", "Ollama")(p, c) : null; } },
  { id: "openshift-console-or-api", paths: ["/version"], hint: CERT(/openshift/i),
    parse: (p, c) => { const k = kubeVersion(p, c); return k ? tok("Red Hat", "OpenShift Container Platform", "", { guessed: true, evidence: `API /version ${k.evidence} (the Kubernetes version, not the OpenShift release)` }) : null; } },
  { id: "owncloud", paths: ["/status.php"], hint: any(B(/ownCloud/), T(/ownCloud/)),
    parse: (p, c) => { const j = J(c); return j && /^owncloud$/i.test(str(j.productname)) ? tok("ownCloud", "ownCloud Server", str(j.versionstring) || str(j.version), { evidence: `status.php ${clip(j.versionstring || j.version, 30)}` }) : null; } },
  { id: "plex-media-server", paths: ["/identity"], hint: any(HN(/^x-plex-/), T(/\bPlex\b/)),
    parse: (p, c) => { const m = /<MediaContainer\b[^>]*\bversion="([^"]{1,60})"/.exec(c.body); return m ? tok("Plex", "Plex Media Server", m[1].replace(/-.*$/, ""), { evidence: `identity version ${clip(m[1], 40)}` }) : null; } },
  { id: "portainer", paths: ["/api/system/status"], hint: any(T(/Portainer/i), B(/Portainer/)),
    parse: (p, c) => { const j = J(c); const v = j ? str(j.Version) : ""; return v ? tok("Portainer", "Portainer", v, { evidence: `Version ${clip(v, 30)}` }) : null; } },
  { id: "prometheus-ui-or-api", paths: ["/-/ready", "/api/v1/status/buildinfo"], hint: any(T(/Prometheus/), all(P(9090), L(/^\/(graph|query)\b/))),
    parse: (p, c) => { if (p === "/-/ready") return /Prometheus.*Ready/i.test(c.body) ? tok("Prometheus", "Prometheus", "", { evidence: "ready" }) : null;
      const j = J(c); const v = j && j.data && typeof j.data === "object" ? str(j.data.version) : ""; return v ? tok("Prometheus", "Prometheus", v, { evidence: `buildinfo ${v}` }) : null; } },
  { id: "qlik-sense", paths: ["/resources/autogenerated/product-info.json"], hint: any(T(/Qlik-Sense/i), B(/qlik-logo|alt="Qlik[ .]Sense"|qliksenseserver/i)),
    // the server build token is not the release name NVD's ranges use, so it is shown and never compared
    parse: (p, c) => { const m = /qliksenseserver:(\d+\.\d+\.\d+)/i.exec(c.body); return m ? tok("Qlik", "Qlik Sense", m[1], { guessed: true, matchVersion: "", evidence: `qliksenseserver:${m[1]} (server build, not the release name)` }) : null; } },
  { id: "qnap-photo-station", paths: ["/photo/"], hint: any(T(/QNAP/i), CERT(/QNAP/i)),
    parse: (p, c) => { const m = /<title>([^<]{0,80}Photo Station[^<]{0,40})<\/title>/i.exec(c.body); return m ? tok("QNAP", "Photo Station", "", { evidence: `title: ${clip(m[1], 80)}` }) : null; } },
  { id: "sonatype-nexus-repository", paths: ["/service/rest/v1/status"], hint: any(T(/Nexus Repository/i), B(/Sonatype Nexus/i)),
    parse: (p, c) => { const m = /^Nexus\/(\d[\w.\-]*)/i.exec(str(c.headers.server)); return tok("Sonatype", "Nexus Repository Manager", m ? m[1].replace(/-.*$/, "") : "", { evidence: `status ${c.status}${m ? `, Server: Nexus/${m[1]}` : ""}` }); } },
  { id: "weaviate", paths: ["/v1/meta"], hint: B(/weaviate/i),
    parse: (p, c) => { const j = J(c); return j && ("modules" in j || "hostname" in j) ? jsonVersion("Weaviate", "Weaviate")(p, c) : null; } },
  { id: "adobe-magento-commerce", paths: ["/magento_version"], hint: any(HN(/^x-magento-/), CK(/^mage-/)),
    // only the major.minor line is stated (e.g. "Magento/2.4 (Community)"): shown, never compared with patch-level ranges
    parse: (p, c) => { const m = /^Magento\/(\d+\.\d+)\s*(\([^)]{1,30}\))?/.exec(c.body.trim()); return m ? tok("Adobe", "Magento", m[1], { guessed: true, matchVersion: "", evidence: `Magento/${m[1]} ${m[2] || ""}`.trim() }) : null; } },
  { id: "drupal-core", paths: ["/CHANGELOG.txt"], hint: G(/^Drupal/i),
    parse: (p, c) => { const m = /^\s*Drupal (\d+\.\d+(?:\.\d+)?),/m.exec(c.body); return m ? tok("Drupal", "Drupal", m[1], { evidence: `CHANGELOG: Drupal ${m[1]}` }) : null; } },
  { id: "sitecore-xp", paths: ["/sitecore/shell/sitecore.version.xml"], hint: any(CK(/^(SC_ANALYTICS_GLOBAL_COOKIE|SC_OS_SessionId|sxa_site)$/), B(/\/_sitecore\//)),
    parse: (p, c) => { if (!/Sitecore Corporation/.test(c.body)) return null; const x = (k) => (new RegExp(`<${k}>\\s*(\\d{1,6})\\s*</${k}>`).exec(c.body) || [])[1];
      const ma = x("major"), mi = x("minor"), bu = x("build"), re = x("revision"); if (!ma || !mi) return null;
      return tok("Sitecore", "Experience Platform", [ma, mi, bu].filter((v) => v !== undefined).join("."), { evidence: `version.xml ${ma}.${mi}${bu !== undefined ? "." + bu : ""}${re ? ` rev. ${re}` : ""}` }); } },
  { id: "wordpress-core", paths: ["/readme.html"], hint: WP,
    parse: (p, c) => { if (!/WordPress/.test(c.body)) return null; const m = /\bVersion (\d+\.\d+(?:\.\d+)?)/.exec(c.body); return m ? tok("WordPress", "WordPress", m[1], { evidence: `readme.html Version ${m[1]}` }) : null; } },
  { id: "wordpress-file-manager-plugin", paths: ["/wp-content/plugins/wp-file-manager/readme.txt"], hint: WP, parse: stableTag("webdesi9", "File Manager (WordPress plugin)") },
  { id: "wordpress-snap-creek-duplicator-plugin", paths: ["/wp-content/plugins/duplicator/readme.txt"], hint: WP, parse: stableTag("Snap Creek", "Duplicator (WordPress plugin)") },
  { id: "wordpress-social-warfare-plugin", paths: ["/wp-content/plugins/social-warfare/readme.txt"], hint: WP, parse: stableTag("Warfare Plugins", "Social Warfare (WordPress plugin)") },
  { id: "lantronix-eds5000", paths: ["/LTX_navi.html"], hint: any(T(/^Lantronix WEB-Manager$/i), S(/Gordian Embedded/i)),
    parse: (p, c) => { if (!/EDS ?5000/i.test(c.body)) return null; const m = />Version (\d+(?:\.\d+)+)<\/font>/i.exec(c.body); return tok("Lantronix", "EDS5000 Firmware", m ? m[1] : "", { evidence: `EDS5000${m ? ` Version ${m[1]}` : ""}` }); } },
  { id: "netgear-dgn2200-devices", paths: ["/currentsetting.htm"], hint: any(T(/DGN2200/i), R(/DGN2200/i)), parse: currentSetting(/DGN2200/i) },
  { id: "netgear-jgs516pe-devices", paths: ["/settingsJGS516.gif"], hint: NETGEAR,
    parse: (p, c) => (/^image\/gif/i.test(str(c.headers["content-type"])) && c.raw && c.raw.subarray(0, 4).toString("latin1") === "GIF8" ? tok("NETGEAR", "JGS516PE Firmware", "", { evidence: "static asset settingsJGS516.gif present" }) : null) },
  { id: "netgear-multiple-routers", paths: ["/currentsetting.htm"], hint: any(T(/^NETGEAR Router /i), R(/NETGEAR/i)), parse: currentSetting(null) },
  { id: "netgear-wireless-router-dgn2200", paths: ["/currentsetting.htm"], hint: any(T(/NETGEAR Router DGN2200/i), R(/NETGEAR Router DGN2200/i)), parse: currentSetting(/DGN2200/i) },
  { id: "netgear-wnr2000v5-router", paths: ["/currentsetting.htm"], hint: any(T(/NETGEAR.*WNR2000/i), R(/NETGEAR.*WNR2000/i), S(/WNR2000v5 UPnP\/1\.0 miniupnpd\/1\.0/i)), parse: currentSetting(/WNR2000/i) },
  // scan-research-pack, lead decision 2026-11-22: the same frozen path for the catalog row ivanti-connect-secure-version-path, hinted by
  // a recorded root redirect into /dana-na/ (or the existing ds.css marker); a dotted ProductVersion is stated (guessed false) but
  // is a build number, not the release naming NVD's ranges use ("9.1R11"), so it is shown and never compared
  { id: "ivanti-connect-secure-version-path", paths: ["/dana-na/nc/nc_gina_ver.txt"], hint: any(L(/^(?:https?:\/\/[^/\s]+)?\/dana-na\//i), B(/\/dana-na\/css\/ds\.css/i)),
    parse: (p, c) => { const m = /NAME="ProductVersion"\s+?VALUE="([^"]{1,40})"/i.exec(c.body); if (!m) return null; const v = m[1].trim(), dotted = /^\d+(?:\.\d+)+$/.test(v);
      return tok("Ivanti", "Connect Secure", dotted ? v : "", { guessed: !dotted, matchVersion: "", evidence: dotted ? `ProductVersion ${v} (build number, not compared)` : "nc_gina_ver.txt present; ProductVersion not a dotted version" }); } },
  { id: "pulse-secure-pulse-connect-secure", paths: ["/dana-na/nc/nc_gina_ver.txt"], hint: any(L(/\/dana-na\/auth\//i), B(/\/dana-na\/css\/ds\.css/i)),
    // the build number ("9.1.11.10541") is not the release naming NVD's ranges use ("9.1R11"): shown, never compared
    parse: (p, c) => { const m = /NAME="ProductVersion"\s+VALUE="([\d.]{3,30})"/i.exec(c.body); return m ? tok("Ivanti", "Connect Secure", m[1], { guessed: true, matchVersion: "", evidence: `ProductVersion ${m[1]} (build number)` }) : null; } },
  { id: "sonicwall-sonicwall-email-security", paths: ["/favicon.ico"], hint: any(B(/SonicWall Email Security/i), T(/SonicWall Email Security/i)),
    parse: (p, c) => (c.raw && !c.truncated && faviconHash(c.raw) === 2063459123 ? tok("SonicWall", "Email Security", "", { evidence: "favicon hash 2063459123" }) : null) },
  { id: "samsung-magicinfo-9-server", paths: ["/MagicInfo/logo.ico"], hint: any(T(/MagicINFO/i), L(/\/MagicInfo\//i)),
    // reviewed status/content pair, so a generic 404 page never matches: status 200, an image content type, and ICO magic bytes
    parse: (p, c) => (/^image\//i.test(str(c.headers["content-type"])) && c.raw && c.raw.length >= 4 && c.raw[0] === 0 && c.raw[1] === 0 && c.raw[2] === 1 && c.raw[3] === 0 ? tok("Samsung", "MagicINFO 9 Server", "", { evidence: "static asset MagicInfo/logo.ico present (200, image, ICO)" }) : null) },
  { id: "ami-megarac-spx", group: "bmc", paths: ["/redfish/v1/"], hint: (ev) => /\bCN=AMI\b/.test(ev.subject) && /\bOU=Service Processors\b/.test(ev.subject) && /\bO=American Megatrends/.test(ev.subject),
    parse: (p, c) => { const j = J(c); return j && /ServiceRoot/.test(str(j["@odata.type"])) ? tok("AMI", "MegaRAC SP-X", "", { evidence: `Redfish ${clip(j["@odata.type"], 60)}` }) : null; } },
  { id: "redfish-service-root", group: "bmc", paths: ["/redfish/v1/"], hint: (ev) => /\bCN=AMI\b/.test(ev.subject) && /\bO=American Megatrends/.test(ev.subject),
    parse: (p, c) => { const j = J(c); if (!j || !/ServiceRoot/.test(str(j["@odata.type"]))) return null; const ven = clip(str(j.Vendor), 40);
      return tok(ven || "DMTF", "Redfish service", "", { guessed: true, evidence: `Redfish ${clip(str(j.RedfishVersion), 20)}${ven ? `, Vendor ${ven}` : ""}` }); } },
  { id: "perforce-puppet-enterprise", paths: ["/pdb/meta/v1/version"], hint: any(CERT(/Puppet CA/), HN(/^x-puppet-version$/)),
    parse: (p, c) => { const j = J(c); return j && Object.keys(j).length <= 2 ? jsonVersion("Puppet", "PuppetDB")(p, c) : null; } },
  { id: "mitel-micollab", paths: ["/ucs/micollab/version.json"], hint: B(/micollab|mitel_logo|MiCollab End User Portal/i), parse: jsonVersion("Mitel", "MiCollab") },
].map((e) => { e.paths = Object.freeze(e.paths); return Object.freeze(e); }));

/** Every literal path the rail may ever request; probe.mjs getPath refuses anything else before connecting. */
export const RAIL_PATHS = Object.freeze([...new Set(RAIL.flatMap((e) => e.paths))]);

/** --paths-per-host: a positive whole number no higher than PATHS_PER_HOST (lowered only). -> { ok, value, problem } */
export function pathsPerHost(v) {
  if (v === undefined || v === null || v === "" || v === true) return { ok: true, value: PATHS_PER_HOST };
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1) return { ok: false, problem: "--paths-per-host must be a whole number of at least 1" };
  if (n > PATHS_PER_HOST) return { ok: false, problem: `--paths-per-host ${n} is above the ceiling of ${PATHS_PER_HOST}; limits can only be lowered` };
  return { ok: true, value: n };
}

const dn = (o) => (o && typeof o === "object" ? Object.entries(o).slice(0, 12).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("+") : v}`).join(", ") : "");

/**
 * One port's already-collected evidence, as the hints read it. r: probe.mjs probePort's result for a web port. Pure.
 * Cookie VALUES are never read (names only); the body is the root page already in memory, never kept in the report.
 */
export function railEvidence(port, r) {
  const http = (r && r.http) || {}, hd = http.headers && typeof http.headers === "object" ? http.headers : {};
  const headers = {};
  for (const [k, v] of Object.entries(hd).slice(0, 80)) if (k.toLowerCase() !== "set-cookie") headers[k.toLowerCase()] = clip(Array.isArray(v) ? v.join(", ") : v, 400);
  const sc = hd["set-cookie"], cookies = (Array.isArray(sc) ? sc : sc ? [sc] : []).map((c) => (/^\s*([^=;\s]{1,80})=/.exec(String(c)) || [])[1]).filter(Boolean).slice(0, 40);
  const body = clip(http.body, 65536), t = /<title[^>]*>([^<]{0,200})<\/title>/i.exec(body);
  const gen = /<meta\s+name=["']generator["']\s+content=["']([^"']{1,120})["']/i.exec(body) || /<meta\s+content=["']([^"']{1,120})["']\s+name=["']generator["']/i.exec(body);
  const cert = r && r.tls && r.tls.cert ? r.tls.cert : null, subject = cert ? dn(cert.subject) : "", issuer = cert ? dn(cert.issuer) : "";
  return { port, tls: !!(r && r.tls), status: Number(http.status) || 0, title: t ? t[1].replace(/\s+/g, " ").trim() : "", location: headers.location || "", server: headers.server || "",
    realm: (/realm="([^"]{0,120})"/i.exec(headers["www-authenticate"] || "") || [])[1] || "", generator: gen ? gen[1] : "", headers, cookies, body,
    subject, issuer, cert: cert ? `${subject} | ${issuer} | ${clip(cert.subjectaltname, 600)}` : "" };
}

/**
 * Which frozen paths a host gets, from its own evidence. Pure.
 * evs: railEvidence(...) for each web port of ONE host; opts: { perHost (<= PATHS_PER_HOST), bmc (the opt-in BMC group) }
 * -> { plan: [{ port, tls, path, ids[] }], skipped: [{ port, path, ids[], why }] }  (one request per port+path, table order)
 */
export function railPlan(evs, { perHost = PATHS_PER_HOST, bmc = false } = {}) {
  const cap = Math.max(0, Math.min(PATHS_PER_HOST, Math.floor(Number(perHost) || 0)));
  const plan = [], skipped = [], seen = new Map(), ports = new Set();
  for (const ev of [...(evs || [])].sort((a, b) => a.port - b.port)) {
    if (ports.has(ev.port)) continue; ports.add(ev.port);   // one evidence set per port (a throttle retry may add a second)
    for (const e of RAIL) {
      if (!e.hint || (e.group === "bmc" && !bmc)) continue;
      let hit = false; try { hit = !!e.hint(ev); } catch { hit = false; }
      if (!hit) continue;
      for (const path of e.paths) {
        const key = `${ev.port} ${path}`;
        if (seen.has(key)) { const x = seen.get(key); if (!x.ids.includes(e.id)) x.ids.push(e.id); continue; }
        const item = { port: ev.port, tls: ev.tls, path, ids: [e.id] };
        if (plan.length < cap) plan.push(item); else skipped.push({ ...item, why: "per-host cap" });
        seen.set(key, item);
      }
    }
  }
  return { plan, skipped };
}

/** A getPath result -> its coverage outcome: ok, redirect, unauthorized, forbidden, not-found, http-<code>, timeout, error. */
export function outcomeOf(res) {
  if (!res || !res.status) return res && res.error && !/timeout/i.test(res.error) ? "error" : "timeout";
  const s = res.status;
  if (s >= 200 && s < 300) return "ok";
  if (s >= 300 && s < 400) return "redirect";
  if (s === 401) return "unauthorized";
  if (s === 403) return "forbidden";
  if (s === 404) return "not-found";
  return `http-${s}`;
}

/**
 * One rail response -> { record (for the report and coverage), services (service records, the fingerprint.mjs shape) }.
 * Parses only a 200; keeps the status, the redirect Location (recorded, not followed) and each parsed token, never the body.
 */
export function railResult(item, res) {
  const outcome = outcomeOf(res), status = (res && Number(res.status)) || 0;
  const record = { port: item.port, path: item.path, for: item.ids.slice(), status, outcome };
  if (outcome === "redirect") record.location = clip(res.headers && res.headers.location, 200);
  if (res && res.error && !status) record.error = clip(res.error, 80);
  const services = [];
  if (status === 200) {
    let parsed;
    const ctx = { status, headers: (res.headers && typeof res.headers === "object") ? res.headers : {}, body: clip(res.body, 65536), raw: Buffer.isBuffer(res.raw) ? res.raw : null, truncated: !!res.truncated,
      json: () => { if (parsed === undefined) { try { parsed = JSON.parse(ctx.body); } catch { parsed = null; } } return parsed; } };
    for (const id of item.ids) {
      const e = RAIL.find((x) => x.id === id); if (!e) continue;
      let t = null; try { t = isStatus200(ctx) ? e.parse(item.path, ctx) : null; } catch { t = null; }
      if (!t || !t.product) continue;
      if (services.some((x) => x.product === clip(t.product, 80) && x.vendor === clip(t.vendor, 60))) continue;   // two rows on one shared path: the first in table order wins
      const shown = cleanVersion(t.version), proto = item.tls ? "https" : "http";
      services.push({ port: item.port, proto, vendor: clip(t.vendor, 60), product: clip(t.product, 80), label: clip(t.vendor && !t.product.toLowerCase().startsWith(t.vendor.toLowerCase().split(" ")[0]) ? `${t.vendor} ${t.product}` : t.product, 120),
        version: t.matchVersion !== undefined ? t.matchVersion : core(shown), shown_version: shown, distro: "", source: `HTTP GET ${item.path} (path rail, ${id})`, evidence: clip(t.evidence, 200), guessed: !!t.guessed });
    }
  }
  record.found = services.map((s) => `${s.product}${s.shown_version ? " " + s.shown_version : ""}`);
  return { record, services };
}

/** The coverage section for the rail: every request's status, and every planned path left unsent, counted. Pure. */
export function railCoverage(hosts, { enabled = false, perHost = PATHS_PER_HOST, bmc = false } = {}) {
  const rows = (hosts || []).flatMap((h) => (h.rail || []).map((r) => ({ address: h.address, ...r })));
  const by = {}; for (const r of rows) by[r.outcome] = (by[r.outcome] || 0) + 1;
  return { enabled: !!enabled, per_host_cap: enabled ? perHost : 0, bmc: !!(enabled && bmc), requests: rows.filter((r) => !/^not-sent/.test(r.outcome)).length, by_outcome: by,
    not_ok: rows.filter((r) => r.outcome !== "ok").slice(0, 500).map((r) => ({ address: r.address, port: r.port, path: r.path, status: r.status, outcome: r.outcome, ...(r.location ? { location: r.location } : {}) })) };
}

/** The run header's "Path rail" line: what is sent, when, and the cap (or that nothing beyond GET / is). */
export function railHeaderText(p) {
  if (!p || !p.enabled) return "off (--paths not given): web ports get one GET / and nothing else";
  return `on (--paths): at most ${p.perHost || p.per_host || PATHS_PER_HOST} extra GET request(s) per host (hard cap ${PATHS_PER_HOST}), only frozen literal paths from scanner/lib/paths.mjs (${RAIL_PATHS.length} reviewed), and only when the host's own root page, headers, certificate or port already hint at that product; redirects recorded, not followed; BMC identify ${p.bmc ? "on (--paths-bmc)" : "off"}`;
}

/** One line for summary.txt (empty when the rail was off). */
export function railSummaryLine(cov) {
  if (!cov || !cov.enabled) return "";
  const parts = Object.entries(cov.by_outcome || {}).map(([k, n]) => `${n} ${k}`);
  return `Path rail (--paths, at most ${cov.per_host_cap} per host): ${cov.requests} extra GET request(s)${parts.length ? ` — ${parts.join(", ")}` : ""}. Redirects were recorded, not followed; see coverage.paths in report.json.`;
}
