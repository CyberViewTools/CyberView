// The fixed lists for an event's `sectors` and `surface` (docs/schema.md), and the keyword assignment they replace.
// Sectors are the US CISA 16 critical infrastructure sectors (cisa.gov/topics/critical-infrastructure-security-and-resilience/
// critical-infrastructure-sectors) plus a few that are not critical infrastructure. Each carries the group the map's analysis
// views use (`g`, site/app.js SECG) and the status page's coverage key (`cov`, scripts/efficiency.mjs). Surfaces carry the
// analysis views' lane (`layer`, site/app.js LAYERS). site/app.js keeps a copy of these tables (it cannot import this file);
// tests/unit/classify.test.mjs fails when the two differ.
// Both fields carry a basis: "stated" (a page in sources says it) or "inferred" (CyberView AI concluded it from what the
// sources say). An event without them falls back to the keyword assignment below, and every view says which it used.

export const BASES = ["stated", "inferred"];

// k, label, critical infrastructure (CISA 16), analysis group, coverage key
export const SECTORS = [
  ["chemical", "Chemical", true, "other", "other"],
  ["commercial-facilities", "Commercial facilities (retail, hotels, venues, media)", true, "other", "other"],
  ["communications", "Communications", true, "telecom", "telecom"],
  ["critical-manufacturing", "Critical manufacturing", true, "other", "other"],
  ["dams", "Dams", true, "energy", "energy"],
  ["defense-industrial-base", "Defense industrial base", true, "gov", "government"],
  ["emergency-services", "Emergency services", true, "gov", "government"],
  ["energy", "Energy", true, "energy", "energy"],
  ["financial-services", "Financial services", true, "finance", "other"],
  ["food-agriculture", "Food and agriculture", true, "other", "other"],
  ["government-facilities", "Government services and facilities", true, "gov", "government"],
  ["healthcare-public-health", "Healthcare and public health", true, "health", "health"],
  ["information-technology", "Information technology", true, "tech", "other"],
  ["nuclear", "Nuclear reactors, materials and waste", true, "energy", "energy"],
  ["transportation-systems", "Transportation systems", true, "transport", "transport"],
  ["water-wastewater", "Water and wastewater", true, "energy", "water"],
  // not critical infrastructure
  ["education", "Education", false, "edu", "other"],
  ["professional-services", "Professional and legal services", false, "other", "other"],
  ["manufacturing", "Other manufacturing", false, "other", "other"],
  ["nonprofit", "Non-profits, civil society and religious groups", false, "other", "other"],
  ["individuals", "Individuals and consumers", false, "other", "other"],
  // no one sector: a flaw in widely used software, a law for everyone; or the sources do not say
  ["cross-sector", "Many sectors", false, "cross", "other"],
  ["unknown", "Not known", false, null, null],
].map(([k, label, ci, g, cov]) => ({ k, label, ci, g, cov }));

// k, label, analysis-view lane
export const SURFACES = [
  ["edge-appliance", "Internet-facing appliance (VPN, firewall, gateway)", "edge"],
  ["web-app", "Web application", "app"],
  ["email-phishing", "Email and phishing", "email"],
  ["endpoint", "Endpoint (computers, servers, browsers)", "endpoint"],
  ["cloud-saas", "Cloud and SaaS", "cloud"],
  ["supply-chain", "Supply chain and third parties", "app"],
  ["ot-ics", "OT and industrial control", "ot"],
  ["identity", "Identity and credentials", "identity"],
  ["mobile", "Mobile devices", "endpoint"],
  ["physical-insider", "Physical access and insiders", "people"],
  ["unknown", "Not known", null],
].map(([k, label, layer]) => ({ k, label, layer }));

export const SECTOR = Object.fromEntries(SECTORS.map((s) => [s.k, s]));
export const SURFACE = Object.fromEntries(SURFACES.map((s) => [s.k, s]));
export const MAX_SECTORS = 4;

/** Pure: the explicit sectors of an event as {values, basis}, or null when absent or not usable (unknown keys dropped). */
export function sectorsOf(e) {
  const s = e && e.sectors;
  if (!s || typeof s !== "object" || Array.isArray(s) || !BASES.includes(s.basis) || !Array.isArray(s.values)) return null;
  const values = [...new Set(s.values.filter((k) => typeof k === "string" && SECTOR[k]))].slice(0, MAX_SECTORS);
  return values.length ? { values, basis: s.basis } : null;
}
/** Pure: the explicit surface of an event as {value, basis}, or null. */
export function surfaceOf(e) {
  const s = e && e.surface;
  if (!s || typeof s !== "object" || Array.isArray(s) || !BASES.includes(s.basis) || !SURFACE[s.value]) return null;
  return { value: s.value, basis: s.basis };
}

// ---------- the keyword assignment (a copy of site/app.js LAYERS and LENS; the unit test keeps them in step) ----------
export const KW_LAYERS = [
  ["ot", /ot-ics|scada|\bplc\b|controller|industrial|refrigerat|siemens|codesys|johnson controls|danfoss|copeland/],
  ["edge", /vpn|firewall|gateway|netscaler|forti|sonicwall|check point|ivanti|citrix|palo alto|pan-os|cisco|router|big-ip|\bf5\b|barracuda|juniper|gaia/],
  ["identity", /identity|\bsso\b|saml|\bmfa\b|okta|entra|active directory|credential|ldap|oauth|password|stealer/],
  ["email", /outlook|exchange|e-?mail|microsoft 365|\bteams\b|sharepoint|zoom|gmail|phishing/],
  ["cloud", /cloud|\baws\b|azure|saas|kubernetes|container|ai-enabled|\bllm\b|\bai\b|api key/],
  ["app", /supply-chain|\bnpm\b|pypi|github|gitlab|java|\bjdk\b|node\.js|react|rails|wordpress|\bsap\b|confluence|atlassian|package|script|puppet|n8n|\bweb/],
  ["endpoint", /windows|linux|macos|\bios\b|android|chrome|browser|endpoint|kernel|driver|patch tuesday/],
  ["telecom", /telecom|\bbgp\b|\bdns\b|\bsms\b|carrier|\b5g\b|ss7|\birc/],
];
export const KW_SECG = [
  ["energy", /energy|utilit|power|electric|water|\boil\b|\bgas\b|nuclear|\bgrid\b|pipeline/],
  ["health", /health|hospital|medical|pharma|clinic|dental|\bnhs\b/],
  ["gov", /government|public sector|election|municip|ministry|defen[cs]e|military|federal|\bcouncil\b|\bcity of\b/],
  ["finance", /financ|bank|insur|payment|fintech|credit|accounting|crypto|invest/],
  ["telecom", /telecom|telco|\bisp\b|broadband|\bsms\b|wireless|mobile operator/],
  ["transport", /transport|aviation|airline|airport|\brail|shipping|logistic|maritime|\bports?\b|automotive/],
  ["edu", /educat|universit|school|college|academ/],
  ["tech", /technolog|software|saas|cloud|semiconduct|\bai\b|\bweb\b|\berp\b|network security|it services/],
];
const TECH = new Set(["incident", "vuln", "report", "outage"]);
const low = (v) => String(v || "").toLowerCase();
const list = (v) => (Array.isArray(v) ? v.map((x) => low(x)) : []);
/** Pure: the analysis lane the keyword rules give an event (what the map did before explicit fields; "org" = none). */
export function keywordLayer(e) {
  if (!TECH.has(e.category)) return "org";
  const lh = (low(e.title) + " " + list(e.products).join(" ") + " " + list(e.tags).join(" ") + " " + low(e.sector)).toLowerCase();
  for (const [k, re] of KW_LAYERS) if (re.test(lh)) return k;
  return "org";
}
/** Pure: the sector group the keyword rules give an event ("other" = none). */
export function keywordGroup(e) {
  const hay = (low(e.sector) + " " + list(e.tags).join(" ") + " " + low(e.org)).toLowerCase();
  for (const [k, re] of KW_SECG) if (re.test(hay)) return k;
  return "other";
}

/** Pure: the analysis lane and sector group of an event, each with where it came from: "stated", "inferred" or "keyword".
 *  An explicit "unknown" says nothing about a lane or group, so the keyword rules still place the event (labelled so);
 *  "cross-sector" has its own group ("cross", Many sectors), which the keyword rules never give. */
export function placement(e) {
  const su = surfaceOf(e), se = sectorsOf(e);
  const lane = su && TECH.has(e.category) && SURFACE[su.value].layer ? { k: SURFACE[su.value].layer, basis: su.basis } : { k: keywordLayer(e), basis: "keyword" };
  const g = se && se.values.map((k) => SECTOR[k].g).find(Boolean);
  const group = g ? { k: g, basis: se.basis } : { k: keywordGroup(e), basis: "keyword" };
  return { lane, group };
}
