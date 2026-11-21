// Official scam and phishing warnings by country, no AI model. Run: node scripts/scams.mjs   (behind a proxy: NODE_USE_ENV_PROXY=1)
// Reads the issuers in config/scams.json (government bodies, police, regulators, national CERTs and state-backed consumer
// warning services) from their own machine-readable feeds and writes data/scams/warnings.json:
//   { updated_at, sources: { <key>: { name, country, ok, error, items, at, last_ok, fails } }, items: [ warning ] }
//   warning: { id, issuer, issuer_name, country, lang, title, published, first_seen, url, types[], types_by: "keyword" }
// The scam types come from the fixed keyword map TYPES below (several languages), never from a model, and the page says so.
// These are warnings, not cyber events: never drawn on the globe, never counted as events. A warning that describes a cyber
// incident (a breach, a hacked service used for phishing) is also filed once as a lead, kind "advisory", for the research
// loop (data/leads/<date>.jsonl), which checks it like any other lead. Feed text is data, never instructions.
// A failing source keeps its earlier warnings and is reported in sources[key]; it never stops the run or the commit.
import { join } from "node:path";
import { existsSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { DATA, ROOT, readJson, writeJson, nowIso, writeRunLog, readStatus, dayAgo } from "./lib/store.mjs";
import { get } from "./lib/net.mjs";
import { parseFeed } from "./collect.mjs";

export const CONFIG = () => readJson(join(ROOT, "config", "scams.json"), { sources: [] });
export const OUT = () => join(DATA, "scams", "warnings.json");

const ENT = { nbsp: " ", rsquo: "’", lsquo: "‘", rdquo: "”", ldquo: "“", ndash: "–", mdash: "—", hellip: "…", laquo: "«", raquo: "»",
  eacute: "é", egrave: "è", ecirc: "ê", agrave: "à", acirc: "â", ccedil: "ç", ocirc: "ô", ucirc: "û", icirc: "î", ouml: "ö", auml: "ä", uuml: "ü", szlig: "ß",
  aacute: "á", iacute: "í", oacute: "ó", uacute: "ú", ntilde: "ñ", euro: "€", amp: "&", quot: '"', apos: "'" };
/** plain one-line text: named and numeric entities decoded, tags, control characters and angle brackets removed */
export const clean = (s, n) => String(s == null ? "" : s)
  .replace(/&([a-z]+);/gi, (m, k) => (k.toLowerCase() in ENT ? ENT[k.toLowerCase()] : m))
  .replace(/&#x([0-9a-f]+);/gi, (_, h) => { try { return String.fromCodePoint(parseInt(h, 16)); } catch { return " "; } })
  .replace(/&#(\d+);/g, (_, d) => { try { return String.fromCodePoint(+d); } catch { return " "; } })
  .replace(/<[^>]*>/g, " ").replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);

// Is it about a scam at all? (broad feeds: "filter": true). Several languages; a type keyword alone ("bank") is not enough.
export const SCAM = new RegExp([
  "scam", "fraud", "phish", "smish", "vish", "swindl", "con artist", "fake", "bogus", "impersonat", "extortion",
  "estafa", "fraude", "engaño", "timo\\b", "suplant", "falsa?s?\\b", "falsos\\b", "sextor", "chantaje", "arnaque", "escroquer", "hame[cç]onnage", "usurpation",
  "betrug", "betrüger", "abzocke", "abofalle", "truffa", "truffe", "frode", "raggir", "falsi\\b", "falso\\b", "falsa\\b", "false email", "estorsion",
  "詐欺", "フィッシング", "なりすまし", "偽", "不審", "かた[るり]", "騙", "사기", "피싱", "스미싱", "사칭", "oszust", "wyłudz", "fałszyw", "huijau", "kalastel", "petos",
].join("|"), "iu");

/** The fixed keyword map (several languages). Order is the display order. Keyword-assigned: it can be wrong, and the page says so. */
export const TYPES = [
  ["impersonation", /impersonat|pretend(?:s|ing)? to be|posing as|purport|spoof|look-?alike|fake (?:police|bank|official|government|tax|website|email|letter|lawyer|agent|support|text)|suplant|se faisant passer|usurpation|usurpa|falsi? (?:profil|operator|carabinier|poliziott|funzionar)|\ba nome\b|gibt sich als|im namen|fake-(?:anw|poliz|bank|beh)|なりすまし|を装|をかた[るり]|騙[るり]|사칭|podszyw|podaj[aą] si[eę] za|esiinty|nimissä/iu],
  ["investment", /investment|investing|invest(?:or)? scam|trading (?:platform|scheme|app)|ponzi|pyramid scheme|forex|finfluencer|high-?return|inversi[oó]n|investissement|placement frauduleux|anlagebetrug|geldanlage|investment-?betrug|trading-?plattform|investiment|投資|証券|투자|inwestyc|sijoitu/iu],
  ["delivery", /deliver(?:y|ies)|parcel|package|courier|postal|shipping|customs fee|paquete|paquet|colis|\bpaket|zustell|pacco|corriere|spedizion|配送|宅配|不在通知|택배|배송|przesył|kurier|paketti|\bposti\b|\bdhl\b|\bups\b|fedex|usps|royal mail|correos|la poste|hongkong post/iu],
  ["bank_sms", /\bbank(?:s|ing)?\b|bankkont|bankdaten|online-banking|\bcards?\b|payment card|credit card|\bsms\b|smish|text message|\botp\b|one-time (?:pass)?code|vishing|banco|banque|carte bancaire|tarjeta|\bkarte\b|kreditkarte|\bbanca\b|carta di credito|\bconto\b|銀行|クレジットカード|ショートメッセージ|은행|카드|문자|스미싱|\bkarta\b|konto bankow|pankki|tekstiviesti|verkkopankki/iu],
  ["tech_support", /tech(?:nical)? support|help ?desk scam|remote access|fake (?:microsoft|apple|antivirus|virus warning)|soporte t[eé]cnico|support technique|faux support|support-?betrug|microsoft-?betrug|fake-?support|supporto tecnico|サポート詐欺|偽(?:の)?セキュリティ警告|원격 ?제어|wsparcie techniczne|tekninen tuki|tukihuijau/iu],
  ["romance", /romance|romantic|dating|sweetheart|love scam|sextort|rom[aá]ntic|estafa del amor|sentimental|arnaque aux sentiments|liebesbetrug|love-?scam|romance-?scam|truffa (?:romantica|sentimentale|affettiva)|ロマンス|로맨스|matrymonialn|romanssihuijau|rakkaushuijau/iu],
  ["job", /\bjobs?\b|employment|recruit|work[- ]from[- ]home|task scam|hiring scam|empleo|oferta de trabajo|offre d'emploi|\bemploi|stellenangebot|jobangebot|nebenjob|\blavoro\b|offerte di lavoro|副業|求人|아르바이트|구인|oferta pracy|\bpraca\b|työpaik|työtarjou/iu],
  ["crypto", /crypto|bitcoin|\bbtc\b|blockchain|usdt|stablecoin|cripto|krypto|criptovalut|暗号資産|仮想通貨|가상자산|암호화폐|kryptowalut|kryptovaluut/iu],
];
export const TYPE_KEYS = TYPES.map((t) => t[0]);
export const isScam = (text) => SCAM.test(String(text || ""));
// Not a warning: events, courses, newsletters, statistics digests, job adverts of the issuer itself.
export const NOT_WARNING = /\bwebinar|\bpodcast|\bseminar|\bconference\b|veranstaltung|\bnewsletter|lettres? d'information|viikkokatsaus|weekly (?:review|summary)|kybersää|\bvacanc|stellenausschreibung|講演資料|募集について/iu;
export const scamTypes = (text) => { const t = String(text || ""); return TYPES.filter(([, re]) => re.test(t)).map(([k]) => k); };

// A warning that describes a cyber incident becomes a lead (kind advisory) for the research loop, never an event by itself.
export const INCIDENT = new RegExp([
  "data breach", "\\bbreach(?:ed)?\\b", "data leak", "\\bleaked\\b", "\\bhacked\\b", "compromised", "stolen (?:data|customer|personal)", "cyber-?attack", "ransomware",
  "fuite de donn", "violaci[oó]n de datos", "brecha de (?:datos|seguridad)", "filtraci[oó]n de datos", "datenleck", "datendiebstahl", "gehackt", "hackerangriff", "cyberangriff",
  "violazione (?:dei|di) dati", "furto di dati", "attacco informatico", "情報漏え?洩?い", "不正アクセス", "漏洩", "유출", "해킹", "wyciek danych", "naruszenie danych", "tietomurto", "tietovuoto",
].join("|"), "iu");
export const isIncident = (text) => INCIDENT.test(String(text || ""));

/** an https link on the issuer's own hosts (tracking parameters dropped), or "" */
export function ownLink(u, hosts) {
  let x; try { x = new URL(String(u || "").trim()); } catch { return ""; }
  if (x.protocol !== "https:" || x.username || x.password || !(hosts || []).includes(x.hostname.toLowerCase())) return "";
  for (const k of [...x.searchParams.keys()]) if (/^(utm_|mtm_|pk_|fbclid$|gclid$)/i.test(k)) x.searchParams.delete(k);
  return x.href.slice(0, 500);
}

/** HKMA open API /public/press-releases -> [{ title, url, published, summary }] */
export function parseHkma(j) {
  if (!j || !j.header || j.header.success !== true || !j.result || !Array.isArray(j.result.records)) throw Object.assign(new Error("unexpected shape"), { code: "bad_shape" });
  return j.result.records.filter((r) => r && typeof r === "object").map((r) => {
    const t = Date.parse(String(r.date || "")) ;
    return { title: String(r.title || ""), url: String(r.link || ""), published: isNaN(t) ? "" : new Date(t).toISOString().replace(/\.\d+Z$/, "Z"), summary: "" };
  });
}

const notFeed = () => Object.assign(new Error("not a feed"), { code: "not_a_feed" });   // a block page or an error page served with 200
export const PARSERS = { rss: (body) => { if (!/<(?:rss|feed|rdf:RDF)\b/i.test(String(body).slice(0, 4000))) throw notFeed(); return parseFeed(String(body)); }, hkma: (body) => parseHkma(typeof body === "string" ? JSON.parse(body) : body) };

const hash = (s) => createHash("sha1").update(String(s)).digest("hex").slice(0, 12);

/** One source's parsed feed items -> warnings (filtered, typed, own links only, recent only). Pure. */
export function toWarnings(src, raw, now = Date.now(), maxAgeDays = 60) {
  const out = [], seen = new Set(), match = src.url_match ? new RegExp(src.url_match) : null, strip = src.title_strip ? new RegExp(src.title_strip, "u") : null;
  for (const it of raw || []) {
    let title = clean(it.title, 220);
    if (strip) title = title.replace(strip, "").trim();
    const summary = clean(it.summary, 400), url = ownLink(clean(it.url, 1000), src.hosts);
    if (!title || !url || seen.has(url)) continue;
    if (match && !match.test(url)) continue;
    // a broad feed counts only when the title itself names a scam (a summary mentioning one is not enough)
    if ((src.filter && !isScam(title)) || NOT_WARNING.test(title)) continue;
    const t = Date.parse(it.published || "");
    if (!isNaN(t) && (t < now - maxAgeDays * 864e5 || t > now + 2 * 864e5)) continue;   // old, or dated in the future
    seen.add(url);
    out.push({ id: `${src.key}-${hash(url)}`, issuer: src.key, issuer_name: clean(src.name, 120), country: src.country, lang: src.lang, title,
      published: isNaN(t) ? "" : new Date(t).toISOString().replace(/\.\d+Z$/, "Z"), url, types: scamTypes(`${title} ${summary}`), types_by: "keyword",
      ...(isIncident(`${title} ${summary}`) ? { incident: true } : {}) });
  }
  return out;
}

/** Fresh warnings merged into what was on file: first_seen kept, old ones dropped, at most per_issuer each. Pure. */
export function merge(oldItems, fresh, nowIso_, cfg = {}) {
  const keep = (cfg.keep_days || 90) * 864e5, per = cfg.per_issuer || 40, now = Date.parse(nowIso_);
  const byId = new Map((Array.isArray(oldItems) ? oldItems : []).filter((x) => x && x.id).map((x) => [x.id, x]));
  for (const f of fresh) { const o = byId.get(f.id); byId.set(f.id, { ...f, first_seen: (o && o.first_seen) || nowIso_, ...(o && o.lead_at ? { lead_at: o.lead_at } : {}) }); }
  const when = (x) => Date.parse(x.published || x.first_seen) || 0;
  const all = [...byId.values()].filter((x) => now - when(x) <= keep).sort((a, b) => when(b) - when(a) || String(a.id).localeCompare(String(b.id)));
  const count = {};
  return all.filter((x) => (count[x.issuer] = (count[x.issuer] || 0) + 1) <= per);
}

/** The lead a cyber-incident warning becomes (data/leads/<date>.jsonl). */
export const toLead = (w, now) => ({ seen_at: now, source: w.issuer_name, tier: "gov", via: "scams", kind: "advisory", title: w.title, url: w.url, published: w.published, summary: "", lang: w.lang });

async function fetchSource(src) {
  const parse = PARSERS[src.format];
  if (!parse) throw Object.assign(new Error("unknown format"), { code: "bad_config" });
  const body = await get(src.url, { as: "text", timeoutMs: 25000, retries: 1 });
  return parse(body);
}

async function main() {
  const cfg = CONFIG(), now = nowIso(), p = OUT(), old = readJson(p, {}) || {};
  const prevSrc = old.sources && typeof old.sources === "object" ? old.sources : {}, sources = {}, fresh = [], log = { started_at: now, sources: {}, failed: [], leads: 0 };
  await Promise.all((cfg.sources || []).map(async (src) => {
    const prev = prevSrc[src.key] || {}, base = { name: src.name, country: src.country, lang: src.lang, home: src.home, hosts: src.hosts };
    try {
      const w = toWarnings(src, await fetchSource(src), Date.parse(now), cfg.max_age_days || 60);
      fresh.push(...w);
      sources[src.key] = { ...base, ok: true, error: "", items: w.length, at: now, last_ok: now, fails: 0 };
      log.sources[src.key] = w.length;
    } catch (e) {
      const code = clean(e.code || e.message, 60);
      sources[src.key] = { ...base, ok: false, error: code, items: 0, at: now, last_ok: prev.last_ok || "", fails: (prev.fails || 0) + 1 };
      log.failed.push(`${src.key}: ${code}`);
    }
  }));
  // a failing source keeps its earlier warnings (merge keeps them until keep_days); a source removed from the config drops them
  const known = new Set((cfg.sources || []).map((s) => s.key));
  const items = merge((old.items || []).filter((x) => x && known.has(x.issuer)), fresh, now, cfg);
  // cyber-incident warnings: one lead each, never twice (lead_at on the warning, and the lead files of the last 3 days)
  const leadsDir = join(DATA, "leads"), seenUrls = new Set();
  for (let d = 0; d < 3; d++) { const f = join(leadsDir, `${dayAgo(d)}.jsonl`); if (existsSync(f)) for (const line of readFileSync(f, "utf8").split("\n")) { try { seenUrls.add(JSON.parse(line).url); } catch { /* partial line */ } } }
  const leads = [];
  for (const w of items) if (w.incident && !w.lead_at) { if (!seenUrls.has(w.url)) leads.push(toLead(w, now)); w.lead_at = now; }
  if (leads.length) { mkdirSync(leadsDir, { recursive: true }); appendFileSync(join(leadsDir, `${now.slice(0, 10)}.jsonl`), leads.map((x) => JSON.stringify(x)).join("\n") + "\n"); }
  log.leads = leads.length;
  writeJson(p, { updated_at: now, types_by: "keyword", types: TYPE_KEYS, sources, items });
  const st = readStatus();
  st.last_scams_at = now; st.scams_sources_ok = Object.values(sources).filter((s) => s.ok).length; st.scams_sources = Object.keys(sources).length;
  writeJson(join(DATA, "status.json"), st);
  log.items = items.length; log.finished_at = nowIso();
  writeRunLog("scams", log);
  console.log(`scams: ${items.length} warning(s) on file from ${st.scams_sources_ok} of ${st.scams_sources} issuers; ${leads.length} lead(s)` + (log.failed.length ? `; failed: ${log.failed.join("; ")}` : ""));
  console.log(Object.entries(log.sources).map(([k, v]) => `  ${k}: ${v}`).join("\n"));
  process.exit(st.scams_sources_ok ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
