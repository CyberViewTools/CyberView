// Which country a collected feed covers, and how many feeds each country has. No AI model.
// A feed's country is, in order: its `country` field (ISO 3166-1 alpha-2, written by scripts/feed-check.mjs from the
// candidate), the country named in brackets at the end of its name ("CBC News (Canada)", "Brandon Sun (CA)",
// "CJME (Regina, SK)", "Arizona Attorney General (US)"), or its address's country-code domain (.ca, .de, .co.uk).
// Feeds with none of these (most .com, .org and .io feeds: international news, vendors, research) are "international".
// Used by `node scripts/feed-check.mjs coverage` to show which countries have too few feeds.

// The 193 UN member states plus the places reporting treats on their own (Taiwan, Hong Kong, Macao, Palestine, Kosovo,
// Puerto Rico).
export const COUNTRIES = ("AF AL DZ AD AO AG AR AM AU AT AZ BS BH BD BB BY BE BZ BJ BT BO BA BW BR BN BG BF BI CV KH CM CA CF TD CL CN " +
  "CO KM CG CD CR CI HR CU CY CZ DK DJ DM DO EC EG SV GQ ER EE SZ ET FJ FI FR GA GM GE DE GH GR GD GT GN GW GY HT HN HU IS IN ID IR " +
  "IQ IE IL IT JM JP JO KZ KE KI KP KR KW KG LA LV LB LS LR LY LI LT LU MG MW MY MV ML MT MH MR MU MX FM MD MC MN ME MA MZ MM NA NR " +
  "NP NL NZ NI NE NG MK NO OM PK PW PA PG PY PE PH PL PT QA RO RU RW KN LC VC WS SM ST SA SN RS SC SL SG SK SI SB SO ZA SS ES LK SD " +
  "SR SE CH SY TJ TZ TH TL TG TO TT TN TR TM TV UG UA AE GB US UY UZ VU VA VE VN YE ZM ZW TW HK MO PS XK PR").split(" ");
const SET = new Set(COUNTRIES);
const NAMES = new Intl.DisplayNames(["en"], { type: "region" });
export const countryName = (cc) => { try { return NAMES.of(cc); } catch { return cc; } };

// Country-code domains used as generic names (.io, .co, .me, .tv, .ai ...): not evidence of a country.
const VANITY = new Set(["io", "co", "me", "tv", "ai", "fm", "gg", "to", "ws", "ly", "sh", "cc", "im", "la", "so", "ms", "sc", "re", "nu", "tk", "ml", "ag", "vc", "bz", "st", "am", "dj", "ac", "md", "gl", "is", "mn", "cx"]);
const TLD = { uk: "GB" };
const US_STATES = "AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC".split(" ");
const CA_PROVINCES = "AB BC MB NB NL NS NT NU ON PE QC SK YT".split(" ");
// Names and spellings feed names use, beyond the English names Intl gives.
const ALIAS = {
  usa: "US", "u.s.": "US", "united states": "US", us: "US", uk: "GB", "united kingdom": "GB", britain: "GB", england: "GB", scotland: "GB", wales: "GB",
  "northern ireland": "GB", korea: "KR", "south korea": "KR", "north korea": "KP", brasil: "BR", "méxico": "MX", "perú": "PE", maroc: "MA",
  "algérie": "DZ", tunisie: "TN", "sénégal": "SN", cameroun: "CM", tchad: "TD", "bénin": "BJ", rdc: "CD", "dr congo": "CD", drc: "CD",
  bosnia: "BA", "bosnia and herzegovina": "BA", "n. macedonia": "MK", macedonia: "MK", turkey: "TR", "türkiye": "TR", uae: "AE", saudi: "SA",
  "côte d'ivoire": "CI", "ivory coast": "CI", czech: "CZ", "czech republic": "CZ", russia: "RU", palestine: "PS", "st vincent": "VC",
  macau: "MO", macao: "MO", "hong kong": "HK", burma: "MM", myanmar: "MM", "cabo verde": "CV", "cape verde": "CV", eswatini: "SZ", swaziland: "SZ",
  "timor-leste": "TL", "east timor": "TL", vietnam: "VN", "viet nam": "VN", laos: "LA", "the gambia": "GM", gambia: "GM", "trinidad and tobago": "TT",
  "antigua and barbuda": "AG", "saint lucia": "LC", "st lucia": "LC", "saint kitts and nevis": "KN", "são tomé and príncipe": "ST", "sao tome": "ST",
  deutschland: "DE", "españa": "ES", italia: "IT", "österreich": "AT", schweiz: "CH", suisse: "CH", nederland: "NL", polska: "PL", "україна": "UA",
  "república dominicana": "DO", "costa de marfil": "CI", "guinée": "GN", "congo-brazzaville": "CG", "congo-kinshasa": "CD", "republic of the congo": "CG",
  micronesia: "FM", "vatican": "VA", "holy see": "VA", kosovo: "XK", taiwan: "TW", "puerto rico": "PR", "solomon islands": "SB",
};
for (const cc of COUNTRIES) { const n = countryName(cc); if (n && n !== cc) ALIAS[n.toLowerCase().replace(/&/g, "and")] = cc; }

/** Pure: the country a bracketed label at the end of a feed name names, or "". */
export function countryFromName(name) {
  const m = String(name || "").match(/\(([^()]+)\)\s*$/);
  if (!m) return "";
  const label = m[1].trim(), low = label.toLowerCase().replace(/&/g, "and");
  if (ALIAS[low]) return ALIAS[low];
  if (/^[A-Z]{2}$/.test(label)) return label === "UK" ? "GB" : SET.has(label) ? label : "";
  const tail = label.match(/,\s*([A-Za-z.\s]+)$/);   // "Regina, SK", "Tucson, US", "Washington, D.C., US"
  if (tail) {
    const t = tail[1].trim();
    if (CA_PROVINCES.includes(t)) return "CA";
    if (US_STATES.includes(t)) return "US";
    if (ALIAS[t.toLowerCase()]) return ALIAS[t.toLowerCase()];
  }
  for (const part of low.split(/[,/;]\s*/)) if (ALIAS[part.trim()]) return ALIAS[part.trim()];
  return "";
}

/** Pure: the country a feed covers (ISO alpha-2), or "" for an international feed. */
export function countryOf(feed) {
  const f = feed || {};
  if (typeof f.country === "string" && SET.has(f.country)) return f.country;
  const byName = countryFromName(f.name);
  if (byName) return byName;
  let host = ""; try { host = new URL(f.url).hostname.toLowerCase(); } catch { return ""; }
  const tld = host.split(".").pop();
  if (tld === "gov" || tld === "mil") return "US";
  if (tld.length !== 2 || VANITY.has(tld)) return "";
  const cc = TLD[tld] || tld.toUpperCase();
  return SET.has(cc) ? cc : "";
}

/** Pure: feeds -> { counts: {CC: n}, international: n, thin: [{cc, name, n}] (fewer than `under`, fewest first) }. */
export function coverage(feeds, { under = 5 } = {}) {
  const counts = Object.fromEntries(COUNTRIES.map((c) => [c, 0]));
  let international = 0;
  for (const f of feeds || []) { const c = countryOf(f); if (c) counts[c] = (counts[c] || 0) + 1; else international++; }
  const thin = COUNTRIES.filter((c) => counts[c] < under).map((cc) => ({ cc, name: countryName(cc), n: counts[cc] }))
    .sort((a, b) => a.n - b.n || a.name.localeCompare(b.name));
  return { counts, international, thin };
}
