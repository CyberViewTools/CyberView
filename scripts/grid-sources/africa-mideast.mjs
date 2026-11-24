// Grid sources, lane "africa-mideast": Rwanda (REG outage centre), Mauritius (CEB planned outages) and South Africa
// (Nelson Mandela Bay Municipality service alerts). Loaded by scripts/grid.mjs (see the comment above PLUGIN_ERRORS there).
// Every parser is pure and exported, tested on real saved replies in tests/fixtures/grid/africa-mideast/
// (tests/unit/grid-africa-mideast.test.mjs). Parsers return complete Items (the grid contract's shape); the adapters still
// pass each one through h.item, which cleans it again. Local wall-clock times go through zonedToIso (h.zonedToIso at run
// time, the same function imported from scripts/grid.mjs in the tests). Nothing here sends a key, a cookie or a browser
// header: h.get sends CyberView's own user agent, and a refusal fails the source, which grid.mjs reports.
//
// Checked 2026-11-24 (terms, robots.txt, no block for CyberView's user agent):
//   reg-rwanda       no terms page on www.reg.rw (silent); robots.txt allows /outages
//   ceb-mauritius    disclaimer: "general information purposes only", content "remains the property of the CEB"; nothing
//                    against reading or reuse (silent); robots.txt absent (404)
//   nmb-electricity  terms: "Users may view, copy, download to a local drive, print and distribute the content of this website
//                    or any part thereof for non-commercial, information or reference purposes only" (allowed, non-commercial,
//                    like AESO); robots.txt absent
// Every other candidate in the area, and why it is not connected, is in the lane's rejected list (swarm notes).
//
// What each item carries is only what the operator's page states: none of these pages gives customer counts, a level or
// coordinates, so customers and level stay null and the point is the region's centre (district or municipality).
// Planned work is kept from 24 hours before it starts until its stated end; an unplanned NMB alert while the operator lists
// it as CURRENT, for at most 7 days after it was published (the operator moves alerts to "Resolved" by hand).

// ---------- local helpers (same rules as scripts/grid.mjs item(), so h.item leaves the result unchanged) ----------
const str = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const round3 = (x) => Math.round(x * 1000) / 1000;
const okLat = (x) => typeof x === "number" && isFinite(x) && Math.abs(x) <= 90;
const okLng = (x) => typeof x === "number" && isFinite(x) && Math.abs(x) <= 180;
const intOrNull = (x) => (x === null || x === undefined || x === "" || !isFinite(Number(x)) ? null : Math.max(0, Math.round(Number(x))));
const slug = (s, n = 50) => String(s || "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, n).replace(/-$/, "") || "x";
const badShape = (why = "") => Object.assign(new Error(`unexpected shape${why ? `: ${why}` : ""}`), { code: "bad_shape" });
// the operator's own data time travels with the items (scripts/grid.mjs collect marks a source stale when it is old)
export const stamp = (arr, at) => Object.defineProperty(arr, "data_at", { value: at || "", enumerable: false, configurable: true });
const ENT = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", rarr: "→", larr: "←", darr: "↓", ndash: "–", mdash: "—", rsquo: "’", lsquo: "‘", laquo: "«", raquo: "»" };
/** HTML fragment -> plain text (tags dropped, <br> and block ends to newlines, entities decoded). */
export function htmlText(s) {
  return String(s || "").replace(/<br\s*\/?>/gi, "\n").replace(/<\/(p|div|tr|li|h\d)>/gi, "\n").replace(/<[^>]*>/g, "")
    .replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (m, e) => (e[0] === "#" ? String.fromCodePoint(e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : +e.slice(1)) : ENT[e.toLowerCase()] ?? m))
    .replace(/[ \t ]+/g, " ").replace(/ *\n */g, "\n").trim();
}
const MON = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
const MOIS = { janvier: 1, fevrier: 2, mars: 3, avril: 4, mai: 5, juin: 6, juillet: 7, aout: 8, septembre: 9, octobre: 10, novembre: 11, decembre: 12 };
const p2 = (n) => String(n).padStart(2, "0");
const day = (y, m, d) => `${y}-${p2(m)}-${p2(d)}`;
// planned work shows from 24 h before its start until its end
const plannedLive = (start, end, now) => { const s = Date.parse(start), e = Date.parse(end || start); return isFinite(s) && isFinite(e) && e > now && s - 864e5 <= now; };

const ownHost = (key, u) => {
  const s = String(u || "");
  if (!/^https:\/\/[^\s"'<>\\]+$/.test(s) || s.length > 300) return "";
  try { return SOURCES[key].hosts.includes(new URL(s).host) ? s : ""; } catch { return ""; }
};

/** A complete Item (swarm/handoff/grid-contract.md). */
function mk(o) {
  const src = o.source, has = okLat(o.lat) && okLng(o.lng);
  return {
    id: str(o.id, 120), source: src, country: o.country || SOURCES[src].country, region: str(o.region, 60), area: str(o.area, 120),
    lat: has ? round3(o.lat) : null, lng: has ? round3(o.lng) : null, customers: intOrNull(o.customers), kind: o.kind || "outage",
    planned: !!o.planned, cause: str(o.cause, 120), level: o.level == null ? null : intOrNull(o.level),
    started_at: o.started_at || "", restore_est: o.restore_est || "", url: ownHost(src, o.url) || SOURCES[src].page,
  };
}

// ---------- sources ----------
export const SOURCES = {
  "reg-rwanda": { name: "Rwanda Energy Group (REG)", country: "RW", kind: "outages",
    url: "https://www.reg.rw/outages/planned", page: "https://www.reg.rw/outages/current", hosts: ["www.reg.rw"],
    terms_url: "https://www.reg.rw/", terms_ok: "silent", customers_served: null },
  "ceb-mauritius": { name: "Central Electricity Board (CEB)", country: "MU", kind: "outages",
    url: "https://ceb.mu/customer-corner/power-outage-information", page: "https://ceb.mu/customer-corner/power-outage-information",
    hosts: ["ceb.mu"], terms_url: "https://ceb.mu/disclaimer", terms_ok: "silent", customers_served: null },
  "nmb-electricity": { name: "Nelson Mandela Bay Municipality (Electricity and Energy)", country: "ZA", kind: "outages",
    url: "https://www.nelsonmandelabay.gov.za/alerts", page: "https://www.nelsonmandelabay.gov.za/alerts",
    hosts: ["www.nelsonmandelabay.gov.za"], terms_url: "https://www.nelsonmandelabay.gov.za/page/terms-and-conditions/",
    terms_ok: "allowed", customers_served: null,
    attribution: "Service alerts: Nelson Mandela Bay Municipality (nelsonmandelabay.gov.za), shown for non-commercial information purposes as its terms allow" },
};

// ---------- regions (district or municipality centres) ----------
export const RW_DISTRICTS = {
  Gasabo: [-1.884, 30.131], Kicukiro: [-1.987, 30.102], Nyarugenge: [-1.958, 30.06],
  Bugesera: [-2.215, 30.151], Gatsibo: [-1.587, 30.43], Kayonza: [-1.9, 30.507], Kirehe: [-2.258, 30.697], Ngoma: [-2.158, 30.534],
  Nyagatare: [-1.297, 30.327], Rwamagana: [-1.949, 30.434],
  Burera: [-1.474, 29.834], Gakenke: [-1.694, 29.783], Gicumbi: [-1.577, 30.066], Musanze: [-1.499, 29.634], Rulindo: [-1.728, 29.99],
  Gisagara: [-2.6, 29.833], Huye: [-2.597, 29.739], Kamonyi: [-2.003, 29.904], Muhanga: [-2.084, 29.756], Nyamagabe: [-2.479, 29.48],
  Nyanza: [-2.352, 29.751], Nyaruguru: [-2.7, 29.55], Ruhango: [-2.226, 29.779],
  Karongi: [-2.06, 29.348], Ngororero: [-1.865, 29.62], Nyabihu: [-1.654, 29.505], Nyamasheke: [-2.33, 29.115], Rubavu: [-1.68, 29.326],
  Rusizi: [-2.484, 28.903], Rutsiro: [-1.933, 29.33],
};
export const CEB_DISTRICTS = {
  blackriver: ["Black River", -20.36, 57.37], flacq: ["Flacq", -20.22, 57.68], grandport: ["Grand Port", -20.38, 57.63],
  moka: ["Moka", -20.23, 57.55], pamplemousses: ["Pamplemousses", -20.1, 57.58], plainewilhems: ["Plaines Wilhems", -20.3, 57.48],
  portlouis: ["Port Louis", -20.162, 57.499], rivieredurempart: ["Rivière du Rempart", -20.06, 57.65], savanne: ["Savanne", -20.47, 57.48],
  rodrigues: ["Rodrigues", -19.72, 63.42],
};
const NMB = { name: "Nelson Mandela Bay", lat: -33.96, lng: 25.6 };

export const REGIONS = {
  "reg-rwanda|Rwanda": { name: "Rwanda", lat: -1.94, lng: 29.874 },
  ...Object.fromEntries(Object.entries(RW_DISTRICTS).map(([n, [lat, lng]]) => [`reg-rwanda|${n}`, { name: `${n} District`, lat, lng }])),
  ...Object.fromEntries(Object.values(CEB_DISTRICTS).map(([n, lat, lng]) => [`ceb-mauritius|${n}`, { name: n === "Rodrigues" ? "Rodrigues" : `${n} District`, lat, lng }])),
  "nmb-electricity|Nelson Mandela Bay": NMB,
};

// ---------- REG (Rwanda): the outage centre's notice cards ----------
/** "25 Nov 2026, 12:00 CAT" -> ISO (Africa/Kigali). */
export function regTime(s, zonedToIso) {
  const m = String(s || "").match(/(\d{1,2}) ([A-Za-z]{3})[a-z]* (\d{4}),? (\d{1,2}):(\d{2})/);
  if (!m || !MON[m[2].toLowerCase()]) return "";
  return zonedToIso(`${day(m[3], MON[m[2].toLowerCase()], m[1])} ${p2(m[4])}:${m[5]}:00`, "Africa/Kigali");
}
const REG_LIVE = new Set(["scheduled", "ongoing", "in-progress", "active"]);
/** One page of www.reg.rw/outages/* -> Items for notices that are under way or start within 24 h. */
export function parseReg(html, zonedToIso, now = Date.now()) {
  const s = String(html || "");
  if (!/class="outage-center__summary"/.test(s)) throw badShape("reg outage centre");
  const upd = s.match(/Last updated:\s*([^<]+)</);
  const out = [];
  for (const [, status, card] of s.matchAll(/<article class="outage-card outage-card--([a-z-]+)"[^>]*>([\s\S]*?)<\/article>/g)) {
    if (!REG_LIVE.has(status)) continue;   // awaiting confirmation, restored, postponed, cancelled
    const href = (card.match(/<h2><a href="(\/outages\/[^"#?]+)"/) || [])[1] || "";
    const title = htmlText((card.match(/<h2>([\s\S]*?)<\/h2>/) || [])[1]);
    const type = htmlText((card.match(/outage-card__topline">[\s\S]*?<\/span><span>([\s\S]*?)<\/span>/) || [])[1]);
    const desc = htmlText((card.match(/<\/h2>\s*<p>([\s\S]*?)<\/p>/) || [])[1]);
    const facts = Object.fromEntries([...card.matchAll(/<dt>([\s\S]*?)<\/dt>\s*<dd>([\s\S]*?)<\/dd>/g)].map((m) => [htmlText(m[1]).toLowerCase(), htmlText(m[2])]));
    const start = regTime(facts.starts, zonedToIso), end = regTime(facts["scheduled end"] || facts["overall end"] || facts.ends, zonedToIso);
    const planned = !/emergenc|unplanned|fault|repair/i.test(type);
    if (planned ? !plannedLive(start, end, now) : end && Date.parse(end) <= now) continue;
    const districts = (facts.districts || "").split(/\s*[·,]\s*/).filter(Boolean);
    // one or two districts: the first one's centre; a line across more districts (or none named): the country
    const first = districts.length && districts.length <= 2 && RW_DISTRICTS[districts[0]] ? districts[0] : "Rwanda";
    const at = first === "Rwanda" ? [-1.94, 29.874] : RW_DISTRICTS[first];
    const where = [facts["network element"], districts.join(", ")].filter(Boolean).join(" — ");
    out.push(mk({ source: "reg-rwanda", id: `reg-rwanda:${slug(href.split("/").pop() || title, 80)}`,
      region: first, area: where || title, lat: at[0], lng: at[1],
      customers: null, kind: "outage", planned, level: null, cause: [type, desc].filter(Boolean).join(": "),
      started_at: start, restore_est: end, url: href ? `https://www.reg.rw${href}` : "" }));
  }
  return stamp(out, upd ? regTime(upd[1], zonedToIso) : "");
}

// ---------- CEB (Mauritius): planned outages by district, embedded as a JSON object of HTML tables ----------
/** "Le dimanche 22 novembre 2026 de 08:15:00 à 17:00:00" -> { start, end } (Indian/Mauritius). */
export function cebWindow(s, zonedToIso) {
  const t = String(s || "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
  const m = t.match(/(\d{1,2}) ([a-z]+) (\d{4}) de\s+(\d{1,2}):(\d{2})(?::\d{2})?\s+a\s+(\d{1,2}):(\d{2})/);
  if (!m || !MOIS[m[2]]) return { start: "", end: "" };
  const d = day(m[3], MOIS[m[2]], m[1]);
  const start = zonedToIso(`${d} ${p2(m[4])}:${m[5]}:00`, "Indian/Mauritius");
  let end = zonedToIso(`${d} ${p2(m[6])}:${m[7]}:00`, "Indian/Mauritius");
  if (end && start && Date.parse(end) <= Date.parse(start)) end = new Date(Date.parse(end) + 864e5).toISOString().replace(/\.\d+Z$/, "Z");
  return { start, end };
}
export function parseCeb(html, zonedToIso, now = Date.now()) {
  const m = String(html || "").match(/var arDistrictLocations\s*=\s*(\{[\s\S]*?\});\s*\n/);
  if (!m) throw badShape("ceb arDistrictLocations");
  let d;
  try { d = JSON.parse(m[1]); } catch { throw badShape("ceb json"); }
  const out = [];
  let rows = 0, read = 0;
  for (const [key, frag] of Object.entries(d)) {
    const dist = CEB_DISTRICTS[key];
    if (!dist) continue;
    const body = (String(frag).match(/<tbody>([\s\S]*?)<\/tbody>/) || [])[1] || "";
    for (const [, tr] of body.matchAll(/<tr>([\s\S]*?)<\/tr>/g)) {
      const td = [...tr.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map((x) => htmlText(x[1]));
      if (td.length < 2) continue;
      rows++;
      const { start, end } = cebWindow(td[0], zonedToIso);
      if (!start) continue;
      read++;
      if (!plannedLive(start, end, now)) continue;
      const area = [td[1], td[2]].filter(Boolean).join(": ");
      out.push(mk({ source: "ceb-mauritius", id: `ceb-mauritius:${key}-${start.slice(0, 16).replace(/\D/g, "")}-${slug(td[1], 40)}`,
        region: dist[0], area, lat: dist[1], lng: dist[2], customers: null, kind: "outage", planned: true, level: null,
        cause: "", started_at: start, restore_est: end, url: "" }));
    }
  }
  if (rows && !read) throw badShape("ceb dates");
  return out;
}

// ---------- Nelson Mandela Bay (South Africa): service alerts, electricity only ----------
const NMB_POWER = /\b(POWER|ELECTRICITY|ELECTRICAL|SUBSTATION|LOAD ?SHEDDING)\b/i;
/** "19 Nov 2026" / "Sunday, 22 November 2026" -> "2026-11-22" */
const nmbDay = (s) => { const m = String(s || "").match(/(\d{1,2}) ([A-Za-z]{3})[a-z]* (\d{4})/); return m && MON[m[2].toLowerCase()] ? day(m[3], MON[m[2].toLowerCase()], m[1]) : ""; };
export function parseNmb(html, zonedToIso, now = Date.now()) {
  const s = String(html || "");
  const a = s.indexOf('<div id="current"'), b = s.indexOf('<div id="resolved"');
  if (a < 0) throw badShape("nmb current tab");
  const cur = s.slice(a, b > a ? b : undefined);
  const out = [];
  for (const [, block] of cur.matchAll(/<div class="m-sm p-sm bg-light-grey"[^>]*>([\s\S]*?)<\/div>/g)) {
    if (!/>\s*CURRENT\s*</.test(block)) continue;
    const pub = nmbDay((block.match(/Published:<\/b>\s*([^<,]+)/) || [])[1]);
    const text = htmlText((block.match(/<p>([\s\S]*)<\/p>/) || [])[1]);
    const lines = text.split("\n").map((x) => x.trim()).filter(Boolean);
    const title = lines[0] || "";
    if (!NMB_POWER.test(title) || /\bWATER\b/i.test(title)) continue;
    const planned = /\bPLANNED\b/i.test(title);
    const dateL = text.match(/DATE(?: OF SHUTDOWN)?:\s*([^\n]+)/i), timeL = text.match(/TIME:\s*(\d{1,2})[:h](\d{2})\s*[–-]\s*(\d{1,2})[:h](\d{2})/i);
    const d = nmbDay(dateL && dateL[1]);
    let start = "", end = "";
    if (d && timeL) {
      start = zonedToIso(`${d} ${p2(timeL[1])}:${timeL[2]}:00`, "Africa/Johannesburg");
      end = zonedToIso(`${d} ${p2(timeL[3])}:${timeL[4]}:00`, "Africa/Johannesburg");
    }
    if (planned) { if (!plannedLive(start, end, now)) continue; }
    else if (!pub || Date.parse(`${pub}T00:00:00Z`) < now - 7 * 864e5) continue;
    // affected areas: the "* ..." lines after "AFFECTED AREA(S):"
    const ai = lines.findIndex((x) => /^AFFECTED AREAS?:?/i.test(x));
    const areas = [];
    if (ai >= 0) for (const x of lines.slice(ai + 1)) { if (/^\*/.test(x)) areas.push(x.replace(/^\*\s*/, "")); else if (/:$/.test(x)) continue; else break; }
    const subject = title.replace(/^.*?\s[–-]\s/, "");
    let cause;
    if (planned) {
      const why = (text.match(/planned power shutdown[^.]*?\bto (facilitate [^.\n]+)/i) || [])[1] || "";
      cause = `Planned power shutdown${why ? `, to ${why}` : ""}`;
    } else cause = (lines.find((x) => /\btripp?(ed)?\b|\btrip\b|\bfault|\bcable|\bfailure|\bvandal|\btheft/i.test(x) && !/^(The Municipality apologises|Further updates)/.test(x)) || title).replace(/^(.*?[a-z0-9)]\.)\s.*$/, "$1");   // its first sentence
    out.push(mk({ source: "nmb-electricity", id: `nmb-electricity:${pub.replace(/-/g, "")}-${slug(subject, 60)}`,
      region: NMB.name, area: areas.length ? `${subject}: ${areas.join(", ")}` : subject, lat: NMB.lat, lng: NMB.lng,
      customers: null, kind: "outage", planned, level: null, cause, started_at: start, restore_est: end, url: "" }));
  }
  return out;
}

// ---------- adapters ----------
export const ADAPTERS = {
  // the current page (ongoing work) and the planned page (scheduled work); the source fails only when neither can be read
  "reg-rwanda": async (h) => {
    const out = [], seen = new Set(), errs = [];
    let newest = "";
    for (const u of ["https://www.reg.rw/outages/current", "https://www.reg.rw/outages/planned"]) {
      try {
        const got = parseReg(await h.get(u, { as: "text", timeoutMs: 30000 }), h.zonedToIso);
        for (const x of got) if (!seen.has(x.id)) { seen.add(x.id); out.push(x); }
        if (got.data_at > newest) newest = got.data_at;
      } catch (e) { errs.push(e); }
    }
    if (errs.length === 2) throw errs[0];
    return stamp(out, newest);
  },
  "ceb-mauritius": async (h) => parseCeb(await h.get(h.SOURCES["ceb-mauritius"].url, { as: "text", timeoutMs: 30000 }), h.zonedToIso),
  // the alerts page is about 3 MB (every resolved alert is on it)
  "nmb-electricity": async (h) => parseNmb(await h.get(h.SOURCES["nmb-electricity"].url, { as: "text", timeoutMs: 60000 }), h.zonedToIso),
};

export default {
  sources: SOURCES,
  regions: REGIONS,
  adapters: Object.fromEntries(Object.entries(ADAPTERS).map(([k, fn]) => [k, async (h) => { const got = await fn(h); return stamp(got.map((x) => h.item(x)), got.data_at); }])),
};
