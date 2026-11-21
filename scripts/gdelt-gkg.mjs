// GDELT 2.0 Global Knowledge Graph files as leads, no AI model.
// Run: node scripts/gdelt-gkg.mjs [--dry] [--json] [--from <YYYYMMDDHHMMSS>] [--file <path.zip>...]
//   --dry writes nothing; --from reads the 15-minute files after that slot (at most catch_up_files per stream) instead of
//   those after the last one read; --file parses local zips only (no network, no state)
// (behind a proxy: NODE_USE_ENV_PROXY=1)
// Why (owner, 2026-11-21): the GDELT DOC search API (api.gdeltproject.org) allows one request every 5 seconds per address
// and answered 429, then 403 and connection timeouts from this address. GDELT also publishes every article it processed
// as plain 15-minute files on data.gdeltproject.org (no key, no rate limit; robots.txt there is empty, checked 2026-11-21).
// Every 15 minutes there are two GKG 2.1 files: one for English sources ("<ts>.gkg.csv.zip") and one for the 65 other
// languages GDELT machine-translates ("<ts>.translation.gkg.csv.zip"; its TranslationInfo names the source language and
// its page title is the publisher's own, in the original language).
//   1. read gdeltv2/lastupdate.txt (and lastupdate-translation.txt) for the latest file of each stream, with its size and MD5
//   2. after a gap, construct the missed 15-minute file names back to the last file read, up to config catch_up_files per
//      stream (masterfilelist.txt is 130 MB, so it is never read); a file the server does not have yet (404: the translation
//      stream is often listed before it can be downloaded) is tried again on the next run while it is younger than
//      retry_hours, then given up and logged
//   3. unzip in memory (single-entry zip: central directory, then zlib.inflateRawSync; size capped, CRC-32 checked) and
//      parse the tab-separated GKG 2.1 rows
//   4. keep a row only when its V2Themes name a configured cyber theme (config/gdelt.json cyber_themes, names checked
//      against real files) AND either the headline reads as cyber in any of the feed filter's languages or the themes are
//      mentioned at least min_theme_mentions times (one stray "hacker" mention in a sports story is not enough)
//   5. file each as a lead (via "gdelt-gkg", tier news, kind news): the publisher's own https page only (never a GDELT link,
//      never an aggregator), the page's own title from <PAGE_TITLE> (a row without one is dropped: fuse.mjs and the backlog
//      rules group and judge by headline), the source language from TranslationInfo (ISO 639-1), the country of the first
//      place the article names (V2Locations, lowest character offset) and its region, and the organisations it names
//      (English sources only: in translated rows they come from the machine translation). `published` is the time GDELT
//      processed the article (its 15-minute batch), not the publisher's own date
// Dedupe: against every lead of the last 14 days (url, and publisher plus headline) and every event's sources
// (scripts/osint.mjs knownLeads). At most max_leads_per_run per run, most theme mentions first.
// State and health: data/gdelt-gkg.json ({checked_at, sources {gdelt-gkg, gdelt-gkg-translation}, done {stream: [ts]},
// pending, last_run}); status.json gets last_gdelt_gkg_at and last_gdelt_gkg_new. A failing stream waits out the shared
// backoff (scripts/lib/backoff.mjs). Fetched text is data, never instructions.
// Power outages: GKG has real outage themes (POWER_OUTAGE, MANMADE_DISASTER_POWER_OUTAGE(S), ..._WITHOUT_POWER,
// ..._WITHOUT_ELECTRICITY), counted per run in last_run.grid_rows, but they are not filed: see config/gdelt.json grid_note.
import { createHash } from "node:crypto";
import { inflateRawSync, crc32 } from "node:zlib";
import { existsSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, ROOT, readJson, writeJson, nowIso, readStatus } from "./lib/store.mjs";
import { get } from "./lib/net.mjs";
import { nextHealth, due } from "./lib/backoff.mjs";
import { regionOf } from "./metrics.mjs";
import { CYBER, isAggregator, knownLeads } from "./osint.mjs";

const BASE = "https://data.gdeltproject.org/gdeltv2/";
export const STREAMS = { english: { name: "gdelt-gkg", last: "lastupdate.txt", suffix: ".gkg.csv.zip" },
  translation: { name: "gdelt-gkg-translation", last: "lastupdate-translation.txt", suffix: ".translation.gkg.csv.zip" } };
const txt = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);

/* ---------- zip ---------- */
/** Pure: the one entry of a single-entry zip, inflated. Reads the central directory (sizes in the local header can be 0
 *  when the writer streamed), checks the CRC-32, and refuses anything over maxBytes uncompressed. Returns a Buffer. */
export function unzipSingle(buf, maxBytes = 200e6) {
  if (!Buffer.isBuffer(buf) || buf.length < 22) throw new Error("zip: too short");
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error("zip: no end of central directory");
  const cd = buf.readUInt32LE(eocd + 16);
  if (cd + 46 > buf.length || buf.readUInt32LE(cd) !== 0x02014b50) throw new Error("zip: bad central directory");
  const method = buf.readUInt16LE(cd + 10), crc = buf.readUInt32LE(cd + 16), csize = buf.readUInt32LE(cd + 20), usize = buf.readUInt32LE(cd + 24), loc = buf.readUInt32LE(cd + 42);
  if (usize > maxBytes) throw new Error(`zip: entry of ${usize} bytes is over the ${maxBytes} cap`);
  if (loc + 30 > buf.length || buf.readUInt32LE(loc) !== 0x04034b50) throw new Error("zip: bad local header");
  const start = loc + 30 + buf.readUInt16LE(loc + 26) + buf.readUInt16LE(loc + 28);
  if (start + csize > buf.length) throw new Error("zip: truncated");
  const raw = buf.subarray(start, start + csize);
  const out = method === 0 ? Buffer.from(raw) : method === 8 ? inflateRawSync(raw, { maxOutputLength: maxBytes }) : null;
  if (!out) throw new Error(`zip: compression method ${method} not supported`);
  if (out.length !== usize || (crc32(out) >>> 0) !== crc) throw new Error("zip: size or CRC-32 mismatch");
  return out;
}

/* ---------- file names and the update lists ---------- */
/** Pure: lastupdate.txt -> [{size, md5, url, ts}] for the GKG lines only (always https: the list says http). */
export function parseLastUpdate(s) {
  return String(s || "").split("\n").map((l) => l.trim().split(/\s+/)).filter((p) => p.length === 3 && /^\d+$/.test(p[0]) && /^[0-9a-f]{32}$/.test(p[1]))
    .map(([size, md5, u]) => { const m = u.match(/^https?:\/\/data\.gdeltproject\.org\/gdeltv2\/(\d{14})\.(translation\.)?gkg\.csv\.zip$/); return m ? { size: +size, md5, ts: m[1], url: `${BASE}${m[1]}.${m[2] || ""}gkg.csv.zip` } : null; })
    .filter(Boolean);
}
const tsMs = (ts) => Date.UTC(+ts.slice(0, 4), +ts.slice(4, 6) - 1, +ts.slice(6, 8), +ts.slice(8, 10), +ts.slice(10, 12), +ts.slice(12, 14));
const msTs = (ms) => new Date(ms).toISOString().replace(/[-:T]/g, "").slice(0, 14);
/** Pure: the 15-minute file stamps to read, oldest first: every slot after `lastDone` up to `latest`, at most `cap` (the
 *  newest ones when the gap is longer), plus `pending` stamps not yet past retryHours. No lastDone: the latest only. */
export function slotsToRead(latest, lastDone, cap = 8, pending = [], retryHours = 3, now = Date.now()) {
  if (!/^\d{14}$/.test(latest || "")) return [];
  const want = new Set(pending.filter((p) => /^\d{14}$/.test(p) && now - tsMs(p) < retryHours * 36e5 && p <= latest));
  const end = tsMs(latest), from = /^\d{14}$/.test(lastDone || "") ? tsMs(lastDone) : end - 9e5;
  const fresh = [];
  for (let t = end; t > from && fresh.length < cap; t -= 9e5) fresh.push(msTs(t));
  fresh.forEach((s) => want.add(s));
  return [...want].sort();
}

/* ---------- rows ---------- */
// ISO 639-2/3 codes GDELT names in TranslationInfo -> ISO 639-1 (the code the other collectors and the backlog rules use)
const LANG = { eng: "en", spa: "es", ita: "it", tur: "tr", deu: "de", ger: "de", zho: "zh", chi: "zh", rus: "ru", por: "pt", fra: "fr", fre: "fr", ara: "ar", ell: "el", gre: "el",
  srp: "sr", ukr: "uk", vie: "vi", ron: "ro", rum: "ro", hrv: "hr", pol: "pl", sqi: "sq", alb: "sq", fin: "fi", hin: "hi", hun: "hu", kor: "ko", ind: "id", bul: "bg", jpn: "ja",
  nld: "nl", dut: "nl", swe: "sv", nor: "no", nob: "no", nno: "no", mal: "ml", dan: "da", ben: "bn", urd: "ur", ces: "cs", cze: "cs", mar: "mr", slv: "sl", bos: "bs", heb: "he",
  guj: "gu", tel: "te", mkd: "mk", mac: "mk", nep: "ne", slk: "sk", slo: "sk", pan: "pa", lit: "lt", hye: "hy", arm: "hy", tha: "th", isl: "is", ice: "is", glg: "gl", tam: "ta",
  kan: "kn", fas: "fa", per: "fa", sin: "si", est: "et", msa: "ms", may: "ms", cat: "ca", mon: "mn", lav: "lv", kat: "ka", geo: "ka", aze: "az", kaz: "kk", uzb: "uz", swa: "sw",
  amh: "am", som: "so", hau: "ha", afr: "af", khm: "km", mya: "my", bur: "my", lao: "lo", tgl: "tl", fil: "tl", eus: "eu", baq: "eu", bel: "be", tgk: "tg", kir: "ky", pus: "ps",
  kur: "ku", yor: "yo", ibo: "ig", zul: "zu", xho: "xh", mlt: "mt", gle: "ga", cym: "cy", wel: "cy", lat: "la", ori: "or", asm: "as", tuk: "tk" };
/** Pure: TranslationInfo ("srclc:spa;eng:GT-SPA 1.0") -> ISO 639-1; "" (empty field) is English; an unmapped code is "". */
export function srcLang(info) {
  const m = String(info || "").match(/srclc:([a-z]{3})/);
  return !String(info || "").trim() ? "en" : m ? LANG[m[1]] || "" : "";
}
const ENT = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", ndash: "–", mdash: "—", hellip: "…", rsquo: "’", lsquo: "‘", rdquo: "”", ldquo: "“" };
/** Pure: decode the HTML entities GDELT leaves in page titles (&#x2013; &#233; &amp; ...). */
export function decodeEntities(s) {
  return String(s || "").replace(/&#x([0-9a-f]{1,6});/gi, (_, h) => { const c = parseInt(h, 16); return c > 0 && c <= 0x10ffff ? String.fromCodePoint(c) : " "; })
    .replace(/&#(\d{1,7});/g, (_, d) => { const c = +d; return c > 0 && c <= 0x10ffff ? String.fromCodePoint(c) : " "; })
    .replace(/&([a-z]+);/gi, (m, n) => ENT[n.toLowerCase()] ?? m);
}
/** Pure: the publisher's headline from the Extras column, cleaned: entities decoded, tags and control characters gone, and a
 *  trailing " | Site" or " - Site" dropped when it names the publisher (source = its domain). "" when there is none. */
export function cleanTitle(extras, source = "") {
  const m = String(extras || "").match(/<PAGE_TITLE>([\s\S]*?)<\/PAGE_TITLE>/);
  if (!m) return "";
  let t = txt(decodeEntities(m[1]).replace(/<[^>]*>/g, " "), 400);
  const base = String(source).toLowerCase().replace(/^www\./, "").split(".")[0].replace(/[^a-z0-9]/g, "");
  const tail = t.match(/^(.{20,}?)\s+[|\-–—:]\s+([^|\-–—]{2,60})$/);
  if (tail && base.length >= 3 && tail[2].toLowerCase().replace(/[^a-z0-9]/g, "").includes(base)) t = tail[1];
  return txt(t, 200);
}
/** Pure: the publisher's own https page, or "" (http, a GDELT or aggregator address, credentials, odd characters). */
export function cleanUrl(u) {
  const s = String(u || "").trim();
  if (!/^https:\/\/[^\s"'<>\\]+$/.test(s) || s.length > 1000) return "";
  try { const x = new URL(s); if (x.username || x.password || isAggregator(s)) return ""; } catch { return ""; }
  return s;
}
/** Pure: V2Themes ("THEME,offset;...") -> Map(theme -> mentions). */
export function themeCounts(v2) {
  const m = new Map();
  for (const p of String(v2 || "").split(";")) { const t = p.split(",")[0]; if (/^[A-Z0-9_]{2,80}$/.test(t)) m.set(t, (m.get(t) || 0) + 1); }
  return m;
}
/** Pure: the country (English name) of the place an article mentions first, or "". V2Locations rows are
 *  type#full name#FIPS country#ADM1#ADM2#lat#lon#feature id#offset (the first by offset wins); a country-level row's name is
 *  the word as written, often a demonym ("Americans", "Britons"), so the name comes from the FIPS code: the canonical
 *  country names in V1Locations (type#name#FIPS#...) and the last part of any place name ("Louisiana, United States"). */
export function firstCountry(v2loc, v1loc = "") {
  const names = new Map();
  for (const p of `${v1loc};${v2loc}`.split(";")) {
    const f = p.split("#"); if (f.length < 7 || !/^[A-Z]{2}$/.test(f[2] || "") || !f[1]) continue;
    const n = f[0] === "1" && p.split("#").length < 9 ? f[1] : f[1].includes(",") ? f[1].split(",").pop() : "";
    if (n && !names.has(f[2])) names.set(f[2], txt(n, 60));
  }
  let best = null;
  for (const p of String(v2loc || "").split(";")) {
    const f = p.split("#"); if (f.length < 9 || !/^[A-Z]{2}$/.test(f[2] || "")) continue;
    const off = Number(f[8]); if (!best || (isFinite(off) ? off : 1e9) < best.off) best = { off: isFinite(off) ? off : 1e9, cc: f[2] };
  }
  return best ? names.get(best.cc) || "" : "";
}
/** Pure: V2Organizations ("name,offset;...") -> unique names in order of first mention, at most n, each cut to len. */
export function orgsOf(v2org, n = 5, len = 60) {
  const seen = new Map();
  for (const p of String(v2org || "").split(";")) {
    const i = p.lastIndexOf(","), name = txt(i > 0 ? p.slice(0, i) : p, len), off = i > 0 ? Number(p.slice(i + 1)) : 1e9;
    if (name.length < 2 || !/\p{L}/u.test(name)) continue;
    const k = name.toLowerCase(); if (!seen.has(k) || off < seen.get(k).off) seen.set(k, { name, off: isFinite(off) ? off : 1e9 });
  }
  return [...seen.values()].sort((a, b) => a.off - b.off).slice(0, n).map((o) => o.name);
}
const iso14 = (s) => (/^\d{14}$/.test(s) ? `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z` : "");
/** Pure: one tab-separated GKG 2.1 line -> a row, or null (wrong column count, not a web article). */
export function parseRow(line) {
  const c = String(line).split("\t");
  if (c.length < 27 || c[2] !== "1") return null;
  return { id: c[0], date: iso14(c[1]), source: txt(c[3], 80), url: c[4], themes: themeCounts(c[8] || c[7]), country: firstCountry(c[10], c[9]), orgs: c[14],
    tone: Number(String(c[15]).split(",")[0]), lang: srcLang(c[25]), extras: c[26] };
}
/** Pure: GKG file text -> rows. */
export function parseGkg(text) {
  return String(text).split("\n").map((l) => (l ? parseRow(l.replace(/\r$/, "")) : null)).filter(Boolean);
}
/** Pure: mentions of any of `themes` in a row's theme counts (0 = no match). */
export function themeHits(counts, themes) { let n = 0; for (const t of themes) n += counts.get(t) || 0; return n; }

/** Pure: does this headline read as cyber? The feed filter's words (osint.mjs CYBER, many languages) plus config
 *  title_words (plain text, matched case-insensitively anywhere: words for languages the feed filter does not cover). */
export function cyberTitle(title, words = []) {
  if (CYBER.test(title)) return true;
  const t = String(title).toLowerCase();
  return (Array.isArray(words) ? words : []).some((w) => typeof w === "string" && w.length >= 3 && t.includes(w.toLowerCase()));
}
/** Pure: rows -> candidate leads. cfg: { cyber_themes, min_theme_mentions, title_words, grid_themes }. Returns { leads, stats }. */
export function select(rows, cfg, seenAt = nowIso()) {
  const themes = cfg.cyber_themes || [], minM = Math.max(1, Number(cfg.min_theme_mentions) || 4), grid = cfg.grid_themes || [];
  const st = { rows: rows.length, themed: 0, weak: 0, no_https: 0, no_title: 0, grid_rows: 0 }, out = [];
  for (const r of rows) {
    if (grid.length && themeHits(r.themes, grid)) st.grid_rows++;
    const hits = themeHits(r.themes, themes); if (!hits) continue;
    st.themed++;
    const url = cleanUrl(r.url); if (!url) { st.no_https++; continue; }
    const title = cleanTitle(r.extras, r.source); if (!title) { st.no_title++; continue; }
    if (hits < minM && !cyberTitle(title, cfg.title_words)) { st.weak++; continue; }
    // organisations only from English sources: in the translation stream they are extracted from GDELT's machine
    // translation and are often not names at all ("Police Be", "Even Armed" from a Swedish article, 2026-11-21)
    const orgs = r.lang === "en" ? orgsOf(r.orgs) : [], region = regionOf(r.country), matched = themes.filter((t) => r.themes.get(t));
    out.push({ seen_at: seenAt, source: r.source || new URL(url).hostname.replace(/^www\./, ""), tier: "news", via: "gdelt-gkg", kind: "news", title, url,
      published: r.date && r.date > seenAt ? seenAt : r.date,   // a file is stamped with the end of its 15 minutes: never later than now
      summary: txt(`GDELT knowledge graph: ${matched.join(", ")} (${hits} mention${hits === 1 ? "" : "s"})${r.country ? `; first place named: ${r.country}` : ""}${orgs.length ? `; organisations named: ${orgs.join(", ")}` : ""}. Machine-tagged by GDELT, not checked.`, 300),
      lang: r.lang || "", ...(r.country ? { country: r.country } : {}), ...(/^(other|unplaced)$/.test(region) ? {} : { region }), ...(orgs.length ? { orgs } : {}), gkg_id: txt(r.id, 40), _hits: hits });
  }
  return { leads: out, stats: st };
}
/** Pure: drop leads already known (url, or publisher and headline) and duplicates within the batch; at most perTitle
 *  leads with the same headline (syndicated copies: six Fox stations ran "FBI's NCIC criminal database hacked, Trump
 *  confirms" in one file, 2026-11-21); keep the `cap` with the most theme mentions (newest first among equals).
 *  known = osint.mjs knownLeads(). Returns { leads, dupes, syndicated, capped }. */
export function dedupeAndCap(leads, known, cap = 60, perTitle = 2) {
  const urls = new Set(known.known), titles = new Set(known.knownTitle), norm = known.norm || ((t) => String(t).toLowerCase()), same = new Map();
  let dupes = 0, syndicated = 0; const keep = [];
  for (const l of leads) {
    const tk = l.source + "|" + norm(l.title), n = same.get(norm(l.title)) || 0;
    if (urls.has(l.url) || titles.has(tk)) { dupes++; continue; }
    if (n >= Math.max(1, perTitle)) { syndicated++; continue; }
    urls.add(l.url); titles.add(tk); same.set(norm(l.title), n + 1); keep.push(l);
  }
  keep.sort((a, b) => (b._hits - a._hits) || String(b.published).localeCompare(String(a.published)));
  const out = keep.slice(0, Math.max(0, cap)).map(({ _hits, ...l }) => (l.lang ? l : (({ lang, ...x }) => x)(l)));
  return { leads: out, dupes, syndicated, capped: Math.max(0, keep.length - out.length) };
}

/* ---------- run ---------- */
async function readFile(stream, ts, cfg, expect) {
  const url = `${BASE}${ts}${STREAMS[stream].suffix}`;
  // the circuit is per file: a listed file that is not downloadable yet (404, common in the translation stream) must not
  // open the breaker for the whole host and block the other files of the run
  const zip = await get(url, { as: "buffer", timeoutMs: 60000, retries: 1, key: `gdelt-file:${ts}:${stream}` });
  if (zip.length > (Number(cfg.max_zip_bytes) || 40e6)) throw new Error(`file of ${zip.length} bytes is over max_zip_bytes`);
  if (expect && expect.md5 && createHash("md5").update(zip).digest("hex") !== expect.md5) throw new Error("MD5 does not match lastupdate");
  return { bytes: zip.length, text: unzipSingle(zip, Number(cfg.max_unzipped_bytes) || 200e6).toString("utf8") };
}

export async function run({ dry = false, files = [], from = "" } = {}) {
  const cfg = readJson(join(ROOT, "config", "gdelt.json"), {}) || {};
  if (cfg.enabled === false && !files.length) { console.log("gdelt-gkg: disabled in config/gdelt.json"); return null; }
  const statePath = join(DATA, "gdelt-gkg.json"), state = readJson(statePath, {}) || {};
  state.sources ||= {}; state.done ||= {}; state.pending ||= {};
  const now = nowIso(), t0 = Date.now(), budget = (Number(cfg.time_budget_seconds) || 150) * 1000;
  const rows = [], read = [], failed = []; let bytes = 0;
  if (files.length) {   // local files (tests and checks): no network, no state change
    for (const f of files) { const t = unzipSingle(readFileSync(f)).toString("utf8"); bytes += readFileSync(f).length; rows.push(...parseGkg(t)); read.push(f); }
  } else {
    for (const stream of (cfg.streams || ["english", "translation"]).filter((s) => STREAMS[s])) {
      const S = STREAMS[stream], prev = state.sources[S.name] || {};
      if (!due(prev)) continue;
      try {
        const latest = parseLastUpdate(await get(BASE + S.last, { as: "text", timeoutMs: 20000, retries: 1, key: "data.gdeltproject.org" }))[0];
        if (!latest) throw new Error("no GKG file in the update list");
        // --from <ts>: read the slots after <ts> (still at most catch_up_files) instead of those after the last one read
        const done = /^\d{14}$/.test(from) ? [] : state.done[stream] || [], lastDone = /^\d{14}$/.test(from) ? from : done[done.length - 1] || "";
        const todo = slotsToRead(latest.ts, lastDone, Math.max(1, Number(cfg.catch_up_files) || 8), state.pending[stream] || [], Number(cfg.retry_hours) || 3).filter((s) => !done.includes(s));
        const pending = [], got = []; let items = 0, missing = 0, lastErr = null;
        for (const ts of todo) {
          if (Date.now() - t0 > budget) { pending.push(ts); continue; }   // out of time: the next run reads it
          try {
            const f = await readFile(stream, ts, cfg, ts === latest.ts ? latest : null);
            const r = parseGkg(f.text); rows.push(...r); items += r.length; bytes += f.bytes; got.push(ts); read.push(`${stream}:${ts}`);
          } catch (e) {
            if (e.code === "http_404") { missing++; pending.push(ts); }   // listed but not downloadable yet
            else { lastErr = e; pending.push(ts); failed.push(`${stream}:${ts}: ${txt(e.code || e.message, 80)}`); }
          }
        }
        state.done[stream] = [...new Set([...done, ...got])].sort().slice(-200);
        state.pending[stream] = pending.filter((p) => Date.now() - tsMs(p) < (Number(cfg.retry_hours) || 3) * 36e5);
        if (!got.length && lastErr) throw lastErr;
        state.sources[S.name] = nextHealth(prev, { ok: true, items, extra: { files: got.length, waiting: state.pending[stream].length, not_yet_published: missing, latest: latest.ts } }, Date.now());
      } catch (e) {
        state.sources[S.name] = nextHealth(prev, { ok: false, error: txt(e.code || e.message, 90), retryAfterMs: e.retryAfterMs }, Date.now());
      }
    }
  }
  const sel = select(rows, cfg, now);
  const { leads, dupes, syndicated, capped } = dedupeAndCap(sel.leads, knownLeads(), Number(cfg.max_leads_per_run) || 60, Number(cfg.max_per_title) || 2);
  const report = { at: now, files: read.length, bytes, ...sel.stats, candidates: sel.leads.length, duplicates: dupes, syndicated, capped, new: leads.length, failed: failed.slice(0, 10) };
  if (!dry && !files.length) {
    if (leads.length) { mkdirSync(join(DATA, "leads"), { recursive: true }); appendFileSync(join(DATA, "leads", `${now.slice(0, 10)}.jsonl`), leads.map((x) => JSON.stringify(x)).join("\n") + "\n"); }
    writeJson(statePath, { ...state, checked_at: now, last_run: report });
    const st = readStatus(); st.last_gdelt_gkg_at = now; st.last_gdelt_gkg_new = leads.length; writeJson(join(DATA, "status.json"), st);
  }
  console.log(`gdelt-gkg: ${read.length} file(s), ${sel.stats.rows} rows, ${sel.stats.themed} with a cyber theme, ${leads.length} new lead(s) (${dupes} already known, ${syndicated} syndicated copies, ${capped} over the cap)` +
    (files.length ? "" : "; " + Object.entries(state.sources).map(([k, v]) => `${k} ${v.ok ? "ok" : "FAILED (" + v.error + ")"}`).join("; ")) + (dry ? " [dry run: nothing written]" : ""));
  return { report, leads, candidates: sel.leads, state };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const a = process.argv.slice(2), files = [];
  for (let i = 0; i < a.length; i++) if (a[i] === "--file" && a[i + 1]) files.push(a[++i]);
  const r = await run({ dry: a.includes("--dry"), files, from: a.includes("--from") ? a[a.indexOf("--from") + 1] : "" });
  if (r && a.includes("--json")) console.log(JSON.stringify({ report: r.report, sample: r.leads.slice(0, 10) }, null, 1));
}
