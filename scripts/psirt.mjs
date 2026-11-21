// Vendor security advisories (PSIRTs) as structured data, no AI model: Microsoft (MSRC CVRF API), Cisco, Fortinet, Palo Alto
// Networks and Red Hat (CSAF 2.0), Ubuntu (notices API), Debian (DSA list and security tracker), Oracle (security alerts
// feed), Google Chrome (release notes feed), Apple (security releases), Mozilla (MFSA advisories) and Ivanti (advisory
// posts). The parsers are in scripts/lib/psirt.mjs.
//   node scripts/psirt.mjs [collect] [--only <vendor,...>]   read the sources, update data/psirt/advisories.json, file leads
//   node scripts/psirt.mjs stats | get <CVE-or-advisory-id>
// Writes data/psirt/advisories.json ({ updated_at, sources: { vkey: { name, ok, at, n, error } }, advisories: [...] }, the
// shape in docs/schema.md), data/psirt/state.json (what each source has already read), status.json last_psirt_at, and leads
// (kind "advisory", tier "vendor") for a vendor's own "exploited" statement or a critical advisory for widely used software.
// A failing source keeps its advisories from the last run and is reported in sources; it never stops the others.
// robots.txt checked 2026-11-21 for every host read here: api.msrc.microsoft.com (none), www.cisco.com, filestore.fortinet.com
// (none), www.fortiguard.com (Crawl-delay 2), security.paloaltonetworks.com (/json is disallowed: not read; /csaf and
// /rss.xml are allowed), security.access.redhat.com (none), ubuntu.com (Crawl-delay 2), www.debian.org and
// security-tracker.debian.org (none), www.oracle.com, chromereleases.googleblog.com, support.apple.com, www.mozilla.org,
// www.ivanti.com (Crawl-delay 1). Not read: SAP (blocks automated readers), salsa.debian.org raw files (disallowed),
// msrc.microsoft.com/csaf (Crawl-delay 30: the CVRF API carries the same data), and vendors whose advisories are only in a
// script-built page or behind a sign-in (Juniper, Citrix, SonicWall, VMware by Broadcom, F5, Atlassian, Check Point, Zyxel,
// Progress); the ICS vendors are scripts/ics.mjs.
import { mkdirSync, readdirSync, readFileSync, appendFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, readJson, writeJson, nowIso, readStatus } from "./lib/store.mjs";
import { get } from "./lib/net.mjs";
import * as P from "./lib/psirt.mjs";

const DIR = join(DATA, "psirt"), FILE = join(DIR, "advisories.json"), STATE = join(DIR, "state.json");
const T0 = Date.now(), BUDGET = (Number(process.env.PSIRT_BUDGET_S) || 420) * 1000;
const timeLeft = () => BUDGET - (Date.now() - T0);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// one request at a time per host, spaced by the host's crawl delay (or 400 ms)
const DELAY = { "ubuntu.com": 2000, "www.fortiguard.com": 2000, "www.ivanti.com": 1000, "security-tracker.debian.org": 1000 }, next = new Map();
async function fetchOne(url, o = {}) {
  if (timeLeft() < 5000) throw Object.assign(new Error("time budget spent"), { code: "budget" });
  const h = new URL(url).host, wait = (next.get(h) || 0) - Date.now();
  next.set(h, Math.max(Date.now(), next.get(h) || 0) + (DELAY[h] || 400));
  if (wait > 0) await sleep(wait);
  return get(url, { timeoutMs: 45000, retries: 1, ...o });
}
const seenAt = nowIso();

// ---------- the sources: each returns { name, advisories, note } and may update its part of the state ----------
async function microsoft(st) {
  const ids = P.msrcReleases(await fetchOne("https://api.msrc.microsoft.com/cvrf/v3.0/updates", { accept: "application/json" }), 2), out = [];
  for (const id of ids) out.push(...P.parseMsrc(await fetchOne(`https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/${id}`, { accept: "application/json", timeoutMs: 120000 })));
  return { name: "Microsoft (MSRC CVRF)", advisories: out, note: `releases ${ids.join(", ")}` };
}
async function cisco(st) {
  // Cisco regenerates its whole CSAF directory often (thousands of changed files a month), so the advisory RSS says what is
  // new or updated, and the directory's index says where each one's CSAF document is
  const items = P.parseCiscoRss(await fetchOne("https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", { as: "text" }));
  const paths = P.ciscoCsafPaths(await fetchOne("https://www.cisco.com/.well-known/csaf/index.txt", { as: "text", timeoutMs: 60000 }));
  const seen = (st.cisco ||= {}).read || {}, out = [];
  let n = 0;
  for (const it of items) {
    const p = paths.get(it.id.toLowerCase());
    if (p && seen[it.id] !== it.updated && n < 40) {
      try { n++; const u = "https://www.cisco.com/.well-known/csaf/" + p, a = P.parseCsaf(await fetchOne(u, { key: "cisco-csaf" }), { vendor: "Cisco", vkey: "cisco", csaf: u }); if (a) out.push(a); seen[it.id] = it.updated; }
      catch (e) { if (e.code === "budget") break; }
    }
  }
  const ids = new Set(items.map((i) => i.id));
  st.cisco = { read: Object.fromEntries(Object.entries(seen).filter(([k]) => ids.has(k))) };   // advisories read before stay in the store
  return { name: "Cisco PSIRT (RSS and CSAF)", advisories: out, note: `${items.length} in the feed, ${n} CSAF read` };
}
async function redhat(st) {
  // Red Hat regenerates old documents often too; a new advisory is one with a higher RHSA number than any read before
  const base = "https://security.access.redhat.com/data/csaf/v2/advisories/";
  const all = P.redhatNew(P.parseChanges(await fetchOne(base + "changes.csv", { as: "text", timeoutMs: 60000 }), base), (st.redhat ||= {}).after || 0);
  const todo = st.redhat.after ? all.slice(0, 25) : all.slice(-25), out = [];
  let n = 0, after = st.redhat.after || 0;
  for (const c of todo) {
    try { const a = P.parseCsaf(await fetchOne(c.url, { key: "redhat-csaf" }), { vendor: "Red Hat", vkey: "redhat", csaf: c.url }); n++; if (a && /^(Critical|Important)$/.test(a.severity)) out.push(a); after = c.n; }
    catch (e) { break; }   // read again next run
  }
  st.redhat = { after };
  return { name: "Red Hat (CSAF, Critical and Important)", advisories: out, note: `${n} of ${all.length} new advisories read` };
}
async function fortinet(st) {
  const items = P.parseFortinetRss(await fetchOne("https://www.fortiguard.com/rss/ir.xml", { as: "text" })), out = [], seen = (st.fortinet ||= {}).read || {};
  let n = 0;
  for (const it of items) {
    let a = P.fortinetFromRss(it);
    if (it.csaf && /^https:\/\/filestore\.fortinet\.com\//.test(it.csaf) && seen[it.id] !== it.published && n < 30) {
      try { n++; const c = P.parseCsaf(await fetchOne(it.csaf), { vendor: "Fortinet", vkey: "fortinet", csaf: it.csaf }); if (c && c.cves.length) a = { ...c, url: it.url, exploited: c.exploited || (a && a.exploited), exploited_cves: c.exploited ? c.exploited_cves : (a && a.exploited_cves) || [], exploited_text: c.exploited_text || (a && a.exploited_text) || "" }; seen[it.id] = it.published; }
      catch (e) { if (e.code === "budget") break; }
    }
    if (a) out.push(a);
  }
  st.fortinet.read = Object.fromEntries(Object.entries(seen).slice(-300));
  return { name: "Fortinet PSIRT (RSS and CSAF)", advisories: out, note: `${items.length} in the feed, ${n} CSAF read` };
}
async function paloalto(st) {
  const items = P.parsePanRss(await fetchOne("https://security.paloaltonetworks.com/rss.xml", { as: "text" })), out = [], seen = (st.paloalto ||= {}).read || {};
  let n = 0;
  for (const it of items) {
    let a = P.advisory({ vendor: "Palo Alto Networks", vkey: "paloalto", ...it, updated: it.published, source: "rss" });
    if (seen[it.id] !== it.published && n < 25) {
      try { n++; const u = `https://security.paloaltonetworks.com/csaf/${it.id}`, c = P.parseCsaf(await fetchOne(u), { vendor: "Palo Alto Networks", vkey: "paloalto", csaf: u });
        if (c) a = { ...c, id: it.id, url: it.url, title: it.title || c.title, severity: P.sevWord(it.severity) || c.severity }; seen[it.id] = it.published; }
      catch (e) { if (e.code === "budget") break; }
    }
    if (a) out.push(a);
  }
  st.paloalto.read = Object.fromEntries(Object.entries(seen).slice(-300));
  return { name: "Palo Alto Networks (RSS and CSAF)", advisories: out, note: `${items.length} in the feed, ${n} CSAF read` };
}
async function ubuntu() {
  const out = P.parseUbuntu(await fetchOne("https://ubuntu.com/security/notices.json?limit=20&offset=0", { timeoutMs: 90000 }));
  return { name: "Ubuntu security notices", advisories: out };
}
async function debian(st) {
  const items = P.parseDebianRdf(await fetchOne("https://www.debian.org/security/dsa-long", { as: "text" })), out = [], seen = (st.debian ||= {}).read || {};
  let n = 0;
  for (const it of items) {
    let r = seen[it.id];
    if (!r && n < 15) { try { n++; r = P.parseDebianTracker(await fetchOne(it.url, { as: "text" })); seen[it.id] = r; } catch (e) { if (e.code === "budget") break; } }
    if (r) { const a = P.advisory({ vendor: "Debian", vkey: "debian", ...it, cves: r.cves, fixed: r.fixed, updated: it.published, source: "html" }); if (a) out.push(a); }
  }
  st.debian.read = Object.fromEntries(Object.entries(seen).slice(-120));
  return { name: "Debian security advisories (DSA)", advisories: out, note: `${items.length} in the list, ${n} tracker page(s) read` };
}
async function oracle(st) {
  const items = P.parseOracleRss(await fetchOne("https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml", { as: "text" })), out = [], seen = (st.oracle ||= {}).read || {};
  const recent = items.filter((it) => Date.now() - Date.parse(it.published || 0) < 400 * 864e5);
  let n = 0;
  for (const it of recent) {
    let cves = seen[it.id];
    if (!cves && n < 3) { try { n++; cves = P.cvesIn(await fetchOne(it.url, { as: "text", timeoutMs: 90000 })); seen[it.id] = cves.length > 300 ? cves : cves; } catch (e) { if (e.code === "budget") break; } }
    const a = P.advisory({ vendor: "Oracle", vkey: "oracle", ...it, cves: [...new Set([...(it.cves || []), ...(cves || [])])], updated: it.published, source: "rss" });
    if (a) out.push(a);
  }
  st.oracle.read = Object.fromEntries(Object.entries(seen).slice(-30));
  return { name: "Oracle security alerts and patch updates", advisories: out, note: `${recent.length} in the last 400 days, ${n} page(s) read` };
}
async function chrome() {
  const out = P.parseChromeAtom(await fetchOne("https://chromereleases.googleblog.com/feeds/posts/default?redirect=false&max-results=40", { as: "text", timeoutMs: 90000 }));
  return { name: "Google Chrome releases", advisories: out };
}
async function apple(st) {
  const rel = P.parseAppleIndex(await fetchOne("https://support.apple.com/en-us/100100", { as: "text" })).filter((r) => Date.now() - Date.parse(r.date || 0) < 60 * 864e5);
  const seen = (st.apple ||= {}).read || {}, out = [];
  let n = 0;
  for (const r of rel) {
    // a page is read when new, and again while it is a week old (Apple adds "may have been exploited" notes after release)
    const fresh = Date.now() - Date.parse(r.date || 0) < 7 * 864e5, prev = seen[r.url];
    if ((!prev || (fresh && Date.now() - Date.parse(prev.at || 0) > 12 * 36e5)) && n < 12) {
      try { n++; const a = P.parseApplePage(await fetchOne(r.url, { as: "text" }), r.url, r.name); seen[r.url] = { at: seenAt, a }; } catch (e) { if (e.code === "budget") break; }
    }
    if (seen[r.url] && seen[r.url].a) out.push(seen[r.url].a);
  }
  st.apple.read = Object.fromEntries(Object.entries(seen).filter(([, v]) => Date.now() - Date.parse(v.at || 0) < 90 * 864e5));
  return { name: "Apple security releases", advisories: out, note: `${rel.length} release(s) in 60 days, ${n} page(s) read` };
}
async function mozilla(st) {
  const items = P.parseMozillaIndex(await fetchOne("https://www.mozilla.org/en-US/security/advisories/", { as: "text" })).slice(0, 12);
  const seen = (st.mozilla ||= {}).read || {}, out = [];
  let n = 0;
  for (const it of items) {
    if (!seen[it.id] && n < 8) { try { n++; seen[it.id] = P.parseMozillaPage(await fetchOne(it.url, { as: "text" }), it); } catch (e) { if (e.code === "budget") break; } }
    if (seen[it.id]) out.push(seen[it.id]);
  }
  st.mozilla.read = Object.fromEntries(Object.entries(seen).filter(([k]) => items.some((i) => i.id === k)));
  return { name: "Mozilla security advisories", advisories: out, note: `${items.length} listed, ${n} page(s) read` };
}
async function ivanti() {
  return { name: "Ivanti security advisories", advisories: P.parseIvantiRss(await fetchOne("https://www.ivanti.com/blog/topics/security-advisory/rss", { as: "text" })) };
}
export const SOURCES = { microsoft, cisco, fortinet, paloalto, redhat, ubuntu, debian, oracle, chrome, apple, mozilla, ivanti };

// ---------- the run ----------
async function collect(only) {
  mkdirSync(DIR, { recursive: true });
  const cur = readJson(FILE, { advisories: [], sources: {} }), st = readJson(STATE, {}), fresh = [], sources = { ...(cur.sources || {}) };
  const keys = Object.keys(SOURCES).filter((k) => !only.length || only.includes(k));
  await Promise.all(keys.map(async (k) => {
    try {
      const r = await SOURCES[k](st);
      const list = (r.advisories || []).filter(Boolean);
      fresh.push(...list);
      sources[k] = { name: r.name, ok: true, at: seenAt, n: list.length, exploited: list.filter((a) => a.exploited).length, ...(r.note ? { note: r.note } : {}) };
    } catch (e) {
      sources[k] = { ...(sources[k] || {}), ok: false, error: String(e.code || e.message).slice(0, 120), failed_at: seenAt };
    }
  }));
  const advisories = P.merge(cur.advisories, fresh);
  // one advisory per line: the data branch keeps history, so a change shows as the lines that changed
  writeFileSync(FILE, '{"updated_at":' + JSON.stringify(seenAt) + ',"sources":' + JSON.stringify(sources) + ',"advisories":[\n' + advisories.map((a) => JSON.stringify(a)).join(",\n") + "\n]}\n");
  // leads: the vendor's own exploited statement, or a critical advisory for widely used software; each once
  const filed = new Set(st.leads_filed || []), leadsDir = join(DATA, "leads"), known = new Set();
  mkdirSync(leadsDir, { recursive: true });
  for (const f of readdirSync(leadsDir).filter((f) => f.endsWith(".jsonl")).sort().slice(-3)) for (const l of readFileSync(join(leadsDir, f), "utf8").split("\n")) { try { known.add(JSON.parse(l).url); } catch {} }
  const leads = [];
  for (const a of fresh.slice().sort((x, y) => (y.exploited ? 1 : 0) - (x.exploited ? 1 : 0))) {
    const key = `${a.vkey}|${a.id}|${a.exploited ? "x" : "c"}`;
    if (!P.leadWorthy(a) || filed.has(key) || leads.length >= 40) continue;   // at most 40 a run; the rest next run
    filed.add(key);
    if (!known.has(a.url)) { leads.push(P.toLead(a, seenAt)); known.add(a.url); }
  }
  if (leads.length) appendFileSync(join(leadsDir, `${seenAt.slice(0, 10)}.jsonl`), leads.map((l) => JSON.stringify(l)).join("\n") + "\n");
  st.leads_filed = [...filed].slice(-3000);
  writeJson(STATE, st);
  const s = readStatus(); s.last_psirt_at = seenAt;
  s.psirt_note = `${advisories.length} advisories from ${Object.values(sources).filter((x) => x.ok).length} of ${Object.keys(sources).length} sources; ${advisories.filter((a) => a.exploited).length} with the vendor's own exploited statement`;
  writeJson(join(DATA, "status.json"), s);
  for (const k of keys) { const x = sources[k]; console.log(`  ${k.padEnd(10)} ${x.ok ? `ok   ${String(x.n).padStart(4)} advisories, ${x.exploited} exploited${x.note ? "  (" + x.note + ")" : ""}` : `FAIL ${x.error}`}`); }
  console.log(`PSIRT: ${advisories.length} advisories kept (${fresh.length} read this run), ${leads.length} new lead(s), ${Math.round((Date.now() - T0) / 1000)} s.`);
  if (keys.length && keys.every((k) => !sources[k].ok)) process.exitCode = 1;   // every source failed: say so; the workflow carries on
}

function stats() {
  const cur = readJson(FILE, { advisories: [], sources: {} }), by = {};
  for (const a of cur.advisories) { const b = (by[a.vkey] ||= { n: 0, x: 0, cves: new Set() }); b.n++; if (a.exploited) b.x++; a.cves.forEach((c) => b.cves.add(c)); }
  console.log(`PSIRT advisories (${cur.updated_at || "never"}):`);
  for (const [k, b] of Object.entries(by)) console.log(`  ${k.padEnd(10)} ${String(b.n).padStart(5)} advisories, ${String(b.cves.size).padStart(5)} CVEs, ${b.x} exploited`);
  for (const [k, s] of Object.entries(cur.sources || {})) if (!s.ok) console.log(`  ${k}: failing (${s.error}) since ${s.failed_at}`);
}

async function main() {
  const args = process.argv.slice(2), cmd = args[0] && !args[0].startsWith("--") ? args[0] : "collect";
  const oi = args.indexOf("--only"), only = oi >= 0 ? String(args[oi + 1] || "").split(",").filter(Boolean) : [];
  if (cmd === "collect") return collect(only);
  if (cmd === "stats") return stats();
  if (cmd === "get") {
    const q = String(args[1] || "").toUpperCase(), cur = readJson(FILE, { advisories: [] });
    console.log(JSON.stringify(cur.advisories.filter((a) => a.id.toUpperCase() === q || a.cves.includes(q)), null, 2)); return;
  }
  console.error("usage: psirt.mjs [collect] [--only microsoft,cisco,...] | stats | get <CVE or advisory id>"); process.exit(1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
