// Proves a build is safe to publish, and that what is live is what was built. No AI model.
//   node scripts/verify-build.mjs                 check site/data after a build: every file parses and has the expected shape,
//                                                the manifest's fingerprints match the files, nothing essential is empty
//   node scripts/verify-build.mjs --against-live  also compare with the live site: refuse a build that has lost a large share
//                                                of the events or known-exploited entries (set ALLOW_SHRINK=1 to override on purpose)
//   node scripts/verify-build.mjs --live          after deploying: fetch the live manifest and bundle (retrying for up to 4 minutes)
//                                                and confirm they are byte-for-byte the build in site/data
// Exit 0 = verified. Exit 1 = do not publish (or: the deploy did not take). The previous deployment stays live when this fails.
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT } from "./lib/store.mjs";
import { SITE_URL } from "./lib/site-url.mjs";

const OUT = join(ROOT, "site", "data");
const SITE = SITE_URL;
const CATS = ["incident", "outage", "vuln", "report", "policy", "investment", "enforcement"];
const sha = (b) => createHash("sha256").update(b).digest("hex");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Shape checks on the parsed outputs. files: { "bundle.json": object, ... } -> list of problems. */
export function checkOutputs(files, now = Date.now()) {
  const p = [], need = (name) => { if (!files[name] || typeof files[name] !== "object") { p.push(`${name} is missing or not JSON`); return null; } return files[name]; };
  const b = need("bundle.json");
  if (b) {
    if (!Array.isArray(b.events) || !b.events.length) p.push("bundle.json has no events");
    else {
      const bad = b.events.filter((e) => !e || !/^[a-z0-9][a-z0-9-]{2,119}$/.test(e.id || "") || typeof e.title !== "string" || !e.title.trim() || !/^\d{4}-\d{2}-\d{2}$/.test(e.date || "") || !CATS.includes(e.category) || ![1, 2, 3].includes(e.severity));
      if (bad.length) p.push(`bundle.json: ${bad.length} event(s) lack an id, title, date, category or severity (first: ${JSON.stringify(bad[0] && bad[0].id)})`);
      if (new Set(b.events.map((e) => e.id)).size !== b.events.length) p.push("bundle.json: an event id appears twice");
    }
    if (!Array.isArray(b.kev)) p.push("bundle.json: kev is not a list");
    if (!b.docs || typeof b.docs !== "object") p.push("bundle.json: docs is missing");
    const age = (now - Date.parse(b.built_at)) / 6e4;
    if (!isFinite(age) || age > 30 || age < -5) p.push(`bundle.json: built_at is ${isFinite(age) ? Math.round(age) + " minutes old" : "not a time"}; the build is not fresh`);
  }
  const idx = need("archive/index.json");
  if (idx && b && Array.isArray(b.events) && !(idx.total >= b.events.length)) p.push(`archive/index.json: total ${idx.total} is smaller than the bundle's ${b.events.length} events`);
  const s = need("archive/search.json"); if (s && (!Array.isArray(s.rows) || (idx && s.rows.length !== idx.total))) p.push("archive/search.json: rows do not match the archive total");
  const w = need("workbench.json"); if (w && (!Array.isArray(w.kev) || typeof w.guides !== "object")) p.push("workbench.json: kev or guides missing");
  const o = need("ops.json"); if (o && (!Array.isArray(o.routines) || !o.routines.length)) p.push("ops.json: no routines");
  const c = need("chat.json"); if (c && (!Array.isArray(c.posts) || c.posts.some((x) => !x || !x.reviewed_at))) p.push("chat.json: a post without a review is in the feed");
  need("trends.json"); need("tabletop.json"); need("health.json"); need("feed.json");
  return p;
}

/** Refuse a build that lost a large share of what is live. counts: { events_total, events_bundle, kev_total }. */
export function checkShrink(local, live) {
  const p = [];
  if (!live || !local) return p;
  const drop = (k, max) => { const a = Number(live[k]), b = Number(local[k]); if (a >= 20 && b < a * (1 - max)) p.push(`${k} fell from ${a} (live) to ${b}: more than ${Math.round(max * 100)}% lost`); };
  drop("events_total", 0.05);   // events are never deleted, so the total on file should only grow
  drop("events_bundle", 0.5);   // the seven-day window moves, but it should not halve between builds
  drop("kev_total", 0.05);
  return p;
}

function readLocal() {
  const problems = [], files = {};
  const mp = join(OUT, "manifest.json");
  if (!existsSync(mp)) return { problems: ["site/data/manifest.json is missing: run node scripts/build.mjs first"], files, manifest: null };
  const manifest = JSON.parse(readFileSync(mp, "utf8"));
  for (const [name, meta] of Object.entries(manifest.files || {})) {
    const fp = join(OUT, name);
    if (!existsSync(fp)) { problems.push(`${name} is in the manifest but not on disk`); continue; }
    const buf = readFileSync(fp);
    if (buf.length !== meta.bytes || sha(buf) !== meta.sha256) problems.push(`${name} does not match its fingerprint in the manifest`);
    if (name.endsWith(".json")) { try { files[name] = JSON.parse(buf.toString("utf8")); } catch { problems.push(`${name} is not valid JSON`); } }
  }
  return { problems, files, manifest };
}

async function fetchLive(path, as = "json") {
  const r = await fetch(`${SITE}/data/${path}?t=${Date.now()}`, { headers: { "cache-control": "no-cache", "user-agent": "cyberview-verify/1.0" }, signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return as === "json" ? r.json() : Buffer.from(await r.arrayBuffer());
}

async function main() {
  const { problems, files, manifest } = readLocal();
  if (manifest) problems.push(...checkOutputs(files));
  const mode = process.argv[2] || "";
  if (manifest && mode === "--against-live") {
    try {
      const lm = await fetchLive("manifest.json").catch(async () => { const b = await fetchLive("bundle.json"), i = await fetchLive("archive/index.json"); return { counts: { events_bundle: b.events.length, events_total: i.total, kev_total: i.kev_total } }; });
      const s = checkShrink(manifest.counts, lm.counts);
      if (s.length && process.env.ALLOW_SHRINK !== "1") problems.push(...s.map((x) => `refusing to publish a shrunken dataset: ${x}`));
      else if (s.length) console.log("shrink allowed by ALLOW_SHRINK=1: " + s.join("; "));
      else console.log(`against live: ${lm.counts.events_total} -> ${manifest.counts.events_total} events on file, ${lm.counts.kev_total} -> ${manifest.counts.kev_total} known-exploited`);
    } catch (e) { console.log(`against live: the live site could not be read (${e.message}); comparison skipped, local checks still apply`); }
  }
  if (manifest && mode === "--live") {
    let last = "";
    for (let i = 0; i < 16; i++) {   // Pages takes a moment to serve a new deployment
      try {
        const lm = await fetchLive("manifest.json");
        if (lm.built_at === manifest.built_at) {
          const lb = await fetchLive("bundle.json", "buffer"), want = manifest.files["bundle.json"];
          if (sha(lb) === want.sha256) { console.log(`live verified: ${SITE} serves the build of ${manifest.built_at} (${manifest.counts.events_bundle} events, bundle fingerprint matches)`); last = ""; break; }
          last = "the live bundle's fingerprint differs from the build";
        } else if (String(lm.built_at || "") > String(manifest.built_at)) {
          // a newer run's build is already live: this build's data is in it, nothing is left behind
          console.log(`live verified: ${SITE} already serves a newer build (${lm.built_at}) than this one (${manifest.built_at})`); last = ""; break;
        } else last = `live is still the build of ${lm.built_at}`;
      } catch (e) { last = `live site not readable: ${e.message}`; }
      await sleep(15000);
    }
    if (last) problems.push(`deploy not confirmed after 4 minutes: ${last}`);
  }
  if (problems.length) { problems.forEach((x) => console.error("verify: " + x)); console.error(`\nVerification failed: ${problems.length} problem(s).`); process.exit(1); }
  console.log(`verified: ${Object.keys(manifest.files).length} data files match the manifest; ${manifest.counts.events_bundle} events in the bundle, ${manifest.counts.events_total} on file, ${manifest.counts.quarantined} quarantined`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
