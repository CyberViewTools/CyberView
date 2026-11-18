// Builds site/data/bundle.json from the data/ folder. Run: node scripts/build.mjs
// The page reads only the bundle. Every record is validated here first; a bad file fails the build (exit 1) instead of reaching the site.
import { readFileSync, readdirSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DATA = join(ROOT, "data"), OUT = join(ROOT, "site", "data");
const WINDOW_DAYS = 9, KEV_DAYS = 45;
const CATS = ["incident", "outage", "vuln", "report", "policy", "investment", "enforcement"];
const STATUS = ["confirmed", "official", "developing", "claimed"];
const TAGS = ["ransomware","data-breach","supply-chain","zero-day","ddos","espionage","critical-infrastructure","ai-enabled","third-party","phishing","insider","hacktivism","ot-ics","cloud","identity","fraud","takedown","regulation","funding","acquisition"];
const errors = [], warnings = [];
const day = (n) => new Date(Date.now() - n * 864e5).toISOString().slice(0, 10);

function readDir(dir) {
  const p = join(DATA, dir);
  if (!existsSync(p)) return [];
  return readdirSync(p).filter((f) => f.endsWith(".json")).map((f) => {
    const id = f.slice(0, -5);
    try { return { id, ...JSON.parse(readFileSync(join(p, f), "utf8")) }; }
    catch (e) { errors.push(`${dir}/${f}: not valid JSON (${e.message})`); return null; }
  }).filter(Boolean);
}
function readDoc(name) {
  const p = join(DATA, name);
  if (!existsSync(p)) return null;
  try { return JSON.parse(readFileSync(p, "utf8")); } catch (e) { errors.push(`${name}: not valid JSON (${e.message})`); return null; }
}
function checkEvent(e) {
  const where = `events/${e.id}.json`;
  if (!/^[a-z0-9][a-z0-9-]{2,119}$/.test(e.id)) errors.push(`${where}: file name must be lowercase letters, digits and hyphens`);
  if (typeof e.title !== "string" || !e.title.trim()) errors.push(`${where}: missing title`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(e.date || "")) errors.push(`${where}: date must be YYYY-MM-DD`);
  if (!CATS.includes(e.category)) errors.push(`${where}: category "${e.category}" is not one of ${CATS.join(", ")}`);
  if (![1, 2, 3].includes(e.severity)) errors.push(`${where}: severity must be 1, 2 or 3`);
  if (e.status && !STATUS.includes(e.status)) errors.push(`${where}: status "${e.status}" is not one of ${STATUS.join(", ")}`);
  if (e.lat != null && (typeof e.lat !== "number" || e.lat < -90 || e.lat > 90)) errors.push(`${where}: lat out of range`);
  if (e.lng != null && (typeof e.lng !== "number" || e.lng < -180 || e.lng > 180)) errors.push(`${where}: lng out of range`);
  for (const k of ["sources", "tags", "cves", "products", "attack"]) if (e[k] != null && !Array.isArray(e[k])) errors.push(`${where}: ${k} must be a list`);
  (e.sources || []).forEach((s) => { if (!s || !/^https?:\/\//.test(s.url || "")) errors.push(`${where}: every source needs an http(s) url`); });
  (e.tags || []).forEach((t) => { if (!TAGS.includes(t)) warnings.push(`${where}: tag "${t}" is not on the list and will be ignored`); });
  if (e.date > day(-1)) errors.push(`${where}: date is in the future`);
  if (e.status === "claimed" && e.severity !== 1) warnings.push(`${where}: unverified claims should be severity 1`);
}

const allEvents = readDir("events");
allEvents.forEach(checkEvent);
const events = allEvents.filter((e) => e.date >= day(WINDOW_DAYS) && !e.duplicate_of);
const kev = readDir("kev").filter((k) => (k.added || "") >= day(KEV_DAYS));
const corrections = readDir("corrections").sort((a, b) => (a.at < b.at ? 1 : -1)).slice(0, 50);
const docs = {};
for (const [path, file] of [["meta/status", "status.json"], ["analysis/latest", "analysis.json"], ["analysis/ripples", "ripples.json"], ["brief/latest", "brief.json"], ["stats/history", "history.json"]]) {
  const d = readDoc(file); if (d) docs[path] = d;
}
warnings.forEach((w) => console.warn("warning: " + w));
if (errors.length) { errors.forEach((e) => console.error("error: " + e)); console.error(`\nBuild failed: ${errors.length} problem(s). Nothing was written.`); process.exit(1); }

mkdirSync(OUT, { recursive: true });
const bundle = { built_at: new Date().toISOString(), events, kev, corrections, docs };
writeFileSync(join(OUT, "bundle.json"), JSON.stringify(bundle));
console.log(`Built site/data/bundle.json: ${events.length} events (of ${allEvents.length} on file), ${kev.length} known-exploited, ${corrections.length} corrections, docs: ${Object.keys(docs).join(", ") || "none"}.`);
