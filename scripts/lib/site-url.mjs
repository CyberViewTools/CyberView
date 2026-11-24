// The site's public address, in one place (pen test, 2026-11-24: moving to its own domain must be a one-line change).
// Order: the SITE_URL environment variable (the workflows pass the repository variable vars.SITE_URL), then
// config/site.json site_url, then the GitHub Pages address. No trailing slash.
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT = "https://cyberview.tools";
function fromConfig() {
  try { return String(JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "config", "site.json"), "utf8")).site_url || ""); } catch { return ""; }
}
/** Pure: the address from the given sources, validated (https only), without a trailing slash. */
export function siteUrl(env = process.env.SITE_URL, conf = fromConfig()) {
  for (const v of [env, conf, DEFAULT]) { const s = String(v || "").trim().replace(/\/+$/, ""); if (/^https:\/\/[a-z0-9.-]+(\/[A-Za-z0-9._-]+)*$/i.test(s)) return s; }
  return DEFAULT;
}
export const SITE_URL = siteUrl();
export const SITE_HOST = new URL(SITE_URL).hostname;
