// Visitor analytics (owner, 2026-11-24): Cloudflare Web Analytics, which Cloudflare injects into pages served through
// its proxy (cyberview.tools). It sets no cookies and no local storage; the beacon reports the page address, referrer,
// browser and device type, country (from the IP address) and load timings. Disclosed in legal/privacy.html.
// The site's Content-Security-Policy allows exactly these two Cloudflare hosts and nothing else, and NOT on the pages
// where a visitor's own data lives (their software list, their account): there the beacon stays blocked, so nothing
// about those pages ever leaves the browser. scripts/security-check.mjs enforces both lists.
export const ANALYTICS = {
  provider: "Cloudflare Web Analytics",
  script: "https://static.cloudflareinsights.com",
  beacon: "https://cloudflareinsights.com",
  excluded: ["vulnerabilities.html", "workbench.html", "cve.html", "account.html", "unsubscribe.html"],
};
/** Pure: does this page (file name) allow the analytics beacon? */
export const analyticsOn = (file) => !ANALYTICS.excluded.includes(String(file).replace(/^.*\//, ""));
/** Pure: a page's CSP with the analytics hosts added where allowed. */
export function withAnalytics(csp, file) {
  if (!analyticsOn(file)) return csp;
  return csp.replace("script-src 'self'", `script-src 'self' ${ANALYTICS.script}`).replace("connect-src 'self'", `connect-src 'self' ${ANALYTICS.beacon}`);
}
