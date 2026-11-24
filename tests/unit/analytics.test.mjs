// Visitor analytics (scripts/lib/analytics.mjs): Cloudflare's two hosts only, never on the visitor-data pages.
import { test } from "node:test";
import assert from "node:assert/strict";
import { withAnalytics, analyticsOn, ANALYTICS } from "../../scripts/lib/analytics.mjs";
const CSP = "default-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'";
test("analytics hosts are added to ordinary pages and never to the software-list or account pages", () => {
  assert.equal(withAnalytics(CSP, "index.html"), "default-src 'self'; script-src 'self' https://static.cloudflareinsights.com; connect-src 'self' https://cloudflareinsights.com; base-uri 'none'");
  for (const f of ["vulnerabilities.html", "workbench.html", "cve.html", "account.html", "site/unsubscribe.html"]) { assert.equal(analyticsOn(f), false, f); assert.equal(withAnalytics(CSP, f), CSP, f); }
  assert.ok(ANALYTICS.script.startsWith("https://") && ANALYTICS.beacon.startsWith("https://"));
});
