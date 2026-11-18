// Unit tests for the alert matcher and the email (CASL elements, escaping).
import { test } from "node:test";
import assert from "node:assert/strict";
import { due, matches, compose } from "../../scripts/alerts.mjs";

const now = Date.parse("2026-11-18T18:00:00Z");
const r = { user_id: "u1", alert_terms: ["Fortinet", "SAP"], alert_frequency: "daily", alert_min_severity: 2, unsubscribe_token: "11111111-2222-3333-4444-555555555555", last_alert_at: "2026-11-17T18:00:00Z" };
const bundle = {
  events: [
    { id: "a", title: "Fortinet FortiOS flaw exploited", severity: 3, status: "confirmed", first_seen: "2026-11-18T10:00:00Z", date: "2026-11-18", products: ["FortiOS"], action: "Patch now" },
    { id: "b", title: "Sapphire Rapids microcode note", severity: 3, status: "confirmed", first_seen: "2026-11-18T10:00:00Z", date: "2026-11-18" },
    { id: "c", title: "SAP NetWeaver advisory", severity: 1, status: "official", first_seen: "2026-11-18T10:00:00Z", date: "2026-11-18" },
    { id: "d", title: "Fortinet customer listed by gang", severity: 2, status: "claimed", first_seen: "2026-11-18T10:00:00Z", date: "2026-11-18" },
    { id: "e", title: "Fortinet old story", severity: 3, status: "confirmed", first_seen: "2026-11-10T10:00:00Z", date: "2026-11-10" },
    { id: "f", title: "<img src=x onerror=alert(1)> SAP", severity: 2, status: "confirmed", first_seen: "2026-11-18T11:00:00Z", date: "2026-11-18" },
  ],
  kev: [{ cve: "CVE-2026-1", vendor: "SAP", product: "NetWeaver", name: "x", added: "2026-11-18", due: "2026-12-09" }, { cve: "CVE-2026-2", vendor: "Fortinet", product: "x", added: "2026-11-01" }],
};

test("due: frequencies", () => {
  assert.equal(due({ ...r, last_alert_at: null }, now), true);
  assert.equal(due({ ...r, alert_frequency: "daily", last_alert_at: "2026-11-18T00:00:00Z" }, now), false);
  assert.equal(due({ ...r, alert_frequency: "daily", last_alert_at: "2026-11-17T18:00:00Z" }, now), true);
  assert.equal(due({ ...r, alert_frequency: "weekly", last_alert_at: "2026-11-15T00:00:00Z" }, now), false);
  assert.equal(due({ ...r, alert_frequency: "instant", last_alert_at: "2026-11-18T17:59:00Z" }, now), true);
});

test("matches: whole words, new only, severity floor, no claims, no repeats", () => {
  const ids = matches(r, bundle, new Set(), now).map((x) => x.id);
  assert.deepEqual(ids.sort(), ["a", "f", "kev-CVE-2026-1"].sort());
  assert.deepEqual(matches(r, bundle, new Set(["a", "f", "kev-CVE-2026-1"]), now), []);
});

test("compose: CASL elements present and HTML escaped", () => {
  const items = matches(r, bundle, new Set(), now);
  const m = compose(r, items, { owner_name: "the CyberView maintainer", mailing_address: "PO Box 1, Toronto ON", contact_email: "privacy@example.test" });
  for (const part of [m.text, m.html]) {
    assert.match(part, /CyberView, run by the CyberView maintainer/);
    assert.match(part, /PO Box 1, Toronto ON/);
    assert.match(part, /unsubscribe\.html\?t=11111111-2222-3333-4444-555555555555/);
    assert.match(part, /You get this because you turned on/);
  }
  assert.ok(!m.html.includes("<img src=x"), "event text is escaped in the HTML email");
  assert.match(m.headers["List-Unsubscribe"], /^<https:\/\/.+unsubscribe\.html\?t=.+>, <mailto:privacy@example\.test\?subject=unsubscribe>$/);
  assert.match(m.subject, /^CyberView: 3 new matches/);
});
