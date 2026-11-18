// Unit tests for the mechanical routines added for the agent desks: lead triage rules and link classification.
import { test } from "node:test";
import assert from "node:assert/strict";
import { reason, matchEvent, NOT_EVENT } from "../../scripts/triage.mjs";
import { classify } from "../../scripts/linkcheck.mjs";

const evs = [
  { id: "cisa-java4shell-alert-cve-2026-114938-2026-11", title: "CISA alert: Java4Shell flaw CVE-2026-114938 exploited", org: "Oracle", cves: ["CVE-2026-114938"] },
  { id: "uber-third-party-breach-2026-11", title: "Uber data breach affects 150,000 people through a third-party provider", org: "Uber", cves: [] },
];

test("triage: same CVE or most words in common means already on file", () => {
  assert.equal(matchEvent("CVE-2026-114938: critical vulnerability in OpenJDK Java", evs).id, evs[0].id);
  assert.equal(matchEvent("Uber data breach affects 150,000 people", evs).id, evs[1].id);
  assert.equal(matchEvent("Uber launches new delivery app in Brazil", evs), null);
  assert.equal(matchEvent("Data breach", evs), null, "too short to judge");
});

test("triage: obvious non-events, expiry, and leaving real leads open", () => {
  const today = "2026-11-18";
  assert.match(reason({ title: "Webinar: securing your cloud in 2027", published: "2026-11-18" }, evs, today), /not an event/);
  assert.match(reason({ title: "Week in review: ransomware, patches and more", published: "2026-11-18" }, evs, today), /not an event/);
  assert.match(reason({ title: "Hospital network hit by ransomware", published: "2026-11-10" }, evs, today), /expired/);
  assert.equal(reason({ title: "Hospital network in Lyon hit by ransomware", published: "2026-11-17" }, evs, today), "");
  assert.ok(!NOT_EVENT.test("Fortinet patches exploited FortiWeb flaw"));
});

test("link check: only gone pages count as broken", () => {
  assert.equal(classify(404, ""), "broken");
  assert.equal(classify(410, ""), "broken");
  assert.equal(classify(0, "ENOTFOUND"), "broken");
  assert.equal(classify(200, ""), "ok");
  assert.equal(classify(301, ""), "ok");
  assert.equal(classify(403, ""), "blocked", "sites that refuse robots are not broken");
  assert.equal(classify(503, ""), "blocked");
  assert.equal(classify(0, "UND_ERR_CONNECT_TIMEOUT"), "blocked");
});
