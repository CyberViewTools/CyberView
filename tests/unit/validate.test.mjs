import { test } from "node:test";
import assert from "node:assert/strict";
import { checkAttribution, checkLinks, checkTabletop } from "../../scripts/lib/validate.mjs";

const attr = { actor: "APT29", origin_country: "Russia", lat: 55.75, lng: 37.62, by: "UK NCSC", by_type: "government", url: "https://www.ncsc.gov.uk/news/advisory-apt29" };

test("attribution: a government attribution with its page passes", () => {
  assert.deepEqual(checkAttribution(attr), []);
  assert.deepEqual(checkAttribution(undefined), []);
});
test("attribution: attacker boasts, front pages and bad coordinates are refused", () => {
  assert.ok(checkAttribution({ ...attr, by_type: "attacker" }).some((m) => /by_type/.test(m)));
  assert.ok(checkAttribution({ ...attr, url: "https://www.ncsc.gov.uk/" }).some((m) => /url/.test(m)));
  assert.ok(checkAttribution({ ...attr, url: "http://www.ncsc.gov.uk/x" }).some((m) => /url/.test(m)));
  assert.ok(checkAttribution({ ...attr, lat: 120 }).some((m) => /lat/.test(m)));
  assert.ok(checkAttribution([]).length);
});

test("links: must point at a known event with a stating page", () => {
  const known = new Set(["acme-breach-2026-11", "beta-hit-2026-11"]);
  assert.deepEqual(checkLinks([{ to: "beta-hit-2026-11", rel: "customer of breached supplier", url: "https://example.com/story" }], "acme-breach-2026-11", known), []);
  assert.ok(checkLinks([{ to: "missing-one", rel: "x", url: "https://example.com/a" }], "acme-breach-2026-11", known)[0].includes("not an event on file"));
  assert.ok(checkLinks([{ to: "acme-breach-2026-11", rel: "x", url: "https://example.com/a" }], "acme-breach-2026-11", known)[0].includes("itself"));
  assert.ok(checkLinks([{ to: "beta-hit-2026-11", rel: "", url: "javascript:alert(1)" }], "acme-breach-2026-11", known).length === 2);
  assert.ok(checkLinks("nope").length);
});

const ex = () => ({
  label: "exercise", generated_at: "2026-11-20T15:40:00Z", date: "2026-11-20", title: "Exercise: a supplier's breach reaches you",
  based_on: ["acme-breach-2026-11"], real_story: "A software supplier was breached and customer data was taken.",
  facts: [{ text: "The supplier confirmed the breach.", source_url: "https://example.com/a" }, { text: "About 40 customers were affected.", source_url: "https://example.com/b" }],
  scenario: "Your organisation uses the supplier's hosted service.", duration_min: 60, roles: ["Incident lead", "Communications"],
  injects: [{ at_min: 0, title: "First signal", text: "A customer emails." }, { at_min: 15, title: "Confirmation", text: "The supplier confirms.", ask: "Who decides?" }, { at_min: 30, title: "Media", text: "A reporter calls." }],
  questions: ["a?", "b?", "c?", "d?"], good_looks_like: ["x", "y", "z"], sources: [{ name: "Example", url: "https://example.com/a" }],
});

test("tabletop: a complete exercise passes", () => {
  assert.deepEqual(checkTabletop(ex(), new Set(["acme-breach-2026-11"])), []);
});
test("tabletop: must be labelled as an exercise and built on a real event on file", () => {
  assert.ok(checkTabletop({ ...ex(), label: "incident" }).some((m) => /label/.test(m)));
  assert.ok(checkTabletop(ex(), new Set(["other"])).some((m) => /not an event on file/.test(m)));
});
test("tabletop: facts need sources, injects need time order", () => {
  const a = ex(); a.facts[0].source_url = "https://example.com/";
  assert.ok(checkTabletop(a).some((m) => /facts\[0\]\.source_url/.test(m)));
  const b = ex(); b.injects[2].at_min = 5;
  assert.ok(checkTabletop(b).some((m) => /out of time order/.test(m)));
  const c = ex(); c.injects = c.injects.slice(0, 2);
  assert.ok(checkTabletop(c).some((m) => /3 to 10/.test(m)));
  const d = ex(); d.questions = ["one"];
  assert.ok(checkTabletop(d).some((m) => /questions/.test(m)));
});
