import { test } from "node:test";
import assert from "node:assert/strict";
import { problems, entryProblems, groups, requestText, accessSection, load, REQUEST, WHY } from "../../scripts/access.mjs";

const good = { key: "example-power", operator: "Example Power", feed: "Example Power outage map", country: "US", region: "Ohio", what: "outage map feed",
  customers_served: 1000, why_not: "terms", detail: 'Terms: "personal use only".', contact: "", status: "not_asked", updated: "2026-11-20" };

test("access: a well-formed entry has no problems", () => assert.deepEqual(entryProblems(good), []));

test("access: enums, sizes, country and dates are enforced", () => {
  const p = (o) => entryProblems({ ...good, ...o });
  assert.ok(p({ why_not: "rude" }).some((x) => /why_not/.test(x)));
  assert.ok(p({ status: "maybe" }).some((x) => /status/.test(x)));
  assert.ok(p({ detail: "x".repeat(201) }).some((x) => /detail is longer than 200/.test(x)));
  assert.ok(p({ detail: "<b>x</b>" }).some((x) => /plain text/.test(x)));
  assert.ok(p({ country: "XX" }).some((x) => /country/.test(x)));
  assert.ok(p({ customers_served: -5 }).some((x) => /customers_served/.test(x)));
  assert.deepEqual(p({ customers_served: null }), []);
  assert.ok(p({ updated: "soon" }).some((x) => /updated/.test(x)));
  assert.ok(p({ key: "Bad Key" }).some((x) => /key/.test(x)));
  assert.ok(p({ operator: "" }).some((x) => /operator is required/.test(x)));
});

test("access: contact is empty, an email address or an https page, nothing else", () => {
  assert.deepEqual(entryProblems({ ...good, contact: "Opendata@example.com" }), []);
  assert.deepEqual(entryProblems({ ...good, contact: "https://data.example.com/" }), []);
  assert.ok(entryProblems({ ...good, contact: "javascript:alert(1)" }).some((x) => /contact/.test(x)));
  assert.ok(entryProblems({ ...good, contact: "http://example.com" }).some((x) => /contact/.test(x)));
});

test("access: duplicate keys and a missing list are refused", () => {
  assert.ok(problems({ sources: [good, good] }).some((x) => /duplicate key/.test(x)));
  assert.ok(problems({}).length === 1);
});

test("access: countries with most sources first, biggest customers first inside, unknown counts last", () => {
  const s = (key, country, c) => ({ ...good, key, operator: key, country, customers_served: c });
  const g = groups([s("a", "CA", 5), s("b", "US", null), s("c", "US", 10), s("d", "US", 99)]);
  assert.deepEqual(g.map((x) => x.country), ["US", "CA"]);
  assert.deepEqual(g[0].sources.map((x) => x.key), ["d", "c", "b"]);
  assert.equal(g[0].name, "United States");
});

test("access: the request names the operator and the feed, promises the limits and asks first", () => {
  const t = requestText(good);
  assert.ok(t.includes("credit Example Power") && t.includes("your Example Power outage map"));
  assert.ok(!/\[operator\]|\[feed\]/.test(t));
  for (const w of ["non-commercial", "robots.txt", "never works around a block", "no personal data", "every few minutes", "stop if you ask"]) assert.ok(t.includes(w), w);
  assert.ok(REQUEST.length < 1400, "the request stays short");
});

test("access: the rendered section escapes every value and leaves broken entries out", () => {
  const evil = { ...good, key: "evil", operator: 'A"><img src=x onerror=1>', feed: "<script>" };
  const html = accessSection({ sources: [good, evil, { ...good, key: "broken", why_not: "nope" }] });
  assert.ok(!/<img|<script>|onerror=1"/.test(html));
  assert.ok(html.includes('id="src-example-power"') && !html.includes('id="src-broken"'));
  assert.ok(/Copy request/.test(html) && /never sends anything/.test(html));
});

test("access: the real config/data-access.json checks out and covers every reason", () => {
  const doc = load();
  assert.deepEqual(problems(doc), []);
  assert.ok(doc.sources.length >= 100);
  for (const w of Object.keys(WHY)) assert.ok(doc.sources.some((s) => s.why_not === w), w);
  assert.ok(doc.sources.every((s) => s.status === "not_asked" || s.updated));
});
