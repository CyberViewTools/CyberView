// scripts/x-leads.mjs — X (Twitter) as a lead source only (Route B, Grok handoff). Pure functions only; no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseHandoff, cleanXLead, ingest, registry, config, SOCIAL_HOST } from "../../scripts/x-leads.mjs";
import { checkEventQuality, SOCIAL_SRC } from "../../scripts/lib/validate.mjs";

const AT = "2026-11-22T12:00:00Z";
// a tiny registry: one active curated account, one inactive
const REG = registry({ accounts: [
  { username: "CISAgov", x_user_id: "2228198189", display: "CISA", tier: "gov", lang: "en", active: true },
  { username: "campuscodi", display: "Catalin", tier: "research", lang: "en", active: false },
] });
const CFG = config();

test("parseHandoff reads a fenced ```json block from an issue body", () => {
  const body = "Grok Bot batch, 2026-11-22\n\n```json\n[{\"x_post_id\":\"1\",\"handle\":\"CISAgov\",\"title\":\"a\"}]\n```\nthanks";
  const a = parseHandoff(body);
  assert.equal(a.length, 1);
  assert.equal(a[0].handle, "CISAgov");
});

test("parseHandoff reads a bare JSON array and a {leads:[...]} wrapper", () => {
  assert.equal(parseHandoff('[{"x_post_id":"1"}]').length, 1);
  assert.equal(parseHandoff('{"leads":[{"x_post_id":"1"},{"x_post_id":"2"}]}').length, 2);
  assert.deepEqual(parseHandoff("no json here"), []);
});

test("cleanXLead: a CISAgov post with a .gov linked_url becomes a standard lead", () => {
  const { lead, drop } = cleanXLead({
    x_post_id: "1859200000000000001", handle: "CISAgov",
    title: "CISA releases advisory on an exploited vulnerability",
    url: "https://x.com/CISAgov/status/1859200000000000001",
    linked_url: "https://www.cisa.gov/news-events/alerts/2026/11/22/example",
    summary: "Patch now.", lang: "en",
  }, REG, AT);
  assert.equal(drop, undefined);
  assert.equal(lead.via, "x");
  assert.equal(lead.kind, "x-post");
  assert.equal(lead.tier, "gov");
  assert.equal(lead.handle, "CISAgov");
  assert.equal(lead.x_post_id, "1859200000000000001");
  assert.equal(lead.x_user_id, "2228198189"); // filled from the registry
  assert.equal(lead.linked_url, "https://www.cisa.gov/news-events/alerts/2026/11/22/example");
  assert.ok(lead.summary.startsWith("Posted on X, not checked."));
});

test("cleanXLead: an x.com/twitter linked_url is dropped, never handed to a researcher", () => {
  const { lead } = cleanXLead({
    x_post_id: "2", handle: "CISAgov", title: "t",
    linked_url: "https://twitter.com/someone/status/9",
    urls: ["https://t.me/chan/9", "https://www.cisa.gov/real-page"],
  }, REG, AT);
  assert.equal(lead.linked_url, "https://www.cisa.gov/real-page");
});

test("cleanXLead: a post with no non-social link has no linked_url (researcher must find an independent page)", () => {
  const { lead } = cleanXLead({ x_post_id: "3", handle: "CISAgov", title: "t", linked_url: "https://x.com/x/status/3" }, REG, AT);
  assert.equal(lead.linked_url, undefined);
});

test("cleanXLead rejects: retweet, no id, and a non-curated/inactive handle", () => {
  assert.equal(cleanXLead({ x_post_id: "4", handle: "CISAgov", title: "RT @x: hi", is_retweet: true }, REG, AT).drop, "retweet");
  assert.match(cleanXLead({ x_post_id: "5", title: "RT @someone: boom" }, REG, AT).drop, /retweet/);
  assert.equal(cleanXLead({ handle: "CISAgov", title: "t" }, REG, AT).drop, "no x_post_id");
  assert.match(cleanXLead({ x_post_id: "6", handle: "nobody_cert", title: "t" }, REG, AT).drop, /not an active curated account/);
  assert.match(cleanXLead({ x_post_id: "7", handle: "campuscodi", title: "t" }, REG, AT).drop, /not an active curated account/);
});

test("cleanXLead: a cluster (x-news) is allowed without a registry handle, as low-weight news", () => {
  const { lead, drop } = cleanXLead({ x_post_id: "8", kind: "x-news", title: "ransomware cluster", url: "https://x.com/i/status/8" }, REG, AT);
  assert.equal(drop, undefined);
  assert.equal(lead.kind, "x-news");
  assert.equal(lead.tier, "news");
});

test("ingest dedupes by x_post_id and against known urls, and enforces the per-run cap", () => {
  const bodies = [JSON.stringify([
    { x_post_id: "100", handle: "CISAgov", title: "one", linked_url: "https://www.cisa.gov/a" },
    { x_post_id: "100", handle: "CISAgov", title: "dup same id" },
    { x_post_id: "101", handle: "CISAgov", title: "already known", url: "https://x.com/CISAgov/status/101" },
    { x_post_id: "102", handle: "CISAgov", title: "two", linked_url: "https://www.cisa.gov/b" },
  ])];
  const known = { known: new Set(["https://x.com/CISAgov/status/101"]) };
  const r = ingest(bodies, known, { ...CFG, max_posts_per_run: 2 }, REG, AT);
  assert.equal(r.leads.length, 2);           // 100 and 102; 100-dup collapsed, 101 known
  assert.equal(r.stats.dupes, 2);
  assert.deepEqual(r.leads.map((l) => l.x_post_id), ["100", "102"]);
});

test("ingest caps candidates per batch (max_posts_per_batch)", () => {
  const many = Array.from({ length: 10 }, (_, i) => ({ x_post_id: String(500 + i), handle: "CISAgov", title: "t" + i }));
  const r = ingest([JSON.stringify(many)], { known: new Set() }, { ...CFG, max_posts_per_batch: 3 }, REG, AT);
  assert.equal(r.stats.seen, 3);             // only the first 3 of the batch are looked at
});

test("validator: an x.com (or telegram) URL is rejected as an event source", () => {
  const ev = { sources: [{ name: "X", url: "https://x.com/CISAgov/status/1" }], first_seen: AT, date: "2026-11-22" };
  const codes = checkEventQuality(ev).map((p) => p.code);
  assert.ok(codes.includes("social-source"), "x.com source must raise social-source");
  assert.ok(SOCIAL_SRC.test("x.com") && SOCIAL_SRC.test("t.me") && !SOCIAL_SRC.test("cisa.gov"));
});

test("validator: an official .gov source does NOT raise social-source", () => {
  const ev = { sources: [{ name: "CISA", url: "https://www.cisa.gov/news-events/alerts/x" }], first_seen: AT, date: "2026-11-22" };
  assert.ok(!checkEventQuality(ev).map((p) => p.code).includes("social-source"));
});

test("SOCIAL_HOST guards the hosts the brief names", () => {
  for (const h of ["x.com", "twitter.com", "t.me", "telegram.org", "bsky.app", "reddit.com"]) assert.ok(SOCIAL_HOST.test(h), h);
  for (const h of ["cisa.gov", "microsoft.com", "therecord.media"]) assert.ok(!SOCIAL_HOST.test(h), h);
});
