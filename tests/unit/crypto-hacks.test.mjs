// Crypto hacks and exploits (scripts/crypto-hacks.mjs): the SlowMist Hacked parser on a trimmed real page, the labels from
// the database's own category pages, the lead it files, the dedupe, and how the backlog rules and fuse treat it. No network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseSlowmist, labelRows, toLead, fresh, rowKey, askedRecently, KIND, VIA, BASE, TARGET_TYPES, CHAINS } from "../../scripts/crypto-hacks.mjs";
import { story, developing } from "../../scripts/fuse.mjs";
import { autoReason } from "../../scripts/backlog.mjs";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "crypto-hacks"), fx = (f) => readFileSync(join(FIX, f), "utf8");
const NOW = Date.parse("2026-11-24T06:00:00Z");
const cats = () => Object.fromEntries(["Bridge", "Other", "ETH", "Wallet", "Exchange"].map((c) => [c, parseSlowmist(fx(`cat-${c}.html`))]));
const rows = () => labelRows(parseSlowmist(fx("list.html")), cats());
const byName = (n) => rows().find((r) => r.project === n);

test("parser: every row of the list page, each field as the page states it", () => {
  const r = parseSlowmist(fx("list.html"));
  assert.equal(r.length, 13);
  assert.deepEqual(r.map((x) => x.date).slice(0, 4), ["2026-11-22", "2026-11-21", "2026-11-21", "2026-11-21"]);
  const c = r.find((x) => x.project === "Chainflip");
  assert.equal(c.date, "2026-11-21");
  assert.equal(c.loss, "$ 12,000,000");                                // as written, currency included
  assert.equal(c.attack_method, "Private Key Leak");
  assert.deepEqual(c.reference_urls, ["https://x.com/Chainflip/status/2124068986845532605"]);
  assert.match(c.description, /^Cross-chain swap protocol Chainflip was attacked on November 21, 2026\./);
  assert.match(c.description, /offered the attacker a 10% bounty in exchange for returning 90% of the funds\.$/);   // kept whole
  assert.equal(r.find((x) => x.project === "Wagyu (XMR1)").loss, "$ 13,500,000");
  assert.equal(r.find((x) => x.project === "Aramid Bridge").loss, "$ 8500");            // no thousands separator: kept as stated
  assert.equal(r.find((x) => x.project === "Peapods Finance").loss, "");                // "-": the database states no amount
  assert.equal(r.find((x) => x.project === "Paytaca").loss, "0");                       // a stated 0 is kept, not dropped
  assert.equal(r.find((x) => x.project === "Cyber Bridge").attack_method, "Unknown");
  assert.equal(r.find((x) => x.project === "Lighter"), undefined);                       // beyond the trimmed page
  for (const x of r) { assert.match(x.date, /^\d{4}-\d{2}-\d{2}$/); assert.ok(x.project && x.description && x.attack_method); x.reference_urls.forEach((u) => assert.match(u, /^https:\/\//)); }
  assert.deepEqual(parseSlowmist("<html>nothing</html>"), []);
  assert.deepEqual(parseSlowmist('<li><span class="time">2026-11-22</span><h3><em>Hacked target: </em></h3></li>'), []);   // no project, no row
});

test("labels: target type and chain only from the database's own category pages", () => {
  assert.deepEqual(byName("Endurance Bridge").target_types, ["Bridge"]);
  assert.deepEqual(byName("Endurance Bridge").chains, []);              // on no chain page read: no chain is guessed
  assert.deepEqual(byName("Chainflip").chains, ["ETH"]);
  assert.deepEqual(byName("Chainflip").target_types, []);
  assert.deepEqual(byName("Aramid Bridge").target_types, ["Other"]);   // its name says bridge; the database files it under Other
  assert.deepEqual(byName("Fluidkey").target_types, ["Wallet"]);
  assert.deepEqual(byName("K3 Capital").chains, ["ETH"]);
  assert.deepEqual(byName("Peapods Finance").chains, ["ETH"]);
  assert.equal(rowKey(byName("Wagyu (XMR1)")), "2026-11-20-wagyu-xmr1");
  assert.ok(TARGET_TYPES.includes("Bridge") && CHAINS.includes("ETH") && CHAINS.includes("Base"));
  assert.deepEqual(labelRows(parseSlowmist(fx("list.html")))[0].chains, []);   // no category page read: no labels
});

test("lead: title and summary carry the key facts; every database field is kept as structured data", () => {
  const l = toLead(byName("Chainflip"));
  assert.equal(l.kind, KIND); assert.equal(l.kind, "breach-db"); assert.equal(l.via, VIA); assert.equal(l.tier, "vendor"); assert.equal(l.source, "SlowMist Hacked"); assert.equal(l.lang, "en");
  assert.equal(l.title, "Chainflip hacked: $12,000,000 lost on ETH (Private Key Leak), per SlowMist Hacked");
  assert.equal(l.url, `${BASE}#2026-11-21-chainflip`); assert.equal(l.db_url, "https://hacked.slowmist.io/");
  assert.equal(l.published, "2026-11-21T00:00:00Z");
  assert.match(l.summary, /^SlowMist Hacked database row, not checked\. Date 2026-11-21; loss \$12,000,000; attack method Private Key Leak; chain ETH\. Cross-chain swap/);
  assert.ok(l.summary.length <= 300);
  // the structured fields, each as the database states it
  assert.equal(l.project, "Chainflip"); assert.equal(l.loss, "$ 12,000,000"); assert.equal(l.attack_method, "Private Key Leak");
  assert.deepEqual(l.chains, ["ETH"]); assert.deepEqual(l.target_types, []);
  assert.deepEqual(l.reference_urls, ["https://x.com/Chainflip/status/2124068986845532605"]);
  assert.match(l.description, /Tornado Cash/);
  // fields the database does not publish are never invented
  for (const k of ["returned", "returned_funds", "audited", "attacker", "actor"]) assert.equal(k in l, false, k);

  const b = toLead(byName("Endurance Bridge"));
  assert.equal(b.title, "Endurance Bridge hacked: $5,700,000 lost (Private Key Leakage), per SlowMist Hacked");
  assert.deepEqual(b.target_types, ["Bridge"]); assert.match(b.summary, /target type Bridge/);
  assert.equal(toLead(byName("Cyber Bridge")).title, "Cyber Bridge hacked: $1,100,000 lost, per SlowMist Hacked");   // "Unknown" method: not in the title
  assert.equal(toLead(byName("Cyber Bridge")).attack_method, "Unknown");                                                // but kept as written
  assert.equal(toLead(byName("Peapods Finance")).title, "Peapods Finance hacked on ETH (Private Key Leakage), per SlowMist Hacked");
  assert.match(toLead(byName("Peapods Finance")).summary, /loss not stated/);
  assert.equal(toLead(byName("Paytaca")).title, "Paytaca hacked: loss recorded as 0 (Backend Vulnerability), per SlowMist Hacked");
});

test("dedupe: once per row, the 14-day window, rows already on file", () => {
  const leads = rows().map(toLead), known = new Set([`${BASE}#2026-11-22-endurance-bridge`]);
  const a = fresh(leads, known, [], NOW);
  assert.equal(a.length, 12);
  assert.ok(!a.some((l) => l.project === "Endurance Bridge"));
  assert.equal(fresh(leads, known, [], NOW).length, 0);                          // the same rows again: nothing new
  assert.equal(fresh(leads, new Set(), [], Date.parse("2026-12-20T00:00:00Z")).length, 0);   // older than the window
  const ev = { id: "2026-11-21-chainflip-vault-drain", title: "Chainflip vault drained after signing key compromise", category: "incident", org: "Chainflip", date: "2026-11-21", cves: [] };
  const m = fresh([toLead(byName("Chainflip"))], new Set(), [ev], NOW)[0];
  assert.match(m.summary, /^Matches event 2026-11-21-chainflip-vault-drain on file\./);
  assert.ok(askedRecently({ ok: true, at: "2026-11-24T05:30:00Z" }, NOW));
  assert.ok(!askedRecently({ ok: true, at: "2026-11-24T04:30:00Z" }, NOW));
  assert.ok(!askedRecently({ ok: false, at: "2026-11-24T05:50:00Z" }, NOW));
});

test("backlog and fuse: a hack row is read, not closed as a bare row, and never heads the being-checked list", () => {
  const l = { ...toLead(byName("Chainflip")), seen_at: "2026-11-23T06:00:00Z", published: "2026-11-23T00:00:00Z", _open: true };
  const s = story([l], [], NOW);
  assert.equal(autoReason(s, NOW), "");
  // another database row of the same kind (Have I Been Pwned) is still closed as one
  const hibp = { source: "Have I Been Pwned", tier: "vendor", via: "hibp", kind: "breach-db", title: "Example: 1,000 accounts in a breach list", url: "https://haveibeenpwned.com/PwnedWebsites#Example", seen_at: "2026-11-23T06:00:00Z", published: "2026-11-23T00:00:00Z", lang: "en", _open: true };
  assert.match(autoReason(story([hibp], [], NOW), NOW), /bare database row/);
  assert.deepEqual(developing([s], NOW), []);
});
