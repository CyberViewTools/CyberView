// Threat actor profiles (scripts/actors.mjs): alias merge rules, attribution labelling, claims never shown as fact.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { norm, parseActor, isName, attackGroups, loadAttack, buildActors, ATTACK_FILE } from "../../scripts/actors.mjs";

const ATTACK = { version: "test", groups: [
  { id: "G0094", name: "Kimsuky", aliases: ["Emerald Sleet", "APT43", "Velvet Chollima"] },
  { id: "G0082", name: "APT38", aliases: ["Bluenoroff", "Sapphire Sleet"] },
  { id: "G0100", name: "Inception", aliases: ["Cloud Atlas"] },
  { id: "G0001", name: "Axiom", aliases: ["Shared Name"] },
  { id: "G0002", name: "Other", aliases: ["Shared Name"] },
].map((g) => ({ ...g, url: `https://attack.mitre.org/groups/${g.id}/` })) };
let n = 0;
const ev = (o) => ({ id: `ev-${++n}-2026-11`, title: `Event ${n}`, date: "2026-11-1" + (n % 10), category: "incident", severity: 2, status: "confirmed", country: "South Korea", sector: "Government", cves: [], ...o });
const byName = (out, name) => out.profiles.find((p) => p.name === name);

test("names: spelling differences are one name; generic descriptions are not names", () => {
  assert.equal(norm("APT 28"), norm("apt-28"));
  assert.equal(norm("Crème"), norm("creme"));
  for (const g of ["Unattributed", "unknown", "China-nexus actor", "Iran-linked actors", "Suspected Chinese APT group", "Gootloader operators", "Overlaps with Kimsuky"]) assert.equal(isName(g), false, g);
  for (const g of ["Kimsuky", "Lazarus Group", "8-Digits Team", "NoName057(16)", "Global Secret Group"]) assert.equal(isName(g), true, g);
});

test("parseActor: lists, stated aliases and qualifiers", () => {
  assert.deepEqual(parseActor("Qilin; The Gentlemen; INC Ransom").map((p) => p.name), ["Qilin", "The Gentlemen", "INC Ransom"]);
  const s = parseActor("Sapphire Sleet / UNC1069 / BlueNoroff (North Korea)")[0];
  assert.equal(s.name, "Sapphire Sleet"); assert.deepEqual(s.aliases, ["UNC1069", "BlueNoroff"]);
  assert.deepEqual(parseActor("TGR-STA-0049 (also REF7707, Earth Alux, Ink Dragon)")[0].aliases, ["REF7707", "Earth Alux", "Ink Dragon"]);
  // a bracket list without "also" is a qualifier, not a merge
  assert.deepEqual(parseActor("COLD RELIC (COLDRIVER, UNC4057, Star Blizzard)")[0].aliases, []);
  assert.equal(parseActor("Qilin (ransomware)")[0].name, "Qilin");
  assert.equal(parseActor("NoName057(16)")[0].name, "NoName057(16)");
  assert.equal(parseActor("Shahid Kaveh (IRGC-linked), per French authorities")[0].name, "Shahid Kaveh");
  assert.equal(parseActor("REF3364 (Elastic's tracking name; financially motivated, unattributed)").length, 1);
  assert.equal(parseActor("WorldLeaks (claimed)")[0].claimed, true);
  assert.equal(parseActor("Kimsuky (attributed by Genians, moderate confidence)")[0].claimed, false);
  assert.deepEqual(parseActor("Unattributed; Google notes Russian-language comments in the framework's configuration"), []);
  assert.deepEqual(parseActor(""), []);
});

test("merge: ATT&CK aliases join, each alias says where it comes from", () => {
  const out = buildActors([ev({ actor: "Emerald Sleet" }), ev({ actor: "kimsuky" }), ev({ actor: "Kimsuky" })], ATTACK);
  assert.equal(out.profiles.length, 1);
  const p = out.profiles[0];
  assert.equal(p.attack.id, "G0094");
  assert.equal(p.name, "Kimsuky");
  assert.equal(p.named.length, 3);
  const em = p.aliases.find((a) => a.name === "Emerald Sleet");
  assert.equal(em.basis, "attack"); assert.equal(em.source, "MITRE ATT&CK G0094"); assert.equal(em.url, "https://attack.mitre.org/groups/G0094/");
});

test("merge: never on a hunch; similar names without a stated basis stay apart", () => {
  const out = buildActors([ev({ actor: "Silent Lynx" }), ev({ actor: "SilentAir" }), ev({ actor: "Storm-0940" }), ev({ actor: "Storm-3358" })], ATTACK);
  assert.equal(out.profiles.length, 4);
  assert.ok(out.profiles.every((p) => p.aliases.length === 0 && !p.attack));
});

test("merge: an event's own text can join names, and says which event", () => {
  const a = ev({ actor: "TraderX / UNC9999" }), b = ev({ actor: "UNC9999" });
  const out = buildActors([a, b], ATTACK);
  assert.equal(out.profiles.length, 1);
  const al = out.profiles[0].aliases.find((x) => x.name !== out.profiles[0].name);
  assert.equal(al.basis, "event"); assert.equal(al.event_id, a.id);
});

test("merge: an event that would join two ATT&CK groups is refused and shown as related", () => {
  const out = buildActors([ev({ actor: "Kimsuky / APT38" })], ATTACK);
  const k = byName(out, "Kimsuky");
  assert.equal(k.attack.id, "G0094");
  assert.ok(!k.aliases.some((a) => a.name === "APT38"));
  assert.equal(k.related[0].name, "APT38");
});

test("merge: a name ATT&CK lists under two groups matches neither", () => {
  const out = buildActors([ev({ actor: "Shared Name" })], ATTACK);
  const p = out.profiles[0];
  assert.equal(p.attack, null);
  assert.deepEqual(p.ambiguous[0].attack_ids, ["G0001", "G0002"]);
});

test("claims: a name seen only in leak-site claims is never matched to ATT&CK", () => {
  const out = buildActors([ev({ actor: "Inception (ransomware)", status: "claimed", severity: 1, org: "Acme", cves: ["CVE-2026-0001"] })], ATTACK);
  const p = out.profiles[0];
  assert.equal(p.attack, null);
  assert.equal(p.attack_namesake.id, "G0100");
  assert.equal(p.claims_only, true);
  assert.equal(p.aliases.length, 0);
});

test("claims: never shown as fact, never counted in sectors, countries or CVEs", () => {
  const out = buildActors([
    ev({ actor: "Qilin (ransomware)", status: "claimed", severity: 1, org: "Claimed Org", country: "Brazil", sector: "Retail", cves: ["CVE-2026-1111"] }),
    ev({ actor: "Qilin", status: "confirmed", country: "Japan", sector: "Healthcare", cves: ["CVE-2026-2222"] }),
    ev({ actor: "WorldLeaks (claimed)", status: "confirmed", country: "France" }),
  ], ATTACK);
  const q = byName(out, "Qilin");
  assert.equal(q.claimed.length, 1); assert.equal(q.named.length, 1); assert.equal(q.attributed.length, 0);
  assert.equal(q.claimed[0].org, "Claimed Org");
  assert.deepEqual(q.countries.map((c) => c.k), ["Japan"]);
  assert.deepEqual(q.sectors.map((c) => c.k), ["Healthcare"]);
  assert.deepEqual(q.cves.map((c) => c.id), ["CVE-2026-2222"]);
  const w = byName(out, "WorldLeaks");
  assert.equal(w.claimed.length, 1); assert.equal(w.named.length, 0); assert.equal(w.claims_only, true);
  assert.deepEqual(w.countries, []);
});

test("attribution: labelled with who said so, and outranks a mention in the same event", () => {
  const e = ev({ actor: "Kimsuky (attributed by Genians Security Center)", attribution: { actor: "Kimsuky", by: "Genians Security Center", by_type: "investigator", origin_country: "North Korea", lat: 39, lng: 125.7, url: "https://example.com/report" } });
  const g = ev({ actor: "", attribution: { actor: "APT43", by: "Some Agency", by_type: "government", origin_country: "North Korea", lat: 39, lng: 125.7, url: "https://agency.example.gov/advisory" } });
  const out = buildActors([e, g], ATTACK);
  const p = out.profiles[0];
  assert.equal(out.profiles.length, 1);
  assert.equal(p.attributed.length, 2); assert.equal(p.named.length, 0);
  const r = p.attributed.find((x) => x.event_id === e.id);
  assert.equal(r.by, "Genians Security Center"); assert.equal(r.by_type, "investigator"); assert.equal(r.url, "https://example.com/report");
  assert.deepEqual(p.origins.map((o) => o.by).sort(), ["Genians Security Center", "Some Agency"]);
  // a government attribution page is listed as an advisory
  assert.ok(p.advisories.some((a) => a.url === "https://agency.example.gov/advisory" && a.publisher === "Some Agency"));
});

test("government advisories come from the events' own report field", () => {
  const out = buildActors([ev({ actor: "Turla", report: { publisher: "SRI", publisher_type: "government", doc_id: "X-1", url: "https://www.sri.ro/a" } }), ev({ actor: "Turla", report: { publisher: "A vendor", publisher_type: "vendor", url: "https://vendor.example/a" } })], ATTACK);
  assert.deepEqual(out.profiles[0].advisories.map((a) => a.publisher), ["SRI"]);
});

test("duplicates are left out and profile ids are unique", () => {
  const out = buildActors([ev({ actor: "Akira", duplicate_of: "x" }), ev({ actor: "Akira" }), ev({ actor: "AKIRA!" })], ATTACK);
  assert.equal(out.profiles.length, 1); assert.equal(out.profiles[0].named.length, 2);
  const ids = buildActors([ev({ actor: "A B" }), ev({ actor: "A-B two" })], ATTACK).profiles.map((p) => p.id);
  assert.equal(new Set(ids).size, ids.length);
});

test("ATT&CK: only live intrusion sets with a G id; names, aliases and IDs only", () => {
  const g = attackGroups({ objects: [
    { type: "intrusion-set", name: "Alpha", aliases: ["Alpha", "Beta"], description: "long text", external_references: [{ source_name: "mitre-attack", external_id: "G0101" }] },
    { type: "intrusion-set", name: "Gone", revoked: true, external_references: [{ source_name: "mitre-attack", external_id: "G0102" }] },
    { type: "intrusion-set", name: "Old", x_mitre_deprecated: true, external_references: [{ source_name: "mitre-attack", external_id: "G0103" }] },
    { type: "malware", name: "Tool", external_references: [{ source_name: "mitre-attack", external_id: "S0001" }] },
  ] });
  assert.deepEqual(g, [{ id: "G0101", name: "Alpha", aliases: ["Beta"], url: "https://attack.mitre.org/groups/G0101/" }]);
  const stored = loadAttack(ATTACK_FILE);
  assert.ok(stored.groups.length > 100, "config/attack-groups.json holds the ATT&CK groups");
  const raw = JSON.parse(readFileSync(ATTACK_FILE, "utf8"));
  assert.ok(raw.groups.every((x) => Object.keys(x).every((k) => ["id", "name", "aliases"].includes(k))), "no descriptions are stored");
  assert.match(raw._note, /The MITRE Corporation/);
});
