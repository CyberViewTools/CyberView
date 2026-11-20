// Cross-language "already on file" matching by name (scripts/triage.mjs matchByName), with real headlines that agents had to
// close by hand as "already on file" on 2026-11-18/19 (data/runs/*/closures.jsonl). Run: node --test tests/unit/
import { test } from "node:test";
import assert from "node:assert/strict";
import { matchEvent, matchByName, eventNames, norm, hasName, nearInTime } from "../../scripts/triage.mjs";
import { story } from "../../scripts/fuse.mjs";
import { onFile } from "../../scripts/backlog.mjs";

// the events as they were on file (fields copied from data/events/2026-11)
const EVS = [
  { id: "equinor-ongoing-cyberattack-2026-11", title: "Equinor detects ongoing cyberattack on IT systems; production unaffected", org: "Equinor", products: ["Equinor"], category: "incident", date: "2026-11-17", first_seen: "2026-11-17T22:28:00Z", cves: [] },
  { id: "cert-fr-nginx-http2-rce-2026-11", title: "CERT-FR: NGINX flaws allow unauthenticated remote code execution over HTTP/2; public PoC exists", org: "CERT-FR (ANSSI)", products: ["F5 NGINX Open Source", "F5 NGINX Plus"], category: "vuln", date: "2026-11-18", first_seen: "2026-11-18T21:13:25Z", cves: ["CVE-2026-123633", "CVE-2026-123007"] },
  { id: "office-partner-service-provider-breach-2026-11", title: "Office Partner says data held by an external service provider was accessed", org: "Office Partner GmbH", products: [], category: "incident", date: "2026-11-18", first_seen: "2026-11-19T04:23:55Z", cves: [] },
  { id: "riken-fugaku-supercomputer-cyberattack-2026-11", title: "Japan's RIKEN takes Fugaku supercomputer offline after intrusion", org: "RIKEN Center for Computational Science", products: ["Fugaku", "Rikyu"], category: "incident", date: "2026-11-16", first_seen: "2026-11-18T00:25:00Z", cves: [] },
  { id: "jpmorganchase-third-party-vendor-cyberattack-2026-11", title: "JPMorganChase says vendors that serve it were hit by a cyberattack; marketing data may be exposed", org: "JPMorgan Chase", products: ["JPMorgan Chase"], category: "incident", date: "2026-11-19", first_seen: "2026-11-19T15:30:00Z", cves: [] },
  { id: "jpmorgan-chase-banking-outage-2026-11", title: "JPMorgan Chase outage delays payments; cause disputed", org: "JPMorgan Chase", products: ["JPMorgan Chase", "Zelle"], category: "outage", date: "2026-11-16", first_seen: "2026-11-17T22:28:00Z", cves: [] },
  { id: "ms-agent-pypi-2026-11", title: "Poisoned Microsoft Agent Framework releases on PyPI steal cloud credentials", org: "Microsoft", products: ["Microsoft Agent Framework"], category: "incident", date: "2026-11-18", first_seen: "2026-11-18T12:00:00Z", cves: [],
    summary: "The attackers published poisoned releases; a rising number of projects pulled the worm-like package." },
];
const at = "2026-11-19T10:00:00Z";

test("names: case, diacritics, apostrophes and every script are folded the same way", () => {
  assert.equal(norm("Équinor'un SİSTEMLERİ"), "equinor un sistemleri");
  assert.ok(hasName(norm("Cyberangriff auf Equinor: Gaslieferant"), "equinor"));
  assert.ok(!hasName(norm("Equinorway"), "equinor"), "whole words only");
  assert.ok(hasName(norm("スパコン「富岳」に不正アクセス"), norm("富岳")), "a name in a script without spaces is found inside the text");
  assert.deepEqual(eventNames(EVS[0]).map((n) => n.name), ["equinor"]);
  assert.ok(eventNames(EVS[1]).some((n) => n.name === "nginx"), "a capitalised word of a product name");
  assert.ok(!eventNames(EVS[1]).some((n) => n.name === "cert fr anssi"), "for a flaw or a report, org is the publisher, not a name of the event");
  assert.deepEqual(eventNames(EVS[2]).map((n) => n.name), ["office partner"], "legal suffixes dropped, a plain word alone is never a name");
});

test("foreign-language retellings that agents closed by hand are now matched by name", () => {
  const cases = [
    ["Cyberangriff auf Equinor: Deutschlands wichtigster Gaslieferant im Visier", "2026-11-18T12:46:36Z", EVS[0].id],          // de, FAZ
    ["Ações da Equinor ASA caem após ataque cibernético a sistemas de TI", "2026-11-18T18:00:00Z", EVS[0].id],                    // pt
    ["Serangan Siber Lumpuhkan Email Internal Perusahaan Equinor", "2026-11-19T04:04:11Z", EVS[0].id],                           // id, Peradaban.id
    ["Cyberattaque contre le géant du gaz Equinor, l'Europe face à une menace inquiétante", "2026-11-20T02:10:00Z", EVS[0].id],  // fr
    ["Kritische Sicherheitslücken in NGINX Plus und NGINX Open Source - Updates verfügbar", "2026-11-18T15:15:42Z", EVS[1].id],    // de, CERT.at
    ["Cyberangriff auf Office Partner", "2026-11-18T10:25:35Z", EVS[2].id],                                                      // de, ChannelPartner
    ["Fugaku offline usai serangan siber, 4.222 pengguna terdampak", "2026-11-18T07:43:50Z", EVS[3].id],                          // id, Meteora Web
  ];
  for (const [title, when, id] of cases) assert.equal((matchEvent(title, EVS, when) || {}).id, id, title);
  assert.match(matchByName(cases[0][0], EVS, cases[0][1]).by, /equinor/);
});

test("conservative: no match far from the event's dates, for a claim, for another CVE, for a shared or plain name", () => {
  assert.equal(matchEvent("Cyberangriff auf Equinor: Deutschlands wichtigster Gaslieferant im Visier", EVS, "2026-12-10T08:00:00Z"), null, "weeks later it may be a new incident");
  assert.equal(matchEvent("Claim: akira lists Equinor on its leak site", EVS, at), null, "a gang's leak-site post is never matched by a name");
  assert.equal(matchEvent("Neue NGINX-Lücke CVE-2026-999001 wird ausgenutzt", EVS, at), null, "a CVE the event does not have is a different flaw");
  assert.equal(matchByName("JPMorgan Chase culpa a proveedores externos", EVS, at), null, "two events are known by the name: an agent decides");
  assert.equal(matchEvent("Microsoft confirms Exchange Online outage across Europe after update", EVS, at), null, "a big vendor's name says nothing");
  assert.equal(matchEvent("Ransomware attacks are rising as worm-like loaders spread", EVS, at), null, "ordinary words are not names");
  assert.equal(matchEvent("スパコン「富岳」に不正アクセス 理研が明らかに", EVS, at), null, "no Latin name and no alias: left for an agent");
  const withAlias = EVS.map((e) => e.id === EVS[3].id ? { ...e, aliases: ["富岳", "理研"] } : e);
  assert.equal((matchEvent("スパコン「富岳」に不正アクセス 理研が明らかに", withAlias, at) || {}).id, EVS[3].id, "names in other scripts, when a record carries them");
});

test("the time window runs from two days before the event to five days after it was filed", () => {
  assert.ok(nearInTime(EVS[0], "2026-11-15T12:00:00Z"));
  assert.ok(!nearInTime(EVS[0], "2026-11-14T12:00:00Z"));
  assert.ok(nearInTime(EVS[0], "2026-11-22T12:00:00Z"));
  assert.ok(!nearInTime(EVS[0], "2026-11-24T12:00:00Z"));
  assert.ok(!nearInTime(EVS[0], "not a date"));
});

test("a story matched by name is on file, and the backlog rule closes it with the event id", () => {
  const NOW = Date.parse("2026-11-19T13:00:00Z");
  const s = story([{ title: "Equinor: Cyberangriff dauert an, Produktion läuft normal", url: "https://de.marketscreener.com/x", source: "MarketScreener Deutschland", tier: "news", via: "bing-news", lang: "de", seen_at: "2026-11-19T12:20:00Z", published: "2026-11-19T12:13:23Z", _open: true }], EVS, NOW);
  assert.equal(s.event, EVS[0].id);
  assert.equal(onFile(s), `already on file: ${EVS[0].id}`);
  assert.equal(onFile({ ...s, open: 0 }), "", "nothing to log when every lead is already handled");
  assert.equal(onFile({ ...s, event: "" }), "");
});
