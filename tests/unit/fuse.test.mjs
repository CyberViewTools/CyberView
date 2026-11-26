// Story ranking and the "reported, being checked" list (scripts/fuse.mjs). Run: node --test tests/unit/
import test from "node:test";
import assert from "node:assert/strict";
import { story, developing, cluster } from "../../scripts/fuse.mjs";

const NOW = Date.parse("2026-11-19T02:00:00Z");
const lead = (o) => ({ title: "x", url: "https://example.org/" + Math.random(), source: "Example", tier: "news", via: "rss", seen_at: "2026-11-19T01:30:00Z", published: "2026-11-19T01:00:00Z", lang: "en", region: "north-america", _open: true, ...o });

test("ranking: a fresh incident outranks an old bulletin met for the first time", () => {
  const fresh = story([lead({ title: "County hospital hit by ransomware attack, officials say", source: "A" }), lead({ title: "Ransomware attack disrupts county hospital", source: "B" })], [], NOW);
  const old = story([lead({ title: "Security update for Example Server", tier: "gov", source: "CERT", published: "2026-11-10T09:00:00Z" })], [], NOW);
  assert.ok(fresh.score > old.score + 8, `${fresh.score} vs ${old.score}`);
  assert.ok(old.why.includes("published more than six days ago"));
  assert.equal(fresh.incident, true);
});

test("ranking: a routine bulletin is marked down unless it reports exploitation", () => {
  const routine = story([lead({ title: "[NEU] [hoch] Example Router: Mehrere Schwachstellen", tier: "gov", source: "BSI", lang: "de" })], [], NOW);
  const hot = story([lead({ title: "Example Router: multiple vulnerabilities actively exploited", tier: "gov", source: "CERT" })], [], NOW);
  assert.equal(routine.routine, true); assert.equal(hot.routine, false);
  assert.ok(hot.score > routine.score);
});

test("ranking: commentary and undated posts earn no freshness or incident points", () => {
  const opinion = story([lead({ title: "If we are under cyber attack, would our government tell us?" })], [], NOW);
  assert.equal(opinion.explainer, true); assert.equal(opinion.incident, false);
  const undated = story([lead({ title: "The Nansh0u Campaign: hackers arsenal grows stronger", published: undefined })], [], NOW);
  assert.equal(undated.dated, false);
  assert.ok(!undated.why.some((w) => /published in the last/.test(w)));
});

test("being checked: only fresh, corroborated or official reports; never claims, database rows, commentary or redirects", () => {
  const mk = (leads) => story(leads, [], NOW);
  const good = mk([lead({ title: "City water utility confirms cyberattack", source: "A", url: "https://a.example/story" }), lead({ title: "Cyberattack on city water utility", source: "B", via: "google-news", url: "https://news.google.com/rss/articles/abc" })]);
  const claim = mk([lead({ title: "Acme listed by ransomware group", kind: "claim", source: "ransomwarelive" })]);
  const row = mk([lead({ title: "CVE-2026-1000 (CVSS 9.8): something", kind: "cve", tier: "gov", source: "NVD" })]);
  const single = mk([lead({ title: "Local firm hacked", source: "C" })]);
  const opinion = mk([lead({ title: "Why are so many outages happening?", source: "D" }), lead({ title: "Why are so many outages happening?", source: "E" })]);
  const stale = mk([lead({ title: "Bank confirms data breach", source: "F", published: "2026-11-16T00:00:00Z" }), lead({ title: "Data breach at bank", source: "G", published: "2026-11-16T00:00:00Z" })]);
  const out = developing([good, claim, row, single, opinion, stale], NOW);
  assert.deepEqual(out.map((x) => x.id), [good.id]);
  assert.equal(out[0].url, "https://a.example/story");   // the publisher's own page, never the search redirect
  assert.equal(out[0].publishers, 2);
  const onlyRedirect = mk([lead({ title: "Port operator confirms cyberattack", source: "H", url: "https://news.google.com/rss/articles/x" }), lead({ title: "Cyberattack at port operator", source: "I", url: "https://www.bing.com/news/apiclick.aspx?u=1" })]);
  assert.equal(developing([onlyRedirect], NOW)[0].url, "");
});

test("already on file: a retold incident matches by organisation plus shared words; a big vendor's name alone does not", async () => {
  const { matchEvent } = await import("../../scripts/triage.mjs");
  const evs = [{ id: "visa-third-party-2026-11", title: "Visa says incident was at an Asia Pacific third-party provider after gang lists it", org: "Visa", category: "incident" },
    { id: "ms-agent-pypi-2026-11", title: "Poisoned Microsoft Agent Framework releases on PyPI steal cloud credentials", org: "Microsoft", category: "incident" }];
  assert.equal((matchEvent("Visa confirms apparent cyberattack at third-party provider, gang claims hit", evs) || {}).id, "visa-third-party-2026-11");
  assert.equal(matchEvent("Microsoft confirms Exchange Online outage across Europe after update", evs), null);
  assert.equal(matchEvent("Regional bank discloses ransomware attack on loan systems", evs), null);
});

test("an advisory lead whose vendor states exploitation ranks as listed exploited", async () => {
  const { story } = await import("../../scripts/fuse.mjs");
  const lead = (x) => ({ id: "a" + x, title: "Acme Gateway critical vulnerability CVE-2026-1111", url: "https://psirt.acme.example/a" + x, source: "Acme PSIRT", tier: "vendor", kind: "advisory", via: "psirt", seen_at: "2026-11-21T10:00:00Z", published: "2026-11-21T09:00:00Z", _open: true });
  const now = Date.parse("2026-11-21T12:00:00Z");
  const yes = story([{ ...lead(1), exploited: true }], [], now), no = story([lead(2)], [], now);
  const why = (s) => JSON.stringify(s);
  assert.ok(why(yes).includes("listed as exploited") && !why(no).includes("listed as exploited"));
});

// Story grouping must not chain: A like B and B like C is not A like C. Headlines from the leads of 2026-11-22..24.
const N = (title, source, o = {}) => lead({ title, source, url: "https://" + String(source).toLowerCase().replace(/[^a-z0-9]+/g, "") + ".example/" + encodeURIComponent(title).slice(0, 60), ...o });
const groupOf = (groups, re) => groups.filter((g) => g.some((l) => re.test(l.title)));
const together = (groups, re) => groupOf(groups, re).length === 1;

test("grouping: one shared filler word does not chain two companies' incidents into one story", () => {
  const bell = [N("Bell Canada data breach 2026: What you need to know", "A"), N("Bell Canada data breach 2026: What you need to know", "B"),
    N("Bell Canada residential customers affected by cybersecurity incident", "Globe"), N("Some Bell customers' information accessed in cybersecurity incident - National", "Global News"),
    N("Bell Canada customers' personal information targeted in cybersecurity incident", "C")];
  const next = [N("Next says some data accessed in cyber incident affecting online supplier", "Guardian"), N("Next says some data accessed in cyber incident affecting online supplier", "York Press"),
    N("Next says some data accessed in cyber incident affecting online supplier", "Leader Live"), N("Next investigates cyber incident involving third-party supplier", "City AM")];
  const staples = [N("Staples Canada data breach: What staplesprint.ca customers need to know", "D"), N("Staples Canada data breach: What staplesprint.ca customers need to know", "E")];
  const g = cluster([...bell, ...next, ...staples]);
  for (const [a, b] of [[/bell/i, /\bnext\b/i], [/bell/i, /staples/i], [/\bnext\b/i, /staples/i]])
    assert.ok(!g.some((x) => x.some((l) => a.test(l.title)) && x.some((l) => b.test(l.title))), `${a} and ${b} must be separate stories`);
  assert.ok(together(g, /next says/i) && together(g, /staples/i) && together(g, /Bell Canada data breach 2026/), "each company's own coverage stays together");
});

test("grouping: French coverage of different victims does not chain through function words or broken accents", () => {
  const g = cluster([
    N("Le CHU de Guadeloupe victime d'une «cyberattaque de grande ampleur»", "RFI"), N("Guadeloupe : le CHU victime d’une « cyberattaque de grande ampleur », le plan blanc déclenché", "Le Monde"),
    N("Le CHU de Guadeloupe victime d'une cyberattaque, une cellule de crise déclenchée", "RCI"), N("Cyberattaque visant le CHU de Guadeloupe : le parquet de Paris a ouvert une enquête", "Le Figaro"),
    N("Cyberattaque : la Banque Delubac & Cie déjoue une tentative de fraude mais subit une fuite de données", "F"), N("La banque Delubac victime d'une cyberattaque", "G"),
    N("Après le Crédit Mutuel Arkéa, la banque Delubac victime d’une cyberattaque", "H"), N("Quimper Bretagne occidentale est victime d’une cyberattaque", "Ouest-France")]);
  assert.ok(together(g, /guadeloupe/i), "the hospital's coverage, prosecutor included, is one story");
  assert.ok(together(g, /delubac/i), "the bank's coverage is one story");
  assert.ok(!g.some((x) => x.some((l) => /guadeloupe/i.test(l.title)) && x.some((l) => /delubac|quimper/i.test(l.title))), "the hospital is not joined to the bank or the town");
  assert.ok(!g.some((x) => x.some((l) => /delubac/i.test(l.title)) && x.some((l) => /quimper/i.test(l.title))), "the bank is not joined to the town");
});

test("grouping: routine bulletins do not join each other by their boilerplate; a shared CVE still joins", () => {
  const bsi = (t) => N(t, "BSI CERT-Bund", { tier: "gov", lang: "de" });
  const g = cluster([bsi("[UPDATE] [hoch] NATS Server: Mehrere Schwachstellen"), bsi("[UPDATE] [hoch] Linux Kernel: Mehrere Schwachstellen"), bsi("[UPDATE] [hoch] GIMP: Mehrere Schwachstellen"),
    bsi("[UPDATE] [mittel] Red Hat Enterprise Linux (undici-nodejs): Mehrere Schwachstellen"), bsi("[UPDATE] [hoch] Ghostscript: Schwachstelle ermöglicht Codeausführung"),
    bsi("[UPDATE] [hoch] Red Hat Quay: Mehrere Schwachstellen"), N("Ghostscript Upload2Shell Flaw Exposes WordPress Sites to Remote Code Execution", "Cyberpress"),
    N("Proof-of-concept exploit code available for Ghostscript ‘Upload2Shell’ flaw", "Help Net Security"),
    N("CVE-2026-90436 security advisory for Apache Axis", "X", { kind: "advisory" }), N("CVE-2026-90436: multiple vulnerabilities in Apache Axis", "Y")]);
  assert.equal(groupOf(g, /BSI|Mehrere|Schwachstelle/).length, 6, "six bulletins about six products are six stories");
  assert.ok(together(g, /upload2shell/i), "the Ghostscript flaw's news coverage is one story");
  assert.ok(together(g, /CVE-2026-90436/), "two routine bulletins on the same CVE are one story");
});

test("grouping: many publishers' differently worded coverage of one incident stays one story", () => {
  // forty publishers on the FBI crime-database hack, 22-24 November 2026: worded every way, one incident
  const fbi = [
    "'I'm not happy' - Trump reacts to hack of FBI information center",
    "FBI Criminal Records Database Hacked, Trump Confirms: 'I Will Say That It's Not Good'",
    "FBI Database Breach Confirmed: Hackers Access Critical Criminal Information System",
    "FBI Investigating Apparent Hack Of Its Key National Criminal Justice Database",
    "FBI Investigating Apparent Hack of Its Key National Criminal Justice Database, AP Source Says",
    "FBI Launches Investigation into Possible Breach of National Crime Information Center",
    "FBI Probes Cyberattack Targeting National Crime Information Center Database: Scope, Stolen Data, and Law Enforcement Alert",
    "FBI Probes Hack of National Crime Database Used by Police",
    "FBI crime database breach probed as USDA farm payment systems hit by cyber incident",
    "FBI crime database hack could affect law enforcement",
    "FBI crime database hack could affect law enforcement | National",
    "FBI crime database reportedly hacked",
    "FBI crime database reportedly hit by suspected cyberattack",
    "FBI investigates apparent hack into National Crime Information Center database",
    "FBI investigates apparent hack of national law enforcement database",
    "FBI investigating apparent hack of a key criminal justice information database, AP source says",
    "FBI investigating apparent hack of criminal justice info database: source",
    "FBI investigating apparent hack of its key national criminal justice database , AP source says",
    "FBI investigating apparent hack of its key national criminal justice database, AP source says",
    "FBI investigating apparent hack of its key national criminal justice database, AP source says - Boston News, Weather, Sports",
    "FBI investigating apparent hack of national criminal justice database",
    "FBI investigating breach of its National Crime Information Center database",
    "FBI law enforcement database becomes the latest target of hackers",
    "FBI probes crime database intrusion as Trump fires US cyber chief",
    "FBI probing hack of its national criminal justice database: AP source",
    "FBI reportedly facing second data breach involving National Crime Information Center",
    "FBI reportedly investigating apparent hack of its criminal database",
    "FBI's National Crime Information Center Database Reportedly Hacked for the Second Time",
    "Flights to Atlanta halted after Delta system fail ; FBI criminal database breached",
    "Hackers Breach Critical FBI Database Used By Police Nationwide Amid Wave Of Cyberattacks",
    "Hackers Breach FBI Crime Database, Farm Agency and Dams in U.S.",
    "Hackers break into FBI criminal database",
    "News 12 | Westchester | Fbi Investigating Possible Hack Of Major Criminal Justice Database",
    "President Trump Responds to FBI National Crime Information Center Getting Hacked",
    "Reported FBI hack 'not good' but could have benefits, Trump says",
    "Trump Reacts to Reports That FBI's Records System Was Hacked",
    "Trump reacts to report of hackers breaching FBI database",
    "Trump responds to reports of FBI database breach: ‘It’s not good’",
    "Trump says reported FBI hack 'not good' but could have benefits",
    "USDA and FBI’s National Crime Information Center Breached by Hackers",
  ];
  const water = ["FBI Warns Hackers Target U.S. Water Supply Systems", "Water supply hack warning: FBI says threats are rising", "FBI Warns Hackers Target U.S. Water Supply Systems | News Radio"];
  const g = cluster([...fbi.map((t, i) => N(t, "pub" + i)), ...water.map((t, i) => N(t, "radio" + i))]);
  const main = groupOf(g, /Apparent Hack of Its Key National/)[0];
  // the reaction pieces ("Trump reacts to ...") may form their own story; every report of the hack itself is in this one
  assert.ok(main.length >= fbi.length - 3, `the hack's coverage is one story (${main.length} of ${fbi.length})`);
  assert.ok(fbi.filter((t) => !/^'I'm not happy'|^Trump reacts/i.test(t)).every((t) => main.some((l) => l.title === t)), "every report of the hack itself is in it");
  assert.ok(together(g, /water/i) && !groupOf(g, /water/i)[0].some((l) => /database/i.test(l.title)), "the FBI's water-supply warning is a different story");
  assert.ok(!main.some((l) => /water/i.test(l.title)));
  // and the story it makes is corroborated by every one of its publishers (that drives the score, developing() and routing)
  assert.equal(story(main, [], NOW).publishers, main.length);
});

test("grouping: a vendor's name shared by every headline does not join two different CVEs", () => {
  const row = (c, t, src) => N(`${c} (CVSS 9.1): ${t}`, src, { kind: "cve", tier: "gov" });
  const g = cluster([row("CVE-2026-118285", "Server-side request forgery in Azure Machine Learning allows an authorized attacker to elevate privilege", "NIST NVD"),
    row("CVE-2026-118285", "Microsoft Azure Machine Learning: Azure Machine Learning Elevation of Privilege Vulnerability", "CVE.org"),
    row("CVE-2026-62841", "Improper authentication in Azure Event Grid allows an unauthorized attacker to elevate privileges", "NIST NVD"),
    row("CVE-2026-62841", "Microsoft Azure Event Grid System: Azure Event Grid Elevation of Privilege Vulnerability", "CVE.org")]);
  assert.deepEqual(g.map((x) => x.length).sort(), [2, 2]);
});
