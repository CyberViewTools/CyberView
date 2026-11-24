// Scanner incident citations (--data-incidents) and hunt links (scanner/lib/cite.mjs): reviewed CyberView events cited per
// finding by CVE (every event, not first-wins), claims never cited, hunt files as links only, and the targets never contacted
// for either. Fixture events in tests/fixtures/scanner/cite/ are invented (CVE-2026-90xxx). No real host is contacted.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync, cpSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { eventIndex, citeRule, citation, loadIncidents, attachIncidents, attachHunt, huntLink, eventLink } from "../../scanner/lib/cite.mjs";
import { dirSource, webSource, ALLOWED } from "../../scanner/lib/data.mjs";
import { STATEMENT } from "../../scanner/lib/scope.mjs";
import { main } from "../../scanner/cyberview-scan.mjs";

const FIX = new URL("../fixtures/scanner/", import.meta.url).pathname, SNAP = join(FIX, "snapshot"), CITE = join(FIX, "cite");
const HUNT = JSON.parse(readFileSync(join(CITE, "hunt.json"), "utf8"));
const SEARCH = JSON.parse(readFileSync(join(CITE, "data", "archive", "search.json"), "utf8"));
const NOV = JSON.parse(readFileSync(join(CITE, "data", "archive", "2026-11.json"), "utf8"));
const tmp = () => mkdtempSync(join(tmpdir(), "cvcite-"));
const SSH = "CVE-2026-90101";
const CITED = ["fixture-ssh-intrusion-hospital", "fixture-ssh-agency-advisory"];
// text that must never reach a report: indicator and rule bodies, actor names, the claim's own title
const NEVER = ["IOC-BODY-MUST-NOT-COPY", "203.0.113.66", "RULE_BODY_MUST_NOT_COPY", "FixtureBear", "PressSpeculationBear", "FixtureGang", "https://vendor.example/hunt/claim.csv", "csaf", "http://vendor.example"];

/** The base snapshot plus hunt entries (workbench) and, unless bare, the archive files. */
function makeSnap({ archive = true } = {}) {
  const d = tmp(); cpSync(SNAP, d, { recursive: true });
  const wbp = join(d, "data", "workbench.json"), wb = JSON.parse(readFileSync(wbp, "utf8"));
  wb.hunt = HUNT.hunt; wb.guides[SSH] = { ...wb.guides[SSH], hunt: HUNT.guide_hunt };
  writeFileSync(wbp, JSON.stringify(wb));
  if (archive) cpSync(join(CITE, "data", "archive"), join(d, "data", "archive"), { recursive: true });
  return d;
}
const scope = (dir) => { const p = join(dir, "scope.json"); writeFileSync(p, JSON.stringify({ cyberview_scope: 1, owner: "Example lab", contact: "lab@example.org",
  attestation: { statement: STATEMENT, agreed: true, name: "Test Operator", date: new Date().toISOString().slice(0, 10), authorization_ref: "test" }, targets: ["10.0.0.5"], exclude: [] })); return p; };
const io = (extra = {}) => { const out = [], err = []; return { out: (s) => out.push(s), err: (s) => err.push(s), sleep: async () => {}, publicWaitMs: 0, lines: { out, err },
  fetchImpl: () => { throw new Error("no network in this test"); }, resolve: async () => { throw Object.assign(new Error("no DNS"), { code: "ENOTFOUND" }); }, ...extra }; };
// a stand-in probe that records every call: OpenSSH 9.6 on 22 (CVE-2026-90101), nginx 1.22.1 on 80 (CVE-2026-90102)
const recorder = () => { const calls = []; const probe = async (ip, port) => { calls.push(`${ip}:${port}`);
  return port === 22 ? { port, state: "open", banner: "SSH-2.0-OpenSSH_9.6\r\n" } : port === 80 ? { port, state: "open", http: { status: 200, headers: { server: "nginx/1.22.1" }, body: "" } } : { port, state: "closed" }; };
  return { calls, probe, udpProbe: async () => { calls.push("udp"); throw new Error("UDP must not be used"); } }; };
async function scan(snapDir, flags = [], extra = {}) {
  const d = tmp(), rec = recorder(), x = io({ probe: rec.probe, udpProbe: rec.udpProbe, ...extra });
  const code = await main(["scan", "--scope", scope(d), ...snapDir, "--ports", "22,80,443", "--out", join(d, "out"), ...flags], x);
  assert.equal(code, 0, x.lines.err.join("\n"));
  return { rep: JSON.parse(readFileSync(join(d, "out", "report.json"), "utf8")), text: readFileSync(join(d, "out", "summary.txt"), "utf8"), json: readFileSync(join(d, "out", "report.json"), "utf8"),
    csv: readFileSync(join(d, "out", "findings.csv"), "utf8"), calls: rec.calls, x };
}

test("the CVE-to-events index keeps EVERY event naming a CVE (not the workbench's first-wins event_of)", () => {
  const idx = eventIndex(SEARCH);
  assert.deepEqual(idx.get(SSH).map((x) => x.id), ["fixture-ssh-developing", "fixture-ssh-mass-exploitation", "fixture-ssh-flagged", "fixture-ssh-intrusion-hospital", "fixture-ssh-agency-advisory"]);
  assert.deepEqual(idx.get("CVE-2026-90199").map((x) => x.id), ["fixture-ssh-agency-advisory"]);   // one event, two CVEs
  const firstWins = {}; for (const r of SEARCH.rows) for (const c of r[8]) (firstWins[c] ||= r[0]);
  assert.equal(typeof firstWins[SSH], "string"); assert.ok(idx.get(SSH).length > 1);
  assert.deepEqual([...eventIndex(SEARCH, new Set(["CVE-2026-90102"])).keys()], ["CVE-2026-90102"]);   // narrowed to the CVEs wanted
  assert.equal(eventIndex({ fields: ["x"], rows: [[1]] }).size, 0); assert.equal(eventIndex(null).size, 0);
});

test("the claims rule: only confirmed or official AND passed or corrected are cited; claims are labelled, never cited", () => {
  const by = Object.fromEntries(NOV.events.map((e) => [e.id, e]));
  assert.equal(citeRule(by["fixture-ssh-intrusion-hospital"]), "cite");
  assert.equal(citeRule(by["fixture-ssh-mass-exploitation"]), "claimed");   // reviewed, but a claim
  assert.equal(citeRule(by["fixture-ssh-developing"]), "unreviewed");
  assert.equal(citeRule(by["fixture-ssh-flagged"]), "unreviewed");
  assert.equal(citation(by["fixture-ssh-mass-exploitation"]), null);
  const c = citation(by["fixture-ssh-intrusion-hospital"]);
  assert.deepEqual(Object.keys(c).sort(), ["attribution", "date", "event_id", "link", "review", "sources", "status", "title"]);
  assert.equal(c.sources, 2); assert.equal(c.link, eventLink("fixture-ssh-intrusion-hospital")); assert.match(c.link, /^https:\/\/cyberview\.tools\/archive\.html#q=/);
  assert.deepEqual(c.attribution, { by: "Fixture National CERT", by_type: "government", url: "https://gov.example/attribution-1" });   // who and where, no actor name
  for (const s of NEVER) assert.ok(!JSON.stringify(c).includes(s), s);
});

test("offline with --data-incidents: two reviewed citations print with their links, the claim is labelled and not cited, hunt links print; the probe sees nothing new", async () => {
  const snap = makeSnap();
  const on = await scan(["--data", snap], ["--data-incidents"]), off = await scan(["--data", snap]);
  // the probe is never called for either feature: the same probe calls with and without the flag, and no UDP
  assert.deepEqual(on.calls, off.calls); assert.ok(!on.calls.includes("udp")); assert.deepEqual([...new Set(on.calls)].sort(), ["10.0.0.5:22", "10.0.0.5:443", "10.0.0.5:80"]);
  const f = on.rep.findings.find((x) => x.cve === SSH);
  assert.deepEqual(f.incidents.cited.map((c) => c.event_id), CITED);
  assert.equal(f.incidents.claimed_not_cited, 1); assert.equal(f.incidents.unreviewed_not_cited, 2);
  assert.equal(f.incidents.cited[1].attribution, undefined);   // press "attribution" is not an attribution
  assert.equal(f.incidents.cited[1].review, "corrected");
  for (const id of CITED) assert.ok(on.text.includes(eventLink(id)), id);
  assert.match(on.text, /Reported incidents naming this CVE \(CyberView, second-reviewed\): 2/);
  assert.match(on.text, /1 attacker CLAIM\(S\) naming this CVE not cited \(unconfirmed/);
  assert.match(on.text, /attributed by Fixture National CERT \(government\) https:\/\/gov\.example\/attribution-1/);
  // hunt: the CVE's entries, the guide's, and the cited event's, as links; never the claim's, a CSAF file or a plain-http one
  assert.deepEqual(f.hunt.map((h) => h.url), ["https://advisories.example.com/fixture-openssh-iocs.txt", "https://vendor.example/hunt/openssh.yar", "https://vendor.example/hunt/ssh.yml"]);
  for (const h of f.hunt) { assert.deepEqual(Object.keys(h).sort(), ["format", "name", "publisher", "url"]); assert.ok(on.text.includes(h.url)); }
  assert.match(on.text, /Hunt \(publishers' detection files, links only; nothing copied\)/);
  for (const s of NEVER) { assert.ok(!on.json.includes(s), `report.json carries ${s}`); assert.ok(!on.text.includes(s), `summary.txt carries ${s}`); }
  assert.ok(!on.json.includes("Claim: FixtureGang"));
  // another finding gets its own event; the report records that the archive was read
  assert.deepEqual(on.rep.findings.find((x) => x.cve === "CVE-2026-90102").incidents.cited.map((c) => c.event_id), ["fixture-nginx-other"]);
  assert.deepEqual(on.rep.run.data.incidents, { requested: true, available: true, months_read: 2, months_skipped: 0 });
  assert.equal(on.csv, off.csv);   // the CSV columns are unchanged
});

test("without the flag nothing about incidents changes: no archive is read, no citation is attached", async () => {
  const snap = makeSnap(), off = await scan(["--data", snap]);
  assert.ok(off.rep.findings.every((f) => !("incidents" in f))); assert.equal(off.rep.run.data.incidents, undefined);
  assert.doesNotMatch(off.text, /Reported incidents|CLAIM/);
  // hunt links are still attached from the workbench, by CVE only (an event's file needs a cited event)
  assert.deepEqual(off.rep.findings.find((x) => x.cve === SSH).hunt.map((h) => h.url), ["https://advisories.example.com/fixture-openssh-iocs.txt", "https://vendor.example/hunt/openssh.yar"]);
  // the plain test snapshot (no hunt entries, no archive) gives exactly the report it gave before: no hunt and no incidents keys
  const base = await scan(["--data", SNAP]);
  assert.ok(base.rep.findings.every((f) => !("incidents" in f) && !("hunt" in f)));
  // with the flag but a snapshot that has no archive: no citation, a note says how to get one, the scan still succeeds
  const bare = await scan(["--data", makeSnap({ archive: false })], ["--data-incidents"]);
  assert.ok(bare.rep.findings.every((f) => !("incidents" in f))); assert.match(bare.rep.notes.join(" "), /no event archive/);
  assert.equal(bare.rep.run.data.incidents.available, false);
});

test("the data command: without the flag the snapshot is unchanged; with it, a thin archive (no bodies) that cites the same events offline", async () => {
  const served = makeSnap(), asked = [];
  const fetchImpl = async (url, opts) => { asked.push([opts.method, url.replace("https://cyberview.example/", "")]);
    const p = join(served, url.replace("https://cyberview.example/", "")); return existsSync(p) ? new Response(readFileSync(p), { status: 200 }) : new Response("no", { status: 404 }); };
  const d = tmp();
  assert.equal(await main(["data", "--out", join(d, "plain"), "--source", "https://cyberview.example/"], io({ fetchImpl })), 0);
  assert.ok(!existsSync(join(d, "plain", "data", "archive"))); assert.ok(asked.every(([, p]) => !p.startsWith("data/archive/")));
  assert.deepEqual(readdirSync(join(d, "plain", "data")).sort(), ["cve", "psirt.json", "workbench.json"]);
  assert.equal(JSON.parse(readFileSync(join(d, "plain", "manifest.json"), "utf8")).incidents, undefined);
  asked.length = 0;
  assert.equal(await main(["data", "--out", join(d, "inc"), "--source", "https://cyberview.example/", "--data-incidents"], io({ fetchImpl })), 0);
  assert.ok(asked.every(([m, p]) => m === "GET" && ALLOWED.test(p))); assert.ok(asked.some(([, p]) => p === "data/archive/search.json"));
  const m = JSON.parse(readFileSync(join(d, "inc", "manifest.json"), "utf8")); assert.equal(m.incidents, true); assert.equal(m.incident_months, 2);
  const thin = readFileSync(join(d, "inc", "data", "archive", "2026-11.json"), "utf8") + readFileSync(join(d, "inc", "data", "archive", "search.json"), "utf8");
  for (const s of ["IOC-BODY-MUST-NOT-COPY", "203.0.113.66", "FixtureBear", "fixture-no-cve", "hunt"]) assert.ok(!thin.includes(s), s);
  const on = await scan(["--data", join(d, "inc")], ["--data-incidents"]);
  assert.deepEqual(on.rep.findings.find((x) => x.cve === SSH).incidents.cited.map((c) => c.event_id), CITED);
});

test("online: --data-incidents reads only allowlisted archive paths with GET; without it no archive path is asked for", async () => {
  const served = makeSnap();
  const mk = () => { const asked = []; return { asked, fetchImpl: async (url, opts) => { asked.push([opts.method, url.replace("https://cyberview.example/", "")]);
    const p = join(served, url.replace("https://cyberview.example/", "")); return existsSync(p) ? new Response(readFileSync(p), { status: 200 }) : new Response("no", { status: 404 }); } }; };
  const a = mk(), on = await scan(["--online", "--source", "https://cyberview.example/"], ["--data-incidents"], { fetchImpl: a.fetchImpl });
  assert.ok(a.asked.every(([m, p]) => m === "GET" && ALLOWED.test(p)));
  assert.deepEqual(a.asked.filter(([, p]) => p.startsWith("data/archive/")).map(([, p]) => p), ["data/archive/search.json", "data/archive/2026-11.json", "data/archive/2026-10.json"]);
  assert.deepEqual(on.rep.findings.find((x) => x.cve === SSH).incidents.cited.map((c) => c.event_id), CITED);
  const b = mk(); await scan(["--online", "--source", "https://cyberview.example/"], [], { fetchImpl: b.fetchImpl });
  assert.ok(b.asked.every(([, p]) => !p.startsWith("data/archive/")));
  // the allowlist admits only the archive's index and month files, nothing else under data/archive or data/events
  for (const p of ["data/archive/search.json", "data/archive/2026-11.json"]) assert.ok(ALLOWED.test(p), p);
  for (const p of ["data/archive/events.jsonl", "data/archive/index.json", "data/archive/undated.json", "data/archive/../workbench.json", "data/events/2026-11/x.json", "data/bundle.json"]) assert.ok(!ALLOWED.test(p), p);
  await assert.rejects(webSource("https://cyberview.example/", { fetchImpl: a.fetchImpl }).json("data/archive/events.jsonl"), /not a CyberView data file/);
});

test("cite.mjs never reaches a target: no probe, UDP, socket or HTTP client, only the data source it is handed", async () => {
  const src = readFileSync(new URL("../../scanner/lib/cite.mjs", import.meta.url), "utf8");
  const imports = src.split("\n").filter((l) => /^\s*import\b/.test(l)).join("\n");
  assert.deepEqual(imports.match(/from\s+"[^"]+"/g), ['from "node:fs"', 'from "node:path"', 'from "./data.mjs"']);   // data.mjs: DEFAULT_SOURCE only
  assert.doesNotMatch(src, /\bfetch\s*\(|\.connect\s*\(|createSocket|child_process|probePort|udpProbe/);
  // pure use: a source that only serves files; attachHunt and attachIncidents take plain data
  const s = dirSource(makeSnap()), loaded = await loadIncidents(s, [SSH, "not-a-cve"]);
  const f = attachHunt(attachIncidents([{ cve: SSH }, { cve: "CVE-2026-90999" }], loaded), { hunt: HUNT.hunt, guides: {} });
  assert.deepEqual(f[0].incidents.cited.map((c) => c.event_id), CITED); assert.equal(f[1].incidents, undefined); assert.equal(f[1].hunt, undefined);
  assert.equal(huntLink({ name: "x", format: "exe", url: "https://a.example/x" }), null);
  assert.equal(huntLink({ name: "x", format: "yara", url: "javascript:alert(1)" }), null);
});
