import { test } from "node:test";
import assert from "node:assert/strict";
import { compact, parseEpss, bucket, deltaSince, notable, toLead, bestCvss } from "../../scripts/lib/cve.mjs";

const rec = {
  cveMetadata: { cveId: "CVE-2024-3400", state: "PUBLISHED", assignerShortName: "palo_alto", datePublished: "2024-04-12T07:20:00.707Z", dateUpdated: "2025-10-21T23:05:21.315Z" },
  containers: {
    cna: { title: "PAN-OS: command injection", descriptions: [{ lang: "en", value: "A command injection   vulnerability." }], affected: [{ vendor: "Palo Alto Networks", product: "PAN-OS" }],
      metrics: [{ cvssV3_1: { baseScore: 10, baseSeverity: "CRITICAL" } }], problemTypes: [{ descriptions: [{ cweId: "CWE-77" }] }] },
    adp: [{ metrics: [{ other: { type: "ssvc", content: { options: [{ Exploitation: "active" }, { Automatable: "yes" }] } } }, { other: { type: "kev", content: { dateAdded: "2024-04-12" } } }] }],
  },
};

test("a CVE JSON 5 record becomes one compact row with CISA's enrichment", () => {
  const r = compact(rec);
  assert.equal(r.id, "CVE-2024-3400"); assert.equal(r.state, "P"); assert.equal(r.pub, "2024-04-12"); assert.equal(r.upd, "2025-10-21");
  assert.equal(r.cvss, 10); assert.equal(r.sev, "C"); assert.equal(r.ver, "3.1"); assert.equal(r.cwe, "CWE-77");
  assert.equal(r.vendor, "Palo Alto Networks"); assert.equal(r.desc, "A command injection vulnerability."); assert.equal(r.expl, "active"); assert.equal(r.kev, "2024-04-12");
});
test("CVSS falls back to CISA's score, v4 is preferred, and rejected records are marked", () => {
  assert.deepEqual(bestCvss([{ cvssV3_1: { baseScore: 7.5 } }, { cvssV4_0: { baseScore: 8.7, baseSeverity: "HIGH" } }]), { score: 8.7, sev: "H", ver: "4.0" });
  const r = compact({ cveMetadata: { cveId: "CVE-2020-0001", state: "REJECTED", datePublished: "2020-01-01" }, containers: { cna: { rejectedReasons: [{ value: "Duplicate." }] }, adp: [{ metrics: [{ cvssV3_1: { baseScore: 5 } }] }] } });
  assert.equal(r.state, "R"); assert.equal(r.cvss, 5); assert.equal(r.sev, "M"); assert.equal(r.desc, "Duplicate.");
  assert.equal(compact({ cveMetadata: { cveId: "not-a-cve" } }), null);
});
test("EPSS, buckets and the change log", () => {
  const m = parseEpss("#model_version:v2025,score_date:2026-11-19\ncve,epss,percentile\nCVE-2021-44228,0.999990000,1.000000000\nbad,1,1\n");
  assert.deepEqual(m.get("CVE-2021-44228"), [0.99999, 1]); assert.equal(m.size, 1);
  assert.equal(bucket("CVE-2024-3400"), "2024/3"); assert.equal(bucket("CVE-2026-129225"), "2026/129");
  const raw = (id) => `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/1xxx/${id}.json`;
  const log = [
    { fetchTime: "2026-11-19T10:00:00Z", new: [{ cveId: "CVE-2026-1000", githubLink: raw("CVE-2026-1000"), dateUpdated: "2026-11-19T09:59:00Z" }] },
    { fetchTime: "2026-11-19T12:00:00Z", updated: [{ cveId: "CVE-2026-1000", githubLink: raw("CVE-2026-1000"), dateUpdated: "2026-11-19T11:59:00Z" }, { cveId: "CVE-2026-1001", githubLink: "https://evil.example/x.json" }] },
  ];
  const d = deltaSince(log, "2026-11-19T09:00:00Z");
  assert.equal(d.length, 1); assert.equal(d[0].isNew, true); assert.equal(d[0].at, "2026-11-19T11:59:00Z");
  assert.equal(deltaSince(log, "2026-11-19T12:00:00Z").length, 0);
});
test("only exploited, known-exploited or critical new CVEs become leads", () => {
  const r = compact(rec);
  assert.equal(notable({ ...r, pub: "2026-11-18" }, "2026-11-12"), true);
  assert.equal(notable({ ...r, pub: "2026-11-18", expl: "", kev: "", cvss: 6.5 }, "2026-11-12"), false);
  assert.equal(notable({ ...r, pub: "2026-10-01" }, "2026-11-12"), false);
  const l = toLead({ ...r, pub: "2026-11-18" }, "2026-11-19T10:00:00Z");
  assert.equal(l.kind, "exploited"); assert.equal(l.tier, "gov"); assert.match(l.url, /^https:\/\/www\.cve\.org\/CVERecord\?id=CVE-2024-3400$/); assert.match(l.title, /CVSS 10/);
});
