// scan-ics-identify report surfacing: the industrial (ICS/OT) devices --ics identifies (hosts[].ics, written by
// scanner/lib/ics.mjs) must appear in summary.txt, inventory.csv and report.html — inventory only, low confidence, and
// NEVER in the known-exploited / Critical / Act / overdue headline counts. A report without --ics shows no such section
// and adds no inventory rows. These tests render only; nothing is sent (no probe, ics or net code is touched).
import { test } from "node:test";
import assert from "node:assert/strict";
import { summarize, coverage, summaryText, toInventory, icsDevices } from "../../scanner/lib/report.mjs";
import { toHtml } from "../../scanner/lib/html-report.mjs";
import { icsRecord, ICS_PROTOCOLS } from "../../scanner/lib/ics.mjs";
import * as FX from "../fixtures/scanner/ics/servers.mjs";

/** An "identified" hosts[].ics record built from the loopback fixtures' real protocol replies (parsed by icsRecord). */
const idRec = (key, replies) => icsRecord(key, { port: ICS_PROTOCOLS[key].port, transport: ICS_PROTOCOLS[key].transport, sent: replies.length, state: "open", replies, error: "" });
const modbus = () => idRec("modbus", [FX.modbusReply([["Schneider Electric"], ["BMXP342020"], ["V2.60"]])]);
const enip = () => idRec("enip", [FX.enipReply({ name: "1756-L71/B LOGIX5571", major: 20, minor: 11 })]);
const s7 = () => idRec("s7", [FX.s7Cc(), FX.s7SetupAck(), FX.s7Szl({ order: "6ES7 214-1AG40-0XB0", fw: [4, 2, 1] })]);

const finding = (o = {}) => ({
  rank: 1, cve: "CVE-2026-0001", title: "Fixture flaw", vendor: "OpenBSD", product: "OpenSSH", state: "affected",
  kev: true, kev_added: "2026-10-20", cisa_due: "2026-11-10", overdue: true, ransomware: false, epss: 0.4,
  rating: { score: 9.1, band: "Critical", text: "Critical" },
  priority: { decision: "act", label: "Act", rank: 3, fix_by: { text: "within 3 days" } },
  points: { total: 60, list: [{ points: 35, why: "Known exploited (CISA)" }] },
  confidence: "high", confidence_why: "version inside the affected range",
  seen_on: [{ host: "10.0.0.6", names: [], port: 22, product: "OpenSSH", version: "9.6", shown_version: "9.6p1", state: "affected", confidence: "high", confidence_why: "range" }],
  fix: { fixed_in: ["9.8"], vendor_fixed: [], workaround: [], cisa_required_action: "", advisory: null, details: "", references: [] },
  ...o,
});

/** A report whose host carries three identified ICS devices, plus one real (known-exploited) software finding. */
function report({ ics = true } = {}) {
  const host = { address: "10.0.0.6", names: ["plc.lab"], up: true, ports: [{ port: 502, state: "open" }], services: [{ vendor: "OpenBSD", product: "OpenSSH", version: "9.6", shown_version: "9.6p1" }], observations: [] };
  if (ics) host.ics = [modbus(), enip(), s7(),
    { protocol: "bacnet", name: "BACnet/IP", port: 47808, outcome: "no answer", messages_sent: 1, inventory_only: true }];   // a non-identified record must not render
  const hosts = [host], findings = [finding()];
  return {
    run: { started_at: "2026-11-23T10:00:00Z", finished_at: "2026-11-23T10:01:00Z", interrupted: false, stop_reason: "", ports: [502], settings: { rate: 5, concurrency: 4, hostConcurrency: 2, hostBudget: 300, budget: 20000, minutes: 60 }, network: { connections: 1, sends: {} }, data: { mode: "offline" } },
    scope: { file: "scope.json", sha256: "ab".repeat(32), owner: "Lab", contact: "c@example.org", attestation: { statement: "s", name: "Op", date: "2026-11-20" }, targets: ["10.0.0.0/24"], exclude: [], public_addresses: 0, public_confirmed: false, refused: [] },
    summary: summarize(hosts, findings), coverage: coverage(hosts.map((h) => ({ ...h, outcomes: [{ port: 502, state: "open" }] })), { ports: [502] }),
    hosts, findings, named: [], notes: [],
  };
}

test("icsDevices surfaces only identified records, with the real parsed fields", () => {
  const ds = icsDevices(report());
  assert.equal(ds.length, 3, "the non-identified bacnet record is left out");
  const m = ds.find((d) => d.protocol === "modbus");
  assert.equal(m.vendor, "Schneider Electric"); assert.equal(m.model, "BMXP342020"); assert.equal(m.firmware, "V2.60"); assert.equal(m.port, 502);
  const e = ds.find((d) => d.protocol === "enip");
  assert.equal(e.vendor, "Rockwell Automation/Allen-Bradley"); assert.equal(e.product, "1756-L71/B LOGIX5571"); assert.equal(e.firmware, "20.11");
  const s = ds.find((d) => d.protocol === "s7");
  assert.equal(s.vendor, "Siemens"); assert.equal(s.product, "6ES7 214-1AG40-0XB0"); assert.equal(s.firmware, "4.2.1");
  assert.equal(icsDevices(report({ ics: false })).length, 0);
});

test("summary.txt lists the industrial devices and marks them inventory-only, not in the counts", () => {
  const txt = summaryText(report());
  assert.match(txt, /Industrial \(ICS\/OT\) devices/);
  assert.match(txt, /inventory only, low confidence, not in the counts above/);
  assert.match(txt, /Schneider Electric/);
  assert.match(txt, /1756-L71\/B LOGIX5571/);
  assert.match(txt, /6ES7 214-1AG40-0XB0/);
  // no industrial section, no device text when --ics did not run
  const off = summaryText(report({ ics: false }));
  assert.doesNotMatch(off, /Industrial \(ICS\/OT\) devices/);
  assert.doesNotMatch(off, /Schneider Electric/);
});

test("inventory.csv adds the industrial devices as rows (same columns, marked industrial/guessed) and none without --ics", () => {
  const csv = toInventory(report());
  const head = csv.split("\r\n")[0];
  assert.equal(head, "name,version,vendor,count", "no new columns");
  assert.match(csv, /"1756-L71\/B LOGIX5571 \(industrial, guessed\)",20\.11,Rockwell/);
  assert.match(csv, /"6ES7 214-1AG40-0XB0 \(industrial, guessed\)",4\.2\.1,Siemens/);
  assert.ok(csv.includes("OpenSSH"), "the ordinary software inventory row is still present");
  const off = toInventory(report({ ics: false }));
  assert.doesNotMatch(off, /industrial, guessed/);
  assert.equal(off.split("\r\n").filter(Boolean).length, 2, "header + one ordinary software row only");
});

test("report.html has an Industrial (ICS/OT) section with the devices, and none without --ics", () => {
  const h = toHtml(report());
  assert.match(h, /<h2 id="industrial">Industrial \(ICS\/OT\) devices<\/h2>/);
  assert.match(h, /Schneider Electric/);
  assert.match(h, /1756-L71\/B LOGIX5571/);
  assert.match(h, /never matched to CVEs/);
  assert.doesNotMatch(toHtml(report({ ics: false })), /id="industrial"/);
});

test("ICS devices never enter the known-exploited / Critical / Act / overdue headline counts", () => {
  const s = report().summary;
  // the single ordinary finding is the only thing counted; the three ICS devices add nothing
  assert.equal(s.known_exploited, 1); assert.equal(s.critical, 1); assert.equal(s.act, 1); assert.equal(s.overdue, 1);
  assert.equal(s.findings, 1);
  assert.deepEqual(report().summary, report({ ics: false }).summary, "the counts are identical with and without --ics results");
});
