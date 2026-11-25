// ORKL library ingest (scripts/orkl.mjs): metadata + links only, never the report text. Run: node --test tests/unit/
import test from "node:test";
import assert from "node:assert/strict";
import { cleanReport, cleanActor, mergeReports, summarize, siteData, https, archiveUrl } from "../../scripts/orkl.mjs";

const rawReport = () => ({
  id: "11111111-2222-3333-4444-555555555555",
  sha1_hash: "ABCDEF0123456789abcdef0123456789ABCDEF01",
  title: "APT Example: a campaign report",
  llm_title: "A campaign report about APT Example",
  authors: "Jane Doe, John Roe",
  file_creation_date: "2024-05-01T00:00:00Z",
  created_at: "2024-05-02T09:30:00Z",
  updated_at: "2024-05-02T09:30:00Z",
  file_size: 1234567,
  language: "EN",
  sources: ["Malpedia", "web"],
  origins: ["web"],
  references: ["https://vendor.example/report.pdf", "http://insecure.example/x", "ftp://bad.example/y", "not a url"],
  threat_actors: [{ id: "a1", main_name: "APT Example" }, { id: "a2", main_name: "Second Group" }],
  files: { pdf: "https://archive.orkl.eu/abcdef0123456789abcdef0123456789abcdef01.pdf", text: "https://archive.orkl.eu/abcdef0123456789abcdef0123456789abcdef01.txt", img: "https://archive.orkl.eu/x.png" },
  plain_text: "SECRET FULL REPORT TEXT THAT MUST NEVER BE STORED",
});

test("cleanReport keeps metadata and links, never the plain_text", () => {
  const r = cleanReport(rawReport());
  assert.equal(r.id, "11111111-2222-3333-4444-555555555555");
  assert.equal(r.sha1, "abcdef0123456789abcdef0123456789abcdef01");           // lowercased
  assert.equal(r.title, "APT Example: a campaign report");
  assert.deepEqual(r.authors, ["Jane Doe", "John Roe"]);                        // comma-split string
  assert.equal(r.lang, "en");                                                    // lowercased
  assert.deepEqual(r.sources, ["Malpedia", "web"]);
  assert.deepEqual(r.actors, ["APT Example", "Second Group"]);
  assert.equal(r.url, "https://orkl.eu/library/11111111-2222-3333-4444-555555555555");
  assert.equal(r.pdf, "https://archive.orkl.eu/abcdef0123456789abcdef0123456789abcdef01.pdf");
  assert.equal(r.txt_url, "https://archive.orkl.eu/abcdef0123456789abcdef0123456789abcdef01.txt");
  // the whole record, serialised, must not leak the report body anywhere
  const blob = JSON.stringify(r);
  assert.ok(!/SECRET FULL REPORT TEXT/.test(blob), "plain_text leaked into the record");
  assert.ok(!("plain_text" in r) && !("text" in r) && !("body" in r));
});

test("cleanReport filters references to https and caps them", () => {
  const r = cleanReport(rawReport());
  assert.deepEqual(r.refs, ["https://vendor.example/report.pdf"]);              // http/ftp/junk dropped
  const many = rawReport(); many.references = Array.from({ length: 80 }, (_, i) => `https://ref.example/${i}`);
  assert.ok(cleanReport(many).refs.length <= 30);
});

test("archiveUrl allows only the orkl archive host over https", () => {
  assert.equal(archiveUrl("https://archive.orkl.eu/a.pdf"), "https://archive.orkl.eu/a.pdf");
  assert.equal(archiveUrl("https://orkl.eu/a.pdf"), "https://orkl.eu/a.pdf");
  assert.equal(archiveUrl("https://evil.example/a.pdf"), "");                   // foreign host dropped
  assert.equal(archiveUrl("http://archive.orkl.eu/a.pdf"), "");                 // must be https
  assert.equal(archiveUrl("https://archive.orkl.eu.evil.com/a.pdf"), "");       // not a suffix trick
});

test("https() returns only valid https urls", () => {
  assert.equal(https("https://a.example/x"), "https://a.example/x");
  assert.equal(https("http://a.example/x"), "");
  assert.equal(https("javascript:alert(1)"), "");
  assert.equal(https(""), "");
  assert.equal(https(null), "");
});

test("cleanReport applies length limits and needs a sha1", () => {
  const big = rawReport();
  big.title = "T".repeat(5000);
  big.authors = Array.from({ length: 60 }, (_, i) => `Author ${i}`).join(", ");
  assert.ok(cleanReport(big).title.length <= 301);
  assert.ok(cleanReport(big).authors.length <= 20);
  assert.equal(cleanReport({ ...rawReport(), sha1_hash: "" }), null);           // no sha1 -> unkeyable
  assert.equal(cleanReport({ ...rawReport(), sha1_hash: "nothex" }), null);
});

test("cleanActor keeps names, aliases and tools, needs id and name", () => {
  const a = cleanActor({ id: "ta-1", main_name: "APT Example", aliases: ["Group A", "Group B"], source_name: "ETDA", source_id: "s9", tools: ["cobalt strike", { name: "mimikatz" }] });
  assert.equal(a.id, "ta-1");
  assert.equal(a.name, "APT Example");
  assert.deepEqual(a.aliases, ["Group A", "Group B"]);
  assert.equal(a.source, "ETDA");
  assert.deepEqual(a.tools, ["cobalt strike", "mimikatz"]);                      // object tool -> name
  assert.equal(cleanActor({ id: "", main_name: "x" }), null);
  assert.equal(cleanActor({ id: "x", main_name: "" }), null);
});

test("mergeReports is additive: existing records are never dropped", () => {
  const prev = { "ab": { abcdef0123456789abcdef0123456789abcdef01: cleanReport(rawReport()) } };
  const second = cleanReport({ ...rawReport(), id: "99999999-2222-3333-4444-555555555555", sha1_hash: "ab00000000000000000000000000000000000000", title: "Second report" });
  const merged = mergeReports(prev, [second]);
  assert.equal(Object.keys(merged.ab).length, 2);                               // both share shard "ab"
  assert.ok(merged.ab.abcdef0123456789abcdef0123456789abcdef01);                // the old one survived
  assert.ok(merged.ab.ab00000000000000000000000000000000000000);
  // a fresh copy of an existing sha1 replaces (updates) in place, never duplicates
  const updated = cleanReport({ ...rawReport(), title: "Corrected title" });
  const merged2 = mergeReports(merged, [updated]);
  assert.equal(merged2.ab.abcdef0123456789abcdef0123456789abcdef01.title, "Corrected title");
});

test("summarize and siteData report counts without any report body", () => {
  const reports = [cleanReport(rawReport()), cleanReport({ ...rawReport(), sha1_hash: "bb00000000000000000000000000000000000000", id: "22222222-2222-3333-4444-555555555555", language: "NL", created_at: "2024-06-01T00:00:00Z" })];
  const actors = [cleanActor({ id: "a1", main_name: "APT Example" })];
  const state = summarize(reports, actors, { at: "2026-11-25T00:00:00Z", library_version: 620, health: { ok: true }, backfill_done: true });
  assert.equal(state.reports_total, 2);
  assert.equal(state.actors_total, 1);
  assert.equal(state.languages.en, 1);
  assert.equal(state.languages.nl, 1);
  assert.ok(state.top_actors.find((t) => t.name === "APT Example").count === 2);
  const sd = siteData(state, "2026-11-25T01:00:00Z");
  assert.equal(sd.reports, 2);
  assert.equal(sd.actors, 1);
  assert.equal(sd.built_at, "2026-11-25T01:00:00Z");
  assert.ok(sd.recent.length <= 30);
  assert.ok(!/SECRET FULL REPORT TEXT/.test(JSON.stringify(sd)));
  assert.equal(siteData(null), null);
});
