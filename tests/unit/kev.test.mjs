// scripts/lib/kev.mjs: which CISA catalog entries scripts/feeds.mjs writes to data/kev/. Run: node --test tests/unit/
import test from "node:test";
import assert from "node:assert/strict";
import { kevToImport } from "../../scripts/lib/kev.mjs";

const v = (cveID, dateAdded) => ({ cveID, dateAdded, vendorProject: "V", product: "P" });
const catalog = [
  v("CVE-2026-125350", "2026-11-17"),   // recent, 6-digit sequence
  v("CVE-2026-84869", "2026-09-11"),    // older than 45 days; an event on file names it (the reported gap)
  v("CVE-2021-44228", "2021-12-10"),    // old, named by an event
  v("CVE-2020-0001", "2020-01-01"),     // old, not named: stays out
  v("not-a-cve", "2026-11-18"),
  null,
];

test("recent entries are imported; older ones only when an event on file names the CVE", () => {
  const ids = kevToImport(catalog, "2026-10-05", new Set(["CVE-2026-84869", "CVE-2021-44228"])).map((x) => x.cveID);
  assert.deepEqual(ids, ["CVE-2026-125350", "CVE-2026-84869", "CVE-2021-44228"]);
});

test("without events on file only the last 45 days come in, and bad input is ignored", () => {
  assert.deepEqual(kevToImport(catalog, "2026-10-05").map((x) => x.cveID), ["CVE-2026-125350"]);
  assert.deepEqual(kevToImport(undefined, "2026-10-05"), []);
});
