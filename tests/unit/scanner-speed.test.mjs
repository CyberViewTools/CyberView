// The matcher's first-word index (scanner/lib/match.mjs wordIndex) must never change a result: it only skips products
// that nameHit could not match anyway. Checked against the plain nested loop on a mixed list of real-looking names.
import { test } from "node:test";
import assert from "node:assert/strict";
import { wordIndex } from "../../scanner/lib/match.mjs";
import { W } from "../../scanner/lib/shared.mjs";

const names = ["Microsoft Windows Desktop Runtime - 8.0.8 (x64)", "Microsoft Edge", "Google Chrome", "Fortinet FortiOS", "FortiOS", "OpenBSD OpenSSH", "nginx",
  "Apache HTTP Server", "Palo Alto PAN-OS", "VMwareTools", "Node.js", "Microsoft .NET Runtime - 8.0.8 (x64)", "Python 3.12.1 (64-bit)", "Zoom Workplace (64-bit)",
  "Windows Server 2022 Datacenter", "Microsoft Office Professional Plus 2021", "BeyondTrust Remote Support", "jQuery", "Ivanti Connect Secure", "", "7-Zip 24.08 (x64)"];
const products = [["microsoft", "windows"], ["microsoft", "edge"], ["google", "chrome"], ["fortinet", "fortios"], ["openbsd", "openssh"], ["f5", "nginx"], ["apache", "http_server"],
  ["paloaltonetworks", "pan-os"], ["vmware", "tools"], ["vmware", "vmware tools"], ["nodejs", "node.js"], ["microsoft", ".net"], ["python", "python"], ["zoom", "zoom"],
  ["microsoft", "windows server 2022"], ["microsoft", "office"], ["beyondtrust", "remote support"], ["jquery", "jquery"], ["ivanti", "connect secure"], ["acme", "server"], ["igor_pavlov", "7-zip"], ["x", ""]];

test("wordIndex keeps every product nameHit can match, for every name", () => {
  const idx = wordIndex(products, (p) => [p[1]]);
  let hits = 0;
  for (const n of names) {
    const brute = products.filter((p) => W.nameHit(n, p[0], p[1]));
    const fast = idx.for(n).filter((p) => W.nameHit(n, p[0], p[1]));
    assert.deepEqual(new Set(fast), new Set(brute), n);
    hits += brute.length;
  }
  assert.ok(hits > 10, "the list exercises real matches");
  assert.ok(idx.for("Google Chrome").length < products.length, "and it actually narrows the search");
});

test("the name cache returns the same normalised text", () => {
  for (const s of ["Microsoft .NET Runtime", "  PAN-OS  ", "", null, 42]) assert.equal(W.norm(s), W.norm(s));
  assert.equal(W.norm("Node.js 22"), "node js 22");
});
