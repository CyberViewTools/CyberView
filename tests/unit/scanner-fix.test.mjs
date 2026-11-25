// The scanner's fix command: a plan and a PowerShell script from the operator's own Windows package list. The scanner runs
// nothing: these tests prove it contacts nothing, that untrusted names never reach the script, that nothing is removed
// before its replacement, and that out-of-support .NET is removed only on the operator's extra switch.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { planFix, fixScript, fixText, SUPPORT } from "../../scanner/lib/fix.mjs";
import { parsePackages } from "../../scanner/lib/imports.mjs";
import { main } from "../../scanner/cyberview-scan.mjs";

const CSV = `#TYPE Microsoft.PackageManagement.Packaging.SoftwareIdentity
"Name","Version","ProviderName"
"Microsoft Windows Desktop Runtime - 8.0.8 (x64)","8.0.8.34004","Programs"
"Microsoft Windows Desktop Runtime - 8.0.8 (x64)","64.32.29000","msi"
"Microsoft Windows Desktop Runtime - 8.0.11 (x64)","8.0.11.34221","Programs"
"Microsoft Windows Desktop Runtime - 6.0.36 (x86)","6.0.36.34217","Programs"
"Microsoft .NET Host FX Resolver - 8.0.11 (x64)","64.44.43800","msi"
"Microsoft .NET SDK 8.0.400 (x64) from Visual Studio","8.4.24.37502","msi"
"Security Update for Microsoft Office 2016 (KB5002700) 64-Bit Edition","","msu"
"Python 3.11.4 (64-bit)","3.11.4150.0","Programs"
"Python 3.11.9 (64-bit)","3.11.9150.0","Programs"
"Python 3.12.1 (64-bit)","3.12.1150.0","Programs"
"Evil'; Remove-Item C:\\ -Recurse; '","1.0.1","Programs"
"Evil'; Remove-Item C:\\ -Recurse; '","1.0.2","Programs"
`;
const items = () => parsePackages(CSV).items;
const of = (plan, step) => plan.actions.filter((a) => a.step === step);

test("after .NET 8's end of support: install 10, drop the superseded patch, keep 8 unless asked", () => {
  const p = planFix(items(), { today: "2026-11-25" });
  assert.deepEqual(of(p, "superseded").map((a) => a.name).filter((n) => /Desktop/.test(n)), ["Microsoft Windows Desktop Runtime - 8.0.8 (x64)"]);
  const inst = of(p, "runtimes").filter((a) => a.kind === "install-id");
  assert.deepEqual(inst.map((a) => `${a.id}|${a.arch}`).sort(), ["Microsoft.DotNet.DesktopRuntime.10|", "Microsoft.DotNet.DesktopRuntime.10|x86"]);
  // only the newest 8.0 patch is an end-of-support removal (the older one is already superseded), and 6 (x86) is too
  assert.deepEqual(of(p, "end-of-support").map((a) => a.name).sort(), ["Microsoft Windows Desktop Runtime - 6.0.36 (x86)", "Microsoft Windows Desktop Runtime - 8.0.11 (x64)"]);
  // components, KB updates and Visual Studio's SDK are left alone; Python 3.11.4 is an orphan beside 3.11.9, 3.12 is not
  assert.ok(p.skipped.some((s) => /Host FX/.test(s.name)) && p.skipped.some((s) => /KB5002700/.test(s.name)) && p.skipped.some((s) => /from Visual Studio/.test(s.name)));
  assert.deepEqual(of(p, "superseded").filter((a) => /Python/.test(a.name)).map((a) => a.name), ["Python 3.11.4 (64-bit)"]);
});

test("while .NET 8 is supported: update it in place, install nothing new, remove nothing out of support", () => {
  const p = planFix(items(), { today: "2026-11-01" });
  assert.ok(of(p, "runtimes").some((a) => a.kind === "upgrade-id" && a.id === "Microsoft.DotNet.DesktopRuntime.8"));
  assert.ok(!of(p, "runtimes").some((a) => a.kind === "install-id" && a.arch === ""));
  assert.ok(!of(p, "end-of-support").some((a) => /8\.0/.test(a.name)));
});

test("an untrusted name never reaches the script: it is listed to do by hand", () => {
  const p = planFix(items(), { today: "2026-11-25" });
  assert.ok(p.by_hand.some((b) => /^Evil/.test(b.name)));
  const ps = fixScript(p, { file: "x.csv", version: "t" });
  assert.ok(!/Evil|Remove-Item/.test(ps));
  // the second gate: even an action handed in directly with an unsafe name, id or step is not written
  const bad = { ...p, actions: [{ step: "superseded", kind: "remove", name: "a'b", why: "x" }, { step: "runtimes", kind: "install-id", name: "ok name", id: "X; Y", why: "x" }, { step: "nope", kind: "remove", name: "fine", why: "x" }] };
  const ps2 = fixScript(bad, {});
  assert.ok(!/a'b|X; Y|'nope'/.test(ps2));
  assert.match(ps2, /\$Plan = @\(\n\n\)/);
});

test("the script is a dry run unless -Apply, removes after upgrading, and removes out-of-support only with -RemoveEndOfSupport", () => {
  const ps = fixScript(planFix(items(), { today: "2026-11-25" }), { file: "LAPTOP.packages.csv", version: "t" });
  assert.match(ps, /param\(\[switch\]\$Apply, \[switch\]\$RemoveEndOfSupport\)/);
  assert.match(ps, /if \(-not \$Apply\) \{ Note \$step \$what 'would run'/);
  const at = (s) => ps.indexOf(s);
  assert.ok(at("Where-Object { $_.Step -eq 'runtimes' }") < at("upgrade --all @get") && at("upgrade --all @get") < at("Where-Object { $_.Step -eq 'superseded' }"));
  assert.match(ps, /if \(\$RemoveEndOfSupport\) \{ Invoke-Winget 'end-of-support'/);
  assert.ok(/^[\x00-\x7f]*$/.test(ps), "ASCII only (Windows PowerShell 5.1 reads a file without a BOM as ANSI)");
  assert.ok(!/Invoke-Expression|iex |DownloadString|Invoke-WebRequest|Start-Process/i.test(ps));
});

test("flagged software comes first, named with its CVE", () => {
  const findings = [{ cve: "CVE-2026-124194", kev: true, cisa_due: "2026-11-24", fixed_in: [], items: [{ name: "Python 3.12.1 (64-bit)", version: "3.12.1", state: "affected" }] }];
  const p = planFix(items(), { today: "2026-11-25", findings });
  assert.equal(p.actions[0].step, "flagged");
  assert.equal(p.actions[0].name, "Python 3.12.1 (64-bit)");
  assert.match(p.actions[0].why, /CVE-2026-124194 \(known exploited\)/);
  assert.match(fixText(p, {}), /Flagged by CyberView/);
});

test("the support table is dated and a stale plan says so", () => {
  assert.ok(/^\d{4}-\d{2}-\d{2}$/.test(SUPPORT.as_of) && SUPPORT.source.startsWith("https://"));
  assert.ok(planFix(items(), { today: "2028-01-01" }).notes.some((n) => /support table is from/.test(n)));
});

test("fix command: writes the plan and script, contacts nothing, refuses a Linux list", async () => {
  const dir = mkdtempSync(join(tmpdir(), "cvfix-")), f = join(dir, "LAPTOP.packages.csv"), out = join(dir, "out");
  writeFileSync(f, CSV);
  const lines = [], err = [], calls = { probe: 0, fetch: 0, resolve: 0 };
  const io = { out: (s) => lines.push(s), err: (s) => err.push(s), probe: async () => { calls.probe++; return {}; }, fetchImpl: () => { calls.fetch++; throw new Error("no network"); }, resolve: async () => { calls.resolve++; throw new Error("no DNS"); } };
  assert.equal(await main(["fix", "--packages", f, "--out", out], io), 0);
  assert.deepEqual(readdirSync(out).sort(), ["cyberview-fix.ps1", "fix-plan.json", "fix-plan.txt"]);
  assert.deepEqual(calls, { probe: 0, fetch: 0, resolve: 0 });
  assert.equal(JSON.parse(readFileSync(join(out, "fix-plan.json"), "utf8")).tool.runs_nothing, true);
  assert.match(lines.join("\n"), /Nothing was installed, removed or sent anywhere/);
  const deb = join(dir, "dpkg.txt"); writeFileSync(deb, "ii  openssl  3.0.2-0ubuntu1.15  amd64  Secure Sockets Layer toolkit\n");
  assert.equal(await main(["fix", "--packages", deb, "--out", join(dir, "o2")], io), 1);
  assert.equal(await main(["fix", "--out", join(dir, "o3")], io), 1);
  assert.equal(await main(["fix", "--packages", f, "--online"], io), 1);
});
