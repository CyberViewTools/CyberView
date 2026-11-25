// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// fix (offline): from the operator's own Windows package list (Get-Package | Export-Csv), a plan and a PowerShell script that
// removes superseded side-by-side versions (an old .NET 8.0.8 beside 8.0.22), moves end-of-support runtimes to the current
// major, and asks winget to bring everything else to the latest version it offers, flagged software first.
// The scanner runs nothing: this module only turns text into text. The operator reads the script and runs it; it is a dry
// run unless they pass -Apply. Every name from the list is untrusted: only names made of plain characters reach the script
// (as single-quoted PowerShell strings), anything else is listed for the operator to handle by hand.
import { clip } from "./imports.mjs";
import { W } from "./shared.mjs";

export const FIX_LIMITS = Object.freeze({ items: 5000, actions: 600 });

/**
 * .NET support windows (Microsoft's .NET support policy). Dated: a plan made long after `as_of` says the table may be old.
 * An end of support given only as a month (YYYY-MM) is still running in that month.
 */
export const SUPPORT = Object.freeze({
  as_of: "2026-11-25",
  source: "https://dotnet.microsoft.com/platform/support/policy/dotnet-core",
  dotnet: Object.freeze({ latest: 10, ends: Object.freeze({ 5: "2022-05-10", 6: "2024-11-12", 7: "2024-05-14", 8: "2026-11-10", 9: "2026-11-10", 10: "2028-11" }) }),
});

/** The .NET installers that sit side by side. `winget` is the package family; the major is appended (Microsoft.DotNet.DesktopRuntime.10). */
export const RUNTIMES = Object.freeze([
  { id: "desktop", label: ".NET Desktop Runtime", re: /^Microsoft Windows Desktop Runtime - (\d+\.\d+\.\d+)(?:\s*\((x64|x86|arm64)\))?$/i, winget: "Microsoft.DotNet.DesktopRuntime" },
  { id: "runtime", label: ".NET Runtime", re: /^Microsoft \.NET Runtime - (\d+\.\d+\.\d+)(?:\s*\((x64|x86|arm64)\))?$/i, winget: "Microsoft.DotNet.Runtime" },
  { id: "aspnet", label: "ASP.NET Core Runtime", re: /^Microsoft ASP\.NET Core (\d+\.\d+\.\d+) (?:- )?Shared Framework(?:\s*\((x64|x86|arm64)\))?$/i, winget: "Microsoft.DotNet.AspNetCore" },
  { id: "sdk", label: ".NET SDK", re: /^Microsoft \.NET SDK (\d+\.\d+\.\d+)(?:\s*\((x64|x86|arm64)\))?$/i, winget: "Microsoft.DotNet.SDK" },
]);
// parts a runtime or SDK installs with itself (removed with it, never on their own)
const COMPONENT = /^Microsoft (?:\.NET|ASP\.NET Core|Windows Desktop)\b.*\b(Host|Targeting Pack|AppHost Pack|Toolset|Templates|Manifest|Workload|Documentation|Standard)\b/i;
// what Windows Update or Visual Studio manages, not this script
const SKIP = [[/^(Security )?Update for |^Hotfix for |\(KB\d{5,8}\)/i, "a Windows or Office update (KB): Windows Update manages it"],
  [/\bfrom Visual Studio\b/i, "installed by Visual Studio: the Visual Studio Installer manages it"]];
// the only names written into the script; anything else (quotes, $, backticks, non-ASCII) is left for the operator by hand
const SAFE = /^[A-Za-z0-9 .,+()_&/:#@[\]-]{2,120}$/;
const ARCH = /^(x64|x86|arm64)$/;

const dotted = (s) => { const m = String(s || "").match(/\d+(?:\.\d+){1,3}/g); return m ? m[m.length - 1] : ""; };
const majorMinor = (v) => { const p = String(v || "").split("."); return p.length >= 2 ? `${Number(p[0])}.${Number(p[1])}` : String(Number(p[0]) || ""); };
const genericKey = (name) => W.norm(name.replace(/\d+(?:\.\d+)+/g, " ").replace(/\((x64|x86|arm64|64-bit|32-bit)\)/gi, " $1 "));
const ended = (end, today) => !!end && (end.length === 7 ? end < today.slice(0, 7) : end < today);
const psq = (s) => `'${s}'`;   // only ever called on SAFE text, which holds no quote of any kind

/**
 * items: the parsed Windows package list (imports.mjs parsePackages); findings: matchInventory(...) or [].
 * -> { entries, actions, by_hand, skipped, flagged, support, notes }
 */
export function planFix(items, { today = new Date().toISOString().slice(0, 10), findings = [] } = {}) {
  const notes = [], skipped = [], byHand = [], seen = new Map();
  const flagOf = new Map();
  for (const f of findings || []) for (const it of f.items || []) if (it.state === "affected" || it.state === "check") {
    const k = clip(it.name, 120); if (!flagOf.has(k)) flagOf.set(k, []);
    flagOf.get(k).push({ cve: f.cve, kev: !!f.kev, due: f.cisa_due || "", state: it.state, fixed_in: (f.fixed_in || []).slice(0, 4) });
  }
  for (const it of (items || []).slice(0, FIX_LIMITS.items)) {
    const name = clip(it.name, 120); if (name.length < 2) continue;
    const skip = SKIP.find(([re]) => re.test(name));
    if (skip) { skipped.push({ name, why: skip[1] }); continue; }
    let fam = null, version = "", arch = "";
    for (const f of RUNTIMES) { const m = f.re.exec(name); if (m) { fam = f; version = m[1]; arch = (m[2] || "x64").toLowerCase(); break; } }
    if (!fam && COMPONENT.test(name)) { skipped.push({ name, why: "part of a .NET runtime or SDK: it is removed with that runtime" }); continue; }
    if (!fam) version = dotted(name) || dotted(clip(it.version, 40));
    const key = fam ? `${fam.id}|${arch}` : genericKey(name);
    const id = `${name}|${version}`;
    if (seen.has(id)) continue;   // Get-Package lists a bundle and its MSI under one name: one entry
    seen.set(id, { name, version, family: fam ? fam.id : "", label: fam ? fam.label : name, arch: ARCH.test(arch) ? arch : "", key, safe: SAFE.test(name), flags: flagOf.get(name) || [] });
  }
  const entries = [...seen.values()];
  const groups = new Map();
  for (const e of entries) { if (!groups.has(e.key)) groups.set(e.key, []); groups.get(e.key).push(e); }

  const actions = [];
  const push = (a) => { if (actions.length < FIX_LIMITS.actions) actions.push(a); };
  const removeOrHand = (e, step, why) => { if (e.safe) push({ step, kind: "remove", name: e.name, version: e.version, why }); else byHand.push({ name: e.name, version: e.version, what: "remove", why }); };

  // 1. flagged software first: CyberView's known-exploited and affected matches
  for (const e of entries.filter((x) => x.flags.length && !x.family)) {
    const why = e.flags.slice(0, 4).map((f) => `${f.cve}${f.kev ? " (known exploited)" : ""}`).join(", ");
    if (e.safe) push({ step: "flagged", kind: "upgrade-name", name: e.name, version: e.version, why }); else byHand.push({ name: e.name, version: e.version, what: "update", why });
  }
  // 2. .NET: current patch for every supported major, the current major where an old one is out of support,
  //    superseded patches removed, out-of-support majors removed only with -RemoveEndOfSupport
  const ends = SUPPORT.dotnet.ends, latest = SUPPORT.dotnet.latest;
  for (const f of RUNTIMES) for (const arch of ["x64", "x86", "arm64"]) {
    const list = groups.get(`${f.id}|${arch}`); if (!list || !list.length) continue;
    const archArg = arch === "x64" ? "" : arch;
    const majors = [...new Set(list.map((e) => Number(e.version.split(".")[0])))].sort((a, b) => a - b);
    for (const mj of majors) {
      const inMajor = list.filter((e) => Number(e.version.split(".")[0]) === mj).sort((a, b) => W.cmp(b.version, a.version));
      const newest = inMajor[0], flags = list.flatMap((e) => e.flags).map((x) => x.cve);
      const end = ends[mj] || "", out = ended(end, today);
      if (!out) push({ step: "runtimes", kind: "upgrade-id", id: `${f.winget}.${mj}`, arch: archArg, name: `${f.label} ${mj} (${arch})`, version: newest.version, why: `latest ${mj}.0 patch${flags.length ? `; flagged ${[...new Set(flags)].slice(0, 3).join(", ")}` : ""}` });
      for (const old of inMajor.slice(1)) removeOrHand(old, "superseded", `superseded by ${f.label} ${newest.version} (${arch}), already installed; apps use the newest ${mj}.0 patch on their own`);
      if (out) {
        // only the newest patch: the older ones are already planned as superseded
        for (const e of inMajor.slice(0, 1)) if (e.safe) push({ step: "end-of-support", kind: "remove", name: e.name, version: e.version, why: `${f.label} ${mj} support ended ${end}; apps built for ${mj} stop starting until they move to ${latest}` });
          else byHand.push({ name: e.name, version: e.version, what: "remove (out of support)", why: `${f.label} ${mj} support ended ${end}` });
      }
    }
    if (majors.some((mj) => ended(ends[mj] || "", today)) && !majors.includes(latest)) {
      push({ step: "runtimes", kind: "install-id", id: `${f.winget}.${latest}`, arch: archArg, name: `${f.label} ${latest} (${arch})`, version: "", why: `the current .NET (${latest}, supported to ${ends[latest]}) for the out-of-support ${majors.filter((mj) => ended(ends[mj] || "", today)).join(", ")}` });
    }
    if (majors.some((mj) => !ends[mj])) notes.push(`${f.label}: major ${majors.filter((mj) => !ends[mj]).join(", ")} is not in the support table (as of ${SUPPORT.as_of}); check ${SUPPORT.source}`);
  }
  // 3. other software installed twice in the same major.minor (an old copy left behind by an upgrade): keep the newest
  for (const [, list] of groups) {
    if (list[0].family || list.length < 2) continue;
    const buckets = new Map();
    for (const e of list) { if (!e.version) continue; const mm = majorMinor(e.version); if (!buckets.has(mm)) buckets.set(mm, []); buckets.get(mm).push(e); }
    for (const [, b] of buckets) {
      if (b.length < 2) continue;
      b.sort((x, y) => W.cmp(y.version, x.version));
      for (const old of b.slice(1)) removeOrHand(old, "superseded", `an older copy of ${b[0].name} ${b[0].version}, which is also installed`);
    }
  }
  const stale = (Date.parse(today) - Date.parse(SUPPORT.as_of)) / 864e5;
  if (stale > 180) notes.push(`the .NET support table is from ${SUPPORT.as_of}, ${Math.round(stale)} days ago: use a newer scanner, or check ${SUPPORT.source}`);
  if (actions.length >= FIX_LIMITS.actions) notes.push(`more than ${FIX_LIMITS.actions} actions: the rest are left out; run the script, export the list again and plan again`);
  return { today, entries, actions, by_hand: byHand, skipped, flagged: entries.filter((e) => e.flags.length).map((e) => ({ name: e.name, version: e.version, flags: e.flags })), support: SUPPORT, notes };
}

const STEP_TITLE = { flagged: "Flagged by CyberView (update first)", runtimes: ".NET: current versions", superseded: "Remove superseded copies", "end-of-support": "Remove out-of-support .NET (only with -RemoveEndOfSupport)" };

/** The plan as text, for the operator to read before running anything. */
export function fixText(plan, { file = "", version = "" } = {}) {
  const L = [`CyberView fix plan${version ? ` (scanner ${version})` : ""}, ${plan.today}${file ? `, from ${file}` : ""}`,
    `${plan.entries.length} installed item(s) read; ${plan.actions.length} planned action(s); ${plan.by_hand.length} to do by hand.`,
    "Nothing has been changed. The script cyberview-fix.ps1 does a dry run unless you pass -Apply.", ""];
  for (const step of ["flagged", "runtimes", "superseded", "end-of-support"]) {
    const xs = plan.actions.filter((a) => a.step === step); if (!xs.length) continue;
    L.push(STEP_TITLE[step] + ":");
    for (const a of xs) L.push(`  ${a.kind === "remove" ? "remove " : a.kind === "install-id" ? "install" : "update "} ${a.name}${a.version && a.kind === "remove" ? "" : a.version ? ` (now ${a.version})` : ""}${a.id ? ` [winget ${a.id}${a.arch ? `, ${a.arch}` : ""}]` : ""}: ${a.why}`);
    L.push("");
  }
  L.push("Everything else: the script asks winget which installed apps have a newer version and updates them (winget upgrade --all).",
    "The scanner cannot know the newest version of every app offline; winget does, from its sources, when the script runs.", "");
  if (plan.by_hand.length) { L.push("By hand (names with characters the script will not use):"); plan.by_hand.forEach((b) => L.push(`  ${b.what}: ${b.name}${b.version ? " " + b.version : ""}: ${b.why}`)); L.push(""); }
  if (plan.skipped.length) L.push(`Left alone: ${plan.skipped.length} item(s) (Windows updates, Visual Studio parts, .NET components removed with their runtime).`);
  plan.notes.forEach((n) => L.push("Note: " + n));
  L.push("", "Run it (PowerShell as administrator, in this folder):", "  dry run:  powershell -ExecutionPolicy Bypass -File .\\cyberview-fix.ps1",
    "  apply:    powershell -ExecutionPolicy Bypass -File .\\cyberview-fix.ps1 -Apply",
    "  also remove out-of-support .NET: add -RemoveEndOfSupport (apps built only for that version stop starting)",
    "Afterwards it saves packages-after.csv: run fix or match on it again to confirm.");
  return L.join("\n");
}

/** The PowerShell script. Plan data are single-quoted literals of SAFE text and winget ids built here; nothing else varies. */
export function fixScript(plan, { file = "", version = "" } = {}) {
  const clean = (s) => clip(s, 300).replace(/;/g, ",").replace(/[^A-Za-z0-9 .,+()_&/:#@[\]-]/g, " ");
  // a second gate at the point of writing: a row whose name, id or step is not plain text is never written
  const ok = (a) => SAFE.test(a.name) && /^[A-Za-z0-9.]{0,80}$/.test(a.id || "") && /^(|x86|arm64)$/.test(a.arch || "") && Object.prototype.hasOwnProperty.call(STEP_TITLE, a.step) && /^(remove|upgrade-name|upgrade-id|install-id)$/.test(a.kind);
  const row = (a) => `  @{ Step = ${psq(a.step)}; Kind = ${psq(a.kind)}; Name = ${psq(a.name)}; Id = ${psq(a.id || "")}; Arch = ${psq(a.arch || "")}; Why = ${psq(clean(a.why))} }`;
  const src = clean(file).slice(0, 120);
  const rows = plan.actions.filter(ok).map(row);
  return `# CyberView fix script: written by CyberView Scanner ${version} (fix) on ${plan.today}${src ? ` from ${src}` : ""}.
# READ IT BEFORE YOU RUN IT. It installs, updates and removes software on this computer.
# The scanner ran nothing: you run this. Without -Apply it is a dry run and changes nothing.
#   dry run:  powershell -ExecutionPolicy Bypass -File .\\cyberview-fix.ps1
#   apply:    powershell -ExecutionPolicy Bypass -File .\\cyberview-fix.ps1 -Apply   (PowerShell opened as administrator)
#   -RemoveEndOfSupport also removes .NET versions Microsoft no longer supports; apps built only for them stop starting.
# Order: flagged software, then .NET (current patch, current major), then winget upgrade --all, and only then removals,
# so nothing is removed before its replacement is in place. A log and packages-after.csv are written next to this file.
#Requires -Version 5.1
[CmdletBinding()]
param([switch]$Apply, [switch]$RemoveEndOfSupport)
Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

$Plan = @(
${rows.join(",\n")}
)

$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$results = New-Object System.Collections.Generic.List[object]
function Note([string]$step, [string]$what, [string]$state, [string]$detail) {
  $results.Add([pscustomobject]@{ Step = $step; Item = $what; Result = $state; Detail = $detail })
  Write-Host ('[{0}] {1}: {2} {3}' -f $step, $what, $state, $detail)
}
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
  Write-Host 'winget was not found. Install or update App Installer from the Microsoft Store, then run this again.'; exit 1
}
if ($Apply) {
  $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $admin) { Write-Host 'Open PowerShell with Run as administrator: installing and removing runtimes needs it.'; exit 1 }
}
if ($Apply) { Start-Transcript -Path (Join-Path $here "cyberview-fix-$stamp.log") | Out-Null }
Write-Host ($(if ($Apply) { 'APPLYING the plan.' } else { 'DRY RUN: nothing will change. Add -Apply to make these changes.' }))

$get = @('--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity', '--silent')
$del = @('--accept-source-agreements', '--disable-interactivity', '--silent')
function Explain([int]$code) {
  switch ($code) {
    0 { 'done' }
    -1978335189 { 'already current' }
    -1978335212 { 'winget does not know it by this name' }
    -1978335211 { 'more than one match: do it by hand in Settings, Apps' }
    default { 'failed (winget exit code ' + $code + ')' }
  }
}
function Invoke-Winget([string]$step, [string]$what, [string[]]$wargs, [string[]]$extra) {
  if (-not $Apply) { Note $step $what 'would run' ('winget ' + ($wargs -join ' ')); return }
  & winget @wargs @extra | Out-Host
  $state = Explain $LASTEXITCODE
  Note $step $what $state ''
}

foreach ($a in @($Plan | Where-Object { $_.Step -eq 'flagged' })) { Invoke-Winget 'flagged' $a.Name @('upgrade', '--name', $a.Name, '--exact') $get }
foreach ($a in @($Plan | Where-Object { $_.Step -eq 'runtimes' })) {
  $verb = if ($a.Kind -eq 'install-id') { 'install' } else { 'upgrade' }
  $w = @($verb, '--id', $a.Id, '--exact')
  if ($a.Arch) { $w += @('--architecture', $a.Arch) }
  Invoke-Winget 'runtimes' $a.Name $w $get
}
Write-Host 'Everything else with a newer version, as winget sees it:'
& winget upgrade --accept-source-agreements --disable-interactivity | Out-Host
if ($Apply) { & winget upgrade --all @get | Out-Host; Note 'upgrade-all' 'winget upgrade --all' (Explain $LASTEXITCODE) '' }
else { Note 'upgrade-all' 'winget upgrade --all' 'would run' 'updates every app listed above' }
foreach ($a in @($Plan | Where-Object { $_.Step -eq 'superseded' })) { Invoke-Winget 'superseded' $a.Name @('uninstall', '--name', $a.Name, '--exact') $del }
foreach ($a in @($Plan | Where-Object { $_.Step -eq 'end-of-support' })) {
  if ($RemoveEndOfSupport) { Invoke-Winget 'end-of-support' $a.Name @('uninstall', '--name', $a.Name, '--exact') $del }
  else { Note 'end-of-support' $a.Name 'kept' 'add -RemoveEndOfSupport to remove it' }
}

if ($Apply) {
  try { Get-Package | Select-Object Name, Version, ProviderName | Export-Csv -NoTypeInformation -Path (Join-Path $here 'packages-after.csv'); Write-Host 'Saved packages-after.csv: plan again on it to confirm.' }
  catch { Write-Host 'Could not save packages-after.csv.' }
}
$results | Format-Table -AutoSize | Out-Host
if ($Apply) { Stop-Transcript | Out-Null }
`;
}
