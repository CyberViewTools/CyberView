// The research queue after many feeds were added at once (2026-11-20): routine bulletins in other languages close by
// rule, "exploit" meaning a feat no longer passes the cyber filter, and a new feed files only its last day.
import { test } from "node:test";
import assert from "node:assert/strict";
import { isCyber, FIRST_RUN_H } from "../../scripts/collect.mjs";
import { ROUTINE, CRITICAL } from "../../scripts/fuse.mjs";

test("cyber filter: 'exploit' alone is a feat outside English, a cyber word in English", () => {
  assert.equal(isCyber("Football pour amputés : un exploit qui enflamme le Maroc", "fr"), false);
  assert.equal(isCyber("Un exploit pour une faille dans Exchange, rançongiciel en cours", "fr"), true);
  assert.equal(isCyber("Public exploit released for Fortinet flaw", "en"), true);
  assert.equal(isCyber("Ataque de ransomware contra hospital", "es"), true);
});

test("routine bulletins are recognised in other languages; critical ones still go to an agent", () => {
  for (const t of ["Vulnerabilidades en OpenVPN", "Ruby dasturlaş tilida 7 ta xavfsizlik zaifliklar", "Ranljivosti v spletnem strežniku",
    "Uyarı: güvenlik açığı giderildi", "Kwetsbaarheden in Citrix", "OpenSSL 취약점 보안 업데이트"]) assert.ok(ROUTINE.test(t), t);
  for (const t of ["Критични уязвимости в PHP", "KRITIČNE RANJIVOSTI NGINX", "Riasztás az NGINX kritikus sérülékenységeiről"]) assert.ok(CRITICAL.test(t), t);
  assert.ok(!CRITICAL.test("Vulnerabilidades en OpenVPN"));
});

test("a new feed files only its last day", () => { assert.equal(FIRST_RUN_H, 24); });
