# Handoff: scan-ics-identify — industrial and clinical identification reads (`--ics`)

Plan `w3-build`, branch `scanner/ics-optin`. Catalog rows: `modbus-identify`, `ethernet-ip-list-identity`,
`rockwell-factorytalk-or-controllogix`, `s7comm-identify`, `bacnet-who-is-i-am`, `opc-ua-getendpoints`,
`dicom-association-identify` (built); `dnp3-identify`, `fhir-or-hl7-http-endpoint` (not built, see the end).
Lead decision 11 (DECISIONS.md): allowed only behind an explicit `--ics`, one read-only identification request per
protocol, private ranges, never a write or a state change.

## Discovery → Design
- **Need:** operators of OT, building-automation and clinical networks want an inventory of PLCs, controllers, OPC UA
  servers and DICOM nodes (vendor, product, firmware where the device states it) from the same authorised scan.
- **Constraints:** detection only; opt-in only (`--ics`, off by default); private/loopback/link-local addresses only, a
  public address is refused per host even with `--i-am-authorized-for-public-ranges`; standard port only, and only when
  that port is in the scan's port list (none of them is in `DEFAULT_PORTS`, so the operator names them in `--ports`) and,
  for TCP, the normal probe found it open; one identification exchange per protocol per host; frozen request bytes;
  every connection through the same `Limiter` (rate, host/total budgets, `--max-minutes`, Ctrl-C).
- **Standards used for the byte layouts** (each cited beside its literal in `scanner/lib/ics.mjs`): MODBUS Application
  Protocol V1.1b3 6.21 and the Modbus/TCP Implementation Guide V1.0b 3.1.3; CIP Networks Library Vol. 2 (EtherNet/IP)
  2-3 / 2-4.2; RFC 1006 TPKT, ISO 8073 COTP, the Wireshark s7comm dissector layout and Siemens' SSL-ID W#16#xy11;
  ANSI/ASHRAE 135 Annex J (BVLL), 6.2 (NPCI), 20.1.2 (unconfirmed PDU), clause 16 (Who-Is/I-Am); OPC 10000-6 (UA TCP,
  secure conversation, binary encoding) and 10000-4 5.5.2 / 5.4.4; DICOM PS3.8 9.3.x, PS3.7 Annex A/D, PS3.5 B.2.
  No live device was contacted; the loopback fixtures were built from the same layouts.
- **Recommendation:** build (done), inventory only.

## Design (per-protocol exchange, and why it is read-only)

| Protocol | Port | Messages sent (all on one connection, each only after the expected reply) | Read | Why it cannot change the device |
|---|---|---|---|---|
| Modbus/TCP | TCP 502 | 1: MBAP (unit 0xFF) + function 0x2B / MEI 0x0E Read Device Identification, basic category, object 0 | VendorName, ProductCode, MajorMinorRevision | 0x2B/0x0E is a read of identification objects; no coil/register read, no write (5/6/15/16/22/23), no diagnostics (8). Unit 0xFF, not 0, because 0 is broadcast on a serial line behind a gateway. "More follows" is recorded, never followed. |
| EtherNet/IP | TCP 44818 | 1: encapsulation command 0x63 ListIdentity, no data, session 0 | vendor id, device type, product code, revision, serial, product name | ListIdentity needs no session; no RegisterSession (0x65), no SendRRData/CIP service. Covers Rockwell (vendor id 1). |
| S7comm | TCP 102 | 3 = ONE identification exchange: COTP Connection Request (TSAP 0x0100 → 0x0102) → S7 Setup Communication (0xF0) → userdata Read SZL ID 0x0011 index 0 | module order number, basic hardware, firmware (SZL index 7, "V" + 3 bytes) | Setup Communication only negotiates PDU size; Read SZL is a read of the system status list. No read/write var (0x04/0x05), no PI service/start (0x28), no stop (0x29), no block upload/download (0x1A-0x1F). Step 2 only after a Connection Confirm, step 3 only after an error-free ack. |
| BACnet/IP | UDP 47808 | 1 datagram: BVLC Original-Unicast-NPDU (0x0A), NPDU without DNET, unconfirmed Who-Is (0x10 0x08), no range | I-Am: device instance, max APDU, segmentation, vendor id | Who-Is is an unconfirmed discovery request. Unicast to the attested address only: never 0x0B Original-Broadcast, never a DNET (would be re-broadcast by routers), no broadcast socket option, and .0/.255 IPv4 addresses are refused. No ReadProperty. Sent by `udp.mjs` (one send, no retransmit) with ics.mjs's frozen bytes. |
| OPC UA | TCP 4840 | 3: Hello → OpenSecureChannel (SecurityPolicy None, mode None, no certificate) → GetEndpoints; then TCP close | application name/URI, product URI, each endpoint's security mode and policy | No CreateSession/ActivateSession, so no login and no Read/Browse/Write/Call is possible. The GetEndpoints message is the frozen literal with only the SecureChannelId/TokenId the server assigned copied in (bytes 8-15), as the protocol requires. The server certificate is skipped, never kept. |
| DICOM | TCP 104 | 2: A-ASSOCIATE-RQ (Verification SOP class 1.2.840.10008.1.1 only, Implicit VR LE) → A-RELEASE-RQ (only after an A-ASSOCIATE-AC) | accept/reject (result, source, reason), Implementation Class UID, Implementation Version Name | No P-DATA-TF is ever sent, so no DIMSE command (not even C-ECHO). An A-ASSOCIATE-RJ ends the exchange with nothing more sent. Our Implementation Class UID is a UUID-derived 2.25 UID (PS3.5 B.2), no organisation root claimed. |

- **Gates (`icsPlan`, `icsTargetOk`):** off unless `ics.enabled === true`; each protocol once; standard port in the list;
  TCP port open in this scan; UDP only when the host answered; `public !== false`, a non-private kind, or a non-private
  address → `not-sent: public address`.
- **Limits:** each exchange takes one `Limiter` slot (counted in `connections`, host/total budgets, rate); a spent budget
  is recorded `not-sent: budget or time`; replies capped at `TIMEOUTS.maxBytes` (16 KB, so OPC UA Hello asks for 16 KB
  buffers); connect/read timeouts from `TIMEOUTS`; Ctrl-C/abort stops it.
- **Output:** `report.json` `run.ics` `{ enabled }`, `run.network.sends.ics` (+ `ics-<protocol>` lines when on), and
  per host `hosts[].ics[]`: `{ protocol, name, catalog[], port, transport, messages_sent, state, outcome, identity,
  version, version_stated, inventory_only: true, error }`. Outcomes: identified, answered without identity, unrecognised
  reply, no reply, closed, no answer, not-sent: ….
- **Matcher:** inventory only. Nothing goes to `h.services`, so no KEV/NVD match and nothing in headline counts: the
  names these devices report (S7 order numbers, CIP product names, OPC UA application names) do not map cleanly to
  NVD vendor/product names. `version_stated` is true only where the protocol's own field states a version (Modbus
  MajorMinorRevision, CIP revision, S7 firmware record).
- **CLI:** `--ics` (boolean). `check`/`scan` header always lists `ics  only with --ics (off by default) …`; with `--ics`
  it lists each protocol's send line and says which standard ports are in the port list (or that nothing industrial
  will be sent).
- **Safety-model check (security-check section 7):** `scripts/lib/scanner-ics-check.mjs` (`icsProblems`, `stepProblems`)
  enforces: ics.mjs is the only new file allowed `net.connect` (allowlisted beside probe.mjs); it writes in exactly one
  place `sock.write(bytes)` with `bytes = requestBytes(...)` from the frozen hex literals, sends no datagram itself and
  imports no dgram (BACnet goes through `udp.mjs` via one `udpProbe(…, { services: ICS_UDP })`; no other file may pass
  `services`); every step decodes to the allowed read-only message (Modbus 0x2B/0x0E basic and unit ≠ 0; ENIP 0x63 with no
  data/session; S7 CR → 0xF0 → Read SZL 0x0011; BACnet 0x0A, no DNET, Who-Is; OPC UA HEL/OPN(None, 446)/MSG(428);
  DICOM A-ASSOCIATE-RQ with Verification only, then only 0x05/0x07, never 0x04); a message count cap per protocol;
  frozen table; no broadcast/multicast option or address; only the six reviewed protocols (no DNP3, no FHIR); `runIcs`
  and `icsPlan` return nothing unless `ics.enabled === true`; scan.mjs runs it only under `icsOn`; the CLI enables it only
  from `--ics`; and, from the loaded module, that a public host, a possible broadcast address, a missing opt-in, an
  unlisted port or a closed TCP port plan nothing, and each protocol is planned at most once.
- **Shared-file hooks:** `scan.mjs` (import, `ics`/`icsProbe` options, one `if (icsOn) await runIcs(...)`, report
  fields), `cyberview-scan.mjs` (flag, help, header sends, one header line, pass-through), `udp.mjs` (one optional
  `services` parameter, default unchanged; still one send), `scripts/security-check.mjs` (allowlist + icsProblems call).

## Implementation → Review
- **Tests:** `tests/unit/scanner-ics.test.mjs` (16 tests) with loopback stand-ins in `tests/fixtures/scanner/ics/servers.mjs`
  (TCP and UDP on 127.0.0.1, recording every byte): exact bytes per protocol; S7/OPC UA/DICOM later steps not sent
  after a refusal; one datagram and no retransmit on a silent BACnet port; size cap; closed port; nothing received and the
  exchange never called without `--ics`; public host / unlisted port / spent budget / aborted run send nothing; CLI header,
  report fields; every checker rule fires (write function codes, extra messages, DNP3, broadcast BVLC/DNET/socket option,
  public targets, missing opt-in in ics/scan/CLI, extra write/send, computed steps, unfrozen table).

### Could not do (and why)
- **DNP3 (`dnp3-identify`) — not built.** The read-only candidates (link-layer Request Link Status, or an application
  Read of device attributes) need the outstation's link address. A fixed guess would rarely match, trying several would be
  enumeration, and the "all stations" addresses (0xFFFD-0xFFFF) are DNP3 broadcast, which the rules forbid; the 0xFFFC
  self-address is an optional feature. Needs an owner decision (e.g. an operator-supplied outstation address in the scope
  file) and its own Design.
- **FHIR `/metadata` (`fhir-or-hl7-http-endpoint`) — not built here.** It is an HTTP path; it belongs on the path rail
  (`scanner/lib/paths.mjs`) after the path-rail review lists `/metadata` (and decides on `/fhir`), behind an opt-in.
- **S7 module/plant name:** needs a second SZL read (ID 0x001C); the rule is one SZL read (0x0011), so it is not read.
  S7-1200/1500 that refuse called TSAP 0x0102 are not retried with another TSAP (one attempt).
- **BACnet devices that answer Who-Is only with a broadcast I-Am** (to port 47808) are not heard: the scanner does not
  listen for broadcasts. No vendor names for BACnet/EtherNet/IP vendor ids except CIP vendor 1 (Rockwell Automation /
  Allen-Bradley); the numeric ids are kept.
- **OPC UA servers whose GetEndpoints reply exceeds 16 KB** answer with an error (the reply cap is the scanner's fixed
  `TIMEOUTS.maxBytes`); recorded as such. Software build/version (BuildInfo) needs a session Read, which is not done.
- **DICOM on 11112** (the registered alternative port) is not tried: standard port 104 only.
- **Matcher:** no ICS identity is matched to KEV/NVD (no clean mapping); summary.txt, inventory.csv and report.html do not
  yet show `hosts[].ics` (the orchestrator may add a section when consolidating report.mjs/html-report.mjs).

## Doc text to add

### docs/scanner.md (new section, after the path rail)

> **Industrial and clinical identification (`--ics`, off by default).** With `--ics`, the scanner sends one read-only
> identification exchange per protocol per host, only to private, loopback or link-local addresses (never a public
> address, even with `--i-am-authorized-for-public-ranges`), only on the protocol's standard port, and only when that
> port is in the port list (`--ports`; none is in the default list) and, for TCP, the probe found it open: Modbus/TCP 502
> (Read Device Identification 0x2B/0x0E, basic objects), EtherNet/IP 44818 (ListIdentity; covers Rockwell), S7comm 102
> (COTP connect, Setup Communication, one Read SZL 0x0011), BACnet/IP UDP 47808 (one unicast Who-Is, never broadcast),
> OPC UA 4840 (Hello, OpenSecureChannel with SecurityPolicy None, GetEndpoints; no session) and DICOM 104
> (A-ASSOCIATE-RQ for Verification, then A-RELEASE-RQ; no DIMSE command, not even C-ECHO). The request bytes are frozen
> literals in `scanner/lib/ics.mjs`, each with the public specification section it follows; nothing writes, controls,
> restarts, logs in or enumerates. Every exchange counts against the same rate and budgets. Results are inventory only
> (`hosts[].ics` in report.json): vendor, product, model and firmware where the device states them; they are not matched
> to KEV/NVD. DNP3 and FHIR are not included. `scripts/security-check.mjs` section 7 (`scripts/lib/scanner-ics-check.mjs`)
> enforces these rules.

### scanner/README.md

Under the flags list:

> `--ics` — industrial/clinical identification reads (off by default): one read-only identification exchange per
> protocol per host for Modbus (502), S7 (102), EtherNet/IP (44818), BACnet (UDP 47808, unicast), OPC UA (4840) and DICOM
> (104), private addresses only, and only when the port is in `--ports`. Inventory only.

Under "What it deliberately does not do", add:

> - No industrial writes or control: with `--ics` it sends only read-only identification requests (no Modbus write or
>   register read, no S7 job other than one SZL read, no BACnet broadcast or ReadProperty, no OPC UA session, no DICOM
>   DIMSE command), never to a public address.
