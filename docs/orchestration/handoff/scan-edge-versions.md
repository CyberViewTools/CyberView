# Handoff: scan-edge-versions — collected pages and certificates

## Discovery → Design
- **Need:** KEV appliances that are only a certificate guess cannot carry a version.
- **Constraints:** no new request in this slice. A login title stays a guess. Needs-research rows stay unmatched. No ASA, AnyConnect, or CGI login check.
- **Recommendation:** build the cited literals only.

## Design → Implementation
- `scanner/lib/edge.mjs` matches titles, headers, and one Telnet greeting the catalog quotes, each with its source.
- Certificate hints that already shipped stay as they are.

## Implementation → Review
- Tests cover Arcserve, Aviatrix, Expedition (not PAN-OS), ALEOS with a version, Sophos UTM only when the theme path is present, SMA and ACS versions, DNS-320, and Fabric OS.
