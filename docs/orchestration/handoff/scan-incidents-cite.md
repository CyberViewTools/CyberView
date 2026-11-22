# Handoff: scan-incidents-cite — incident citations

## Discovery → Design
- **Need:** thin citations on a finding. The workbench `event_of` map is first-wins and is not this index.
- **Constraints:** no probe. Confirmed or official, and review passed or corrected. Claimed events omitted. No indicator bodies.
- **Recommendation:** build an opt-in offline file so a small snapshot stays small.

## Design → Implementation
- `--data-incidents` reads `data/incidents.json` from `--data`. The live site is not asked. Every kept event for the CVE is listed.

## Implementation → Review
- Fixture index with two corroborated events and one claim.
