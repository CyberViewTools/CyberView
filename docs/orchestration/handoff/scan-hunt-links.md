# Handoff: scan-hunt-links — hunt pointers, links only

## Discovery → Design
- **Need:** publisher hunt URLs on a finding, without waiting on the events index.
- **Constraints:** links only. No rule or indicator body.
- **Recommendation:** build.

## Design → Implementation
- `huntLinks` reads workbench `guides[].hunt` and `hunt`. https URLs only. A record that carries a body is dropped.

## Implementation → Review
- The summary section is titled as links only. The test fixture body is not in the output.
