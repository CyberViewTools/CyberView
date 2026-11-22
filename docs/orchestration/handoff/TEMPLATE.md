# Handoff: <item-id> — <short title>

Copy this to `handoff/<item-id>.md` and fill the stage you are handing off. Keep it to one page.

## Discovery → Design
- **Need / user story:** who needs this and why, in one or two sentences.
- **Constraints:** the rails that apply (keyless? detection-only? authorization-gated? data rules?).
- **Prior art / standards:** formats, specs, existing tools to match (e.g. CycloneDX, SPDX, nmap XML, SARIF).
- **Data / APIs that exist:** what CyberView data or public source this uses; reachable and keyless?
- **Feasibility / risks:** what could block it; what is out of scope.
- **Recommendation:** build / don't / needs an owner decision.

## Design → Implementation
- **Interfaces / CLI:** commands, flags, inputs and outputs.
- **Data model:** the shapes produced/consumed; where they live.
- **Safety-model check:** confirm it keeps every "deliberately does not do" rule and `security-check` green.
- **Test plan:** the unit/fixture tests that must exist.
- **PR plan:** the sequenced PRs (each small, reviewable), with what each one lands.

## Implementation → Review
- **PRs:** links, with what each landed and its test status.
- **Open questions / follow-ups.**
