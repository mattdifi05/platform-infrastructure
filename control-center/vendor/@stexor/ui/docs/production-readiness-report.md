# Production Readiness Report

Status: 10/10-ready candidate only after all automated gates pass and manual checks are signed.

## Automated

- Public API manifest and breaking-change detector.
- Unit and contract tests for catalog-visible primitives, async, validation and overlays.
- E2E flows for host app surfaces, catalog, internal product flow, form validation, command action and bulk action.
- Visual regression for official catalog sections, dark mode and selected open overlays on desktop and mobile.
- Release notes, changelog, migration notes, changeset and release checklist gates.
- Immutable semver image references with digest pins for release admission.
- Performance hygiene and visual snapshots for overlay, CommandPalette and runtime paths.
- Package publish dry-run through `release:ui:dry-run` or Docker fallback.

## Manual

- VoiceOver.
- NVDA.
- Keyboard-only complete workflows.
- 200 percent zoom.
- Reduced motion.
- High contrast.
- Touch on iOS and Android.
- Edge Windows smoke.

## Remaining Limits

- Browser FPS and memory timelines still require browser performance tooling during release validation.
- Real-device mobile overlay behavior still requires iOS/Android manual review in addition to the automated mobile overlay snapshots.
- Full go-live approval still requires attaching real-device evidence to the release record.

## Go Live Checklist

- All package, e2e, visual, accessibility, API, performance and build gates pass.
- Cross-device matrix completed.
- Manual accessibility checklist completed.
- Release notes and migration notes reviewed.
- Rollback version identified.
- Package publish dry-run completed.
- Release images are semver tagged and digest pinned.
- Platform observability evidence is attached when debugging a release issue.

## 10/10 Conditions

Declare 10/10-ready candidate only when the automated gates pass and manual accessibility/device evidence is attached.
