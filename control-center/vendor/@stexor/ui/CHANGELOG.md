# @stexor/ui Changelog

## Unreleased

- Performance: route release confidence through workspace performance and visual gates instead of package-only benchmark runtime.
- Telemetry: added production event normalization for Web Vitals, client errors, long tasks, interaction latency, rage clicks and overlay failures.
- UI primitives: exposed `CustomScrollbar` with configurable local scroll roots for CSP-safe app surfaces.
- Theme: exposed shared theme/accent persistence helpers through the core client API.
- Validation: added an internal product-flow checklist that composes users, forms, command palette, overlays, async loading, dark/light and density from Stexor UI primitives.
- Visual regression: extended the documented release gate to include catalog, overlay, desktop/mobile and dark/light confidence snapshots.
- Accessibility: documented component-level keyboard, focus, reduced-motion and screen-reader certification checks.
- Release: added changeset metadata, API manifest checks, migration notes, rollback guidance, dry-run publishing and a release checklist for restricted internal publishing.
- Release: documented immutable semver image references, release governance, operations readiness, visual drift policy and enterprise release-grade reporting.
- Telemetry: added persistence with batching, retry, local buffering, rate limiting, redaction and export for release diagnostics.
