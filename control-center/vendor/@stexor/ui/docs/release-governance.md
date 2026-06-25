# Release Governance

Stexor UI releases are immutable internal artifacts. A release is admissible only when package version, image version, changelog, migration notes, API manifest and rollback target agree.

## Immutable Images

Production image references must use semver tags and digest pins:

```text
registry.stexor.com/stexor/backend:1.0.0@sha256:<release-digest>
registry.stexor.com/stexor/web:1.0.0@sha256:<release-digest>
registry.stexor.com/stexor/worker-notifications:1.0.0@sha256:<release-digest>
registry.stexor.com/stexor/worker-jobs:1.0.0@sha256:<release-digest>
```

Mutable tags are forbidden for every release artifact. `:latest` may appear only in rejection policy text or non-promotable local experiments outside release admission.

## Required Gates

- `pnpm version:check`
- `pnpm api:check`
- `pnpm release:ui:dry-run`
- `pnpm infra:release-gate`
- `pnpm enterprise:10-check`

## Breaking Changes

Any public API contraction or contract change requires:

- major semver bump;
- migration note in `MIGRATION.md`;
- API manifest update;
- rollback target in `RELEASE_CHECKLIST.md`;
- release owner approval.

Additive APIs are minor. Fixes without API change are patch.

## Signing Readiness

Release images must be ready for cosign verification and SLSA provenance attachment. The admission policy requires verified signing annotations before production promotion.
