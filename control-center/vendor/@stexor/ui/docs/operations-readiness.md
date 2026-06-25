# Operations Readiness

This checklist aligns Stexor UI release work with the platform runbooks.

## Release Operator Checklist

- Confirm immutable image references use semver tags and digest pins.
- Run `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm test:e2e`, `pnpm test:visual` and `pnpm build`.
- Run `enterprise-check`, `enterprise-hardening-audit`, `security-smoke` and `enterprise-10-check`.
- Attach visual diff review, API manifest result, migration notes and rollback target.
- Confirm platform observability gates pass in the release validation flow.

## Rollback

Rollback requires:

- previous package version;
- previous image references;
- matching migration note;
- operator initials;
- smoke checklist after rollback.

## Incident Checklist

- Capture current theme, viewport and route.
- Capture overlay stack state if relevant.
- Run security smoke and internal product-flow smoke.
- Attach failing visual diff or accessibility note.

## Backup And Restore

Database backup and restore drills are owned by the platform runbook. UI release sign-off requires the latest restore drill to be green before production promotion.
