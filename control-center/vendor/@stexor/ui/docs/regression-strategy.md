# Regression Strategy

Visual confidence is treated as release evidence, not decoration.

## Baseline Update Workflow

1. Run the UI locally and confirm the intended visual change.
2. Run `pnpm test:visual:update`.
3. Review every changed PNG in desktop, mobile, light, dark and overlay states.
4. Attach visual diff notes to the release record.
5. Run `pnpm test:visual` without update mode.

## Snapshot Approval

Snapshot updates require a human approval note that names:

- affected section;
- intentional design change;
- theme and viewport coverage;
- reviewer initials.

## Drift Policy

Unexpected padding, radius, icon saturation, contrast, focus, motion or layout movement is a blocker. Do not accept a snapshot to hide drift.

## Flaky Test Policy

No release test may stay skipped for convenience. A flaky test must be made deterministic, isolated to a stable fixture or documented as a manual-only device check with owner approval.

## History

The current baseline includes catalog sections, dark mode, open overlay states and host app snapshots across Chromium desktop/mobile plus Linux CI baselines.
