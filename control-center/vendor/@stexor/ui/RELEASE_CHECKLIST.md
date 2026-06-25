# @stexor/ui Release Checklist

Before tagging an internal release:

- `pnpm lint`
- `pnpm typecheck`
- `pnpm test`
- `pnpm test:e2e`
- `pnpm test:visual`
- `pnpm build`
- Run `pnpm version:check`.
- Run `pnpm api:check`.
- Run `pnpm performance:check`.
- Run `pnpm release:ui:dry-run`.
- Confirm release images use semver tags and digest pins, never mutable tags.
- Confirm telemetry persistence export works in the release validation flow.
- Confirm visual snapshots for light, dark, desktop, mobile and catalog-visible overlays.
- Confirm internal product-flow validation passes.
- Confirm manual accessibility and cross-device matrices are attached.
- Confirm no migration note is missing for public API changes.
- Confirm no hardcoded colors, z-index values or non-tokenized motion were introduced.
- Confirm rollback target and `pnpm rollback:ui <version>` plan are recorded.
