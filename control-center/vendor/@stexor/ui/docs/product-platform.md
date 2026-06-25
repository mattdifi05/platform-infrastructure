# Stexor UI Product Platform

Stexor UI is an internal UI platform, not a loose component kit. The catalog is the visual source of truth and the package owns shared interaction behavior.

## Runtime Systems

- OverlayManager: stack ownership, topmost Escape routing, focus return, inert lower layers, aria-hidden lower layers and tokenized layering.
- AsyncState: AbortController-backed async state, stale request protection and catalog-visible loading/progress/error states.
- FormValidation: dirty, touched, pending, warning, invalid, blocking and ARIA attributes.
- CommandPalette: grouped commands, recent commands, async command execution, loading/error/empty states and keyboard control.

## Do

- Compose app screens from package primitives and `UiShell`.
- Keep state ownership controlled when app data must persist.
- Use semantic tokens for surface, feedback, actions, focus, overlay and motion.
- Add tests and catalog visibility for every public visual primitive.
- Exercise the internal product-flow checklist before release to prove primitives compose into a real product surface.

## Do Not

- Add app-local visual skins for domain-specific or shell surfaces.
- Introduce hardcoded colors, z-index values, one-off motion or duplicate overlay logic.
- Hide public primitives outside the catalog.

## Product Gates

Release confidence requires unit tests, integration tests, accessibility checks, keyboard checks, internal product flows, e2e smoke, visual snapshots, performance hygiene, API stability, immutable release images, observability gates and package build.
