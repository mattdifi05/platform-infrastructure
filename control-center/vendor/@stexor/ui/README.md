# @stexor/ui

Next-first UI package for Stexor apps.

## Setup

Import the core stylesheet once in the app root:

```tsx
import "@stexor/ui/styles.css";
```

Add the UI surface stylesheet for app screens that should render exactly like the Stexor UI catalog:

```tsx
import "@stexor/ui/ui.css";
```

Mount the provider in the root layout:

```tsx
import { StexorNextUiProviders } from "@stexor/ui/next";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="it">
      <body>
        <StexorNextUiProviders>{children}</StexorNextUiProviders>
      </body>
    </html>
  );
}
```

## Public API

Use these entrypoints:

- `@stexor/ui` for server-safe shared exports.
- `@stexor/ui/client` for client components.
- `@stexor/ui/next` for Next.js providers, metadata and surface helpers.
- `@stexor/ui/catalog` for the real UI catalog surface.

Compose app-level empty, not-found and error pages from the exported `SectionCard` and `Button` primitives so fallback screens keep the same package-owned visual language without an extra wrapper.

## Shell

Use `UiShell` when an app needs the standard Stexor frame. It mounts the body-level surface, logo-first fixed header, sidebar navigation and scroll scene from one component:

```tsx
import { UiShell } from "@stexor/ui/client";

<UiShell
  activeId={section}
  brand={{ title: "STEXOR", subtitle: "Custom" }}
  navItems={items}
  navLabel="Sezioni"
  onSelect={setSection}
>
  {page}
</UiShell>
```

## Catalog

`ui.localhost.com` mounts `UiCatalogApp` from `@stexor/ui/catalog`. The catalog includes only the production UI sections shown by the browser screenshots: Overview, Inputs, Actions, Navigation, Blocks, Feedback, Async and Modals.

The Account Center is not part of the UI package catalog. Its current sections
and app-owned rules are documented in the workspace root at
`docs/account-center.md`.

## Design System Contract

These rules are part of the package contract:

- The catalog is the source of truth: every public visual primitive must be visible in an official catalog section.
- Non-catalog audit sections must not exist in the catalog; cleanup state belongs in tests and release notes, not runtime UI.
- App screens compose `@stexor/ui` primitives and shared styles. Domain-owned
  screens may keep local CSS only for layout/copy-specific composition, with a
  strict app prefix such as `sx-account-*`, token-only colors and no duplicate
  generic primitive.
- `UiShell` owns the standard frame: logo-first header, sidebar navigation and page surface.
- Actions use `Button` directly for catalog buttons; use `ActionFlow` only for start/stop plus reveal flows with configurable size and label visibility. Both keep icon, label, variant, size, loading and spin behavior inside the package-owned action system.
- Inputs, modals, feedback, popup notifications, async states, blocks, tabs, sidebars, badges and pills use the package primitives shown in the catalog.
- Surface context is automatic: components inherit white or gray tokens from the nearest UI surface. Light mode keeps the standard semantic tones; dark mode uses a quieter dedicated palette for feedback, actions, input borders and input icons, while dark panel and gray-block surfaces stay close in contrast.
- Accent is interaction-only. It can style primary actions, active navigation, focus, selected states, command active rows, toggles and subtle progress, but it must not recolor semantic feedback: success stays green, warning amber, danger red, info semantic blue and media/upload violet.
- Icons come from the official UI icon set and must be visible in the catalog before app screens can use them.
- Motion must be smooth, interruptible and layout-stable; interactions must not resize unrelated elements or add unlisted feedback.
- Package CSS must not use `!important`, wrapper indirections, private cleanup class names or parallel app-domain visual classes.

## Enterprise Primitives

Use these public primitives before adding app-local UI behavior:

- `Modal` routes overlays through the package stack manager: topmost Escape handling, focus trap, focus return, inert lower layers, aria-hidden lower layers and ref-counted scroll lock.
- `uiOverlayStack` is typed for modal, popover, dropdown and command palette ownership, with interaction priority, lifecycle subscriptions and stack snapshots.
- `CommandPalette` runs on the same overlay stack with grouped/recent commands, async command execution, loading/error/empty states, roving keyboard navigation and focus restore.
- `Popover` and `Dropdown` are the official floating overlay patterns. They share portal layering, Escape routing, outside click handling and tokenized z-index instead of app-local floating panels.
- `CustomScrollbar` owns CSP-safe scrollbar geometry through CSS rules and can bind either to the standard shell scroll root or a supplied local `rootRef`.
- `UiPopupProvider` owns bottom-right temporary notifications with tone icons, timer line, close action and tokenized enter/exit motion.
- `createUiAsyncMachine` owns async state: `idle`, `loading`, `progress`, `success`, `error`, `stale`, `cancelled` and `optimistic`; every run is AbortController-backed and stale requests cannot overwrite newer results.
- `createUiFieldValidationState`, `uiFieldA11yProps` own the field validation contract used by catalog inputs: aria-invalid, aria-describedby, pending, dirty, touched and severity.
- `Button asChild` uses internal Slot composition without adding a public wrapper-only primitive.
- `SelectList` owns the large-list virtualized path; hosts use `SelectList` rather than importing low-level virtualization directly.
- `uiMotionDurations` is the JavaScript timing contract consumed by modal, overlay and popup primitives; CSS motion lives in foundation tokens.
- `useThemeWave` and `ThemeWaveOverlay` are the official theme-transition primitive: hosts pass the toggle source element, the package owns origin geometry, reduced-motion fallback, View Transition reveal and overlay CSS variables.

## Dark Mode

Theme is semantic-token based. Hosts can set `data-ui-theme="light"` or `data-ui-theme="dark"` on `html` or any wrapping surface. Components must consume tokens such as `--panel`, `--text`, `--line`, `--ui-feedback-*`, `--ui-action-*`, `--ui-icon-tone-*`, `--ui-field-*`, `--ui-overlay-*`, `--shadow` and `--ui-z-*`; component files must not introduce hardcoded colors. Dark mode has its own restrained feedback/action/input palette (`--ui-dark-info-*`, `--ui-dark-good-*`, `--ui-dark-warn-*`, `--ui-dark-danger-*`, `--ui-dark-violet-*`, `--ui-dark-primary-*`) and keeps white/gray surface deltas deliberately low. The catalog exposes a dark/light toggle so visual snapshots can cover both themes without separate component variants.

## Accent Governance

Blue is the official default accent. The governed accent palette contains 20 tones in the header picker: `blue`, `sky`, `cyan`, `teal`, `emerald`, `green`, `lime`, `olive`, `yellow`, `amber`, `orange`, `red`, `rose`, `pink`, `fuchsia`, `purple`, `violet`, `indigo`, `slate` and `neutral`.

Accent tokens describe interaction emphasis only: `--ui-accent-primary`, `--ui-accent-subtle`, `--ui-accent-hover`, `--ui-accent-active`, `--ui-accent-focus`, `--ui-accent-border`, `--ui-accent-overlay`, `--ui-accent-selection` and `--ui-accent-selection-on-gray`. Use them for primary CTAs, active nav, focus rings, selected rows, command active items, toggle/radio active states and subtle progress. Do not use accent tokens for success, warning, danger, info, media/upload or destructive meaning.

Semantic colors remain stable across accents: success is green, warning is amber, danger is red, info is semantic blue and media/upload is violet. This keeps the UI customizable without making status colors cognitively unstable.

Icon color policy is fixed: input icons use accent and feedback icons use semantic colors. There is no separate product/service color layer in the package.

## Action Builder

FontAwesome is centralized through `uiIconRegistry`, `resolveIcon` and `getUiIcon`, so components receive string icon names without duplicating FontAwesome imports. Unknown icon names fall back to the package fallback icon.

The catalog Action Builder is intentionally small: it creates actions directly with `Button`, using only the four official shapes: normal, icon-only, compact and compact icon-only. Color is a separate choice limited to distinct action tones: `primary`, `muted`, `cyan`, `teal`, `edit`, `violet`, `rose`, `slate`, `warning` and `danger`; `info` is not an action tone, and orange-style actions are merged into `warning` to avoid duplicate cognitive signals. There are no parallel wrappers or extra runtime layers. Loading means busy, not disabled; unavailable actions should be omitted from the UI instead of rendered disabled.

## Accessibility

Interactive primitives keep native semantics first. Modal content uses `role="dialog"`, `aria-modal`, labelled titles, focus trapping, focus return and Escape routing on the active overlay only. Form fields accept validation state and emit `aria-invalid`, `aria-describedby`, `aria-busy` and disabled attributes from the shared validation primitive. Lists use listbox/option semantics and keyboard navigation; virtualized lists keep stable active indexes.

## State Matrix

Buttons: `primary`, `muted`, `edit`, `warning`, `danger`, `cyan`, `teal`, `violet`, `rose`, `slate`, `plain`; states are idle, loading, morphing, icon-spin and asChild trigger. Loading uses `aria-busy` without forcing disabled behavior.

Inputs: idle, touched, dirty, valid, invalid, pending and disabled; hover changes only border/focus tokens and surface context chooses white/gray backgrounds.

Feedback: info, good, warn, danger and neutral; each tone has white and gray surface tokens. Popup notifications add opening, open, timer, manual-close and closing states.

Overlay: closed, opening, open, nested/topmost and closing; only the active overlay handles Escape and focus.

Command Palette: closed, searchable, filtered, empty, loading, error, disabled command, running command and selected command; Arrow keys move the active command and Enter executes it.

Async: idle, optimistic, loading, progress, success, error, stale and cancelled with race protection.

## Component Docs

### CommandPalette And Overlays

`CommandPalette` is the command layer for shortcuts and global operations. `Popover` and `Dropdown` are controlled components: pass `open`, `onOpenChange` and a trigger render prop, then compose the content with normal package primitives.

Do: hide unavailable commands until allowed, group commands, and let `uiOverlayStack` handle Escape/focus. Don't: create app-local portals, random z-index values, independent scroll locks, or disabled action clutter.

### Performance Gates

Use the workspace performance and visual gates before release or after risky overlay/runtime changes:

```sh
pnpm performance:check
pnpm test:visual
```

The package runtime only carries primitives visible in the catalog or required by those primitives; release stress checks live in the workspace gates, not as extra runtime framework code.

## Release And Versioning

Semver policy:

- Patch: token tuning, bug fixes, accessibility fixes, test/doc updates and visual corrections that do not remove public API.
- Minor: new primitives, new action ids, new public tokens or additive component props.
- Major: public surface contraction, changed visual contract, renamed tokens or behavior requiring app migration.

Every public API change needs a Migration note in the PR or release notes. `pnpm version:check` validates the package metadata, changeset, changelog, migration notes and release checklist before release.

`packages/ui/api-manifest.json` is the public API contract. `pnpm api:check` detects entrypoint or core export drift before release.

Release images must be immutable semver references with digest pins. Mutable `:latest` references are rejected by the release artifact gate.

## Styling

`styles.css` contains reusable core UI. `ui.css` contains the catalog surface used by screens that must match `ui.localhost.com`. App-level screens should rely on these shared UI styles instead of shipping a separate visual skin. Domain-owned layout CSS is acceptable only when it stays scoped, tokenized and outside the package public primitive layer.

`--ui-accent` is the accent seed, while the public interaction layer is `--ui-accent-primary`, `--ui-accent-subtle`, `--ui-accent-hover`, `--ui-accent-active`, `--ui-accent-focus`, `--ui-accent-border`, `--ui-accent-overlay`, `--ui-accent-selection` and `--ui-accent-selection-on-gray`. Feedback and status components must use `--ui-feedback-*` and semantic tokens instead of accent shortcuts. `--ui-shell-bar-background` controls the shared background applied by the `UiShell` header and `PillSidebarNav`, so header and sidebar stay aligned from one setting.

## Build

The workspace consumes source exports during development so Next can compile the package directly. For packaging or release validation, build the distributable bundle:

```sh
pnpm --filter @stexor/ui build
```

The build writes compiled JavaScript, declarations and CSS to `packages/ui/dist`.
