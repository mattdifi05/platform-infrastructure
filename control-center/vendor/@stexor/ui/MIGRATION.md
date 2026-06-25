# @stexor/ui Migration Notes

## Unreleased

Breaking cleanup:

- `Button` does not expose an `info` action variant. Use `primary` for interaction emphasis or semantic feedback primitives for informational messaging.
- `uiIconRegistry` exposes the visible catalog names only. Use the official icon names and `resolveIcon` fallback behavior.

Added APIs:

- `CustomScrollbar`
- `readStoredUiTheme`
- `writeStoredUiAccent`
- `writeStoredUiTheme`

Unsupported public APIs: none.

Closed public surface:

- `info` action CSS class and action tokens are outside the public contract.
- Service/product icon shortcuts are outside the public icon contract.
- Non-catalog public exports stay closed. New primitives must be added to the official UI catalog before being exposed.
- `CssPresence`, `Slot` and `VirtualList` stay internal implementation helpers for catalog-visible primitives.
- Async resource management, density runtime and production telemetry stay in workspace gates and observability packages instead of hidden UI framework APIs.
- The catalog-visible field contract is `createUiFieldValidationState` plus `uiFieldA11yProps`.
