# Accessibility Matrix

## Overlay

- Role: dialog or menu.
- Keyboard: Escape only closes the active overlay; Tab is trapped inside modal layers.
- Focus: focus moves into the panel on open and returns to the trigger on close.
- Screen reader: inactive document layers are inert and `aria-hidden`.

## Forms

- State: idle, dirty, touched, pending, valid, warning, invalid, blocking and disabled.
- ARIA: `aria-invalid`, `aria-describedby`, `aria-busy` and disabled attributes come from shared validation state.
- Recovery: field errors stay inline; grouped and section errors use shared summaries.

## Command Palette

- Role: combobox plus listbox/option commands.
- Keyboard: Arrow keys change the active command; Enter executes; Escape routes through OverlayManager.
- Async: loading, disabled, error and empty states remain announced by visible state regions.
