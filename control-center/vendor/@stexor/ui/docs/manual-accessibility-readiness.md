# Manual Accessibility Readiness

Automated axe and keyboard tests are gates, but final readiness still requires manual assistive-technology checks.

## VoiceOver

- Navigate catalog, host login and host app surface by headings, landmarks and controls.
- Verify modal, nested overlay and command palette announcements.
- Confirm focus returns to the trigger after overlay close.

## NVDA

- Verify form validation, command palette navigation and inline form errors.
- Confirm validation summary and field-level errors are announced.
- Confirm loading, empty and error states are understandable.

## Keyboard Only

- Complete the representative host login flow.
- Open command palette, execute a command, close with Escape.
- Navigate catalog rails, form controls and modal actions with keyboard only.

## Zoom 200 Percent

- Verify no clipped buttons, labels or modal actions.
- Verify modal, form and inspector overflow stay reachable.
- Verify form and inspector content stack cleanly.

## Reduced Motion

- Enable reduced motion at OS/browser level.
- Verify overlay, action morphing, block disclosure and catalog transitions reduce motion.

## High Contrast

- Verify semantic status, action, focus and disabled states remain distinguishable.
- Confirm dark mode does not lose icon contrast.

## Touch

- Test mobile catalog sections, modals, command triggers and form inputs.
- Verify tap targets stay large enough and no hover-only affordance is required.
