import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workspaceRoot = new URL("../../../", import.meta.url);

function readText(relativePath: string): string {
  return readFileSync(new URL(relativePath, workspaceRoot), "utf8").replace(/\r\n/g, "\n");
}

test("feedback and action colors are centralized behind semantic tokens", () => {
  const foundation = [
    readText("packages/ui/src/styles/base-01-foundation.css"),
    readText("packages/ui/src/styles/base-01-accent.css"),
  ].join("\n");
  const demoStyles = [
    "packages/ui/src/styles/base-06-modal.css",
    "packages/ui/src/styles/ui-01-navigation.css",
    "packages/ui/src/styles/ui-02-controls.css",
    "packages/ui/src/styles/ui-02-forms.css",
    "packages/ui/src/styles/ui-03-data.css",
    "packages/ui/src/styles/ui-03-monochrome-surfaces.css",
    "packages/ui/src/styles/ui-app-01-shell.css",
    "packages/ui/src/styles/ui-app-02-overview.css",
    "packages/ui/src/styles/ui-app-03-actions.css",
    "packages/ui/src/styles/ui-app-04-feedback.css",
    "packages/ui/src/styles/ui-app-06-async.css",
    "packages/ui/src/styles/ui-app-07-modals.css",
    "packages/ui/src/styles/ui-app-09-blocks.css",
    "packages/ui/src/styles/ui-app-10-themes.css",
    "packages/ui/src/styles/ui-app-11-action-builder.css",
    "packages/ui/src/styles/ui-shared-foundation.css",
    "packages/ui/src/styles/ui-shared-controls.css",
    "packages/ui/src/styles/ui-shared-surfaces.css",
  ].map(readText).join("\n");
  const componentSources = [
    "packages/ui/src/DatePicker.tsx",
    "packages/ui/src/Select.tsx",
  ].map(readText).join("\n");

  for (const token of [
    "--ui-accent-primary", "--ui-accent-subtle", "--ui-accent-focus", "--ui-accent-border", "--ui-accent-overlay", "--ui-accent-selection", "--ui-accent-selection-on-gray",
    "--ui-list-option-active-bg", "--ui-list-option-hover-bg", "--ui-list-option-selected-bg", "--ui-choice-card-active-bg", "--ui-choice-card-icon-bg",
    "--ui-semantic-info-bg", "--ui-semantic-info-bg-on-gray", "--ui-semantic-info-border", "--ui-semantic-info-fg",
    "--ui-feedback-good-bg", "--ui-feedback-info-bg", "--ui-feedback-warn-bg", "--ui-feedback-danger-bg",
    "--ui-action-cyan-bg", "--ui-action-danger-bg", "--ui-action-muted-bg", "--ui-action-primary-soft-bg", "--ui-action-rose-bg", "--ui-action-slate-bg", "--ui-action-solid-fg", "--ui-action-teal-bg", "--ui-action-violet-bg",
    "--ui-field-focus-border", "--ui-icon-on-tone", "--ui-icon-tone-brand", "--ui-pill-active-bg-surface", "--ui-pill-active-bg-gray", "--ui-sidebar-pill-shadow", "--ui-skeleton-white-start", "--ui-shell-glow-blue", "--ui-motion-ease-standard", "--ui-density-control-height", "--ui-density-table-row-height",
    "--ui-motion-delay-short",
  ]) {
    assert(foundation.includes(token) || demoStyles.includes(token), `Missing semantic color token: ${token}`);
  }

  assert(demoStyles.includes("box-shadow: inset 0 0 0 1.5px var(--ui-control-tone-border);"), "Input tone borders must be palette-driven.");
  assert(demoStyles.includes("color: var(--ui-setting-icon-fg);"), "Input icons must use the soft input icon foreground token.");
  assert(foundation.includes("--ui-action-primary-bg: var(--ui-accent-primary);"), "Primary actions must inherit the current accent background.");
  assert.equal(foundation.includes("--ui-action-primary-hover-bg"), false, "Primary action hover background tokens must not remain when action hover keeps its base background.");
  assert.equal(foundation.includes("--ui-action-info-"), false, "Info action tokens must stay out of the foundation.");
  assert.equal(demoStyles.includes("info-button"), false, "Info action styles must stay out of the UI CSS.");
  assert(foundation.includes("--ui-accent-subtle: var(--ui-accent-selection);"), "Dark primary soft actions must inherit the current accent selection color.");
  assert.equal(foundation.includes("--ui-accent-selection: var(--ui-action-primary-soft-bg);"), false, "Accent selection must not reference primary soft action tokens circularly.");
  const darkBlueAccentBlock = foundation.match(/\[data-ui-theme="dark"\]\[data-ui-accent="blue"\]\s*\{[\s\S]*?\n\}/)?.[0] ?? "";
  assert.equal(darkBlueAccentBlock.includes("--ui-accent-selection: var(--ui-action-primary-soft-bg);"), false, "Dark blue accent must not create a circular primary-soft selection token.");
  assert(demoStyles.includes("background: var(--ui-action-primary-bg);"), "Primary action base styles must use the accent-backed primary action token.");
  assert.equal(demoStyles.includes("background: var(--ui-action-primary-hover-bg);"), false, "Primary action hover must not switch to a separate background token.");
  assert(demoStyles.includes(".primary-button > .button-label {\n  color: currentColor;"), "Primary action labels must inherit the Button foreground.");
  assert(demoStyles.includes("--ui-pill-active-bg: var(--ui-pill-active-bg-surface);"), "Active navigation pills must default to surface-aware background tokens.");
  assert(demoStyles.includes("--ui-pill-active-bg: var(--ui-pill-active-bg-gray);"), "Gray surfaces must override active navigation pill background tokens.");
  assert(demoStyles.includes("background: var(--ui-pill-active-bg);"), "Command and selected states must use the interaction accent layer.");
  assert(demoStyles.includes("background: var(--ui-list-option-selected-bg"), "Choice modal selected states must use the interaction accent layer.");
  assert(foundation.includes("--ui-current-pill-fg: var(--ui-action-primary-soft-fg);"), "Current feedback pills must use the same readable soft foreground as accent actions.");
  assert(demoStyles.includes("color: var(--ui-current-pill-fg, var(--ui-action-primary-soft-fg));"), "Current feedback pills must use the dedicated action-backed foreground token.");
  assert(foundation.includes("--ui-sidebar-active-fg: var(--ui-action-primary-soft-fg);"), "Sidebar active labels must use the same readable soft foreground as accent actions.");
  assert(demoStyles.includes(".pill-sidebar-nav .nav-item:hover,\n.pill-sidebar-nav .nav-item.active {\n  background: transparent;\n  color: var(--ui-sidebar-active-fg, var(--ui-action-primary-soft-fg));"), "Sidebar active labels must override generic nav item colors through the action accent layer.");
  assert(demoStyles.includes("--choice-card-active-bg: var(--ui-choice-card-active-bg);"), "Choice cards must use the interaction accent layer instead of semantic info.");
  assert(demoStyles.includes("--ui-choice-card-icon-bg: var(--ui-input-icon-bg);"), "Choice card icon backgrounds on white panels must use the white-surface accent token.");
  assert(demoStyles.includes("--ui-choice-card-icon-bg: var(--ui-input-icon-bg-on-gray);"), "Choice card icon backgrounds on gray panels must use the gray-surface accent token.");
  assert(demoStyles.includes("--ui-choice-card-idle-icon-bg: var(--ui-input-icon-bg-on-gray);"), "Choice cards on white surfaces must default non-selected icons to the gray accent.");
  assert(demoStyles.includes("--ui-choice-card-hover-icon-bg: var(--ui-input-icon-bg);"), "Choice cards on white surfaces must swap non-selected icon hover to the white accent.");
  assert(demoStyles.includes("--ui-choice-card-idle-icon-bg: var(--ui-input-icon-bg);"), "Choice cards on gray surfaces must default non-selected icons to the white accent.");
  assert(demoStyles.includes("--ui-choice-card-hover-icon-bg: var(--ui-input-icon-bg-on-gray);"), "Choice cards on gray surfaces must swap non-selected icon hover to the gray accent.");
  assert(demoStyles.includes(".ui-choice-card:not(.is-selected) {\n  --choice-card-icon-bg: var(--ui-choice-card-idle-icon-bg, var(--ui-choice-card-icon-bg));\n}"), "Choice cards must implement non-selected icon accents as a default primitive behavior.");
  assert(demoStyles.includes(".ui-choice-card:not(.is-selected):is(:hover, :focus-visible) {\n  --choice-card-icon-bg: var(--ui-choice-card-hover-icon-bg, var(--ui-choice-card-icon-bg));\n}"), "Choice cards must implement non-selected icon hover accents as a default primitive behavior.");
  assert(demoStyles.includes("background-color: var(--choice-card-icon-bg);"), "Choice card icon accent swaps must fade through background-color instead of snapping.");
  assert.equal(demoStyles.includes(".ui-actions-choices-block .ui-actions-surface-panel"), false, "Actions choices must inherit default choice-card surface behavior instead of swapping accents locally.");
  assert.equal(demoStyles.includes("--choice-card-active-bg: var(--mono-cell);"), false, "Actions choices must not override choice card selected/hover backgrounds locally.");
  assert(demoStyles.includes("--ui-choice-card-active-fg: var(--ui-auto-input-icon-fg);"), "Choice card icon colors must reuse the same automatic input icon foreground.");
  assert.equal(demoStyles.includes("--choice-card-active-bg: var(--ui-feedback-info-bg-on-gray);"), false, "Choice cards must not consume semantic info backgrounds for interaction states.");
  assert(demoStyles.includes("background: var(--ui-choice-card-icon-bg, var(--ui-input-icon-bg));"), "Section and block icons must consume the existing automatic choice/icon surface tokens.");
  assert.equal(demoStyles.includes("--ui-auto-surface-icon-bg"), false, "Section and block icons must not create a second automatic icon surface system.");
  assert.equal(demoStyles.includes("--ui-overview-icon-bg"), false, "Overview icon previews must not use local accent swaps.");
  assert(demoStyles.includes("ui-overview-icon-demo"), "Overview must expose static block icon demonstrations in the visible catalog.");
  assert(demoStyles.includes("color: var(--ui-action-primary-soft-fg);"), "Selected interactive states must inherit the action accent foreground.");
  assert.equal(demoStyles.includes("var(--blue)"), false, "Component CSS must not bypass action accent tokens with the blue shortcut.");
  assert.equal(componentSources.includes("var(--blue)"), false, "Component runtime animation styles must not bypass action accent tokens with the blue shortcut.");
  assert(demoStyles.includes("var(--ui-sidebar-pill-shadow)"), "Sidebar active pill shadow must be tokenized.");
  const horizontalPillRule = readText("packages/ui/src/styles/ui-02-forms.css").match(/\.pill-tabs-pill::before\s*\{[\s\S]*?\n\}/)?.[0] ?? "";
  assert(horizontalPillRule.includes("box-shadow: none;"), "Horizontal tab pill must not draw a border or elevation.");
  assert.equal(horizontalPillRule.includes("var(--ui-pill-active-shadow)"), false, "Horizontal tab pill must not use an elevation shadow.");
  assert.equal(demoStyles.includes("var(--ui-pill-active-ring)"), false, "Navigation pills must not draw border rings.");
  assert(/\.muted-button:hover:not\(\[aria-disabled="true"\]\),\s*\.muted-button\.is-loading:hover/.test(demoStyles), "Muted actions must use the shared action hover lift, including loading wait actions.");
  assert.equal(demoStyles.includes(".muted-button:hover:not([aria-disabled=\"true\"]) {\n  transform: none;"), false, "Muted actions must not suppress the shared action hover lift.");

  const forbiddenTokens = ["--surface-green", "--surface-yellow", "--surface-blue", "--surface-red", "--ui-gray-good-bg", "--ui-gray-info-bg", "--ui-gray-warn-bg", "--ui-gray-danger-bg", "--ui-surface-violet", "--ui-surface-violet-gray", "--ui-violet-strong"];
  for (const forbiddenToken of forbiddenTokens) {
    assert.equal(foundation.includes(`${forbiddenToken}:`), false, `Foundation should not expose forbidden token ${forbiddenToken}`);
    assert.equal(demoStyles.includes(`${forbiddenToken}:`), false, `Demo styles should not expose forbidden token ${forbiddenToken}`);
    assert.equal(demoStyles.includes(`var(${forbiddenToken})`), false, `Demo styles should use semantic feedback/action tokens instead of ${forbiddenToken}`);
  }

  const accentBlocks = foundation.match(/\[data-ui-accent="(?:blue|sky|cyan|teal|emerald|green|lime|olive|yellow|amber|orange|red|rose|pink|fuchsia|purple|violet|indigo|slate|neutral)"\]\s*\{[\s\S]*?\n\}/g)?.join("\n") ?? "";
  assert.equal(accentBlocks.includes("--ui-feedback-info-"), false, "Accent variants must not rewrite semantic info feedback tokens.");
  assert.equal(accentBlocks.includes("--ui-icon-tone-brand"), false, "Accent variants must not rewrite semantic brand icon tokens.");
  const blueAccentBlock = foundation.match(/\[data-ui-accent="blue"\]\s*\{[\s\S]*?\n\}/)?.[0] ?? "";
  const lightBlueInputBlock = foundation.match(/:root:not\(\[data-ui-theme="dark"\]\)\[data-ui-accent="blue"\]\s*\{[\s\S]*?\n\}/)?.[0] ?? "";
  assert(blueAccentBlock.includes("--ui-accent: #1a73e8;"), "Blue accent foreground must match the primary action foreground.");
  assert(blueAccentBlock.includes("--ui-accent-selection: #e8f0fe;"), "Blue selected surfaces must match the primary action soft background.");
  assert(lightBlueInputBlock.includes("--ui-input-icon-bg: var(--ui-action-primary-soft-bg);"), "Blue input icons must use the exact primary action soft background.");
  assert(lightBlueInputBlock.includes("--ui-input-icon-bg-on-gray: var(--ui-action-primary-soft-bg-on-gray);"), "Blue input icons on gray must use the exact primary action gray soft background.");
  assert(foundation.includes("--ui-feedback-info-bg: var(--ui-semantic-info-bg);"), "Info feedback must stay on fixed semantic blue tokens.");
  assert(foundation.includes("--ui-feedback-info-fg: var(--ui-semantic-info-fg);"), "Info feedback foreground must stay semantically stable.");
  assert(demoStyles.includes(".ui-token.is-accent {\n  background: var(--ui-action-primary-soft-bg);"), "Overview accent blocks must use the interaction accent layer.");
  assert.equal(demoStyles.includes(".ui-token.is-accent {\n  background: var(--ui-feedback-info-bg);"), false, "Overview accent blocks must not use semantic info feedback colors.");
  assert.equal(readText("packages/ui/src/catalog/UiCatalogAsync.tsx").includes("ui.async.retry.alert"), false, "Async catalog must not render inline retry alerts.");
  assert.equal(readText("packages/ui/src/catalog/UiCatalogModals.tsx").includes("<InlineAlert"), false, "Modal examples must not render inline alert patterns.");
});
