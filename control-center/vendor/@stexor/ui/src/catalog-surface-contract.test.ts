import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";

const workspaceRoot = new URL("../../../", import.meta.url);

function readText(relativePath: string): string {
  return readFileSync(new URL(relativePath, workspaceRoot), "utf8").replace(/\r\n/g, "\n");
}

function walk(relativePath: string): string[] {
  const directory = new URL(relativePath, workspaceRoot);
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const childPath = `${relativePath}/${entry.name}`;
    return entry.isDirectory() ? walk(childPath) : childPath;
  });
}

test("catalog surfaces adapt controls and pills from inherited surface tokens", () => {
  const catalogSource = walk("packages/ui/src/catalog").filter((file) => /\.(?:ts|tsx)$/.test(file)).map((file) => readText(file)).join("\n");
  const autoSurfaceStyles = readText("packages/ui/src/styles/ui-03-monochrome-surfaces.css");
  const foundationStyles = readText("packages/ui/src/styles/base-01-foundation.css");
  const controlsStyles = [
    readText("packages/ui/src/styles/ui-02-controls.css"),
    readText("packages/ui/src/styles/ui-02-forms.css"),
  ].join("\n");
  const formRuntime = [
    readText("packages/ui/src/Form.tsx"),
    readText("packages/ui/src/Select.tsx"),
    readText("packages/ui/src/DatePicker.tsx"),
  ].join("\n");
  const surfaceRuntime = readText("packages/ui/src/useResolvedSurface.ts");
  const actionCatalog = readText("packages/ui/src/catalog/UiCatalogActions.tsx");
  const blockCatalog = readText("packages/ui/src/catalog/UiCatalogBlocks.tsx");
  const overlayPatterns = readText("packages/ui/src/OverlayPatterns.tsx");
  const sectionStyles = [
    readText("packages/ui/src/styles/ui-app-04-feedback.css"),
    readText("packages/ui/src/styles/ui-app-06-async.css"),
    readText("packages/ui/src/styles/ui-app-09-blocks.css"),
  ].join("\n");

  for (const forbiddenManualClass of ["ui-button-on-gray", "is-surface-control", "ui-gray-action-card"]) {
    assert.equal(catalogSource.includes(forbiddenManualClass), false);
    assert.equal(autoSurfaceStyles.includes(forbiddenManualClass), false);
    assert.equal(controlsStyles.includes(forbiddenManualClass), false);
  }
  for (const token of ["--ui-auto-control-bg", "--ui-auto-muted-button-bg", "--ui-auto-violet-button-bg", "--ui-auto-input-icon-bg", "--ui-auto-input-icon-fg", "--ui-auto-input-icon-brand-bg", "--ui-auto-input-icon-country-bg", "--ui-auto-good-pill-bg", "--ui-auto-info-pill-bg", "--ui-auto-danger-pill-bg"]) {
    assert(autoSurfaceStyles.includes(token) || controlsStyles.includes(token), `Missing automatic surface token: ${token}`);
  }
  const grayControlSurfaceSelector = ':is(.ui-page, .ui-modal) [data-ui-surface="gray"] :is(.field-control, .custom-select-button, .ui-date-button, .ui-search)';
  assert(autoSurfaceStyles.includes(grayControlSurfaceSelector));
  assert(formRuntime.includes("useResolvedSurfaceRef"), "Input primitives must resolve the nearest visual surface instead of trusting an outer block.");
  assert(surfaceRuntime.includes('getAttribute("data-ui-surface")'), "Surface resolver must read explicit surface attributes.");
  assert(surfaceRuntime.includes("current.matches(surfaceRootSelector)"), "Surface resolver must observe overlay/modal root surface changes for portaled inputs.");
  assert.equal(surfaceRuntime.includes("while (current && !current.matches(surfaceRootSelector))"), false, "Surface resolver must not skip the overlay/modal root surface node.");
  assert(autoSurfaceStyles.includes('[data-ui-resolved-surface="white"]'), "Resolved white controls must override outer gray ancestors.");
  assert(autoSurfaceStyles.includes('[data-ui-resolved-surface="gray"]'), "Resolved gray controls must override outer white ancestors.");
  assert(actionCatalog.includes("data-ui-surface={variant}"), "Choice cards must declare their live surface instead of relying on class-only detection.");
  assert(blockCatalog.includes("data-ui-surface={blockCardSurface(surface.id)}"), "Block cards must declare the inverted visual card surface for automatic icon/action colors.");
  assert.equal(blockCatalog.includes("<ActionFlow"), false, "Multi-step blocks must use stable edge icon actions instead of morphing ActionFlow controls.");
  assert(blockCatalog.includes("ui-block-step-action is-back"), "Multi-step blocks must expose a left edge back icon action.");
  assert(blockCatalog.includes("ui-block-step-action is-forward"), "Multi-step blocks must expose a stable right edge action.");
  assert(/className=\{`ui-block-step-action is-forward[\s\S]+variant="primary"/.test(blockCatalog), "Multi-step forward action must use the primary accent color, not the violet variant.");
  assert(blockCatalog.includes('isLastStep ? "is-complete" : "ui-block-step-round is-next"'), "The right edge action must transform between icon-only next and complete states.");
  assert(blockCatalog.includes("ui-block-step-action-slot is-left"), "Multi-step block actions must keep a stable left edge slot.");
  assert(blockCatalog.includes("ui-block-step-action-slot is-right"), "Multi-step block actions must keep a stable right edge slot.");
  assert(blockCatalog.includes('aria-label={t("common.back")}'), "Back icon action must keep an accessible text label.");
  assert(blockCatalog.includes("aria-label={isLastStep ? undefined : rightActionLabel}"), "Icon-only next action must keep an accessible text label.");
  assert(blockCatalog.includes('rightActionLabel = isLastStep ? t("ui.action.complete") : t("ui.action.next")'), "Final multi-step action must derive the visible complete label.");
  assert(blockCatalog.includes("{isLastStep ? rightActionLabel : undefined}"), "Final multi-step action must show the complete label as visible text.");
  assert.equal(blockCatalog.includes("id=\"save\""), false, "Multi-step blocks must use the current action set.");
  assert.equal(blockCatalog.includes('type BlockButtonId = "commands" | "complete" | "continue"'), false, "Blocks local action config must use the current button ids.");
  assert.equal(overlayPatterns.includes("blockSurfaceNode"), false, "Overlay surface context must use the nearest trigger surface, not a broad outer demo block.");
  assert(autoSurfaceStyles.includes('[data-ui-resolved-surface="white"] {\n  --ui-auto-control-bg: var(--ui-control-bg);\n  --ui-auto-input-icon-bg: var(--ui-input-icon-bg-on-gray);'), "Gray input fields on white surfaces must use the softer accent icon token.");
  assert(autoSurfaceStyles.includes('[data-ui-resolved-surface="gray"] {\n  --ui-auto-control-bg: var(--mono-cell);\n  --ui-auto-input-icon-bg: var(--ui-input-icon-bg);'), "White input fields on gray surfaces must use the clearer accent icon token.");
  assert(autoSurfaceStyles.includes("--ui-choice-card-icon-bg: var(--ui-input-icon-bg);"), "Title/choice icons on white surfaces must use the existing direct white-surface accent token.");
  assert(autoSurfaceStyles.includes("--ui-choice-card-icon-bg: var(--ui-input-icon-bg-on-gray);"), "Title/choice icons on gray surfaces must use the existing direct gray-surface accent token.");
  assert(controlsStyles.includes("--ui-setting-icon-fg: var(--ui-auto-input-icon-fg, var(--ui-input-icon-fg));"), "Input icons must keep surface-aware accent foregrounds instead of full white icons.");
  assert(foundationStyles.includes("--ui-field-focus-border: var(--ui-action-primary-bg);"), "Input hover/focus borders must inherit the same accent token as primary actions.");
  assert(controlsStyles.includes("--ui-control-tone-border: var(--ui-field-focus-border);"), "Input tone borders must use the shared accent focus border.");
  assert(autoSurfaceStyles.includes(":is(.ui-page, .ui-modal, .ui-overlay-panel) :is(\n  .field-control,\n  .custom-select-button,\n  .ui-date-button,\n  .ui-search\n):is("), "Input hover effects must apply inside pages, modals and overlays.");
  assert(autoSurfaceStyles.includes(":is(.ui-page, .ui-modal, .ui-overlay-panel) :is(\n  .field-control,\n  .ui-search\n):is("), "Text input focus effects must apply inside pages, modals and overlays.");
  assert.equal(controlsStyles.includes("--ui-control-tone-border: var(--ui-icon-tone-brand-ring);"), false, "Input hover/focus borders must not stay pinned to the brand ring.");
  assert.equal(/--ui-setting-icon-fg:\s*var\(--ui-input-icon-(?:email|date|country|language)-fg\)/.test(controlsStyles), false, "Input icon tones must not bypass the global accent foreground.");
  assert(controlsStyles.includes("box-shadow: none;"), "Input icons must not draw an extra inner ring.");
  assert(controlsStyles.includes("border-radius: var(--ui-radius-icon);"), "Input icons must use the shared rounded icon radius.");
  assert(controlsStyles.includes("corner-shape: var(--ui-corner-shape);"), "Input icons must use the shared squircle geometry.");
  assert(
    autoSurfaceStyles.indexOf('[data-ui-resolved-surface="white"]') > autoSurfaceStyles.indexOf(grayControlSurfaceSelector),
    "Resolved control surface rules must come after broad gray ancestor rules.",
  );

  assert(sectionStyles.includes(".ui-block-step-action.is-hidden {\n  filter: blur(3px);\n  opacity: 0;"), "Multi-step edge actions must fade in from a blurred hidden state.");
  assert(sectionStyles.includes(".ui-block-step-round {\n  aspect-ratio: 1;"), "The morphing right edge icon action must use a local low-specificity round size.");
  assert.equal(sectionStyles.includes("--ui-block-step-morph-duration"), false, "Multi-step actions must not add a second local morph timeline over the Button primitive.");
  assert.equal(sectionStyles.includes("ui-block-step-forward-grow"), false, "Multi-step actions must not restart interrupted width morphs from fixed grow keyframes.");
  assert.equal(sectionStyles.includes("ui-block-step-forward-shrink"), false, "Multi-step actions must not restart interrupted width morphs from fixed shrink keyframes.");
  assert(sectionStyles.includes(".ui-block-step-action.is-forward.is-next.is-morphing > .button-morph-outgoing"), "The complete-to-next morph must suppress the outgoing text flicker.");
  assert(sectionStyles.includes(".ui-block-step-action.is-forward.is-next.is-morphing > .button-morph-outgoing {\n  animation: none;\n  opacity: 0;\n  overflow: hidden;\n}"), "The complete label must not flash while shrinking back to the icon action.");
  assert(sectionStyles.includes(".ui-block-step-marker.is-done {\n  animation: ui-block-step-marker-in var(--ui-motion-smooth) var(--ui-ease) both;\n  background: var(--ui-action-primary-soft-bg);"), "Completed multi-step markers must not use the semantic green feedback token.");
  assert(sectionStyles.includes(".ui-block-step-marker.is-active {\n  animation: ui-block-step-marker-in var(--ui-motion-step) var(--ui-ease) both;\n  background: var(--ui-action-primary-bg);\n  color: var(--ui-action-primary-fg);"), "Active multi-step markers must use the solid primary action token instead of soft input icon tokens.");
  const asyncLoadingCardIndex = autoSurfaceStyles.indexOf(".ui-page .ui-async-loading-card");
  const asyncLoadingCardResetIndex = autoSurfaceStyles.indexOf('.ui-async-loading-surface[data-ui-surface="gray"] .ui-async-loading-card');
  assert(asyncLoadingCardIndex >= 0, "Async loading card must adapt the badge to its gray card surface.");
  assert(asyncLoadingCardResetIndex > asyncLoadingCardIndex, "Async gray variant uses a white card and must reset pill tokens after the gray-card rule.");
  assert(autoSurfaceStyles.slice(asyncLoadingCardIndex, asyncLoadingCardResetIndex).includes("--ui-auto-good-pill-bg: var(--ui-feedback-good-bg-on-gray);"));
  assert(autoSurfaceStyles.slice(asyncLoadingCardResetIndex).includes("--ui-auto-good-pill-bg: var(--ui-feedback-good-bg);"));
});
