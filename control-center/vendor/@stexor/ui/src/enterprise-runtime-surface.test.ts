import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { uiMotionDurations } from "./motion-tokens";

const workspaceRoot = new URL("../../../", import.meta.url);

function readText(relativePath: string) {
  return readFileSync(new URL(relativePath, workspaceRoot), "utf8").replace(/\r\n/g, "\n");
}

test("CommandPalette and overlay patterns are stack-owned catalog-visible primitives", () => {
  const commandSource = readText("packages/ui/src/CommandPalette.tsx");
  const modalSource = readText("packages/ui/src/Modal.tsx");
  const overlayManagerSource = readText("packages/ui/src/OverlayManager.ts");
  const overlayPatternsSource = readText("packages/ui/src/OverlayPatterns.tsx");
  const blocksSource = readText("packages/ui/src/catalog/UiCatalogBlocks.tsx");
  const coreSource = readText("packages/ui/src/core.ts");

  const commandModelSource = readText("packages/ui/src/CommandPaletteModel.ts");
  for (const token of ["CommandPalette", "SearchInput", "groupCommands", "recentCommandIds", "runningCommandId", "role: \"combobox\"", "role=\"listbox\"", "role=\"option\""]) {
    assert(commandSource.includes(token), `CommandPalette must expose ${token}.`);
  }
  assert(commandModelSource.includes("groupCommandPaletteCommands"), "CommandPalette filtering must live in the shared model used by the visible command runtime.");
  assert(commandModelSource.includes("commandMatchesQuery"), "CommandPalette query matching must stay centralized.");
  for (const token of ["Popover", "Dropdown", "uiOverlayStack.register", "routeEscape()", "getFocusableElements", "getNearestSurfaceContext", "data-ui-surface={resolvedPanelSurface}", "type=\"command-palette\""]) {
    assert(overlayPatternsSource.includes(token) || commandSource.includes(token), `Overlay patterns must use ${token}.`);
  }
  assert(overlayPatternsSource.includes('type === "command-palette" ? "white" : surfaceContext'), "Command palettes must default to a white overlay surface so shared SearchInput stays gray without a local surface override.");
  assert.equal(commandSource.includes('surface="white"'), false, "CommandPalette must inherit its white surface from the overlay type default instead of passing a local override.");
  assert(commandSource.includes('panelClassName="ui-command-panel"'), "CommandPalette must keep its original command-panel layout.");
  for (const token of ["modal?: boolean", "const hasModalEntry = this.#entries.some((entry) => entry.modal)", "classList.toggle(\"modal-open\", hasModalEntry)", "if (!hasModalEntry && !isOverlayLayer)"]) {
    assert(overlayManagerSource.includes(token), `Overlay manager must keep page scroll locking scoped to modal overlays: ${token}.`);
  }
  assert(modalSource.includes("modal: true"), "Classic modals must still register as scroll-locking modal overlays.");
  assert(overlayPatternsSource.includes("document.addEventListener(\"mousedown\", handleOutsidePointerDown, true)"), "Non-modal floating overlays must close from document outside-click handling without blocking page scroll.");
  for (const token of ["UiOverlayVisualState", "data-ui-overlay-state", "closingDurationMs", "uiMotionDurations.overlay"]) {
    assert(overlayPatternsSource.includes(token), `Overlay patterns must animate ${token}.`);
  }
  for (const token of ["UiOverlayMotion", "data-ui-overlay-motion={motion}", 'motion="morph"']) {
    assert(overlayPatternsSource.includes(token) || blocksSource.includes(token), `Overlay morph variant must expose ${token}.`);
  }
  const overlayStyles = readText("packages/ui/src/styles/base-06-modal.css");
  const surfaceStyles = readText("packages/ui/src/styles/ui-03-monochrome-surfaces.css");
  for (const token of ["--ui-overlay-trigger-gap", ".ui-overlay-layer[data-ui-overlay-state=\"closing\"]", ".ui-overlay-layer[data-ui-overlay-state=\"open\"] .ui-overlay-panel"]) {
    assert(overlayStyles.includes(token), `Overlay styles must include ${token}.`);
  }
  assert(overlayStyles.includes("border: 1px solid color-mix(in srgb, var(--text) 7%, transparent);"), "Floating overlays must use only a near-invisible tokenized contrast edge.");
  assert(overlayStyles.includes("box-shadow: 0 18px 52px color-mix(in srgb, var(--ui-shadow-neutral-modal) 72%, transparent);"), "Floating overlays must keep a wider but still soft tokenized shadow.");
  assert(overlayStyles.includes(".ui-overlay-layer:not(.is-modal):not(.ui-command-layer) {\n  pointer-events: none;\n}"), "Floating overlay layers must not intercept page scroll outside the panel.");
  assert(overlayStyles.includes("[data-ui-theme=\"dark\"] .ui-overlay-panel {\n  background: var(--mono-cell);\n}"), "Dark floating overlays must use a flat tokenized surface instead of a gradient.");
  assert(overlayStyles.includes("[data-ui-theme=\"dark\"] .ui-overlay-panel[data-ui-surface=\"gray\"] {\n  background: var(--mono-cell-muted);\n}"), "Dark gray-surface floating overlays must stay flat while preserving surface contrast.");
  for (const token of ['[data-ui-overlay-motion="morph"]', "border-radius: var(--ui-radius-24);", "filter: blur(7px);", "will-change: opacity, transform, filter, border-radius;"]) {
    assert(overlayStyles.includes(token), `Overlay morph styles must include ${token}.`);
  }
  assert(!overlayStyles.includes("clip-path: inset(0 round var(--ui-radius-24));"), "Overlay morph must use real squircle corners instead of round clip-path corners.");
  assert(!/\.ui-overlay-panel\s*\{[^}]*box-shadow:\s*0 24px 72px var\(--ui-shadow-neutral-modal\);/.test(overlayStyles), "Floating overlays must avoid heavy panel shadows.");
  assert(surfaceStyles.includes(".ui-overlay-panel[data-ui-surface=\"gray\"]"), "Overlay panels must inherit automatic gray/white surface tokens.");
  for (const token of [
    "--ui-command-backdrop-blur-open",
    ".ui-command-layer[data-ui-overlay-state=\"open\"]",
    ".ui-command-layer[data-ui-overlay-state=\"closing\"] .ui-command-panel",
    ".ui-command-panel {\n  background: var(--ui-white);",
    "border-radius: var(--ui-radius-48);",
    "transform: scale(0.76) translateZ(0);",
  ]) {
    assert(overlayStyles.includes(token), `Command palette must use modal-style overlay motion: ${token}.`);
  }
  assert(!commandSource.includes('className="ui-command-search"'), "CommandPalette must use the shared SearchInput without a custom search class.");
  assert(!overlayStyles.includes(".ui-command-search"), "CommandPalette must not override the shared SearchInput geometry.");
  assert(overlayStyles.includes(".custom-select-menu.choice-modal-list .choice-modal-virtual-list::-webkit-scrollbar"), "Virtualized choice modal lists must inherit visible modal scrollbar styling.");
  assert(!overlayStyles.includes(".custom-select-menu.choice-modal-list {\n  background: var(--ui-white);\n  border: 0;\n  border-radius: 0;\n  box-shadow: none;\n  display: grid;\n  gap: 6px;\n  max-height: min(430px, calc(100dvh - 170px));\n  overflow: auto;\n  padding: 0 2px 0 0;\n  scrollbar-gutter: stable;"), "Plain choice modal lists must not reserve scrollbar space when they do not overflow.");
  assert(!overlayStyles.includes(".choice-modal-virtual-list {\n  min-height: 0;\n  overflow: auto;\n  scrollbar-gutter: stable;"), "Virtualized choice modal lists must not reserve scrollbar space while search results do not overflow.");
  assert(!overlayPatternsSource.includes("ui-overlay-backdrop"), "Overlay windows must stay backdrop-free.");
  assert(blocksSource.includes("data-ui-surface={blockCardSurface(surface.id)}"));
  assert(blocksSource.includes("BlockButton"), "Blocks must keep using shared action primitives.");
  for (const token of ["CommandPalette", "Dropdown", "Popover"]) {
    assert(coreSource.includes(token), `${token} must be exported.`);
    assert(blocksSource.includes(`<${token}`), `${token} must be visible in Blocks.`);
  }
  for (const token of ["ContextMenu", "Drawer", "Sheet", "Tooltip"]) {
    assert.equal(coreSource.includes(token), false, `${token} must stay out until it is visible in the catalog.`);
    assert.equal(overlayPatternsSource.includes(`function ${token}`), false, `${token} must not remain as a hidden overlay wrapper.`);
  }
});

test("release maturity docs cover performance, accessibility and migration gates", () => {
  const rootManifest = readText("package.json");
  const uiManifest = readText("packages/ui/package.json");
  const releaseScript = readText("scripts/ui-release-notes.mjs");
  const accessibilityDocs = readText("packages/ui/docs/accessibility-matrix.md");
  const deviceDocs = readText("packages/ui/docs/cross-device-validation.md");
  const readinessReport = readText("packages/ui/docs/production-readiness-report.md");
  const productDocs = readText("packages/ui/docs/product-platform.md");
  const releaseGovernance = readText("packages/ui/docs/release-governance.md");
  const regressionDocs = readText("packages/ui/docs/regression-strategy.md");
  const operationsDocs = readText("packages/ui/docs/operations-readiness.md");
  const releaseReport = readText("packages/ui/docs/enterprise-release-report.md");

  assert(rootManifest.includes("scripts/ui-release-notes.mjs"));
  assert(rootManifest.includes("scripts/ui-api-stability.mjs"));
  assert.equal(uiManifest.includes('"benchmark"'), false);
  assert(uiManifest.includes('"docs"'));
  assert(releaseScript.includes("CHANGELOG.md"));
  assert(releaseScript.includes("Performance"));
  assert(accessibilityDocs.includes("Command Palette"));
  assert(deviceDocs.includes("Safari iOS"));
  assert(productDocs.includes("Product Gates"));
  assert(readinessReport.includes("10/10-ready candidate"));
  assert(releaseGovernance.includes("Mutable tags are forbidden"));
  assert(regressionDocs.includes("No release test may stay skipped"));
  assert(operationsDocs.includes("platform observability gates pass"));
  assert(operationsDocs.includes("Release Operator Checklist"));
  assert(releaseReport.includes("enterprise release-grade candidate"));
});

test("motion durations centralize overlay timing", () => {
  assert.equal(uiMotionDurations.overlay, 380);
  assert.equal(uiMotionDurations.morph, 460);
});
