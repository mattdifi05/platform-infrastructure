import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workspaceRoot = new URL("../../../", import.meta.url);

function readText(relativePath: string): string {
  return readFileSync(new URL(relativePath, workspaceRoot), "utf8").replace(/\r\n/g, "\n");
}

test("accent governance and action builder stay framework-owned", () => {
  const foundation = [
    readText("packages/ui/src/styles/base-01-foundation.css"),
    readText("packages/ui/src/styles/base-01-accent.css"),
  ].join("\n");
  const formSource = readText("packages/ui/src/Form.tsx");
  const builderCatalog = readText("packages/ui/src/catalog/UiCatalogActionBuilder.tsx");
  const builderStyles = readText("packages/ui/src/styles/ui-app-11-action-builder.css");
  const controlsStyles = readText("packages/ui/src/styles/ui-02-controls.css");
  const sharedControlsStyles = readText("packages/ui/src/styles/ui-shared-controls.css");
  const actionConfig = readText("packages/ui/src/ActionConfig.ts");
  const iconSource = readText("packages/ui/src/icons.tsx");
  const readme = readText("packages/ui/README.md");

  const accentBlocks = foundation.match(/\[data-ui-accent="(?:blue|sky|cyan|teal|emerald|green|lime|olive|yellow|amber|orange|red|rose|pink|fuchsia|purple|violet|indigo|slate|neutral)"\]\s*\{[\s\S]*?\n\}/g)?.join("\n") ?? "";
  assert.equal(foundation.includes("--ui-service-"), false, "Service/product color tokens must stay out of the foundation.");
  assert.equal(accentBlocks.includes("--ui-feedback-info-"), false, "Accent variants must not rewrite semantic info feedback tokens.");
  assert.equal(accentBlocks.includes("--ui-icon-tone-brand"), false, "Accent variants must not rewrite semantic brand icon tokens.");
  assert.equal(builderCatalog.includes(["define", "Action"].join("")), false, "Action Builder catalog must not introduce a parallel action system.");
  assert.equal(builderCatalog.includes(["create", "Ui", "Action"].join("")), false, "Action Builder catalog must use Button directly.");
  assert(builderCatalog.includes("IconPickerField"), "Action Builder must use a dedicated searchable icon picker.");
  assert(builderCatalog.includes("SearchInput"), "Action Builder icon picker must include search.");
  assert(builderCatalog.includes('panelClassName="choice-modal-panel ui-modal-panel ui-action-builder-icon-modal"'), "Action Builder icon picker must use the official modal panel surface.");
  assert(builderCatalog.includes('<div className="ui-modal">'), "Action Builder icon picker content must inherit the official modal surface context.");
  assert(formSource.includes('classNames("ui-search", className'), "SearchInput must always keep the framework ui-search base class.");
  assert(formSource.includes('type={inputProps?.type ?? "search"}'), "SearchInput must render as a native search input by default.");
  assert.equal(builderCatalog.includes("ui-action-builder-icon-search"), false, "Action Builder icon picker must not add a custom search input class.");
  assert.equal(builderStyles.includes("ui-action-builder-icon-search"), false, "Action Builder styles must not override the shared search input.");
  assert(builderCatalog.includes("VirtualList"), "Action Builder icon picker must stay performant with a large icon set.");
  assert(builderCatalog.includes("ui-action-builder-icon-option-icon"), "Action Builder icon options must show the icon before its name.");
  assert(builderCatalog.includes("Object.entries(uiIconRegistry)"), "Action Builder must expose the governed enumerable FontAwesome icon registry.");
  assert(builderCatalog.includes("ColorPickerField"), "Action Builder must expose a color picker with swatches.");
  assert(builderCatalog.includes("ui-action-builder-color-dot"), "Action Builder color options must show a swatch beside the color name.");
  assert(builderCatalog.includes("const [fullColor, setFullColor] = useState(false)"), "Action Builder color fullness must default to the soft action style.");
  assert(builderCatalog.includes('label="Colore pieno"'), "Action Builder must expose a switch for filled action color.");
  assert(builderCatalog.includes("solid={previewSolid}"), "Action Builder previews must drive Button fullness through the shared Button primitive.");
  assert.equal(builderCatalog.includes("formatSolidProp"), false, "Action Builder must not keep code-output helpers.");
  assert.equal(builderCatalog.includes("ui-action-builder-config"), false, "Action Builder must not render a code-output block.");
  assert(builderStyles.includes('[data-ui-action-solid="true"]'), "Action Builder color swatches must expose soft and filled color states.");
  assert(builderStyles.includes(".ui-action-builder-color-picker .custom-select-button"), "Action Builder color picker must align its chevron without the standard leading icon column.");
  assert(builderStyles.includes("corner-shape: var(--ui-corner-shape)"), "Action Builder blocks must use the shared squircle geometry.");
  assert(builderCatalog.includes("confirmBeforeAction"), "Action Builder must expose an opt-in confirmation modal flow.");
  assert(builderCatalog.includes("ModalFooter"), "Action Builder confirmation flow must use the shared modal primitives.");
  assert(builderCatalog.includes("ActionBuilderPreviewButtons"), "Action Builder must reuse the same Button preview across surfaces.");
  assert(builderCatalog.includes('data-ui-surface="white"'), "Action Builder must preview the white surface.");
  assert(builderCatalog.includes('data-ui-surface="gray"'), "Action Builder must preview the gray surface.");
  assert(builderCatalog.includes('const previewVariant = loading ? "muted" : variant'), "Action Builder loading preview must use the neutral base Actions variant.");
  assert(builderCatalog.includes("const previewClick = confirmBeforeAction && !loading"), "Action Builder loading preview must not trigger actions while busy.");
  assert.equal(builderCatalog.includes('"bookings"'), false, "Action Builder icon picker must not hardcode service identity names.");
  assert.equal(builderCatalog.includes('"workManager"'), false, "Action Builder icon picker must not hardcode service identity names.");
  assert.equal(iconSource.includes(["with", "Private", ["Ali", "ases"].join("")].join("")), false, "Icon registry must not keep private shortcuts.");
  for (const forbiddenIconKey of ["bookings", "workManager", "studentHub", "qrTool", "timeTracker", "service"]) {
    assert.equal(iconSource.includes(`${forbiddenIconKey}:`), false, `Icon registry must not keep private key ${forbiddenIconKey}.`);
  }
  assert(builderCatalog.includes("uiActionBuilderVariantOptions"), "Builder catalog must consume the central action variant options.");
  assert(actionConfig.includes('value: "primary"'), "Primary action variant must be visible in the Builder config.");
  assert(actionConfig.includes('value: "muted"'), "Muted action variant must be visible in the Builder config.");
  assert.equal(actionConfig.includes('value: "info"'), false, "Info must stay out of the Builder palette.");
  assert(actionConfig.includes('value: "cyan"'), "Cyan action variant must be visible in the Builder config.");
  assert(actionConfig.includes('value: "teal"'), "Teal action variant must be visible in the Builder config.");
  assert(actionConfig.includes('value: "edit"'), "Edit action variant must be visible in the Builder config.");
  assert(actionConfig.includes('value: "violet"'), "Violet action variant must be visible in the Builder config.");
  assert.equal(actionConfig.includes('value: "orange"'), false, "Orange must stay merged into Warning in the Builder palette.");
  assert(actionConfig.includes('value: "rose"'), "Rose action variant must be visible in the Builder config.");
  assert(actionConfig.includes('value: "slate"'), "Slate action variant must be visible in the Builder config.");
  assert(actionConfig.includes('value: "warning"'), "Warning action variant must be visible in the Builder config.");
  assert(actionConfig.includes('value: "danger"'), "Destructive action variant must be visible in the Builder config.");
  assert.equal(readText("packages/ui/src/styles/base-01-foundation.css").includes("--ui-action-primary-hover-bg"), false, "Action background hover tokens must not remain as an unused parallel color path.");
  assert.doesNotMatch(controlsStyles, /\.primary-button:hover[^{]*\{[^}]*--ui-action-primary-hover-bg/s, "Action hover must not change the primary background color.");
  assert.doesNotMatch(sharedControlsStyles, /\.primary-button:hover[^{]*\{[^}]*--ui-action-primary-hover-bg/s, "Shared action hover must not change the primary background color.");
  assert.equal(builderCatalog.includes("setDisabled"), false, "Action Builder must not promote disabled buttons.");
  assert.equal(builderCatalog.includes("disabled={"), false, "Action Builder must keep unavailable actions out of the UI.");
  assert(readme.includes("The governed accent palette contains 20 tones"));
  assert(readme.includes("Accent is interaction-only"));
  assert(readme.includes("Action Builder"));
  assert(readme.includes("only the four official shapes"));
  assert(readme.includes("`info` is not an action tone"));
  assert(readme.includes("Loading means busy, not disabled"));
});
