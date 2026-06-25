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

function catalogShowsComponent(source: string, component: string) {
  const alternateMounts: Record<string, string[]> = {
    EmptyState: ["UiFeedbackEmpty", "SelectList"],
    FactGrid: ["UiFactGrid"],
    Metric: ["UiMetricGrid"],
    SectionCard: ["UiSectionCard"],
    UiSectionStack: ["UiSectionCard"],
    VirtualList: ["SelectList"],
  };

  return [component, ...(alternateMounts[component] ?? [])].some((candidate) => new RegExp(`<${candidate}\\b`).test(source));
}

test("UI catalog sidebar persists the active section in the URL hash", () => {
  const catalogApp = readText("packages/ui/src/catalog/UiCatalogApp.tsx");
  const catalogRouting = readText("packages/ui/src/catalog/catalog-routing.ts");
  const catalogPage = readText("apps/web/src/app/ui/page.tsx");
  const nextEntrypoint = readText("packages/ui/src/next.tsx");
  const sidebarSource = readText("packages/ui/src/PillSidebarNav.tsx");
  assert(catalogApp.includes("readUiCatalogSectionFromLocation"), "Catalog must read the current section from location.");
  assert(catalogApp.includes("initialSection = \"overview\""), "Catalog must accept an SSR-safe initial section.");
  assert(catalogApp.includes("useState<UiSectionId>(() => readUiCatalogSectionFromLocation(initialSection))"), "Catalog must hydrate from the current URL section before showing the first section.");
  assert(catalogApp.includes("const [catalogBooting, setCatalogBooting] = useState(true);"), "Catalog must keep the shell hidden until the active section is ready.");
  assert(catalogApp.includes("if (catalogBooting) return null;"), "Catalog must not mount the shell/sidebar before the active section is stable.");
  assert(catalogApp.includes("writeUiCatalogSectionToLocation"), "Catalog must write the selected section to location.");
  assert(catalogApp.includes('window.addEventListener("hashchange"'), "Catalog must react to direct hash changes.");
  assert(catalogApp.includes('window.addEventListener("popstate"'), "Catalog must keep browser back/forward in sync.");
  assert(catalogApp.includes("window.history.pushState"), "Catalog sidebar clicks must create a reloadable section URL.");
  assert(catalogApp.includes("UI_CATALOG_SECTION_QUERY_KEY"), "Catalog must keep a query section for SSR reloads without tab flash.");
  assert(catalogApp.includes("UI_CATALOG_SECTION_COOKIE"), "Catalog must persist the active section for refresh-safe SSR.");
  assert(catalogPage.includes("resolveStexorCatalogInitialSection"), "The UI route must resolve the initial section on the server.");
  assert(catalogPage.includes("StexorCatalogBootScript"), "The UI route must install the pre-hydration catalog section guard.");
  assert(nextEntrypoint.includes("data-ui-catalog-hydrating"), "Hash-only non-catalog section URLs must stay hidden until the client syncs the right section.");
  assert(sidebarSource.includes("data-pill-sidebar-active-index={activeIndex}"), "Sidebar active pill must be positioned before motion hydration to avoid refresh jumps.");
  assert(catalogApp.includes('onSelect={handleSectionSelect}'), "UiShell sidebar selection must use the hash-aware section handler.");
  for (const section of ["overview", "inputs", "actions", "navigation", "blocks", "feedback", "async", "modals"]) {
    assert(catalogRouting.includes(`"${section}"`), `Catalog hash whitelist must include ${section}.`);
  }
  assert.equal(catalogRouting.includes('"hidden"'), false, "Catalog hash whitelist must not keep non-catalog audit sections.");
});

test("UI catalog visibly covers every public visual primitive", () => {
  const catalogSource = [
    "UiCatalogActionBuilder.tsx", "UiCatalogActions.tsx", "UiCatalogApp.tsx", "UiCatalogAsync.tsx", "UiCatalogBlocks.tsx", "UiCatalogFeedback.tsx",
    "UiCatalogModals.tsx", "UiCatalogNavigation.tsx", "UiCatalogPanel.tsx", "catalog-data.tsx",
  ].map((file) => readText(`packages/ui/src/catalog/${file}`)).join("\n");

  for (const component of [
    "ActionFlow", "Badge", "Button", "CalendarPickerPanel", "CheckboxField", "ChoiceCard", "ChoiceModalHeader", "CommandPalette",
    "CustomScrollbar", "DateInputField", "Dropdown", "EmptyState", "FactGrid", "FieldGroup",
    "InlineAlert", "Modal", "ModalFooter", "PillSidebarNav", "PillTabs", "Popover", "RadioField", "RangeField",
    "SearchInput", "SectionCard", "SectionHeader", "SelectField", "SelectList", "Spinner", "StatusBadge", "StatusPill",
    "SwitchField", "TextareaField", "TextField", "UiPopupProvider",
    "UiFactGrid", "UiFeedbackEmpty", "UiMetricGrid", "UiPanelFrame", "UiSectionCard", "UiSectionStack", "UiShell",
  ]) {
    assert(catalogShowsComponent(catalogSource, component), `${component} must be visible in the catalog.`);
  }
});

test("UI popup system owns portal, timer and close motion in the framework", () => {
  const source = readText("packages/ui/src/Popup.tsx");
  const styles = readText("packages/ui/src/styles/base-07-popup.css");
  const catalog = readText("packages/ui/src/catalog/UiCatalogFeedback.tsx");

  assert(source.includes("createPortal"), "Popup provider must own portal rendering.");
  assert(source.includes('aria-live="polite"'), "Popup viewport must announce temporary messages politely.");
  assert(source.includes("showPopup"), "Popup system must expose a showPopup controller.");
  assert(source.includes("dismissPopup"), "Popup system must expose immediate dismissal.");
  assert(source.includes("const maxVisiblePopups = 5;"), "Popup stack must cap visible items at five.");
  assert(source.includes("const popupMotionMs = uiMotionDurations.morph;"), "Popup runtime must wait for the full visual motion before changing state or removing cards.");
  assert(source.includes("updatePopupTextMetrics"), "Popup runtime must extend timed dismissal from measured overflowing text.");
  assert(source.includes("measurePopupTextOverflow"), "Popup runtime must measure overflowing text before enabling marquee.");
  assert(source.includes("useDynamicCssProperties"), "Popup runtime must update marquee and timer duration without inline styles.");
  assert(source.includes("slice(-maxVisiblePopups)"), "Popup provider must enforce the visible stack cap.");
  assert(source.includes('className="ui-popup-close"'), "Popup cards must include an explicit close action.");
  assert(source.includes('className="ui-popup-timer"'), "Timed popup cards must render a timer line.");
  const inlineStyleProbe = "style=" + "{{";
  assert.equal(source.includes(inlineStyleProbe), false, "Popup runtime must remain CSP-safe without inline style attributes.");
  assert(styles.includes(".ui-popup-viewport"));
  assert(styles.includes("bottom: max(16px, env(safe-area-inset-bottom));"));
  assert(styles.includes("right: max(16px, env(safe-area-inset-right));"));
  assert(styles.includes(".ui-popup-card + .ui-popup-card"), "Popup stack spacing must be owned by cards so closing cards can collapse smoothly.");
  assert(styles.includes("--ui-popup-card-block-size: 64px;"), "Popup cards must keep a stable shared height.");
  assert(styles.includes("inline-size: min(280px, calc(100vw - 24px));"), "Popup cards must keep a stable shared desktop width.");
  assert(styles.includes("max-block-size: var(--ui-popup-card-block-size);"), "Popup stack motion must use the same fixed card height.");
  assert(styles.includes("--ui-popup-motion-duration: var(--ui-motion-morph);"), "Popup enter and exit motion must use the slower shared morph duration.");
  assert(styles.includes("max-block-size: 0;"), "Closing popup cards must collapse their layout space before removal.");
  assert(styles.includes("margin-block-start: 0;"), "Closing popup cards must animate stack spacing away.");
  assert(styles.includes("@keyframes ui-popup-stack-enter"), "Opening popup cards must grow layout space so existing cards slide upward.");
  assert(styles.includes("@keyframes ui-popup-stack-gap-enter"), "Opening popup cards must animate stack spacing instead of pushing siblings instantly.");
  assert(styles.includes("grid-template-columns: 30px minmax(0, 1fr) 30px;"), "Popup icon and close action must stay concentrically aligned.");
  assert(styles.includes("position: absolute;"), "Popup timer must not disturb card body alignment.");
  assert.equal(styles.includes(".ui-popup-close:hover"), false, "Popup close action must not have hover effects.");
  assert(styles.includes("@keyframes ui-popup-enter"));
  assert(styles.includes("@keyframes ui-popup-exit"));
  assert(styles.includes("@keyframes ui-popup-timer"));
  assert(styles.includes("@keyframes ui-popup-marquee"), "Overflowing popup text must scroll on a single line.");
  assert(styles.includes("white-space: nowrap;"), "Popup text must remain on one line before marquee starts.");
  assert(styles.includes("--ui-popup-marquee-duration"), "Popup marquee duration must be tokenized through a CSS variable.");
  assert(styles.includes("animation: ui-popup-marquee var(--ui-popup-marquee-duration)"), "Popup marquee must use the measured duration.");
  assert(styles.includes("var(--ui-motion-ease-emphasized)"), "Popup enter motion must use the shared smooth curve.");
  assert.equal(styles.includes("var(--ui-motion-ease-soft-spring)"), false, "Popup motion must not use bounce curves.");
  assert(styles.includes("@media (prefers-reduced-motion: reduce)"));
  assert(catalog.includes("<UiPopupProvider"));
  assert(catalog.includes("showPopup({"));
});

test("catalog package files stay limited to official sections", () => {
  const catalogFiles = walk("packages/ui/src/catalog").map((file) => file.replace("packages/ui/src/catalog/", "")).sort();
  const publicCore = readText("packages/ui/src/core.ts");

  assert.deepEqual(catalogFiles, [
    "UiCatalogActionBuilder.tsx",
    "UiCatalogActions.tsx",
    "UiCatalogApp.tsx",
    "UiCatalogAsync.tsx",
    "UiCatalogBlocks.tsx",
    "UiCatalogFeedback.tsx",
    "UiCatalogModals.tsx",
    "UiCatalogNavigation.tsx",
    "UiCatalogPanel.tsx",
    "UiCatalogToken.tsx",
    "catalog-data.tsx",
    "catalog-routing.ts",
    "catalog-theme.ts",
    "catalog-types.ts",
  ]);
  assert.equal(/Ui[A-Z][A-Za-z]*Sandbox/.test(publicCore), false, "Sandbox-only patterns must not become public API exports automatically.");
});

test("catalog source stays scoped to UI class names and package-local imports", () => {
  for (const file of walk("packages/ui/src/catalog").filter((candidate) => /\.(?:ts|tsx)$/.test(candidate))) {
    const text = readText(file);
    assert.equal(text.includes("@/components"), false, `${file} must not import app components.`);
    assert.equal(text.includes("@stexor/ui/cssom"), false, `${file} must not import package internals through public paths.`);
    assert.equal(/["'`][^"'`]*(?:account-|profile-)/.test(text), false, `${file} must not define account/profile class names.`);
  }
});
