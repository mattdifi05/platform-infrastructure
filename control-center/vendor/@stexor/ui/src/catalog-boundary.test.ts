import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workspaceRoot = new URL("../../../", import.meta.url);

function readText(relativePath: string): string {
  return readFileSync(new URL(relativePath, workspaceRoot), "utf8").replace(/\r\n/g, "\n");
}

test("UI catalog keeps only official visible sections", () => {
  const catalogData = readText("packages/ui/src/catalog/catalog-data.tsx");
  const catalogRouting = readText("packages/ui/src/catalog/catalog-routing.ts");
  const catalogPanel = readText("packages/ui/src/catalog/UiCatalogPanel.tsx");
  const catalogModals = readText("packages/ui/src/catalog/UiCatalogModals.tsx");
  const classicModalSource = catalogModals.slice(catalogModals.indexOf('layoutId="ui-modal-classic"'), catalogModals.indexOf('layoutId="ui-modal-calendar"'));
  const optionsModalSource = catalogModals.slice(catalogModals.indexOf('layoutId="ui-modal-options"'));

  assert(catalogRouting.includes('uiCatalogSectionIds = ["overview", "inputs", "actions", "navigation", "blocks", "feedback", "async", "modals"] as const;'));
  for (const token of ["getUiSectionGuides", "UiSectionGuidePanel"]) assert(catalogData.includes(token));
  for (const section of ["overview", "inputs", "actions", "navigation", "blocks", "feedback", "async", "modals"]) {
    assert(catalogPanel.includes(`guide={sectionGuides.${section}}`));
  }
  assert.equal(catalogData.includes('id: "hidden"'), false);
  assert.equal(catalogData.includes('id: "package"'), false);
  assert.equal(catalogData.includes('id: "mobile"'), false);
  assert.equal(catalogPanel.includes("UiPackageSurface"), false);
  assert.equal(catalogPanel.includes("beforePanel="), false, "Catalog buttons must not mount click feedback above the panel.");
  assert.equal(catalogPanel.includes("showNotice"), false, "Catalog buttons must not use central click feedback notices.");
  assert.equal(readText("packages/ui/src/catalog/catalog-types.ts").includes("UiCatalogNotice"), false, "Catalog notice state must not remain as hidden internal state.");
  for (const source of [
    readText("packages/ui/src/catalog/UiCatalogAsync.tsx"),
    readText("packages/ui/src/catalog/UiCatalogModals.tsx"),
    readText("packages/ui/src/catalog/UiCatalogNavigation.tsx"),
  ]) {
    assert.equal(source.includes("showNotice"), false, "Catalog section buttons must not trigger notice feedback on click.");
  }
  assert.equal(classicModalSource.includes("ui.action.cancel"), false);
  assert.equal(optionsModalSource.includes("ui.action.cancel"), false);
  assert.equal(catalogModals.includes("ui.modals.list.empty"), false);

  for (const localeFile of ["de-DE", "en-US", "es-ES", "fr-FR", "it-IT"].map((locale) => `packages/ui/src/i18n/locales/${locale}.ts`)) {
    const localeSource = readText(localeFile);
    assert.equal(localeSource.includes("ui.mobile."), false);
    assert.equal(localeSource.includes("ui.section.mobile"), false);
    assert.equal(localeSource.includes("ui.tabs.mobile"), false);
    assert.equal(localeSource.includes("ui.hidden."), false);
    assert.equal(localeSource.includes("ui.guide.hidden."), false);
    assert.equal(localeSource.includes("ui.section.hidden"), false);
    assert.equal(localeSource.includes("ui.tabs.hidden"), false);
    assert(localeSource.includes("ui.guide.overview.import"));
  }
});
