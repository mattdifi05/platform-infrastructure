export const UI_CATALOG_SECTION_COOKIE = "stexor-ui-catalog-section";
export const UI_CATALOG_SECTION_QUERY_KEY = "section";

export const uiCatalogSectionIds = ["overview", "inputs", "actions", "navigation", "blocks", "feedback", "async", "modals"] as const;

export type UiSectionId = (typeof uiCatalogSectionIds)[number];

const uiCatalogSectionSet = new Set<string>(uiCatalogSectionIds);

export function isUiCatalogSectionId(value: string): value is UiSectionId {
  return uiCatalogSectionSet.has(value);
}

export function normalizeUiCatalogSection(value: string | null | undefined, fallback: UiSectionId = "overview"): UiSectionId {
  const section = decodeUiCatalogSection(value);
  return isUiCatalogSectionId(section) ? section : fallback;
}

export function decodeUiCatalogSection(value: string | null | undefined) {
  if (!value) return "";
  try {
    return decodeURIComponent(value.replace(/^#\/?/, "").trim());
  } catch {
    return "";
  }
}
