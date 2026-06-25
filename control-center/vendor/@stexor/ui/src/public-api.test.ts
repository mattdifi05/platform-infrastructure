import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import test from "node:test";

const workspaceRoot = new URL("../../../", import.meta.url);
const stexorUiPublicExports = [".", "./catalog", "./client", "./i18n", "./icons", "./next", "./styles.css", "./ui.css"] as const;
const stexorUiInternalModules = ["./src/ActionConfig.ts", "./src/classNames.ts", "./src/cssom.ts", "./src/styleMotion.ts"] as const;

function readText(relativePath: string): string {
  return readFileSync(new URL(relativePath, workspaceRoot), "utf8").replace(/\r\n/g, "\n");
}

function exists(relativePath: string): boolean {
  return existsSync(new URL(relativePath, workspaceRoot));
}

function walk(relativePath: string): string[] {
  const directory = new URL(relativePath, workspaceRoot);
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const childPath = `${relativePath}/${entry.name}`;
    return entry.isDirectory() ? walk(childPath) : childPath;
  });
}

function joinToken(...parts: string[]): string {
  return parts.join("");
}

test("package exports match the documented public API", () => {
  const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { exports: Record<string, string> };

  assert.deepEqual(Object.keys(manifest.exports).sort(), [...stexorUiPublicExports].sort());
});

test("internal implementation modules stay out of public exports", () => {
  const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { exports: Record<string, string> };
  const exportedTargets = new Set(Object.values(manifest.exports));

  for (const internalModule of stexorUiInternalModules) {
    assert.equal(exportedTargets.has(internalModule), false);
  }
});

test("package declares a distributable build for external apps", () => {
  const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
    files?: string[];
    main?: string;
    private?: boolean;
    publishConfig?: { access?: string };
    scripts?: Record<string, string>;
    types?: string;
  };

  assert.equal(manifest.private, false);
  assert.equal(manifest.main, "./dist/index.js");
  assert.equal(manifest.types, "./dist/index.d.ts");
  assert.equal(manifest.publishConfig?.access, "restricted");
  assert.equal(manifest.scripts?.build, "node scripts/build.mjs");
  assert(manifest.files?.includes("dist"));
  assert.equal(exists("packages/ui/tsconfig.build.json"), true);
  assert.equal(exists("packages/ui/scripts/build.mjs"), true);
});

test("dist package build script keeps CSS entrypoints publishable", () => {
  const buildScript = readText("packages/ui/scripts/build.mjs");

  assert(buildScript.includes("copyCss"));
  assert(buildScript.includes("createDistManifest"));
  assert(buildScript.includes("distExportForTarget"));
  assert(buildScript.includes("check-catalog-coverage.mjs"));
});

test("README documents the Stexor UI design system contract", () => {
  const readme = readText("packages/ui/README.md");

  for (const requiredText of [
    "## Design System Contract",
    "The catalog is the source of truth",
    "every public visual primitive must be visible in an official catalog section",
    "Non-catalog audit sections must not exist in the catalog",
    "App screens compose `@stexor/ui` primitives and shared styles",
    "`UiShell` owns the standard frame",
    "Actions use `Button` directly for catalog buttons",
    "Surface context is automatic",
    "Icons come from the official UI icon set",
    "Motion must be smooth, interruptible and layout-stable",
    "Package CSS must not use `!important`",
    "## Enterprise Primitives",
    "`createUiAsyncMachine` owns async state",
    "`createUiFieldValidationState`, `uiFieldA11yProps`",
    "`Button asChild` uses internal Slot composition",
    "`SelectList` owns the large-list virtualized path",
    "## Dark Mode",
    "## Accessibility",
    "## State Matrix",
    "## Release And Versioning",
    "Semver policy",
  ]) {
    assert(readme.includes(requiredText), `README must document: ${requiredText}`);
  }
});

test("style entrypoints expose only the shared UI demo layer", () => {
  const coreStyles = readText("packages/ui/src/styles.css");
  const uiStyles = readText("packages/ui/src/ui.css");

  assert.equal(coreStyles.includes(joinToken("account", "-surfaces")), false);
  assert.equal(coreStyles.includes(joinToken("responsive-02-", "account", "-layout")), false);
  assert.equal(coreStyles.includes("ui-03-monochrome-surfaces"), false);
  assert(uiStyles.includes("ui-04-app.css"));
  assert.equal(exists(joinToken("packages/ui/src/", "account", ".css")), false);
});

test("package styles do not rely on important overrides", () => {
  const importantToken = "!" + "important";

  for (const file of walk("packages/ui/src").filter((candidate) => candidate.endsWith(".css"))) {
    assert.equal(readText(file).includes(importantToken), false, `${file} must not use important overrides.`);
  }
});

test("UI catalog is served from the package, not from app-local component copies", () => {
  const uiPage = readText("apps/web/src/app/ui/page.tsx");

  assert(uiPage.includes('import("@stexor/ui/catalog")'));
  assert.equal(exists("apps/web/src/components/UiApp.tsx"), false);
  assert.equal(exists("apps/web/src/components/ui-app"), false);
  assert.equal(exists("apps/web/src/app/catalog"), false);
});

test("package exports only components used by real UI surfaces", () => {
  const coreEntrypoint = readText("packages/ui/src/core.ts");
  const rootEntrypoint = readText("packages/ui/src/index.ts");
  const clientEntrypoint = readText("packages/ui/src/client.ts");
  const expectedCoreEntrypoint = [
    'export { Badge, StatusBadge, type BadgeTone } from "./Badge";',
    'export { ActionFlow, type ActionFlowButton, type ActionFlowProps } from "./ActionFlow";',
    'export { Button, type ButtonProps, type ButtonVariant } from "./Button";',
    'export { CommandPalette, type CommandPaletteCommand, type CommandPaletteProps } from "./CommandPalette";',
    'export { CustomScrollbar, type CustomScrollbarProps } from "./CustomScrollbar";',
    'export { CalendarPickerPanel, DateInputField } from "./DatePicker";',
    'export { CheckboxField, FieldGroup, RadioField, RangeField, SearchInput, SelectField, SwitchField, TextareaField, TextField, type IconTone } from "./Form";',
    'export { FactGrid, type FactItem } from "./FactGrid";',
    'export { ChoiceCard } from "./ChoiceCard";',
    'export { DEFAULT_UI_ACCENT, DEFAULT_UI_THEME, readStoredUiTheme, writeStoredUiAccent, writeStoredUiTheme, type UiTheme } from "./catalog/catalog-theme";',
    'export { createUiAsyncMachine, UiAsyncMachine, type UiAsyncSnapshot, type UiAsyncStatus } from "./AsyncState";',
    'export { AvatarCropper, AvatarFilterStepper, getAvatarVisualFilterItems, renderAvatarImage, type AvatarCrop, type AvatarVisualFilter, type AvatarVisualFilterItem } from "./AvatarCropper";',
    'export { ChoiceModalHeader, ModalFooter } from "./ModalHeader";',
    'export { createUiFieldValidationState, uiFieldA11yProps, type UiFieldStatus, type UiFieldValidationState, type UiValidationIssue, type UiValidationSeverity } from "./FormValidation";',
    'export { PillSidebarNav, type PillNavItem } from "./PillSidebarNav";',
    'export { PillTabs, type PillTabItem } from "./PillTabs";',
    'export { SelectList, type SelectOption } from "./Select";',
    'export { EmptyState, InlineAlert, Spinner } from "./States";',
    'export { SectionCard, SectionHeader, StatusPill, UiFactGrid, UiFeedbackEmpty, UiMetricGrid, UiPanelFrame, UiSectionCard, UiSectionStack, type UiTone } from "./Surface";',
    'export { Modal } from "./Modal";',
    'export { uiMotionDurations } from "./motion-tokens";',
    'export { useDynamicCssProperties } from "./styleMotion";',
    'export { ThemeWaveOverlay, useThemeWave, type ThemeWave } from "./theme-wave";',
    'export { uiOverlayStack, type UiOverlayEntry, type UiOverlayLifecycleEvent, type UiOverlayType } from "./OverlayManager";',
    'export { Dropdown, Popover, type DropdownProps, type PopoverProps, type UiOverlayFrameProps, type UiOverlayMotion, type UiOverlayPlacement, type UiOverlayRenderProps } from "./OverlayPatterns";',
    'export { UiPopupProvider, useUiPopup, type UiPopupController, type UiPopupDuration, type UiPopupOptions, type UiPopupTone } from "./Popup";',
    'export { UiShell, type UiBrand, type UiShellProps } from "./UiShell";',
    'export * from "./icons";',
    'export { countryOptions, I18nProvider, languageOptions, normalizeLocale, useI18n, type SupportedLocale, type TranslationKey } from "./i18n";',
  ].join("\n");

  assert.equal(coreEntrypoint.trim(), expectedCoreEntrypoint);
  assert.equal(rootEntrypoint.trim(), 'export * from "./core";');
  assert.equal(clientEntrypoint.trim(), '"use client";\n\nexport * from "./core";');
});

test("source root keeps only the shared UI implementation modules", () => {
  const files = readdirSync(new URL("packages/ui/src", workspaceRoot), { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .sort();

  assert.deepEqual(files, [
    "ActionConfig.ts",
    "ActionFlow.tsx",
    "ActionGovernance.test.ts",
    "AsyncState.ts",
    "AvatarCropper.tsx",
    "Badge.tsx",
    "BrandLogo.tsx",
    "Button.tsx",
    "ChoiceCard.tsx",
    "ColorGovernance.test.ts",
    "CommandPalette.tsx",
    "CommandPaletteModel.ts",
    "CssPresence.tsx",
    "CustomScrollbar.tsx",
    "DatePicker.tsx",
    "FactGrid.tsx",
    "Form.tsx",
    "FormValidation.ts",
    "Modal.tsx",
    "ModalHeader.tsx",
    "NamingGovernance.test.ts",
    "NoRuntimeAdapters.test.ts",
    "OverlayManager.ts",
    "OverlayPatterns.tsx",
    "PillSidebarNav.tsx",
    "PillTabs.tsx",
    "Popup.tsx",
    "Select.tsx",
    "Slot.tsx",
    "States.tsx",
    "StyleHygiene.test.ts",
    "Surface.tsx",
    "SurfaceContract.test.ts",
    "UiShell.tsx",
    "VirtualList.tsx",
    "catalog-boundary.test.ts",
    "catalog-contract.test.ts",
    "catalog-surface-contract.test.ts",
    "catalog.ts",
    "classNames.ts",
    "client.ts",
    "core.ts",
    "cssom.ts",
    "date.ts",
    "enterprise-primitives.test.ts",
    "enterprise-runtime-surface.test.ts",
    "icons.tsx",
    "index.ts",
    "motion-tokens.ts",
    "next.tsx",
    "package-boundary-contract.test.ts",
    "public-api.test.ts",
    "styleClasses.ts",
    "styleMotion.ts",
    "styles.css",
    "theme-wave.tsx",
    "theme.test.ts",
    "ui.css",
    "useResolvedSurface.ts",
  ]);
});
