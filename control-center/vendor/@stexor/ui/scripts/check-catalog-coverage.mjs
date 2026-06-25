#!/usr/bin/env node
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { unusedCssClasses } from "./css-class-coverage.mjs";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = path.resolve(packageRoot, "..", "..");

const officialCatalogFiles = [
  "packages/ui/src/catalog/UiCatalogActions.tsx",
  "packages/ui/src/catalog/UiCatalogActionBuilder.tsx",
  "packages/ui/src/catalog/UiCatalogApp.tsx",
  "packages/ui/src/catalog/UiCatalogAsync.tsx",
  "packages/ui/src/catalog/UiCatalogBlocks.tsx",
  "packages/ui/src/catalog/UiCatalogFeedback.tsx",
  "packages/ui/src/catalog/UiCatalogModals.tsx",
  "packages/ui/src/catalog/UiCatalogNavigation.tsx",
  "packages/ui/src/catalog/UiCatalogPanel.tsx",
  "packages/ui/src/catalog/catalog-data.tsx",
];

const nonVisualCoreExports = new Set([
  "CssPresence",
  "DEFAULT_UI_ACCENT",
  "DEFAULT_UI_THEME",
  "I18nProvider",
  "Slot",
  "UiAsyncMachine",
  "createUiAsyncMachine",
  "createUiFieldValidationState",
  "countryOptions",
  "getAvatarVisualFilterItems",
  "languageOptions",
  "normalizeLocale",
  "readStoredUiTheme",
  "renderAvatarImage",
  "uiFieldA11yProps",
  "uiMotionDurations",
  "uiOverlayStack",
  "useDynamicCssProperties",
  "useI18n",
  "useThemeWave",
  "useUiPopup",
  "writeStoredUiAccent",
  "writeStoredUiTheme",
]);
const visualCoverageAlternates = new Map([
  ["EmptyState", ["UiFeedbackEmpty", "SelectList"]],
  ["FactGrid", ["UiFactGrid"]],
  ["Metric", ["UiMetricGrid"]],
  ["SectionCard", ["UiSectionCard"]],
  ["UiSectionStack", ["UiSectionCard"]],
  ["VirtualList", ["SelectList"]],
]);
const joinToken = (...parts) => parts.join("");
const jsxToken = (...parts) => `<${joinToken(...parts)}`;
const officialCatalogSource = officialCatalogFiles.map(readWorkspaceText).join("\n");
const packageSource = walkWorkspaceFiles("packages/ui/src")
  .filter((file) => /\.(?:css|ts|tsx)$/.test(file))
  .filter((file) => !/\.test\.(?:ts|tsx)$/.test(file))
  .map(readWorkspaceText)
  .join("\n");

try {
  for (const component of publicVisualCoreExports()) {
    assert(
      isVisibleInOfficialCatalog(component),
      `${component} must be visible in an official UI catalog section.`,
    );
  }

  for (const forbiddenToken of [
    jsxToken("Feedback", "Page"),
    jsxToken("To", "ast"),
    jsxToken("App", "Shell"),
    jsxToken("Header", "Bar"),
    jsxToken("Side", "bar"),
    jsxToken("Main", "Surface"),
    joinToken("options=", "{", "[]", "}"),
    joinToken("choice-modal-", "search-", "bar"),
    "is-step-1-of-3",
    "is-step-3-of-3",
    joinToken("ui-modal-", "sum", "mary"),
    joinToken("ui-modal-", "wiz", "ard"),
    joinToken("ui-", "wiz", "ard"),
    joinToken("Account", "Loading"),
    joinToken("account.", "loading"),
    joinToken("ui-", "notice"),
    joinToken('className = "', "form", "-grid", '"'),
    joinToken("\n.", "form", "-grid"),
    joinToken('className = "', "modal", "-footer", '"'),
    joinToken("\n.", "modal", "-footer"),
    joinToken("ui-section-", "card"),
    joinToken("ui-fact-", "grid"),
    joinToken("ui-", "empty"),
    joinToken("ui-", "muted"),
    joinToken("ui-action-", "panel"),
    joinToken("ui-action-", "copy"),
    joinToken("ui-action-", "row"),
    joinToken("ui-icon-", "row"),
    joinToken("ui-gray-action-", "grid"),
    joinToken("ui-gray-button-", "stack"),
    joinToken("ui-gray-control-", "stack"),
    joinToken("ui-", "preview"),
    joinToken("ui-", "inline"),
    joinToken("ui-date-year-", "grid"),
    joinToken("ui-date-year-", "grid-wrap"),
    joinToken("modal-panel-", "lg"),
    joinToken("modal-panel-", "full"),
    joinToken("ui-modal-header-", "copy"),
    joinToken("ui-modal-", "controls"),
    joinToken("grecaptcha-", "badge"),
    joinToken("ui-shell-", "canvas"),
    "headerEnd",
    "headerStart",
    "afterHeader",
  ]) {
    assert.equal(
      packageSource.includes(forbiddenToken),
      false,
      `Forbidden package token must stay out of the package: ${forbiddenToken}`,
    );
  }

  assertNoUnshownVisualVariants();
  assertNoUnusedIconExports();
  assertNoOrphanSourceModules();
  assertNoUnusedInternalExports();
  assertNoUnmountedPublicCoreExports();
  assertNoUnusedCssClasses();
  assertAccountUsesOnlyCatalogVisuals();
} catch (error) {
  console.error("\n@stexor/ui catalog coverage failed.");
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}

function assertAccountUsesOnlyCatalogVisuals() {
  const accountFiles = walkWorkspaceFiles("apps/web/src/components/account-center")
    .filter((file) => /\.(?:ts|tsx)$/.test(file));
  const accountSource = accountFiles.map(readWorkspaceText).join("\n");
  const iconSource = readWorkspaceText("packages/ui/src/icons.tsx");
  const exportedIcons = Array.from(iconSource.matchAll(/export const (\w+)/g), (match) => match[1]);

  for (const token of ["<progress", "<code", "<ol", "<li"]) {
    assert.equal(
      accountSource.includes(token),
      false,
      `Account Center must use visible UI catalog primitives instead of direct visuals: ${token}`,
    );
  }

  for (const file of accountFiles) {
    for (const match of readWorkspaceText(file).matchAll(/from "(@stexor\/ui(?:\/[^"]+)?)"/g)) {
      assert.equal(
        match[1],
        "@stexor/ui/client",
        `Account Center UI import must be centralized through @stexor/ui/client: ${file} imports ${match[1]}`,
      );
    }
  }

  for (const iconName of exportedIcons) {
    if (!new RegExp(`\\b${iconName}\\b`).test(accountSource)) continue;
    if (officialCatalogSource.includes("uiIconRegistry")) continue;
    assert.match(
      officialCatalogSource,
      new RegExp(`\\b${iconName}\\b`),
      `Account Center icon is not visible in the official UI catalog: ${iconName}`,
    );
  }
}

function assertNoUnusedIconExports() {
  const iconSourcePath = "packages/ui/src/icons.tsx";
  const iconSource = readWorkspaceText(iconSourcePath);
  const exportedIcons = Array.from(iconSource.matchAll(/export const (\w+)/g), (match) => match[1]);
  const iconRegistrySource = iconSource.slice(iconSource.indexOf("export const uiIconRegistry"));
  const searchableSource = [
    ...walkWorkspaceFiles("packages/ui/src"),
    ...walkWorkspaceFiles("apps/web/src"),
  ]
    .filter((file) => /\.(?:ts|tsx)$/.test(file))
    .filter((file) => file !== iconSourcePath)
    .filter((file) => !/\.test\.(?:ts|tsx)$/.test(file))
    .map(readWorkspaceText)
    .join("\n");

  for (const iconName of exportedIcons) {
    if (new RegExp(`\\b${iconName}\\b`).test(iconRegistrySource)) continue;

    assert.match(
      searchableSource,
      new RegExp(`\\b${iconName}\\b`),
      `Exported icon is not used by the demo/account surfaces: ${iconName}`,
    );
  }
}

function assertNoOrphanSourceModules() {
  const sourceRoot = "packages/ui/src";
  const entrypoints = [
    "index.ts",
    "client.ts",
    "catalog.ts",
    "next.tsx",
    "i18n/index.tsx",
    "icons.tsx",
    "styles.css",
    "ui.css",
  ].map((file) => `${sourceRoot}/${file}`);
  const sourceFiles = walkWorkspaceFiles(sourceRoot)
    .filter((file) => /\.(?:css|ts|tsx)$/.test(file))
    .filter((file) => !/\.test\.(?:ts|tsx)$/.test(file));
  const reachable = new Set();
  const stack = entrypoints.filter((file) => sourceFiles.includes(file));

  while (stack.length > 0) {
    const file = stack.pop();
    if (!file || reachable.has(file)) continue;
    reachable.add(file);
    stack.push(...localImports(file));
  }

  const orphan = sourceFiles.filter((file) => !reachable.has(file)).sort();
  assert.deepEqual(orphan, [], `UI source modules must be reachable from package entrypoints: ${orphan.join(", ")}`);
}

function assertNoUnusedInternalExports() {
  const sourceFiles = walkWorkspaceFiles("packages/ui/src")
    .filter((file) => /\.(?:ts|tsx)$/.test(file))
    .filter((file) => !/\.test\.(?:ts|tsx)$/.test(file));
  const consumerSource = [
    ...sourceFiles,
    ...walkWorkspaceFiles("apps/web/src").filter((file) => /\.(?:ts|tsx)$/.test(file)),
  ];
  const publicSource = [
    "packages/ui/src/core.ts",
    "packages/ui/src/catalog.ts",
    "packages/ui/src/next.tsx",
    "packages/ui/src/i18n/index.tsx",
    "packages/ui/src/icons.tsx",
  ].filter(fsExists).map(readWorkspaceText).join("\n");
  const unusedExports = [];

  for (const file of sourceFiles) {
    const source = readWorkspaceText(file);
    for (const match of source.matchAll(/export\s+(?:const|function|class|type|interface)\s+([A-Za-z0-9_]+)/g)) {
      const name = match[1];
      if (new RegExp(`\\b${name}\\b`).test(publicSource)) continue;
      const usedOutsideFile = consumerSource.some((candidate) => {
        if (candidate === file) return false;
        return new RegExp(`\\b${name}\\b`).test(readWorkspaceText(candidate));
      });
      if (!usedOutsideFile) unusedExports.push(`${file}:${name}`);
    }
  }

  assert.deepEqual(unusedExports.sort(), [], `Internal UI exports must be public or consumed outside their defining file: ${unusedExports.join(", ")}`);
}

function assertNoUnmountedPublicCoreExports() {
  const corePath = "packages/ui/src/core.ts";
  const searchFiles = [
    ...walkWorkspaceFiles("packages/ui/src"),
    ...walkWorkspaceFiles("apps/web/src"),
  ]
    .filter((file) => /\.(?:ts|tsx)$/.test(file))
    .filter((file) => !/\.test\.(?:ts|tsx)$/.test(file))
    .filter((file) => !["packages/ui/src/core.ts", "packages/ui/src/index.ts", "packages/ui/src/client.ts"].includes(file));
  const unmounted = [];

  for (const match of readWorkspaceText(corePath).matchAll(/export \{([^}]+)\} from "([^"]+)"/g)) {
    const definingFile = resolveLocalImport(corePath, match[2]);
    for (const rawName of match[1].split(",")) {
      const name = rawName.trim();
      if (!name || name.startsWith("type ")) continue;
      const exportedName = name.split(/\s+as\s+/).at(-1)?.trim() ?? name;
      if (!/^[A-Za-z0-9_]+$/.test(exportedName)) continue;
      const usedOutsideDefinition = searchFiles.some((file) => file !== definingFile && new RegExp(`\\b${exportedName}\\b`).test(readWorkspaceText(file)));
      if (!usedOutsideDefinition) unmounted.push(exportedName);
    }
  }

  assert.deepEqual(unmounted.sort(), [], `Public core exports must be mounted by demo/app sources outside their defining file: ${unmounted.join(", ")}`);
}

function assertNoUnusedCssClasses() {
  const cssFiles = [
    ...walkWorkspaceFiles("packages/ui/src/styles"),
    ...walkWorkspaceFiles("packages/ui/src"),
  ].filter((file) => /\.css$/.test(file));
  const sourceText = [
    ...walkWorkspaceFiles("packages/ui/src"),
    ...walkWorkspaceFiles("apps/web/src"),
  ]
    .filter((file) => /\.(?:mjs|ts|tsx)$/.test(file))
    .map(readWorkspaceText)
    .join("\n");
  const unusedClasses = unusedCssClasses(cssFiles, readWorkspaceText, sourceText);
  assert.deepEqual(unusedClasses, [], `UI CSS classes must be mounted by demo/app sources or explicit dynamic generators: ${unusedClasses.join(", ")}`);
}

function localImports(relativePath) {
  const source = readWorkspaceText(relativePath);
  const imports = [];
  for (const pattern of [
    /(?:import|export)\s+(?:[^'"]*?\s+from\s+)?["']([^"']+)["']/g,
    /import\(\s*["']([^"']+)["']\s*\)/g,
    /@import\s+["']([^"']+)["']/g,
  ]) {
    for (const match of source.matchAll(pattern)) {
      const resolved = resolveLocalImport(relativePath, match[1]);
      if (resolved) imports.push(resolved);
    }
  }
  return imports;
}

function resolveLocalImport(from, specifier) {
  if (!specifier?.startsWith(".")) return null;
  const fromDirectory = path.dirname(from);
  const base = path.posix.normalize(path.posix.join(fromDirectory, specifier));
  const candidates = [
    base,
    `${base}.ts`,
    `${base}.tsx`,
    `${base}.css`,
    `${base}/index.ts`,
    `${base}/index.tsx`,
    `${base}/index.css`,
  ];
  return candidates.find((candidate) => fsExists(candidate)) ?? null;
}

function assertNoUnshownVisualVariants() {
  assertButtonVariantsAreCataloged();
  assertToneUnionsAreCataloged();
}

function isVisibleInOfficialCatalog(component) {
  if (new RegExp(`<${component}\\b`).test(officialCatalogSource)) return true;
  return (visualCoverageAlternates.get(component) ?? []).some((alternate) => new RegExp(`<${alternate}\\b`).test(officialCatalogSource));
}

function assertButtonVariantsAreCataloged() {
  const variants = stringUnionValues("packages/ui/src/Button.tsx", "ButtonVariant");

  for (const variant of variants) {
    const directlyShown = officialCatalogSource.includes(`variant="${variant}"`)
      || officialCatalogSource.includes(`variant: "${variant}"`)
      || officialCatalogSource.includes(`value: "${variant}"`);
    const shownThroughNavigation = variant === "plain" && officialCatalogSource.includes("<PillSidebarNav");

    assert(
      directlyShown || shownThroughNavigation,
      `Button variant is exported but not visible in official catalog sections: ${variant}`,
    );
  }
}

function assertToneUnionsAreCataloged() {
  assertVisibleValues("packages/ui/src/Badge.tsx", "BadgeTone", {
    neutral: ["<Badge>{", 'tone="neutral"', "tone: \"neutral\""],
  });
  assertVisibleValues("packages/ui/src/Surface.tsx", "UiTone", {});
  assertVisibleValues("packages/ui/src/Form.tsx", "IconTone", {});
  assertVisibleValues("packages/ui/src/AvatarCropper.tsx", "AvatarVisualFilter", {});
}

function assertVisibleValues(relativePath, typeName, alternates) {
  for (const value of stringUnionValues(relativePath, typeName)) {
    const candidates = [
      `"${value}"`,
      `'${value}'`,
      `is-${value}`,
      `tone="${value}"`,
      ...(alternates[value] ?? []),
    ];

    assert(
      candidates.some((candidate) => officialCatalogSource.includes(candidate)),
      `${typeName} value is exported but not visible in official catalog sections: ${value}`,
    );
  }
}

function stringUnionValues(relativePath, typeName) {
  const source = readWorkspaceText(relativePath);
  const match = source.match(new RegExp(`export type ${typeName} = ([^;]+);`));
  assert(match, `Missing string union type: ${typeName}`);
  return Array.from(match[1].matchAll(/"([^"]+)"/g), (valueMatch) => valueMatch[1]);
}

function publicVisualCoreExports() {
  const coreSource = readWorkspaceText("packages/ui/src/core.ts");
  const exportedValues = [];

  for (const match of coreSource.matchAll(/export \{([^}]+)\} from/g)) {
    for (const rawName of match[1].split(",")) {
      const name = rawName.trim();
      if (!name || name.startsWith("type ")) continue;
      if (nonVisualCoreExports.has(name)) continue;
      exportedValues.push(name);
    }
  }

  return exportedValues;
}

function readWorkspaceText(relativePath) {
  return readFileSync(path.join(workspaceRoot, relativePath), "utf8").replace(/\r\n/g, "\n");
}

function fsExists(relativePath) {
  const absolutePath = path.join(workspaceRoot, relativePath);
  return existsSync(absolutePath) && statSync(absolutePath).isFile();
}

function walkWorkspaceFiles(relativePath) {
  const directory = path.join(workspaceRoot, relativePath);
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const childPath = `${relativePath}/${entry.name}`;
    if (entry.isDirectory()) return walkWorkspaceFiles(childPath);
    return childPath;
  });
}
