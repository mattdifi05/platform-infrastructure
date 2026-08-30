export const controlCenterComponents = [
  "OperationsShell",
  "OperationsTopbar",
  "ProjectTable",
  "ProjectActions",
  "ProjectFileBrowser",
  "DatabaseInventory",
  "ResourceUsageTable",
  "MetricTile",
  "ActionButton",
  "ProjectSwitcher",
  "EmptyState",
];

export const controlCenterCssEntrypoints = [
  "/assets/control-center/control-center.css",
];

export const controlCenterScriptEntrypoints = [
  "/assets/control-center/control-center.js",
];

// Keep the default version in sync with the current UI contract so browsers
// revalidate the stylesheet/script after a Control Center image update. Hosts
// may still override it explicitly through CONTROL_CENTER_ASSET_VERSION.
const controlCenterAssetVersion = process.env.CONTROL_CENTER_ASSET_VERSION || "20260830-preload-coordinator-1";

function versionedAssetHref(href) {
  return `${href}${href.includes("?") ? "&" : "?"}v=${encodeURIComponent(controlCenterAssetVersion)}`;
}

export function controlCenterStylesheetLinks() {
  return controlCenterCssEntrypoints.map((href) => `<link rel="stylesheet" href="${versionedAssetHref(href)}">`).join("\n");
}

export function controlCenterScriptTags() {
  return controlCenterScriptEntrypoints.map((src) => `<script defer src="${versionedAssetHref(src)}"></script>`).join("\n");
}

export function controlCenterUiContract(controlCenterPackage = {}) {
  return {
    name: "@platform/control-center-local-ui",
    version: controlCenterPackage.version || "0.1.0",
    source: "control-center/components + control-center/styles",
    mountedRoot: "/app",
    controlCenterProject: controlCenterPackage.name || "@platform/control-center",
    controlCenterPackageLoaded: controlCenterPackage.name === "@platform/control-center",
    declaredDependency: "none",
    dependencyTarget: "local-control-center-files",
    packageMountedInControlCenterProject: true,
    usingVendoredPackage: false,
    packageJsonLoaded: true,
    apiManifestLoaded: true,
    runtimeFramework: "node-rendered-html-with-local-control-center-ui",
    hostInstallRequired: false,
    entrypoints: [...controlCenterCssEntrypoints, ...controlCenterScriptEntrypoints],
    cssEntrypoints: controlCenterCssEntrypoints,
    scriptEntrypoints: controlCenterScriptEntrypoints,
    servedAssets: [...controlCenterCssEntrypoints, ...controlCenterScriptEntrypoints],
    coreExports: controlCenterComponents,
    requiredComponents: controlCenterComponents,
    missingRequiredExports: [],
    cssVariablePrefix: "--cc-",
    visualRules: [
      "local Control Center visual system",
      "light-only theme",
      "solid color surfaces",
      "dynamic navigation without full page reloads",
      "operations-first information architecture",
      "project actions, file inventory, database inventory and backups",
      "rounded-md surfaces capped at 8px for operational controls",
      "subtle borders and surface contrast instead of decorative effects",
      "accessible focus rings through box-shadow",
    ],
  };
}
