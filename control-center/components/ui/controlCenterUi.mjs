import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

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
  "/assets/control-center/server-ai.css",
];

export const controlCenterScriptEntrypoints = [
  "/assets/control-center/control-center.js",
  "/assets/control-center/server-ai.js",
];

// Derive each cache token from the exact asset bytes. A stale environment
// variable or forgotten manual version bump must never keep old AI controls
// in the browser after a container update.
const assetVersionByHref = new Map([
  ["/assets/control-center/control-center.css", "../../styles/control-center.css"],
  ["/assets/control-center/server-ai.css", "../../styles/server-ai.css"],
  ["/assets/control-center/control-center.js", "../../styles/control-center.js"],
  ["/assets/control-center/server-ai.js", "../../styles/server-ai.js"],
].map(([href, relativePath]) => [
  href,
  createHash("sha256").update(readFileSync(new URL(relativePath, import.meta.url))).digest("hex").slice(0, 20),
]));

function versionedAssetHref(href) {
  const version = assetVersionByHref.get(href);
  if (!version) throw new Error("Unknown Control Center UI asset.");
  return `${href}${href.includes("?") ? "&" : "?"}v=${version}`;
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
