export const controlCenterComponents = [
  "AppShell",
  "Sidebar",
  "Topbar",
  "PageHeader",
  "Section",
  "Card",
  "MetricCard",
  "StatusPill",
  "ActionButton",
  "TabGroup",
  "DataList",
  "EmptyState",
  "AlertBanner",
  "EnvironmentBadge",
  "ProjectSwitcher",
  "SimpleAdvancedToggle",
];

export const controlCenterCssEntrypoints = [
  "/assets/control-center/control-center.css",
];

export const controlCenterScriptEntrypoints = [
  "/assets/control-center/control-center.js",
];

export function controlCenterStylesheetLinks() {
  return controlCenterCssEntrypoints.map((href) => `<link rel="stylesheet" href="${href}">`).join("\n");
}

export function controlCenterScriptTags() {
  return controlCenterScriptEntrypoints.map((src) => `<script defer src="${src}"></script>`).join("\n");
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
      "hosting-panel information architecture",
      "rounded-md to rounded-xl surfaces",
      "subtle borders and surface contrast instead of decorative effects",
      "accessible focus rings through box-shadow",
    ],
  };
}
