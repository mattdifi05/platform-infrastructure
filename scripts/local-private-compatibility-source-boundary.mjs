export function assertCoreProjectGenericSources({ compose, controlCenterServer, projectRouterServer, forbiddenTokens = [] }) {
  if ([compose, controlCenterServer, projectRouterServer].some((source) => typeof source !== "string")) {
    throw new Error("Core project-generic policy requires three text sources.");
  }
  if (!Array.isArray(forbiddenTokens)
      || forbiddenTokens.some((token) => typeof token !== "string" || token.length < 4)) {
    throw new Error("Core project-generic policy requires explicit source-boundary tokens.");
  }
  const coreSources = `${compose}\n${controlCenterServer}\n${projectRouterServer}`;
  for (const token of forbiddenTokens) {
    if (coreSources.toLowerCase().includes(token.toLowerCase())) {
      throw new Error("Core infrastructure includes an app-specific source or route token.");
    }
  }
  if (/compose\.local-private-applications(?:-build)?\.yaml|v1-local-private-source-lock\.json/i.test(compose)) {
    throw new Error("Generic Compose defaults must not seed application overlays or private source locks.");
  }
  if (/localPrivateCompatibilityContract|routeOwnership\s*=/.test(projectRouterServer)
      || !/loadProjectRouterHostExtension/.test(projectRouterServer)) {
    throw new Error("Project router must use the external host-profile boundary.");
  }
  return true;
}
