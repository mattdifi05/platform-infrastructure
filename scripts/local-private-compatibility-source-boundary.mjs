const compatibilityDeclaration = "const localPrivateCompatibilityContract = Object.freeze({";
const compatibilityTerminator = "\n});\nconst localPrivateRouteOwnership = new Map(";
const forbiddenProjectToken = /stexor|fireport|matthewdifilippo/i;

function uniqueIndex(source, marker, label) {
  const index = source.indexOf(marker);
  if (index === -1 || source.indexOf(marker, index + marker.length) !== -1) {
    throw new Error(`Project router must contain exactly one ${label}.`);
  }
  return index;
}

export function isolateLocalPrivateCompatibilityContract(projectRouterServer) {
  if (typeof projectRouterServer !== "string") throw new Error("Project router source must be text.");
  const start = uniqueIndex(projectRouterServer, compatibilityDeclaration, "exact LOCAL_PRIVATE compatibility declaration");
  const terminator = uniqueIndex(projectRouterServer, compatibilityTerminator, "exact LOCAL_PRIVATE compatibility terminator");
  if (terminator <= start) throw new Error("LOCAL_PRIVATE compatibility source boundary is reversed or overlapping.");
  const end = terminator + "\n});".length;
  return {
    compatibilityContractSource: projectRouterServer.slice(start, end),
    projectRouterOutsideCompatibilityContract: `${projectRouterServer.slice(0, start)}${projectRouterServer.slice(end)}`,
  };
}

export function assertCoreProjectGenericSources({ compose, controlCenterServer, projectRouterServer }) {
  if ([compose, controlCenterServer, projectRouterServer].some((source) => typeof source !== "string")) {
    throw new Error("Core project-generic policy requires three text sources.");
  }
  if (forbiddenProjectToken.test(`${compose}\n${controlCenterServer}`)) {
    throw new Error("Core infrastructure must stay project-generic outside the exact LOCAL_PRIVATE compatibility contract.");
  }
  const isolated = isolateLocalPrivateCompatibilityContract(projectRouterServer);
  if (forbiddenProjectToken.test(isolated.projectRouterOutsideCompatibilityContract)) {
    throw new Error("Core infrastructure must stay project-generic outside the exact LOCAL_PRIVATE compatibility contract.");
  }
  return isolated;
}
