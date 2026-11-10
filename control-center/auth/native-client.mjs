import { listNativeRouteDefinitions } from "./route-capabilities.mjs";

export function nativeAuthenticationMetadata(auth) {
  return {
    mode: auth.mode,
    origin: auth.config.publicOrigin || "",
    rpId: auth.config.rpId || "",
    freshAuthSeconds: auth.config.freshAuthSeconds || 0,
    associationConfigured: Boolean(auth.config.associatedAppIds?.length),
  };
}

export function nativeAssociationDocument(config) {
  return { webcredentials: { apps: [...(config.associatedAppIds || [])] } };
}

export function nativeSessionBootstrap(auth, session) {
  const identity = session.identity || {};
  return {
    schemaVersion: 1,
    authentication: nativeAuthenticationMetadata(auth),
    session: {
      subject: identity.subject,
      email: identity.email || "",
      displayName: identity.displayName || "",
      role: session.role,
      roles: identity.roles || [session.role],
      authTime: identity.authTime || null,
      expiresAt: identity.expiresAt || null,
    },
    csrfToken: identity.csrfToken || "",
    capabilities: listNativeRouteDefinitions().map((definition) => {
      const decision = auth.authorize({ method: definition.method, controlCenterOperation: definition }, new URL("/", auth.config.publicOrigin || "https://localhost"), session);
      return { ...definition, allowed: decision.ok, requiresFreshAuthentication: decision.status === 428 };
    }),
  };
}
