import assert from "node:assert/strict";
import test from "node:test";
import { createControlCenterAuth, readAuthConfig, AuthConfigurationError } from "../auth/app-passkey.mjs";
import { nativeAssociationDocument, nativeSessionBootstrap } from "../auth/native-client.mjs";
import { listNativeRouteDefinitions, resolveAuthorizationCapability } from "../auth/route-capabilities.mjs";

const env = {
  NODE_ENV: "test", CONTROL_CENTER_BIND_HOST: "127.0.0.1", CONTROL_CENTER_AUTH_MODE: "app-passkey",
  CONTROL_CENTER_AUTH_STORE: "memory", CONTROL_CENTER_PUBLIC_ORIGIN: "https://portal.example.com",
  CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS: "172.16.0.0/12",
};

test("Apple association contains only explicitly configured application identities", () => {
  assert.deepEqual(nativeAssociationDocument(readAuthConfig(env)), { webcredentials: { apps: [] } });
  const config = readAuthConfig({ ...env, CONTROL_CENTER_APPLE_ASSOCIATED_APP_IDS: "ABCDE12345.com.example.control, ABCDE12345.com.example.control" });
  assert.deepEqual(nativeAssociationDocument(config), { webcredentials: { apps: ["ABCDE12345.com.example.control"] } });
  for (const value of ["*.com.example.control", "ABCDE12345.*", "com.example.control", "ABCDE12345.com.example/control", "ABCDE12345.com.example.control\nATTACK"]) {
    assert.throws(() => readAuthConfig({ ...env, CONTROL_CENTER_APPLE_ASSOCIATED_APP_IDS: value }), AuthConfigurationError);
  }
});

test("native bootstrap exposes verified session CSRF and role/freshness decisions without session secrets", async () => {
  const auth = await createControlCenterAuth({ env });
  try {
    const result = await auth.createSessionResult();
    const req = { method: "GET", socket: { remoteAddress: "127.0.0.1" }, headers: { host: "portal.example.com", cookie: result.cookies.map(item => item.split(";", 1)[0]).join("; ") } };
    const session = await auth.authenticate(req);
    const bootstrap = nativeSessionBootstrap(auth, session);
    assert.equal(bootstrap.schemaVersion, 1);
    assert.equal(bootstrap.session.role, "owner");
    assert.ok(bootstrap.csrfToken.length > 20);
    assert.equal(JSON.stringify(bootstrap).includes(session.sessionTokenHash), false);
    assert.equal(JSON.stringify(bootstrap).includes(session.identity.csrfHash), false);
    assert.equal(bootstrap.capabilities.find(item => item.operationId === "native.database").allowed, true);
    const stale = nativeSessionBootstrap(auth, { ...session, identity: { ...session.identity, authTime: new Date(Date.now() - 1_000_000) } });
    assert.equal(stale.capabilities.find(item => item.operationId === "native.database").requiresFreshAuthentication, true);
    assert.equal(stale.capabilities.find(item => item.operationId === "projects.list").allowed, true);
    req.headers.cookie = req.headers.cookie.replace(/(__Host-platform_cc_csrf=)[^;]+/, "$1tampered");
    assert.equal(nativeSessionBootstrap(auth, await auth.authenticate(req)).csrfToken, "");
  } finally { await auth.close(); }
});

test("native routes retain explicit capabilities and exclude the dashboard and application file manager", () => {
  assert.equal(resolveAuthorizationCapability("GET", "/api/native/v1/bootstrap").operationId, "native.bootstrap");
  assert.equal(resolveAuthorizationCapability("POST", "/api/native/v1/database-delete-command").capability, "owner:fresh");
  assert.equal(resolveAuthorizationCapability("POST", "/api/native/v1/redis-backup-command").capability, "admin");
  for (const path of ["/api/native/v1/missing", "/api/native/v1/bootstrap/", "/api/native/v1//bootstrap"]) {
    assert.equal(resolveAuthorizationCapability("GET", path).capability, "deny");
  }
  const routes = listNativeRouteDefinitions();
  assert.equal(routes.some(item => item.operationId.startsWith("ui.")), false);
  assert.equal(routes.some(item => item.operationId === "projects.files.read"), false);
});
