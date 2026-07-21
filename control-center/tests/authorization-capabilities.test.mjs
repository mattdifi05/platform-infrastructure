import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createControlCenterAuth } from "../auth/oidc.mjs";
import {
  listControlRouteDefinitions,
  normalizeControlApiParts,
  resolveAuthorizationCapability,
} from "../auth/route-capabilities.mjs";

const SENSITIVE_MUTATIONS = Object.freeze([
  { id: "CAN-016", method: "POST", path: "/control/vault/secrets/example/reveal", operationId: "vault.secret.reveal" },
  { id: "CAN-017", method: "POST", path: "/control/vault/secrets", operationId: "vault.secret.store" },
  { id: "CAN-018", method: "POST", path: "/control/vault/import-existing", operationId: "vault.import-existing" },
  { id: "CAN-019", method: "POST", path: "/control/vault/secrets/example/delete", operationId: "vault.secret.delete" },
  { id: "CAN-020", method: "POST", path: "/control/databases", operationId: "database.create" },
  { id: "CAN-021", method: "POST", path: "/control/backups/files/delete", operationId: "backup.file.delete" },
  { id: "CAN-022", method: "POST", path: "/control/backups/run", operationId: "backup.run" },
  { id: "CAN-023", method: "POST", path: "/control/databases/example/backup", operationId: "database.backup" },
]);

const SENSITIVE_READS = Object.freeze([
  { id: "CAN-148-overview-projection", method: "GET", path: "/control/overview", operationId: "overview.read" },
  { id: "CAN-148-advanced-projection", method: "GET", path: "/control/advanced/backup-restore", operationId: "advanced.section.read" },
  { id: "CAN-148-summary", method: "GET", path: "/control/backups/summary", operationId: "backup.summary.read" },
  { id: "CAN-148-records", method: "GET", path: "/control/backups/records", operationId: "backup.records.read" },
  { id: "CAN-148-jobs", method: "GET", path: "/control/backups/jobs", operationId: "backup.jobs.read" },
  { id: "CAN-148-files", method: "GET", path: "/control/backups/files", operationId: "backup.files.list" },
  { id: "CAN-148-preview", method: "GET", path: "/control/backups/preview", operationId: "backup.file.preview" },
  { id: "CAN-208", method: "GET", path: "/control/vault", operationId: "vault.inventory.read" },
]);

const LEGACY_SENSITIVE_ROUTES = Object.freeze([
  ["GET", "/"],
  ["GET", "/index.html"],
  ["POST", "/actions/vault-command"],
  ["POST", "/actions/database-command"],
  ["POST", "/actions/database-admin-login"],
  ["GET", "/actions/phpmyadmin-login"],
  ["GET", "/actions/phppgadmin-login"],
  ["POST", "/actions/backup-command"],
  ["POST", "/actions/identity-command"],
  ["POST", "/actions/settings-command"],
]);

test("the explicit Control catalog is unique and resolves every canonical and v1 template", () => {
  const definitions = listControlRouteDefinitions();
  assert.ok(definitions.length > 80, "the complete dispatcher surface must remain cataloged");
  assert.equal(new Set(definitions.map(({ method, template }) => `${method} ${template}`)).size, definitions.length);
  assert.equal(new Set(definitions.map(({ operationId }) => operationId)).size, definitions.length);

  for (const definition of definitions) {
    const pathname = definition.template.replaceAll(/:[A-Za-z][A-Za-z0-9]*/g, "fixture-id");
    for (const alias of [pathname, versioned(pathname)]) {
      const resolved = resolveAuthorizationCapability(definition.method, alias);
      assert.equal(Object.isFrozen(resolved), true, `${definition.method} ${alias} immutable operation`);
      assert.equal(resolved.classified, true, `${definition.method} ${alias}`);
      assert.equal(resolved.operationId, definition.operationId, `${definition.method} ${alias}`);
      assert.equal(resolved.capability, definition.capability, `${definition.method} ${alias}`);
      assert.equal(resolved.control, true, `${definition.method} ${alias}`);
    }
  }
});

test("the explicit catalog remains cardinality-bound to every dispatcher branch", () => {
  const definitions = listControlRouteDefinitions();
  const source = readFileSync(new URL("../server.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function handleApi(");
  const end = source.indexOf("async function handleToggleProject(", start);
  assert.ok(start >= 0 && end > start, "Control API dispatcher source must be discoverable");
  const dispatcher = source.slice(start, end);

  for (const method of ["GET", "POST"]) {
    const branchCount = [...dispatcher.matchAll(new RegExp(`if \\(method === "${method}"`, "g"))].length;
    assert.equal(
      definitions.filter((definition) => definition.method === method).length,
      branchCount,
      `${method} dispatcher branches and catalog entries must change together`,
    );
  }

  const operationIds = new Set(definitions.map(({ operationId }) => operationId));
  for (const [, operationId] of dispatcher.matchAll(/case "([^"]+)":/g)) {
    assert.equal(operationIds.has(operationId), true, `direct dispatcher operation ${operationId} must be cataloged`);
  }
});

test("FG-004 and FG-043 routes require a fresh owner for canonical and v1 aliases", async (t) => {
  const auth = await createControlCenterAuth({ env: completeOidcEnv() });
  t.after(() => auth.close());

  const principals = [
    { label: "viewer", session: session("viewer"), status: 403 },
    { label: "admin", session: session("admin"), status: 403 },
    { label: "stale-owner", session: session("owner", 301), status: 428 },
    { label: "fresh-owner", session: session("owner", 0), status: 200 },
  ];

  for (const target of [...SENSITIVE_MUTATIONS, ...SENSITIVE_READS]) {
    for (const pathname of [target.path, versioned(target.path)]) {
      const resolved = resolveAuthorizationCapability(target.method, pathname);
      assert.equal(resolved.operationId, target.operationId, `${target.id} ${pathname}`);
      assert.equal(resolved.capability, "owner:fresh", `${target.id} ${pathname}`);
      for (const principal of principals) {
        const request = { method: target.method, controlCenterOperation: resolved };
        const result = auth.authorize(request, url(pathname), principal.session);
        assert.equal(result.status, principal.status, `${target.id} ${pathname} ${principal.label}`);
        if (principal.status === 428) {
          assert.equal(result.error, "admin_reauthentication_required");
          assert.equal(result.reauthUrl, "/auth/login");
        }
      }
    }
  }
});

test("fresh-owner authorization accepts 299 and 300 seconds but rejects 301 seconds", async (t) => {
  const now = new Date("2030-01-01T00:00:00.000Z");
  t.mock.timers.enable({ apis: ["Date"], now });
  const auth = await createControlCenterAuth({ env: completeOidcEnv() });
  t.after(() => auth.close());
  for (const pathname of ["/control/vault", "/", "/index.html"]) {
    const target = url(pathname);
    const request = {
      method: "GET",
      controlCenterOperation: resolveAuthorizationCapability("GET", target.pathname),
    };

    assert.equal(auth.authorize(request, target, session("owner", 299, now)).status, 200, pathname);
    assert.equal(auth.authorize(request, target, session("owner", 300, now)).status, 200, pathname);
    assert.equal(auth.authorize(request, target, session("owner", 301, now)).status, 428, pathname);
    assert.equal(auth.authorize(request, target, session("owner", -0.001, now)).status, 428, `${pathname} future auth_time`);
  }
});

test("fresh-owner authorization fails closed for missing, malformed, and future auth_time", async (t) => {
  const auth = await createControlCenterAuth({ env: completeOidcEnv() });
  t.after(() => auth.close());
  const target = url("/control/vault");
  const request = {
    method: "GET",
    controlCenterOperation: resolveAuthorizationCapability("GET", target.pathname),
  };

  for (const authTime of [undefined, "not-a-date", new Date(Date.now() + 60_000)]) {
    const result = auth.authorize(request, target, {
      ok: true,
      status: 200,
      role: "owner",
      identity: { authTime },
    });
    assert.equal(result.status, 428, `auth_time=${String(authTime)}`);
  }
});

test("unknown Control routes and non-GET HTML shell methods fail closed", async (t) => {
  const auth = await createControlCenterAuth({ env: completeOidcEnv() });
  t.after(() => auth.close());
  const cases = [
    ["GET", "/control/not-cataloged"],
    ["POST", "/control/not-cataloged"],
    ["GET", "/control/v10/vault"],
    ["POST", "/control/v1/vault"],
    ["GET", "/control/v1/backups/files/extra"],
    ["GET", "/control/v1/backups/file"],
    ["POST", "/control/v1/vault/secrets/example/revealed"],
    ["POST", "/control/v1/vault/secrets/example/reveal/extra"],
    ["GET", "/control//vault"],
    ["GET", "/control/vault/"],
    ["HEAD", "/control/vault"],
    ["OPTIONS", "/control/backups/files"],
    ["HEAD", "/"],
    ["OPTIONS", "/index.html"],
    ["POST", "/"],
    ["PUT", "/index.html"],
  ];

  for (const [method, pathname] of cases) {
    const resolved = resolveAuthorizationCapability(method, pathname);
    assert.equal(resolved.classified, false, `${method} ${pathname}`);
    assert.equal(resolved.capability, "deny", `${method} ${pathname}`);
    const result = auth.authorize(
      { method, controlCenterOperation: resolved },
      url(pathname),
      session("owner"),
    );
    assert.equal(result.status, 403, `${method} ${pathname}`);
    assert.equal(result.error, "endpoint_capability_denied", `${method} ${pathname}`);
  }
});

test("ordinary cataloged reads and mutations preserve documented role behavior", async (t) => {
  const auth = await createControlCenterAuth({ env: completeOidcEnv() });
  t.after(() => auth.close());

  assert.equal(authorize(auth, "GET", "/control/projects", session("viewer")).status, 200);
  assert.equal(authorize(auth, "POST", "/control/projects", session("viewer")).status, 403);
  assert.equal(authorize(auth, "POST", "/control/projects", session("admin")).status, 200);
  assert.equal(authorize(auth, "GET", "/control/projects", session("unknown")).status, 403);
});

test("the HTML shell and legacy sensitive actions retain the same owner and freshness boundary", async (t) => {
  const auth = await createControlCenterAuth({ env: completeOidcEnv() });
  t.after(() => auth.close());

  for (const [method, pathname] of LEGACY_SENSITIVE_ROUTES) {
    assert.equal(authorize(auth, method, pathname, session("viewer")).status, 403);
    assert.equal(authorize(auth, method, pathname, session("admin")).status, 403);
    assert.equal(authorize(auth, method, pathname, session("owner", 301)).status, 428);
    assert.equal(authorize(auth, method, pathname, session("owner")).status, 200);
  }
});

test("the shared normalizer removes only the exact v1 API segment", () => {
  assert.deepEqual(normalizeControlApiParts(["control", "v1", "vault"]), ["control", "vault"]);
  assert.deepEqual(normalizeControlApiParts(["control", "v10", "vault"]), ["control", "v10", "vault"]);
  const dynamic = resolveAuthorizationCapability("POST", "/control/v1/databases/example/backup");
  assert.deepEqual(dynamic.parameters, { databaseId: "example" });
});

function authorize(auth, method, pathname, principal) {
  const target = url(pathname);
  const operation = resolveAuthorizationCapability(method, target.pathname);
  return auth.authorize({ method, controlCenterOperation: operation }, target, principal);
}

function session(role, ageSeconds = 0, now = new Date()) {
  return {
    ok: true,
    status: 200,
    role,
    identity: { authTime: new Date(now.getTime() - ageSeconds * 1000) },
  };
}

function versioned(pathname) {
  return pathname.replace(/^\/control(?=\/|$)/, "/control/v1");
}

function url(pathname) {
  return new URL(`https://portal.example.test${pathname}`);
}

function completeOidcEnv() {
  return {
    NODE_ENV: "test",
    CONTROL_CENTER_ENV: "test",
    CONTROL_CENTER_BIND_HOST: "127.0.0.1",
    CONTROL_CENTER_AUTH_MODE: "oidc-passkey",
    CONTROL_CENTER_AUTH_STORE: "memory",
    CONTROL_CENTER_OIDC_ISSUER: "https://identity.example.test/realms/platform",
    CONTROL_CENTER_OIDC_AUTHORIZATION_ENDPOINT: "https://identity.example.test/realms/platform/protocol/openid-connect/auth",
    CONTROL_CENTER_OIDC_TOKEN_ENDPOINT: "http://127.0.0.1/token",
    CONTROL_CENTER_OIDC_JWKS_URI: "http://127.0.0.1/jwks",
    CONTROL_CENTER_OIDC_REDIRECT_URI: "https://portal.example.test/auth/callback",
    CONTROL_CENTER_OIDC_CLIENT_ID: "platform-control-center",
    CONTROL_CENTER_OIDC_REQUIRED_ACR: "urn:platform:loa:passkey",
  };
}
