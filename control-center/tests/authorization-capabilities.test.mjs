import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createControlCenterAuth } from "../auth/app-passkey.mjs";
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
  ["POST", "/actions/vault-command"],
  ["POST", "/actions/database-command"],
  ["POST", "/actions/database-delete-command"],
  ["POST", "/actions/database-admin-login"],
  ["GET", "/actions/phpmyadmin-login"],
  ["GET", "/actions/phppgadmin-login"],
  ["POST", "/actions/backup-command"],
  ["POST", "/actions/backup-delete-command"],
  ["POST", "/actions/redis-restore-command"],
  ["POST", "/actions/redis-backup-delete-command"],
  ["POST", "/actions/identity-command"],
  ["POST", "/actions/settings-command"],
]);

test("the explicit Control catalog resolves canonical aliases and rejects every confusable projection", () => {
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

  for (const definition of definitions) {
    const canonical = definition.template.replaceAll(/:[A-Za-z][A-Za-z0-9]*/g, "fixture-id");
    for (const catalogPath of [canonical, versioned(canonical)]) {
      for (const pathname of controlPathConfusables(catalogPath)) {
        const resolved = resolveAuthorizationCapability(definition.method, pathname);
        assert.equal(resolved.classified, false, `${definition.method} ${pathname}`);
        assert.equal(resolved.operationId, "control.denied", `${definition.method} ${pathname}`);
        assert.equal(resolved.capability, "deny", `${definition.method} ${pathname}`);
        assert.equal(resolved.control, true, `${definition.method} ${pathname}`);
        assert.notEqual(resolved.canonicalPath, canonical, `${pathname} must not normalize to ${canonical}`);
      }
    }
  }

  for (const [rawPathname, parsedPathname] of [
    ["/control\\vault", "/control/vault"],
    ["/control/../vault", "/vault"],
    ["/control/%2e%2e/vault", "/vault"],
    ["//control/vault", "/vault"],
  ]) {
    const resolved = resolveAuthorizationCapability("GET", parsedPathname, { rawPathname });
    assert.equal(resolved.classified, false, rawPathname);
    assert.equal(resolved.operationId, "control.denied", rawPathname);
    assert.equal(resolved.capability, "deny", rawPathname);
    assert.equal(resolved.control, true, rawPathname);
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
  const auth = await createControlCenterAuth({ env: appPasskeyEnv() });
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
  const auth = await createControlCenterAuth({ env: appPasskeyEnv() });
  t.after(() => auth.close());
  for (const pathname of ["/control/vault"]) {
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
  const auth = await createControlCenterAuth({ env: appPasskeyEnv() });
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
  const auth = await createControlCenterAuth({ env: appPasskeyEnv() });
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
  const auth = await createControlCenterAuth({ env: appPasskeyEnv() });
  t.after(() => auth.close());

  assert.equal(authorize(auth, "GET", "/control/projects", session("viewer")).status, 200);
  assert.equal(authorize(auth, "POST", "/control/projects", session("viewer")).status, 403);
  assert.equal(authorize(auth, "POST", "/control/projects", session("admin")).status, 200);
  assert.equal(authorize(auth, "GET", "/control/projects", session("unknown")).status, 403);
});

test("the HTML shell lasts for the session while legacy sensitive actions require a fresh owner", async (t) => {
  const auth = await createControlCenterAuth({ env: appPasskeyEnv() });
  t.after(() => auth.close());

  for (const pathname of ["/", "/index.html"]) {
    assert.equal(authorize(auth, "GET", pathname, session("viewer")).status, 200);
    assert.equal(authorize(auth, "GET", pathname, session("admin")).status, 200);
    assert.equal(authorize(auth, "GET", pathname, session("owner", 301)).status, 200);
  }

  for (const [method, pathname] of LEGACY_SENSITIVE_ROUTES) {
    assert.equal(authorize(auth, method, pathname, session("viewer")).status, 403);
    assert.equal(authorize(auth, method, pathname, session("admin")).status, 403);
    assert.equal(authorize(auth, method, pathname, session("owner", 301)).status, 428);
    assert.equal(authorize(auth, method, pathname, session("owner")).status, 200);
  }

  assert.equal(authorize(auth, "POST", "/actions/redis-backup-command", session("viewer")).status, 403);
  assert.equal(authorize(auth, "POST", "/actions/redis-backup-command", session("admin")).status, 200);
  assert.equal(authorize(auth, "POST", "/actions/redis-backup-command", session("owner", 301)).status, 200);
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

function controlPathConfusables(pathname) {
  const suffix = pathname.slice("/control".length);
  const withoutLeadingSlash = suffix.replace(/^\//, "");
  const segmentCharacterIndex = pathname.slice("/control/".length).search(/[A-Za-z0-9]/);
  const absoluteCharacterIndex = segmentCharacterIndex < 0
    ? -1
    : "/control/".length + segmentCharacterIndex;
  const encodedSegment = absoluteCharacterIndex < 0
    ? `${pathname}%41`
    : `${pathname.slice(0, absoluteCharacterIndex)}%${pathname.charCodeAt(absoluteCharacterIndex).toString(16).padStart(2, "0")}${pathname.slice(absoluteCharacterIndex + 1)}`;
  const doubleEncodedSegment = encodedSegment.replace("%", "%25");
  const encodedParameter = pathname.includes("fixture-id")
    ? pathname.replace("fixture-id", "fixture%2did")
    : encodedSegment;
  return new Set([
    `/CONTROL${suffix}`,
    `/Control${suffix}`,
    `/c%6fntrol${suffix}`,
    `/c%256fntrol${suffix}`,
    `/c%25256fntrol${suffix}`,
    `/c%2525256fntrol${suffix}`,
    `/c%${"25".repeat(31)}6fntrol${suffix}`,
    `/c%25256fntrol/%FF${suffix}`,
    `/c%2525256fntrol/%ZZ${suffix}`,
    `/control%2F${withoutLeadingSlash}`,
    `/control%252F${withoutLeadingSlash}`,
    `/control%5C${withoutLeadingSlash}`,
    `/control%255C${withoutLeadingSlash}`,
    `/control\\${withoutLeadingSlash}`,
    `/%2Fcontrol${suffix}`,
    `/%252Fcontrol${suffix}`,
    encodedSegment,
    doubleEncodedSegment,
    encodedParameter,
  ]);
}

function url(pathname) {
  return new URL(`https://portal.example.test${pathname}`);
}

function appPasskeyEnv() {
  return {
    NODE_ENV: "test",
    CONTROL_CENTER_ENV: "test",
    CONTROL_CENTER_BIND_HOST: "127.0.0.1",
    CONTROL_CENTER_AUTH_MODE: "app-passkey",
    CONTROL_CENTER_AUTH_STORE: "memory",
    CONTROL_CENTER_PUBLIC_ORIGIN: "https://portal.example.test",
    CONTROL_CENTER_AUTH_RP_ID: "portal.example.test",
    CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS: "127.0.0.0/8",
  };
}
