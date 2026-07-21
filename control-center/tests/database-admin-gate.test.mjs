import assert from "node:assert/strict";
import test from "node:test";
import { authorizeDatabaseAdminForwardTarget } from "../auth/database-admin-gate.mjs";

test("database admin target gate accepts only exact portal paths and bounded methods", () => {
  const expectedHost = "portal.example.test";
  for (const [method, uri] of [
    ["GET", "/phpmyadmin/"],
    ["POST", "/phpmyadmin/index.php?route=%2Fsql"],
    ["GET", "/phpmyadmin/themes/%E2%9C%93.css?route=%2Fsql"],
    ["HEAD", "/phppgadmin/redirect.php?subject=server"],
  ]) {
    assert.equal(authorizeDatabaseAdminForwardTarget(headers(expectedHost, method, uri), { expectedHost }).status, 204);
  }
});

test("database admin target gate rejects missing, dedicated-host, ambiguous, and unrelated targets", () => {
  const expectedHost = "portal.example.test";
  for (const candidate of [
    {},
    headers("phpmyadmin.example.test", "GET", "/phpmyadmin/"),
    headers(expectedHost, "DELETE", "/phpmyadmin/"),
    headers(expectedHost, "GET", "/control/overview"),
    headers(expectedHost, "GET", "/phpmyadmin/../control"),
    headers(expectedHost, "GET", "/%2e%2e/phpmyadmin"),
    { ...headers(expectedHost, "GET", "/phpmyadmin/"), "x-forwarded-host": "portal.example.test,attacker.test" },
  ]) {
    assert.equal(authorizeDatabaseAdminForwardTarget(candidate, { expectedHost }).status, 403);
  }
});

test("database admin target gate rejects encoded control, separator, delimiter, and dot-segment variants", () => {
  const expectedHost = "portal.example.test";
  for (const uri of [
    "/phpmyadmin/%00index.php",
    "/phpmyadmin/%250aindex.php",
    "/phpmyadmin/%2fcontrol",
    "/phpmyadmin/%252fcontrol",
    "/phpmyadmin/%5c..%5ccontrol",
    "/phpmyadmin/%3fcontrol",
    "/phpmyadmin/%23control",
    "/phpmyadmin/%3bcontrol",
    "/phpmyadmin/%2e/index.php",
    "/phpmyadmin/%252e%252e%252fcontrol",
    "/phppgadmin/%2E%2E/%2fcontrol",
  ]) {
    const result = authorizeDatabaseAdminForwardTarget(headers(expectedHost, "GET", uri), { expectedHost });
    assert.equal(result.status, 403, uri);
  }
});

test("database admin target gate ignores spoofed identity assertions", () => {
  const result = authorizeDatabaseAdminForwardTarget({
    ...headers("portal.example.test", "GET", "/phppgadmin/"),
    "x-platform-role": "owner",
    "x-platform-subject": "spoofed",
    "x-platform-auth-time": new Date().toISOString(),
  }, { expectedHost: "portal.example.test" });
  assert.deepEqual(result, { ok: true, status: 204, method: "GET", host: "portal.example.test", path: "/phppgadmin/" });
});

function headers(host, method, uri) {
  return {
    "x-forwarded-host": host,
    "x-forwarded-method": method,
    "x-forwarded-uri": uri,
  };
}
