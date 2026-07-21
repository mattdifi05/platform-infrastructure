import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  assertExactAdminApplications,
  buildAdminAccessEvidence,
  evaluateAdminAccessEvidence,
  loadAdminAccessInventory,
  reconcileAdminRouteInventory,
  sha256Canonical,
  validateAdminAccessInventory,
} from "./admin-access-inventory.mjs";

const root = path.resolve(import.meta.dirname, "..");
const inventoryPath = path.join(root, "governance", "admin-access-surfaces.json");
const rawInventory = JSON.parse(readFileSync(inventoryPath, "utf8"));
const inventoryRecord = loadAdminAccessInventory(inventoryPath);
const manifest = JSON.parse(readFileSync(path.join(root, "cloudflare", "access-admin.example.json"), "utf8"));
const adminRoutes = readFileSync(path.join(root, "traefik", "dynamic", "admin-routes.yml"), "utf8");
const verifierSource = readFileSync(path.join(root, "scripts", "cloudflare-access-admin.mjs"), "utf8");
const goNoGoSource = readFileSync(path.join(root, "scripts", "infra-ops.mjs"), "utf8");

function clone(value) {
  return structuredClone(value);
}

function recordFor(raw) {
  return { inventory: validateAdminAccessInventory(raw), sha256: sha256Canonical(raw) };
}

function exactManifestContract(applications = manifest.applications, binding = manifest.adminSurfaceInventory) {
  return assertExactAdminApplications(applications, inventoryRecord, {
    domainSuffix: manifest.domainSuffix,
    binding,
  });
}

function exactPayload() {
  const inventoryContract = exactManifestContract();
  const routeReconciliation = reconcileAdminRouteInventory(inventoryRecord, adminRoutes);
  const applications = manifest.applications.map((app, index) => ({
    ...app,
    result: "access-shape-verified",
    applicationId: `app-${index}`,
    policyId: `policy-${index}`,
  }));
  return {
    generatedAt: "2026-07-21T12:00:00.000Z",
    mode: "verifyRemote",
    status: "passed",
    manifest: {
      domainSuffix: manifest.domainSuffix,
      adminSurfaceInventory: inventoryContract.inventory,
    },
    applications,
    adminSurfaceCoverage: buildAdminAccessEvidence({
      inventoryContract,
      routeReconciliation,
      applications,
      mode: "verifyRemote",
    }),
  };
}

test("a versioned authoritative admin surface inventory exists independently of the manifest", () => {
  assert.equal(existsSync(inventoryPath), true);
  assert.match(inventoryRecord.inventory.version, /^\d{4}-\d{2}-\d{2}\.\d+$/);
  assert.match(inventoryRecord.sha256, /^[a-f0-9]{64}$/);
});

test("the example manifest exactly binds all inventory applications including phpPgAdmin", () => {
  const contract = exactManifestContract();
  assert.equal(contract.manifestComplete, true);
  assert.equal(contract.expectedCount, rawInventory.applications.length);
  assert.equal(contract.expectedDomains.includes("phppgadmin.platform-infrastructure.com"), true);
  assert.deepEqual(manifest.adminSurfaceInventory, {
    id: inventoryRecord.inventory.inventoryId,
    version: inventoryRecord.inventory.version,
    sha256: inventoryRecord.sha256,
  });
});

test("the manifest domain suffix must equal the authoritative route suffix", () => {
  const mismatchedSuffix = "other.example";
  const applications = rawInventory.applications.map((entry) => ({
    name: entry.name,
    domain: `${entry.subdomain}.${mismatchedSuffix}`,
  }));
  assert.throws(() => assertExactAdminApplications(applications, inventoryRecord, {
    domainSuffix: mismatchedSuffix,
    binding: manifest.adminSurfaceInventory,
  }), /domainSuffix must match the authoritative inventory routeDomainSuffix/);
});

test("omitting first, middle, last, or phpPgAdmin application fails exact validation", () => {
  const indexes = new Set([0, Math.floor(manifest.applications.length / 2), manifest.applications.length - 1]);
  indexes.add(manifest.applications.findIndex((app) => app.name === "Platform phpPgAdmin"));
  for (const index of indexes) {
    const applications = manifest.applications.filter((_, candidate) => candidate !== index);
    assert.throws(() => exactManifestContract(applications), /Admin Access set mismatch/);
  }
});

test("empty, single, duplicate-name, duplicate-domain, case-variant, and unknown sets fail", () => {
  assert.throws(() => exactManifestContract([]), /Admin Access set mismatch/);
  assert.throws(() => exactManifestContract([manifest.applications[0]]), /Admin Access set mismatch/);

  const duplicateName = clone(manifest.applications);
  duplicateName[1].name = duplicateName[0].name;
  assert.throws(() => exactManifestContract(duplicateName), /duplicateNames=platform grafana/);

  const duplicateDomain = clone(manifest.applications);
  duplicateDomain[1].domain = duplicateDomain[0].domain;
  assert.throws(() => exactManifestContract(duplicateDomain), /duplicateDomains=grafana\.platform-infrastructure\.com/);

  const caseVariant = [...clone(manifest.applications), {
    name: "Case variant duplicate",
    domain: manifest.applications[0].domain.toUpperCase(),
  }];
  assert.throws(() => exactManifestContract(caseVariant), /duplicateDomains=grafana\.platform-infrastructure\.com/);

  const unknown = clone(manifest.applications);
  unknown[0] = { name: "Unknown admin", domain: "unknown.example.com" };
  assert.throws(() => exactManifestContract(unknown), /unknown=unknown\.example\.com/);
});

test("stale or mismatched inventory bindings fail before provider verification", () => {
  for (const binding of [
    { ...manifest.adminSurfaceInventory, id: "attacker-inventory" },
    { ...manifest.adminSurfaceInventory, version: "stale" },
    { ...manifest.adminSurfaceInventory, sha256: "0".repeat(64) },
  ]) {
    assert.throws(() => exactManifestContract(manifest.applications, binding), /binding is stale or mismatched/);
  }
});

test("real verifyRemote entrypoint rejects an incomplete manifest before credentials or provider calls", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "admin-access-inventory-"));
  try {
    const incomplete = clone(manifest);
    incomplete.accountId = "a".repeat(32);
    incomplete.allowedIdentityProviderIds = ["provider-id"];
    incomplete.mfaAssurancePolicy.expectedLoginMethodId = "provider-id";
    incomplete.allowedEmails = ["admin@real.invalid"];
    incomplete.applications = incomplete.applications.filter((app) => app.name !== "Platform phpPgAdmin");
    const manifestPath = path.join(directory, "incomplete.json");
    writeFileSync(manifestPath, `${JSON.stringify(incomplete)}\n`, { mode: 0o600 });
    const result = spawnSync(process.execPath, [
      path.join(root, "scripts", "cloudflare-access-admin.mjs"),
      "--manifest",
      manifestPath,
      "--verifyRemote",
    ], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, CLOUDFLARE_API_TOKEN: "", CLOUDFLARE_ACCOUNT_ID: "" },
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Admin Access set mismatch/);
    assert.doesNotMatch(result.stderr, /CLOUDFLARE_API_TOKEN|Cloudflare GET|fetch/i);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("database admin route inventory exactly covers both shared portal paths", () => {
  const result = reconcileAdminRouteInventory(inventoryRecord, adminRoutes);
  assert.equal(result.complete, true);
  assert.equal(result.expectedCount, 2);
  assert.match(result.expectedRoutes.join("\n"), /portal\.platform-infrastructure\.com\|\/phpmyadmin/);
  assert.match(result.expectedRoutes.join("\n"), /portal\.platform-infrastructure\.com\|\/phppgadmin/);
  assert.doesNotMatch(adminRoutes, /Host\(`(?:phpmyadmin|phppgadmin)\.platform-infrastructure\.com`\)/);
});

test("an added route or an inventory route absent from Traefik fails reconciliation", () => {
  const addedRoute = adminRoutes.replace("  middlewares:", [
    "    enterprise-phppgadmin-unknown-path:",
    "      rule: Host(`portal.platform-infrastructure.com`) && PathPrefix(`/pg-unknown`)",
    "      service: enterprise-phppgadmin",
    "",
    "  middlewares:",
  ].join("\n"));
  assert.throws(() => reconcileAdminRouteInventory(inventoryRecord, addedRoute), /unknown=.*pg-unknown/);

  const expanded = clone(rawInventory);
  expanded.routes.push({
    id: "database-phppgadmin-second-path",
    sourceFile: "traefik/dynamic/admin-routes.yml",
    router: "enterprise-phppgadmin-second-path",
    host: "portal.platform-infrastructure.com",
    pathPrefix: "/phppgadmin-second",
    service: "enterprise-phppgadmin",
    accessApplicationId: "portal-control-center",
  });
  assert.throws(() => reconcileAdminRouteInventory(recordFor(expanded), adminRoutes), /missing=.*phppgadmin-second/);
});

test("a router through a backend alias cannot disappear from exact surface reconciliation", () => {
  const aliased = adminRoutes
    .replace("\n  middlewares:\n", [
      "",
      "    enterprise-phpmyadmin-alias-path:",
      "      rule: Host(`portal.platform-infrastructure.com`) && PathPrefix(`/hidden-phpmyadmin`)",
      "      service: database-admin-backend-alias",
      "",
      "  middlewares:",
      "",
    ].join("\n"))
    .replace("\n  services:\n", [
      "",
      "  services:",
      "    database-admin-backend-alias:",
      "      loadBalancer:",
      "        servers:",
      "          - url: http://phpmyadmin:80",
      "",
    ].join("\n"));
  assert.throws(
    () => reconcileAdminRouteInventory(inventoryRecord, aliased),
    /unknown=.*enterprise-phpmyadmin-alias-path.*database-admin-backend-alias/,
  );

  const dottedAlias = adminRoutes.replace("  routers:\n", [
    "  routers:",
    "    enterprise.phpmyadmin.alias:",
    "      rule: Host(`portal.platform-infrastructure.com`) && PathPrefix(`/hidden-phpmyadmin-dotted`)",
    "      service: enterprise-phpmyadmin",
  ].join("\n") + "\n");
  assert.throws(
    () => reconcileAdminRouteInventory(inventoryRecord, dottedAlias),
    /unknown=.*enterprise\.phpmyadmin\.alias/,
  );
});

test("phpPgAdmin absence and duplicate inventory identities fail authoritative inventory validation", () => {
  const absent = clone(rawInventory);
  absent.applications = absent.applications.filter((entry) => entry.id !== "phppgadmin");
  assert.throws(() => validateAdminAccessInventory(absent), /must include phpPgAdmin/);

  const duplicate = clone(rawInventory);
  duplicate.applications.push(clone(duplicate.applications[0]));
  assert.throws(() => validateAdminAccessInventory(duplicate), /contains duplicates/);
});

test("exact and reordered evidence passes the production inventory evaluator", () => {
  const payload = exactPayload();
  assert.deepEqual(evaluateAdminAccessEvidence(payload, inventoryRecord), {
    ok: true,
    reason: "exact inventory-bound Access evidence",
  });
  payload.applications.reverse();
  assert.equal(evaluateAdminAccessEvidence(payload, inventoryRecord).ok, true);
});

test("missing, extra, duplicate, failed, or digest-mismatched evidence fails closed", () => {
  const mutations = [
    (payload) => payload.applications.pop(),
    (payload) => payload.applications.push({ name: "Unknown", domain: "unknown.example.com", result: "access-shape-verified" }),
    (payload) => payload.applications.push(clone(payload.applications[0])),
    (payload) => { payload.applications[0].result = "failed"; },
    (payload) => { payload.adminSurfaceCoverage.inventory.sha256 = "0".repeat(64); },
    (payload) => { payload.adminSurfaceCoverage.complete = false; },
    (payload) => { payload.adminSurfaceCoverage.verifiedDomains.pop(); },
    (payload) => { payload.adminSurfaceCoverage.routeCoverage.discoveredRoutes.pop(); },
  ];
  for (const mutate of mutations) {
    const payload = exactPayload();
    mutate(payload);
    assert.equal(evaluateAdminAccessEvidence(payload, inventoryRecord).ok, false);
  }
});

test("verifier and go-no-go consumer require the shared exact inventory contract", () => {
  assert.match(verifierSource, /assertExactAdminApplications/);
  assert.match(verifierSource, /reconcileAdminRouteInventory/);
  assert.match(goNoGoSource, /evaluateAdminAccessEvidence/);
  assert.doesNotMatch(goNoGoSource, /cloudflareApps\.length > 0\s*&&\s*cloudflareApps\.every/);
});
