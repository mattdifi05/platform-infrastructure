import test from "node:test";
import assert from "node:assert/strict";
import {
  activatePrincipalBinding,
  assertManagedDatabaseName,
  assertPrincipalCleanupAllowed,
  assertPrincipalCreateAllowed,
  assertPrincipalDeletionAllowed,
  assertPrincipalRotationAllowed,
  buildPrincipalMigrationPlan,
  createPrincipalBinding,
  DatabaseOwnershipError,
  generatedDatabasePrincipal,
  reservePrincipalBinding,
} from "../database/ownership.mjs";

const database = {
  id: "node-demo-postgres-node-demo-app",
  projectId: "node-demo",
  engine: "postgres",
  name: "node_demo_app",
};

test("database principals are deterministic, resource-scoped, and protected names are denied", () => {
  const principal = generatedDatabasePrincipal({ projectId: "node-demo", engine: "postgres", databaseName: "node_demo_app" });
  assert.match(principal, /^pi_p_node_demo_[a-f0-9]{12}$/);
  assert.equal(principal, generatedDatabasePrincipal({ projectId: "node-demo", engine: "postgres", databaseName: "node_demo_app" }));
  assert.notEqual(principal, generatedDatabasePrincipal({ projectId: "other-app", engine: "postgres", databaseName: "node_demo_app" }));
  assert.throws(() => assertManagedDatabaseName("postgres", "postgres"), DatabaseOwnershipError);
  assert.throws(() => assertManagedDatabaseName("mariadb", "mysql"), DatabaseOwnershipError);
});

test("new principal provisioning refuses existing and foreign resources without ALTER fallback", () => {
  const ownerRole = generatedDatabasePrincipal({ projectId: database.projectId, engine: database.engine, databaseName: database.name });
  const managedDatabase = { ...database, ownerRole };
  const registry = reservePrincipalBinding({}, managedDatabase);
  assert.equal(assertPrincipalCreateAllowed({
    database: managedDatabase,
    registry,
    catalog: { principal: { exists: false }, database: { exists: false } },
  }).principalName, ownerRole);
  assert.throws(() => assertPrincipalCreateAllowed({
    database: managedDatabase,
    registry,
    catalog: { principal: { exists: true }, database: { exists: false } },
  }), DatabaseOwnershipError);
  const foreignRegistry = {
    ...registry,
    [database.id]: { ...registry[database.id], projectId: "other-app" },
  };
  assert.throws(() => assertPrincipalCreateAllowed({
    database: managedDatabase,
    registry: foreignRegistry,
    catalog: { principal: { exists: false }, database: { exists: false } },
  }), DatabaseOwnershipError);
  assert.throws(() => createPrincipalBinding({ ...managedDatabase, ownerRole: "postgres" }), DatabaseOwnershipError);
});

test("credential rotation requires exact active ownership and a non-privileged catalog principal", () => {
  const ownerRole = generatedDatabasePrincipal({ projectId: database.projectId, engine: database.engine, databaseName: database.name });
  const managedDatabase = { ...database, ownerRole };
  const reserved = reservePrincipalBinding({}, managedDatabase);
  const active = activatePrincipalBinding(reserved, managedDatabase);
  const catalog = {
    principal: { exists: true, superuser: false, createRole: false, createDb: false, replication: false, bypassRls: false },
    database: { exists: true, owner: ownerRole },
  };
  assert.equal(assertPrincipalRotationAllowed({ database: managedDatabase, registry: active, catalog }).principalName, ownerRole);
  assert.equal(assertPrincipalDeletionAllowed({ database: managedDatabase, registry: active, catalog }).principalName, ownerRole);
  assert.equal(assertPrincipalCleanupAllowed({
    database: managedDatabase,
    registry: active,
    catalog: { ...catalog, database: { exists: false, owner: "" } },
  }).principalName, ownerRole);
  assert.throws(() => assertPrincipalRotationAllowed({
    database: managedDatabase,
    registry: active,
    catalog: { ...catalog, principal: { ...catalog.principal, superuser: true } },
  }), DatabaseOwnershipError);
  assert.throws(() => assertPrincipalRotationAllowed({
    database: managedDatabase,
    registry: active,
    catalog: { ...catalog, database: { exists: true, owner: "foreign_role" } },
  }), DatabaseOwnershipError);
  assert.throws(() => assertPrincipalRotationAllowed({ database: managedDatabase, registry: reserved, catalog }), DatabaseOwnershipError);
  assert.throws(() => assertPrincipalDeletionAllowed({
    database: managedDatabase,
    registry: active,
    catalog: { ...catalog, database: { exists: true, owner: "foreign_role" } },
  }), DatabaseOwnershipError);
  assert.throws(() => assertPrincipalCleanupAllowed({ database: managedDatabase, registry: active, catalog }), DatabaseOwnershipError);
  assert.throws(() => assertPrincipalCleanupAllowed({
    database: managedDatabase,
    registry: active,
    catalog: { ...catalog, principal: { ...catalog.principal, createRole: true }, database: { exists: false, owner: "" } },
  }), DatabaseOwnershipError);
});

test("legacy databases produce a non-mutating dual-credential migration plan", () => {
  const plan = buildPrincipalMigrationPlan({
    legacy: {
      id: "legacy",
      projectId: "node-demo",
      engine: "mariadb",
      name: "node_demo_legacy",
      ownerRole: "shared_user",
      status: "active",
    },
  });
  assert.equal(plan.length, 1);
  assert.equal(plan[0].status, "migration-required");
  assert.equal(plan[0].mutationExecuted, false);
  assert.match(plan[0].targetPrincipal, /^pi_m_node_demo_/);
  assert.equal(plan[0].steps.length, 5);
});
