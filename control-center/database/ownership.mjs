import { createHash } from "node:crypto";

const IDENTIFIER_PATTERN = /^[a-z][a-z0-9_]{0,62}$/;
const PROTECTED_DATABASES = {
  mariadb: new Set(["information_schema", "mysql", "performance_schema", "sys"]),
  postgres: new Set(["postgres", "template0", "template1"]),
};
const PROTECTED_PRINCIPALS = new Set([
  "admin",
  "administrator",
  "mariadb.sys",
  "mysql",
  "mysql.session",
  "mysql.sys",
  "pma",
  "postgres",
  "root",
]);

export class DatabaseOwnershipError extends Error {}

export function generatedDatabasePrincipal({ projectId, engine, databaseName }) {
  const cleanProject = normalizedProjectId(projectId);
  const cleanEngine = normalizedEngine(engine);
  const cleanDatabase = normalizedIdentifier(databaseName, "database name");
  assertManagedDatabaseName(cleanEngine, cleanDatabase);
  const projectPart = cleanProject.replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 10) || "app";
  const digest = createHash("sha256")
    .update(`platform-database-principal:v1:${cleanEngine}:${cleanProject}:${cleanDatabase}`)
    .digest("hex")
    .slice(0, 12);
  return `pi_${cleanEngine === "postgres" ? "p" : "m"}_${projectPart}_${digest}`;
}

export function createPrincipalBinding(database, { status = "reserved", now = new Date().toISOString() } = {}) {
  const normalized = normalizedDatabase(database);
  const principalName = generatedDatabasePrincipal(normalized);
  if (normalized.ownerRole && normalized.ownerRole !== principalName) {
    throw new DatabaseOwnershipError("Database principal does not match the server-generated owner.");
  }
  return {
    id: normalized.id,
    databaseId: normalized.id,
    projectId: normalized.projectId,
    engine: normalized.engine,
    databaseName: normalized.databaseName,
    principalName,
    status: normalizedBindingStatus(status),
    ownershipVersion: 1,
    createdAt: now,
    updatedAt: now,
    activatedAt: status === "active" ? now : null,
  };
}

export function reservePrincipalBinding(registry, database, { now = new Date().toISOString() } = {}) {
  const bindings = normalizedBindings(registry);
  const candidate = createPrincipalBinding(database, { status: "reserved", now });
  const current = bindings[candidate.id];
  if (current) {
    assertBindingMatches(current, candidate);
    return { ...bindings, [candidate.id]: { ...current, updatedAt: now } };
  }
  for (const binding of Object.values(bindings)) {
    if (binding.principalName === candidate.principalName && binding.databaseId !== candidate.databaseId) {
      throw new DatabaseOwnershipError("Generated database principal is already bound to another resource.");
    }
  }
  return { ...bindings, [candidate.id]: candidate };
}

export function activatePrincipalBinding(registry, database, { now = new Date().toISOString() } = {}) {
  const bindings = normalizedBindings(registry);
  const expected = createPrincipalBinding(database, { status: "active", now });
  const current = bindings[expected.id];
  if (!current) throw new DatabaseOwnershipError("Database principal binding is missing.");
  assertBindingMatches(current, expected);
  return {
    ...bindings,
    [expected.id]: {
      ...current,
      status: "active",
      updatedAt: now,
      activatedAt: current.activatedAt || now,
    },
  };
}

export function assertPrincipalCreateAllowed({ database, registry, catalog }) {
  const expected = createPrincipalBinding(database);
  const binding = normalizedBindings(registry)[expected.id];
  if (!binding) throw new DatabaseOwnershipError("Database principal binding is missing.");
  assertBindingMatches(binding, expected);
  if (binding.status !== "reserved") throw new DatabaseOwnershipError("Database principal is not in the reserved provisioning state.");
  assertPrincipalIsManaged(expected.principalName, expected.engine);
  if (catalog?.principal?.exists) throw new DatabaseOwnershipError("Database principal already exists and will not be altered during provisioning.");
  if (catalog?.database?.exists) throw new DatabaseOwnershipError("Database already exists and is not owned by this new binding.");
  return expected;
}

export function assertPrincipalRotationAllowed({ database, registry, catalog }) {
  const expected = createPrincipalBinding(database, { status: "active" });
  const binding = normalizedBindings(registry)[expected.id];
  if (!binding) throw new DatabaseOwnershipError("Database principal binding is missing.");
  assertBindingMatches(binding, expected);
  if (binding.status !== "active") throw new DatabaseOwnershipError("Database principal binding is not active.");
  assertPrincipalIsManaged(expected.principalName, expected.engine);
  if (!catalog?.principal?.exists) throw new DatabaseOwnershipError("Bound database principal does not exist.");
  if (!catalog?.database?.exists) throw new DatabaseOwnershipError("Bound database does not exist.");
  if (String(catalog.database.owner || "") !== expected.principalName) {
    throw new DatabaseOwnershipError("Database ownership does not match the registered principal.");
  }
  const privilegeFlags = ["superuser", "createRole", "createDb", "replication", "bypassRls", "admin", "grantOption", "identityMismatch"];
  if (privilegeFlags.some((flag) => Boolean(catalog.principal[flag]))) {
    throw new DatabaseOwnershipError("Database principal has privileged capabilities and will not be altered.");
  }
  return expected;
}

export function principalBindingFor(registry, database) {
  const bindings = normalizedBindings(registry);
  const binding = bindings[String(database?.id || "")];
  if (!binding) return null;
  try {
    const expected = createPrincipalBinding(database, { status: binding.status || "reserved" });
    assertBindingMatches(binding, expected);
    return { ...binding };
  } catch {
    return null;
  }
}

export function buildPrincipalMigrationPlan(databases, registry = {}) {
  const bindings = normalizedBindings(registry);
  return Object.values(databases || {})
    .filter((database) => database && !database.deletedAt && database.status !== "deleted")
    .map((database) => {
      const normalized = normalizedDatabase(database);
      const targetPrincipal = generatedDatabasePrincipal(normalized);
      const binding = principalBindingFor(bindings, { ...database, ownerRole: targetPrincipal });
      const managed = Boolean(binding && binding.status === "active");
      return {
        databaseId: normalized.id,
        projectId: normalized.projectId,
        engine: normalized.engine,
        databaseName: normalized.databaseName,
        currentPrincipal: String(database.ownerRole || ""),
        targetPrincipal,
        status: managed ? "managed" : "migration-required",
        mutationExecuted: false,
        steps: managed ? [] : [
          "create generated principal with a new credential",
          "grant only the target database",
          "deploy the application with the new credential",
          "verify application and backup/restore behavior",
          "revoke the legacy principal only after separate approval",
        ],
      };
    })
    .sort((left, right) => left.databaseId.localeCompare(right.databaseId));
}

export function assertManagedDatabaseName(engine, databaseName) {
  const cleanEngine = normalizedEngine(engine);
  const cleanName = normalizedIdentifier(databaseName, "database name");
  if (PROTECTED_DATABASES[cleanEngine].has(cleanName)) {
    throw new DatabaseOwnershipError("Protected system database cannot be managed as an application database.");
  }
  return cleanName;
}

function normalizedDatabase(database) {
  const id = String(database?.id || "").trim();
  const projectId = normalizedProjectId(database?.projectId);
  const engine = normalizedEngine(database?.engine);
  const databaseName = assertManagedDatabaseName(engine, database?.name || database?.databaseName);
  if (!id) throw new DatabaseOwnershipError("Database id is required for principal ownership.");
  return {
    id,
    projectId,
    engine,
    databaseName,
    ownerRole: String(database?.ownerRole || "").trim().toLowerCase(),
  };
}

function normalizedBindings(registry) {
  const source = registry?.bindings && typeof registry.bindings === "object" ? registry.bindings : registry;
  return source && typeof source === "object" && !Array.isArray(source) ? source : {};
}

function assertBindingMatches(actual, expected) {
  for (const field of ["databaseId", "projectId", "engine", "databaseName", "principalName"]) {
    if (String(actual?.[field] || "") !== String(expected[field])) {
      throw new DatabaseOwnershipError("Database principal binding belongs to another resource.");
    }
  }
}

function assertPrincipalIsManaged(principal, engine) {
  const value = normalizedIdentifier(principal, "database principal");
  if (!value.startsWith(`pi_${engine === "postgres" ? "p" : "m"}_`)
    || PROTECTED_PRINCIPALS.has(value)
    || value.startsWith("pg_")
    || value.startsWith("rds")
    || value.startsWith("azure_")
    || value.startsWith("cloudsql")) {
    throw new DatabaseOwnershipError("Protected or unmanaged database principal is not allowed.");
  }
}

function normalizedProjectId(value) {
  const project = String(value || "").trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(project)) throw new DatabaseOwnershipError("Valid project id is required for database ownership.");
  return project;
}

function normalizedEngine(value) {
  const engine = String(value || "").trim().toLowerCase();
  if (!new Set(["mariadb", "postgres"]).has(engine)) throw new DatabaseOwnershipError("Unsupported database engine.");
  return engine;
}

function normalizedIdentifier(value, label) {
  const identifier = String(value || "").trim().toLowerCase();
  if (!IDENTIFIER_PATTERN.test(identifier)) throw new DatabaseOwnershipError(`Invalid ${label}.`);
  return identifier;
}

function normalizedBindingStatus(value) {
  const status = String(value || "reserved");
  if (!new Set(["reserved", "active", "migration-required", "retired"]).has(status)) {
    throw new DatabaseOwnershipError("Invalid database principal binding status.");
  }
  return status;
}
