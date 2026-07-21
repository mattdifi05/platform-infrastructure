const DIGEST_IMAGE = /@sha256:[a-f0-9]{64}$/i;
const IDENTIFIER = /^[a-z][a-z0-9_]{0,62}$/;

export const defaultPostgresRestoreImage = "postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa";
export const postgresRestoreRole = "restore_runner";

function identifier(value, label) {
  const clean = String(value ?? "");
  if (!IDENTIFIER.test(clean)) throw new Error(`${label} must be a lowercase PostgreSQL identifier.`);
  return clean;
}

export function postgresRestoreSandboxPlan({ image, containerName, backupMount, databaseName }) {
  const cleanImage = String(image ?? "").trim();
  if (!DIGEST_IMAGE.test(cleanImage) || /@sha256:0{64}$/i.test(cleanImage)) {
    throw new Error("POSTGRES_RESTORE_TEST_IMAGE must be pinned by a nonzero digest.");
  }
  const cleanContainer = String(containerName ?? "");
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(cleanContainer)) throw new Error("Restore sandbox container name is invalid.");
  const cleanMount = String(backupMount ?? "");
  if (!cleanMount.includes(":/restore/input.dump:ro")) throw new Error("Restore sandbox backup mount must be read-only.");
  const database = identifier(databaseName, "Restore sandbox database");
  const role = postgresRestoreRole;
  return {
    containerName: cleanContainer,
    database,
    role,
    dockerRunArgs: [
      "run", "-d", "--name", cleanContainer,
      "--network", "none",
      "--read-only",
      "--cap-drop", "ALL",
      "--security-opt", "no-new-privileges:true",
      "--pids-limit", "256",
      "--memory", "1g",
      "--cpus", "1",
      "--user", "postgres",
      "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,noexec,mode=1777,size=768m",
      "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=128m",
      "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,noexec,mode=1777,size=16m",
      "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
      "-e", "PGDATA=/var/lib/postgresql/data/pgdata",
      "-v", cleanMount,
      cleanImage,
    ],
    bootstrapSql: [
      `create role ${role} login nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls;`,
      `create database ${database} owner ${role};`,
    ].join(" "),
    restoreArgs: ["pg_restore", "-U", role, "-d", database, "--no-owner", "--no-acl", "--exit-on-error", "/restore/input.dump"],
  };
}

