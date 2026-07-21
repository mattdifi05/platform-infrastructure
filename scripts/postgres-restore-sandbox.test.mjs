import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { defaultPostgresRestoreImage, postgresRestoreSandboxPlan } from "./postgres-restore-sandbox.mjs";

test("restore plan is disposable, offline, bounded, and feeds the dump only to a restricted role", () => {
  const plan = postgresRestoreSandboxPlan({
    image: defaultPostgresRestoreImage,
    containerName: "restore-sandbox-1",
    backupMount: "/host/backup.dump:/restore/input.dump:ro",
    databaseName: "restore_sandbox",
  });
  const argv = plan.dockerRunArgs.join(" ");
  for (const required of ["--network none", "--read-only", "--cap-drop ALL", "no-new-privileges:true", "--pids-limit 256", "--memory 1g", "--cpus 1", ":/restore/input.dump:ro"] ) {
    assert.match(argv, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.doesNotMatch(argv, /enterprise-postgres|\/var\/run\/docker\.sock|platform.*volume/);
  assert.match(plan.bootstrapSql, /nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls/);
  assert.deepEqual(plan.restoreArgs.slice(0, 4), ["pg_restore", "-U", "restore_runner", "-d"]);
  assert.equal(plan.restoreArgs.includes("postgres"), false);
  assert.equal(plan.restoreArgs.includes("--exit-on-error"), true);
});

test("rejects mutable images, writable mounts, and unsafe identifiers", () => {
  const input = { image: defaultPostgresRestoreImage, containerName: "restore-sandbox", backupMount: "/host/a.dump:/restore/input.dump:ro", databaseName: "restore_sandbox" };
  assert.throws(() => postgresRestoreSandboxPlan({ ...input, image: "postgres:latest" }), /pinned/);
  assert.throws(() => postgresRestoreSandboxPlan({ ...input, backupMount: "/host/a.dump:/restore/input.dump" }), /read-only/);
  assert.throws(() => postgresRestoreSandboxPlan({ ...input, databaseName: "postgres; create role evil" }), /identifier/);
});

test("all PostgreSQL drill paths use the isolated helper, not the live database", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const source = fs.readFileSync(path.join(here, "infra-ops.mjs"), "utf8");
  const body = source.match(/async function restoreTestPostgres\(options = \{\}\) \{([\s\S]*?)\n\}\n\nasync function backupRestoreDrill/)?.[1] ?? "";
  assert.match(body, /postgresRestoreSandboxPlan/);
  assert.doesNotMatch(body, /dockerExec\(container/);
  assert.doesNotMatch(body, /drop database if exists/);
  assert.match(body, /liveSourceTouched: false/);
});

