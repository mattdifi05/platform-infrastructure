import assert from "node:assert/strict";
import test from "node:test";

import {
  initializeLocalPrivateBackupInvocation,
  keycloakBackupCleanupProgram,
  keycloakBackupProgram,
  keycloakBackupResidueAssertionProgram,
  localPrivateBackupChildBindings,
  localPrivateBackupDockerInvocationAllowed,
  mariadbBackupProgram,
} from "./local-private-backup-docker-policy.mjs";

const sha = (value) => value.repeat(64);
const nodeImage = `node:26.3.1-alpine@sha256:${sha("a")}`;
const resticImage = `sha256:${sha("b")}`;
const roots = {
  backupHost: "/srv/platform/local-private-backup/data/backups",
  brokerStateHost: "/srv/platform/local-private-backup/broker-state",
  dataContainer: "/var/lib/platform-backup-data",
  dataHost: "/srv/platform/local-private-backup/data",
  secretsHost: "/srv/platform/critical",
  stagingContainer: "/var/lib/platform-backup-data/.tmp/broker-artifact-staging",
  stagingHost: "/srv/platform/local-private-backup/data/.tmp/broker-artifact-staging",
};

function invocation(action = "backup.catalog") {
  return {
    action,
    egressNetwork: "platform_infra_greenfield_platform_egress",
    nodeImage,
    receipt: {
      resources: {
        offsite: {
          repository: "rclone:platform-onedrive:platform-infrastructure/restic",
          resticImageId: resticImage,
        },
      },
    },
    roots,
  };
}

const pid = 4321;
const random = "c".repeat(24);

test("LOCAL_PRIVATE catalog and job Docker policy admits only exact backup capture primitives", () => {
  const current = invocation();
  const postgresFile = "/tmp/stexor-20260831-141500.dump";
  const mariadbFile = "/tmp/mariadb-stexor-20260831-141501.sql.gz";
  const allowed = [
    ["exec", "gf-postgres", "pg_dump", "-U", "postgres", "-d", "stexor", "--format=custom", "--no-owner", "--no-acl", `--file=${postgresFile}`],
    ["exec", "gf-postgres", "rm", "-f", postgresFile],
    ["cp", `gf-postgres:${postgresFile}`, `${roots.stagingContainer}/.stexor-20260831-141500.dump.staging-${pid}-${random}`],
    ["exec", "gf-mariadb", "sh", "-ec", mariadbBackupProgram(mariadbFile, "stexor")],
    ["exec", "gf-mariadb", "rm", "-f", mariadbFile],
    ["cp", `gf-mariadb:${mariadbFile}`, `${roots.stagingContainer}/.mariadb-stexor-20260831-141501.sql.gz.staging-${pid}-${random}`],
    ["cp", "gf-minio:/data", `${roots.dataContainer}/.tmp/ops/platform-minio-data-Abc123/minio-data`],
    ["exec", "gf-keycloak", "sh", "-ec", keycloakBackupProgram()],
    ["exec", "gf-keycloak", "sh", "-ec", keycloakBackupCleanupProgram()],
    ["exec", "gf-keycloak", "sh", "-ec", keycloakBackupResidueAssertionProgram()],
    ["cp", "gf-keycloak:/tmp/platform-keycloak-config-backup", `${roots.dataContainer}/.tmp/ops/platform-keycloak-config-Abc123/keycloak-config`],
    [
      "run", "--rm", "--network", "none",
      "-v", `${roots.dataHost}/.tmp/ops/platform-minio-data-Abc123/minio-data:/work:ro`,
      "-v", `${roots.stagingHost}:/backup`, nodeImage, "sh", "-lc",
      `tar -czf /backup/'.minio-data-20260831-141502.tar.gz.staging-${pid}-${random}' -C /work .`,
    ],
    [
      "run", "--rm", "--network", "none",
      "-v", `${roots.dataHost}/.tmp/ops/platform-keycloak-config-Abc123/keycloak-config:/work:ro`,
      "-v", `${roots.stagingHost}:/backup`, nodeImage, "sh", "-lc",
      `tar -czf /backup/'.keycloak-config-20260831-141503.tar.gz.staging-${pid}-${random}' -C /work .`,
    ],
    [
      "run", "--rm", "--network", "none",
      "-v", `${roots.dataHost}/.tmp/ops/infra-secret-manager-metadata-Abc123:/work:ro`,
      "-v", `${roots.stagingHost}:/backup`, nodeImage, "sh", "-lc",
      `tar -czf /backup/'.secret-manager-metadata-20260831-141504.tar.gz.staging-${pid}-${random}' -C /work .`,
    ],
  ];
  for (const args of allowed) {
    assert.equal(localPrivateBackupDockerInvocationAllowed(current, args, {}, pid), true, args.join(" "));
    assert.equal(localPrivateBackupDockerInvocationAllowed({ ...current, action: "backup.job.execute" }, args, {}, pid), true, args.join(" "));
  }
});

test("LOCAL_PRIVATE Docker policy rejects arbitrary containers, mounts, flags, restore and stdin", () => {
  const current = invocation();
  const rejected = [
    ["ps"],
    ["exec", "gf-control-center", "id"],
    ["exec", "gf-postgres", "rm", "-rf", "/"],
    ["cp", "gf-minio:/data", "/tmp/escaped"],
    ["cp", "gf-postgres:/tmp/stexor-20260831-141500.dump", `${roots.stagingHost}/.stexor-20260831-141500.dump.staging-${pid}-${random}`],
    [
      "run", "--rm", "--network", "none",
      "-v", `${roots.dataContainer}/.tmp/ops/platform-minio-data-Abc123/minio-data:/work:ro`,
      "-v", `${roots.stagingHost}:/backup`, nodeImage, "sh", "-lc",
      `tar -czf /backup/'.minio-data-20260831-141502.tar.gz.staging-${pid}-${random}' -C /work .`,
    ],
    ["run", "--rm", "--privileged", nodeImage, "sh"],
    ["run", "--rm", "--network", "none", "-v", "/var/run/docker.sock:/var/run/docker.sock", nodeImage],
    ["rm", "-f", "gf-postgres"],
    ["volume", "rm", "database"],
  ];
  for (const args of rejected) {
    assert.equal(localPrivateBackupDockerInvocationAllowed(current, args, {}, pid), false, args.join(" "));
  }
  assert.equal(localPrivateBackupDockerInvocationAllowed(current, ["exec", "gf-postgres", "cat"], { input: "x" }, pid), false);
  assert.equal(localPrivateBackupDockerInvocationAllowed(invocation("backup.offsite.sync"), rejected[0], {}, pid), false);
});

function offsitePrefix() {
  return [
    "run", "--rm", "--network", "platform_infra_greenfield_platform_egress", "--user", "1000:1000",
    "-e", "HOME=/tmp", "-e", "XDG_CACHE_HOME=/tmp/.cache",
  ];
}

function offsiteProcessEnvironment() {
  return {
    RESTIC_REPOSITORY: "rclone:platform-onedrive:platform-infrastructure/restic",
    RESTIC_PASSWORD_FILE: "/restic-password/restic_password.txt",
  };
}

test("LOCAL_PRIVATE off-site policy binds egress, image, credential mounts and exact operations", () => {
  const current = invocation("backup.offsite.sync");
  const configMount = `${roots.brokerStateHost}/rclone-refresh:/rclone-config:rw`;
  const passwordMount = `${roots.secretsHost}/restic_password.txt:/restic-password/restic_password.txt:ro`;
  const resticBase = [
    ...offsitePrefix(),
    "-e", "RESTIC_REPOSITORY", "-e", "RESTIC_PASSWORD_FILE",
    "-e", "RCLONE_CONFIG=/rclone-config/rclone.conf",
  ];
  const backup = [
    ...resticBase,
    "-v", `${roots.backupHost}:/backups:ro`, "-v", configMount, "-v", passwordMount, resticImage,
    "backup", "--json",
    "/backups/manifests/manifest-scheduled-platform-20260831-141500-abc123.json",
    "/backups/postgres/stexor-20260831-141500.dump",
    "--tag", "platform-backups",
    "--tag", "platform-manifest-id=manifest-scheduled-platform-20260831-141500-abc123",
    "--tag", `platform-manifest-digest=${sha("d")}`,
    "--host", "platform-infrastructure",
  ];
  const retention = [
    ...resticBase,
    "-v", configMount, "-v", passwordMount, resticImage,
    "forget", "--tag", "platform-backups", "--group-by", "tags", "--keep-last", "42", "--prune",
  ];
  const size = [
    ...offsitePrefix(), "--entrypoint", "rclone",
    "-e", "RCLONE_CONFIG=/rclone-config/rclone.conf", "-v", configMount, resticImage,
    "size", "platform-onedrive:platform-infrastructure/restic", "--json",
  ];
  assert.equal(localPrivateBackupDockerInvocationAllowed(current, backup, { env: offsiteProcessEnvironment() }, pid), true);
  assert.equal(localPrivateBackupDockerInvocationAllowed(current, retention, { env: offsiteProcessEnvironment() }, pid), true);
  assert.equal(localPrivateBackupDockerInvocationAllowed(current, size, {}, pid), true);

  for (const mutated of [
    backup.with(3, "bridge"),
    backup.with(backup.indexOf(resticImage), `sha256:${sha("e")}`),
    backup.with(backup.indexOf(`${roots.backupHost}:/backups:ro`), "/etc:/backups:ro"),
    [...backup.slice(0, -2), "--host", "attacker"],
    [...resticBase, "-v", configMount, "-v", passwordMount, resticImage, "restore", "latest", "--target", "/restore"],
  ]) {
    assert.equal(localPrivateBackupDockerInvocationAllowed(current, mutated, { env: offsiteProcessEnvironment() }, pid), false);
  }
});

test("LOCAL_PRIVATE child authority is complete and partial or root execution fails closed", () => {
  const trusted = {
    receiptDigest: sha("1"),
    receipt: {
      generation: 4,
      releaseCommitSha1: "2".repeat(40),
      treeSha256: sha("3"),
    },
  };
  const bindings = localPrivateBackupChildBindings({
    action: "backup.catalog",
    command: "backup-platform-catalog",
    egressNetwork: "platform_infra_greenfield_platform_egress",
    requestSha256: sha("4"),
    trusted,
  });
  assert.equal(bindings.PLATFORM_LOCAL_PRIVATE_BACKUP_INVOCATION_SCHEMA, "platform.local-private-backup-invocation/v1");
  assert.equal(bindings.PLATFORM_LOCAL_PRIVATE_BACKUP_JOB_SHA256, "-");
  assert.equal(initializeLocalPrivateBackupInvocation({ environment: {} }), null);
  assert.throws(() => initializeLocalPrivateBackupInvocation({
    environment: { PLATFORM_LOCAL_PRIVATE_BACKUP_INVOCATION_SCHEMA: "platform.local-private-backup-invocation/v1" },
    uid: 0,
    gid: 0,
  }), /marker set is incomplete|service identity/);
});
