import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { parseBackupJobDocument } from "../control-center/backup/contracts.mjs";
import { ACTIONS } from "./docker-action-contract.mjs";
import {
  LOCAL_PRIVATE_ALLOWED_ACTIONS,
  readCanonicalAdmission,
  verifyAdmissionDocument,
} from "./local-private-backup-admission.mjs";

export const LOCAL_PRIVATE_BACKUP_INVOCATION_SCHEMA = "platform.local-private-backup-invocation/v1";

const DEFAULT_ADMISSION = "/run/platform/docker-action-broker/client/admission.json";
const DEFAULT_CAPABILITY_DIR = "/run/platform/docker-action-broker/client";
const DEFAULT_PUBLIC_KEY = "/opt/platform-infrastructure/policy/local-private-backup-admission.pub.pem";
const DEFAULT_RENDER = "/run/platform/local-private-input/combined-render.yaml";
const DEFAULT_SIGNING_KEY = "/run/platform/local-private-input/backup_signing_keys";
const DEFAULT_JOBS_ROOT = "/var/lib/platform-backup-data/backup-jobs";
const SHA256 = /^[a-f0-9]{64}$/;
const SHA1 = /^[a-f0-9]{40}$/;
const IMAGE = /^(?:sha256:|[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:)[a-f0-9]{64}$/;
const NETWORK = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const LOCAL_PRIVATE_MARKER_KEYS = Object.freeze([
  "PLATFORM_LOCAL_PRIVATE_BACKUP_ACTION",
  "PLATFORM_LOCAL_PRIVATE_BACKUP_AUTHORITY_SHA256",
  "PLATFORM_LOCAL_PRIVATE_BACKUP_COMMAND",
  "PLATFORM_LOCAL_PRIVATE_BACKUP_EGRESS_NETWORK",
  "PLATFORM_LOCAL_PRIVATE_BACKUP_GENERATION",
  "PLATFORM_LOCAL_PRIVATE_BACKUP_INVOCATION_SCHEMA",
  "PLATFORM_LOCAL_PRIVATE_BACKUP_JOB_SHA256",
  "PLATFORM_LOCAL_PRIVATE_BACKUP_RELEASE_COMMIT_SHA1",
  "PLATFORM_LOCAL_PRIVATE_BACKUP_REQUEST_SHA256",
  "PLATFORM_LOCAL_PRIVATE_BACKUP_TREE_SHA256",
]);

function fail(message) {
  throw new Error(message);
}

function sameStringArray(left, right) {
  return Array.isArray(left) && Array.isArray(right)
    && left.length === right.length
    && left.every((value, index) => value === right[index]);
}

function plainRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function sha256Bytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function protectedFileBytes(file, {
  expectedGid,
  expectedUid,
  maximumBytes = 128 * 1024,
  minimumBytes = 1,
} = {}) {
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1
      || before.uid !== expectedUid || before.gid !== expectedGid
      || (before.mode & 0o077) !== 0 || (before.mode & 0o400) === 0
      || before.size < minimumBytes || before.size > maximumBytes) {
      fail(`LOCAL_PRIVATE protected file rejected: ${file}`);
    }
    const first = Buffer.alloc(before.size);
    const second = Buffer.alloc(before.size);
    if (fs.readSync(descriptor, first, 0, first.length, 0) !== first.length
      || fs.readSync(descriptor, second, 0, second.length, 0) !== second.length) {
      fail(`LOCAL_PRIVATE protected file changed: ${file}`);
    }
    const after = fs.fstatSync(descriptor);
    if (!["dev", "ino", "size", "mtimeMs", "ctimeMs", "mode", "uid", "gid", "nlink"]
      .every((field) => Object.is(before[field], after[field]))
      || !crypto.timingSafeEqual(first, second)) {
      fail(`LOCAL_PRIVATE protected file changed: ${file}`);
    }
    return first;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function capabilityFiles(capabilityDir) {
  return Object.fromEntries(LOCAL_PRIVATE_ALLOWED_ACTIONS.map((action) => [
    action,
    path.join(capabilityDir, path.basename(ACTIONS[action].capabilityFile)),
  ]));
}

export function readLocalPrivateRenderBinding(renderFile) {
  let render;
  try {
    render = JSON.parse(fs.readFileSync(renderFile, "utf8"));
  } catch {
    fail("LOCAL_PRIVATE canonical render is not valid JSON");
  }
  const broker = render?.services?.["docker-action-broker"];
  const egress = render?.networks?.platform_egress;
  if (!plainRecord(broker) || !plainRecord(broker.environment)
    || broker.container_name !== "gf-docker-action-broker"
    || broker.user !== "1000:1000"
    || broker.network_mode !== "none"
    || broker.read_only !== true
    || !sameStringArray(broker.cap_drop, ["ALL"])
    || !sameStringArray(broker.security_opt, ["no-new-privileges:true"])) {
    fail("LOCAL_PRIVATE canonical render does not contain the closed broker runtime");
  }
  const requiredEnvironment = {
    BACKUP_KEYCLOAK_CONTAINER: "gf-keycloak",
    BACKUP_MARIADB_CONTAINER: "gf-mariadb",
    BACKUP_MINIO_CONTAINER: "gf-minio",
    BACKUP_POSTGRES_CONTAINER: "gf-postgres",
    BACKUP_SCHEDULER_JOBS_DIR: DEFAULT_JOBS_ROOT,
    BACKUP_SIGNING_KEYS_FILE: DEFAULT_SIGNING_KEY,
    DOCKER_ACTION_LOCAL_ADMISSION_FILE: DEFAULT_ADMISSION,
    DOCKER_ACTION_LOCAL_CAPABILITY_DIR: DEFAULT_CAPABILITY_DIR,
    DOCKER_ACTION_LOCAL_PUBLIC_KEY_FILE: DEFAULT_PUBLIC_KEY,
    DOCKER_ACTION_LOCAL_RENDER_FILE: DEFAULT_RENDER,
    KEYCLOAK_DB_NAME: "keycloak",
    PLATFORM_CLOSED_HOST_PATH_MAPPINGS: "1",
    PLATFORM_DATA_CONTAINER_ROOT: "/var/lib/platform-backup-data",
    PLATFORM_DATA_ROOT: "/var/lib/platform-backup-data",
    PLATFORM_ENVIRONMENT: "production",
    PLATFORM_INFRA_CONTAINER_ROOT: "/opt/platform-infrastructure",
    PLATFORM_INFRA_ROOT: "/opt/platform-infrastructure",
    PLATFORM_SECRETS_CONTAINER_ROOT: "/run/platform/critical",
    PLATFORM_SECRETS_ROOT: "/run/platform/critical",
    PLATFORM_STATE_CONTAINER_ROOT: "/run/platform/control-center-state",
    PROJECT_SOURCE_ROOT: "/var/www/projects",
    PROJECT_STATE_ROOT: "/run/platform/control-center-state",
    RESTIC_KEEP_LAST: "42",
    RESTIC_MAX_REPOSITORY_BYTES: "2500000000000",
  };
  if (Object.entries(requiredEnvironment).some(([key, value]) => broker.environment[key] !== value)
    || !IMAGE.test(String(broker.environment.NODE_IMAGE ?? ""))) {
    fail("LOCAL_PRIVATE canonical render broker environment is not the fixed V1.1 backup environment");
  }
  for (const key of [
    "LOCAL_PRIVATE_BACKUP_BROKER_STATE_HOST_ROOT",
    "PLATFORM_DATA_HOST_ROOT",
    "PLATFORM_INFRA_HOST_ROOT",
    "PLATFORM_SECRETS_HOST_ROOT",
    "PLATFORM_STATE_HOST_ROOT",
    "PROJECT_SOURCE_HOST_ROOT",
  ]) {
    const value = broker.environment[key];
    if (typeof value !== "string" || !path.posix.isAbsolute(value) || path.posix.normalize(value) !== value) {
      fail(`LOCAL_PRIVATE canonical render host mapping is invalid: ${key}`);
    }
  }
  const controlCenter = render?.services?.["control-center"];
  const controlCenterDataVolumes = Array.isArray(controlCenter?.volumes)
    ? controlCenter.volumes.filter((entry) => String(entry?.target ?? "").startsWith("/var/lib/platform-backup-data"))
    : [];
  const expectedControlCenterDataVolumes = ["backup-jobs", "backups", "reports"].map((name) => ({
    source: path.posix.join(broker.environment.PLATFORM_DATA_HOST_ROOT, name),
    target: path.posix.join("/var/lib/platform-backup-data", name),
  }));
  if (controlCenterDataVolumes.length !== expectedControlCenterDataVolumes.length
    || expectedControlCenterDataVolumes.some(({ source, target }) => !controlCenterDataVolumes.some((entry) => (
      entry?.type === "bind" && entry.source === source && entry.target === target && entry.read_only !== true
    )))) {
    fail("LOCAL_PRIVATE canonical render exposes backup data outside the three bounded Control Center mounts");
  }
  if (!plainRecord(egress) || !NETWORK.test(String(egress.name ?? ""))
    || egress.internal === true || egress.enable_ipv6 !== false
    || egress.labels?.["com.platform.trust-zone"] !== "trusted-platform-egress") {
    fail("LOCAL_PRIVATE canonical render egress network is invalid");
  }
  const socketMounts = (broker.volumes ?? []).filter((entry) => entry?.source === "/var/run/docker.sock"
    && entry?.target === "/var/run/docker.sock" && entry?.read_only === true);
  if (socketMounts.length !== 1) fail("LOCAL_PRIVATE canonical render broker socket boundary is invalid");
  return Object.freeze({
    brokerEnvironment: Object.freeze({ ...broker.environment }),
    egressNetwork: egress.name,
    nodeImage: broker.environment.NODE_IMAGE,
  });
}

export function localPrivateBackupChildBindings({
  action,
  command,
  egressNetwork,
  jobSha256 = "-",
  requestSha256,
  trusted,
} = {}) {
  if (!LOCAL_PRIVATE_ALLOWED_ACTIONS.includes(action)
    || typeof command !== "string" || !command
    || !NETWORK.test(String(egressNetwork ?? ""))
    || !SHA256.test(String(requestSha256 ?? ""))
    || (action === "backup.job.execute" ? !SHA256.test(String(jobSha256 ?? "")) : jobSha256 !== "-")
    || !SHA256.test(String(trusted?.receiptDigest ?? ""))
    || !Number.isSafeInteger(trusted?.receipt?.generation)
    || !SHA1.test(String(trusted?.receipt?.releaseCommitSha1 ?? ""))
    || !SHA256.test(String(trusted?.receipt?.treeSha256 ?? ""))) {
    fail("LOCAL_PRIVATE child invocation binding is invalid");
  }
  return Object.freeze({
    PLATFORM_LOCAL_PRIVATE_BACKUP_ACTION: action,
    PLATFORM_LOCAL_PRIVATE_BACKUP_AUTHORITY_SHA256: trusted.receiptDigest,
    PLATFORM_LOCAL_PRIVATE_BACKUP_COMMAND: command,
    PLATFORM_LOCAL_PRIVATE_BACKUP_EGRESS_NETWORK: egressNetwork,
    PLATFORM_LOCAL_PRIVATE_BACKUP_GENERATION: String(trusted.receipt.generation),
    PLATFORM_LOCAL_PRIVATE_BACKUP_INVOCATION_SCHEMA: LOCAL_PRIVATE_BACKUP_INVOCATION_SCHEMA,
    PLATFORM_LOCAL_PRIVATE_BACKUP_JOB_SHA256: jobSha256,
    PLATFORM_LOCAL_PRIVATE_BACKUP_RELEASE_COMMIT_SHA1: trusted.receipt.releaseCommitSha1,
    PLATFORM_LOCAL_PRIVATE_BACKUP_REQUEST_SHA256: requestSha256,
    PLATFORM_LOCAL_PRIVATE_BACKUP_TREE_SHA256: trusted.receipt.treeSha256,
  });
}

function assertRenderedEnvironment(rendered, environment) {
  for (const [key, value] of Object.entries(rendered)) {
    if (typeof value !== "string" || environment[key] !== value) {
      fail(`LOCAL_PRIVATE process environment differs from canonical render: ${key}`);
    }
  }
}

function exactCli(action, processArgs, jobsRoot) {
  if (action === "backup.catalog") return sameStringArray(processArgs, ["backup-platform-catalog"]);
  if (action === "backup.offsite.sync") return sameStringArray(processArgs, ["offsite-backup-restic"]);
  if (action === "restore.offsite.proof") {
    return sameStringArray(processArgs, []) || sameStringArray(processArgs, ["reconcile-interrupted"]);
  }
  if (action !== "backup.job.execute" || processArgs.length !== 3 || processArgs[0] !== "execute-backup-job"
    || processArgs[1] !== "--jobFile") return false;
  const file = path.resolve(processArgs[2]);
  const running = path.join(jobsRoot, "running");
  return path.dirname(file) === running && path.basename(file) === file.slice(running.length + 1)
    && /^[a-z0-9][a-z0-9-]{15,127}\.json$/.test(path.basename(file));
}

export function initializeLocalPrivateBackupInvocation({
  environment = process.env,
  expectedFileGid = typeof process.getgid === "function" ? process.getgid() : -1,
  expectedFileUid = typeof process.getuid === "function" ? process.getuid() : -1,
  gid = typeof process.getgid === "function" ? process.getgid() : -1,
  now = Date.now(),
  processArgs = process.argv.slice(2),
  uid = typeof process.getuid === "function" ? process.getuid() : -1,
} = {}) {
  const presentMarkers = Object.keys(environment).filter((key) => key.startsWith("PLATFORM_LOCAL_PRIVATE_BACKUP_"));
  if (!presentMarkers.length) return null;
  if (!sameStringArray([...presentMarkers].sort(), [...LOCAL_PRIVATE_MARKER_KEYS].sort())
    || environment.PLATFORM_LOCAL_PRIVATE_BACKUP_INVOCATION_SCHEMA !== LOCAL_PRIVATE_BACKUP_INVOCATION_SCHEMA) {
    fail("LOCAL_PRIVATE invocation marker set is incomplete or widened");
  }
  if (uid !== 1000 || gid !== 1000) fail("LOCAL_PRIVATE backup execution requires the fixed service identity 1000:1000");

  const admissionFile = environment.DOCKER_ACTION_LOCAL_ADMISSION_FILE;
  const capabilityDir = environment.DOCKER_ACTION_LOCAL_CAPABILITY_DIR;
  const publicKeyFile = environment.DOCKER_ACTION_LOCAL_PUBLIC_KEY_FILE;
  const renderFile = environment.DOCKER_ACTION_LOCAL_RENDER_FILE;
  const signingKeyFile = environment.BACKUP_SIGNING_KEYS_FILE;
  if (admissionFile !== DEFAULT_ADMISSION || capabilityDir !== DEFAULT_CAPABILITY_DIR
    || publicKeyFile !== DEFAULT_PUBLIC_KEY || renderFile !== DEFAULT_RENDER
    || signingKeyFile !== DEFAULT_SIGNING_KEY) {
    fail("LOCAL_PRIVATE invocation trust paths are not canonical");
  }
  const verified = verifyAdmissionDocument(readCanonicalAdmission(admissionFile), {
    backupSigningKeyFile: signingKeyFile,
    capabilityFiles: capabilityFiles(capabilityDir),
    now,
    publicKeyPem: fs.readFileSync(publicKeyFile),
    renderFile,
  });
  const render = readLocalPrivateRenderBinding(renderFile);
  assertRenderedEnvironment(render.brokerEnvironment, environment);
  const action = environment.PLATFORM_LOCAL_PRIVATE_BACKUP_ACTION;
  const command = environment.PLATFORM_LOCAL_PRIVATE_BACKUP_COMMAND;
  const jobsRoot = environment.BACKUP_SCHEDULER_JOBS_DIR;
  const commandByAction = {
    "backup.catalog": "backup-platform-catalog",
    "backup.job.execute": "execute-backup-job",
    "restore.offsite.proof": "restore-offsite-proof",
    "backup.offsite.sync": "offsite-backup-restic",
  };
  if (!verified.payload.allowedActions.includes(action)
    || commandByAction[action] !== command
    || !exactCli(action, processArgs, jobsRoot)
    || environment.PLATFORM_LOCAL_PRIVATE_BACKUP_AUTHORITY_SHA256 !== verified.receiptDigest
    || environment.PLATFORM_LOCAL_PRIVATE_BACKUP_GENERATION !== String(verified.payload.generation)
    || environment.PLATFORM_LOCAL_PRIVATE_BACKUP_RELEASE_COMMIT_SHA1 !== verified.payload.releaseCommitSha1
    || environment.PLATFORM_LOCAL_PRIVATE_BACKUP_TREE_SHA256 !== verified.payload.treeSha256
    || environment.PLATFORM_LOCAL_PRIVATE_BACKUP_EGRESS_NETWORK !== render.egressNetwork
    || !SHA256.test(String(environment.PLATFORM_LOCAL_PRIVATE_BACKUP_REQUEST_SHA256 ?? ""))) {
    fail("LOCAL_PRIVATE invocation is not bound to its signed admission, action, command and render");
  }

  const jobSha256 = environment.PLATFORM_LOCAL_PRIVATE_BACKUP_JOB_SHA256;
  if (action === "backup.job.execute") {
    if (!SHA256.test(String(jobSha256 ?? ""))) fail("LOCAL_PRIVATE backup job digest is invalid");
    const jobFile = processArgs[2];
    const bytes = protectedFileBytes(jobFile, {
      expectedGid: expectedFileGid,
      expectedUid: expectedFileUid,
    });
    if (sha256Bytes(bytes) !== jobSha256) fail("LOCAL_PRIVATE backup job changed after broker admission");
    const job = parseBackupJobDocument(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
    if (job.operation !== "backup" || job.status !== "running") fail("LOCAL_PRIVATE executor accepts only a claimed backup job");
  } else if (jobSha256 !== "-") {
    fail("LOCAL_PRIVATE non-job action carried a job authority");
  }

  const offsiteOnly = [
    "RCLONE_CONFIG", "RCLONE_CONFIG_WRITABLE", "RESTIC_DOCKER_USER", "RESTIC_HOSTNAME",
    "RESTIC_IMAGE", "RESTIC_PASSWORD_FILE", "RESTIC_REPOSITORY", "RESTIC_REQUIRE_IMMUTABLE_IMAGE",
    "LOCAL_PRIVATE_RESTORE_MANIFEST_DIGEST", "LOCAL_PRIVATE_RESTORE_MANIFEST_ID",
    "LOCAL_PRIVATE_RESTORE_RECEIPT_FILE_NAME", "LOCAL_PRIVATE_RESTORE_RECEIPT_FILE_SHA256",
    "LOCAL_PRIVATE_RESTORE_SNAPSHOT_ID",
  ];
  if (action === "backup.offsite.sync") {
    const expectedOffsite = {
      HOME: "/tmp",
      XDG_CACHE_HOME: "/tmp/.cache",
      RCLONE_CONFIG: "/var/lib/platform-docker-action-broker/rclone-refresh/rclone.conf",
      RCLONE_CONFIG_WRITABLE: "1",
      RESTIC_DOCKER_USER: "1000:1000",
      RESTIC_HOSTNAME: "platform-infrastructure",
      RESTIC_IMAGE: verified.payload.resources.offsite.resticImageId,
      RESTIC_PASSWORD_FILE: verified.payload.resources.offsite.resticPasswordPath,
      RESTIC_REPOSITORY: verified.payload.resources.offsite.repository,
      RESTIC_REQUIRE_IMMUTABLE_IMAGE: "true",
    };
    if (Object.entries(expectedOffsite).some(([key, value]) => environment[key] !== value)
      || environment.RESTIC_SKIP_RETENTION !== undefined || environment.RESTIC_NO_PRUNE !== undefined) {
      fail("LOCAL_PRIVATE off-site process environment is not exact");
    }
  } else if (action === "restore.offsite.proof") {
    const restore = verified.payload.resources.offsite.restore;
    const expectedRestore = {
      HOME: "/tmp",
      XDG_CACHE_HOME: "/tmp/.cache",
      RCLONE_CONFIG: "/var/lib/platform-docker-action-broker/rclone-refresh/rclone.conf",
      RCLONE_CONFIG_WRITABLE: "1",
      RESTIC_DOCKER_USER: "1000:1000",
      RESTIC_IMAGE: verified.payload.resources.offsite.resticImageId,
      RESTIC_PASSWORD_FILE: verified.payload.resources.offsite.resticPasswordPath,
      RESTIC_REPOSITORY: verified.payload.resources.offsite.repository,
      RESTIC_REQUIRE_IMMUTABLE_IMAGE: "true",
      LOCAL_PRIVATE_RESTORE_MANIFEST_DIGEST: restore.manifestDigest,
      LOCAL_PRIVATE_RESTORE_MANIFEST_ID: restore.manifestId,
      LOCAL_PRIVATE_RESTORE_RECEIPT_FILE_NAME: restore.receiptFileName,
      LOCAL_PRIVATE_RESTORE_RECEIPT_FILE_SHA256: restore.receiptFileSha256,
      LOCAL_PRIVATE_RESTORE_SNAPSHOT_ID: restore.snapshotId,
    };
    if (Object.entries(expectedRestore).some(([key, value]) => environment[key] !== value)
      || environment.RESTIC_HOSTNAME !== undefined
      || environment.RESTIC_SKIP_RETENTION !== undefined
      || environment.RESTIC_NO_PRUNE !== undefined) {
      fail("LOCAL_PRIVATE off-site restore process environment is not exact");
    }
  } else if (offsiteOnly.some((key) => environment[key] !== undefined)) {
    fail("LOCAL_PRIVATE non-offsite action received off-site credentials or controls");
  }

  return Object.freeze({
    action,
    command,
    egressNetwork: render.egressNetwork,
    nodeImage: render.nodeImage,
    receipt: verified.payload,
    requestSha256: environment.PLATFORM_LOCAL_PRIVATE_BACKUP_REQUEST_SHA256,
    roots: Object.freeze({
      backupHost: path.join(render.brokerEnvironment.PLATFORM_DATA_HOST_ROOT, "backups"),
      brokerStateHost: render.brokerEnvironment.LOCAL_PRIVATE_BACKUP_BROKER_STATE_HOST_ROOT,
      dataContainer: render.brokerEnvironment.PLATFORM_DATA_CONTAINER_ROOT,
      dataHost: render.brokerEnvironment.PLATFORM_DATA_HOST_ROOT,
      secretsHost: render.brokerEnvironment.PLATFORM_SECRETS_HOST_ROOT,
      stagingContainer: path.join(render.brokerEnvironment.PLATFORM_DATA_CONTAINER_ROOT, ".tmp", "broker-artifact-staging"),
      stagingHost: path.join(render.brokerEnvironment.PLATFORM_DATA_HOST_ROOT, ".tmp", "broker-artifact-staging"),
    }),
  });
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\"'\"'")}'`;
}

export function mariadbBackupProgram(containerPath, database = "") {
  const databaseSelection = database
    ? `DATABASES=${shellQuote(database)}`
    : 'DATABASES="$(mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" -N -e "select schema_name from information_schema.schemata where schema_name not in (\'information_schema\',\'mysql\',\'performance_schema\',\'sys\') order by schema_name")"';
  return [
    "test -s /run/secrets/mariadb_root_password",
    'MARIADB_ROOT_PASSWORD="$(cat /run/secrets/mariadb_root_password)"',
    databaseSelection,
    'test -n "$DATABASES"',
    `mariadb-dump --single-transaction --routines --events --triggers --databases $DATABASES -uroot -p"$MARIADB_ROOT_PASSWORD" | gzip -9 > ${shellQuote(containerPath)}`,
  ].join(" && ");
}

export function mariadbBackupProgramFromScript(script) {
  const match = String(script ?? "").match(/ > '(\/tmp\/mariadb-(all|[a-z][a-z0-9_]*)-[0-9]{8}-[0-9]{6}\.sql\.gz)'$/);
  if (!match) return null;
  const database = match[2] === "all" ? "" : match[2];
  return script === mariadbBackupProgram(match[1], database) ? match[1] : null;
}

export function keycloakBackupProgram() {
  return `
set -eu
umask 077
work="/tmp/platform-keycloak-config-backup"
kcadm_config="/tmp/platform-kcadm-backup.config"
kcadm_log="/tmp/platform-kcadm-backup.log"
default_kcadm_config="$HOME/.keycloak/kcadm.config"
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  rm -f "$kcadm_config" "$kcadm_log" "$default_kcadm_config"
  if [ "$status" -ne 0 ]; then rm -rf "$work"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
rm -rf "$work"
rm -f "$kcadm_config" "$kcadm_log" "$default_kcadm_config"
mkdir -p "$work/realms" "$work/import" "$work/runtime"
KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat /run/secrets/keycloak_admin_password)"
export KC_BOOTSTRAP_ADMIN_PASSWORD
/opt/keycloak/bin/kcadm.sh config credentials --config "$kcadm_config" --server http://127.0.0.1:8080 --realm master --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >"$kcadm_log" 2>&1
/opt/keycloak/bin/kcadm.sh get realms --config "$kcadm_config" --fields realm,enabled > "$work/realms.json"
for realm in $(grep -o '"realm"[[:space:]]*:[[:space:]]*"[^"]*"' "$work/realms.json" | sed 's/.*"realm"[[:space:]]*:[[:space:]]*"//; s/".*//'); do
  safe="$(printf '%s' "$realm" | tr -c 'A-Za-z0-9_.-' '_')"
  /opt/keycloak/bin/kcadm.sh get "realms/$realm" --config "$kcadm_config" > "$work/realms/\${safe}-realm.json"
  /opt/keycloak/bin/kcadm.sh get clients --config "$kcadm_config" -r "$realm" > "$work/realms/\${safe}-clients.json"
  /opt/keycloak/bin/kcadm.sh get roles --config "$kcadm_config" -r "$realm" > "$work/realms/\${safe}-roles.json"
done
if [ -d /opt/keycloak/data/import ]; then
  cp -R /opt/keycloak/data/import/. "$work/import/" 2>/dev/null || true
fi
env | grep '^KC_' | grep -Ev 'PASSWORD|SECRET|TOKEN|KEY' | sort > "$work/runtime/kc-env-sanitized.txt" || true
`;
}

export function keycloakBackupResidueAssertionProgram() {
  return "test ! -e '/tmp/platform-keycloak-config-backup' && test ! -e '/tmp/platform-kcadm-backup.config' && test ! -e '/tmp/platform-kcadm-backup.log' && test ! -e '/tmp/platform-keycloak-config-backup.tar.gz' && test ! -e \"$HOME/.keycloak/kcadm.config\"";
}

export function keycloakBackupCleanupProgram() {
  return "rm -rf '/tmp/platform-keycloak-config-backup' '/tmp/platform-keycloak-config-backup.tar.gz' '/tmp/platform-kcadm-backup.config' '/tmp/platform-kcadm-backup.log' \"$HOME/.keycloak/kcadm.config\"";
}

function pathInside(root, candidate) {
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(candidate);
  const relative = path.relative(resolvedRoot, resolved);
  return resolved === resolvedRoot || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function localPrivateExecAllowed(invocation, args) {
  if (args[0] !== "exec" || args.length < 3 || args[1] === "-i") return false;
  const [container, program] = args.slice(1, 3);
  if (container === "gf-postgres") {
    if (program === "rm") return args.length === 5 && args[3] === "-f"
      && /^\/tmp\/[a-z][a-z0-9_]*-[0-9]{8}-[0-9]{6}\.dump$/.test(args[4]);
    const database = args[6];
    return program === "pg_dump" && /^[a-z][a-z0-9_]*$/.test(String(database ?? ""))
      && sameStringArray(args.slice(2, -1), [
        "pg_dump", "-U", "postgres", "-d", database, "--format=custom", "--no-owner", "--no-acl",
      ]) && args.at(-1) === `--file=/tmp/${database}-${String(args.at(-1)).match(/([0-9]{8}-[0-9]{6})\.dump$/)?.[1]}.dump`;
  }
  if (container === "gf-mariadb") {
    if (program === "rm") return args.length === 5 && args[3] === "-f"
      && /^\/tmp\/mariadb-(?:all|[a-z][a-z0-9_]*)-[0-9]{8}-[0-9]{6}\.sql\.gz$/.test(args[4]);
    return program === "sh" && args[3] === "-ec" && args.length === 5
      && mariadbBackupProgramFromScript(args[4]) !== null;
  }
  if (container === "gf-keycloak") {
    return program === "sh" && args[3] === "-ec" && args.length === 5
      && [keycloakBackupProgram(), keycloakBackupCleanupProgram(), keycloakBackupResidueAssertionProgram()].includes(args[4]);
  }
  return false;
}

function localPrivateCopyAllowed(invocation, args, processId) {
  if (args[0] !== "cp" || args.length !== 3) return false;
  const [source, destination] = args.slice(1);
  // Unlike daemon-side bind mounts, `docker cp` writes through the CLI client
  // filesystem. The broker client may therefore write only into its admitted
  // container-side data bind, never to a daemon-host path.
  const dataRoot = invocation.roots.dataContainer;
  let match = source.match(/^gf-postgres:(\/tmp\/([a-z][a-z0-9_]*)-[0-9]{8}-[0-9]{6}\.dump)$/);
  if (match) return new RegExp(`^${escapeRegExp(path.join(invocation.roots.stagingContainer, `.${path.basename(match[1])}.staging-${processId}-`))}[a-f0-9]{24}$`).test(destination);
  match = source.match(/^gf-mariadb:(\/tmp\/mariadb-(?:all|[a-z][a-z0-9_]*)-[0-9]{8}-[0-9]{6}\.sql\.gz)$/);
  if (match) return new RegExp(`^${escapeRegExp(path.join(invocation.roots.stagingContainer, `.${path.basename(match[1])}.staging-${processId}-`))}[a-f0-9]{24}$`).test(destination);
  if (source === "gf-minio:/data") {
    return pathInside(path.join(dataRoot, ".tmp/ops"), destination)
      && /\/platform-minio-data-[A-Za-z0-9_-]+\/minio-data$/.test(destination);
  }
  if (source === "gf-keycloak:/tmp/platform-keycloak-config-backup") {
    return pathInside(path.join(dataRoot, ".tmp/ops"), destination)
      && /\/platform-keycloak-config-[A-Za-z0-9_-]+\/keycloak-config$/.test(destination);
  }
  return false;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function localPrivateArchiveRunAllowed(invocation, args, processId) {
  const prefix = ["run", "--rm", "--network", "none", "--user", "1000:1000"];
  if (args.length !== 14 || !sameStringArray(args.slice(0, prefix.length), prefix)
    || args[6] !== "-v" || args[8] !== "-v" || args[10] !== invocation.nodeImage
    || !sameStringArray(args.slice(11, 13), ["sh", "-lc"])) return false;
  const workSuffix = ":/work:ro";
  const outputSuffix = ":/backup";
  const work = args[7].endsWith(workSuffix) ? args[7].slice(0, -workSuffix.length) : "";
  const output = args[9].endsWith(outputSuffix) ? args[9].slice(0, -outputSuffix.length) : "";
  const families = [
    ["platform-minio-data-", /\/platform-minio-data-[A-Za-z0-9_-]+\/minio-data$/, "minio-data"],
    ["platform-keycloak-config-", /\/platform-keycloak-config-[A-Za-z0-9_-]+\/keycloak-config$/, "keycloak-config"],
    ["infra-secret-manager-metadata-", /\/infra-secret-manager-metadata-[A-Za-z0-9_-]+$/, "secret-manager-metadata"],
  ];
  const family = families.find(([prefix, pattern]) => work.includes(`/${prefix}`) && pattern.test(work));
  if (!family || !pathInside(path.join(invocation.roots.dataHost, ".tmp/ops"), work)
    || output !== invocation.roots.stagingHost) return false;
  const archive = args[13].match(/^tar -czf \/backup\/'([^']+)' -C \/work \.$/);
  return Boolean(archive)
    && new RegExp(`^\\.${family[2]}-[0-9]{8}-[0-9]{6}\\.tar\\.gz\\.staging-${processId}-[a-f0-9]{24}$`).test(archive[1]);
}

function localPrivateResticBackupTailAllowed(tail) {
  if (!sameStringArray(tail.slice(0, 2), ["backup", "--json"])) return false;
  const firstTag = tail.indexOf("--tag", 2);
  if (firstTag < 3) return false;
  const paths = tail.slice(2, firstTag);
  if (new Set(paths).size !== paths.length || paths.some((entry) => {
    const value = String(entry ?? "");
    return !value.startsWith("/backups/") || value.includes("\\") || value.includes("\0")
      || value.split("/").some((part) => part === ".." || part === ".");
  })) return false;
  return paths.filter((entry) => /^\/backups\/manifests\/[A-Za-z0-9._-]+\.json$/.test(entry)).length === 1
    && tail.length === firstTag + 8
    && tail[firstTag + 1] === "platform-backups"
    && tail[firstTag + 2] === "--tag"
    && /^platform-manifest-id=[a-z0-9][a-z0-9._:-]{0,159}$/.test(tail[firstTag + 3])
    && tail[firstTag + 4] === "--tag"
    && /^platform-manifest-digest=[a-f0-9]{64}$/.test(tail[firstTag + 5])
    && tail[firstTag + 6] === "--host"
    && tail[firstTag + 7] === "platform-infrastructure";
}

function localPrivateOffsiteRunAllowed(invocation, args, options) {
  const prefix = [
    "run", "--rm", "--network", invocation.egressNetwork, "--user", "1000:1000",
    "-e", "HOME=/tmp", "-e", "XDG_CACHE_HOME=/tmp/.cache",
  ];
  if (!sameStringArray(args.slice(0, prefix.length), prefix)) return false;
  const configMount = `${path.join(invocation.roots.brokerStateHost, "rclone-refresh")}:/rclone-config:rw`;
  const passwordMount = `${path.join(invocation.roots.secretsHost, "restic_password.txt")}:/restic-password/restic_password.txt:ro`;
  const backupMount = `${invocation.roots.backupHost}:/backups:ro`;
  const rcloneEnv = "RCLONE_CONFIG=/rclone-config/rclone.conf";
  const image = invocation.receipt.resources.offsite.resticImageId;
  const repository = invocation.receipt.resources.offsite.repository;
  const resticBase = [
    ...prefix,
    "-e", "RESTIC_REPOSITORY", "-e", "RESTIC_PASSWORD_FILE", "-e", rcloneEnv,
  ];
  if (sameStringArray(args.slice(0, resticBase.length), resticBase)) {
    const remainder = args.slice(resticBase.length);
    let tail;
    if (sameStringArray(remainder.slice(0, 7), [
      "-v", backupMount, "-v", configMount, "-v", passwordMount, image,
    ])) tail = remainder.slice(7);
    else if (sameStringArray(remainder.slice(0, 5), [
      "-v", configMount, "-v", passwordMount, image,
    ])) tail = remainder.slice(5);
    else return false;
    const exactProcessEnv = sameStringArray(Object.keys(options.env ?? {}).sort(), ["RESTIC_PASSWORD_FILE", "RESTIC_REPOSITORY"])
      && options.env?.RESTIC_REPOSITORY === repository
      && options.env?.RESTIC_PASSWORD_FILE === "/restic-password/restic_password.txt";
    if (!exactProcessEnv) return false;
    return localPrivateResticBackupTailAllowed(tail)
      || sameStringArray(tail, [
        "forget", "--tag", "platform-backups", "--group-by", "tags", "--keep-last", "42", "--prune",
      ]);
  }
  const size = [
    ...prefix,
    "--entrypoint", "rclone", "-e", rcloneEnv, "-v", configMount, image,
    "size", repository.replace(/^rclone:/, ""), "--json",
  ];
  return sameStringArray(args, size) && options.env === undefined;
}

function localPrivateOffsiteRestoreRunAllowed(invocation, args, options) {
  const requestSha256 = String(invocation.requestSha256 ?? "");
  const short = requestSha256.slice(0, 12);
  const expected = invocation.receipt.resources.offsite.restore;
  if (!SHA256.test(requestSha256) || !expected || expected.snapshotId !== String(expected.snapshotId)
    || !SHA256.test(String(expected.snapshotId ?? ""))) return false;
  const snapshotsName = `gf-restic-snapshots-${short}`;
  const restoreName = `gf-restic-restore-${short}`;
  const name = args[3];
  if (!sameStringArray(args.slice(0, 3), ["run", "--rm", "--name"])
    || ![snapshotsName, restoreName].includes(name)) return false;
  const prefix = [
    "--pull", "never",
    "--network", invocation.egressNetwork,
    "--read-only",
    "--user", "1000:1000",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true",
    "--pids-limit", "128",
    "--log-driver", "none",
    "--label", `com.platform.local-private.offsite-restore-request-sha256=${requestSha256}`,
    "--label", `com.platform.local-private.offsite-restore-role=${name === snapshotsName ? "snapshots" : "restore"}`,
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777",
    "-e", "HOME=/tmp",
    "-e", "XDG_CACHE_HOME=/tmp/.cache",
    "-e", "RESTIC_REPOSITORY",
    "-e", "RESTIC_PASSWORD_FILE",
    "-e", "RCLONE_CONFIG=/rclone-config/rclone.conf",
    "--mount", `type=bind,src=${path.join(invocation.roots.brokerStateHost, "rclone-refresh")},dst=/rclone-config`,
    "--mount", `type=bind,src=${path.join(invocation.roots.secretsHost, "restic_password.txt")},dst=/restic-password/restic_password.txt,readonly`,
  ];
  if (!sameStringArray(args.slice(4, 4 + prefix.length), prefix)) return false;
  const exactProcessEnv = sameStringArray(Object.keys(options.env ?? {}).sort(), ["RESTIC_PASSWORD_FILE", "RESTIC_REPOSITORY"])
    && options.env.RESTIC_REPOSITORY === invocation.receipt.resources.offsite.repository
    && options.env.RESTIC_PASSWORD_FILE === "/restic-password/restic_password.txt";
  if (!exactProcessEnv) return false;
  const remainder = args.slice(4 + prefix.length);
  const image = invocation.receipt.resources.offsite.resticImageId;
  if (name === snapshotsName) {
    return sameStringArray(remainder, [
      image, "--no-lock", "snapshots", "--json", "--tag", "platform-backups",
    ]);
  }
  const scratch = path.join(invocation.roots.dataHost, ".offsite-restore-proof", requestSha256);
  return sameStringArray(remainder, [
    "--mount", `type=bind,src=${scratch},dst=/restore`, image,
    "--no-lock", "restore", expected.snapshotId, "--target", "/restore",
  ]);
}

function localPrivateOffsiteRestoreControlAllowed(invocation, args, options) {
  if (options.env !== undefined || options.input !== undefined) return false;
  const short = String(invocation.requestSha256 ?? "").slice(0, 12);
  const roles = new Map([
    [`gf-restic-snapshots-${short}`, "snapshots"],
    [`gf-restic-restore-${short}`, "restore"],
  ]);
  if (args[0] === "ps") {
    return Object.keys(options).length === 0 && [...roles.keys()].some((name) => sameStringArray(args, [
      "ps", "-aq", "--no-trunc", "--filter", `name=^/${name}$`,
    ]));
  }
  const binding = options.restoreContainer;
  if (!plainRecord(binding)
    || !sameStringArray(Object.keys(options), ["restoreContainer"])
    || !sameStringArray(Object.keys(binding).sort(), ["id", "name", "role"])
    || !/^[a-f0-9]{64}$/.test(String(binding.id ?? ""))
    || roles.get(binding.name) !== binding.role || args.at(-1) !== binding.id) return false;
  return (args[0] === "container" && args[1] === "inspect" && args.length === 3)
    || (args[0] === "rm" && args[1] === "-f" && args.length === 3);
}

export function localPrivateBackupDockerInvocationAllowed(invocation, args, options = {}, processId = process.pid) {
  if (!invocation || !LOCAL_PRIVATE_ALLOWED_ACTIONS.includes(invocation.action)
    || !Array.isArray(args) || args.length < 1 || args.length > 2048
    || args.some((item) => typeof item !== "string" || !item || item.length > 4096 || item.includes("\0"))
    || options.input !== undefined) return false;
  if (invocation.action === "backup.offsite.sync") {
    return localPrivateOffsiteRunAllowed(invocation, args, options);
  }
  if (invocation.action === "restore.offsite.proof") {
    return localPrivateOffsiteRestoreRunAllowed(invocation, args, options)
      || localPrivateOffsiteRestoreControlAllowed(invocation, args, options);
  }
  return localPrivateExecAllowed(invocation, args)
    || localPrivateCopyAllowed(invocation, args, processId)
    || localPrivateArchiveRunAllowed(invocation, args, processId);
}

export function assertLocalPrivateBackupDockerInvocation(invocation, args, options = {}) {
  if (!localPrivateBackupDockerInvocationAllowed(invocation, args, options)) {
    fail("LOCAL_PRIVATE backup requested a Docker operation outside its signed closed action contract");
  }
}
