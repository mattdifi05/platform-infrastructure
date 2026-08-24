#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const ROOT = path.resolve(import.meta.dirname, "..");
const PRODUCER = path.join(import.meta.dirname, "v1-local-private-evidence-producer.py");
const INFRA_OPS = path.join(import.meta.dirname, "infra-ops.mjs");
const PYTHON = "/usr/bin/python3";
const BUNDLED_NODE = "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node";
const NODE = fs.existsSync(BUNDLED_NODE) ? BUNDLED_NODE : process.execPath;
const FAMILIES = [
  "anniversary", "fiplatform", "matthewdifilippo", "opstudents",
  "public", "stexor", "stream", "workcalendar", "pg-stexor",
  "pg-keycloak", "mariadb", "minio", "keycloak-config", "confidential",
];

const LOGICAL = {
  state: "/var/lib/platform-infrastructure/v1/local-private",
  predeploy: "/var/lib/platform-infrastructure/v1/predeploy/current",
  live: "/home/platform_infrastructure/platform-infrastructure",
  source: "/home/platform_infrastructure/src",
};
LOGICAL.authority = `${LOGICAL.state}/exact-release-authority.json`;
LOGICAL.reconciliation = `${LOGICAL.state}/reconciliation.json`;
LOGICAL.journal = `${LOGICAL.state}/reconcile-journal.json`;
LOGICAL.renderEnv = `${LOGICAL.state}/exact-compose.env`;
LOGICAL.passphrase = `${LOGICAL.state}/confidential-backup-passphrase`;
LOGICAL.archive = `${LOGICAL.predeploy}/exact-source-archive.tar`;
LOGICAL.install = `${LOGICAL.predeploy}/install-checkpoint.json`;
LOGICAL.checkpoint = `${LOGICAL.predeploy}/local-private-checkpoint.json`;
LOGICAL.recoveryExport = `${LOGICAL.predeploy}/scheduler-recovery-image.tar`;
LOGICAL.logicalEvidence = `${LOGICAL.predeploy}/logical-backup-evidence.json`;
LOGICAL.offhostEvidence = `${LOGICAL.predeploy}/offhost-backup-evidence.json`;
LOGICAL.restoreEvidence = `${LOGICAL.predeploy}/restore-evidence.json`;
LOGICAL.runtimeEvidence = `${LOGICAL.predeploy}/runtime-inventory-evidence.json`;
LOGICAL.secretsEvidence = `${LOGICAL.predeploy}/secrets-backup-evidence.json`;
LOGICAL.secrets = `${LOGICAL.live}/secrets`;
LOGICAL.backups = `${LOGICAL.live}/backups`;
LOGICAL.projectState = `${LOGICAL.live}/projects-portal/state`;
Object.freeze(LOGICAL);

const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const stableJson = (value) => Array.isArray(value)
  ? `[${value.map(stableJson).join(",")}]`
  : value && typeof value === "object"
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`
    : JSON.stringify(value);
const canonicalBytes = (value) => Buffer.from(`${stableJson(value)}\n`);
const mapPath = (fixture, logical) => path.join(fixture.root, logical.replace(/^\/+/, ""));

function writeFile(filename, value, mode = 0o600) {
  fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filename, value, { mode: 0o600 });
  fs.chmodSync(filename, mode);
}

function writeLogical(fixture, logical, value, mode = 0o600) {
  writeFile(mapPath(fixture, logical), value, mode);
}

function writeCanonical(fixture, logical, value, mode = 0o400) {
  writeLogical(fixture, logical, canonicalBytes(value), mode);
}

function readCanonical(fixture, logical) {
  return JSON.parse(fs.readFileSync(mapPath(fixture, logical), "utf8"));
}

function executable(filename, source) {
  writeFile(filename, `#!${NODE}\n${source}`, 0o700);
}

function run(command, args, options = {}) {
  return spawnSync(command, args, {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    ...options,
  });
}

function requireSuccess(result, label) {
  assert.equal(result.error, undefined, `${label}: ${result.error?.message ?? "spawn error"}`);
  assert.equal(result.status, 0, `${label}\nstdout: ${result.stdout}\nstderr: ${result.stderr}`);
}

function makeInfraStub(filename, fixtureRoot) {
  executable(filename, String.raw`
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const fixtureRoot = ${JSON.stringify(fixtureRoot)};
const stateRoot = path.join(fixtureRoot, "stub-state");
const logFile = path.join(stateRoot, "infra.jsonl");
const families = ${JSON.stringify(FAMILIES.slice(0, 8))};
const [operation, ...args] = process.argv.slice(2);
fs.mkdirSync(stateRoot, { recursive: true, mode: 0o700 });
fs.appendFileSync(logFile, JSON.stringify({ operation, args }) + "\n", { mode: 0o600 });

const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const stable = (value) => Array.isArray(value)
  ? "[" + value.map(stable).join(",") + "]"
  : value && typeof value === "object"
    ? "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + stable(value[key])).join(",") + "}"
    : JSON.stringify(value);
const sign = (filename) => {
  const bytes = fs.readFileSync(filename);
  const digest = sha(bytes);
  const [keyId, secret] = fs.readFileSync(process.env.BACKUP_SIGNING_KEYS_FILE, "utf8").trim().split(",")[0].split("=", 2);
  const message = "platform-postgres-backup-v1\n" + path.basename(filename) + "\n" + digest + "\n";
  const signature = crypto.createHmac("sha256", secret).update(message).digest("base64url");
  fs.writeFileSync(filename + ".sha256", digest + "  " + path.basename(filename) + "\n", { mode: 0o600 });
  fs.writeFileSync(filename + ".sig.json", stable({
    algorithm: "HMAC-SHA256", artifact: path.basename(filename), keyId, sha256: digest,
    signature, signedAt: "2030-01-01T00:00:00Z", version: 1,
  }) + "\n", { mode: 0o600 });
};
const counterFile = path.join(stateRoot, "artifact-counter");
const nextCounter = () => {
  const value = fs.existsSync(counterFile) ? Number(fs.readFileSync(counterFile, "utf8")) + 1 : 1;
  fs.writeFileSync(counterFile, String(value), { mode: 0o600 });
  return String(value).padStart(4, "0");
};
const output = (relative, bytes) => {
  const filename = path.join(process.env.PLATFORM_DATA_ROOT, "backups", relative);
  fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filename, bytes, { mode: 0o600 });
  sign(filename);
  return filename;
};
const excluded = (name) => name === ".env" || name.startsWith(".env.") || /\.(?:pem|key|p12|pfx|dump|sql|sqlite|sqlite3)$/.test(name);
const selectedEntries = (slug) => {
  const root = path.join(process.env.PROJECT_SOURCE_ROOT, slug);
  const result = [slug];
  const visit = (directory, relative) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const childRelative = path.join(relative, entry.name);
      if ([".git", ".hg", ".svn", "node_modules", "vendor", ".next", ".nuxt", "dist", "build", "coverage", ".cache", ".turbo", ".parcel-cache", "backups", ".codex-backups"].includes(entry.name) || excluded(entry.name)) continue;
      if (entry.isDirectory()) { result.push(childRelative); visit(path.join(directory, entry.name), childRelative); }
      else if (entry.isFile()) result.push(childRelative);
      else throw new Error("fixture source contains unsupported entry");
    }
  };
  visit(root, slug);
  return result;
};
const requireExact = (expected) => {
  if (JSON.stringify(args) !== JSON.stringify(expected)) throw new Error("unexpected " + operation + " arguments: " + JSON.stringify(args));
};
const comparatorReceipt = (operation, artifactSha256) => {
  const fingerprintSha = sha("comparator:" + operation + ":" + artifactSha256);
  const component = (value) => ({ firstRestore: value, matched: true, secondRestore: value });
  let counts;
  let scope;
  let semanticComparator;
  if (operation === "restore-test-postgres") {
    const fingerprint = {
      combinedSha256: fingerprintSha, largeObjectBytes: 0, largeObjectRows: 0, largeObjectsSha256: fingerprintSha,
      relationCount: 1, rowCount: 1, rowDataSha256: fingerprintSha, schemaBytes: 1, schemaLines: 1,
      sequenceCount: 1, sequencesSha256: fingerprintSha, structureSha256: fingerprintSha,
    };
    counts = { restoredTables: 1 }; scope = "same-artifact-independent-double-restore";
    semanticComparator = {
      algorithm: "sha256", components: {
        largeObjectsSha256: component(fingerprintSha), rowDataSha256: component(fingerprintSha),
        sequencesSha256: component(fingerprintSha), structureSha256: component(fingerprintSha),
      }, engine: "postgres", firstRestore: fingerprint, firstRestoreSha256: fingerprintSha, matched: true,
      scope, secondRestore: fingerprint, secondRestoreSha256: fingerprintSha,
      version: "platform.database-restore-semantic-comparator/v1",
    };
  } else if (operation === "restore-test-mariadb") {
    const fingerprint = {
      combinedSha256: fingerprintSha, relationCount: 1, rowCount: 1, rowDataSha256: fingerprintSha,
      schemaBytes: 1, schemaCount: 1, schemaLines: 1, schemaSetSha256: fingerprintSha,
      structureSha256: fingerprintSha,
    };
    counts = { restoredSchemas: 1, restoredTables: 1 }; scope = "same-artifact-independent-double-restore";
    semanticComparator = {
      algorithm: "sha256", components: {
        rowDataSha256: component(fingerprintSha), schemaSetSha256: component(fingerprintSha),
        structureSha256: component(fingerprintSha),
      }, engine: "mariadb", firstRestore: fingerprint, firstRestoreSha256: fingerprintSha, matched: true,
      scope, secondRestore: fingerprint, secondRestoreSha256: fingerprintSha,
      version: "platform.database-restore-semantic-comparator/v1",
    };
  } else if (operation === "restore-test-minio") {
    const exclusions = [".minio.sys/tmp/*", ".minio.sys/buckets/.bloomcycle.bin/xl.meta", ".minio.sys/buckets/.usage.json/xl.meta"];
    const fingerprint = {
      combinedSha256: fingerprintSha, directoryCount: 1, entryCount: 2, excludedPaths: exclusions,
      fileCount: 1, totalFileBytes: 1, treeSha256: fingerprintSha,
    };
    counts = { bootHealthy: true, restoredDurableEntries: 2, sourceDurableEntries: 2 };
    scope = "stable-live-source-before-after-to-isolated-restored-durable-tree";
    semanticComparator = {
      algorithm: "sha256", components: { treeSha256: {
        restored: fingerprintSha, restoredMatchesSource: true, sourceAfter: fingerprintSha,
        sourceBefore: fingerprintSha, sourceStable: true,
      } }, engine: "minio", matched: true, restored: fingerprint, restoredMatchesSource: true,
      restoredSha256: fingerprintSha, scope, sourceAfter: fingerprint, sourceAfterSha256: fingerprintSha,
      sourceBefore: fingerprint, sourceBeforeSha256: fingerprintSha, sourceStable: true,
      version: "platform.minio-restore-tree-comparator/v1", volatileExclusions: exclusions,
    };
  } else {
    const fingerprint = {
      archiveTreeSha256: fingerprintSha, canonicalContentSha256: fingerprintSha, combinedSha256: fingerprintSha,
      fileCount: 1, jsonCount: 1, rawJsonSetSha256: fingerprintSha, realmCount: 1, totalJsonBytes: 1,
    };
    counts = { jsonCount: 1, realmCount: 1 }; scope = "same-artifact-independent-double-extract-and-parse";
    semanticComparator = {
      algorithm: "sha256", components: {
        archiveTreeSha256: component(fingerprintSha), canonicalContentSha256: component(fingerprintSha),
        rawJsonSetSha256: component(fingerprintSha),
      }, engine: "keycloak", firstRestore: fingerprint, firstRestoreSha256: fingerprintSha, matched: true,
      scope, secondRestore: fingerprint, secondRestoreSha256: fingerprintSha,
      version: "platform.keycloak-config-restore-semantic-comparator/v1",
    };
  }
  return { artifactSha256, counts, matched: true, operation, schema: "platform.v1.restore-evidence-receipt/v1", scope, semanticComparator };
};

if (operation === "backup-applications") {
  requireExact([]);
  for (const slug of families) {
    const filename = path.join(process.env.PLATFORM_DATA_ROOT, "backups", "applications", slug, slug + "-" + nextCounter() + ".tar.gz");
    fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
    const stage = path.join(stateRoot, "application-stage", slug);
    fs.rmSync(stage, { recursive: true, force: true });
    for (const relative of selectedEntries(slug)) {
      const source = path.join(process.env.PROJECT_SOURCE_ROOT, relative);
      const destination = path.join(path.dirname(stage), relative);
      const metadata = fs.lstatSync(source);
      if (metadata.isDirectory()) fs.mkdirSync(destination, { recursive: true, mode: metadata.mode & 0o777 });
      else { fs.mkdirSync(path.dirname(destination), { recursive: true }); fs.copyFileSync(source, destination); fs.chmodSync(destination, metadata.mode & 0o777); }
    }
    const result = spawnSync("/usr/bin/tar", ["-czf", filename, "-C", path.dirname(stage), slug], { encoding: "utf8", env: { ...process.env, COPYFILE_DISABLE: "1" } });
    if (result.status !== 0) throw new Error("tar failed: " + result.stderr);
    fs.rmSync(stage, { recursive: true, force: true });
    fs.chmodSync(filename, 0o600); sign(filename);
  }
} else if (operation === "backup-postgres") {
  const database = args[args.indexOf("--database") + 1];
  requireExact(["--database", database, "--container", "enterprise-postgres", "--user", "postgres"]);
  if (!["stexor", "keycloak"].includes(database)) throw new Error("foreign postgres database");
  output(path.join("postgres", database + "-" + nextCounter() + ".dump"), Buffer.from("PG:" + database + "\n"));
} else if (operation === "backup-mariadb") {
  requireExact(["--container", "mariadb"]);
  output(path.join("mariadb", "mariadb-all-" + nextCounter() + ".sql.gz"), Buffer.from("MARIADB\n"));
} else if (operation === "backup-minio") {
  requireExact(["--container", "enterprise-minio"]);
  output(path.join("minio", "minio-data-" + nextCounter() + ".tar.gz"), Buffer.from("MINIO\n"));
} else if (operation === "backup-keycloak") {
  requireExact(["--container", "enterprise-keycloak"]);
  output(path.join("keycloak", "keycloak-config-" + nextCounter() + ".tar.gz"), Buffer.from("KEYCLOAK\n"));
} else if (operation === "backup-secret-manager-metadata") {
  requireExact([]);
  output(path.join("secret-manager", "secret-manager-metadata-" + nextCounter() + ".tar.gz"), Buffer.from("SECRET-METADATA-NO-VALUES\n"));
} else if (operation.startsWith("restore-test-")) {
  const backupIndex = args.indexOf("--backupFile");
  const backupFile = args[1]?.startsWith("/") && !args[1].startsWith(fixtureRoot)
    ? path.join(fixtureRoot, args[1].replace(/^\/+/, "")) : args[1];
  const immutableRoot = path.resolve(fixtureRoot, "dev", "shm") + path.sep;
  if (
    backupIndex !== 0 || !backupFile || !path.resolve(backupFile).startsWith(immutableRoot)
    || !path.resolve(backupFile).includes("-transaction" + path.sep + "artifact-staging" + path.sep)
    || path.resolve(backupFile).startsWith(path.resolve(process.env.PLATFORM_DATA_ROOT, "backups") + path.sep)
  ) {
    throw new Error("restore backupFile is not the immutable transaction snapshot");
  }
  if (!fs.statSync(backupFile).isFile()) throw new Error("restore backupFile is absent");
  const exact = {
    "restore-test-postgres": args[3] === "stexor"
      ? ["--backupFile", args[1], "--database", "stexor", "--countAllUserTables", "true", "--minimumTables", "1", "--v1EvidenceReceipt", "true"]
      : ["--backupFile", args[1], "--database", "keycloak", "--countAllUserTables", "true", "--minimumTables", "1", "--v1EvidenceReceipt", "true"],
    "restore-test-mariadb": ["--backupFile", args[1], "--container", "mariadb", "--minSchemas", "1", "--v1EvidenceReceipt", "true"],
    "restore-test-minio": ["--backupFile", args[1], "--container", "enterprise-minio", "--v1EvidenceReceipt", "true"],
    "restore-test-keycloak": ["--backupFile", args[1], "--container", "enterprise-keycloak", "--minRealms", "1", "--v1EvidenceReceipt", "true"],
  }[operation];
  requireExact(exact);
  const receipt = comparatorReceipt(operation, sha(fs.readFileSync(backupFile)));
  fs.appendFileSync(path.join(stateRoot, "comparator-receipts.jsonl"), stable(receipt) + "\n", { mode: 0o600 });
  process.stdout.write("V1_EVIDENCE_RECEIPT:" + stable(receipt) + "\n");
} else {
  throw new Error("foreign infra operation " + operation);
}
process.stdout.write("V1_EVIDENCE_EXECUTOR_LAST_ID:" + process.env.PLATFORM_V1_EVIDENCE_EXECUTOR_START_ID + "\n");
`);
}

function makeGpgStub(filename) {
  executable(filename, String.raw`
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
const args = process.argv.slice(2);
const transform = (bytes) => Buffer.from(Uint8Array.from(bytes, (value) => value ^ 0x5a));
const cleanTar = (bytes) => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "v1-gpg-stub-"));
  const input = path.join(temporary, "input.tar");
  const output = path.join(temporary, "output.tar");
  fs.writeFileSync(input, bytes);
  const filter = "import sys,tarfile; source=tarfile.open(sys.argv[1], 'r:'); target=tarfile.open(sys.argv[2], 'w:'); [(target.addfile(member, source.extractfile(member) if member.isfile() else None)) for member in source.getmembers() if not any(part.startswith('._') for part in member.name.split('/'))]; target.close(); source.close()";
  const result = spawnSync("/usr/bin/python3", ["-c", filter, input, output], { encoding: "utf8" });
  if (result.status !== 0) throw new Error("fixture GPG tar filter failed");
  const cleaned = fs.readFileSync(output);
  fs.rmSync(temporary, { recursive: true, force: true });
  return cleaned;
};
if (args.includes("--symmetric")) {
  const output = args[args.indexOf("--output") + 1];
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  fs.writeFileSync(output, Buffer.concat([Buffer.from("GPG1"), transform(cleanTar(Buffer.concat(chunks)))]), { mode: 0o600 });
} else if (args.includes("--decrypt")) {
  const bytes = fs.readFileSync(args.at(-1));
  if (bytes.subarray(0, 4).toString() !== "GPG1") process.exit(65);
  process.stdout.write(transform(bytes.subarray(4)));
} else process.exit(64);
`);
}

function makeOpenSslStub(filename, fixtureRoot, certificateDer) {
  executable(filename, String.raw`
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
const args = process.argv.slice(2);
if (args[0] === "x509" && args.includes("DER")) {
  process.stdout.write(Buffer.from(${JSON.stringify(certificateDer.toString("base64"))}, "base64"));
} else if (args[0] === "x509" && args.includes("-text")) {
  process.stdout.write("Certificate:\n    Public-Key: (4096 bit)\n");
} else if (args[0] === "cms" && args.includes("-encrypt")) {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const input = Buffer.concat(chunks);
  const digest = crypto.createHash("sha256").update(input).digest();
  const envelope = Buffer.alloc(320, 0xa5);
  Buffer.from("CMS1").copy(envelope); digest.copy(envelope, 4);
  fs.writeFileSync(args[args.indexOf("-out") + 1], envelope, { mode: 0o600 });
  const log = path.join(${JSON.stringify(fixtureRoot)}, "stub-state", "openssl.jsonl");
  fs.mkdirSync(path.dirname(log), { recursive: true });
  fs.appendFileSync(log, JSON.stringify({ action: "cms-encrypt", inputSha256: digest.toString("hex"), size: input.length }) + "\n", { mode: 0o600 });
} else process.exit(64);
`);
}

function makeDockerStub(filename, fixtureRoot) {
  executable(filename, String.raw`
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const fixtureRoot = ${JSON.stringify(fixtureRoot)};
const stateRoot = path.join(fixtureRoot, "stub-state");
const stateFile = path.join(stateRoot, "docker-state.json");
const logFile = path.join(stateRoot, "docker.jsonl");
const args = process.argv.slice(2);
const state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
fs.appendFileSync(logFile, JSON.stringify(args) + "\n", { mode: 0o600 });
const save = () => fs.writeFileSync(stateFile, JSON.stringify(state), { mode: 0o600 });
const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");
const copy = (source, destination) => {
  fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
  fs.copyFileSync(source, destination); fs.chmodSync(destination, 0o600);
};

if (args[0] === "ps") {
  process.stdout.write(state.container.Id + "\n");
} else if (args[0] === "inspect") {
  const container = structuredClone(state.container);
  if (state.unmountedSecret) container.Mounts = [];
  process.stdout.write(JSON.stringify([container]));
} else if (args[0] === "volume" && args[1] === "ls") {
  process.stdout.write("platform_fixture_data\n");
} else if (args[0] === "image" && args[1] === "inspect") {
  const reference = args[2];
  const imageId = state.retargetImage ? "sha256:" + "f".repeat(64) : state.images[reference];
  process.stdout.write(JSON.stringify([{ Id: imageId }]));
} else if (args[0] === "run") {
  const mounts = new Map();
  for (let index = 0; index < args.length - 1; index += 1) {
    if (args[index] !== "-v") continue;
    const raw = args[index + 1];
    const match = raw.match(/^(.*):(\/[^:]+):(ro|rw)$/);
    if (!match) throw new Error("invalid mount " + raw);
    mounts.set(match[2], match[1]);
  }
  const resolveContainer = (filename) => {
    const roots = [...mounts.keys()].sort((a, b) => b.length - a.length);
    const root = roots.find((candidate) => filename === candidate || filename.startsWith(candidate + "/"));
    if (!root) throw new Error("unmapped container path " + filename);
    return path.join(mounts.get(root), filename.slice(root.length).replace(/^\/+/, ""));
  };
  const imageIndex = args.findIndex((item) => /^sha256:[a-f0-9]{64}$/.test(item));
  if (imageIndex < 0) throw new Error("missing immutable image id");
  const command = args.slice(imageIndex + 1);
  const isRclone = args.includes("--entrypoint") && args[args.indexOf("--entrypoint") + 1] === "/usr/local/bin/rclone";
  if (isRclone) {
    if (command[0] !== "copyto" || command.length !== 5 || command[3] !== "--immutable" || command[4] !== "--checksum") {
      throw new Error("invalid rclone tuple " + JSON.stringify(command));
    }
    const [source, destination] = command.slice(1, 3);
    const sourceRemote = source.startsWith("platform-onedrive:");
    const destinationRemote = destination.startsWith("platform-onedrive:");
    if (sourceRemote === destinationRemote) throw new Error("rclone copy must cross the direct remote boundary");
    const remotePath = (value) => path.join(stateRoot, "remote", digest(value));
    if (destinationRemote) copy(resolveContainer(source), remotePath(destination));
    else copy(remotePath(source), resolveContainer(destination));
  } else if (command[0] === "snapshots") {
    const tag = command[command.indexOf("--tag") + 1];
    const host = command[command.indexOf("--host") + 1];
    process.stdout.write(JSON.stringify(state.snapshots.filter((item) => item.hostname === host && item.tags.includes(tag))));
  } else if (command[0] === "backup") {
    const firstTag = command.indexOf("--tag");
    const paths = command.slice(2, firstTag);
    const tag = command[firstTag + 1];
    const secondTag = command[firstTag + 3];
    const host = command[command.indexOf("--host") + 1];
    if (paths.length !== 3 || !secondTag.startsWith("logical-key-") || host !== "platform-v1-local-private") {
      throw new Error("invalid Restic backup tuple " + JSON.stringify(command));
    }
    const id = digest(String(state.snapshots.length + 1) + ":" + tag + ":" + secondTag);
    const snapshotRoot = path.join(stateRoot, "snapshots", id, "backup");
    for (const item of paths) copy(resolveContainer(item), path.join(snapshotRoot, path.basename(item)));
    state.snapshots.push({ hostname: host, id, paths, tags: [tag, secondTag] }); save();
    process.stdout.write(JSON.stringify({ message_type: "summary", snapshot_id: id }) + "\n");
  } else if (command[0] === "restore") {
    if (command.length !== 4 || command[1] !== "--target" || command[2] !== "/restore") {
      throw new Error("invalid Restic restore tuple " + JSON.stringify(command));
    }
    const snapshot = state.snapshots.find((item) => item.id === command[3]);
    if (!snapshot) throw new Error("unknown full snapshot id");
    const sourceRoot = path.join(stateRoot, "snapshots", snapshot.id, "backup");
    const destinationRoot = path.join(resolveContainer("/restore"), "backup");
    fs.mkdirSync(destinationRoot, { recursive: true, mode: 0o700 });
    for (const name of fs.readdirSync(sourceRoot)) copy(path.join(sourceRoot, name), path.join(destinationRoot, name));
  } else {
    throw new Error("foreign Docker run command " + JSON.stringify(command));
  }
} else {
  throw new Error("foreign Docker operation " + JSON.stringify(args));
}
`);
}

function makeExecutorLauncher(filename, fixtureRoot, dockerStub) {
  const source = String.raw`
import base64, fcntl, importlib.util, json, os, socket, subprocess, sys

root = ${JSON.stringify(fixtureRoot)}
docker = ${JSON.stringify(dockerStub)}
producer, operation, entrypoint, fault = sys.argv[1:5]
state = os.path.join(root, "stub-state")
os.makedirs(state, mode=0o700, exist_ok=True)
def physical(logical):
    return os.path.join(root, logical.lstrip("/"))
def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
with open(physical(${JSON.stringify(LOGICAL.authority)}), "rb") as handle:
    authority = json.load(handle)
infra = physical(authority["releaseRoot"] + "/scripts/infra-ops.mjs")
families = ${JSON.stringify(FAMILIES)}
tool = authority["backupToolImages"]["resticRclone"]
def infra_environment(start_id):
    value = dict(os.environ)
    value.update({
        "BACKUP_SIGNING_KEYS_FILE": physical(${JSON.stringify(`${LOGICAL.secrets}/backup_signing_keys.txt`)}),
        "PLATFORM_DATA_ROOT": physical(${JSON.stringify(LOGICAL.live)}),
        "PROJECT_SOURCE_ROOT": physical(${JSON.stringify(LOGICAL.source)}),
        "PLATFORM_V1_EVIDENCE_EXECUTOR_START_ID": str(start_id),
    })
    return value
def run_command(arguments, environment=None):
    return subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/", env=environment, check=False)
def docker_run(arguments):
    return run_command([docker, *arguments])
def workspace(run_id):
    return physical("/dev/shm/platform-v1-evidence-" + run_id + "-transaction")
def artifact_paths(run_id, logical_key):
    index = families.index(logical_key) + 1
    directory = os.path.join(workspace(run_id), "artifact-staging", f"{index:02d}-{logical_key}")
    entries = sorted(os.listdir(directory))
    primary = [name for name in entries if not name.endswith(".sha256") and not name.endswith(".sig.json")]
    if len(entries) != 3 or len(primary) != 1:
        raise ValueError("invalid immutable artifact staging")
    return directory, [primary[0], primary[0] + ".sha256", primary[0] + ".sig.json"]
def restic_base(run_id, mounts):
    area = workspace(run_id)
    return [
        "run", "--rm", "--network", "bridge", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--pids-limit", "256", "--memory", "1g", "--cpus", "1",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=128m",
        "-e", "RESTIC_REPOSITORY=rclone:platform-onedrive:platform-infrastructure/restic",
        "-e", "RESTIC_PASSWORD_FILE=/restic-password/restic_password.txt",
        "-e", "RCLONE_CONFIG=/rclone-config/rclone.conf",
        "-v", os.path.join(area, "restic-password-private") + ":/restic-password:ro",
        "-v", os.path.join(area, "rclone-private") + ":/rclone-config:rw",
        *mounts, tool["imageId"],
    ]
def typed_action(action, parameters, request_id):
    run_id = parameters.get("runId")
    if action == "RUNTIME_INVENTORY":
        ids_result = docker_run(["ps", "-aq", "--no-trunc"])
        if ids_result.returncode != 0: return ids_result
        identifiers = sorted(item for item in ids_result.stdout.decode().splitlines() if item)
        containers = []
        if identifiers:
            inspected = docker_run(["inspect", *identifiers])
            if inspected.returncode != 0: return inspected
            containers = json.loads(inspected.stdout)
        volumes = docker_run(["volume", "ls", "--quiet"])
        if volumes.returncode != 0: return volumes
        body = {"containerIds": identifiers, "containers": containers, "status": "PASS", "volumes": sorted(item for item in volumes.stdout.decode().splitlines() if item)}
        return subprocess.CompletedProcess([], 0, canonical(body), b"")
    if action == "VERIFY_TOOL_IMAGE":
        selected = authority["backupToolImages"][parameters["tool"]]
        inspected = docker_run(["image", "inspect", selected["imageReference"]])
        if inspected.returncode != 0: return inspected
        objects = json.loads(inspected.stdout)
        if len(objects) != 1 or objects[0].get("Id") != selected["imageId"]:
            raise ValueError("retargeted tool image")
        return subprocess.CompletedProcess([], 0, canonical({**selected, "status": "PASS", "tool": parameters["tool"]}), b"")
    infra_operations = {
        "BACKUP_APPLICATIONS": ("backup-applications", []),
        "BACKUP_POSTGRES": ("backup-postgres", ["--database", parameters.get("database"), "--container", "enterprise-postgres", "--user", "postgres"]),
        "BACKUP_MARIADB": ("backup-mariadb", ["--container", "mariadb"]),
        "BACKUP_MINIO": ("backup-minio", ["--container", "enterprise-minio"]),
        "BACKUP_KEYCLOAK": ("backup-keycloak", ["--container", "enterprise-keycloak"]),
        "BACKUP_SECRET_METADATA": ("backup-secret-manager-metadata", []),
    }
    if action in infra_operations:
        infra_operation, arguments = infra_operations[action]
        completed = run_command([infra, infra_operation, *arguments], infra_environment(request_id))
        if completed.returncode != 0: return completed
        return subprocess.CompletedProcess([], 0, canonical({"action": action, "status": "PASS"}), b"")
    restore_operations = {
        "RESTORE_POSTGRES": "restore-test-postgres", "RESTORE_MARIADB": "restore-test-mariadb",
        "RESTORE_MINIO": "restore-test-minio", "RESTORE_KEYCLOAK": "restore-test-keycloak",
    }
    if action in restore_operations:
        logical_key = parameters.get("logicalKey") or {"RESTORE_MARIADB": "mariadb", "RESTORE_MINIO": "minio", "RESTORE_KEYCLOAK": "keycloak-config"}[action]
        directory, names = artifact_paths(run_id, logical_key)
        backup_file = os.path.join(directory, names[0])
        if action == "RESTORE_POSTGRES":
            database = "stexor" if logical_key == "pg-stexor" else "keycloak"
            arguments = ["--backupFile", backup_file, "--database", database, "--countAllUserTables", "true", "--minimumTables", "1", "--v1EvidenceReceipt", "true"]
        elif action == "RESTORE_MARIADB":
            arguments = ["--backupFile", backup_file, "--container", "mariadb", "--minSchemas", "1", "--v1EvidenceReceipt", "true"]
        elif action == "RESTORE_MINIO":
            arguments = ["--backupFile", backup_file, "--container", "enterprise-minio", "--v1EvidenceReceipt", "true"]
        else:
            arguments = ["--backupFile", backup_file, "--container", "enterprise-keycloak", "--minRealms", "1", "--v1EvidenceReceipt", "true"]
        completed = run_command([infra, restore_operations[action], *arguments], infra_environment(request_id))
        if completed.returncode != 0: return completed
        prefix = b"V1_EVIDENCE_RECEIPT:"
        receipts = [line[len(prefix):] for line in completed.stdout.splitlines() if line.startswith(prefix)]
        if len(receipts) != 1: raise ValueError("missing comparator receipt")
        return subprocess.CompletedProcess([], 0, canonical({"action": action, "comparatorReceipt": json.loads(receipts[0]), "status": "PASS"}), b"")
    if action.startswith("RESTIC_"):
        logical_key = parameters["logicalKey"]
        directory, names = artifact_paths(run_id, logical_key)
        tag = "local-private-v1-" + run_id
        if action == "RESTIC_SNAPSHOTS":
            command = ["snapshots", "--json", "--tag", tag, "--host", "platform-v1-local-private"]
            mounts = ["-v", directory + ":/backup:ro"]
        elif action == "RESTIC_BACKUP":
            command = ["backup", "--json", *["/backup/" + name for name in names], "--tag", tag, "--tag", "logical-key-" + logical_key, "--host", "platform-v1-local-private"]
            mounts = ["-v", directory + ":/backup:ro"]
        else:
            readback = os.path.join(workspace(run_id), f"readback-{families.index(logical_key) + 1:02d}")
            command = ["restore", "--target", "/restore", parameters["snapshotId"]]
            mounts = ["-v", readback + ":/restore:rw"]
        return docker_run([*restic_base(run_id, mounts), *command])
    if action in ("ESCROW_UPLOAD", "ESCROW_READBACK"):
        name = "v1-local-private-recovery-" + run_id + ".cms"
        area = workspace(run_id)
        remote = "platform-onedrive:platform-infrastructure/key-escrow/" + name
        if action == "ESCROW_UPLOAD":
            mounts = ["-v", os.path.join(area, "cms-recovery-envelope") + ":/envelope:ro", "--entrypoint", "/usr/local/bin/rclone"]
            operands = ["/envelope/" + name, remote]
        else:
            mounts = ["-v", os.path.join(area, "cms-recovery-readback") + ":/readback:rw", "--entrypoint", "/usr/local/bin/rclone"]
            operands = [remote, "/readback/" + name]
        return docker_run([*restic_base(run_id, mounts), "copyto", *operands, "--immutable", "--checksum"])
    raise ValueError("foreign typed action " + str(action))
lock_path = os.path.join(root, "run/lock/platform-v1-local-private-transaction.lock")
os.makedirs(os.path.dirname(lock_path), mode=0o755, exist_ok=True)
lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
os.fchmod(lock_fd, 0o600)
fcntl.flock(lock_fd, fcntl.LOCK_EX)
if lock_fd != 3:
    os.dup2(lock_fd, 3, inheritable=True)
    os.close(lock_fd)
else:
    os.set_inheritable(3, True)

producer_socket, server_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
pid = os.fork()
if pid == 0:
    producer_socket.close()
    pending = b""
    expected_id = 1
    bound_run_id = None
    mutated_live_backups = False
    with open(os.path.join(state, "executor.jsonl"), "ab", buffering=0) as log:
        while True:
            chunk = server_socket.recv(1024 * 1024)
            if not chunk:
                break
            pending += chunk
            while b"\n" in pending:
                frame, pending = pending.split(b"\n", 1)
                frame += b"\n"
                try:
                    request = json.loads(frame.decode("utf-8"), object_pairs_hook=lambda pairs: dict(pairs) if len(pairs) == len(dict(pairs)) else (_ for _ in ()).throw(ValueError("duplicate")))
                    expected = (json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    if frame != expected or set(request) != {"action", "id", "parameters"} or request["id"] != expected_id:
                        raise ValueError("noncanonical request")
                    expected_id += 1
                    log.write(frame)
                    run_id = request["parameters"].get("runId")
                    if run_id is not None:
                        if bound_run_id is None: bound_run_id = run_id
                        if run_id != bound_run_id: raise ValueError("cross-run executor request")
                    if fault == "mutate-live-after-snapshot" and request["action"].startswith("RESTORE_") and not mutated_live_backups:
                        for current, _, files in os.walk(physical(${JSON.stringify(LOGICAL.backups)})):
                            for name in files:
                                if name.endswith(".sha256") or name.endswith(".sig.json"): continue
                                with open(os.path.join(current, name), "wb") as handle: handle.write(b"MUTATED LIVE AFTER IMMUTABLE SNAPSHOT\n")
                        mutated_live_backups = True
                    completed = typed_action(request["action"], request["parameters"], request["id"])
                    response = {
                        "id": request["id"], "status": completed.returncode,
                        "stderrBase64": base64.b64encode(completed.stderr).decode("ascii"),
                        "stdoutBase64": base64.b64encode(completed.stdout).decode("ascii"),
                    }
                except BaseException as error:
                    response = {"id": -1, "status": 70, "stderrBase64": base64.b64encode(str(error).encode()).decode(), "stdoutBase64": ""}
                if fault == "id-mismatch":
                    response["id"] += 1
                if fault == "noncanonical":
                    encoded = (json.dumps(response, sort_keys=False, indent=1) + "\n").encode()
                else:
                    encoded = (json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode()
                server_socket.sendall(encoded)
    server_socket.close()
    os._exit(0)

server_socket.close()
socket_fd = producer_socket.detach()
if socket_fd != 4:
    os.dup2(socket_fd, 4, inheritable=True)
    os.close(socket_fd)
else:
    os.set_inheritable(4, True)
environment = dict(os.environ)
environment["PLATFORM_V1_EVIDENCE_SHARED_LOCK_FD"] = "3"
environment["PLATFORM_V1_EVIDENCE_EXECUTOR_FD"] = "4"
os.environ.clear(); os.environ.update(environment)
if entrypoint == "cli":
    os.execve("/usr/bin/python3", ["/usr/bin/python3", "-I", producer, operation], environment)
if entrypoint != "produce":
    raise SystemExit(64)
sys.argv = [producer]
spec = importlib.util.spec_from_file_location("fixture_evidence_producer", producer)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
receipt = module.produce(operation)
sys.stdout.buffer.write(module.canonical_bytes(receipt))
`;
  writeFile(filename, source, 0o700);
}

function createFixture() {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "v1-evidence-producer-")));
  fs.chmodSync(root, 0o700);
  const fixture = { root };
  const bin = path.join(root, "fixture-bin");
  const archiveSource = path.join(root, "archive-source");
  const certificateBytes = Buffer.from("FIXTURE RECOVERY CERTIFICATE - NOT A CREDENTIAL\n");
  const certificateDer = Buffer.from("fixture-recovery-certificate-der-4096");
  const commit = sha("fixture-candidate-commit").slice(0, 40);
  const tree = sha("fixture-candidate-tree").slice(0, 40);

  fs.mkdirSync(path.join(archiveSource, "scripts"), { recursive: true, mode: 0o700 });
  fs.copyFileSync(PRODUCER, path.join(archiveSource, "scripts", "v1-local-private-evidence-producer.py"));
  fs.mkdirSync(path.dirname(mapPath(fixture, LOGICAL.archive)), { recursive: true, mode: 0o700 });
  const archiveResult = run("/usr/bin/tar", [
    "-cf", mapPath(fixture, LOGICAL.archive), "-C", archiveSource,
    "scripts/v1-local-private-evidence-producer.py",
  ]);
  requireSuccess(archiveResult, "fixture source archive");
  fs.chmodSync(mapPath(fixture, LOGICAL.archive), 0o400);
  const archiveSha = sha(fs.readFileSync(mapPath(fixture, LOGICAL.archive)));
  const releaseRoot = `/srv/platform-infrastructure/releases/${commit}-${archiveSha}`;
  const releaseProducer = mapPath(fixture, `${releaseRoot}/scripts/v1-local-private-evidence-producer.py`);
  const releaseInfra = mapPath(fixture, `${releaseRoot}/scripts/infra-ops.mjs`);
  const certificateLogical = `${releaseRoot}/config/local-private-recovery-escrow-cert.pem`;
  fs.mkdirSync(path.dirname(releaseProducer), { recursive: true, mode: 0o700 });
  fs.copyFileSync(PRODUCER, releaseProducer);
  fs.chmodSync(releaseProducer, 0o500);
  assert.equal(sha(fs.readFileSync(releaseProducer)), sha(fs.readFileSync(PRODUCER)), "ordinary producer SHA must bind exact bytes");
  makeInfraStub(releaseInfra, root);
  writeLogical(fixture, certificateLogical, certificateBytes, 0o400);

  const docker = path.join(bin, "docker-stub.mjs");
  const gpg = path.join(bin, "gpg-stub.mjs");
  const openssl = path.join(bin, "openssl-stub.mjs");
  const launcher = path.join(bin, "executor-launcher.py");
  makeDockerStub(docker, root);
  makeGpgStub(gpg);
  makeOpenSslStub(openssl, root, certificateDer);
  makeExecutorLauncher(launcher, root, docker);

  const backupToolImages = Object.fromEntries([
    "mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone",
  ].map((name) => [name, {
    imageId: `sha256:${sha(`fixture-${name}-image-id`)}`,
    imageReference: `registry.invalid/${name}@sha256:${sha(`fixture-${name}-manifest`)}`,
  }]));
  const producerSha = sha(fs.readFileSync(releaseProducer));
  const authority = {
    backupToolImages,
    candidateCommit: commit,
    candidateTree: tree,
    documentId: sha("fixture-authority-document"),
    evidenceProducer: {
      executor: "/usr/bin/python3",
      executorFlags: ["-I"],
      forbiddenResticOperations: ["forget", "prune"],
      hostingerAllowed: false,
      logicalKeys: FAMILIES,
      offsiteRepository: "rclone:platform-onedrive:platform-infrastructure/restic",
      operations: ["pre", "post"],
      path: `${releaseRoot}/scripts/v1-local-private-evidence-producer.py`,
      recoveryEscrowPrefix: "platform-onedrive:platform-infrastructure/key-escrow",
      sha256: producerSha,
    },
    recoveryEscrowCertificate: {
      path: certificateLogical,
      sha256: sha(certificateBytes),
      sha256Fingerprint: sha(certificateDer),
    },
    releaseRoot,
    schema: "platform.v1-local-private-exact-release-authority/v1",
    sourceArchiveSha256: archiveSha,
    status: "AUTHORIZED",
  };
  writeCanonical(fixture, LOGICAL.authority, authority);
  writeCanonical(fixture, LOGICAL.install, {
    candidateCommit: commit, candidateTree: tree, sourceArchiveSha256: archiveSha,
  });

  const recoveryExport = Buffer.from("FIXTURE SCHEDULER RECOVERY IMAGE EXPORT\n");
  writeLogical(fixture, LOGICAL.recoveryExport, recoveryExport, 0o400);
  writeCanonical(fixture, LOGICAL.checkpoint, {
    schedulerRecoveryImageExportSha256: sha(recoveryExport),
    schedulerRecoveryImageId: `sha256:${sha("fixture-recovery-image")}`,
    schedulerRunningImageId: `sha256:${sha("fixture-running-image")}`,
  });
  writeLogical(fixture, LOGICAL.renderEnv,
    `V1_CONFIDENTIAL_BACKUP_PASSPHRASE_FILE=${LOGICAL.passphrase}\nPOSTGRES_OPS_SCHEMA=ops\n`, 0o400);

  const signingSecret = "fixture-hmac-secret-that-is-at-least-forty-eight-characters-00000000";
  const resticCredential = "RESTIC_CREDENTIAL_TEST_ONLY_DO_NOT_RECORD_0123456789";
  const confidentialCredential = "CONFIDENTIAL_PASSPHRASE_TEST_ONLY_DO_NOT_RECORD_012345678901234567890123";
  writeLogical(fixture, `${LOGICAL.secrets}/backup_signing_keys.txt`, `fixture-key=${signingSecret}\n`, 0o400);
  writeLogical(fixture, `${LOGICAL.secrets}/restic_password.txt`, `${resticCredential}\n`, 0o400);
  writeLogical(fixture, `${LOGICAL.secrets}/rclone/rclone.conf`, "[platform-onedrive]\ntype = onedrive\n", 0o400);
  writeLogical(fixture, `${LOGICAL.secrets}/runtime_token`, "RUNTIME_TOKEN_TEST_ONLY_DO_NOT_RECORD\n", 0o400);
  writeLogical(fixture, LOGICAL.passphrase, `${confidentialCredential}\n`, 0o400);

  for (const slug of FAMILIES.slice(0, 8)) {
    writeLogical(fixture, `${LOGICAL.source}/${slug}/index.txt`, `fixture application ${slug}\n`, 0o644);
  }
  for (const relative of [
    "anniversary/private/database/state.sqlite",
    "stream/private/database/state.sqlite",
    "workcalendar/database/state.sqlite",
    "fiplatform/private/cache/app_cache.sqlite",
  ]) writeLogical(fixture, `${LOGICAL.source}/${relative}`, `fixture overlay ${relative}\n`, 0o600);
  for (const relative of [
    "fiplatform/private/.env", "stream/private/.env", "stream/private/.env.example", "matthewdifilippo/.env",
  ]) writeLogical(fixture, `${LOGICAL.source}/${relative}`, `OVERLAY_SECRET_${sha(relative).slice(0, 16)}\n`, 0o600);
  for (const filename of ["projects.json", "databases.json", "secret-vault.json", "operations.jsonl", "audit.jsonl"]) {
    writeLogical(fixture, `${LOGICAL.projectState}/${filename}`, `fixture-state-${filename}\n`, 0o600);
  }

  fs.mkdirSync(path.join(root, "stub-state"), { recursive: true, mode: 0o700 });
  const images = Object.fromEntries(Object.values(backupToolImages).map((item) => [item.imageReference, item.imageId]));
  writeFile(path.join(root, "stub-state", "docker-state.json"), JSON.stringify({
    container: {
      Config: { Cmd: [], Entrypoint: [], Env: ["TOKEN_FILE=/run/secrets/runtime_token"] },
      Id: sha("fixture-container-id"),
      Image: `sha256:${sha("fixture-runtime-image")}`,
      Mounts: [{
        Destination: "/run/secrets/runtime_token", RW: false,
        Source: `${LOGICAL.secrets}/runtime_token`,
      }],
      Name: "/enterprise-backend",
      RestartCount: 0,
      State: { Status: "running" },
    },
    images,
    retargetImage: false,
    snapshots: [],
    unmountedSecret: false,
  }), 0o600);

  fixture.archiveSha = archiveSha;
  fixture.authority = authority;
  fixture.backupToolImages = backupToolImages;
  fixture.commit = commit;
  fixture.confidentialCredential = confidentialCredential;
  fixture.docker = docker;
  fixture.gpg = gpg;
  fixture.launcher = launcher;
  fixture.openssl = openssl;
  fixture.releaseProducer = releaseProducer;
  fixture.releaseRoot = releaseRoot;
  fixture.resticCredential = resticCredential;
  fixture.tree = tree;
  fixture.env = {
    ...process.env,
    PLATFORM_V1_EVIDENCE_TEST_ROOT: root,
    PLATFORM_V1_EVIDENCE_TEST_DOCKER: docker,
    PLATFORM_V1_EVIDENCE_TEST_GPG: gpg,
    PLATFORM_V1_EVIDENCE_TEST_NODE: NODE,
    PLATFORM_V1_EVIDENCE_TEST_OPENSSL: openssl,
  };
  return fixture;
}

function dockerState(fixture) {
  const filename = path.join(fixture.root, "stub-state", "docker-state.json");
  return {
    get value() { return JSON.parse(fs.readFileSync(filename, "utf8")); },
    set value(value) { writeFile(filename, JSON.stringify(value), 0o600); },
  };
}

function runProducer(fixture, operation, options = {}) {
  return run(PYTHON, ["-I", fixture.launcher, fixture.releaseProducer, operation, options.entrypoint ?? "cli", options.fault ?? "none"], {
    env: fixture.env,
    input: options.input,
    stdio: options.stdio,
  });
}

function runPure(fixture, body, env = fixture.env) {
  const source = String.raw`
import importlib.util, sys
producer = sys.argv[1]
spec = importlib.util.spec_from_file_location("fixture_pure", producer)
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
try:
${body.split("\n").map((line) => `    ${line}`).join("\n")}
except module.Stop as error:
    sys.stderr.write(str(error) + "\n"); raise SystemExit(error.code)
`;
  return run(PYTHON, ["-I", "-c", source, fixture.releaseProducer], { env });
}

function jsonLines(filename) {
  if (!fs.existsSync(filename)) return [];
  return fs.readFileSync(filename, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

const EVIDENCE_PATHS = [
  LOGICAL.logicalEvidence, LOGICAL.offhostEvidence, LOGICAL.restoreEvidence, LOGICAL.secretsEvidence,
];

function readEvidenceBundle(fixture) {
  return EVIDENCE_PATHS.map((logical) => readCanonical(fixture, logical));
}

function evidenceBinding(fixture, documents) {
  const [logical] = documents;
  return {
    archiveSha256: logical.sourceArchiveSha256,
    authorityDocumentId: logical.authorityDocumentId,
    authoritySha256: logical.authoritySha256,
    backupToolImages: logical.backupToolImages,
    candidateCommit: logical.candidateCommit,
    candidateTree: logical.candidateTree,
    operation: logical.evidencePhase.toLowerCase(),
    reconciliationSha256: logical.reconciliationSha256,
    recoveryEscrowCertificate: fixture.authority.recoveryEscrowCertificate,
    transactionId: logical.transactionId,
  };
}

function validateEvidenceBundle(fixture, documents, binding = evidenceBinding(fixture, documents), now = Math.floor(Date.now() / 1000)) {
  const input = path.join(fixture.root, "stub-state", `validator-${crypto.randomUUID()}.json`);
  writeFile(input, canonicalBytes({ binding, documents, now }), 0o600);
  const source = String.raw`
import importlib.util, json, os, sys
producer, input_file = sys.argv[1:3]
spec = importlib.util.spec_from_file_location("fixture_validator", producer)
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
with open(input_file, "r", encoding="utf-8") as handle: value = json.load(handle)
try:
    module.validate_backup_evidence_documents(value["documents"], value["binding"], value["now"])
except module.Stop as error:
    sys.stderr.write(str(error) + "\n"); raise SystemExit(error.code)
sys.stdout.write("PASS\n")
`;
  const result = run(PYTHON, ["-I", "-c", source, fixture.releaseProducer, input], { env: fixture.env });
  fs.rmSync(input, { force: true });
  return result;
}

function clone(value) {
  return structuredClone(value);
}

function assertBundleRejected(fixture, baseline, label, mutate, expected = /invalid|differs|inconsistent|substitut|false|wrong|unresolved/i) {
  const documents = clone(baseline);
  const binding = evidenceBinding(fixture, documents);
  mutate(documents, binding);
  const result = validateEvidenceBundle(fixture, documents, binding);
  assert.notEqual(result.status, 0, `${label} unexpectedly validated`);
  assert.match(result.stderr, expected, label);
}

function preservePostPreimages(fixture) {
  const transactionId = sha("fixture-reconciliation-transaction");
  const sources = [
    LOGICAL.logicalEvidence, LOGICAL.offhostEvidence, LOGICAL.restoreEvidence,
    LOGICAL.runtimeEvidence, LOGICAL.secretsEvidence,
  ].sort().concat(LOGICAL.checkpoint);
  const evidencePreimages = sources.map((logicalPath, index) => {
    const bytes = fs.readFileSync(mapPath(fixture, logicalPath));
    const preimagePath = `${LOGICAL.state}/rollback-specs/${transactionId}/evidence-preimages/${String(index).padStart(2, "0")}.bin`;
    writeLogical(fixture, preimagePath, bytes, 0o600);
    return {
      logicalPath,
      mode: fs.statSync(mapPath(fixture, logicalPath)).mode & 0o777,
      preimagePath,
      sha256: sha(bytes),
      sizeBytes: bytes.length,
    };
  });
  const authorityBytes = fs.readFileSync(mapPath(fixture, LOGICAL.authority));
  const reconciliation = {
    beganAtUnixSeconds: Math.floor(Date.now() / 1000) - 1,
    releaseAuthoritySha256: sha(authorityBytes),
  };
  writeCanonical(fixture, LOGICAL.reconciliation, reconciliation);
  writeCanonical(fixture, LOGICAL.journal, {
    authorityDocumentId: fixture.authority.documentId,
    evidencePreimages,
    phase: "APPLIED",
    transactionId,
  });
  return { evidencePreimages, reconciliation, transactionId };
}

function fixedEvidenceBytes(fixture) {
  return Object.fromEntries([
    ...EVIDENCE_PATHS, LOGICAL.runtimeEvidence, LOGICAL.checkpoint,
  ].map((logical) => [logical, fs.readFileSync(mapPath(fixture, logical))]));
}

function assertBytesUnchanged(fixture, expected, paths = Object.keys(expected)) {
  for (const logical of paths) {
    assert.deepEqual(fs.readFileSync(mapPath(fixture, logical)), expected[logical], `${logical} changed unexpectedly`);
  }
}

function commandAfterImage(arguments_) {
  const index = arguments_.findIndex((item) => /^sha256:[a-f0-9]{64}$/.test(item));
  return index < 0 ? [] : arguments_.slice(index + 1);
}

function assertResticAndEscrowRun(fixture, receipt, offhost) {
  const calls = jsonLines(path.join(fixture.root, "stub-state", "docker.jsonl"));
  const tag = offhost.proofs[0].snapshotTag;
  assert.ok(tag.includes(receipt.runId));
  const commands = calls.map(commandAfterImage);
  const backups = commands.filter((item) => item[0] === "backup" && item.includes(tag));
  const restores = commands.filter((item) => item[0] === "restore" && offhost.proofs.some((proof) => proof.snapshotId === item.at(-1)));
  assert.equal(backups.length, 14, "one Restic backup per exact family");
  assert.equal(restores.length, 14, "one Restic full-ID readback per exact family");
  assert.deepEqual(backups.map((item) => item[item.indexOf("--tag") + 3].replace("logical-key-", "")), FAMILIES);
  assert.equal(new Set(restores.map((item) => item.at(-1))).size, 14);
  for (const command of backups) {
    const firstTag = command.indexOf("--tag");
    assert.equal(command.slice(2, firstTag).length, 3);
    assert.equal(command[command.indexOf("--host") + 1], "platform-v1-local-private");
  }
  const state = dockerState(fixture).value;
  const snapshots = state.snapshots.filter((item) => item.tags.includes(tag));
  assert.equal(snapshots.length, 14);
  assert.equal(new Set(snapshots.map((item) => item.id)).size, 14);
  for (const row of snapshots) {
    assert.match(row.id, /^[a-f0-9]{64}$/);
    assert.equal(row.hostname, "platform-v1-local-private");
    assert.equal(row.paths.length, 3);
    assert.deepEqual(new Set(row.tags), new Set([tag, row.tags.find((item) => item.startsWith("logical-key-"))]));
  }
  const flattened = calls.flat().join("\n").toLowerCase();
  assert.equal(flattened.includes("forget"), false);
  assert.equal(flattened.includes("prune"), false);
  assert.equal(flattened.includes("hostinger"), false);
  const escrowCalls = commands.filter((item) => item[0] === "copyto" && item.some((value) => value.includes(receipt.runId)));
  assert.equal(escrowCalls.length, 2, "CMS escrow has one direct upload and one direct readback");
  const remote = offhost.recoveryEscrow.offHostLocation;
  assert.ok(remote.startsWith("platform-onedrive:platform-infrastructure/key-escrow/"));
  assert.equal(remote.includes("platform-infrastructure/restic"), false);
}

function assertInfraRestoreContracts(fixture, startIndex = 0) {
  const rows = jsonLines(path.join(fixture.root, "stub-state", "infra.jsonl")).slice(startIndex);
  const restores = rows.filter((item) => item.operation.startsWith("restore-test-"));
  assert.equal(restores.length, 5);
  const immutableRoot = mapPath(fixture, "/dev/shm") + path.sep;
  for (const row of restores) {
    assert.equal(row.args[0], "--backupFile");
    assert.ok(path.resolve(row.args[1]).startsWith(path.resolve(immutableRoot)), `${row.operation} did not receive a private tmpfs snapshot`);
    assert.match(row.args[1], /platform-v1-evidence-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}-transaction\/artifact-staging\/\d{2}-/);
    assert.equal(path.resolve(row.args[1]).startsWith(path.resolve(mapPath(fixture, LOGICAL.backups)) + path.sep), false);
    assert.deepEqual(row.args.slice(-2), ["--v1EvidenceReceipt", "true"]);
  }
  const receipts = jsonLines(path.join(fixture.root, "stub-state", "comparator-receipts.jsonl"));
  assert.ok(receipts.length >= 5);
  assert.deepEqual(restores.map((item) => item.operation), receipts.slice(-5).map((item) => item.operation));
  for (const receipt of receipts.slice(-5)) {
    assert.equal(receipt.matched, true);
    assert.equal(receipt.semanticComparator.matched, true);
    assert.match(receipt.artifactSha256, /^[a-f0-9]{64}$/);
  }
}

test("fixture producer completes one exact PRE evidence transaction", { timeout: 120_000 }, () => {
  const fixture = createFixture();
  let passed = false;
  try {
    const stale = mapPath(fixture, "/dev/shm/platform-v1-evidence-20000101T000000Z-deadbeef-abandoned");
    writeFile(path.join(stale, "private-material"), "MUST-BE-REMOVED\n", 0o600);
    fs.chmodSync(stale, 0o700);
    const result = runProducer(fixture, "pre", { fault: "mutate-live-after-snapshot" });
    requireSuccess(result, "PRE evidence producer");
    const receipt = JSON.parse(result.stdout);
    assert.equal(result.stdout, `${stableJson(receipt)}\n`, "producer stdout is one canonical receipt");
    assert.equal(receipt.status, "PASS");
    assert.equal(receipt.mode, "pre");
    assert.equal(receipt.artifactCount, 14);
    assert.equal(receipt.restoreCount, 14);
    assert.equal(receipt.snapshotCount, 14);
    const logical = readCanonical(fixture, LOGICAL.logicalEvidence);
    assert.deepEqual(logical.artifacts.map((item) => item.logicalKey), FAMILIES);
    assert.notEqual(
      sha(fs.readFileSync(mapPath(fixture, logical.artifacts[0].hostPath))),
      logical.artifacts[0].sha256,
      "fixture did not mutate the deployment-writable live artifact after snapshot",
    );
    const documents = readEvidenceBundle(fixture);
    requireSuccess(validateEvidenceBundle(fixture, documents), "closed evidence validator");
    const restore = documents[2];
    assert.deepEqual(restore.results.map((item) => item.logicalKey), FAMILIES);
    for (const row of restore.results) {
      assert.equal(sha(canonicalBytes(row.verification)), row.verificationSha256);
      if (FAMILIES.slice(0, 8).includes(row.logicalKey)) {
        assert.deepEqual(Object.keys(row.verification).sort(), ["entryCount", "restoredTreeSha256", "sourceTreeSha256"]);
        assert.equal(row.verification.restoredTreeSha256, row.verification.sourceTreeSha256);
      } else if (row.logicalKey === "confidential") {
        assert.deepEqual(Object.keys(row.verification).sort(), ["entryCount", "restoredTreeSha256", "sourceTreeSha256", "treeSha256"]);
      } else {
        assert.deepEqual(Object.keys(row.verification), ["comparatorReceipt"]);
        assert.equal(row.verification.comparatorReceipt.matched, true);
      }
    }
    assertBundleRejected(fixture, documents, "opaque restore verification", ([, , changed]) => {
      delete changed.results[0].verification;
    }, /missing|unexpected/i);
    assertBundleRejected(fixture, documents, "mutated restore verification", ([, , changed]) => {
      changed.results[0].verification.entryCount += 1;
    }, /does not match/i);
    assertBundleRejected(fixture, documents, "false semantic comparator", ([, , changed]) => {
      changed.results[8].verification.comparatorReceipt.matched = false;
      changed.results[8].verificationSha256 = sha(canonicalBytes(changed.results[8].verification));
    }, /not artifact|PASS bound/i);
    assertInfraRestoreContracts(fixture);
    assertResticAndEscrowRun(fixture, receipt, documents[1]);
    const executorRows = jsonLines(path.join(fixture.root, "stub-state", "executor.jsonl"));
    assert.ok(executorRows.length > 30);
    assert.deepEqual(executorRows.map((item) => item.id), executorRows.map((_, index) => index + 1));
    assert.equal(new Set(executorRows.map((item) => item.parameters.runId).filter(Boolean)).size, 1);
    assert.equal(executorRows.some((item) => "arguments" in item || "infraOperation" in item || item.action === "PRODUCER_DOCKER"), false);
    assert.equal(fs.existsSync(stale), false, "stale private tmpfs root was not recovered under the transaction lease");
    assert.deepEqual(
      fs.readdirSync(mapPath(fixture, "/dev/shm")).filter((name) => name.startsWith("platform-v1-evidence-")),
      [],
      "private transaction workspace remained after success",
    );
    const serializedEvidence = EVIDENCE_PATHS.map((logicalPath) => fs.readFileSync(mapPath(fixture, logicalPath), "utf8")).join("\n");
    assert.equal(serializedEvidence.includes(fixture.resticCredential), false);
    assert.equal(serializedEvidence.includes(fixture.confidentialCredential), false);
    passed = true;
  } finally {
    if (passed) fs.rmSync(fixture.root, { recursive: true, force: true });
    else process.stderr.write(`fixture retained for diagnosis: ${fixture.root}\n`);
  }
});

test("typed executor response identity and framing fail closed", { timeout: 30_000 }, () => {
  for (const fault of ["id-mismatch", "noncanonical"]) {
    const fixture = createFixture();
    try {
      const result = runProducer(fixture, "pre", { fault });
      assert.equal(result.status, 78, `${fault} response was not rejected`);
      assert.equal(result.stdout, "");
      assert.match(result.stderr, /STOP:/);
      assert.equal(result.stderr.includes(fixture.resticCredential), false);
      assert.equal(result.stderr.includes(fixture.confidentialCredential), false);
      for (const logicalPath of EVIDENCE_PATHS) assert.equal(fs.existsSync(mapPath(fixture, logicalPath)), false);
    } finally {
      fs.rmSync(fixture.root, { recursive: true, force: true });
    }
  }
});
