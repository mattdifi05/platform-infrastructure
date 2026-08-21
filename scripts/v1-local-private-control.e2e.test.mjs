import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  V1_LOCAL_PRIVATE_CANDIDATE_COMMIT as candidateCommit,
  V1_LOCAL_PRIVATE_CANDIDATE_TREE as candidateTree,
  V1_LOCAL_PRIVATE_CONTAINER_NAMES as containerNames,
  V1_LOCAL_PRIVATE_SOURCE_ARCHIVE_SHA256 as sourceArchiveSha256,
  verifyV1LocalPrivateControlReceipt,
} from "./v1-local-private-control-receipt.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const controllerSource = path.join(repositoryRoot, "scripts/v1-local-private-control.py");
const unitSource = path.join(repositoryRoot, "systemd/platform-v1-local-private-control.service");
const bundledNode = process.execPath;
const releaseRoot = `/srv/platform-infrastructure/releases/${candidateCommit}-${sourceArchiveSha256}`;
const nonRootOnly = process.geteuid?.() === 0
  ? "the production root path intentionally disables the non-root TEST_ROOT seam"
  : false;

const stableJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
};

const digest = (value) => crypto.createHash("sha256").update(String(value)).digest("hex");
const bytesDigest = (value) => crypto.createHash("sha256").update(value).digest("hex");
const imageId = (label) => `sha256:${digest(`image:${label}`)}`;
const physical = (root, logical) => path.join(root, logical.slice(1));

function mkdir(root, logical, mode = 0o755) {
  const target = physical(root, logical);
  fs.mkdirSync(target, { recursive: true, mode: 0o755 });
  fs.chmodSync(target, mode);
  return target;
}

function writeCanonical(root, logical, value, mode = 0o600) {
  const target = physical(root, logical);
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
  if (fs.existsSync(target)) fs.chmodSync(target, 0o600);
  fs.writeFileSync(target, `${stableJson(value)}\n`, { mode });
  fs.chmodSync(target, mode);
  return target;
}

function portBindings(name) {
  if (name === "enterprise-waf") {
    return {
      "8080/tcp": [{ HostIp: "0.0.0.0", HostPort: "80" }],
      "8443/tcp": [{ HostIp: "0.0.0.0", HostPort: "443" }],
    };
  }
  if (name === "enterprise-local-dns") {
    return {
      "53/tcp": [{ HostIp: "192.168.1.164", HostPort: "53" }],
      "53/udp": [{ HostIp: "192.168.1.164", HostPort: "53" }],
    };
  }
  if (name === "enterprise-local-registry") {
    return { "5000/tcp": [{ HostIp: "127.0.0.1", HostPort: "5000" }] };
  }
  return {};
}

function recoveryOci(recoveryLabels) {
  const recoveryTag = `platform/v1-scheduler-recovery:${candidateCommit}`;
  const configBytes = Buffer.from(stableJson({ architecture: "amd64", config: { Labels: recoveryLabels }, os: "linux" }));
  const configDigest = `sha256:${bytesDigest(configBytes)}`;
  const layerBytes = Buffer.from("fixed recovery layer\n");
  const layerDigest = `sha256:${bytesDigest(layerBytes)}`;
  const imageManifestBytes = Buffer.from(stableJson({
    config: {
      digest: configDigest,
      mediaType: "application/vnd.oci.image.config.v1+json",
      size: configBytes.length,
    },
    layers: [{
      digest: layerDigest,
      mediaType: "application/vnd.oci.image.layer.v1.tar",
      size: layerBytes.length,
    }],
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    schemaVersion: 2,
  }));
  const imageManifestDigest = `sha256:${bytesDigest(imageManifestBytes)}`;
  const imageIndexBytes = Buffer.from(stableJson({
    manifests: [{
      digest: imageManifestDigest,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      platform: { architecture: "amd64", os: "linux" },
      size: imageManifestBytes.length,
    }],
    mediaType: "application/vnd.oci.image.index.v1+json",
    schemaVersion: 2,
  }));
  const recoveryImageId = `sha256:${bytesDigest(imageIndexBytes)}`;
  const rootIndexBytes = Buffer.from(stableJson({
    manifests: [{
      annotations: {
        "io.containerd.image.name": `docker.io/${recoveryTag}`,
        "org.opencontainers.image.ref.name": candidateCommit,
      },
      digest: recoveryImageId,
      mediaType: "application/vnd.oci.image.index.v1+json",
      size: imageIndexBytes.length,
    }],
    mediaType: "application/vnd.oci.image.index.v1+json",
    schemaVersion: 2,
  }));
  return {
    configBytes,
    configDigest,
    imageIndexBytes,
    imageManifestBytes,
    imageManifestDigest,
    layerBytes,
    layerDigest,
    recoveryImageId,
    recoveryTag,
    rootIndexBytes,
  };
}

function dockerFixture() {
  const withoutHealthcheck = new Set(["enterprise-local-dns", "enterprise-local-registry", "phpmyadmin"]);
  const containers = containerNames.map((name) => {
    const state = { ExitCode: 0, Status: name === "phppgadmin" ? "exited" : "running" };
    if (name !== "phppgadmin" && !withoutHealthcheck.has(name)) state.Health = { Status: "healthy" };
    return {
      Config: {
        Labels: {
          "com.docker.compose.config-hash": digest(`config:${name}`),
          "com.docker.compose.project": name === "node-opstudents" ? "opstudents" : "platform_infra_vps",
          "com.docker.compose.service": name.replace(/^enterprise-/, ""),
        },
      },
      Id: digest(`container:${name}`),
      Image: imageId(name),
      Mounts: name === "enterprise-backup-scheduler"
        ? [{ Destination: "/var/run/docker.sock", RW: true, Source: "/var/run/docker.sock" }]
        : [],
      Name: `/${name}`,
      NetworkSettings: { Ports: portBindings(name) },
      State: state,
    };
  });
  const scheduler = containers.find((item) => item.Name === "/enterprise-backup-scheduler");
  const recoveryLabels = {
    "com.platform.v1.local-private.candidate-commit": candidateCommit,
    "com.platform.v1.local-private.scheduler-config-hash": scheduler.Config.Labels["com.docker.compose.config-hash"],
    "com.platform.v1.local-private.scheduler-container-id": scheduler.Id,
    "com.platform.v1.local-private.scheduler-running-image-id": scheduler.Image,
  };
  const oci = recoveryOci(recoveryLabels);
  return {
    containers,
    daemon: { DockerRootDir: "/var/lib/docker", ID: "daemon-e2e", Name: "vps-e2e", ServerVersion: "28.0.0" },
    recoveryImageId: oci.recoveryImageId,
    recoveryLabels,
    recoveryTag: oci.recoveryTag,
    schedulerImageId: imageId("enterprise-backup-scheduler"),
  };
}

function installFakeDocker(filename, logFile, fixture) {
  const source = `#!${bundledNode}\n` +
`const fs = require("node:fs");
const fixture = ${JSON.stringify(fixture)};
const logFile = ${JSON.stringify(logFile)};
const args = process.argv.slice(2);
fs.appendFileSync(logFile, JSON.stringify(args) + "\\n", { mode: 0o600 });
const reply = (value) => process.stdout.write(JSON.stringify(value) + "\\n");
if (JSON.stringify(args) === JSON.stringify(["info", "--format", "{{json .}}"])) {
  reply(fixture.daemon);
} else if (JSON.stringify(args) === JSON.stringify(["ps", "-aq", "--no-trunc"])) {
  process.stdout.write(fixture.containers.map((item) => item.Id).join("\\n") + "\\n");
} else if (args[0] === "inspect" && args.length === fixture.containers.length + 1) {
  const requested = new Set(args.slice(1));
  if (requested.size !== fixture.containers.length || fixture.containers.some((item) => !requested.has(item.Id))) process.exit(65);
  reply(fixture.containers);
} else if (args[0] === "image" && args[1] === "inspect") {
  const requested = args.slice(2);
  if (requested.length === 1 && requested[0] === fixture.schedulerImageId) {
    fs.writeSync(1, "[]\\n");
    fs.writeSync(2, "Error response from daemon: No such image: " + fixture.schedulerImageId + "\\n");
    process.exit(44);
  }
  if (requested.length === 1 && requested[0] === fixture.recoveryImageId) {
    reply([{ Config: { Labels: fixture.recoveryLabels }, Id: fixture.recoveryImageId, RepoTags: [fixture.recoveryTag] }]);
    process.exit(0);
  }
  const local = new Set(fixture.containers.filter((item) => item.Image !== fixture.schedulerImageId).map((item) => item.Image));
  if (requested.length !== local.size || new Set(requested).size !== local.size || requested.some((id) => !local.has(id))) process.exit(65);
  reply(requested.map((Id) => ({ Id })));
} else {
  process.stderr.write("fixture: forbidden Docker command: " + JSON.stringify(args) + "\\n");
  process.exit(64);
}
`;
  fs.writeFileSync(filename, source, { mode: 0o755 });
  fs.chmodSync(filename, 0o755);
}

function installFakeSystemctl(filename, logFile, stateFile) {
  const source = `#!${bundledNode}\n` +
`const fs = require("node:fs");
const logFile = ${JSON.stringify(logFile)};
const stateFile = ${JSON.stringify(stateFile)};
const args = process.argv.slice(2);
fs.appendFileSync(logFile, JSON.stringify(args) + "\\n", { mode: 0o600 });
const state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
const save = () => fs.writeFileSync(stateFile, JSON.stringify(state) + "\\n", { mode: 0o600 });
if (JSON.stringify(args) === JSON.stringify(["daemon-reload"])) process.exit(0);
if (JSON.stringify(args) === JSON.stringify(["enable", "--now", "platform-v1-local-private-control.service"])) {
  if (state.failEnable) {
    state.failEnable = false;
    save();
    process.stderr.write("fixture: interrupted before supervisor activation\\n");
    process.exit(70);
  }
  state.active = true;
  state.enabled = true;
  save();
  process.exit(0);
}
if (JSON.stringify(args) === JSON.stringify(["is-enabled", "platform-v1-local-private-control.service"])) {
  process.stdout.write(state.enabled ? "enabled\\n" : "disabled\\n");
  process.exit(state.enabled ? 0 : 1);
}
if (JSON.stringify(args) === JSON.stringify(["is-active", "platform-v1-local-private-control.service"])) {
  process.stdout.write(state.active ? "active\\n" : "inactive\\n");
  process.exit(state.active ? 0 : 3);
}
process.stderr.write("fixture: forbidden systemctl command: " + JSON.stringify(args) + "\\n");
process.exit(64);
`;
  fs.writeFileSync(filename, source, { mode: 0o755 });
  fs.chmodSync(filename, 0o755);
}

function executeController(controller, environment, operation) {
  return spawnSync(controller, [operation], {
    cwd: "/",
    encoding: "utf8",
    env: environment,
    maxBuffer: 4 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function runController(controller, environment, operation) {
  const result = executeController(controller, environment, operation);
  assert.equal(result.error, undefined, `${operation} failed to execute: ${result.error}`);
  assert.equal(result.status, 0, `${operation} failed (${result.status}): ${result.stderr}`);
  assert.equal(result.stderr, "", `${operation} wrote stderr`);
  return JSON.parse(result.stdout);
}

function installReceiptDocument() {
  return {
    activationAuthorized: false,
    authorizationSource: "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY",
    backupEvidenceAuthoritative: false,
    candidateCommit,
    candidateTree,
    dataMutation: false,
    dockerMutation: false,
    readyButDisabled: ["PROVIDER_ADMISSION", "DNS_PUBLICATION", "DAST", "SIGSTORE_PROMOTION", "DOCKER_CONTROL_PLANE"],
    releaseRoot,
    schema: "platform.v1-brownfield-install-receipt/v1",
    sourceArchiveSha256,
    status: "INSTALL_ONLY_COMPLETE",
  };
}

function checkpointDocument(fixture, schedulerExportSha256, marker, evidence) {
  const now = Math.floor(Date.now() / 1000);
  return {
    authoritative: false,
    backupCapturedUnixSeconds: now - 30,
    candidateCommit,
    candidateTree,
    destructiveMutationPlanned: false,
    generatedAtUnixSeconds: now,
    logicalBackupEvidenceSha256: evidence.logicalBackupEvidenceSha256,
    offHostBackupEvidenceSha256: evidence.offHostBackupEvidenceSha256,
    restoreEvidenceSha256: evidence.restoreEvidenceSha256,
    restoreVerified: true,
    runtimeInventorySha256: evidence.runtimeInventorySha256,
    runtimeRecovered: true,
    schedulerRecoveryImageExportSha256: schedulerExportSha256,
    schedulerRecoveryImageId: fixture.recoveryImageId,
    schedulerRunningImageId: fixture.schedulerImageId,
    schema: "platform.v1-local-private-predeploy-checkpoint/v1",
    secretsBackupEvidenceSha256: evidence.secretsBackupEvidenceSha256,
    sourceArchiveSha256,
  };
}

function fileSha256(filename) {
  return crypto.createHash("sha256").update(fs.readFileSync(filename)).digest("hex");
}

function tarMember(name, bytes) {
  const data = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const header = Buffer.alloc(512);
  const field = (offset, length, value) => header.write(value, offset, Math.min(length, Buffer.byteLength(value)), "ascii");
  const octal = (value, length) => `${value.toString(8).padStart(length - 1, "0")}\0`;
  field(0, 100, name);
  field(100, 8, octal(0o400, 8));
  field(108, 8, octal(0, 8));
  field(116, 8, octal(0, 8));
  field(124, 12, octal(data.length, 12));
  field(136, 12, octal(1_800_000_000, 12));
  header.fill(0x20, 148, 156);
  header[156] = "0".charCodeAt(0);
  field(257, 6, "ustar\0");
  field(263, 2, "00");
  field(265, 32, "root");
  field(297, 32, "root");
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  field(148, 8, `${checksum.toString(8).padStart(6, "0")}\0 `);
  const padding = Buffer.alloc((512 - (data.length % 512)) % 512);
  return Buffer.concat([header, data, padding]);
}

function writeRecoveryExport(root, fixture, {
  includeLayout = true,
  includeManifest = true,
  layoutVersion = "1.0.0",
  manifestMode = "valid",
} = {}) {
  const oci = recoveryOci(fixture.recoveryLabels);
  assert.equal(oci.recoveryImageId, fixture.recoveryImageId);
  const blobName = (digestValue) => `blobs/sha256/${digestValue.slice("sha256:".length)}`;
  const dockerManifest = [{
    Config: manifestMode === "mismatch" ? `blobs/sha256/${"0".repeat(64)}` : blobName(oci.configDigest),
    Layers: [blobName(oci.layerDigest)],
    RepoTags: [oci.recoveryTag],
  }];
  const dockerManifestBytes = manifestMode === "malformed"
    ? Buffer.from("{not-json")
    : Buffer.from(`${stableJson(dockerManifest)}\n`);
  const members = [
    tarMember("index.json", oci.rootIndexBytes),
  ];
  if (includeLayout) members.push(tarMember("oci-layout", Buffer.from(stableJson({ imageLayoutVersion: layoutVersion }))));
  if (includeManifest) members.push(tarMember("manifest.json", dockerManifestBytes));
  members.push(
    tarMember(blobName(oci.recoveryImageId), oci.imageIndexBytes),
    tarMember(blobName(oci.imageManifestDigest), oci.imageManifestBytes),
    tarMember(blobName(oci.configDigest), oci.configBytes),
    tarMember(blobName(oci.layerDigest), oci.layerBytes),
    Buffer.alloc(1024),
  );
  const archive = Buffer.concat(members);
  const filename = physical(root, "/var/lib/platform-infrastructure/v1/predeploy/current/scheduler-recovery-image.tar");
  if (fs.existsSync(filename)) fs.chmodSync(filename, 0o600);
  fs.writeFileSync(filename, archive, { mode: 0o400 });
  fs.chmodSync(filename, 0o400);
  return {
    configDigest: oci.configDigest,
    filename,
    imageIndexDigest: oci.recoveryImageId,
    imageManifestDigest: oci.imageManifestDigest,
    manifestConfig: blobName(oci.configDigest),
    recoveryTag: oci.recoveryTag,
    sha256: fileSha256(filename),
  };
}

function writeEvidenceFiles(root, marker) {
  const definitions = {
    logicalBackupEvidenceSha256: "logical-backup-evidence.json",
    offHostBackupEvidenceSha256: "offhost-backup-evidence.json",
    restoreEvidenceSha256: "restore-evidence.json",
    runtimeInventorySha256: "runtime-inventory-evidence.json",
    secretsBackupEvidenceSha256: "secrets-backup-evidence.json",
  };
  const result = {};
  for (const [field, basename] of Object.entries(definitions)) {
    const filename = writeCanonical(root, `/var/lib/platform-infrastructure/v1/predeploy/current/${basename}`, { field, marker }, 0o400);
    result[field] = fileSha256(filename);
  }
  return result;
}

test("non-root TEST_ROOT controller activates and verifies without Docker mutation when the scheduler image is recovery-bound", { skip: nonRootOnly }, () => {
  assert.notEqual(process.geteuid?.(), 0, "this E2E must exercise the non-root TEST_ROOT seam");
  const temporary = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "v1-local-private-control-e2e-")));
  fs.chmodSync(temporary, 0o700);
  try {
    const controller = physical(temporary, "/usr/local/libexec/platform-v1-local-private-control");
    const unit = physical(temporary, "/etc/systemd/system/platform-v1-local-private-control.service");
    const fakeDocker = physical(temporary, "/test-bin/docker");
    const fakeSystemctl = physical(temporary, "/test-bin/systemctl");
    const dockerLog = physical(temporary, "/logs/docker.jsonl");
    const systemctlLog = physical(temporary, "/logs/systemctl.jsonl");
    const systemctlState = physical(temporary, "/logs/systemctl-state.json");
    const receiptFile = physical(temporary, "/var/lib/platform-infrastructure/v1/local-private/active-receipt.json");
    const fixture = dockerFixture();

    mkdir(temporary, "/usr/local/libexec");
    mkdir(temporary, "/etc/systemd/system");
    mkdir(temporary, "/test-bin", 0o700);
    mkdir(temporary, "/logs", 0o700);
    mkdir(temporary, "/run/lock");
    mkdir(temporary, "/var/lib/platform-infrastructure/v1/install-receipts");
    mkdir(temporary, "/var/lib/platform-infrastructure/v1/predeploy/current");
    mkdir(temporary, releaseRoot, 0o555);
    fs.copyFileSync(controllerSource, controller);
    fs.chmodSync(controller, 0o555);
    fs.copyFileSync(unitSource, unit);
    fs.chmodSync(unit, 0o444);
    installFakeDocker(fakeDocker, dockerLog, fixture);
    fs.writeFileSync(systemctlState, '{"active":false,"enabled":false,"failEnable":false}\n', { mode: 0o600 });
    installFakeSystemctl(fakeSystemctl, systemctlLog, systemctlState);
    const schedulerExport = writeRecoveryExport(temporary, fixture);
    const evidence = writeEvidenceFiles(temporary, "initial-activation");

    writeCanonical(temporary, `/var/lib/platform-infrastructure/v1/install-receipts/${candidateCommit}-${sourceArchiveSha256}.json`, {
      activationAuthorized: false,
      authorizationSource: "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY",
      backupEvidenceAuthoritative: false,
      candidateCommit,
      candidateTree,
      dataMutation: false,
      dockerMutation: false,
      readyButDisabled: ["PROVIDER_ADMISSION", "DNS_PUBLICATION", "DAST", "SIGSTORE_PROMOTION", "DOCKER_CONTROL_PLANE"],
      releaseRoot,
      schema: "platform.v1-brownfield-install-receipt/v1",
      sourceArchiveSha256,
      status: "INSTALL_ONLY_COMPLETE",
    });
    const validCheckpoint = checkpointDocument(fixture, schedulerExport.sha256, "initial-activation", evidence);
    const checkpointFile = writeCanonical(
      temporary,
      "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json",
      validCheckpoint,
    );

    const environment = {
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
      PLATFORM_V1_LOCAL_PRIVATE_TEST_DOCKER: fakeDocker,
      PLATFORM_V1_LOCAL_PRIVATE_TEST_ROOT: temporary,
      PLATFORM_V1_LOCAL_PRIVATE_TEST_SYSTEMCTL: fakeSystemctl,
    };

    const logicalEvidence = physical(temporary, "/var/lib/platform-infrastructure/v1/predeploy/current/logical-backup-evidence.json");
    const heldEvidence = `${logicalEvidence}.held`;
    fs.renameSync(logicalEvidence, heldEvidence);
    const missingEvidence = executeController(controller, environment, "activate");
    assert.equal(missingEvidence.status, 78);
    assert.match(missingEvidence.stderr, /fixed logicalBackupEvidence file is missing/i);
    fs.renameSync(heldEvidence, logicalEvidence);

    const originalEvidence = fs.readFileSync(logicalEvidence);
    writeCanonical(temporary, "/var/lib/platform-infrastructure/v1/predeploy/current/logical-backup-evidence.json", { field: "logicalBackupEvidenceSha256", marker: "tampered" }, 0o400);
    const tamperedEvidence = executeController(controller, environment, "activate");
    assert.equal(tamperedEvidence.status, 78);
    assert.match(tamperedEvidence.stderr, /bytes differ from the fresh checkpoint/i);
    fs.chmodSync(logicalEvidence, 0o600);
    fs.writeFileSync(logicalEvidence, originalEvidence, { mode: 0o400 });
    fs.chmodSync(logicalEvidence, 0o400);

    writeCanonical(temporary, "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json", { ...validCheckpoint, schedulerRecoveryImageExportSha256: digest("wrong scheduler export") });
    const exportMismatch = executeController(controller, environment, "activate");
    assert.equal(exportMismatch.status, 78);
    assert.match(exportMismatch.stderr, /export bytes differ from the fresh checkpoint/i);

    const tamperedArchive = fs.readFileSync(schedulerExport.filename);
    const layerOffset = tamperedArchive.indexOf(Buffer.from("fixed recovery layer\n"));
    assert.ok(layerOffset >= 0, "OCI layer fixture is missing");
    tamperedArchive[layerOffset] ^= 0x01;
    fs.chmodSync(schedulerExport.filename, 0o600);
    fs.writeFileSync(schedulerExport.filename, tamperedArchive, { mode: 0o400 });
    fs.chmodSync(schedulerExport.filename, 0o400);
    writeCanonical(temporary, "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json", {
      ...validCheckpoint,
      schedulerRecoveryImageExportSha256: fileSha256(schedulerExport.filename),
    });
    const layerMismatch = executeController(controller, environment, "activate");
    assert.equal(layerMismatch.status, 78);
    assert.match(layerMismatch.stderr, /layer descriptor 0 blob digest\/size differs/i);

    const missingLayoutExport = writeRecoveryExport(temporary, fixture, { includeLayout: false });
    writeCanonical(temporary, "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json", {
      ...validCheckpoint,
      schedulerRecoveryImageExportSha256: missingLayoutExport.sha256,
    });
    const missingLayout = executeController(controller, environment, "activate");
    assert.equal(missingLayout.status, 78);
    assert.match(missingLayout.stderr, /OCI layout is missing or invalid/i);

    const wrongLayoutExport = writeRecoveryExport(temporary, fixture, { layoutVersion: "0.9.0" });
    writeCanonical(temporary, "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json", {
      ...validCheckpoint,
      schedulerRecoveryImageExportSha256: wrongLayoutExport.sha256,
    });
    const wrongLayout = executeController(controller, environment, "activate");
    assert.equal(wrongLayout.status, 78);
    assert.match(wrongLayout.stderr, /exact canonical 1\.0\.0 object/i);

    const missingManifestExport = writeRecoveryExport(temporary, fixture, { includeManifest: false });
    writeCanonical(temporary, "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json", {
      ...validCheckpoint,
      schedulerRecoveryImageExportSha256: missingManifestExport.sha256,
    });
    const missingManifest = executeController(controller, environment, "activate");
    assert.equal(missingManifest.status, 78);
    assert.match(missingManifest.stderr, /Docker manifest\.json is missing or invalid/i);

    const malformedManifestExport = writeRecoveryExport(temporary, fixture, { manifestMode: "malformed" });
    writeCanonical(temporary, "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json", {
      ...validCheckpoint,
      schedulerRecoveryImageExportSha256: malformedManifestExport.sha256,
    });
    const malformedManifest = executeController(controller, environment, "activate");
    assert.equal(malformedManifest.status, 78);
    assert.match(malformedManifest.stderr, /Docker manifest\.json is invalid JSON/i);

    const mismatchedManifestExport = writeRecoveryExport(temporary, fixture, { manifestMode: "mismatch" });
    writeCanonical(temporary, "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json", {
      ...validCheckpoint,
      schedulerRecoveryImageExportSha256: mismatchedManifestExport.sha256,
    });
    const mismatchedManifest = executeController(controller, environment, "activate");
    assert.equal(mismatchedManifest.status, 78);
    assert.match(mismatchedManifest.stderr, /exact OCI-bound singleton image/i);

    writeRecoveryExport(temporary, fixture);
    writeCanonical(temporary, "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json", validCheckpoint);
    assert.equal(fs.existsSync(systemctlLog), false, "invalid evidence must STOP before any systemctl command");

    const activation = runController(controller, environment, "activate");
    assert.equal(activation.status, "ACTIVE");
    assert.equal(activation.authorityMode, "LOCAL_PRIVATE");
    assert.equal(activation.dockerMutation, false);
    assert.equal(activation.containerRecreate, false);
    assert.equal(activation.localArtifactTrust.schedulerRecovery.status, "RECOVERY_IMAGE_EXPORT_BOUND");
    assert.equal(activation.localArtifactTrust.schedulerRecovery.exportSha256, schedulerExport.sha256);
    assert.equal(activation.localArtifactTrust.schedulerRecovery.exportPath, "/var/lib/platform-infrastructure/v1/predeploy/current/scheduler-recovery-image.tar");
    assert.equal(activation.localArtifactTrust.schedulerRecovery.archiveFormat, "OCI_DOCKER_SAVE_V1");
    assert.equal(activation.localArtifactTrust.schedulerRecovery.configDigest, schedulerExport.configDigest);
    assert.equal(activation.localArtifactTrust.schedulerRecovery.imageIndexDigest, schedulerExport.imageIndexDigest);
    assert.equal(activation.localArtifactTrust.schedulerRecovery.imageManifestDigest, schedulerExport.imageManifestDigest);
    assert.equal(activation.localArtifactTrust.schedulerRecovery.manifestConfig, schedulerExport.manifestConfig);
    assert.equal(activation.localArtifactTrust.schedulerRecovery.runningImageId, fixture.schedulerImageId);
    assert.equal(activation.localArtifactTrust.schedulerRecovery.recoveryImageId, fixture.recoveryImageId);
    assert.equal(activation.localArtifactTrust.schedulerRecovery.recoveryTag, schedulerExport.recoveryTag);
    assert.equal(activation.runtime.containers.find((item) => item.name === "enterprise-backup-scheduler")?.imageAvailability, "RECOVERY_IMAGE_EXPORT_BOUND");

    const verification = runController(controller, environment, "verify");
    assert.deepEqual(verification, activation);
    assert.deepEqual(JSON.parse(fs.readFileSync(receiptFile, "utf8")), activation);
    assert.equal(verifyV1LocalPrivateControlReceipt({
      candidateCommit,
      candidateTree,
      controllerSha256: activation.controller.sha256,
      file: receiptFile,
      sourceArchiveSha256,
      unitSha256: activation.controller.unitSha256,
    }).documentId, activation.documentId);

    const dockerCommands = fs.readFileSync(dockerLog, "utf8").trim().split("\n").map(JSON.parse);
    assert.ok(dockerCommands.length > 0, "controller did not inspect Docker");
    assert.ok(dockerCommands.every((args) => {
      if (JSON.stringify(args) === JSON.stringify(["info", "--format", "{{json .}}"])) return true;
      if (JSON.stringify(args) === JSON.stringify(["ps", "-aq", "--no-trunc"])) return true;
      if (args[0] === "inspect" && args.length === 36) return true;
      return args[0] === "image" && args[1] === "inspect" && args.length >= 3;
    }), `unexpected Docker command: ${JSON.stringify(dockerCommands)}`);
    assert.equal(dockerCommands.some((args) => new Set(["create", "run", "start", "stop", "restart", "kill", "rm", "update", "pull", "push", "tag", "load", "import", "commit", "compose"]).has(args[0])), false);
    const schedulerMissingInspections = dockerCommands.filter((args) => JSON.stringify(args) === JSON.stringify(["image", "inspect", fixture.schedulerImageId]));
    assert.ok(schedulerMissingInspections.length >= 6, "scheduler missing-image recovery path was not exercised throughout activate and verify");

    const systemctlCommands = fs.readFileSync(systemctlLog, "utf8").trim().split("\n").map(JSON.parse);
    assert.equal(systemctlCommands.filter((args) => JSON.stringify(args) === JSON.stringify(["enable", "--now", "platform-v1-local-private-control.service"])).length, 1);
    assert.ok(systemctlCommands.some((args) => JSON.stringify(args) === JSON.stringify(["is-enabled", "platform-v1-local-private-control.service"])));
    assert.ok(systemctlCommands.some((args) => JSON.stringify(args) === JSON.stringify(["is-active", "platform-v1-local-private-control.service"])));
  } finally {
    fs.rmSync(temporary, { force: true, recursive: true });
  }
});

test("interrupted ACTIVATING state accepts only a fresh checkpoint at identical runtime identity and rejects runtime drift", { skip: nonRootOnly }, () => {
  assert.notEqual(process.geteuid?.(), 0, "this E2E must exercise the non-root TEST_ROOT seam");
  const temporary = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "v1-local-private-crash-e2e-")));
  fs.chmodSync(temporary, 0o700);
  try {
    const controller = physical(temporary, "/usr/local/libexec/platform-v1-local-private-control");
    const unit = physical(temporary, "/etc/systemd/system/platform-v1-local-private-control.service");
    const fakeDocker = physical(temporary, "/test-bin/docker");
    const fakeSystemctl = physical(temporary, "/test-bin/systemctl");
    const dockerLog = physical(temporary, "/logs/docker.jsonl");
    const systemctlLog = physical(temporary, "/logs/systemctl.jsonl");
    const systemctlState = physical(temporary, "/logs/systemctl-state.json");
    const checkpointFile = physical(temporary, "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json");
    const stateFile = physical(temporary, "/var/lib/platform-infrastructure/v1/local-private/state.json");
    const receiptFile = physical(temporary, "/var/lib/platform-infrastructure/v1/local-private/active-receipt.json");
    const fixture = dockerFixture();

    mkdir(temporary, "/usr/local/libexec");
    mkdir(temporary, "/etc/systemd/system");
    mkdir(temporary, "/test-bin", 0o700);
    mkdir(temporary, "/logs", 0o700);
    mkdir(temporary, "/run/lock");
    mkdir(temporary, "/var/lib/platform-infrastructure/v1/install-receipts");
    mkdir(temporary, "/var/lib/platform-infrastructure/v1/predeploy/current");
    mkdir(temporary, releaseRoot, 0o555);
    fs.copyFileSync(controllerSource, controller);
    fs.chmodSync(controller, 0o555);
    fs.copyFileSync(unitSource, unit);
    fs.chmodSync(unit, 0o444);
    installFakeDocker(fakeDocker, dockerLog, fixture);
    fs.writeFileSync(systemctlState, '{"active":false,"enabled":false,"failEnable":true}\n', { mode: 0o600 });
    installFakeSystemctl(fakeSystemctl, systemctlLog, systemctlState);
    const schedulerExport = writeRecoveryExport(temporary, fixture);
    const interruptedEvidence = writeEvidenceFiles(temporary, "before-interruption");
    writeCanonical(
      temporary,
      `/var/lib/platform-infrastructure/v1/install-receipts/${candidateCommit}-${sourceArchiveSha256}.json`,
      installReceiptDocument(),
    );
    writeCanonical(
      temporary,
      "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json",
      checkpointDocument(fixture, schedulerExport.sha256, "before-interruption", interruptedEvidence),
    );
    const interruptedCheckpointSha256 = fileSha256(checkpointFile);
    const environment = {
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
      PLATFORM_V1_LOCAL_PRIVATE_TEST_DOCKER: fakeDocker,
      PLATFORM_V1_LOCAL_PRIVATE_TEST_ROOT: temporary,
      PLATFORM_V1_LOCAL_PRIVATE_TEST_SYSTEMCTL: fakeSystemctl,
    };

    const interrupted = executeController(controller, environment, "activate");
    assert.equal(interrupted.error, undefined);
    assert.equal(interrupted.status, 78);
    assert.match(interrupted.stderr, /interrupted before supervisor activation/);
    assert.equal(fs.existsSync(receiptFile), false, "an interrupted activation must not mint an ACTIVE receipt");
    const activatingState = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    assert.equal(activatingState.status, "ACTIVATING");
    assert.equal(activatingState.checkpointSha256, interruptedCheckpointSha256);
    assert.deepEqual(JSON.parse(fs.readFileSync(systemctlState, "utf8")), { active: false, enabled: false, failEnable: false });

    const freshEvidence = writeEvidenceFiles(temporary, "fresh-after-interruption");
    writeCanonical(
      temporary,
      "/var/lib/platform-infrastructure/v1/predeploy/current/local-private-checkpoint.json",
      checkpointDocument(fixture, schedulerExport.sha256, "fresh-after-interruption", freshEvidence),
    );
    const freshCheckpointSha256 = fileSha256(checkpointFile);
    assert.notEqual(freshCheckpointSha256, interruptedCheckpointSha256, "fresh PRE-DEPLOY evidence must replace the interrupted checkpoint digest");

    const driftedFixture = JSON.parse(JSON.stringify(fixture));
    const driftedContainer = driftedFixture.containers.find((item) => item.Name === "/enterprise-web");
    driftedContainer.Config.Labels["com.docker.compose.config-hash"] = digest("runtime drift after interrupted activation");
    installFakeDocker(fakeDocker, dockerLog, driftedFixture);
    const mismatch = executeController(controller, environment, "activate");
    assert.equal(mismatch.error, undefined);
    assert.equal(mismatch.status, 78);
    assert.match(mismatch.stderr, /existing LOCAL_PRIVATE activation state has runtime drift/);
    assert.deepEqual(JSON.parse(fs.readFileSync(stateFile, "utf8")), activatingState, "runtime mismatch must not refresh the interrupted state");
    assert.equal(fs.existsSync(receiptFile), false, "runtime mismatch must not mint an ACTIVE receipt");

    installFakeDocker(fakeDocker, dockerLog, fixture);
    const activation = runController(controller, environment, "activate");
    assert.equal(activation.status, "ACTIVE");
    assert.equal(activation.checkpointSha256, freshCheckpointSha256);
    assert.equal(activation.dockerMutation, false);
    assert.equal(activation.localArtifactTrust.schedulerRecovery.status, "RECOVERY_IMAGE_EXPORT_BOUND");
    const activeState = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    assert.equal(activeState.status, "ACTIVE");
    assert.equal(activeState.checkpointSha256, freshCheckpointSha256);
    assert.notEqual(activeState.checkpointSha256, activatingState.checkpointSha256);
    assert.deepEqual(activeState.observation, activatingState.observation, "checkpoint refresh must retain the exact frozen runtime observation");
    for (const field of ["candidateCommit", "candidateTree", "controller", "installReceiptSha256", "releaseRoot", "schema", "sourceArchiveSha256"]) {
      assert.deepEqual(activeState[field], activatingState[field], `crash recovery changed immutable state field ${field}`);
    }
    assert.deepEqual(JSON.parse(fs.readFileSync(systemctlState, "utf8")), { active: true, enabled: true, failEnable: false });
    assert.deepEqual(runController(controller, environment, "verify"), activation);

    const dockerCommands = fs.readFileSync(dockerLog, "utf8").trim().split("\n").map(JSON.parse);
    assert.equal(dockerCommands.some((args) => new Set(["create", "run", "start", "stop", "restart", "kill", "rm", "update", "pull", "push", "tag", "load", "import", "commit", "compose"]).has(args[0])), false);
    const schedulerMissingInspections = dockerCommands.filter((args) => JSON.stringify(args) === JSON.stringify(["image", "inspect", fixture.schedulerImageId]));
    assert.ok(schedulerMissingInspections.length >= 10, "missing scheduler image path was not retained through interruption, rejection, recovery, and verify");
    const systemctlCommands = fs.readFileSync(systemctlLog, "utf8").trim().split("\n").map(JSON.parse);
    assert.equal(systemctlCommands.filter((args) => JSON.stringify(args) === JSON.stringify(["enable", "--now", "platform-v1-local-private-control.service"])).length, 2, "only the interrupted and recovered attempts may reach the fixed host mutation");
  } finally {
    fs.rmSync(temporary, { force: true, recursive: true });
  }
});
