import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  V1_LOCAL_PRIVATE_CANDIDATE_COMMIT as commit,
  V1_LOCAL_PRIVATE_CANDIDATE_TREE as tree,
  V1_LOCAL_PRIVATE_CONTAINER_NAMES as names,
  V1_LOCAL_PRIVATE_READY_BUT_DISABLED as disabled,
  V1_LOCAL_PRIVATE_SOURCE_ARCHIVE_SHA256 as archive,
  verifyV1LocalPrivateControlReceipt,
} from "./v1-local-private-control-receipt.mjs";

const stableJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const hex = (index) => crypto.createHash("sha256").update(`fixture-${index}`).digest("hex");

function fixture() {
  const containers = names.map((name, index) => ({
    configHash: hex(`config-${index}`),
    containerId: hex(`container-${index}`),
    exitCode: 0,
    health: name === "phppgadmin" || new Set(["enterprise-local-dns", "enterprise-local-registry", "phpmyadmin"]).has(name) ? "none" : "healthy",
    imageAvailability: name === "enterprise-backup-scheduler" ? "RECOVERY_IMAGE_EXPORT_BOUND" : "LOCAL_IMAGE_STORE",
    imageId: `sha256:${hex(`image-${index}`)}`,
    name,
    project: name === "node-opstudents" ? "opstudents" : "platform_infra_vps",
    service: name.replace(/^enterprise-/, ""),
    state: name === "phppgadmin" ? "exited" : "running",
  }));
  const ports = [
    { containerName: "enterprise-local-dns", containerPort: 53, hostIp: "192.168.1.164", hostPort: 53, protocol: "tcp" },
    { containerName: "enterprise-local-dns", containerPort: 53, hostIp: "192.168.1.164", hostPort: 53, protocol: "udp" },
    { containerName: "enterprise-local-registry", containerPort: 5000, hostIp: "127.0.0.1", hostPort: 5000, protocol: "tcp" },
    { containerName: "enterprise-waf", containerPort: 8080, hostIp: "0.0.0.0", hostPort: 80, protocol: "tcp" },
    { containerName: "enterprise-waf", containerPort: 8443, hostIp: "0.0.0.0", hostPort: 443, protocol: "tcp" },
  ];
  const scheduler = containers.find((item) => item.name === "enterprise-backup-scheduler");
  const recoveryImageId = `sha256:${hex("scheduler-recovery-index")}`;
  const recoveryConfigDigest = `sha256:${hex("scheduler-recovery-config")}`;
  const recoveryManifestDigest = `sha256:${hex("scheduler-recovery-manifest")}`;
  const base = {
    activatedAtUnixSeconds: 1_800_000_000,
    authorityMode: "LOCAL_PRIVATE",
    candidateCommit: commit,
    candidateTree: tree,
    checkpointSha256: hex("checkpoint"),
    containerRecreate: false,
    controller: {
      installedPath: "/usr/local/libexec/platform-v1-local-private-control",
      sha256: hex("controller"),
      unitPath: "/etc/systemd/system/platform-v1-local-private-control.service",
      unitSha256: hex("unit"),
    },
    dataMutation: false,
    dockerControlPlane: { mode: "LOCAL_ROOT_SYSTEMD_SUPERVISOR", providerBrokerStatus: "READY_BUT_DISABLED", service: "platform-v1-local-private-control.service", status: "ACTIVE" },
    dockerMutation: false,
    externalDependencies: [
      { name: "HOSTINGER", status: "NOT_REQUIRED" },
      { name: "CLOUDFLARE", status: "NOT_REQUIRED" },
      { name: "PUBLIC_DNS", status: "READY_BUT_DISABLED" },
      { name: "EXTERNAL_DAST", status: "READY_BUT_DISABLED" },
      { name: "SIGSTORE_PROMOTION", status: "READY_BUT_DISABLED" },
      { name: "PUBLIC_PROVIDER", status: "READY_BUT_DISABLED" },
    ],
    hostControlMutation: true,
    installReceiptSha256: hex("install"),
    localArtifactTrust: {
      mode: "LOCAL_DOCKER_IMMUTABLE_IMAGE_ID",
      status: "PASS",
      schedulerRecovery: {
        archiveFormat: "OCI_DOCKER_SAVE_V1",
        configDigest: recoveryConfigDigest,
        configHash: scheduler.configHash,
        containerId: scheduler.containerId,
        containerName: "enterprise-backup-scheduler",
        exportLabels: {
          "com.platform.v1.local-private.candidate-commit": commit,
          "com.platform.v1.local-private.scheduler-config-hash": scheduler.configHash,
          "com.platform.v1.local-private.scheduler-container-id": scheduler.containerId,
          "com.platform.v1.local-private.scheduler-running-image-id": scheduler.imageId,
        },
        exportPath: "/var/lib/platform-infrastructure/v1/predeploy/current/scheduler-recovery-image.tar",
        exportSha256: hex("scheduler-export"),
        exportSizeBytes: 2048,
        imageIndexDigest: recoveryImageId,
        imageIndexPath: `blobs/sha256/${recoveryImageId.slice("sha256:".length)}`,
        imageManifestDigest: recoveryManifestDigest,
        manifestConfig: `blobs/sha256/${recoveryConfigDigest.slice("sha256:".length)}`,
        recoveryImageId,
        recoveryTag: `platform/v1-scheduler-recovery:${commit}`,
        runningImageId: scheduler.imageId,
        status: "RECOVERY_IMAGE_EXPORT_BOUND",
      },
      subjects: containers.map(({ configHash, containerId, imageAvailability, imageId, name }) => ({ configHash, containerId, imageAvailability, imageId, name })),
    },
    mutationModel: "ADDITIVE_ADOPTION",
    mutationPerformed: true,
    networkIsolation: { policy: "EDGE_PUBLISHED_PORT_ALLOWLIST", publishedPorts: ports, status: "PASS" },
    providerComponents: [
      { name: "PROVIDER_DOCKER_ACTION_ACTIVATION_SIDECAR", status: "READY_BUT_DISABLED" },
      { name: "PROVIDER_DOCKER_ACTION_BROKER", status: "READY_BUT_DISABLED" },
      { name: "PROVIDER_SOCKETLESS_BACKUP_SCHEDULER", status: "READY_BUT_DISABLED" },
    ],
    readyButDisabled: [...disabled],
    releaseRoot: `/srv/platform-infrastructure/releases/${commit}-${archive}`,
    runtime: {
      containerCount: 35,
      containers,
      daemon: { dockerRootDir: "/var/lib/docker", id: "daemon-id", name: "vps", serverVersion: "28.0.0" },
      exitedCount: 1,
      rawDockerAuthority: { containerId: scheduler.containerId, name: scheduler.name, readOnly: false, source: "/var/run/docker.sock", status: "PASS", target: "/var/run/docker.sock" },
      runningCount: 34,
    },
    schema: "platform.v1-local-private-control-receipt/v1",
    sourceArchiveSha256: archive,
    status: "ACTIVE",
    supervisor: { active: true, enabled: true, service: "platform-v1-local-private-control.service", status: "ACTIVE", type: "ROOT_SYSTEMD_NOTIFY" },
  };
  return { ...base, documentId: sha(stableJson(base)) };
}

function writeReceipt(root, receipt) {
  const filename = path.join(root, "receipt.json");
  fs.writeFileSync(filename, `${stableJson(receipt)}\n`, { mode: 0o600 });
  return filename;
}

function verify(file) {
  return verifyV1LocalPrivateControlReceipt({
    file,
    candidateCommit: commit,
    candidateTree: tree,
    sourceArchiveSha256: archive,
    controllerSha256: hex("controller"),
    unitSha256: hex("unit"),
  });
}

test("accepts the exact ACTIVE LOCAL_PRIVATE additive-adoption receipt", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-local-private-receipt-"));
  try {
    const receipt = fixture();
    assert.equal(verify(writeReceipt(root, receipt)).documentId, receipt.documentId);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

for (const [label, mutate, expected] of [
  ["Docker mutation", (value) => { value.dockerMutation = true; }, /mutation truth/i],
  ["controller checkout mismatch", (value) => { value.controller.sha256 = hex("unapproved-controller"); }, /approved checkout artifacts/i],
  ["provider activation", (value) => { value.providerComponents[1].status = "ACTIVE"; }, /provider components/i],
  ["extra publish", (value) => { value.networkIsolation.publishedPorts.push({ containerName: "enterprise-postgres", containerPort: 5432, hostIp: "0.0.0.0", hostPort: 5432, protocol: "tcp" }); }, /exactly five/i],
  ["missing container", (value) => { value.runtime.containers.pop(); }, /cardinality/i],
  ["scheduler running/recovery image mismatch", (value) => { value.localArtifactTrust.schedulerRecovery.runningImageId = value.localArtifactTrust.schedulerRecovery.recoveryImageId; }, /recovery status\/identity/i],
  ["false supervisor", (value) => { value.supervisor.active = false; }, /supervisor/i],
]) {
  test(`rejects ${label}`, () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-local-private-receipt-"));
    try {
      const receipt = fixture();
      mutate(receipt);
      const withoutId = { ...receipt };
      delete withoutId.documentId;
      receipt.documentId = sha(stableJson(withoutId));
      assert.throws(() => verify(writeReceipt(root, receipt)), expected);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
}

test("pins the unit bytes and exposes no Docker mutation command", () => {
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
  const source = fs.readFileSync(path.join(root, "scripts/v1-local-private-control.py"), "utf8");
  const unit = fs.readFileSync(path.join(root, "systemd/platform-v1-local-private-control.service"));
  assert.match(source, new RegExp(`UNIT_SHA256 = "${sha(unit)}"`));
  assert.doesNotMatch(source, /\[DOCKER,\s*"(?:create|run|start|stop|restart|rm|kill|update|pull|compose)"/);
  assert.match(source, /systemctl\(\["enable", "--now", UNIT_NAME\]/);
  assert.doesNotMatch(unit.toString("utf8"), /^ExecStop=/m);
});
