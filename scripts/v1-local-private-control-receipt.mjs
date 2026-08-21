#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

export const V1_LOCAL_PRIVATE_CANDIDATE_COMMIT = "832bf2baec47055342af7e7f73425444381b91e0";
export const V1_LOCAL_PRIVATE_CANDIDATE_TREE = "91cee2380809cb0691b9ac47cafa2a673d434caa";
export const V1_LOCAL_PRIVATE_SOURCE_ARCHIVE_SHA256 = "6eabff5f3fdbb4b129519d23a2dd9864f65477c5f0e1ecb58e1b8a9a79af3007";
export const V1_LOCAL_PRIVATE_CONTAINER_NAMES = Object.freeze([
  "enterprise-alertmanager", "enterprise-backend", "enterprise-backup-scheduler",
  "enterprise-cadvisor", "enterprise-control-center", "enterprise-grafana",
  "enterprise-keycloak", "enterprise-local-dns", "enterprise-local-registry",
  "enterprise-loki", "enterprise-minio", "enterprise-nats", "enterprise-node-exporter",
  "enterprise-postgres", "enterprise-project-router", "enterprise-prometheus",
  "enterprise-promtail", "enterprise-redis", "enterprise-traefik", "enterprise-waf",
  "enterprise-web", "enterprise-worker-jobs", "enterprise-worker-notifications",
  "mariadb", "node-account", "node-opstudents", "node-ui", "php-anniversary",
  "php-apache", "php-fiplatform", "php-matthewdifilippo", "php-stream",
  "php-workcalendar", "phpmyadmin", "phppgadmin",
]);
export const V1_LOCAL_PRIVATE_READY_BUT_DISABLED = Object.freeze([
  "PROVIDER_ADMISSION", "DNS_PUBLICATION", "DAST", "SIGSTORE_PROMOTION",
  "PROVIDER_DOCKER_ACTION_ACTIVATION_SIDECAR", "PROVIDER_DOCKER_ACTION_BROKER",
  "PROVIDER_SOCKETLESS_BACKUP_SCHEDULER",
]);

const SCHEMA = "platform.v1-local-private-control-receipt/v1";
const MAX_BYTES = 128 * 1024;
const SHA256 = /^[a-f0-9]{64}$/;
const IMAGE_ID = /^sha256:[a-f0-9]{64}$/;
const TOP_FIELDS = Object.freeze([
  "activatedAtUnixSeconds", "authorityMode", "candidateCommit",
  "candidateTree", "checkpointSha256", "containerRecreate", "controller", "dataMutation",
  "dockerControlPlane", "dockerMutation", "documentId", "externalDependencies", "hostControlMutation", "installReceiptSha256",
  "localArtifactTrust", "mutationModel", "mutationPerformed", "networkIsolation",
  "providerComponents", "readyButDisabled", "releaseRoot", "runtime", "schema",
  "sourceArchiveSha256", "status", "supervisor",
]);

function invalid(message) { throw new Error(message); }
function exactObject(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid(`${label} must be one object.`);
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) invalid(`${label} has missing or unexpected fields.`);
  return value;
}
function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
function sha(value, label) {
  if (typeof value !== "string" || !SHA256.test(value) || /^0+$/.test(value)) invalid(`${label} must be one non-placeholder lowercase SHA-256.`);
  return value;
}
function same(value, expected, label) { if (value !== expected) invalid(`${label} differs from the frozen V1 binding.`); }
function sha256Text(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function canonicalArray(value, expected, label) {
  if (JSON.stringify(value) !== JSON.stringify(expected)) invalid(`${label} is not the exact closed sequence.`);
}

function verifyPorts(networkIsolation) {
  exactObject(networkIsolation, ["policy", "publishedPorts", "status"], "Network isolation");
  if (networkIsolation.policy !== "EDGE_PUBLISHED_PORT_ALLOWLIST" || networkIsolation.status !== "PASS") invalid("Network isolation is not PASS under the fixed edge policy.");
  const ports = networkIsolation.publishedPorts;
  if (!Array.isArray(ports) || ports.length !== 5) invalid("Published-port allowlist must contain exactly five bindings.");
  for (const port of ports) {
    exactObject(port, ["containerName", "containerPort", "hostIp", "hostPort", "protocol"], "Published port");
    if (!Number.isInteger(port.containerPort) || !Number.isInteger(port.hostPort) || !new Set(["tcp", "udp"]).has(port.protocol)) invalid("Published port is invalid.");
  }
  const signature = new Set(ports.map((port) => `${port.containerName}|${port.hostIp}|${port.hostPort}|${port.containerPort}|${port.protocol}`));
  const waf = new Set(["enterprise-waf|0.0.0.0|80|8080|tcp", "enterprise-waf|0.0.0.0|443|8443|tcp"]);
  for (const entry of waf) if (!signature.has(entry)) invalid("WAF 80/443 bindings are not exact.");
  const registry = ports.filter((port) => port.containerName === "enterprise-local-registry");
  if (registry.length !== 1 || registry[0].hostIp !== "127.0.0.1" || registry[0].hostPort !== 5000 || registry[0].containerPort !== 5000 || registry[0].protocol !== "tcp") invalid("Registry binding is not loopback TCP 5000.");
  const dns = ports.filter((port) => port.containerName === "enterprise-local-dns");
  if (dns.length !== 2 || dns[0].hostIp !== dns[1].hostIp || dns.some((port) => port.hostPort !== 53 || port.containerPort !== 53) || new Set(dns.map((port) => port.protocol)).size !== 2) invalid("DNS bindings are not one LAN TCP/UDP 53 pair.");
  if (!/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/.test(dns[0].hostIp)) invalid("DNS binding is not an IPv4 private-LAN address.");
  if (ports.some((port) => !new Set(["enterprise-waf", "enterprise-local-dns", "enterprise-local-registry"]).has(port.containerName))) invalid("A non-edge container publishes a host port.");
}

function verifyRuntime(runtime) {
  exactObject(runtime, ["containerCount", "containers", "daemon", "exitedCount", "rawDockerAuthority", "runningCount"], "Runtime");
  if (runtime.containerCount !== 35 || runtime.runningCount !== 34 || runtime.exitedCount !== 1 || !Array.isArray(runtime.containers) || runtime.containers.length !== 35) invalid("Runtime cardinality differs from the closed brownfield identity.");
  exactObject(runtime.daemon, ["dockerRootDir", "id", "name", "serverVersion"], "Docker daemon");
  if (Object.values(runtime.daemon).some((value) => typeof value !== "string" || !value)) invalid("Docker daemon identity is incomplete.");
  const noHealth = new Set(["enterprise-local-dns", "enterprise-local-registry", "phpmyadmin"]);
  const ids = new Set();
  for (const container of runtime.containers) {
    exactObject(container, ["configHash", "containerId", "exitCode", "health", "imageAvailability", "imageId", "name", "project", "service", "state"], "Runtime container");
    sha(container.configHash, `Container ${container.name} config hash`);
    sha(container.containerId, `Container ${container.name} ID`);
    if (!IMAGE_ID.test(container.imageId) || ids.has(container.containerId)) invalid(`Container ${container.name} immutable identity is invalid or duplicated.`);
    const expectedAvailability = container.name === "enterprise-backup-scheduler" ? "RECOVERY_IMAGE_EXPORT_BOUND" : "LOCAL_IMAGE_STORE";
    if (container.imageAvailability !== expectedAvailability) invalid(`Container ${container.name} image availability is invalid.`);
    ids.add(container.containerId);
    const expectedProject = container.name === "node-opstudents" ? "opstudents" : "platform_infra_vps";
    if (container.project !== expectedProject || typeof container.service !== "string" || !/^[A-Za-z0-9_.-]{1,128}$/.test(container.service)) invalid(`Container ${container.name} Compose identity is invalid.`);
    if (!Number.isInteger(container.exitCode)) invalid(`Container ${container.name} exit state is invalid.`);
    if (container.name === "phppgadmin") {
      if (container.state !== "exited") invalid("phppgadmin must be the only exited container.");
    } else if (container.state !== "running" || (noHealth.has(container.name) ? container.health !== "none" : container.health !== "healthy")) {
      invalid(`Container ${container.name} state/health is invalid.`);
    }
  }
  canonicalArray(runtime.containers.map((item) => item.name), V1_LOCAL_PRIVATE_CONTAINER_NAMES, "Runtime container names");
  const raw = exactObject(runtime.rawDockerAuthority, ["containerId", "name", "readOnly", "source", "status", "target"], "Raw Docker authority");
  if (raw.name !== "enterprise-backup-scheduler" || raw.readOnly !== false || raw.status !== "PASS" || !new Set(["/run/docker.sock", "/var/run/docker.sock"]).has(raw.source) || !new Set(["/run/docker.sock", "/var/run/docker.sock"]).has(raw.target)) invalid("Raw Docker authority is not the one receipt-bound RW scheduler.");
  if (runtime.containers.find((item) => item.name === raw.name)?.containerId !== raw.containerId) invalid("Raw Docker authority container ID is not receipt-bound.");
}

export function verifyV1LocalPrivateControlReceipt({ file, candidateCommit, candidateTree, sourceArchiveSha256, controllerSha256, unitSha256 }) {
  same(candidateCommit, V1_LOCAL_PRIVATE_CANDIDATE_COMMIT, "Expected candidate commit");
  same(candidateTree, V1_LOCAL_PRIVATE_CANDIDATE_TREE, "Expected candidate tree");
  same(sourceArchiveSha256, V1_LOCAL_PRIVATE_SOURCE_ARCHIVE_SHA256, "Expected source archive SHA-256");
  sha(controllerSha256, "Expected controller bytes");
  sha(unitSha256, "Expected controller unit bytes");
  const filename = String(file ?? "").trim();
  if (!filename) invalid("V1 LOCAL_PRIVATE receipt path is required.");
  let metadata;
  try { metadata = fs.lstatSync(filename); } catch { invalid("V1 LOCAL_PRIVATE receipt is missing."); }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size < 2 || metadata.size > MAX_BYTES) invalid("V1 LOCAL_PRIVATE receipt identity/size is invalid.");
  const raw = fs.readFileSync(filename, "utf8");
  let receipt;
  try { receipt = JSON.parse(raw); } catch { invalid("V1 LOCAL_PRIVATE receipt is not valid JSON."); }
  exactObject(receipt, TOP_FIELDS, "V1 LOCAL_PRIVATE receipt");
  if (`${stableJson(receipt)}\n` !== raw) invalid("V1 LOCAL_PRIVATE receipt is not canonical JSON.");
  if (receipt.schema !== SCHEMA || receipt.status !== "ACTIVE" || receipt.authorityMode !== "LOCAL_PRIVATE") invalid("V1 LOCAL_PRIVATE receipt status/schema/authority is invalid.");
  same(receipt.candidateCommit, candidateCommit, "Receipt candidate commit");
  same(receipt.candidateTree, candidateTree, "Receipt candidate tree");
  same(receipt.sourceArchiveSha256, sourceArchiveSha256, "Receipt source archive SHA-256");
  same(receipt.releaseRoot, `/srv/platform-infrastructure/releases/${candidateCommit}-${sourceArchiveSha256}`, "Receipt release root");
  if (receipt.mutationModel !== "ADDITIVE_ADOPTION") invalid("Receipt mutation model is invalid.");
  if (receipt.dockerMutation !== false || receipt.dataMutation !== false || receipt.containerRecreate !== false || receipt.hostControlMutation !== true || receipt.mutationPerformed !== true) invalid("Receipt mutation truth is invalid.");
  exactObject(receipt.dockerControlPlane, ["mode", "providerBrokerStatus", "service", "status"], "Docker control plane");
  if (receipt.dockerControlPlane.status !== "ACTIVE" || receipt.dockerControlPlane.mode !== "LOCAL_ROOT_SYSTEMD_SUPERVISOR" || receipt.dockerControlPlane.service !== "platform-v1-local-private-control.service" || receipt.dockerControlPlane.providerBrokerStatus !== "READY_BUT_DISABLED") invalid("Docker control plane is not the exact active local supervisor/provider-disabled split.");
  if (!Number.isInteger(receipt.activatedAtUnixSeconds) || receipt.activatedAtUnixSeconds < 1_700_000_000) invalid("Receipt activation timestamp is invalid.");
  sha(receipt.checkpointSha256, "Receipt checkpoint");
  sha(receipt.installReceiptSha256, "Receipt install evidence");
  exactObject(receipt.controller, ["installedPath", "sha256", "unitPath", "unitSha256"], "Controller identity");
  if (receipt.controller.installedPath !== "/usr/local/libexec/platform-v1-local-private-control" || receipt.controller.unitPath !== "/etc/systemd/system/platform-v1-local-private-control.service") invalid("Controller installed paths are invalid.");
  sha(receipt.controller.sha256, "Controller bytes");
  sha(receipt.controller.unitSha256, "Controller unit bytes");
  if (receipt.controller.sha256 !== controllerSha256 || receipt.controller.unitSha256 !== unitSha256) invalid("Receipt controller/unit bytes differ from the approved checkout artifacts.");
  canonicalArray(receipt.readyButDisabled, V1_LOCAL_PRIVATE_READY_BUT_DISABLED, "READY_BUT_DISABLED set");
  canonicalArray(receipt.providerComponents, [
    { name: "PROVIDER_DOCKER_ACTION_ACTIVATION_SIDECAR", status: "READY_BUT_DISABLED" },
    { name: "PROVIDER_DOCKER_ACTION_BROKER", status: "READY_BUT_DISABLED" },
    { name: "PROVIDER_SOCKETLESS_BACKUP_SCHEDULER", status: "READY_BUT_DISABLED" },
  ], "Provider components");
  canonicalArray(receipt.externalDependencies, [
    { name: "HOSTINGER", status: "NOT_REQUIRED" },
    { name: "CLOUDFLARE", status: "NOT_REQUIRED" },
    { name: "PUBLIC_DNS", status: "READY_BUT_DISABLED" },
    { name: "EXTERNAL_DAST", status: "READY_BUT_DISABLED" },
    { name: "SIGSTORE_PROMOTION", status: "READY_BUT_DISABLED" },
    { name: "PUBLIC_PROVIDER", status: "READY_BUT_DISABLED" },
  ], "External dependencies");
  verifyRuntime(receipt.runtime);
  verifyPorts(receipt.networkIsolation);
  exactObject(receipt.localArtifactTrust, ["mode", "schedulerRecovery", "status", "subjects"], "Local artifact trust");
  if (receipt.localArtifactTrust.mode !== "LOCAL_DOCKER_IMMUTABLE_IMAGE_ID" || receipt.localArtifactTrust.status !== "PASS") invalid("Local artifact trust mode/status is invalid.");
  const subjects = receipt.runtime.containers.map(({ configHash, containerId, imageAvailability, imageId, name }) => ({ configHash, containerId, imageAvailability, imageId, name }));
  canonicalArray(receipt.localArtifactTrust.subjects, subjects, "Local artifact subjects");
  const recovery = exactObject(receipt.localArtifactTrust.schedulerRecovery, [
    "archiveFormat", "configDigest", "configHash", "containerId", "containerName",
    "exportLabels", "exportPath", "exportSha256", "exportSizeBytes", "imageIndexDigest",
    "imageIndexPath", "imageManifestDigest", "manifestConfig", "recoveryImageId",
    "recoveryTag", "runningImageId", "status",
  ], "Scheduler recovery");
  if (recovery.containerName !== "enterprise-backup-scheduler" || recovery.status !== "RECOVERY_IMAGE_EXPORT_BOUND" || recovery.runningImageId === recovery.recoveryImageId) invalid("Scheduler recovery status/identity is invalid.");
  sha(recovery.exportSha256, "Scheduler recovery export");
  sha(recovery.configHash, "Scheduler recovery config hash");
  sha(recovery.containerId, "Scheduler recovery container ID");
  const runtimeScheduler = receipt.runtime.containers.find((item) => item.name === recovery.containerName);
  if (!IMAGE_ID.test(recovery.recoveryImageId) || recovery.runningImageId !== runtimeScheduler?.imageId || recovery.containerId !== runtimeScheduler?.containerId || recovery.configHash !== runtimeScheduler?.configHash) invalid("Scheduler recovery artifact is not truthfully runtime-bound.");
  if (recovery.exportPath !== "/var/lib/platform-infrastructure/v1/predeploy/current/scheduler-recovery-image.tar" || !Number.isSafeInteger(recovery.exportSizeBytes) || recovery.exportSizeBytes < 1024 || recovery.exportSizeBytes > 4 * 1024 * 1024 * 1024) invalid("Scheduler recovery export path/size is invalid.");
  const recoveryHex = recovery.recoveryImageId.slice("sha256:".length);
  if (
    recovery.archiveFormat !== "OCI_DOCKER_SAVE_V1"
    || !IMAGE_ID.test(recovery.configDigest)
    || !IMAGE_ID.test(recovery.imageManifestDigest)
    || recovery.imageIndexDigest !== recovery.recoveryImageId
    || recovery.imageIndexPath !== `blobs/sha256/${recoveryHex}`
    || recovery.manifestConfig !== `blobs/sha256/${recovery.configDigest.slice("sha256:".length)}`
    || recovery.recoveryTag !== `platform/v1-scheduler-recovery:${candidateCommit}`
  ) invalid("Scheduler recovery OCI descriptor chain/tag is invalid.");
  const exportLabels = exactObject(recovery.exportLabels, [
    "com.platform.v1.local-private.candidate-commit",
    "com.platform.v1.local-private.scheduler-config-hash",
    "com.platform.v1.local-private.scheduler-container-id",
    "com.platform.v1.local-private.scheduler-running-image-id",
  ], "Scheduler recovery export labels");
  if (
    exportLabels["com.platform.v1.local-private.candidate-commit"] !== candidateCommit
    || exportLabels["com.platform.v1.local-private.scheduler-config-hash"] !== recovery.configHash
    || exportLabels["com.platform.v1.local-private.scheduler-container-id"] !== recovery.containerId
    || exportLabels["com.platform.v1.local-private.scheduler-running-image-id"] !== recovery.runningImageId
  ) invalid("Scheduler recovery OCI config labels are not receipt-bound.");
  exactObject(receipt.supervisor, ["active", "enabled", "service", "status", "type"], "Supervisor");
  if (receipt.supervisor.active !== true || receipt.supervisor.enabled !== true || receipt.supervisor.service !== "platform-v1-local-private-control.service" || receipt.supervisor.status !== "ACTIVE" || receipt.supervisor.type !== "ROOT_SYSTEMD_NOTIFY") invalid("Supervisor is not truthfully ACTIVE.");
  const copy = { ...receipt };
  delete copy.documentId;
  if (receipt.documentId !== sha256Text(stableJson(copy))) invalid("Receipt documentId is invalid.");
  return Object.freeze(receipt);
}

function options(args) {
  if (args[0] !== "verify") invalid("Usage: v1-local-private-control-receipt.mjs verify --file FILE --candidateCommit SHA --candidateTree SHA --sourceArchiveSha256 SHA256 --controllerSha256 SHA256 --unitSha256 SHA256");
  const allowed = new Set(["file", "candidateCommit", "candidateTree", "sourceArchiveSha256", "controllerSha256", "unitSha256"]);
  const result = {};
  for (let index = 1; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!flag?.startsWith("--") || value === undefined || value.startsWith("--")) invalid("V1 LOCAL_PRIVATE options must be value-bearing.");
    const key = flag.slice(2);
    if (!allowed.has(key) || Object.hasOwn(result, key)) invalid(`Unknown or duplicate V1 LOCAL_PRIVATE option: ${flag}.`);
    result[key] = value;
  }
  for (const key of allowed) if (!Object.hasOwn(result, key)) invalid(`V1 LOCAL_PRIVATE receipt is missing --${key}.`);
  return result;
}

function main() {
  verifyV1LocalPrivateControlReceipt(options(process.argv.slice(2)));
  process.stdout.write("V1 LOCAL_PRIVATE control receipt verified.\n");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  try { main(); } catch (error) { process.stderr.write(`${String(error?.message ?? error)}\n`); process.exitCode = 1; }
}
