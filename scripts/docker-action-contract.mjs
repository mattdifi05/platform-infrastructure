import crypto from "node:crypto";

export const REQUEST_SCHEMA = "platform.docker-action.request/v1";
export const RUNTIME_INTENT_SCHEMA = "platform.docker-runtime-intent/v1";
export const ACTIVE_RECEIPT_SCHEMA = "platform.docker-active-receipt/v1";
export const MAX_REQUEST_BYTES = 16 * 1024;
export const MAX_CLOCK_SKEW_MS = 30_000;
export const MAX_REQUEST_LIFETIME_MS = 60_000;

export const ACTIONS = Object.freeze({
  "backup.catalog": Object.freeze({
    capabilityId: "backup.catalog.v1",
    capabilityFile: "/run/secrets/docker_action_backup_catalog",
    modeled: false,
    unsupportedReason: "dedicated socketless database and state backup worker is not implemented",
    parameters: Object.freeze([]),
  }),
  "backup.job.execute": Object.freeze({
    capabilityId: "backup.job.execute.v1",
    capabilityFile: "/run/secrets/docker_action_backup_job_execute",
    modeled: false,
    unsupportedReason: "dedicated socketless typed backup worker is not implemented",
    parameters: Object.freeze(["jobId"]),
  }),
  "backup.prune.plan": Object.freeze({
    capabilityId: "backup.prune.plan.v1",
    capabilityFile: "/run/secrets/docker_action_backup_prune_plan",
    modeled: true,
    workerCommand: "backup-prune-plan",
    parameters: Object.freeze([]),
  }),
  "backup.prune.apply": Object.freeze({
    capabilityId: "backup.prune.apply.v1",
    capabilityFile: "/run/secrets/docker_action_backup_prune_apply",
    modeled: false,
    unsupportedReason: "authenticated deletion worker is not implemented",
    parameters: Object.freeze([]),
  }),
  "restore.drill.full": Object.freeze({
    capabilityId: "restore.drill.full.v1",
    capabilityFile: "/run/secrets/docker_action_restore_drill_full",
    modeled: false,
    unsupportedReason: "dedicated disposable restore workers are not implemented",
    parameters: Object.freeze([]),
  }),
  "backup.offsite.sync": Object.freeze({
    capabilityId: "backup.offsite.sync.v1",
    capabilityFile: "/run/secrets/docker_action_backup_offsite_sync",
    modeled: false,
    unsupportedReason: "dedicated egress-constrained offsite worker is not implemented",
    parameters: Object.freeze([]),
  }),
  "evidence.runtime.snapshot": Object.freeze({
    capabilityId: "evidence.runtime.snapshot.v1",
    capabilityFile: "/run/secrets/docker_action_evidence_runtime_snapshot",
    engineAction: "runtimeSnapshot",
    modeled: true,
    parameters: Object.freeze([]),
  }),
});

export const CLI_ACTIONS = Object.freeze({
  "backup-platform-catalog": "backup.catalog",
  "execute-backup-job": "backup.job.execute",
  "prune-manifest-backups-plan": "backup.prune.plan",
  "prune-manifest-backups-apply": "backup.prune.apply",
  "full-restore-drill": "restore.drill.full",
  "offsite-backup-restic": "backup.offsite.sync",
  "runtime-docker-snapshot": "evidence.runtime.snapshot",
});

const SHA256 = /^[a-f0-9]{64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LOGICAL_ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const BACKUP_RESOURCE_ID = /^(?:source|database|storage|platform-state):[a-z0-9](?:[a-z0-9._:-]{0,158}[a-z0-9])?$/;
const CONTAINER_NAME = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;
const DIGEST_IMAGE = /^[a-zA-Z0-9][a-zA-Z0-9._/:+-]*@sha256:[a-f0-9]{64}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const ALLOWED_CONTAINER_PATHS = new Set([
  "/opt/platform-infrastructure",
  "/opt/platform-infrastructure/backups",
  "/opt/platform-infrastructure/reports",
  "/data/backups",
  "/project",
  "/var/www/project-state",
]);

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function hmac(value, key) {
  return crypto.createHmac("sha256", normalizeKey(key)).update(canonicalJson(value)).digest("hex");
}

export function signRuntimeIntent(intent, trustKey) {
  const unsigned = withoutKey(intent, "mac");
  return { ...unsigned, mac: hmac(unsigned, trustKey) };
}

export function signActionRequest(request, capabilityKey) {
  const unsigned = withoutKey(request, "mac");
  return { ...unsigned, mac: hmac(unsigned, capabilityKey) };
}

export function normalizeTrustedContext(intentValue, receiptValue, trustKey, { now = Date.now() } = {}) {
  const intent = assertPlainObject(intentValue, "runtime intent");
  assertExactKeys(intent, [
    "activeReceiptSha256",
    "activationBundleSha256",
    "allowedActions",
    "candidateId",
    "combinedRenderSha256",
    "dastChainSha256",
    "environment",
    "expiresAt",
    "generation",
    "intentId",
    "issuedAt",
    "mac",
    "releaseId",
    "schema",
    "targetId",
  ], "runtime intent");
  if (intent.schema !== RUNTIME_INTENT_SCHEMA) fail(403, "unsupported runtime intent schema");
  assertLogicalId(intent.intentId, "intentId");
  assertLogicalId(intent.releaseId, "releaseId");
  assertLogicalId(intent.candidateId, "candidateId");
  assertLogicalId(intent.environment, "environment");
  assertLogicalId(intent.targetId, "targetId");
  if (!Number.isSafeInteger(intent.generation) || intent.generation < 1) fail(403, "runtime intent generation is invalid");
  assertTimeWindow(intent.issuedAt, intent.expiresAt, now, 24 * 60 * 60_000, "runtime intent");
  if (!SHA256.test(String(intent.activeReceiptSha256 ?? ""))) fail(403, "runtime intent receipt digest is invalid");
  if (!SHA256.test(String(intent.activationBundleSha256 ?? ""))) fail(403, "runtime intent activation bundle digest is invalid");
  if (!SHA256.test(String(intent.combinedRenderSha256 ?? ""))) fail(403, "runtime intent combined render digest is invalid");
  if (!SHA256.test(String(intent.dastChainSha256 ?? ""))) fail(403, "runtime intent DAST chain digest is invalid");
  if (!Array.isArray(intent.allowedActions) || intent.allowedActions.length < 1) fail(403, "runtime intent has no allowed actions");
  const allowedActions = [...new Set(intent.allowedActions.map(String))];
  if (allowedActions.length !== intent.allowedActions.length || allowedActions.some((action) => !ACTIONS[action]?.modeled)) {
    fail(403, "runtime intent contains an unsupported or duplicate action");
  }
  verifyMac(intent, trustKey, "runtime intent");

  const receipt = normalizeActiveReceipt(receiptValue, { now });
  const receiptDigest = sha256(canonicalJson(receipt));
  if (!constantEqual(receiptDigest, intent.activeReceiptSha256)) fail(403, "active receipt digest does not match runtime intent");
  if (receipt.releaseId !== intent.releaseId) fail(403, "active receipt release does not match runtime intent");
  if (receipt.generation !== intent.generation) fail(403, "active receipt generation does not match runtime intent");
  for (const name of ["activationBundleSha256", "candidateId", "dastChainSha256", "environment", "targetId"]) {
    if (!constantEqual(receipt[name], intent[name])) fail(403, `active receipt ${name} does not match runtime intent`);
  }
  if (!constantEqual(receipt.combinedRenderSha256, intent.combinedRenderSha256)) {
    fail(403, "active receipt combined render digest does not match runtime intent");
  }
  return Object.freeze({
    intent: Object.freeze({ ...intent, allowedActions: Object.freeze(allowedActions) }),
    receipt,
    receiptDigest,
  });
}

export function normalizeActiveReceipt(value, { now = Date.now() } = {}) {
  const receipt = assertPlainObject(value, "active receipt");
  assertExactKeys(receipt, [
    "activationBundleSha256",
    "candidateId",
    "combinedRenderSha256",
    "dastChainSha256",
    "environment",
    "expiresAt",
    "generation",
    "issuedAt",
    "receiptId",
    "releaseId",
    "resources",
    "schema",
    "sourceRenderSha256",
    "targetId",
    "treeSha256",
  ], "active receipt");
  if (receipt.schema !== ACTIVE_RECEIPT_SCHEMA) fail(403, "unsupported active receipt schema");
  assertLogicalId(receipt.receiptId, "receiptId");
  assertLogicalId(receipt.releaseId, "releaseId");
  assertLogicalId(receipt.candidateId, "candidateId");
  assertLogicalId(receipt.environment, "environment");
  assertLogicalId(receipt.targetId, "targetId");
  if (!Number.isSafeInteger(receipt.generation) || receipt.generation < 1) fail(403, "active receipt generation is invalid");
  for (const [name, value] of [
    ["treeSha256", receipt.treeSha256],
    ["activationBundleSha256", receipt.activationBundleSha256],
    ["sourceRenderSha256", receipt.sourceRenderSha256],
    ["combinedRenderSha256", receipt.combinedRenderSha256],
    ["dastChainSha256", receipt.dastChainSha256],
  ]) {
    if (!SHA256.test(String(value ?? ""))) fail(403, `active receipt ${name} is invalid`);
  }
  assertTimeWindow(receipt.issuedAt, receipt.expiresAt, now, 30 * 24 * 60 * 60_000, "active receipt");
  const resources = normalizeResources(receipt.resources);
  for (const [logicalId, container] of Object.entries(resources.containers)) {
    if (!constantEqual(container.labels["com.platform.runtime.candidate-id"], receipt.candidateId)
      || !constantEqual(container.labels["com.platform.runtime.source-render-sha256"], receipt.sourceRenderSha256)) {
      fail(403, `container ${logicalId} candidate or source render label does not match the active receipt`);
    }
  }
  return Object.freeze({ ...receipt, resources });
}

export function normalizeActionRequest(value, trusted, capabilityKey, { now = Date.now() } = {}) {
  const request = assertPlainObject(value, "request");
  assertExactKeys(request, [
    "action",
    "activeReceiptSha256",
    "capabilityId",
    "combinedRenderSha256",
    "expiresAt",
    "issuedAt",
    "mac",
    "nonce",
    "parameters",
    "requestId",
    "runtimeIntentId",
    "schema",
  ], "request");
  if (request.schema !== REQUEST_SCHEMA) fail(400, "unsupported request schema");
  if (!UUID_V4.test(String(request.requestId ?? ""))) fail(400, "requestId must be a UUID v4");
  if (!NONCE.test(String(request.nonce ?? ""))) fail(400, "nonce must encode exactly 32 random bytes");
  assertTimeWindow(request.issuedAt, request.expiresAt, now, MAX_REQUEST_LIFETIME_MS, "request");
  const issuedAt = Date.parse(request.issuedAt);
  if (Math.abs(now - issuedAt) > MAX_CLOCK_SKEW_MS) fail(401, "request timestamp is outside the accepted window");

  const action = String(request.action ?? "");
  const contract = ACTIONS[action];
  if (!contract) fail(403, "action is not authorized");
  if (!trusted.intent.allowedActions.includes(action)) fail(403, "action is not enabled by runtime intent");
  if (request.capabilityId !== contract.capabilityId) fail(403, "capability is not bound to this action");
  if (request.runtimeIntentId !== trusted.intent.intentId) fail(403, "request runtime intent does not match");
  if (!constantEqual(String(request.activeReceiptSha256 ?? ""), trusted.receiptDigest)) fail(403, "request active receipt does not match");
  if (!constantEqual(String(request.combinedRenderSha256 ?? ""), trusted.receipt.combinedRenderSha256)) {
    fail(403, "request combined render digest does not match");
  }
  const parameters = normalizeParameters(action, request.parameters, trusted.receipt.resources);
  verifyMac(request, capabilityKey, "request");
  return Object.freeze({
    action,
    capabilityId: contract.capabilityId,
    parameters,
    requestId: request.requestId,
    nonce: request.nonce,
    runtimeIntentId: request.runtimeIntentId,
    activeReceiptSha256: request.activeReceiptSha256,
    combinedRenderSha256: request.combinedRenderSha256,
  });
}

export function buildUnsignedRequest(action, parameters, trusted, { now = Date.now(), requestId = crypto.randomUUID(), nonce = crypto.randomBytes(32).toString("base64url") } = {}) {
  const contract = ACTIONS[action];
  if (!contract) fail(64, "unsupported action");
  const issuedAt = new Date(now);
  return {
    schema: REQUEST_SCHEMA,
    requestId,
    nonce,
    issuedAt: issuedAt.toISOString(),
    expiresAt: new Date(issuedAt.getTime() + 30_000).toISOString(),
    runtimeIntentId: trusted.intent.intentId,
    activeReceiptSha256: trusted.receiptDigest,
    combinedRenderSha256: trusted.receipt.combinedRenderSha256,
    capabilityId: contract.capabilityId,
    action,
    parameters,
  };
}

function normalizeParameters(action, value, resources) {
  const parameters = assertPlainObject(value, "parameters");
  assertExactKeys(parameters, ACTIONS[action].parameters, "parameters");
  if (action !== "backup.job.execute") return Object.freeze({});
  const jobId = String(parameters.jobId ?? "").toLowerCase();
  if (!UUID_V4.test(jobId)) fail(400, "jobId must be a UUID v4");
  if (!Object.keys(resources.backupResources).length) fail(403, "active receipt contains no admitted backup resources");
  return Object.freeze({ jobId });
}

function normalizeResources(value) {
  const resources = assertPlainObject(value, "active receipt resources");
  assertExactKeys(resources, ["backupResources", "containers", "mounts", "workerImage"], "active receipt resources");
  const backupResources = normalizeMap(resources.backupResources, "backupResources", normalizeBackupResource, BACKUP_RESOURCE_ID);
  const containers = normalizeMap(resources.containers, "containers", (entry, logicalId) => {
    assertExactKeys(entry, ["authority", "containerId", "expectedHealth", "expectedState", "imageId", "imageRef", "labels", "name"], `container ${logicalId}`);
    if (!CONTAINER_NAME.test(String(entry.name ?? ""))) fail(403, `container ${logicalId} name is invalid`);
    if (!/^[a-f0-9]{64}$/.test(String(entry.containerId ?? ""))) fail(403, `container ${logicalId} ID is invalid`);
    if (!DIGEST_IMAGE.test(String(entry.imageRef ?? ""))) fail(403, `container ${logicalId} image must be digest pinned`);
    if (!/^sha256:[a-f0-9]{64}$/.test(String(entry.imageId ?? ""))) fail(403, `container ${logicalId} image ID is invalid`);
    if (!["running", "exited"].includes(entry.expectedState)) fail(403, `container ${logicalId} expected state is invalid`);
    if (!["healthy", "none"].includes(entry.expectedHealth)) fail(403, `container ${logicalId} expected health is invalid`);
    const labels = normalizeIdentityLabels(entry.labels, logicalId);
    const authority = normalizeContainerAuthority(entry.authority, logicalId);
    return Object.freeze({
      containerId: entry.containerId,
      name: entry.name,
      imageRef: entry.imageRef,
      imageId: entry.imageId,
      labels,
      authority,
      expectedState: entry.expectedState,
      expectedHealth: entry.expectedHealth,
    });
  });
  const mounts = normalizeMap(resources.mounts, "mounts", (entry, logicalId) => {
    assertExactKeys(entry, [
      "access",
      "canonicalPath",
      "containerPath",
      "device",
      "inode",
      "kind",
      "mode",
      "ownerGid",
      "ownerUid",
      "symlinkFree",
    ], `mount ${logicalId}`);
    const hostPath = String(entry.canonicalPath ?? "");
    const containerPath = String(entry.containerPath ?? "");
    if (!hostPath.startsWith("/srv/platform/") || hostPath.includes("/../") || hostPath.includes("\0")) {
      fail(403, `mount ${logicalId} host path is outside the fixed platform root`);
    }
    if (!ALLOWED_CONTAINER_PATHS.has(containerPath)) fail(403, `mount ${logicalId} container path is not policy approved`);
    if (!["ro", "rw"].includes(entry.access)) fail(403, `mount ${logicalId} access is invalid`);
    if (entry.kind !== "directory" || entry.symlinkFree !== true || entry.ownerUid !== 0 || entry.ownerGid !== 0
      || !Number.isSafeInteger(entry.device) || entry.device < 0 || !Number.isSafeInteger(entry.inode) || entry.inode < 1
      || !Number.isSafeInteger(entry.mode) || entry.mode < 0 || entry.mode > 0o7777 || (entry.mode & 0o022) !== 0) {
      fail(403, `mount ${logicalId} attestation is invalid`);
    }
    return Object.freeze({
      access: entry.access,
      containerPath,
      hostPath,
      device: entry.device,
      inode: entry.inode,
      kind: entry.kind,
      mode: entry.mode,
      ownerUid: entry.ownerUid,
      ownerGid: entry.ownerGid,
      symlinkFree: true,
    });
  });
  const workerImage = assertPlainObject(resources.workerImage, "worker image");
  assertExactKeys(workerImage, ["imageId", "imageRef"], "worker image");
  if (!DIGEST_IMAGE.test(String(workerImage.imageRef ?? "")) || !/^sha256:[a-f0-9]{64}$/.test(String(workerImage.imageId ?? ""))) {
    fail(403, "worker image reference and image ID must be digest pinned");
  }
  validateContainerMountAuthority(containers, mounts);
  return Object.freeze({
    backupResources,
    containers,
    mounts,
    workerImage: Object.freeze({ imageRef: workerImage.imageRef, imageId: workerImage.imageId }),
  });
}

function normalizeMap(value, label, normalize, idPattern = LOGICAL_ID) {
  const map = assertPlainObject(value, label);
  const out = {};
  for (const logicalId of Object.keys(map).sort()) {
    if (!idPattern.test(logicalId)) fail(403, `${label} logical ID is invalid`);
    out[logicalId] = normalize(assertPlainObject(map[logicalId], `${label} ${logicalId}`), logicalId);
  }
  return Object.freeze(out);
}

function normalizeBackupResource(entry, logicalId) {
  const kind = logicalId.split(":", 1)[0];
  const common = ["externalId", "kind", "name", "projectId"];
  const expected = kind === "database" ? [...common, "engine"] : kind === "source" ? [...common, "sourceDirectory"] : common;
  assertExactKeys(entry, expected, `backup resource ${logicalId}`);
  if (entry.kind !== kind) fail(403, `backup resource ${logicalId} kind does not match its ID`);
  if (!LOGICAL_ID.test(String(entry.externalId ?? "")) || !LOGICAL_ID.test(String(entry.projectId ?? ""))) {
    fail(403, `backup resource ${logicalId} ownership is invalid`);
  }
  if (!CONTAINER_NAME.test(String(entry.name ?? ""))) fail(403, `backup resource ${logicalId} name is invalid`);
  const normalized = { id: logicalId, externalId: entry.externalId, kind, projectId: entry.projectId, name: entry.name };
  if (kind === "database") {
    if (!["postgres", "mariadb"].includes(entry.engine)) fail(403, `backup resource ${logicalId} engine is invalid`);
    normalized.engine = entry.engine;
  }
  if (kind === "source") {
    if (!CONTAINER_NAME.test(String(entry.sourceDirectory ?? ""))) fail(403, `backup resource ${logicalId} source directory is invalid`);
    normalized.sourceDirectory = entry.sourceDirectory;
  }
  return Object.freeze(normalized);
}

function normalizeIdentityLabels(value, logicalId) {
  const labels = assertPlainObject(value, `container ${logicalId} labels`);
  const keys = [
    "com.platform.runtime.candidate-id",
    "com.platform.runtime.commit",
    "com.platform.runtime.deployment-id",
    "com.platform.runtime.source-render-sha256",
    "com.platform.runtime.tree",
    "com.platform.runtime.workload-lock-sha256",
  ];
  assertExactKeys(labels, keys, `container ${logicalId} labels`);
  const out = {};
  for (const key of keys) {
    const text = String(labels[key] ?? "");
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/.test(text)) fail(403, `container ${logicalId} label ${key} is invalid`);
    out[key] = text;
  }
  return Object.freeze(out);
}

function normalizeContainerAuthority(value, logicalId) {
  const authority = assertPlainObject(value, `container ${logicalId} authority`);
  const keys = [
    "binds",
    "capAdd",
    "capDrop",
    "cgroupnsMode",
    "configSha256",
    "deviceCgroupRules",
    "devices",
    "deviceRequests",
    "extraHosts",
    "groupAdd",
    "hostConfigSha256",
    "ipcMode",
    "links",
    "mounts",
    "networkMode",
    "networkSettingsSha256",
    "networks",
    "pidMode",
    "portBindings",
    "privileged",
    "publishAllPorts",
    "readonlyRootfs",
    "runtime",
    "securityOpt",
    "user",
    "usernsMode",
    "utsMode",
    "volumesFrom",
  ];
  assertExactKeys(authority, keys, `container ${logicalId} authority`);
  const stringArrays = {};
  for (const key of [
    "binds",
    "capAdd",
    "capDrop",
    "deviceCgroupRules",
    "devices",
    "deviceRequests",
    "extraHosts",
    "groupAdd",
    "links",
    "networks",
    "securityOpt",
    "volumesFrom",
  ]) {
    if (!Array.isArray(authority[key]) || authority[key].some((item) => typeof item !== "string" || item.length > 512)) {
      fail(403, `container ${logicalId} authority ${key} is invalid`);
    }
    stringArrays[key] = Object.freeze([...authority[key]]);
  }
  for (const key of ["configSha256", "hostConfigSha256", "networkSettingsSha256"]) {
    if (!SHA256.test(String(authority[key] ?? ""))) fail(403, `container ${logicalId} authority ${key} is invalid`);
  }
  const portBindings = assertPlainObject(authority.portBindings, `container ${logicalId} authority portBindings`);
  if (authority.privileged !== false || authority.publishAllPorts !== false || ["host", "container"].includes(authority.networkMode)
    || authority.pidMode === "host" || authority.ipcMode === "host" || authority.cgroupnsMode === "host"
    || authority.usernsMode === "host" || authority.utsMode === "host"
    || String(authority.networkMode).startsWith("container:")
    || stringArrays.devices.length || stringArrays.deviceRequests.length || stringArrays.deviceCgroupRules.length
    || stringArrays.capAdd.length || stringArrays.groupAdd.length || stringArrays.links.length
    || stringArrays.volumesFrom.length || stringArrays.extraHosts.length || Object.keys(portBindings).length
    || authority.runtime !== "runc") {
    fail(403, `container ${logicalId} authority contains a forbidden host privilege`);
  }
  for (const bind of stringArrays.binds) {
    const [source, destination, access, ...extra] = bind.split(":");
    if (!source || !destination || extra.length || !["ro", "rw"].includes(access)
      || !source.startsWith("/srv/platform/") || source.includes("/../") || source.includes("docker.sock")
      || !ALLOWED_CONTAINER_PATHS.has(destination)) {
      fail(403, `container ${logicalId} authority contains a forbidden bind`);
    }
  }
  if (!Array.isArray(authority.mounts)) fail(403, `container ${logicalId} authority mounts are invalid`);
  const mounts = authority.mounts.map((mount, index) => {
    const item = assertPlainObject(mount, `container ${logicalId} mount ${index}`);
    assertExactKeys(item, ["destination", "rw", "source", "type"], `container ${logicalId} mount ${index}`);
    const safeBind = item.type !== "bind" || (item.source.startsWith("/srv/platform/")
      && !item.source.includes("/../") && !item.source.includes("docker.sock"));
    const safeVolume = item.type !== "volume" || /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(item.source);
    if (!["bind", "volume", "tmpfs"].includes(item.type) || typeof item.source !== "string" || typeof item.destination !== "string"
      || typeof item.rw !== "boolean" || !safeBind || !safeVolume || !ALLOWED_CONTAINER_PATHS.has(item.destination)) {
      fail(403, `container ${logicalId} mount ${index} is forbidden`);
    }
    return Object.freeze({ destination: item.destination, rw: item.rw, source: item.source, type: item.type });
  });
  for (const key of ["networkMode", "pidMode", "ipcMode", "cgroupnsMode", "usernsMode", "utsMode", "runtime", "user"]) {
    if (typeof authority[key] !== "string" || authority[key].length > 256) fail(403, `container ${logicalId} authority ${key} is invalid`);
  }
  if (typeof authority.readonlyRootfs !== "boolean" || typeof authority.publishAllPorts !== "boolean") {
    fail(403, `container ${logicalId} rootfs or port publication authority is invalid`);
  }
  return Object.freeze({
    ...stringArrays,
    mounts: Object.freeze(mounts),
    configSha256: authority.configSha256,
    hostConfigSha256: authority.hostConfigSha256,
    networkSettingsSha256: authority.networkSettingsSha256,
    networkMode: authority.networkMode,
    pidMode: authority.pidMode,
    ipcMode: authority.ipcMode,
    cgroupnsMode: authority.cgroupnsMode,
    usernsMode: authority.usernsMode,
    utsMode: authority.utsMode,
    runtime: authority.runtime,
    portBindings: Object.freeze({}),
    privileged: false,
    publishAllPorts: false,
    readonlyRootfs: authority.readonlyRootfs,
    user: authority.user,
  });
}

function validateContainerMountAuthority(containers, mounts) {
  const attestations = new Set(Object.values(mounts).map((mount) => canonicalJson({
    source: mount.hostPath,
    destination: mount.containerPath,
    access: mount.access,
  })));
  for (const [logicalId, container] of Object.entries(containers)) {
    for (const bind of container.authority.binds) {
      const [source, destination, access] = bind.split(":");
      if (!attestations.has(canonicalJson({ source, destination, access }))) {
        fail(403, `container ${logicalId} bind is not backed by an exact host-path attestation`);
      }
    }
    for (const mount of container.authority.mounts.filter((item) => item.type === "bind")) {
      const access = mount.rw ? "rw" : "ro";
      if (!attestations.has(canonicalJson({ source: mount.source, destination: mount.destination, access }))) {
        fail(403, `container ${logicalId} bind mount is not backed by an exact host-path attestation`);
      }
    }
  }
}

function assertTimeWindow(issuedAtValue, expiresAtValue, now, maximumLifetimeMs, label) {
  const issuedAt = Date.parse(String(issuedAtValue ?? ""));
  const expiresAt = Date.parse(String(expiresAtValue ?? ""));
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt || expiresAt - issuedAt > maximumLifetimeMs) {
    fail(401, `${label} validity window is invalid`);
  }
  if (issuedAt > now + MAX_CLOCK_SKEW_MS) fail(401, `${label} is not yet valid`);
  if (expiresAt < now) fail(401, `${label} is expired`);
}

function verifyMac(document, key, label) {
  const actual = String(document.mac ?? "");
  if (!SHA256.test(actual)) fail(401, `${label} authentication failed`);
  const expected = hmac(withoutKey(document, "mac"), key);
  if (!constantEqual(actual, expected)) fail(401, `${label} authentication failed`);
}

function normalizeKey(key) {
  const value = Buffer.isBuffer(key) ? key : Buffer.from(String(key ?? ""));
  if (value.length < 32 || value.length > 4096) fail(500, "capability key length is invalid");
  return value;
}

function canonicalValue(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError("canonical JSON accepts only plain JSON values");
  }
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
}

function withoutKey(value, omitted) {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== omitted));
}

function assertPlainObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(400, `${label} must be an object`);
  }
  return value;
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) fail(400, `${label} contains unsupported or missing fields`);
}

function assertLogicalId(value, label) {
  if (!LOGICAL_ID.test(String(value ?? ""))) fail(403, `${label} is invalid`);
}

function constantEqual(left, right) {
  const actual = Buffer.from(String(left));
  const expected = Buffer.from(String(right));
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function fail(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  throw error;
}
