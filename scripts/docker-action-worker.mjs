#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const MAX_WORKER_STDOUT_BYTES = 4096;

const BACKUP_ROOT = "/data/backups";
const KEEP_COMPLETE_MANIFESTS = 42;
const MAX_MANIFESTS = 10_000;
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;
const MAX_CLAIMED_JOB_BYTES = 128 * 1024;
const MAX_TERMINAL_EVIDENCE_BYTES = 512 * 1024;
const MAX_TERMINAL_ARTIFACT_BYTES = 1024 ** 4;
const MAX_NATIVE_TREE_ENTRIES = 100_000;
const MAX_NATIVE_TREE_DEPTH = 64;
const ARTIFACT_HASH_CHUNK_BYTES = 64 * 1024;
const SHA256 = /^[a-f0-9]{64}$/;
const DIGEST_IMAGE = /^[a-zA-Z0-9][a-zA-Z0-9._/:+-]*@sha256:[a-f0-9]{64}$/;
const BASE64URL_SHA256 = /^[A-Za-z0-9_-]{43}$/;
const JOB_ID = /^[a-z0-9][a-z0-9-]{15,127}$/;
const REQUEST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PRUNE_PLAN_DIGEST_DOMAIN =
  "platform.backup-prune-sealed-plan-digest/v1\0";
const PRUNE_PLAN_MAC_DOMAIN =
  "platform.backup-prune-sealed-plan-mac/v1\0";
const MANIFEST_KEY_ID = "platform.manifest.v1";
const CAPTURE_PHASE_IDS = Object.freeze([
  "catalog.capture",
  "job.backup.capture",
  "restore.capture",
]);
const PRODUCER_PHASE_ID = /^(?:catalog\.capture|job\.backup\.capture|restore\.capture)$/;
const WORKER_ROLES_BY_PHASE = Object.freeze({
  "catalog.capture": Object.freeze(["evidence-finalizer", "helper-preparer"]),
  "job.backup.capture": Object.freeze(["evidence-finalizer", "helper-preparer"]),
  "job.restore.verify": Object.freeze([
    "artifact-resolver",
    "evidence-finalizer",
    "helper-preparer",
    "scratch-cleaner",
    "scratch-preparer",
  ]),
  "offsite.sync": Object.freeze([
    "artifact-resolver",
    "evidence-finalizer",
    "helper-preparer",
  ]),
  "prune.apply": Object.freeze(["standalone"]),
  "prune.plan": Object.freeze(["standalone"]),
  "restore.capture": Object.freeze(["evidence-finalizer", "helper-preparer"]),
  "restore.verify": Object.freeze([
    "evidence-finalizer",
    "helper-preparer",
    "scratch-cleaner",
    "scratch-preparer",
  ]),
});

const COMMANDS = Object.freeze({
  "backup-catalog": Object.freeze({
  }),
  "backup-job": Object.freeze({
    jobOperation: "backup",
  }),
  "backup-offsite-sync": Object.freeze({
  }),
  "backup-prune-apply": Object.freeze({
  }),
  "backup-prune-plan": Object.freeze({
  }),
  "restore-drill-full": Object.freeze({
  }),
  "restore-job": Object.freeze({
    jobOperation: "restore-drill",
  }),
});

const COMMAND_BY_ACTION_PHASE = Object.freeze({
  "backup.catalog\0catalog.capture": "backup-catalog",
  "backup.job.execute\0job.backup.capture": "backup-job",
  "backup.job.execute\0job.restore.verify": "restore-job",
  "backup.offsite.sync\0offsite.sync": "backup-offsite-sync",
  "backup.prune.apply\0prune.apply": "backup-prune-apply",
  "backup.prune.plan\0prune.plan": "backup-prune-plan",
  "restore.drill.full\0restore.capture": "backup-catalog",
  "restore.drill.full\0restore.verify": "restore-drill-full",
});

const OUTPUT_SCHEMA_BY_PHASE = Object.freeze({
  "catalog.capture": "platform.backup-catalog/v1",
  "job.backup.capture": "platform.backup-job-result/v1",
  "job.restore.verify": "platform.backup-job-result/v1",
  "offsite.sync": "platform.offsite-backup-receipt/v1",
  "prune.apply": "platform.backup-prune-apply/v1",
  "prune.plan": "platform.backup-prune-plan/v1",
  "restore.capture": "platform.backup-catalog/v1",
  "restore.verify": "platform.restore-drill/v1",
});

export async function runWorkerCli(
  argv,
  writers = {},
  options = {},
) {
  if (!Array.isArray(argv) || argv.length !== 3 || typeof argv[2] !== "string") {
    fail("worker command arguments are unsupported");
  }
  const command = argv[2];
  commandDefinition(command);
  const env = options.env ?? process.env;
  if (!isPlainRecord(env)) fail("worker environment is invalid");
  const identity = workerIdentity(env, command);
  let job = null;
  let jobDocument = null;
  if (COMMANDS[command].jobOperation) {
    const policy = options.claimedJobPolicy ?? defaultClaimedJobPolicy(env);
    const loaded = loadClaimedJobSnapshot({
      env,
      policy,
      snapshotPath: env.PLATFORM_CLAIMED_JOB_PATH,
    }, { io: options.io ?? fs });
    job = {
      jobFileName: loaded.jobFileName,
      jobId: loaded.jobId,
      jobOperation: loaded.jobOperation,
      jobSha256: loaded.jobSha256,
    };
    jobDocument = loaded.document;
  } else {
    rejectUnexpectedClaimedJobEnvironment(env);
  }
  const output = await runFixedToolEntry(command, {
    backupRoot: options.backupRoot,
    env,
    io: options.io ?? fs,
    helperResultsPolicy: options.helperResultsPolicy,
    jobDocument,
    reportRoot: options.reportRoot,
    scratchRoot: options.scratchRoot,
    writeStdout: () => {},
  });
  const result = normalizeWorkerResult(command, {
    schema: "platform.docker-worker.result/v2",
    requestId: identity.requestId,
    action: identity.action,
    phaseId: identity.phaseId,
    command,
    job,
    status: "completed",
    output,
  }, {
    ...identity,
    job,
    outputSchema: OUTPUT_SCHEMA_BY_PHASE[identity.phaseId],
  });
  const serialized = JSON.stringify(result);
  if (Buffer.byteLength(serialized) > MAX_WORKER_STDOUT_BYTES) {
    fail("worker result is oversized");
  }
  const writeStdout = writers.writeStdout ?? ((chunk) => process.stdout.write(chunk));
  if (typeof writeStdout !== "function") fail("worker stdout writer is invalid");
  writeStdout(`${serialized}\n`);
  return 0;
}

export function readProtectedFile(file, policy, { io = fs } = {}) {
  if (typeof file !== "string" || file.length < 1 || !isPlainRecord(policy)) {
    fail("protected file policy is invalid");
  }
  const parentRoot = path.resolve(exactText(policy.parentRoot, "protected parent root"));
  const resolved = path.resolve(file);
  if (resolved === parentRoot || !resolved.startsWith(`${parentRoot}${path.sep}`)) {
    fail("protected file escaped its parent root");
  }
  const expectedUid = exactInteger(policy.expectedUid, "protected owner UID", 0);
  const expectedGid = exactInteger(policy.expectedGid, "protected owner GID", 0);
  const expectedMode = exactMode(policy.expectedMode, "protected file mode");
  const maximumBytes = exactInteger(
    policy.maximumBytes,
    "protected maximum byte count",
    1,
  );
  assertProtectedAncestors(
    path.dirname(resolved),
    parentRoot,
    { expectedGid, expectedUid },
    io,
  );
  const before = io.lstatSync(resolved);
  assertProtectedLeaf(before, {
    expectedGid,
    expectedMode,
    expectedUid,
    maximumBytes,
  });
  const beforeIdentity = statIdentity(before);
  let descriptor;
  try {
    descriptor = io.openSync(
      resolved,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
    );
    const opened = io.fstatSync(descriptor);
    assertProtectedLeaf(opened, {
      expectedGid,
      expectedMode,
      expectedUid,
      maximumBytes,
    });
    if (!sameIdentity(beforeIdentity, statIdentity(opened))) {
      fail("protected file identity changed between lstat and descriptor admission");
    }
    const first = readDescriptorPass(io, descriptor, opened.size);
    const second = readDescriptorPass(io, descriptor, opened.size);
    if (!first.equals(second)) {
      fail("protected file content changed during the descriptor-stable read");
    }
    const after = io.fstatSync(descriptor);
    if (!sameIdentity(statIdentity(opened), statIdentity(after))) {
      fail("protected file descriptor identity changed during the stable read");
    }
    return first;
  } finally {
    if (descriptor !== undefined) io.closeSync(descriptor);
  }
}

export function loadClaimedJobSnapshot(
  { env, policy, snapshotPath },
  { io = fs } = {},
) {
  if (!isPlainRecord(env) || typeof snapshotPath !== "string") {
    fail("claimed-job snapshot input is invalid");
  }
  const job = claimedJobIdentity(env);
  if (snapshotPath !== env.PLATFORM_CLAIMED_JOB_PATH) {
    fail("claimed-job snapshot path identity is invalid");
  }
  const bytes = readProtectedFile(snapshotPath, policy, { io });
  if (sha256(bytes) !== job.jobSha256) {
    fail("claimed-job snapshot SHA256 digest does not match its authority");
  }
  let document;
  try {
    document = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("claimed-job snapshot document is invalid JSON");
  }
  validateClaimedJobDocument(document, job);
  return deepFreeze({
    document: structuredClone(document),
    ...job,
    sourceId: "jobs.running",
  });
}

export function normalizeWorkerResult(command, candidate, identity) {
  commandDefinition(command);
  if (!isPlainRecord(candidate) || !isPlainRecord(identity)) {
    fail("worker result identity is invalid");
  }
  exactKeys(candidate, [
    "action",
    "command",
    "job",
    "output",
    "phaseId",
    "requestId",
    "schema",
    "status",
  ], "worker result");
  const expectedCommand = COMMAND_BY_ACTION_PHASE[
    `${identity.action}\0${identity.phaseId}`
  ];
  if (candidate.schema !== "platform.docker-worker.result/v2"
    || candidate.status !== "completed"
    || candidate.requestId !== identity.requestId
    || candidate.action !== identity.action
    || candidate.phaseId !== identity.phaseId
    || candidate.command !== command
    || expectedCommand !== command
    || !REQUEST_ID.test(String(identity.requestId ?? ""))) {
    fail("worker result request, action, phase or command identity is invalid");
  }
  const expectedJob = identity.job ?? null;
  if (!sameCanonical(candidate.job, expectedJob)) {
    fail("worker result claimed-job identity is invalid");
  }
  if (candidate.job !== null) validateJobResultIdentity(candidate.job);
  const expectedSchema = exactText(identity.outputSchema, "worker output schema");
  const role = exactText(identity.role, "worker result role");
  if (!WORKER_ROLES_BY_PHASE[identity.phaseId]?.includes(role)) {
    fail("worker result role is outside phase authority");
  }
  if (role === "evidence-finalizer" || role === "standalone") {
    validatePhaseOutput(
      candidate.output,
      identity.phaseId,
      expectedSchema,
      expectedJob,
      identity,
    );
  } else {
    validateInternalRoleOutput(candidate.output, identity, role);
  }
  if (Buffer.byteLength(JSON.stringify(candidate)) > MAX_WORKER_STDOUT_BYTES) {
    fail("worker result is oversized");
  }
  return structuredClone(candidate);
}

export function verifyManifestEnvelope(envelope, options) {
  if (!isPlainRecord(envelope) || !isPlainRecord(options)
    || !isPlainRecord(envelope.manifest)
    || !isPlainRecord(envelope.sidecars)
    || !isPlainRecord(options.manifestKeys)
    || !isPlainRecord(options.artifactKeys)
    || !isPlainRecord(options.artifactBytes)) {
    fail("manifest verification input is invalid");
  }
  const manifest = envelope.manifest;
  if (manifest.schema !== "platform.backup-manifest/v1"
    || !Array.isArray(manifest.artifacts)
    || manifest.artifacts.length < 1
    || manifest.artifacts.length > 256
    || !isPlainRecord(manifest.signature)) {
    fail("manifest schema is invalid");
  }
  exactKeys(manifest.signature, ["algorithm", "digest", "keyId", "value"], "manifest signature");
  const digest = backupDocumentDigest(manifest);
  const signature = manifest.signature;
  if (signature.algorithm !== "HMAC-SHA256"
    || !SHA256.test(String(signature.digest ?? ""))
    || signature.digest !== digest
    || !BASE64URL_SHA256.test(String(signature.value ?? ""))) {
    fail("manifest digest or signature is invalid");
  }
  const manifestKey = options.manifestKeys[signature.keyId];
  if (!Buffer.isBuffer(manifestKey)) fail("manifest signature key ID is unknown");
  const expectedManifestMac = hmacBase64Url(
    manifestKey,
    `platform-backup-manifest-v1\n${manifest.id}\n${digest}\n`,
  );
  if (!constantTextEqual(signature.value, expectedManifestMac)) {
    fail("manifest HMAC authentication failed");
  }
  const seenPaths = new Set();
  for (const artifact of manifest.artifacts) {
    if (!isPlainRecord(artifact)) fail("manifest artifact schema is invalid");
    const artifactPath = safeRelativePath(artifact.path, "manifest artifact path");
    if (seenPaths.has(artifactPath)) fail("manifest artifact path is duplicated");
    seenPaths.add(artifactPath);
    if (!SHA256.test(String(artifact.sha256 ?? ""))
      || !Number.isSafeInteger(artifact.sizeBytes)
      || artifact.sizeBytes < 1) {
      fail("manifest artifact digest or size is invalid");
    }
    const bytes = options.artifactBytes[artifactPath];
    const sidecar = envelope.sidecars[artifactPath];
    if (!Buffer.isBuffer(bytes) || !isPlainRecord(sidecar)) {
      fail("manifest artifact bytes or sidecar are missing");
    }
    if (bytes.length !== artifact.sizeBytes || sha256(bytes) !== artifact.sha256) {
      fail("manifest artifact bytes do not match their SHA256 digest");
    }
    exactKeys(
      sidecar,
      ["algorithm", "artifact", "keyId", "sha256", "signature", "version"],
      "artifact sidecar",
    );
    if (sidecar.version !== 1
      || sidecar.algorithm !== "HMAC-SHA256"
      || sidecar.artifact !== path.basename(artifactPath)
      || sidecar.sha256 !== artifact.sha256
      || sidecar.keyId !== artifact.signatureKeyId
      || !BASE64URL_SHA256.test(String(sidecar.signature ?? ""))) {
      fail("artifact sidecar identity or digest is invalid");
    }
    const artifactKey = options.artifactKeys[sidecar.keyId];
    if (!Buffer.isBuffer(artifactKey)) fail("artifact signature key ID is unknown");
    const manifestResource = manifest.resources?.find(
      (resource) => resource?.id === artifact.resourceId,
    );
    const domainName = backupResourceDomain(manifestResource);
    const expectedArtifactMac = hmacBase64Url(
      artifactKey,
      `platform-${domainName}-backup-v1\n${sidecar.artifact}\n${sidecar.sha256}\n`,
    );
    if (!constantTextEqual(sidecar.signature, expectedArtifactMac)) {
      fail("artifact sidecar HMAC authentication failed");
    }
  }
  if (Object.keys(envelope.sidecars).some((entry) => !seenPaths.has(entry))
    || Object.keys(options.artifactBytes).some((entry) => !seenPaths.has(entry))) {
    fail("manifest envelope contains an unsupported artifact field");
  }
  return deepFreeze({
    artifactCount: manifest.artifacts.length,
    manifestDigest: digest,
  });
}

export function normalizeArtifactBinding(value, options = {}) {
  if (!isPlainRecord(value) || !isPlainRecord(options)) {
    fail("artifact binding input is invalid");
  }
  exactKeys(value, [
    "artifactSetSha256",
    "artifacts",
    "consumerRequestSha256",
    "manifestRelativePath",
    "manifestSha256",
    "producerPhaseId",
    "producerRequestSha256",
    "schema",
    "verification",
  ], "artifact binding");
  if (value.schema !== "platform.docker-action.artifact-binding/v1"
    || !SHA256.test(String(value.artifactSetSha256 ?? ""))
    || !SHA256.test(String(value.consumerRequestSha256 ?? ""))
    || !SHA256.test(String(value.manifestSha256 ?? ""))
    || !SHA256.test(String(value.producerRequestSha256 ?? ""))
    || !PRODUCER_PHASE_ID.test(String(value.producerPhaseId ?? ""))
    || !isPlainRecord(value.artifacts)
    || !isPlainRecord(value.verification)) {
    fail("artifact binding identity or digest is invalid");
  }
  if (options.consumerRequestSha256 !== undefined
    && value.consumerRequestSha256 !== options.consumerRequestSha256) {
    fail("artifact binding consumer request lineage is invalid");
  }
  if (options.producerRequestSha256 !== undefined
    && value.producerRequestSha256 !== options.producerRequestSha256) {
    fail("artifact binding producer request lineage is invalid");
  }
  if (options.producerPhaseId !== undefined
    && value.producerPhaseId !== options.producerPhaseId) {
    fail("artifact binding producer phase lineage is invalid");
  }
  const expectedManifestRelativePath = [
    "requests",
    value.producerRequestSha256,
    "manifests",
    `${value.producerPhaseId}.json`,
  ].join("/");
  if (safeRelativePath(value.manifestRelativePath, "artifact binding manifest path")
      !== expectedManifestRelativePath) {
    fail("artifact binding manifest lineage path is invalid");
  }
  const artifactEntries = Object.entries(value.artifacts);
  if (artifactEntries.length < 1 || artifactEntries.length > 256) {
    fail("artifact binding inventory is missing or oversized");
  }
  const artifacts = {};
  for (const [resourceId, artifact] of artifactEntries.sort(([left], [right]) => (
    left.localeCompare(right)
  ))) {
    if (!isPlainRecord(artifact)) fail("artifact binding entry is invalid");
    exactKeys(
      artifact,
      ["relativePath", "resourceId", "sha256"],
      `artifact binding entry ${resourceId}`,
    );
    const relativePath = safeRelativePath(
      artifact.relativePath,
      `artifact binding entry ${resourceId} path`,
    );
    const expectedPrefix = `requests/${value.producerRequestSha256}/artifacts/`;
    if (artifact.resourceId !== resourceId
      || !/^[a-z0-9](?:[a-z0-9._:-]{0,158}[a-z0-9])?$/.test(resourceId)
      || !SHA256.test(String(artifact.sha256 ?? ""))
      || !relativePath.startsWith(expectedPrefix)) {
      fail("artifact binding resource, path or digest is invalid");
    }
    artifacts[resourceId] = {
      relativePath,
      resourceId,
      sha256: artifact.sha256,
    };
  }
  if (options.resourceIds !== undefined) {
    exactStringArray(options.resourceIds, "artifact binding resource authority");
    if (!sameCanonical(Object.keys(artifacts).sort(), [...options.resourceIds].sort())) {
      fail("artifact binding resource coverage is incomplete");
    }
  }
  const artifactSetSha256 = sha256(JSON.stringify(canonicalValue(artifacts)));
  if (value.artifactSetSha256 !== artifactSetSha256) {
    fail("artifact binding set digest is invalid");
  }
  exactKeys(value.verification, [
    "authoritySha256",
    "evidenceSha256",
    "kind",
    "source",
  ], "artifact binding verification");
  if (!SHA256.test(String(value.verification.authoritySha256 ?? ""))
    || !SHA256.test(String(value.verification.evidenceSha256 ?? ""))
    || !["journaled-phase-result", "verified-manifest"].includes(
      value.verification.kind,
    )) {
    fail("artifact binding verification identity is invalid");
  }
  const expectedVerificationSource = value.verification.kind === "verified-manifest"
    ? expectedManifestRelativePath
    : value.producerPhaseId;
  if (value.verification.source !== expectedVerificationSource
    || (options.verificationKind !== undefined
      && value.verification.kind !== options.verificationKind)) {
    fail("artifact binding verification provenance is invalid");
  }
  return deepFreeze({
    artifactSetSha256,
    artifacts,
    consumerRequestSha256: value.consumerRequestSha256,
    manifestRelativePath: expectedManifestRelativePath,
    manifestSha256: value.manifestSha256,
    producerPhaseId: value.producerPhaseId,
    producerRequestSha256: value.producerRequestSha256,
    schema: value.schema,
    verification: structuredClone(value.verification),
  });
}

export function resolveArtifactBinding(command, options = {}) {
  const env = options.env ?? process.env;
  const io = options.io ?? fs;
  if (!isPlainRecord(env)) fail("artifact resolver environment is invalid");
  const context = loadPhaseAuthority(command, env);
  if (!["job.restore.verify", "offsite.sync"].includes(context.phaseId)) {
    fail("artifact resolver role is not admitted for this phase");
  }
  const authority = context.authority;
  const backupPolicy = validateBackupMountAuthority({
    access: "ro",
    authority,
    io,
    root: options.backupRoot,
  });
  const reportPolicy = validateNamedMountAuthority({
    access: "rw",
    authority,
    io,
    mountId: "report.root.rw",
    root: options.reportRoot,
  });
  const requestSha256 = executionRequestSha256(env);
  let candidate;
  if (context.phaseId === "job.restore.verify") {
    const job = claimedJobIdentity(env);
    if (job.jobOperation !== "restore-drill"
      || !isPlainRecord(options.jobDocument)
      || options.jobDocument.id !== job.jobId
      || options.jobDocument.operation !== job.jobOperation) {
      fail("artifact resolver claimed-job document identity is invalid");
    }
    candidate = verifyManifestCandidate({
      authority,
      backupPolicy,
      io,
      manifestRelativePath: safeRelativePath(
        options.jobDocument.sourceManifestPath,
        "claimed-job source manifest path",
      ),
    });
  } else {
    rejectUnexpectedClaimedJobEnvironment(env);
    candidate = latestVerifiedManifestCandidate({ authority, backupPolicy, io });
  }
  return materializeVerifiedManifestBinding({
    authority,
    candidate,
    context,
    io,
    reportPolicy,
    requestSha256,
  });
}

export function manageRestoreScratch(command, role, options = {}) {
  const env = options.env ?? process.env;
  const io = options.io ?? fs;
  if (!isPlainRecord(env)
    || !["scratch-preparer", "scratch-cleaner"].includes(role)) {
    fail("restore scratch role is invalid");
  }
  const context = loadPhaseAuthority(command, env);
  if (!["job.restore.verify", "restore.verify"].includes(context.phaseId)) {
    fail("restore scratch role is outside a restore helper phase");
  }
  const authority = context.authority;
  if (!sameCanonical(authority.phaseProfile.scratchVolumeIds, ["restore.scratch"])) {
    fail("restore scratch volume authority is not exact");
  }
  const engine = safeLogicalPathToken(
    env.PLATFORM_DOCKER_SCRATCH_ENGINE,
    "restore scratch engine",
  );
  const effectiveEngines = [...new Set(
    authority.effectiveHelperProfileIds.map(
      (helperProfileId) => authority.resources.helperProfiles[helperProfileId].engine,
    ),
  )].sort();
  if (!sameCanonical(effectiveEngines, ["mariadb", "minio", "postgres"])
    || !effectiveEngines.includes(engine)) {
    fail("restore scratch engine is outside effective helper authority");
  }
  const volume = authority.resources.volumes["restore.scratch"];
  if (!isPlainRecord(volume)
    || volume.containerPath !== "/run/platform/restore-scratch") {
    fail("restore scratch volume path authority is invalid");
  }
  const reportMount = authority.resources.mounts["report.root.rw"];
  if (!isPlainRecord(reportMount)) fail("restore scratch owner authority is missing");
  const root = canonicalDirectory(
    options.scratchRoot ?? volume.containerPath,
    io,
  );
  const rootStat = io.lstatSync(root);
  const rootPolicy = {
    expectedGid: reportMount.ownerGid,
    expectedUid: reportMount.ownerUid,
    root,
  };
  if (rootStat.uid !== rootPolicy.expectedUid
    || rootStat.gid !== rootPolicy.expectedGid
    || (rootStat.mode & 0o7777) !== 0o700) {
    fail("restore scratch volume root owner or mode is invalid");
  }
  const serverProfiles = authority.effectiveHelperProfileIds
    .map((helperProfileId) => authority.resources.helperProfiles[helperProfileId])
    .filter((profile) => (
      profile.engine === engine && profile.operation === "restore-server"
    ));
  if (serverProfiles.length !== 1) {
    fail("restore scratch runtime principal authority is not exact");
  }
  const [serverProfile] = serverProfiles;
  const runtimePolicy = {
    expectedGid: serverProfile.runtimeGid,
    expectedUid: serverProfile.runtimeUid,
    root,
  };
  const requestSha256 = executionRequestSha256(env);
  const phaseRelativePath = [
    "requests",
    requestSha256,
    context.phaseId,
  ].join("/");
  const relativePath = `${phaseRelativePath}/${engine}`;
  const engineRoot = path.join(root, ...relativePath.split("/"));
  if (role === "scratch-preparer") {
    ensurePrivateRelativeDirectory(rootPolicy, phaseRelativePath, io);
    ensureRuntimePrivateDirectory(engineRoot, rootPolicy, runtimePolicy, io);
    ensureRuntimePrivateDirectory(
      path.join(engineRoot, "data"),
      rootPolicy,
      runtimePolicy,
      io,
    );
    ensureRuntimePrivateDirectory(
      path.join(engineRoot, "run"),
      rootPolicy,
      runtimePolicy,
      io,
    );
    fsyncDirectory(engineRoot, io);
    fsyncDirectory(path.dirname(engineRoot), io);
  } else {
    removeBoundedRestoreScratchTree(engineRoot, runtimePolicy, io);
    fsyncDirectory(path.dirname(engineRoot), io);
    removeEmptyPrivateAncestors(
      path.dirname(engineRoot),
      path.join(root, "requests"),
      rootPolicy,
      io,
    );
  }
  return deepFreeze({
    engine,
    mutationPerformed: true,
    phaseId: context.phaseId,
    relativePath,
    requestSha256,
    role,
    schema: "platform.docker-worker.scratch-result/v1",
    status: "completed",
  });
}

export function prepareHelperFilesystem(command, options = {}) {
  const env = options.env ?? process.env;
  const io = options.io ?? fs;
  if (!isPlainRecord(env)) fail("helper preparer environment is invalid");
  const context = loadPhaseAuthority(command, env);
  const authority = context.authority;
  if (authority.effectiveHelperProfileIds.length < 1) {
    fail("helper preparer has no effective helper authority");
  }
  const requestSha256 = executionRequestSha256(env);
  const reportPolicy = validateNamedMountAuthority({
    access: "rw",
    authority,
    io,
    mountId: "report.root.rw",
    root: options.reportRoot,
  });
  const preparedRelativePaths = [];
  const helperReportDirectory = [
    "docker-actions",
    requestSha256,
    context.phaseId,
    "helpers",
  ].join("/");
  ensurePrivateRelativeDirectory(reportPolicy, helperReportDirectory, io);
  preparedRelativePaths.push(`report:${helperReportDirectory}`);
  if (CAPTURE_PHASE_IDS.includes(context.phaseId)) {
    const backupPolicy = validateBackupMountAuthority({
      access: "rw",
      authority,
      io,
      root: options.backupRoot,
    });
    for (const helperProfileId of authority.effectiveHelperProfileIds) {
      const profile = authority.resources.helperProfiles[helperProfileId];
      if (profile.outputMode !== "artifact") continue;
      const artifactRelativePath = helperArtifactRelativePath(
        requestSha256,
        profile,
      );
      const parent = path.posix.dirname(artifactRelativePath);
      ensurePrivateRelativeDirectory(backupPolicy, parent, io);
      preparedRelativePaths.push(`backup:${parent}`);
      if (profile.engine === "minio") {
        ensurePrivateRelativeDirectory(backupPolicy, artifactRelativePath, io);
        preparedRelativePaths.push(`backup:${artifactRelativePath}`);
      }
    }
  }
  return deepFreeze({
    mutationPerformed: true,
    phaseId: context.phaseId,
    preparedRelativePaths: [...new Set(preparedRelativePaths)].sort(),
    requestSha256,
    schema: "platform.docker-worker.helper-preparation/v1",
    status: "completed",
  });
}

export function materializeHelperEvidence(command, options = {}) {
  const env = options.env ?? process.env;
  const io = options.io ?? fs;
  if (!isPlainRecord(env)) fail("helper evidence finalizer environment is invalid");
  const context = loadPhaseAuthority(command, env);
  const authority = context.authority;
  const requestSha256 = executionRequestSha256(env);
  const snapshot = loadHelperResultsSnapshot({
    authority,
    context,
    env,
    io,
    policy: options.helperResultsPolicy,
  });
  const reportPolicy = validateNamedMountAuthority({
    access: "rw",
    authority,
    io,
    mountId: "report.root.rw",
    root: options.reportRoot,
  });
  const backupAccess = CAPTURE_PHASE_IDS.includes(context.phaseId) ? "rw" : "ro";
  const backupPolicy = Object.keys(authority.resources.mounts).some(
    (mountId) => mountId === `backup.root.${backupAccess}`,
  ) ? validateBackupMountAuthority({
      access: backupAccess,
      authority,
      io,
      root: options.backupRoot,
    }) : null;
  const helperResults = [];
  const artifacts = [];
  const helperReportRelativeDirectory = [
    "docker-actions",
    requestSha256,
    context.phaseId,
    "helpers",
  ].join("/");
  const helperReportDirectory = ensurePrivateRelativeDirectory(
    reportPolicy,
    helperReportRelativeDirectory,
    io,
  );
  for (const [index, result] of snapshot.helpers.entries()) {
    const profile = authority.resources.helperProfiles[result.helperProfileId];
    helperResults.push({
      helperProfileId: result.helperProfileId,
      imageId: result.imageId,
      status: "completed",
    });
    if (result.outputMode === "artifact") {
      if (!backupPolicy) fail("helper artifact output lacks backup mount authority");
      const artifactPath = path.join(
        backupPolicy.root,
        ...result.artifactRelativePath.split("/"),
      );
      normalizeHelperArtifactPermissions(artifactPath, {
        expectedGid: backupPolicy.expectedGid,
        expectedUid: backupPolicy.expectedUid,
        parentRoot: backupPolicy.root,
      }, io);
      const observed = readProtectedArtifactIdentity(artifactPath, {
        expectedGid: backupPolicy.expectedGid,
        expectedUid: backupPolicy.expectedUid,
        parentRoot: backupPolicy.root,
      }, io);
      const resourceId = helperResourceId(authority, profile);
      artifacts.push({
        backupResourceId: resourceId,
        path: artifactPath,
        producerHelperProfileId: result.helperProfileId,
        sha256: observed.sha256,
        sizeBytes: observed.sizeBytes,
      });
    } else if (result.outputMode === "json") {
      const fileName = `${String(index).padStart(2, "0")}-${result.helperProfileId}.json`;
      const outputPath = path.join(helperReportDirectory, fileName);
      const decoded = decodeCanonicalHelperJson(result.stdoutBase64);
      writeCanonicalPrivateJson(outputPath, decoded, io);
      const outputBytes = readProtectedFile(outputPath, {
        expectedGid: reportPolicy.expectedGid,
        expectedMode: 0o400,
        expectedUid: reportPolicy.expectedUid,
        maximumBytes: MAX_TERMINAL_EVIDENCE_BYTES,
        parentRoot: reportPolicy.root,
      }, { io });
      artifacts.push({
        backupResourceId: profile.operation === "offsite-sync"
          ? null
          : helperResourceId(authority, profile),
        path: outputPath,
        producerHelperProfileId: result.helperProfileId,
        sha256: sha256(outputBytes),
        sizeBytes: outputBytes.length,
      });
    }
  }
  fsyncDirectory(helperReportDirectory, io);
  artifacts.sort((left, right) => (
    `${left.backupResourceId ?? ""}\0${left.path}`.localeCompare(
      `${right.backupResourceId ?? ""}\0${right.path}`,
    )
  ));
  const job = COMMANDS[command].jobOperation ? claimedJobIdentity(env) : null;
  const report = {
    action: context.action,
    artifacts,
    command,
    helperResults,
    job,
    mutationPerformed: true,
    phaseId: context.phaseId,
    repositoryOffsite: context.phaseId === "offsite.sync" ? true : null,
    requestId: context.requestId,
    schema: "platform.docker-helper-evidence/v1",
    status: "passed",
  };
  const evidenceDirectory = path.join(reportPolicy.root, "worker-evidence");
  ensurePrivateDirectory(evidenceDirectory, reportPolicy, io);
  const evidencePath = terminalEvidencePath(reportPolicy.root, context);
  writeCanonicalPrivateJson(evidencePath, report, io);
  fsyncDirectory(evidenceDirectory, io);
  const evidenceBytes = readProtectedFile(evidencePath, {
    expectedGid: reportPolicy.expectedGid,
    expectedMode: 0o400,
    expectedUid: reportPolicy.expectedUid,
    maximumBytes: MAX_TERMINAL_EVIDENCE_BYTES,
    parentRoot: reportPolicy.root,
  }, { io });
  return deepFreeze({
    evidencePath,
    evidenceSha256: sha256(evidenceBytes),
    schema: "platform.docker-worker.helper-evidence-materialization/v1",
    status: "completed",
  });
}

export function planPruneTransition(state, event, sealKey) {
  if (!isPlainRecord(state) || state.phase !== "empty"
    || !isPlainRecord(event) || event.type !== "seal"
    || !isPlainRecord(sealKey) || typeof sealKey.keyId !== "string"
    || !Buffer.isBuffer(sealKey.key)) {
    fail("unsupported prune plan transition");
  }
  const plan = normalizeUnsignedPrunePlan(event.plan);
  const digest = prunePlanDigest(plan);
  const seal = {
    algorithm: "HMAC-SHA256",
    digest,
    keyId: sealKey.keyId,
    value: prunePlanMac(plan, sealKey.keyId, sealKey.key, digest),
  };
  return deepFreeze({
    phase: "sealed",
    plan: { ...plan, seal },
  });
}

export function applyPruneTransition(state, event, options) {
  if (!isPlainRecord(state) || !isPlainRecord(event)
    || !isPlainRecord(options) || !isPlainRecord(options.keys)) {
    fail("unsupported prune apply transition");
  }
  const plan = verifySealedPrunePlan(state.plan, options.keys);
  if (state.phase === "sealed" && event.type === "quarantine") {
    exactKeys(
      event,
      ["artifactCount", "planDigest", "quarantineDigest", "type"],
      "prune quarantine event",
    );
    if (event.planDigest !== plan.seal.digest
      || !SHA256.test(String(event.quarantineDigest ?? ""))
      || event.artifactCount !== plan.artifactCount) {
      fail("prune quarantine barrier digest or artifact count is invalid");
    }
    return deepFreeze({
      ...structuredClone(state),
      deletionCommitted: false,
      phase: "quarantined",
      quarantineDigest: event.quarantineDigest,
    });
  }
  if (state.phase === "quarantined" && event.type === "commit-delete") {
    exactKeys(
      event,
      ["planDigest", "quarantineDigest", "type"],
      "prune commit event",
    );
    if (event.planDigest !== plan.seal.digest
      || event.quarantineDigest !== state.quarantineDigest) {
      fail("prune committed digest substitution crossed the quarantine barrier");
    }
    return deepFreeze({
      ...structuredClone(state),
      deletionCommitted: true,
      phase: "applied",
    });
  }
  fail("unsupported prune phase transition or missing quarantine barrier");
}

export function transitionRestorePhase(state, event) {
  if (!isPlainRecord(state) || !isPlainRecord(event)) {
    fail("unsupported restore transition event");
  }
  if (state.phase === "created" && event.type === "prepare-complete") {
    return deepFreeze({ ...structuredClone(state), phase: "prepared" });
  }
  if (state.phase === "prepared" && event.type === "restore-complete") {
    return deepFreeze({ ...structuredClone(state), phase: "restored" });
  }
  if (state.phase === "restored" && event.type === "verify-complete") {
    if (!SHA256.test(String(event.restoredArtifactSetSha256 ?? ""))
      || event.restoredArtifactSetSha256 !== state.verifiedArtifactSetSha256) {
      fail("restore verification artifact digest is invalid");
    }
    return deepFreeze({
      ...structuredClone(state),
      phase: "verified",
      restoredArtifactSetSha256: event.restoredArtifactSetSha256,
    });
  }
  if (state.phase === "verified" && event.type === "barrier-passed") {
    if (event.restoredArtifactSetSha256 !== state.verifiedArtifactSetSha256
      || event.restoredArtifactSetSha256 !== state.restoredArtifactSetSha256) {
      fail("restore barrier artifact digest substitution is invalid");
    }
    return deepFreeze({ ...structuredClone(state), phase: "barrier-passed" });
  }
  fail("unsupported restore phase transition or barrier order");
}

export function reverseCleanupOrder(cleanupStack) {
  if (!Array.isArray(cleanupStack)
    || cleanupStack.some((entry) => typeof entry !== "string" || entry.length < 1)
    || new Set(cleanupStack).size !== cleanupStack.length) {
    fail("restore cleanup stack is invalid");
  }
  return [...cleanupStack].reverse();
}

export function transitionOffsiteAttempt(state, event) {
  if (!isPlainRecord(state) || !isPlainRecord(event)) {
    fail("unsupported offsite transition event");
  }
  if (state.phase === "complete" && event.type === "begin"
    && event.idempotencyKey === state.idempotencyKey
    && event.manifestDigest === state.manifestDigest) {
    return state;
  }
  if (state.phase === "remote-unknown" && event.type === "begin") {
    fail("offsite remote-unknown state requires reconciliation and cannot retry");
  }
  if (state.phase === "idle" && event.type === "begin") {
    const manifestDigest = String(event.manifestDigest ?? "");
    const expectedKey = sha256(
      `platform-offsite-sync-v1\n${manifestDigest}\n`,
    );
    if (!SHA256.test(manifestDigest) || event.idempotencyKey !== expectedKey) {
      fail("offsite idempotency key does not bind the manifest digest");
    }
    return deepFreeze({
      idempotencyKey: event.idempotencyKey,
      manifestDigest,
      phase: "in-flight",
      snapshotId: null,
    });
  }
  if (state.phase === "in-flight"
    && (event.type === "commit" || event.type === "transport-unknown")) {
    if (event.idempotencyKey !== state.idempotencyKey
      || event.manifestDigest !== state.manifestDigest) {
      fail("offsite attempt identity or manifest digest is invalid");
    }
    if (event.type === "transport-unknown") {
      return deepFreeze({
        ...structuredClone(state),
        phase: "remote-unknown",
        retryAllowed: false,
      });
    }
    if (!SHA256.test(String(event.snapshotId ?? ""))) {
      fail("offsite snapshot identity is invalid");
    }
    return deepFreeze({
      ...structuredClone(state),
      phase: "complete",
      snapshotId: event.snapshotId,
    });
  }
  fail("unsupported offsite phase transition");
}

export async function runFixedToolEntry(command, options = {}) {
  const definition = commandDefinition(command);
  const env = options.env ?? process.env;
  const io = options.io ?? fs;
  if (!isPlainRecord(env)) fail("fixed tool environment is invalid");
  const context = loadPhaseAuthority(command, env);
  assertRoleEnvironment(context, env);
  let job = null;
  if (definition.jobOperation) {
    job = claimedJobIdentity(env);
    if (job.jobOperation !== definition.jobOperation) {
      fail("fixed tool claimed-job operation does not match its command");
    }
  } else {
    rejectUnexpectedClaimedJobEnvironment(env);
  }
  let output;
  if (context.role === "artifact-resolver") {
    output = resolveArtifactBinding(command, {
      backupRoot: options.backupRoot,
      env,
      io,
      jobDocument: options.jobDocument,
      reportRoot: options.reportRoot,
    });
  } else if (context.role === "scratch-preparer"
    || context.role === "scratch-cleaner") {
    output = manageRestoreScratch(command, context.role, {
      env,
      io,
      scratchRoot: options.scratchRoot,
    });
  } else if (context.role === "helper-preparer") {
    output = prepareHelperFilesystem(command, {
      backupRoot: options.backupRoot,
      env,
      io,
      reportRoot: options.reportRoot,
    });
  } else if (context.role === "standalone" && command === "backup-prune-plan") {
    output = backupPrunePlan({
      authority: context.authority,
      backupRoot: options.backupRoot,
      io,
    });
  } else if (context.role === "standalone" && command === "backup-prune-apply") {
    output = backupPruneApply({
      authority: context.authority,
      backupRoot: options.backupRoot,
      context,
      io,
      reportRoot: options.reportRoot,
    });
  } else if (context.role === "evidence-finalizer") {
    materializeHelperEvidence(command, {
      backupRoot: options.backupRoot,
      env,
      helperResultsPolicy: options.helperResultsPolicy,
      io,
      reportRoot: options.reportRoot,
    });
    output = aggregateHelperEvidence({
      authority: context.authority,
      command,
      context,
      env,
      io,
      job,
      reportRoot: options.reportRoot,
    });
  } else {
    fail("worker role does not own this fixed command execution path");
  }
  const writeStdout = options.writeStdout
    ?? ((chunk) => process.stdout.write(chunk));
  if (typeof writeStdout !== "function") fail("fixed tool stdout writer is invalid");
  const serialized = JSON.stringify(output);
  if (Buffer.byteLength(serialized) > MAX_WORKER_STDOUT_BYTES) {
    fail("fixed tool output is oversized");
  }
  writeStdout(`${serialized}\n`);
  return output;
}

function assertRoleEnvironment(context, env) {
  const has = (name) => Object.hasOwn(env, name);
  const helperSnapshotNames = [
    "PLATFORM_DOCKER_HELPER_RESULTS_PATH",
    "PLATFORM_DOCKER_HELPER_RESULTS_SHA256",
  ];
  const bindingNames = [
    "PLATFORM_DOCKER_ARTIFACT_BINDING_BASE64",
    "PLATFORM_DOCKER_ARTIFACT_BINDING_SHA256",
  ];
  const requiresHelperSnapshot = context.role === "evidence-finalizer";
  if (helperSnapshotNames.some(has) !== requiresHelperSnapshot
    || (requiresHelperSnapshot && !helperSnapshotNames.every(has))) {
    fail("worker role helper-results environment is incomplete or unsupported");
  }
  const requiresBinding = context.role === "evidence-finalizer"
    && ["job.restore.verify", "restore.verify", "offsite.sync"].includes(
      context.phaseId,
    );
  if (bindingNames.some(has) !== requiresBinding
    || (requiresBinding && !bindingNames.every(has))) {
    fail("worker role artifact-binding environment is incomplete or unsupported");
  }
  const requiresScratchEngine = context.role === "scratch-preparer"
    || context.role === "scratch-cleaner";
  if (has("PLATFORM_DOCKER_SCRATCH_ENGINE") !== requiresScratchEngine) {
    fail("worker role scratch-engine environment is missing or unsupported");
  }
  if (context.role === "evidence-finalizer"
    && CAPTURE_PHASE_IDS.includes(context.phaseId)) {
    executionRequestIssuedAt(env);
  }
}

function loadPhaseAuthority(command, env) {
  const identity = workerIdentity(env, command);
  const encoded = String(env.PLATFORM_DOCKER_PHASE_AUTHORITY_BASE64 ?? "");
  const expectedDigest = String(
    env.PLATFORM_DOCKER_PHASE_AUTHORITY_SHA256 ?? "",
  );
  if (!/^[A-Za-z0-9_-]+$/.test(encoded) || !SHA256.test(expectedDigest)) {
    fail("phase authority is missing");
  }
  let decoded;
  let authority;
  try {
    decoded = Buffer.from(encoded, "base64url").toString("utf8");
    if (Buffer.from(decoded).toString("base64url") !== encoded) {
      fail("phase authority base64url encoding is non-canonical");
    }
    authority = JSON.parse(decoded);
  } catch (error) {
    if (error?.message?.includes("phase authority")) throw error;
    fail("phase authority is invalid JSON");
  }
  if (sha256(decoded) !== expectedDigest
    || !isPlainRecord(authority)
    || decoded !== JSON.stringify(canonicalValue(authority))) {
    fail("phase authority digest or canonical encoding is invalid");
  }
  exactKeys(
    authority,
    [
      "action",
      "actionProfile",
      "effectiveEndpointIds",
      "effectiveHelperProfileIds",
      "effectiveHelperSecretSetIds",
      "effectiveNetworkIds",
      "phaseProfile",
      "resources",
      "schema",
    ],
    "phase authority",
  );
  if (authority.schema !== "platform.docker-worker.phase-authority/v2"
    || authority.action !== identity.action
    || !isPlainRecord(authority.actionProfile)
    || !isPlainRecord(authority.phaseProfile)
    || !isPlainRecord(authority.resources)) {
    fail("phase authority action or schema identity is invalid");
  }
  for (const field of [
    "effectiveEndpointIds",
    "effectiveHelperProfileIds",
    "effectiveHelperSecretSetIds",
    "effectiveNetworkIds",
  ]) {
    exactStringArray(authority[field], `phase authority ${field}`);
  }
  const phase = authority.phaseProfile;
  exactKeys(phase, [
    "command",
    "endpointIds",
    "helperProfileIds",
    "mountIds",
    "mutationPolicy",
    "networkIds",
    "outputSchema",
    "phaseId",
    "phaseSha256",
    "scratchVolumeIds",
    "workerImageId",
    "workerImageRef",
    "workerSecretSetIds",
    "writableSubpathIds",
  ], "phase authority profile");
  for (const field of [
    "endpointIds",
    "helperProfileIds",
    "mountIds",
    "networkIds",
    "scratchVolumeIds",
    "workerSecretSetIds",
    "writableSubpathIds",
  ]) {
    exactStringArray(phase[field], `phase authority ${field}`);
  }
  if (phase.phaseId !== identity.phaseId
    || phase.command !== command
    || phase.outputSchema !== OUTPUT_SCHEMA_BY_PHASE[identity.phaseId]
    || !SHA256.test(String(phase.phaseSha256 ?? ""))
    || !/^sha256:[a-f0-9]{64}$/.test(String(phase.workerImageId ?? ""))
    || !DIGEST_IMAGE.test(String(phase.workerImageRef ?? ""))) {
    fail("phase authority command, image or output identity is invalid");
  }
  const resources = authority.resources;
  exactKeys(resources, [
    "backupResources",
    "helperProfiles",
    "helperSecretSets",
    "mounts",
    "networks",
    "serviceEndpoints",
    "volumes",
    "workerSecretSets",
    "writableSubpaths",
  ], "phase authority resources");
  for (const field of [
    "backupResources",
    "helperProfiles",
    "helperSecretSets",
    "mounts",
    "networks",
    "serviceEndpoints",
    "volumes",
    "workerSecretSets",
    "writableSubpaths",
  ]) {
    if (!isPlainRecord(resources[field])) {
      fail(`phase authority ${field} map is invalid`);
    }
  }
  if (!sameCanonical(Object.keys(resources.mounts).sort(), [...phase.mountIds].sort())) {
    fail("phase authority mount subset does not match the phase profile");
  }
  const helperProfileIds = Object.keys(resources.helperProfiles).sort();
  if (!sameCanonical(
    helperProfileIds,
    [...authority.effectiveHelperProfileIds].sort(),
  )) {
    fail("phase helper profile subset does not match its authority");
  }
  for (const helperProfileId of authority.effectiveHelperProfileIds) {
    validateHelperProfile(helperProfileId, resources.helperProfiles[helperProfileId]);
  }
  for (const [idsField, resourcesField] of [
    ["effectiveEndpointIds", "serviceEndpoints"],
    ["effectiveHelperSecretSetIds", "helperSecretSets"],
    ["effectiveNetworkIds", "networks"],
  ]) {
    if (!sameCanonical(
      Object.keys(resources[resourcesField]).sort(),
      [...authority[idsField]].sort(),
    )) {
      fail(`phase effective ${resourcesField} subset does not match authority`);
    }
  }
  const backupResourceCount = Object.keys(resources.backupResources).length;
  const requiresBackupResources = [
    "catalog.capture",
    "job.backup.capture",
    "job.restore.verify",
    "restore.capture",
    "restore.verify",
  ].includes(identity.phaseId);
  if ((requiresBackupResources && backupResourceCount < 1)
    || (!requiresBackupResources && backupResourceCount !== 0)) {
    fail("phase authority backup-resource cardinality is invalid");
  }
  return deepFreeze({ authority: structuredClone(authority), ...identity });
}

function validateHelperProfile(helperProfileId, profile) {
  if (!/^helper\.(?:capture|restore|offsite)\.[a-z0-9.-]{1,120}$/.test(
    String(helperProfileId ?? ""),
  ) || !isPlainRecord(profile)) {
    fail("helper profile identity is invalid");
  }
  exactKeys(profile, [
    "declaredVolumePaths",
    "engine",
    "entrypoint",
    "helperProfileId",
    "imageId",
    "imageRef",
    "networkId",
    "operation",
    "outputMode",
    "resourceKind",
    "runtimeGid",
    "runtimeUid",
    "secretSetId",
  ], `helper profile ${helperProfileId}`);
  if (profile.helperProfileId !== helperProfileId
    || !/^sha256:[a-f0-9]{64}$/.test(String(profile.imageId ?? ""))
    || !DIGEST_IMAGE.test(String(profile.imageRef ?? ""))
    || !Array.isArray(profile.entrypoint)
    || profile.entrypoint.length < 1
    || profile.entrypoint.length > 8
    || profile.entrypoint.some(
      (entry) => typeof entry !== "string" || entry.length < 1
        || entry.length > 256 || entry.includes("\0"),
    )
    || !["capture", "offsite-sync", "restore", "restore-server", "verify"]
      .includes(profile.operation)
    || !["artifact", "json", "none"].includes(profile.outputMode)
    || !Number.isSafeInteger(profile.runtimeUid)
    || profile.runtimeUid < 0
    || !Number.isSafeInteger(profile.runtimeGid)
    || profile.runtimeGid < 0
    || !Array.isArray(profile.declaredVolumePaths)
    || profile.declaredVolumePaths.length > 8
    || profile.declaredVolumePaths.some((item, index, values) => (
      typeof item !== "string"
        || !item.startsWith("/")
        || item.includes("\0")
        || item.includes("/../")
        || item.endsWith("/..")
        || path.posix.normalize(item) !== item
        || values.indexOf(item) !== index
    ))
    || !nullableText(profile.engine)
    || !nullableText(profile.networkId)
    || !nullableText(profile.resourceKind)
    || !nullableText(profile.secretSetId)) {
    fail(`helper profile ${helperProfileId} image or execution identity is invalid`);
  }
}

function aggregateHelperEvidence({
  authority,
  command,
  context,
  env,
  io,
  job,
  reportRoot,
}) {
  validateFinalizerArtifactBinding({ authority, context, env });
  const reportPolicy = validateNamedMountAuthority({
    access: "rw",
    authority,
    io,
    mountId: "report.root.rw",
    root: reportRoot,
  });
  const evidencePath = terminalEvidencePath(reportPolicy.root, context);
  let bytes;
  try {
    bytes = readProtectedFile(evidencePath, {
      expectedGid: reportPolicy.expectedGid,
      expectedMode: 0o400,
      expectedUid: reportPolicy.expectedUid,
      maximumBytes: MAX_TERMINAL_EVIDENCE_BYTES,
      parentRoot: reportPolicy.root,
    }, { io });
  } catch (error) {
    fail(`helper evidence report is missing or unsafe: ${error?.message ?? error}`);
  }
  let report;
  try {
    report = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("helper evidence report is invalid JSON");
  }
  if (`${JSON.stringify(canonicalValue(report))}\n` !== bytes.toString("utf8")) {
    fail("helper evidence report is not canonical JSON");
  }
  const helperArtifacts = validateHelperEvidenceReport(report, {
    authority,
    command,
    context,
    evidencePath,
    io,
    job,
    reportPolicy,
  });
  let artifactBinding;
  let evidenceSha256 = sha256(bytes);
  if (CAPTURE_PHASE_IDS.includes(context.phaseId)) {
    const finalized = finalizeCaptureArtifacts({
      authority,
      context,
      env,
      helperArtifacts,
      helperEvidenceSha256: evidenceSha256,
      io,
      job,
      reportPolicy,
    });
    artifactBinding = finalized.artifactBinding;
    evidenceSha256 = finalized.evidenceSha256;
  }
  const output = {
    evidenceSha256,
    mutationPerformed: true,
    schema: authority.phaseProfile.outputSchema,
    status: "passed",
  };
  if (artifactBinding) output.artifactBinding = artifactBinding;
  if (job) {
    output.jobId = job.jobId;
    output.jobOperation = job.jobOperation;
  }
  if (context.phaseId === "offsite.sync") output.repositoryOffsite = true;
  return output;
}

function validateFinalizerArtifactBinding({ authority, context, env }) {
  if (CAPTURE_PHASE_IDS.includes(context.phaseId)) {
    rejectArtifactBindingEnvironment(env);
    return null;
  }
  if (!["job.restore.verify", "restore.verify", "offsite.sync"].includes(
    context.phaseId,
  )) {
    rejectArtifactBindingEnvironment(env);
    return null;
  }
  const requestSha256 = executionRequestSha256(env);
  const expectedKind = context.phaseId === "restore.verify"
    ? "journaled-phase-result"
    : "verified-manifest";
  const binding = loadArtifactBindingEnvironment(env, {
    consumerRequestSha256: requestSha256,
    ...(context.phaseId === "restore.verify" ? {
      producerPhaseId: "restore.capture",
      producerRequestSha256: requestSha256,
    } : {}),
    ...(Object.keys(authority.resources.backupResources).length > 0 ? {
      resourceIds: Object.keys(authority.resources.backupResources),
    } : {}),
    verificationKind: expectedKind,
  });
  if (expectedKind === "verified-manifest") {
    const keySha256 = authority.resources.workerSecretSets?.["manifest.verification"]
      ?.files?.key?.sha256;
    if (!SHA256.test(String(keySha256 ?? ""))
      || binding.verification.authoritySha256 !== keySha256) {
      fail("finalizer artifact binding verification authority is invalid");
    }
  }
  return binding;
}

function loadArtifactBindingEnvironment(env, options) {
  const encoded = String(env.PLATFORM_DOCKER_ARTIFACT_BINDING_BASE64 ?? "");
  const expectedSha256 = String(
    env.PLATFORM_DOCKER_ARTIFACT_BINDING_SHA256 ?? "",
  );
  if (!/^[A-Za-z0-9_-]+$/.test(encoded) || !SHA256.test(expectedSha256)) {
    fail("artifact binding environment authority is missing");
  }
  let text;
  let binding;
  try {
    text = Buffer.from(encoded, "base64url").toString("utf8");
    if (Buffer.from(text).toString("base64url") !== encoded) {
      fail("artifact binding environment encoding is non-canonical");
    }
    binding = JSON.parse(text);
  } catch (error) {
    if (String(error?.message ?? "").includes("artifact binding")) throw error;
    fail("artifact binding environment is invalid JSON");
  }
  if (text !== JSON.stringify(canonicalValue(binding))
    || sha256(text) !== expectedSha256) {
    fail("artifact binding environment digest or canonical encoding is invalid");
  }
  return normalizeArtifactBinding(binding, options);
}

function rejectArtifactBindingEnvironment(env) {
  for (const name of [
    "PLATFORM_DOCKER_ARTIFACT_BINDING_BASE64",
    "PLATFORM_DOCKER_ARTIFACT_BINDING_SHA256",
  ]) {
    if (Object.hasOwn(env, name)) {
      fail("worker phase received unsupported artifact binding authority");
    }
  }
}

function validateHelperEvidenceReport(report, expected) {
  if (!isPlainRecord(report)) fail("helper evidence report schema is invalid");
  exactKeys(report, [
    "action",
    "artifacts",
    "command",
    "helperResults",
    "job",
    "mutationPerformed",
    "phaseId",
    "repositoryOffsite",
    "requestId",
    "schema",
    "status",
  ], "helper evidence report");
  const expectedJob = expected.job ?? null;
  if (report.schema !== "platform.docker-helper-evidence/v1"
    || report.status !== "passed"
    || report.mutationPerformed !== true
    || report.requestId !== expected.context.requestId
    || report.action !== expected.context.action
    || report.phaseId !== expected.context.phaseId
    || report.command !== expected.command
    || !sameCanonical(report.job, expectedJob)
    || report.repositoryOffsite !== (
      expected.context.phaseId === "offsite.sync" ? true : null
    )) {
    fail("helper evidence report request, phase, job or status identity is invalid");
  }
  if (report.job !== null) validateJobResultIdentity(report.job);
  validateHelperResults(
    report.helperResults,
    expected.authority.effectiveHelperProfileIds,
    expected.authority.resources.helperProfiles,
  );
  return validateHelperArtifacts(report.artifacts, expected);
}

function validateHelperResults(results, helperProfileIds, helperProfiles) {
  if (!Array.isArray(results) || results.length !== helperProfileIds.length) {
    fail("helper result coverage is incomplete");
  }
  const actualIds = [];
  for (const result of results) {
    exactKeys(
      result,
      ["helperProfileId", "imageId", "status"],
      "helper execution result",
    );
    const profile = helperProfiles[result.helperProfileId];
    if (!profile || result.imageId !== profile.imageId
      || result.status !== "completed") {
      fail("helper result image or authority identity is invalid");
    }
    actualIds.push(result.helperProfileId);
  }
  if (!sameCanonical(actualIds, helperProfileIds)
    || new Set(actualIds).size !== actualIds.length) {
    fail("helper result coverage does not match phase authority");
  }
}

function validateHelperArtifacts(artifacts, expected) {
  const allowsEmptyNativeOnly = expected.authority.effectiveHelperProfileIds.length === 0
    && Object.values(expected.authority.resources.backupResources).every(
      ({ kind }) => kind === "source" || kind === "platform-state",
    );
  if (!Array.isArray(artifacts)
    || (artifacts.length < 1 && !allowsEmptyNativeOnly)
    || artifacts.length > MAX_MANIFESTS) {
    fail("helper artifact inventory is missing or oversized");
  }
  const resources = expected.authority.resources.backupResources;
  const resourceIds = Object.entries(resources)
    .filter(([, resource]) => (
      resource.kind !== "source" && resource.kind !== "platform-state"
    ))
    .map(([resourceId]) => resourceId)
    .sort();
  const roots = writableArtifactRoots(expected.authority, expected.io);
  const coveredResources = new Set();
  const producingHelpers = new Set();
  const seenPaths = new Set();
  let previousKey = "";
  for (const artifact of artifacts) {
    exactKeys(artifact, [
      "backupResourceId",
      "path",
      "producerHelperProfileId",
      "sha256",
      "sizeBytes",
    ], "helper artifact");
    const phaseLevelOffsiteReceipt = artifact.backupResourceId === null
      && expected.context.phaseId === "offsite.sync";
    const resource = phaseLevelOffsiteReceipt
      ? null
      : resources[artifact.backupResourceId];
    if ((!phaseLevelOffsiteReceipt && (!resource || !isPlainRecord(resource)))
      || !SHA256.test(String(artifact.sha256 ?? ""))
      || !Number.isSafeInteger(artifact.sizeBytes)
      || artifact.sizeBytes < 0
      || artifact.sizeBytes > MAX_TERMINAL_ARTIFACT_BYTES) {
      fail("helper artifact resource, digest or size is invalid");
    }
    const resolved = path.resolve(exactText(artifact.path, "helper artifact path"));
    if (resolved !== artifact.path
      || resolved === expected.evidencePath
      || seenPaths.has(resolved)) {
      fail("helper artifact path identity is invalid or duplicated");
    }
    const orderKey = `${artifact.backupResourceId ?? ""}\0${resolved}`;
    if (previousKey && orderKey.localeCompare(previousKey) <= 0) {
      fail("helper artifact inventory is not in canonical order");
    }
    previousKey = orderKey;
    seenPaths.add(resolved);
    if (phaseLevelOffsiteReceipt) {
      const producer = expected.authority.resources.helperProfiles[
        artifact.producerHelperProfileId
      ];
      if (!producer || producer.operation !== "offsite-sync") {
        fail("offsite receipt producer does not match helper authority");
      }
    } else {
      validateArtifactProducer(
        artifact.producerHelperProfileId,
        resource,
        expected.authority.resources.helperProfiles,
      );
    }
    if (artifact.producerHelperProfileId !== null) {
      producingHelpers.add(artifact.producerHelperProfileId);
    }
    const rootPolicy = roots.find(
      ({ root }) => resolved !== root && resolved.startsWith(`${root}${path.sep}`),
    );
    if (!rootPolicy) fail("helper artifact escaped its writable phase roots");
    const observed = readProtectedArtifactIdentity(resolved, {
      expectedGid: rootPolicy.expectedGid,
      expectedSize: artifact.sizeBytes,
      expectedUid: rootPolicy.expectedUid,
      parentRoot: rootPolicy.root,
    }, expected.io);
    if (observed.sha256 !== artifact.sha256
      || observed.sizeBytes !== artifact.sizeBytes) {
      fail("helper artifact bytes do not match their SHA256 digest");
    }
    if (!phaseLevelOffsiteReceipt) {
      coveredResources.add(artifact.backupResourceId);
    }
  }
  if (!sameCanonical([...coveredResources].sort(), resourceIds)) {
    fail("helper artifact backup-resource coverage is incomplete");
  }
  for (const [helperProfileId, profile] of Object.entries(
    expected.authority.resources.helperProfiles,
  )) {
    if (profile.outputMode !== "none" && !producingHelpers.has(helperProfileId)) {
      fail("helper artifact producer coverage is incomplete");
    }
  }
  return artifacts.map((artifact) => structuredClone(artifact));
}

function validateArtifactProducer(producerHelperProfileId, resource, profiles) {
  if (producerHelperProfileId === null) {
    fail("helper artifact producer identity is missing");
  }
  if (typeof producerHelperProfileId !== "string") {
    fail("helper artifact producer identity is invalid");
  }
  const profile = profiles[producerHelperProfileId];
  if (!profile) fail("helper artifact producer is outside phase authority");
  if (profile.operation === "offsite-sync") return;
  const resourceEngine = resource.engine
    ?? (resource.kind === "storage" ? resource.externalId : null);
  if (profile.resourceKind !== resource.kind
    || (resourceEngine !== null && profile.engine !== resourceEngine)
    || (profile.outputMode !== "artifact" && profile.outputMode !== "json")) {
    fail("helper artifact producer does not own the backup resource");
  }
}

function finalizeCaptureArtifacts({
  authority,
  context,
  env,
  helperArtifacts,
  helperEvidenceSha256,
  io,
  job,
  reportPolicy,
}) {
  const requestSha256 = executionRequestSha256(env);
  const requestIssuedAt = executionRequestIssuedAt(env);
  const backupPolicy = validateBackupMountAuthority({
    access: "rw",
    authority,
    io,
  });
  const nativeArtifacts = createNativeCaptureArtifacts({
    authority,
    backupPolicy,
    io,
    requestSha256,
  });
  const artifacts = [...helperArtifacts, ...nativeArtifacts].sort(
    (left, right) => left.backupResourceId.localeCompare(right.backupResourceId),
  );
  const resourceIds = Object.keys(authority.resources.backupResources).sort();
  if (!sameCanonical(
    artifacts.map(({ backupResourceId }) => backupResourceId),
    resourceIds,
  ) || new Set(artifacts.map(({ backupResourceId }) => backupResourceId)).size
      !== artifacts.length) {
    fail("capture artifact resource coverage is incomplete or duplicated");
  }
  const signing = loadAuthoritySecretKey(authority, "manifest.signing", io);
  const manifestDirectoryRelativePath = [
    "requests",
    requestSha256,
    "manifests",
  ].join("/");
  const manifestDirectory = ensurePrivateRelativeDirectory(
    backupPolicy,
    manifestDirectoryRelativePath,
    io,
  );
  const manifestRelativePath = `${manifestDirectoryRelativePath}/${context.phaseId}.json`;
  const manifestPath = path.join(backupPolicy.root, ...manifestRelativePath.split("/"));
  const manifestArtifacts = [];
  const bindingArtifacts = {};
  for (const artifact of artifacts) {
    const relativePath = relativeArtifactPath(
      backupPolicy.root,
      artifact.path,
      requestSha256,
    );
    const resource = authority.resources.backupResources[artifact.backupResourceId];
    const sidecar = {
      algorithm: "HMAC-SHA256",
      artifact: path.basename(relativePath),
      keyId: MANIFEST_KEY_ID,
      sha256: artifact.sha256,
      signature: hmacBase64Url(
        signing.key,
        `platform-${backupResourceDomain(resource)}-backup-v1\n${path.basename(relativePath)}\n${artifact.sha256}\n`,
      ),
      version: 1,
    };
    const sidecarPath = `${artifact.path}.sig.json`;
    writeCanonicalPrivateJson(sidecarPath, sidecar, io);
    fsyncDirectory(path.dirname(sidecarPath), io);
    manifestArtifacts.push({
      id: `artifact:${artifact.backupResourceId}`,
      path: relativePath,
      resourceId: artifact.backupResourceId,
      sha256: artifact.sha256,
      signatureKeyId: MANIFEST_KEY_ID,
      sizeBytes: artifact.sizeBytes,
    });
    bindingArtifacts[artifact.backupResourceId] = {
      relativePath,
      resourceId: artifact.backupResourceId,
      sha256: artifact.sha256,
    };
  }
  const unsignedManifest = {
    artifacts: manifestArtifacts,
    coverage: {
      artifactResourceIds: resourceIds,
      complete: true,
      missingResourceIds: [],
      requiredResourceIds: resourceIds,
    },
    createdAt: requestIssuedAt,
    id: `manifest:${requestSha256}:${context.phaseId}`,
    jobId: job?.jobId ?? null,
    operation: job?.jobOperation ?? "backup",
    phaseId: context.phaseId,
    requestSha256,
    resources: resourceIds.map((resourceId) => ({
      id: resourceId,
      ...structuredClone(authority.resources.backupResources[resourceId]),
    })),
    schema: "platform.backup-manifest/v1",
    scope: { id: "platform", kind: "platform" },
  };
  const manifestDigest = backupDocumentDigest(unsignedManifest);
  const manifest = {
    ...unsignedManifest,
    signature: {
      algorithm: "HMAC-SHA256",
      digest: manifestDigest,
      keyId: MANIFEST_KEY_ID,
      value: hmacBase64Url(
        signing.key,
        `platform-backup-manifest-v1\n${unsignedManifest.id}\n${manifestDigest}\n`,
      ),
    },
  };
  writeCanonicalPrivateJson(manifestPath, manifest, io);
  fsyncDirectory(manifestDirectory, io);
  const manifestBytes = readProtectedFile(manifestPath, {
    expectedGid: backupPolicy.expectedGid,
    expectedMode: 0o400,
    expectedUid: backupPolicy.expectedUid,
    maximumBytes: MAX_MANIFEST_BYTES,
    parentRoot: backupPolicy.root,
  }, { io });
  const manifestSha256 = sha256(manifestBytes);
  const artifactSetSha256 = sha256(
    JSON.stringify(canonicalValue(bindingArtifacts)),
  );
  const captureEvidence = {
    action: context.action,
    artifactSetSha256,
    helperEvidenceSha256,
    manifestRelativePath,
    manifestSha256,
    phaseId: context.phaseId,
    requestId: context.requestId,
    requestSha256,
    schema: "platform.docker-worker.capture-evidence/v1",
    status: "passed",
  };
  const captureEvidenceDirectory = path.join(
    reportPolicy.root,
    "worker-evidence",
  );
  ensurePrivateDirectory(captureEvidenceDirectory, reportPolicy, io);
  const captureEvidencePath = path.join(
    captureEvidenceDirectory,
    `${context.requestId}-${context.phaseId}-capture.json`,
  );
  writeCanonicalPrivateJson(captureEvidencePath, captureEvidence, io);
  fsyncDirectory(captureEvidenceDirectory, io);
  const captureEvidenceBytes = readProtectedFile(captureEvidencePath, {
    expectedGid: reportPolicy.expectedGid,
    expectedMode: 0o400,
    expectedUid: reportPolicy.expectedUid,
    maximumBytes: MAX_TERMINAL_EVIDENCE_BYTES,
    parentRoot: reportPolicy.root,
  }, { io });
  const evidenceSha256 = sha256(captureEvidenceBytes);
  const artifactBinding = normalizeArtifactBinding({
    artifactSetSha256,
    artifacts: bindingArtifacts,
    consumerRequestSha256: requestSha256,
    manifestRelativePath,
    manifestSha256,
    producerPhaseId: context.phaseId,
    producerRequestSha256: requestSha256,
    schema: "platform.docker-action.artifact-binding/v1",
    verification: {
      authoritySha256: authority.phaseProfile.phaseSha256,
      evidenceSha256,
      kind: "journaled-phase-result",
      source: context.phaseId,
    },
  }, {
    consumerRequestSha256: requestSha256,
    producerPhaseId: context.phaseId,
    producerRequestSha256: requestSha256,
    resourceIds,
    verificationKind: "journaled-phase-result",
  });
  return { artifactBinding, evidenceSha256 };
}

function createNativeCaptureArtifacts({ authority, backupPolicy, io, requestSha256 }) {
  const artifacts = [];
  for (const [resourceId, resource] of Object.entries(
    authority.resources.backupResources,
  ).sort(([left], [right]) => left.localeCompare(right))) {
    if (resource.kind !== "source" && resource.kind !== "platform-state") continue;
    const input = nativeCaptureInput(resourceId, resource, authority, io);
    const artifactRelativeDirectory = [
      "requests",
      requestSha256,
      "artifacts",
      resource.kind,
    ].join("/");
    const artifactDirectory = ensurePrivateRelativeDirectory(
      backupPolicy,
      artifactRelativeDirectory,
      io,
    );
    const artifactName = `${safeLogicalPathToken(resource.externalId, "native resource external ID")}.ptree`;
    const artifactPath = path.join(artifactDirectory, artifactName);
    const written = writeNativeTreeArtifact({
      destination: artifactPath,
      input,
      io,
      resourceId,
    });
    fsyncDirectory(artifactDirectory, io);
    artifacts.push({
      backupResourceId: resourceId,
      path: artifactPath,
      producerHelperProfileId: null,
      sha256: written.sha256,
      sizeBytes: written.sizeBytes,
    });
  }
  return artifacts;
}

function nativeCaptureInput(resourceId, resource, authority, io) {
  const mountId = resource.kind === "source" ? "source.root.ro" : "state.catalog.ro";
  const mountPolicy = validateNamedMountAuthority({
    access: "ro",
    authority,
    io,
    mountId,
  });
  let root = mountPolicy.root;
  if (resource.kind === "source") {
    const sourceDirectory = safeRelativePath(
      resource.sourceDirectory,
      `native source directory ${resourceId}`,
    );
    root = path.join(root, ...sourceDirectory.split("/"));
  }
  root = canonicalDirectory(root, io);
  if (root !== mountPolicy.root
    && !root.startsWith(`${mountPolicy.root}${path.sep}`)) {
    fail("native capture input escaped its admitted mount");
  }
  return { root };
}

function writeNativeTreeArtifact({ destination, input, io, resourceId }) {
  const entries = nativeTreeInventory(input.root, io);
  let descriptor;
  let sizeBytes = 0;
  const digest = crypto.createHash("sha256");
  const write = (bytes) => {
    const value = Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes));
    let offset = 0;
    while (offset < value.length) {
      const count = io.writeSync(
        descriptor,
        value,
        offset,
        value.length - offset,
        sizeBytes + offset,
      );
      if (!Number.isSafeInteger(count) || count <= 0) {
        fail("native artifact write made no bounded progress");
      }
      digest.update(value.subarray(offset, offset + count));
      offset += count;
    }
    sizeBytes += value.length;
  };
  try {
    descriptor = io.openSync(
      destination,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | fs.constants.O_NOFOLLOW,
      0o400,
    );
    write(`${JSON.stringify(canonicalValue({
      resourceId,
      schema: "platform.native-tree-artifact/v1",
    }))}\n`);
    for (const entry of entries) {
      write(`${JSON.stringify(canonicalValue({
        mode: entry.mode,
        path: entry.relativePath,
        sha256: entry.type === "file" ? entry.sha256 : null,
        sizeBytes: entry.type === "file" ? entry.sizeBytes : 0,
        type: entry.type,
      }))}\n`);
      if (entry.type === "file") {
        copyStableNativeFile(entry, descriptor, {
          digest,
          io,
          outputPosition: sizeBytes,
        });
        sizeBytes += entry.sizeBytes;
        write("\n");
      }
    }
    io.fsyncSync(descriptor);
  } catch (error) {
    if (descriptor !== undefined) {
      try {
        io.closeSync(descriptor);
      } catch {
        // Preserve the causal capture error.
      }
      descriptor = undefined;
    }
    try {
      io.unlinkSync(destination);
    } catch {
      // Preserve the causal capture error.
    }
    throw error;
  } finally {
    if (descriptor !== undefined) io.closeSync(descriptor);
  }
  const stat = io.lstatSync(destination);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
    || (stat.mode & 0o777) !== 0o400 || stat.size !== sizeBytes) {
    fail("native artifact leaf identity or size is invalid after write");
  }
  return { sha256: digest.digest("hex"), sizeBytes };
}

function nativeTreeInventory(root, io) {
  const entries = [];
  const walk = (directory, relativeDirectory, depth) => {
    if (depth > MAX_NATIVE_TREE_DEPTH) fail("native capture tree depth is oversized");
    const before = io.lstatSync(directory);
    if (!before.isDirectory() || before.isSymbolicLink()) {
      fail("native capture tree contains an unsafe directory");
    }
    const beforeIdentity = statIdentity(before);
    const names = io.readdirSync(directory).sort();
    for (const name of names) {
      if (!name || name === "." || name === ".." || name.includes("/")
        || name.includes("\\") || name.includes("\0")) {
        fail("native capture tree entry name is invalid");
      }
      const relativePath = relativeDirectory
        ? `${relativeDirectory}/${name}`
        : name;
      safeRelativePath(relativePath, "native capture entry path");
      const file = path.join(directory, name);
      const stat = io.lstatSync(file);
      if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) {
        fail("native capture tree contains an unsupported entry type");
      }
      if (stat.isDirectory()) {
        entries.push({
          mode: stat.mode & 0o7777,
          relativePath,
          type: "directory",
        });
        walk(file, relativePath, depth + 1);
      } else {
        const hashed = hashStableNativeFile(file, stat, io);
        entries.push({
          identity: hashed.identity,
          mode: stat.mode & 0o7777,
          relativePath,
          sha256: hashed.sha256,
          sizeBytes: stat.size,
          sourcePath: file,
          type: "file",
        });
      }
      if (entries.length > MAX_NATIVE_TREE_ENTRIES) {
        fail("native capture tree entry count is oversized");
      }
    }
    const after = io.lstatSync(directory);
    if (!sameIdentity(beforeIdentity, statIdentity(after))) {
      fail("native capture directory changed during inventory");
    }
  };
  walk(root, "", 0);
  return entries;
}

function hashStableNativeFile(file, stat, io) {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
    || !Number.isSafeInteger(stat.size) || stat.size < 0
    || stat.size > MAX_TERMINAL_ARTIFACT_BYTES) {
    fail("native capture file identity or size is invalid");
  }
  const identity = statIdentity(stat);
  let descriptor;
  try {
    descriptor = io.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = io.fstatSync(descriptor);
    if (!sameIdentity(identity, statIdentity(opened))) {
      fail("native capture file identity changed before hashing");
    }
    const first = hashDescriptorPassAllowEmpty(io, descriptor, opened.size);
    const second = hashDescriptorPassAllowEmpty(io, descriptor, opened.size);
    const after = io.fstatSync(descriptor);
    if (first !== second || !sameIdentity(identity, statIdentity(after))) {
      fail("native capture file changed during stable hashing");
    }
    return { identity, sha256: first };
  } finally {
    if (descriptor !== undefined) io.closeSync(descriptor);
  }
}

function copyStableNativeFile(entry, outputDescriptor, { digest, io, outputPosition }) {
  let descriptor;
  try {
    descriptor = io.openSync(
      entry.sourcePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
    );
    const opened = io.fstatSync(descriptor);
    if (!sameIdentity(entry.identity, statIdentity(opened))) {
      fail("native capture file identity changed before copy");
    }
    const chunk = Buffer.alloc(Math.min(
      ARTIFACT_HASH_CHUNK_BYTES,
      Math.max(1, opened.size),
    ));
    const copiedHash = crypto.createHash("sha256");
    let inputPosition = 0;
    let written = 0;
    while (inputPosition < opened.size) {
      const length = Math.min(chunk.length, opened.size - inputPosition);
      const count = io.readSync(descriptor, chunk, 0, length, inputPosition);
      if (!Number.isSafeInteger(count) || count <= 0 || count > length) {
        fail("native capture file copy made no bounded read progress");
      }
      copiedHash.update(chunk.subarray(0, count));
      let chunkOffset = 0;
      while (chunkOffset < count) {
        const outputCount = io.writeSync(
          outputDescriptor,
          chunk,
          chunkOffset,
          count - chunkOffset,
          outputPosition + written,
        );
        if (!Number.isSafeInteger(outputCount) || outputCount <= 0) {
          fail("native capture file copy made no bounded write progress");
        }
        digest.update(chunk.subarray(chunkOffset, chunkOffset + outputCount));
        chunkOffset += outputCount;
        written += outputCount;
      }
      inputPosition += count;
    }
    const after = io.fstatSync(descriptor);
    if (written !== entry.sizeBytes
      || copiedHash.digest("hex") !== entry.sha256
      || !sameIdentity(entry.identity, statIdentity(after))) {
      fail("native capture file bytes changed during copy");
    }
  } finally {
    if (descriptor !== undefined) io.closeSync(descriptor);
  }
}

function hashDescriptorPassAllowEmpty(io, descriptor, size) {
  if (size === 0) return sha256(Buffer.alloc(0));
  return hashDescriptorPass(io, descriptor, size);
}

function ensurePrivateRelativeDirectory(policy, relativePath, io) {
  const safe = safeRelativePath(relativePath, "private output directory path");
  let directory = policy.root;
  for (const component of safe.split("/")) {
    directory = path.join(directory, component);
    ensurePrivateDirectory(directory, policy, io);
  }
  return directory;
}

function ensureRuntimePrivateDirectory(directory, rootPolicy, runtimePolicy, io) {
  let created = false;
  try {
    io.mkdirSync(directory, { mode: 0o700 });
    created = true;
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
  }
  const before = io.lstatSync(directory);
  if (!before.isDirectory() || before.isSymbolicLink()) {
    fail("restore scratch runtime directory is unsafe");
  }
  let descriptor;
  try {
    descriptor = io.openSync(
      directory,
      fs.constants.O_RDONLY
        | fs.constants.O_NOFOLLOW
        | (fs.constants.O_DIRECTORY ?? 0),
    );
    const opened = io.fstatSync(descriptor);
    if (!sameIdentity(statIdentity(before), statIdentity(opened))) {
      fail("restore scratch runtime directory changed before admission");
    }
    if (created) {
      if (opened.uid !== rootPolicy.expectedUid
        || opened.gid !== rootPolicy.expectedGid
        || (opened.mode & 0o7777) !== 0o700) {
        fail("new restore scratch directory owner or mode is invalid");
      }
      if (opened.uid !== runtimePolicy.expectedUid
        || opened.gid !== runtimePolicy.expectedGid) {
        io.fchownSync(
          descriptor,
          runtimePolicy.expectedUid,
          runtimePolicy.expectedGid,
        );
      }
      if ((opened.mode & 0o7777) !== 0o700) io.fchmodSync(descriptor, 0o700);
    }
    const admitted = io.fstatSync(descriptor);
    if (!admitted.isDirectory() || admitted.isSymbolicLink()
      || admitted.uid !== runtimePolicy.expectedUid
      || admitted.gid !== runtimePolicy.expectedGid
      || (admitted.mode & 0o7777) !== 0o700) {
      fail("restore scratch runtime directory principal or mode is invalid");
    }
  } finally {
    if (descriptor !== undefined) io.closeSync(descriptor);
  }
  fsyncDirectory(path.dirname(directory), io);
}

function relativeArtifactPath(backupRoot, artifactPath, requestSha256) {
  const resolved = path.resolve(artifactPath);
  const relative = path.relative(backupRoot, resolved).split(path.sep).join("/");
  const safe = safeRelativePath(relative, "capture artifact relative path");
  if (!safe.startsWith(`requests/${requestSha256}/artifacts/`)) {
    fail("capture artifact path is outside its request namespace");
  }
  return safe;
}

function loadAuthoritySecretKey(authority, secretSetId, io) {
  if (!authority.phaseProfile.workerSecretSetIds.includes(secretSetId)) {
    fail(`worker secret set ${secretSetId} is outside phase authority`);
  }
  const secretSet = authority.resources.workerSecretSets[secretSetId];
  if (!isPlainRecord(secretSet)) fail(`worker secret set ${secretSetId} is missing`);
  exactKeys(secretSet, ["containerRoot", "files", "volumeId"], `worker secret set ${secretSetId}`);
  if (!isPlainRecord(secretSet.files)
    || !isPlainRecord(secretSet.files.key)
    || Object.keys(secretSet.files).length !== 1) {
    fail(`worker secret set ${secretSetId} key inventory is invalid`);
  }
  const file = secretSet.files.key;
  exactKeys(file, [
    "device",
    "inode",
    "mode",
    "ownerGid",
    "ownerUid",
    "relativePath",
    "sha256",
    "symlinkFree",
  ], `worker secret set ${secretSetId} key`);
  const root = canonicalDirectory(secretSet.containerRoot, io);
  const relativePath = safeRelativePath(
    file.relativePath,
    `worker secret set ${secretSetId} relative path`,
  );
  const keyPath = path.join(root, ...relativePath.split("/"));
  const key = readProtectedFile(keyPath, {
    expectedGid: file.ownerGid,
    expectedMode: file.mode,
    expectedUid: file.ownerUid,
    maximumBytes: 64 * 1024,
    parentRoot: root,
  }, { io });
  const stat = io.lstatSync(keyPath);
  if (file.symlinkFree !== true
    || String(stat.dev) !== String(file.device)
    || String(stat.ino) !== String(file.inode)
    || sha256(key) !== file.sha256) {
    fail(`worker secret set ${secretSetId} key authority is invalid`);
  }
  return { authoritySha256: file.sha256, key };
}

function executionRequestSha256(env) {
  const value = String(env.PLATFORM_DOCKER_REQUEST_SHA256 ?? "");
  if (!SHA256.test(value)) fail("worker request SHA256 identity is missing");
  return value;
}

function executionRequestIssuedAt(env) {
  const value = String(env.PLATFORM_DOCKER_REQUEST_ISSUED_AT ?? "");
  if (!Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) {
    fail("worker request issued-at identity is missing or non-canonical");
  }
  return value;
}

function safeLogicalPathToken(value, label) {
  const text = exactText(value, label);
  if (!/^[a-z0-9][a-z0-9._-]{0,126}[a-z0-9]$/.test(text)) {
    fail(`${label} is invalid`);
  }
  return text;
}

function backupResourceDomain(resource) {
  if (resource.kind === "database") return safeLogicalPathToken(resource.engine, "database engine");
  if (resource.kind === "storage") return safeLogicalPathToken(resource.externalId, "storage engine");
  if (resource.kind === "source") return "source";
  if (resource.kind === "platform-state") return "platform-state";
  fail("backup resource signature domain is unsupported");
}

function removeBoundedRestoreScratchTree(root, policy, io) {
  const rootStat = io.lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()
    || rootStat.uid !== policy.expectedUid
    || rootStat.gid !== policy.expectedGid
    || (rootStat.mode & 0o7777) !== 0o700) {
    fail("restore scratch cleanup root identity is invalid");
  }
  const rootIdentity = statIdentity(rootStat);
  const files = [];
  const directories = [];
  let entryCount = 0;
  let totalBytes = 0;
  const walk = (directory, depth) => {
    if (depth > MAX_NATIVE_TREE_DEPTH) {
      fail("restore scratch cleanup tree depth is oversized");
    }
    const before = io.lstatSync(directory);
    if (!before.isDirectory() || before.isSymbolicLink()) {
      fail("restore scratch cleanup encountered an unsafe directory");
    }
    const identity = statIdentity(before);
    const names = io.readdirSync(directory).sort();
    for (const name of names) {
      if (!name || name === "." || name === ".." || name.includes("/")
        || name.includes("\\") || name.includes("\0")) {
        fail("restore scratch cleanup entry name is invalid");
      }
      const candidate = path.join(directory, name);
      const stat = io.lstatSync(candidate);
      entryCount += 1;
      if (entryCount > MAX_NATIVE_TREE_ENTRIES) {
        fail("restore scratch cleanup entry count is oversized");
      }
      if (stat.isSymbolicLink()) {
        fail("restore scratch cleanup refuses symbolic links");
      }
      if (stat.isDirectory()) {
        walk(candidate, depth + 1);
        directories.push({ identity: statIdentity(io.lstatSync(candidate)), path: candidate });
        continue;
      }
      if (!stat.isFile() || stat.nlink !== 1
        || !Number.isSafeInteger(stat.size) || stat.size < 0) {
        fail("restore scratch cleanup refuses hardlinks or special files");
      }
      totalBytes += stat.size;
      if (!Number.isSafeInteger(totalBytes)
        || totalBytes > MAX_TERMINAL_ARTIFACT_BYTES) {
        fail("restore scratch cleanup total bytes are oversized");
      }
      let descriptor;
      try {
        descriptor = io.openSync(
          candidate,
          fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
        );
        const opened = io.fstatSync(descriptor);
        if (!sameIdentity(statIdentity(stat), statIdentity(opened))) {
          fail("restore scratch cleanup file identity changed during preflight");
        }
      } finally {
        if (descriptor !== undefined) io.closeSync(descriptor);
      }
      files.push({ identity: statIdentity(stat), path: candidate });
    }
    if (!sameIdentity(identity, statIdentity(io.lstatSync(directory)))) {
      fail("restore scratch cleanup directory changed during preflight");
    }
  };
  walk(root, 0);
  if (!sameCanonical(io.readdirSync(root).sort(), ["data", "run"])) {
    fail("restore scratch cleanup root contains an unmodeled sibling");
  }
  for (const file of files.reverse()) {
    const stat = io.lstatSync(file.path);
    if (!sameIdentity(file.identity, statIdentity(stat))) {
      fail("restore scratch cleanup file changed after preflight");
    }
    let descriptor;
    try {
      descriptor = io.openSync(
        file.path,
        fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
      );
      if (!sameIdentity(file.identity, statIdentity(io.fstatSync(descriptor)))) {
        fail("restore scratch cleanup file descriptor identity changed");
      }
      io.unlinkSync(file.path);
      io.fsyncSync(descriptor);
    } finally {
      if (descriptor !== undefined) io.closeSync(descriptor);
    }
    fsyncDirectory(path.dirname(file.path), io);
  }
  for (const directory of directories) {
    const stat = io.lstatSync(directory.path);
    if (!sameFilesystemObjectIdentity(directory.identity, statIdentity(stat))
      || io.readdirSync(directory.path).length !== 0) {
      fail("restore scratch cleanup directory changed after preflight");
    }
    const parent = path.dirname(directory.path);
    io.rmdirSync(directory.path);
    fsyncDirectory(parent, io);
  }
  const finalRoot = io.lstatSync(root);
  if (!sameFilesystemObjectIdentity(rootIdentity, statIdentity(finalRoot))
    || io.readdirSync(root).length !== 0) {
    fail("restore scratch cleanup root changed after preflight");
  }
  io.rmdirSync(root);
}

function sameFilesystemObjectIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.isFile === right.isFile
    && left.uid === right.uid
    && left.gid === right.gid;
}

function removeEmptyPrivateAncestors(directory, stop, policy, io) {
  let cursor = directory;
  while (cursor !== stop && cursor.startsWith(`${stop}${path.sep}`)) {
    const stat = io.lstatSync(cursor);
    if (!stat.isDirectory() || stat.isSymbolicLink()
      || stat.uid !== policy.expectedUid
      || stat.gid !== policy.expectedGid
      || (stat.mode & 0o7777) !== 0o700) {
      fail("restore scratch ancestor identity changed during cleanup");
    }
    if (io.readdirSync(cursor).length !== 0) return;
    const parent = path.dirname(cursor);
    io.rmdirSync(cursor);
    fsyncDirectory(parent, io);
    cursor = parent;
  }
}

function latestVerifiedManifestCandidate({ authority, backupPolicy, io }) {
  const requestsRoot = canonicalDirectory(
    path.join(backupPolicy.root, "requests"),
    io,
  );
  const candidates = [];
  const requestNames = io.readdirSync(requestsRoot).sort();
  if (requestNames.length > MAX_MANIFESTS) {
    fail("offsite manifest request inventory is oversized");
  }
  for (const requestName of requestNames) {
    if (!SHA256.test(requestName)) continue;
    const requestRoot = path.join(requestsRoot, requestName);
    const requestStat = io.lstatSync(requestRoot);
    if (!requestStat.isDirectory() || requestStat.isSymbolicLink()) {
      fail("offsite manifest request directory is unsafe");
    }
    const manifestRoot = path.join(requestRoot, "manifests");
    if (!io.existsSync(manifestRoot)) continue;
    const manifestStat = io.lstatSync(manifestRoot);
    if (!manifestStat.isDirectory() || manifestStat.isSymbolicLink()) {
      fail("offsite manifest directory is unsafe");
    }
    for (const name of io.readdirSync(manifestRoot).sort()) {
      const phaseId = name.endsWith(".json") ? name.slice(0, -5) : "";
      if (!PRODUCER_PHASE_ID.test(phaseId)) continue;
      const manifestRelativePath = `requests/${requestName}/manifests/${name}`;
      try {
        candidates.push(verifyManifestCandidate({
          authority,
          backupPolicy,
          io,
          manifestRelativePath,
        }));
      } catch {
        // Selection is explicitly over authenticated complete manifests only.
      }
      if (candidates.length > MAX_MANIFESTS) {
        fail("authenticated manifest inventory is oversized");
      }
    }
  }
  if (candidates.length < 1) {
    fail("no authenticated complete manifest is available for offsite sync");
  }
  candidates.sort((left, right) => (
    right.createdAt.localeCompare(left.createdAt)
      || right.producerRequestSha256.localeCompare(left.producerRequestSha256)
      || right.producerPhaseId.localeCompare(left.producerPhaseId)
  ));
  return candidates[0];
}

function loadHelperResultsSnapshot({ authority, context, env, io, policy }) {
  const snapshotPath = exactText(
    env.PLATFORM_DOCKER_HELPER_RESULTS_PATH,
    "helper results snapshot path",
  );
  const expectedSha256 = String(
    env.PLATFORM_DOCKER_HELPER_RESULTS_SHA256 ?? "",
  );
  if (!path.isAbsolute(snapshotPath) || !SHA256.test(expectedSha256)) {
    fail("helper results snapshot identity is invalid");
  }
  const ownerAuthority = authority.resources.mounts["report.root.rw"];
  const readPolicy = policy ?? {
    expectedGid: ownerAuthority?.ownerGid,
    expectedMode: 0o400,
    expectedUid: ownerAuthority?.ownerUid,
    maximumBytes: MAX_TERMINAL_EVIDENCE_BYTES,
    parentRoot: path.dirname(snapshotPath),
  };
  const bytes = readProtectedFile(snapshotPath, readPolicy, { io });
  if (sha256(bytes) !== expectedSha256) {
    fail("helper results snapshot SHA256 does not match its authority");
  }
  let snapshot;
  try {
    snapshot = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("helper results snapshot is invalid JSON");
  }
  if (`${JSON.stringify(canonicalValue(snapshot))}\n` !== bytes.toString("utf8")) {
    fail("helper results snapshot is not canonical JSON");
  }
  exactKeys(snapshot, [
    "action",
    "helpers",
    "phaseId",
    "requestId",
    "requestSha256",
    "schema",
  ], "helper results snapshot");
  const requestSha256 = executionRequestSha256(env);
  if (snapshot.schema !== "platform.docker-helper-results/v1"
    || snapshot.requestId !== context.requestId
    || snapshot.requestSha256 !== requestSha256
    || snapshot.action !== context.action
    || snapshot.phaseId !== context.phaseId
    || !Array.isArray(snapshot.helpers)
    || snapshot.helpers.length !== authority.effectiveHelperProfileIds.length) {
    fail("helper results snapshot request, phase or helper coverage is invalid");
  }
  for (const [index, result] of snapshot.helpers.entries()) {
    exactKeys(result, [
      "artifactRelativePath",
      "exitCode",
      "helperProfileId",
      "imageId",
      "outputMode",
      "status",
      "stderrSha256",
      "stdoutBase64",
    ], "sealed helper result");
    const helperProfileId = authority.effectiveHelperProfileIds[index];
    const profile = authority.resources.helperProfiles[helperProfileId];
    if (result.helperProfileId !== helperProfileId
      || result.imageId !== profile.imageId
      || result.outputMode !== profile.outputMode
      || result.status !== "completed"
      || result.exitCode !== 0
      || !SHA256.test(String(result.stderrSha256 ?? ""))
      || typeof result.stdoutBase64 !== "string") {
      fail("sealed helper result identity, image, exit or output mode is invalid");
    }
    if (profile.outputMode === "artifact") {
      const expectedPath = helperArtifactRelativePath(requestSha256, profile);
      if (result.artifactRelativePath !== expectedPath
        || result.stdoutBase64 !== "") {
        fail("sealed helper artifact output path or stdout is invalid");
      }
    } else if (profile.outputMode === "json") {
      if (result.artifactRelativePath !== null) {
        fail("sealed helper JSON output contains artifact authority");
      }
      decodeCanonicalHelperJson(result.stdoutBase64);
    } else if (result.artifactRelativePath !== null
      || result.stdoutBase64 !== "") {
      fail("sealed helper no-output result contains unsupported bytes");
    }
  }
  return deepFreeze(structuredClone(snapshot));
}

function helperArtifactRelativePath(requestSha256, profile) {
  const prefix = `requests/${requestSha256}/artifacts/${profile.engine}`;
  if (profile.engine === "mariadb") return `${prefix}/mariadb.sql`;
  if (profile.engine === "minio") return `${prefix}/objects`;
  if (profile.engine === "postgres") return `${prefix}/postgres.dump`;
  fail("helper artifact engine path is unsupported");
}

function normalizeHelperArtifactPermissions(target, policy, io) {
  assertProtectedAncestors(
    path.dirname(target),
    policy.parentRoot,
    { expectedGid: policy.expectedGid, expectedUid: policy.expectedUid },
    io,
  );
  const normalize = (candidate, depth) => {
    if (depth > MAX_NATIVE_TREE_DEPTH) {
      fail("helper artifact normalization tree depth is oversized");
    }
    const before = io.lstatSync(candidate);
    if (before.isSymbolicLink()
      || before.uid !== policy.expectedUid
      || before.gid !== policy.expectedGid) {
      fail("helper artifact normalization owner or link identity is invalid");
    }
    if (before.isDirectory()) {
      const names = io.readdirSync(candidate).sort();
      for (const name of names) {
        if (!name || name === "." || name === ".." || name.includes("/")
          || name.includes("\\") || name.includes("\0")) {
          fail("helper artifact normalization entry name is invalid");
        }
        normalize(path.join(candidate, name), depth + 1);
      }
      if (!sameCanonical(io.readdirSync(candidate).sort(), names)) {
        fail("helper artifact directory changed during permission normalization");
      }
      io.chmodSync(candidate, 0o700);
      fsyncDirectory(candidate, io);
      const after = io.lstatSync(candidate);
      if (!after.isDirectory() || after.isSymbolicLink()
        || after.uid !== policy.expectedUid
        || after.gid !== policy.expectedGid
        || (after.mode & 0o7777) !== 0o700) {
        fail("helper artifact directory normalization did not converge");
      }
      return;
    }
    if (!before.isFile() || before.nlink !== 1
      || !Number.isSafeInteger(before.size)
      || before.size < 0 || before.size > MAX_TERMINAL_ARTIFACT_BYTES) {
      fail("helper artifact normalization found an unsupported leaf");
    }
    const beforeIdentity = statIdentity(before);
    let descriptor;
    try {
      descriptor = io.openSync(
        candidate,
        fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
      );
      const opened = io.fstatSync(descriptor);
      if (!sameIdentity(beforeIdentity, statIdentity(opened))) {
        fail("helper artifact identity changed before permission normalization");
      }
      io.fchmodSync(descriptor, 0o400);
      io.fsyncSync(descriptor);
      const after = io.fstatSync(descriptor);
      if (!after.isFile() || after.nlink !== 1
        || after.uid !== policy.expectedUid
        || after.gid !== policy.expectedGid
        || (after.mode & 0o7777) !== 0o400
        || after.dev !== opened.dev || after.ino !== opened.ino
        || after.size !== opened.size) {
        fail("helper artifact file normalization did not preserve identity");
      }
    } finally {
      if (descriptor !== undefined) io.closeSync(descriptor);
    }
  };
  normalize(target, 0);
  fsyncDirectory(path.dirname(target), io);
}

function helperResourceId(authority, profile) {
  const matches = Object.entries(authority.resources.backupResources).filter(
    ([, resource]) => resource.kind === profile.resourceKind
      && (resource.engine ?? resource.externalId) === profile.engine,
  );
  if (matches.length !== 1) {
    fail("helper output resource authority is missing or ambiguous");
  }
  return matches[0][0];
}

function decodeCanonicalHelperJson(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    fail("sealed helper JSON output encoding is invalid");
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < 2 || bytes.length > MAX_TERMINAL_EVIDENCE_BYTES
    || bytes.toString("base64url") !== value) {
    fail("sealed helper JSON output is missing, oversized or non-canonical base64url");
  }
  let output;
  try {
    output = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("sealed helper JSON output is invalid JSON");
  }
  if (!isPlainRecord(output)
    || JSON.stringify(canonicalValue(output)) !== bytes.toString("utf8")) {
    fail("sealed helper JSON output is not one canonical object");
  }
  return output;
}

function verifyManifestCandidate({
  authority,
  backupPolicy,
  io,
  manifestRelativePath,
}) {
  const relativePath = safeRelativePath(
    manifestRelativePath,
    "verified manifest relative path",
  );
  const match = /^requests\/([a-f0-9]{64})\/manifests\/(catalog\.capture|job\.backup\.capture|restore\.capture)\.json$/
    .exec(relativePath);
  if (!match) fail("verified manifest lineage path is invalid");
  const [, producerRequestSha256, producerPhaseId] = match;
  const manifestPath = path.join(backupPolicy.root, ...relativePath.split("/"));
  const bytes = readProtectedFile(manifestPath, {
    expectedGid: backupPolicy.expectedGid,
    expectedMode: 0o400,
    expectedUid: backupPolicy.expectedUid,
    maximumBytes: MAX_MANIFEST_BYTES,
    parentRoot: backupPolicy.root,
  }, { io });
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("verified manifest is invalid JSON");
  }
  if (`${JSON.stringify(canonicalValue(manifest))}\n` !== bytes.toString("utf8")) {
    fail("verified manifest is not canonical JSON");
  }
  exactKeys(manifest, [
    "artifacts",
    "coverage",
    "createdAt",
    "id",
    "jobId",
    "operation",
    "phaseId",
    "requestSha256",
    "resources",
    "schema",
    "scope",
    "signature",
  ], "verified manifest");
  if (manifest.schema !== "platform.backup-manifest/v1"
    || manifest.requestSha256 !== producerRequestSha256
    || manifest.phaseId !== producerPhaseId
    || manifest.id !== `manifest:${producerRequestSha256}:${producerPhaseId}`
    || !Number.isFinite(Date.parse(String(manifest.createdAt ?? "")))
    || new Date(manifest.createdAt).toISOString() !== manifest.createdAt
    || !["backup", "restore-drill"].includes(manifest.operation)
    || !(manifest.jobId === null || JOB_ID.test(String(manifest.jobId ?? "")))
    || !isPlainRecord(manifest.scope)
    || !sameCanonical(manifest.scope, { id: "platform", kind: "platform" })
    || !Array.isArray(manifest.resources)
    || !Array.isArray(manifest.artifacts)
    || !isPlainRecord(manifest.coverage)
    || !isPlainRecord(manifest.signature)) {
    fail("verified manifest request, phase or metadata identity is invalid");
  }
  const signing = loadAuthoritySecretKey(authority, "manifest.verification", io);
  exactKeys(manifest.signature, ["algorithm", "digest", "keyId", "value"], "verified manifest signature");
  const manifestDigest = backupDocumentDigest(manifest);
  if (manifest.signature.algorithm !== "HMAC-SHA256"
    || manifest.signature.keyId !== MANIFEST_KEY_ID
    || manifest.signature.digest !== manifestDigest
    || !constantTextEqual(
      manifest.signature.value,
      hmacBase64Url(
        signing.key,
        `platform-backup-manifest-v1\n${manifest.id}\n${manifestDigest}\n`,
      ),
    )) {
    fail("verified manifest HMAC authentication failed");
  }
  const resources = {};
  for (const resource of manifest.resources) {
    if (!isPlainRecord(resource)) fail("verified manifest resource is invalid");
    const resourceId = exactText(resource.id, "verified manifest resource ID");
    if (Object.hasOwn(resources, resourceId)) {
      fail("verified manifest resource identity is duplicated");
    }
    backupResourceDomain(resource);
    resources[resourceId] = structuredClone(resource);
  }
  const admittedResourceIds = Object.keys(authority.resources.backupResources).sort();
  if (admittedResourceIds.length > 0) {
    if (!sameCanonical(Object.keys(resources).sort(), admittedResourceIds)) {
      fail("verified manifest resource coverage exceeds claimed authority");
    }
    for (const resourceId of admittedResourceIds) {
      const { id: ignored, ...candidate } = resources[resourceId];
      if (!sameCanonical(candidate, authority.resources.backupResources[resourceId])) {
        fail("verified manifest resource identity differs from claimed authority");
      }
    }
  }
  const resourceIds = Object.keys(resources).sort();
  exactKeys(manifest.coverage, [
    "artifactResourceIds",
    "complete",
    "missingResourceIds",
    "requiredResourceIds",
  ], "verified manifest coverage");
  if (manifest.coverage.complete !== true
    || !sameCanonical(manifest.coverage.requiredResourceIds, resourceIds)
    || !sameCanonical(manifest.coverage.artifactResourceIds, resourceIds)
    || !sameCanonical(manifest.coverage.missingResourceIds, [])) {
    fail("verified manifest coverage is incomplete");
  }
  const artifacts = {};
  for (const artifact of manifest.artifacts) {
    if (!isPlainRecord(artifact)) fail("verified manifest artifact is invalid");
    exactKeys(artifact, [
      "id",
      "path",
      "resourceId",
      "sha256",
      "signatureKeyId",
      "sizeBytes",
    ], "verified manifest artifact");
    const resource = resources[artifact.resourceId];
    const artifactRelativePath = safeRelativePath(
      artifact.path,
      "verified manifest artifact path",
    );
    if (!resource
      || artifact.id !== `artifact:${artifact.resourceId}`
      || artifact.signatureKeyId !== MANIFEST_KEY_ID
      || !SHA256.test(String(artifact.sha256 ?? ""))
      || !Number.isSafeInteger(artifact.sizeBytes)
      || artifact.sizeBytes < 0
      || artifact.sizeBytes > MAX_TERMINAL_ARTIFACT_BYTES
      || !artifactRelativePath.startsWith(
        `requests/${producerRequestSha256}/artifacts/`,
      )
      || Object.hasOwn(artifacts, artifact.resourceId)) {
      fail("verified manifest artifact identity or digest is invalid");
    }
    const artifactPath = path.join(
      backupPolicy.root,
      ...artifactRelativePath.split("/"),
    );
    const observed = readProtectedArtifactIdentity(artifactPath, {
      expectedGid: backupPolicy.expectedGid,
      expectedSize: artifact.sizeBytes,
      expectedUid: backupPolicy.expectedUid,
      parentRoot: backupPolicy.root,
    }, io);
    if (observed.sha256 !== artifact.sha256
      || observed.sizeBytes !== artifact.sizeBytes) {
      fail("verified manifest artifact bytes differ from its digest");
    }
    const sidecarPath = `${artifactPath}.sig.json`;
    const sidecarBytes = readProtectedFile(sidecarPath, {
      expectedGid: backupPolicy.expectedGid,
      expectedMode: 0o400,
      expectedUid: backupPolicy.expectedUid,
      maximumBytes: MAX_TERMINAL_EVIDENCE_BYTES,
      parentRoot: backupPolicy.root,
    }, { io });
    let sidecar;
    try {
      sidecar = JSON.parse(sidecarBytes.toString("utf8"));
    } catch {
      fail("verified manifest artifact sidecar is invalid JSON");
    }
    if (`${JSON.stringify(canonicalValue(sidecar))}\n` !== sidecarBytes.toString("utf8")) {
      fail("verified manifest artifact sidecar is not canonical JSON");
    }
    exactKeys(sidecar, [
      "algorithm",
      "artifact",
      "keyId",
      "sha256",
      "signature",
      "version",
    ], "verified manifest artifact sidecar");
    const expectedSidecarMac = hmacBase64Url(
      signing.key,
      `platform-${backupResourceDomain(resource)}-backup-v1\n${path.basename(artifactRelativePath)}\n${artifact.sha256}\n`,
    );
    if (sidecar.algorithm !== "HMAC-SHA256"
      || sidecar.artifact !== path.basename(artifactRelativePath)
      || sidecar.keyId !== MANIFEST_KEY_ID
      || sidecar.sha256 !== artifact.sha256
      || sidecar.signature !== expectedSidecarMac
      || sidecar.version !== 1) {
      fail("verified manifest artifact sidecar authentication failed");
    }
    artifacts[artifact.resourceId] = {
      relativePath: artifactRelativePath,
      resourceId: artifact.resourceId,
      sha256: artifact.sha256,
    };
  }
  if (!sameCanonical(Object.keys(artifacts).sort(), resourceIds)) {
    fail("verified manifest artifact coverage is incomplete");
  }
  return deepFreeze({
    artifactSetSha256: sha256(JSON.stringify(canonicalValue(artifacts))),
    artifacts,
    authoritySha256: signing.authoritySha256,
    createdAt: manifest.createdAt,
    manifestRelativePath: relativePath,
    manifestSha256: sha256(bytes),
    producerPhaseId,
    producerRequestSha256,
    resourceIds,
  });
}

function materializeVerifiedManifestBinding({
  authority,
  candidate,
  context,
  io,
  reportPolicy,
  requestSha256,
}) {
  const evidenceDirectory = path.join(reportPolicy.root, "worker-evidence");
  ensurePrivateDirectory(evidenceDirectory, reportPolicy, io);
  const evidencePath = path.join(
    evidenceDirectory,
    `${context.requestId}-${context.phaseId}-resolver.json`,
  );
  const evidence = {
    action: context.action,
    artifactSetSha256: candidate.artifactSetSha256,
    authoritySha256: candidate.authoritySha256,
    manifestRelativePath: candidate.manifestRelativePath,
    manifestSha256: candidate.manifestSha256,
    phaseId: context.phaseId,
    requestId: context.requestId,
    requestSha256,
    schema: "platform.docker-worker.manifest-verification/v1",
    status: "passed",
  };
  writeCanonicalPrivateJson(evidencePath, evidence, io);
  fsyncDirectory(evidenceDirectory, io);
  const evidenceBytes = readProtectedFile(evidencePath, {
    expectedGid: reportPolicy.expectedGid,
    expectedMode: 0o400,
    expectedUid: reportPolicy.expectedUid,
    maximumBytes: MAX_TERMINAL_EVIDENCE_BYTES,
    parentRoot: reportPolicy.root,
  }, { io });
  return normalizeArtifactBinding({
    artifactSetSha256: candidate.artifactSetSha256,
    artifacts: candidate.artifacts,
    consumerRequestSha256: requestSha256,
    manifestRelativePath: candidate.manifestRelativePath,
    manifestSha256: candidate.manifestSha256,
    producerPhaseId: candidate.producerPhaseId,
    producerRequestSha256: candidate.producerRequestSha256,
    schema: "platform.docker-action.artifact-binding/v1",
    verification: {
      authoritySha256: candidate.authoritySha256,
      evidenceSha256: sha256(evidenceBytes),
      kind: "verified-manifest",
      source: candidate.manifestRelativePath,
    },
  }, {
    consumerRequestSha256: requestSha256,
    resourceIds: candidate.resourceIds,
    verificationKind: "verified-manifest",
  });
}

function writableArtifactRoots(authority, io) {
  const roots = [];
  for (const [mountId, mount] of Object.entries(authority.resources.mounts)) {
    if (mount.access !== "rw") continue;
    roots.push(validateNamedMountAuthority({
      access: "rw",
      authority,
      io,
      mountId,
    }));
  }
  const reportMount = authority.resources.mounts["report.root.rw"];
  for (const volumeId of authority.phaseProfile.scratchVolumeIds) {
    const volume = authority.resources.volumes[volumeId];
    const root = canonicalDirectory(volume?.containerPath, io);
    const stat = io.lstatSync(root);
    if (stat.uid !== reportMount.ownerUid
      || stat.gid !== reportMount.ownerGid
      || (stat.mode & 0o7777) !== 0o700) {
      fail("scratch artifact root owner or mode is invalid");
    }
    roots.push({
      expectedGid: stat.gid,
      expectedUid: stat.uid,
      root,
    });
  }
  return roots.sort((left, right) => right.root.length - left.root.length);
}

function readProtectedArtifactIdentity(file, policy, io) {
  assertProtectedAncestors(
    path.dirname(file),
    policy.parentRoot,
    { expectedGid: policy.expectedGid, expectedUid: policy.expectedUid },
    io,
  );
  const before = io.lstatSync(file);
  if (before.isDirectory() && !before.isSymbolicLink()) {
    if (before.uid !== policy.expectedUid
      || before.gid !== policy.expectedGid
      || (before.mode & 0o7777) !== 0o700) {
      fail("helper tree artifact root owner or mode is invalid");
    }
    const first = protectedTreeArtifactIdentity(file, policy, io);
    const second = protectedTreeArtifactIdentity(file, policy, io);
    if (!sameCanonical(first, second)
      || (policy.expectedSize !== undefined
        && first.sizeBytes !== policy.expectedSize)) {
      fail("helper tree artifact changed during double traversal");
    }
    return first;
  }
  assertProtectedLeaf(before, {
    expectedGid: policy.expectedGid,
    expectedMode: 0o400,
    expectedUid: policy.expectedUid,
    maximumBytes: MAX_TERMINAL_ARTIFACT_BYTES,
    minimumBytes: 0,
  });
  if (policy.expectedSize !== undefined && before.size !== policy.expectedSize) {
    fail("helper artifact byte size does not match its evidence");
  }
  const beforeIdentity = statIdentity(before);
  let descriptor;
  try {
    descriptor = io.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = io.fstatSync(descriptor);
    assertProtectedLeaf(opened, {
      expectedGid: policy.expectedGid,
      expectedMode: 0o400,
      expectedUid: policy.expectedUid,
      maximumBytes: MAX_TERMINAL_ARTIFACT_BYTES,
      minimumBytes: 0,
    });
    if ((policy.expectedSize !== undefined && opened.size !== policy.expectedSize)
      || !sameIdentity(beforeIdentity, statIdentity(opened))) {
      fail("helper artifact descriptor identity or size changed before hashing");
    }
    const first = hashDescriptorPass(io, descriptor, opened.size);
    const second = hashDescriptorPass(io, descriptor, opened.size);
    const after = io.fstatSync(descriptor);
    if (first !== second
      || !sameIdentity(statIdentity(opened), statIdentity(after))) {
      fail("helper artifact changed during descriptor-stable hashing");
    }
    return { sha256: first, sizeBytes: opened.size };
  } finally {
    if (descriptor !== undefined) io.closeSync(descriptor);
  }
}

function protectedTreeArtifactIdentity(root, policy, io) {
  const entries = [];
  let totalSizeBytes = 0;
  const walk = (directory, relativeDirectory, depth) => {
    if (depth > MAX_NATIVE_TREE_DEPTH) fail("helper tree artifact depth is oversized");
    const before = io.lstatSync(directory);
    if (!before.isDirectory() || before.isSymbolicLink()
      || before.uid !== policy.expectedUid
      || before.gid !== policy.expectedGid
      || (before.mode & 0o7777) !== 0o700) {
      fail("helper tree artifact contains an unsafe directory");
    }
    const identity = statIdentity(before);
    const names = io.readdirSync(directory).sort();
    for (const name of names) {
      if (!name || name === "." || name === ".." || name.includes("/")
        || name.includes("\\") || name.includes("\0")) {
        fail("helper tree artifact entry name is invalid");
      }
      const relativePath = relativeDirectory
        ? `${relativeDirectory}/${name}`
        : name;
      safeRelativePath(relativePath, "helper tree artifact entry path");
      const candidate = path.join(directory, name);
      const stat = io.lstatSync(candidate);
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        walk(candidate, relativePath, depth + 1);
      } else {
        assertProtectedLeaf(stat, {
          expectedGid: policy.expectedGid,
          expectedMode: 0o400,
          expectedUid: policy.expectedUid,
          maximumBytes: MAX_TERMINAL_ARTIFACT_BYTES,
          minimumBytes: 0,
        });
        const fileIdentity = readProtectedArtifactIdentity(candidate, {
          ...policy,
          expectedSize: stat.size,
        }, io);
        totalSizeBytes += fileIdentity.sizeBytes;
        if (!Number.isSafeInteger(totalSizeBytes)
          || totalSizeBytes > MAX_TERMINAL_ARTIFACT_BYTES) {
          fail("helper tree artifact total size is oversized");
        }
        entries.push({
          path: relativePath,
          sha256: fileIdentity.sha256,
          sizeBytes: fileIdentity.sizeBytes,
        });
        if (entries.length > MAX_NATIVE_TREE_ENTRIES) {
          fail("helper tree artifact entry count is oversized");
        }
      }
    }
    if (!sameIdentity(identity, statIdentity(io.lstatSync(directory)))) {
      fail("helper tree artifact directory changed during traversal");
    }
  };
  walk(root, "", 0);
  return {
    sha256: sha256(JSON.stringify(canonicalValue(entries))),
    sizeBytes: totalSizeBytes,
  };
}

function hashDescriptorPass(io, descriptor, size) {
  const hash = crypto.createHash("sha256");
  const chunk = Buffer.alloc(Math.min(ARTIFACT_HASH_CHUNK_BYTES, size));
  let position = 0;
  while (position < size) {
    const length = Math.min(chunk.length, size - position);
    const count = io.readSync(descriptor, chunk, 0, length, position);
    if (!Number.isSafeInteger(count) || count <= 0 || count > length) {
      fail("helper artifact descriptor hash made no bounded progress");
    }
    hash.update(chunk.subarray(0, count));
    position += count;
  }
  return hash.digest("hex");
}

function terminalEvidencePath(reportRoot, context) {
  return path.join(
    reportRoot,
    "worker-evidence",
    `${context.requestId}-${context.phaseId}.json`,
  );
}

function backupPrunePlan({ authority, backupRoot, io }) {
  const backupPolicy = validateBackupMountAuthority({
    access: "ro",
    authority,
    io,
    root: backupRoot,
  });
  const manifests = backupManifestInventory(backupPolicy, io);
  return prunePlanFromInventory(manifests);
}

function backupManifestInventory(backupPolicy, io) {
  const manifestRoot = canonicalDirectory(path.join(backupPolicy.root, "manifests"), io);
  const names = io.readdirSync(manifestRoot).sort();
  if (names.length > MAX_MANIFESTS) fail("manifest inventory is oversized");
  const manifests = [];
  for (const name of names) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}\.json$/.test(name)
      || name.includes("..")) {
      fail("manifest filename is invalid");
    }
    const file = path.join(manifestRoot, name);
    const stat = io.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink()
      || stat.size < 2 || stat.size > MAX_MANIFEST_BYTES) {
      fail("manifest file is unsafe");
    }
    let document;
    let bytes;
    try {
      bytes = readProtectedFile(file, {
        expectedGid: backupPolicy.expectedGid,
        expectedMode: 0o400,
        expectedUid: backupPolicy.expectedUid,
        maximumBytes: MAX_MANIFEST_BYTES,
        parentRoot: backupPolicy.root,
      }, { io });
      document = JSON.parse(bytes.toString("utf8"));
    } catch {
      fail("manifest structure is not admitted");
    }
    if (document?.schema !== "platform.backup-manifest/v1"
      || document?.coverage?.complete !== true
      || !/^[a-z0-9](?:[a-z0-9._:-]{0,158}[a-z0-9])?$/.test(
        String(document.id ?? ""),
      )
      || !Number.isFinite(Date.parse(String(document.createdAt ?? "")))
      || document?.scope?.kind !== "platform"
      || document?.scope?.id !== "platform"
      || document?.signature?.algorithm !== "HMAC-SHA256"
      || !SHA256.test(String(document?.signature?.digest ?? ""))
      || !BASE64URL_SHA256.test(String(document?.signature?.value ?? ""))) {
      fail("manifest structure is not admitted");
    }
    manifests.push({
      createdAt: document.createdAt,
      file,
      fileName: name,
      id: document.id,
      sha256: sha256(bytes),
    });
  }
  manifests.sort(
    (left, right) => right.createdAt.localeCompare(left.createdAt)
      || left.id.localeCompare(right.id),
  );
  return manifests;
}

function prunePlanFromInventory(manifests) {
  return {
    schema: "platform.backup-prune-plan/v1",
    mode: "plan",
    keepCompleteManifests: KEEP_COMPLETE_MANIFESTS,
    completeManifestCount: manifests.length,
    retainedManifestIds: manifests
      .slice(0, KEEP_COMPLETE_MANIFESTS)
      .map(({ id }) => id),
    expiredManifestIds: manifests
      .slice(KEEP_COMPLETE_MANIFESTS)
      .map(({ id }) => id),
    mutationPerformed: false,
  };
}

function backupPruneApply({
  authority,
  backupRoot,
  context,
  io,
  reportRoot,
}) {
  const backupPolicy = validateBackupMountAuthority({
    access: "rw",
    authority,
    io,
    root: backupRoot,
  });
  const reportPolicy = validateNamedMountAuthority({
    access: "rw",
    authority,
    io,
    mountId: "report.root.rw",
    root: reportRoot,
  });
  const writable = authority.resources.writableSubpaths["backup.quarantine"];
  const backupMountId = Object.keys(authority.resources.mounts).find(
    (mountId) => authority.resources.mounts[mountId].containerPath
      === backupPolicy.root,
  );
  if (!isPlainRecord(writable)
    || writable.mountId !== backupMountId
    || writable.relativePath !== ".quarantine"
    || String(writable.device) !== String(
      authority.resources.mounts[backupMountId].device,
    )) {
    fail("retention quarantine authority is invalid");
  }
  const manifests = backupManifestInventory(backupPolicy, io);
  const expired = manifests.slice(KEEP_COMPLETE_MANIFESTS);
  if (expired.length < 1) {
    fail("retention apply has no expired manifest to mutate");
  }
  const evidenceDirectory = path.join(reportPolicy.root, "worker-evidence");
  ensurePrivateDirectory(evidenceDirectory, reportPolicy, io);
  const mutationReceiptPath = path.join(
    evidenceDirectory,
    `${context.requestId}-${context.phaseId}-mutation.json`,
  );
  const evidencePath = terminalEvidencePath(reportPolicy.root, context);
  const pendingEvidencePath = `${evidencePath}.pending`;
  if ([mutationReceiptPath, evidencePath, pendingEvidencePath].some(
    (candidate) => io.existsSync(candidate),
  )) {
    fail("retention evidence path already exists for this request");
  }
  const quarantineRoot = path.join(backupPolicy.root, writable.relativePath);
  ensurePrivateDirectory(quarantineRoot, backupPolicy, io);
  const transactionRoot = path.join(quarantineRoot, context.requestId);
  io.mkdirSync(transactionRoot, { mode: 0o700 });
  const moved = [];
  try {
    for (const manifest of expired) {
      const destination = path.join(transactionRoot, manifest.fileName);
      io.renameSync(manifest.file, destination);
      moved.push({ ...manifest, destination });
    }
    fsyncDirectory(path.join(backupPolicy.root, "manifests"), io);
    fsyncDirectory(transactionRoot, io);
  } catch (error) {
    for (const manifest of [...moved].reverse()) {
      try {
        io.renameSync(manifest.destination, manifest.file);
      } catch {
        // Preserve the first causal filesystem error and leave recoverable bytes.
      }
    }
    throw error;
  }
  const mutationReceipt = {
    action: context.action,
    manifestCount: moved.length,
    manifests: moved.map(({ id, sha256: digest }) => ({ id, sha256: digest })),
    phaseId: context.phaseId,
    requestId: context.requestId,
    schema: "platform.backup-prune-mutation/v1",
    status: "quarantined",
  };
  writeCanonicalPrivateJson(mutationReceiptPath, mutationReceipt, io);
  const receiptBytes = readProtectedFile(mutationReceiptPath, {
    expectedGid: reportPolicy.expectedGid,
    expectedMode: 0o400,
    expectedUid: reportPolicy.expectedUid,
    maximumBytes: MAX_TERMINAL_EVIDENCE_BYTES,
    parentRoot: reportPolicy.root,
  }, { io });
  const evidence = {
    action: context.action,
    artifacts: [{
      backupResourceId: null,
      path: mutationReceiptPath,
      producerHelperProfileId: null,
      sha256: sha256(receiptBytes),
      sizeBytes: receiptBytes.length,
    }],
    command: "backup-prune-apply",
    helperResults: [],
    job: null,
    mutationPerformed: true,
    phaseId: context.phaseId,
    repositoryOffsite: null,
    requestId: context.requestId,
    schema: "platform.docker-helper-evidence/v1",
    status: "passed",
  };
  writeCanonicalPrivateJson(pendingEvidencePath, evidence, io);
  for (const manifest of moved) io.unlinkSync(manifest.destination);
  fsyncDirectory(transactionRoot, io);
  io.rmdirSync(transactionRoot);
  fsyncDirectory(quarantineRoot, io);
  io.renameSync(pendingEvidencePath, evidencePath);
  fsyncDirectory(evidenceDirectory, io);
  const evidenceBytes = readProtectedFile(evidencePath, {
    expectedGid: reportPolicy.expectedGid,
    expectedMode: 0o400,
    expectedUid: reportPolicy.expectedUid,
    maximumBytes: MAX_TERMINAL_EVIDENCE_BYTES,
    parentRoot: reportPolicy.root,
  }, { io });
  return {
    evidenceSha256: sha256(evidenceBytes),
    mutationPerformed: true,
    schema: authority.phaseProfile.outputSchema,
    status: "passed",
  };
}

function validateBackupMountAuthority({ access, authority, io, root }) {
  const matches = Object.entries(authority.resources.mounts).filter(
    ([mountId, mount]) => mountId.startsWith("backup.root.")
      && mount.access === access,
  );
  if (matches.length !== 1) fail("backup mount authority is missing or ambiguous");
  return validateNamedMountAuthority({
    access,
    authority,
    io,
    mountId: matches[0][0],
    root,
  });
}

function validateNamedMountAuthority({ access, authority, io, mountId, root }) {
  const mount = authority.resources.mounts[mountId];
  if (!isPlainRecord(mount)) fail(`mount authority ${mountId} is missing`);
  exactKeys(mount, [
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
  ], `mount authority ${mountId}`);
  const admittedRoot = path.resolve(exactText(
    mount.containerPath,
    `mount authority ${mountId} container path`,
  ));
  const requestedRoot = root === undefined
    ? admittedRoot
    : path.resolve(exactText(root, `mount authority ${mountId} requested root`));
  if (requestedRoot !== admittedRoot
    || mount.access !== access
    || mount.kind !== "host-directory"
    || mount.symlinkFree !== true
    || !Number.isSafeInteger(mount.ownerUid)
    || mount.ownerUid < 0
    || !Number.isSafeInteger(mount.ownerGid)
    || mount.ownerGid < 0
    || !Number.isSafeInteger(mount.mode)
    || (mount.mode & 0o022) !== 0) {
    fail(`mount authority ${mountId} canonical identity is invalid`);
  }
  const canonicalRoot = canonicalDirectory(requestedRoot, io);
  const stat = io.lstatSync(canonicalRoot);
  if (stat.uid !== mount.ownerUid
    || stat.gid !== mount.ownerGid
    || String(stat.dev) !== String(mount.device)
    || String(stat.ino) !== String(mount.inode)
    || (stat.mode & 0o7777) !== mount.mode) {
    fail(`live mount ${mountId} does not match its root-owned attestation`);
  }
  return {
    expectedGid: mount.ownerGid,
    expectedUid: mount.ownerUid,
    mountId,
    root: canonicalRoot,
  };
}

function ensurePrivateDirectory(directory, policy, io) {
  if (!io.existsSync(directory)) io.mkdirSync(directory, { mode: 0o700 });
  const stat = io.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()
    || stat.uid !== policy.expectedUid
    || stat.gid !== policy.expectedGid
    || (stat.mode & 0o7777) !== 0o700) {
    fail("private evidence directory identity, owner or mode is invalid");
  }
}

function writeCanonicalPrivateJson(file, document, io) {
  const bytes = Buffer.from(`${JSON.stringify(canonicalValue(document))}\n`);
  if (bytes.length < 2 || bytes.length > MAX_TERMINAL_EVIDENCE_BYTES) {
    fail("private evidence document is oversized");
  }
  let descriptor;
  try {
    descriptor = io.openSync(
      file,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | fs.constants.O_NOFOLLOW,
      0o400,
    );
    let position = 0;
    while (position < bytes.length) {
      const count = io.writeSync(
        descriptor,
        bytes,
        position,
        bytes.length - position,
        position,
      );
      if (!Number.isSafeInteger(count) || count <= 0) {
        fail("private evidence write made no bounded progress");
      }
      position += count;
    }
    io.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) io.closeSync(descriptor);
  }
}

function fsyncDirectory(directory, io) {
  let descriptor;
  try {
    descriptor = io.openSync(directory, fs.constants.O_RDONLY);
    io.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) io.closeSync(descriptor);
  }
}

function defaultClaimedJobPolicy(env) {
  const snapshotPath = exactText(
    env.PLATFORM_CLAIMED_JOB_PATH,
    "claimed-job snapshot path",
  );
  return {
    expectedGid: 0,
    expectedMode: 0o400,
    expectedUid: 0,
    maximumBytes: MAX_CLAIMED_JOB_BYTES,
    parentRoot: path.dirname(snapshotPath),
  };
}

function workerIdentity(env, command) {
  const action = exactText(env.PLATFORM_DOCKER_ACTION, "worker action");
  const phaseId = exactText(env.PLATFORM_DOCKER_PHASE_ID, "worker phase");
  const requestId = exactText(env.PLATFORM_DOCKER_REQUEST_ID, "worker request ID");
  const role = exactText(env.PLATFORM_DOCKER_WORKER_ROLE, "worker role");
  const requestSha256 = executionRequestSha256(env);
  if (!REQUEST_ID.test(requestId)
    || COMMAND_BY_ACTION_PHASE[`${action}\0${phaseId}`] !== command
    || !WORKER_ROLES_BY_PHASE[phaseId]?.includes(role)
    || typeof OUTPUT_SCHEMA_BY_PHASE[phaseId] !== "string") {
    fail("worker action, phase, role, command or request identity is invalid");
  }
  return { action, phaseId, requestId, requestSha256, role };
}

function claimedJobIdentity(env) {
  const jobId = exactText(env.PLATFORM_CLAIMED_JOB_ID, "claimed-job ID");
  const jobFileName = exactText(
    env.PLATFORM_CLAIMED_JOB_FILE_NAME,
    "claimed-job filename",
  );
  const jobOperation = exactText(
    env.PLATFORM_CLAIMED_JOB_OPERATION,
    "claimed-job operation",
  );
  const jobSha256 = exactText(
    env.PLATFORM_CLAIMED_JOB_SHA256,
    "claimed-job SHA256",
  );
  if (!JOB_ID.test(jobId)
    || jobFileName !== `${jobId}.json`
    || path.basename(jobFileName) !== jobFileName
    || !["backup", "restore-drill"].includes(jobOperation)
    || !SHA256.test(jobSha256)
    || env.PLATFORM_CLAIMED_JOB_SOURCE_ID !== "jobs.running") {
    fail("claimed-job filename, operation, source or digest identity is invalid");
  }
  return { jobFileName, jobId, jobOperation, jobSha256 };
}

function validateClaimedJobDocument(document, job) {
  if (!isPlainRecord(document)
    || document.schema !== "platform.backup-job/v1"
    || document.id !== job.jobId
    || document.operation !== job.jobOperation
    || document.status !== "running"
    || !Array.isArray(document.resources)
    || document.resources.length < 1
    || !isPlainRecord(document.scope)
    || typeof document.requestedBy !== "string"
    || !Number.isFinite(Date.parse(String(document.createdAt ?? "")))) {
    fail("claimed-job document identity or metadata is invalid");
  }
}

function rejectUnexpectedClaimedJobEnvironment(env) {
  for (const name of [
    "PLATFORM_CLAIMED_JOB_FILE_NAME",
    "PLATFORM_CLAIMED_JOB_ID",
    "PLATFORM_CLAIMED_JOB_OPERATION",
    "PLATFORM_CLAIMED_JOB_PATH",
    "PLATFORM_CLAIMED_JOB_SHA256",
    "PLATFORM_CLAIMED_JOB_SOURCE_ID",
  ]) {
    if (Object.hasOwn(env, name)) {
      fail("fixed worker command received unsupported claimed-job parameters");
    }
  }
}

function validateJobResultIdentity(job) {
  if (!isPlainRecord(job)) fail("worker job identity is invalid");
  exactKeys(
    job,
    ["jobFileName", "jobId", "jobOperation", "jobSha256"],
    "worker job identity",
  );
  if (!JOB_ID.test(String(job.jobId ?? ""))
    || job.jobFileName !== `${job.jobId}.json`
    || !["backup", "restore-drill"].includes(job.jobOperation)
    || !SHA256.test(String(job.jobSha256 ?? ""))) {
    fail("worker job filename, operation or digest identity is invalid");
  }
}

function validatePhaseOutput(output, phaseId, expectedSchema, job, identity = {}) {
  if (!isPlainRecord(output) || output.schema !== expectedSchema) {
    fail("worker output schema is invalid");
  }
  if (phaseId === "prune.plan") {
    exactKeys(output, [
      "completeManifestCount",
      "expiredManifestIds",
      "keepCompleteManifests",
      "mode",
      "mutationPerformed",
      "retainedManifestIds",
      "schema",
    ], "prune plan worker output");
    if (output.mode !== "plan"
      || output.mutationPerformed !== false
      || !Number.isSafeInteger(output.keepCompleteManifests)
      || output.keepCompleteManifests < 0
      || !Number.isSafeInteger(output.completeManifestCount)
      || output.completeManifestCount < 0
      || !stringArray(output.retainedManifestIds)
      || !stringArray(output.expiredManifestIds)) {
      fail("prune plan worker output fields are invalid");
    }
    return;
  }
  const expectedKeys = [
    "evidenceSha256",
    "mutationPerformed",
    "schema",
    "status",
  ];
  if (CAPTURE_PHASE_IDS.includes(phaseId)) expectedKeys.push("artifactBinding");
  if (phaseId === "job.backup.capture" || phaseId === "job.restore.verify") {
    expectedKeys.push("jobId", "jobOperation");
  }
  if (phaseId === "offsite.sync") expectedKeys.push("repositoryOffsite");
  exactKeys(output, expectedKeys, "worker phase output");
  if (output.status !== "passed"
    || !SHA256.test(String(output.evidenceSha256 ?? ""))
    || output.mutationPerformed !== true) {
    fail("worker output evidence digest/length or status is invalid");
  }
  if (phaseId === "job.backup.capture" || phaseId === "job.restore.verify") {
    if (!job || output.jobId !== job.jobId
      || output.jobOperation !== job.jobOperation) {
      fail("worker output job identity is invalid");
    }
  }
  if (phaseId === "offsite.sync" && output.repositoryOffsite !== true) {
    fail("offsite worker output receipt is invalid");
  }
  if (CAPTURE_PHASE_IDS.includes(phaseId)) {
    const binding = normalizeArtifactBinding(output.artifactBinding, {
      consumerRequestSha256: identity.requestSha256,
      producerPhaseId: phaseId,
      producerRequestSha256: identity.requestSha256,
      verificationKind: "journaled-phase-result",
    });
    if (binding.verification.evidenceSha256 !== output.evidenceSha256) {
      fail("capture output evidence and artifact binding lineage differ");
    }
  }
}

function validateInternalRoleOutput(output, identity, role) {
  if (role === "artifact-resolver") {
    normalizeArtifactBinding(output, {
      consumerRequestSha256: identity.requestSha256,
      verificationKind: "verified-manifest",
    });
    return;
  }
  if (role === "helper-preparer") {
    exactKeys(output, [
      "mutationPerformed",
      "phaseId",
      "preparedRelativePaths",
      "requestSha256",
      "schema",
      "status",
    ], "helper preparation output");
    if (output.schema !== "platform.docker-worker.helper-preparation/v1"
      || output.status !== "completed"
      || output.mutationPerformed !== true
      || output.phaseId !== identity.phaseId
      || output.requestSha256 !== identity.requestSha256
      || !stringArray(output.preparedRelativePaths)
      || !sameCanonical(
        output.preparedRelativePaths,
        [...output.preparedRelativePaths].sort(),
      )) {
      fail("helper preparation output identity is invalid");
    }
    return;
  }
  if (role === "scratch-preparer" || role === "scratch-cleaner") {
    exactKeys(output, [
      "engine",
      "mutationPerformed",
      "phaseId",
      "relativePath",
      "requestSha256",
      "role",
      "schema",
      "status",
    ], "restore scratch output");
    if (output.schema !== "platform.docker-worker.scratch-result/v1"
      || output.status !== "completed"
      || output.mutationPerformed !== true
      || output.role !== role
      || output.phaseId !== identity.phaseId
      || output.requestSha256 !== identity.requestSha256
      || safeRelativePath(output.relativePath, "restore scratch output path")
        !== `requests/${identity.requestSha256}/${identity.phaseId}/${output.engine}`) {
      fail("restore scratch output identity is invalid");
    }
    return;
  }
  fail("worker result internal role output is unsupported");
}

function assertProtectedAncestors(directory, root, expected, io) {
  const relative = path.relative(root, directory);
  if (relative === ".." || relative.startsWith(`..${path.sep}`)
    || path.isAbsolute(relative)) {
    fail("protected file ancestor escaped its root");
  }
  const cursors = [root];
  if (relative && relative !== ".") {
    let cursor = root;
    for (const component of relative.split(path.sep)) {
      if (!component || component === "." || component === "..") {
        fail("protected file ancestor path is invalid");
      }
      cursor = path.join(cursor, component);
      cursors.push(cursor);
    }
  }
  for (const cursor of cursors) {
    const stat = io.lstatSync(cursor);
    if (!stat.isDirectory() || stat.isSymbolicLink()
      || stat.uid !== expected.expectedUid
      || stat.gid !== expected.expectedGid
      || (stat.mode & 0o777) !== 0o700) {
      fail("protected file ancestor directory identity, owner or mode is invalid");
    }
  }
}

function assertProtectedLeaf(stat, expected) {
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail("protected leaf is not a regular non-symlink file");
  }
  if (stat.uid !== expected.expectedUid) fail("protected leaf owner UID is invalid");
  if (stat.gid !== expected.expectedGid) fail("protected leaf group GID is invalid");
  if ((stat.mode & 0o777) !== expected.expectedMode) {
    fail("protected leaf permission mode is invalid");
  }
  if (stat.nlink !== 1) fail("protected leaf hardlink count is invalid");
  const minimumBytes = expected.minimumBytes ?? 1;
  if (!Number.isSafeInteger(stat.size)
    || stat.size < minimumBytes
    || stat.size > expected.maximumBytes) {
    fail("protected leaf byte size exceeds its maximum");
  }
}

function readDescriptorPass(io, descriptor, size) {
  const result = Buffer.alloc(size);
  let position = 0;
  while (position < size) {
    const count = io.readSync(
      descriptor,
      result,
      position,
      size - position,
      position,
    );
    if (!Number.isSafeInteger(count) || count <= 0 || count > size - position) {
      fail("protected descriptor read made no bounded progress");
    }
    position += count;
  }
  return result;
}

function statIdentity(stat) {
  return {
    ctimeMs: stat.ctimeMs,
    dev: stat.dev,
    gid: stat.gid,
    ino: stat.ino,
    isFile: stat.isFile(),
    mode: stat.mode,
    mtimeMs: stat.mtimeMs,
    nlink: stat.nlink,
    size: stat.size,
    uid: stat.uid,
  };
}

function sameIdentity(left, right) {
  return Object.keys(left).every((field) => Object.is(left[field], right[field]));
}

function normalizeUnsignedPrunePlan(value) {
  if (!isPlainRecord(value)) fail("exact prune plan schema requires a plain object");
  exactKeys(
    value,
    ["artifactCount", "artifactSetSha256", "candidatePaths", "planId", "schema"],
    "exact prune plan schema",
  );
  if (value.schema !== "platform.backup-prune-sealed-plan/v1"
    || typeof value.planId !== "string"
    || value.planId.length < 1
    || value.planId.length > 160
    || !Number.isSafeInteger(value.artifactCount)
    || value.artifactCount < 0
    || !SHA256.test(String(value.artifactSetSha256 ?? ""))
    || !Array.isArray(value.candidatePaths)
    || value.candidatePaths.length !== value.artifactCount) {
    fail("exact prune plan schema identity or field is invalid");
  }
  const candidatePaths = value.candidatePaths.map(
    (entry) => safeRelativePath(entry, "prune candidate path"),
  );
  if (new Set(candidatePaths).size !== candidatePaths.length) {
    fail("prune candidate path is duplicated");
  }
  return {
    artifactCount: value.artifactCount,
    artifactSetSha256: value.artifactSetSha256,
    candidatePaths,
    planId: value.planId,
    schema: value.schema,
  };
}

function verifySealedPrunePlan(value, keys) {
  if (!isPlainRecord(value)) fail("sealed prune plan is missing");
  exactKeys(
    value,
    ["artifactCount", "artifactSetSha256", "candidatePaths", "planId", "schema", "seal"],
    "sealed prune plan",
  );
  const unsigned = normalizeUnsignedPrunePlan(
    Object.fromEntries(Object.entries(value).filter(([key]) => key !== "seal")),
  );
  if (!isPlainRecord(value.seal)) fail("prune authenticated seal is invalid");
  exactKeys(value.seal, ["algorithm", "digest", "keyId", "value"], "prune authenticated seal");
  const key = keys[value.seal.keyId];
  const digest = prunePlanDigest(unsigned);
  if (value.seal.algorithm !== "HMAC-SHA256"
    || !Buffer.isBuffer(key)
    || value.seal.digest !== digest
    || value.seal.value !== prunePlanMac(
      unsigned,
      value.seal.keyId,
      key,
      digest,
    )) {
    fail("prune authenticated HMAC seal, key or digest is invalid");
  }
  return { ...unsigned, seal: structuredClone(value.seal) };
}

function prunePlanDigest(plan) {
  return sha256(
    `${PRUNE_PLAN_DIGEST_DOMAIN}${JSON.stringify(canonicalValue(plan))}`,
  );
}

function prunePlanMac(plan, keyId, key, digest = prunePlanDigest(plan)) {
  return hmacBase64Url(
    key,
    `${PRUNE_PLAN_MAC_DOMAIN}${keyId}\0${plan.planId}\0${digest}\0`,
  );
}

function backupDocumentDigest(document) {
  return sha256(JSON.stringify(canonicalBackupValue(document)));
}

function canonicalBackupValue(value) {
  if (Array.isArray(value)) return value.map(canonicalBackupValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .filter((key) => key !== "signature")
        .sort()
        .map((key) => [key, canonicalBackupValue(value[key])]),
    );
  }
  return value;
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])]),
    );
  }
  return value;
}

function commandDefinition(command) {
  if (typeof command !== "string" || !Object.hasOwn(COMMANDS, command)) {
    fail("unsupported fixed worker command");
  }
  return COMMANDS[command];
}

function exactKeys(value, expected, label) {
  if (!isPlainRecord(value)
    || !sameCanonical(Object.keys(value).sort(), [...expected].sort())) {
    fail(`${label} contains an unsupported field or schema`);
  }
}

function exactInteger(value, label, minimum) {
  if (!Number.isSafeInteger(value) || value < minimum) fail(`${label} is invalid`);
  return value;
}

function exactMode(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0o7777) {
    fail(`${label} is invalid`);
  }
  return value;
}

function exactText(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.includes("\0")) {
    fail(`${label} is invalid`);
  }
  return value;
}

function exactStringArray(value, label) {
  if (!Array.isArray(value)
    || value.some((entry) => typeof entry !== "string"
      || entry.length < 1 || entry.includes("\0"))
    || new Set(value).size !== value.length) {
    fail(`${label} is invalid or contains duplicate identities`);
  }
  return value;
}

function nullableText(value) {
  return value === null
    || (typeof value === "string" && value.length > 0 && !value.includes("\0"));
}

function safeRelativePath(value, label) {
  const text = exactText(value, label).replaceAll("\\", "/");
  if (text.startsWith("/") || text.length > 512
    || text.split("/").some((component) => !component
      || component === "." || component === "..")) {
    fail(`${label} is invalid`);
  }
  return text;
}

function canonicalDirectory(directory, io) {
  const resolved = path.resolve(directory);
  const stat = io.lstatSync(resolved);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    fail("backup directory is unsafe");
  }
  return resolved;
}

function stringArray(value) {
  return Array.isArray(value)
    && value.every((entry) => typeof entry === "string" && entry.length > 0)
    && new Set(value).size === value.length;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function hmacBase64Url(key, value) {
  return crypto.createHmac("sha256", key).update(value).digest("base64url");
}

function constantTextEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length
    && crypto.timingSafeEqual(leftBytes, rightBytes);
}

function sameCanonical(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function isPlainRecord(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

function fail(message) {
  throw new Error(message);
}

function realFileIdentity(value) {
  try {
    return fs.realpathSync.native(path.resolve(value));
  } catch {
    return null;
  }
}

const isMain = process.argv[1]
  ? realFileIdentity(process.argv[1]) === realFileIdentity(fileURLToPath(import.meta.url))
  : false;

if (isMain) {
  try {
    await runWorkerCli(process.argv);
  } catch (error) {
    process.stderr.write(`${error?.message ?? error}\n`);
    process.exitCode = 78;
  }
}
