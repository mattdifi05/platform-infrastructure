import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  ACTIONS,
  canonicalJson,
  sha256,
} from "./docker-action-contract.mjs";
import {
  workerCreateBody,
} from "./docker-action-broker.mjs";
import {
  backupDocumentDigest,
} from "../control-center/backup/contracts.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const workerPath = path.join(scriptDir, "docker-action-worker.mjs");
const workerSource = fs.readFileSync(workerPath, "utf8");

// Test-only deterministic key material. These bytes are not deployment secrets.
const MANIFEST_TEST_KEY = Buffer.alloc(48, 0x4d);
const ARTIFACT_TEST_KEY = Buffer.alloc(48, 0x41);
const PRUNE_TEST_KEY = Buffer.alloc(48, 0x50);

const importedWorker = await importWorkerWithoutCliSideEffects();
const worker = importedWorker.namespace;

test("worker module is import-safe and does not execute its CLI during unit tests", () => {
  assert.equal(importedWorker.stderr, "", "importing the worker must not emit CLI stderr");
  assert.equal(importedWorker.exitCode, undefined, "importing the worker must not set a process exit code");
});

test("worker remains socketless and contains no network or Docker API escape hatch", () => {
  assert.doesNotMatch(
    workerSource,
    /from\s+["']node:(?:net|http|https|tls|dgram|dns)(?:\/promises)?["']/,
    "the fixed worker must not import networking modules",
  );
  assert.doesNotMatch(
    workerSource,
    /docker\.sock|DOCKER_HOST|\/v\d+(?:\.\d+)?\/(?:containers|exec|images|networks|volumes)|node:child_process|\bspawn(?:Sync)?\s*\(|\bexec(?:File|Sync)?\s*\(/,
    "the fixed worker must not contain a Docker endpoint, generic Engine path or subprocess escape hatch",
  );
});

test("manifest envelope verification recomputes the canonical digest and domain-separated HMAC", () => {
  requireContract("manifest verifier wiring", [
    ["export verifyManifestEnvelope", typeof worker.verifyManifestEnvelope === "function"],
    ["verification is used by an action path", occurrences(workerSource, "verifyManifestEnvelope") >= 2],
    ["manifest HMAC domain separator", workerSource.includes("platform-backup-manifest-v1\\n")],
  ]);
  const envelope = signedManifestEnvelope();
  const options = manifestVerificationOptions();

  const verified = worker.verifyManifestEnvelope(envelope, options);
  assert.equal(verified.manifestDigest, envelope.manifest.signature.digest);
  assert.equal(verified.artifactCount, 1);

  const digestTamper = structuredClone(envelope);
  digestTamper.manifest.artifacts[0].sha256 = "9".repeat(64);
  assert.throws(
    () => worker.verifyManifestEnvelope(digestTamper, options),
    /digest|manifest|HMAC|signature/i,
    "a structurally valid manifest with stale authentication must fail",
  );

  const signatureTamper = structuredClone(envelope);
  signatureTamper.manifest.signature.value = base64url(Buffer.alloc(32, 0x58));
  assert.throws(
    () => worker.verifyManifestEnvelope(signatureTamper, options),
    /HMAC|signature|authentication/i,
    "a substituted manifest HMAC must fail",
  );

  const keySubstitution = structuredClone(envelope);
  keySubstitution.manifest.signature.keyId = "manifest-test-unknown";
  assert.throws(
    () => worker.verifyManifestEnvelope(keySubstitution, options),
    /key.?id|key|signature/i,
    "an unpinned manifest key ID must fail instead of trying every key",
  );
});

test("manifest artifact admission binds each protected sidecar digest and keyId", () => {
  requireWorkerExports("verifyManifestEnvelope");
  const envelope = signedManifestEnvelope();
  const options = manifestVerificationOptions();

  const digestSubstitution = structuredClone(envelope);
  digestSubstitution.sidecars["postgres/worker-test.dump"].sha256 = "8".repeat(64);
  assert.throws(
    () => worker.verifyManifestEnvelope(digestSubstitution, options),
    /sidecar|sha256|digest|artifact/i,
    "a sidecar digest different from the signed manifest must fail",
  );

  const keyIdSubstitution = structuredClone(envelope);
  keyIdSubstitution.sidecars["postgres/worker-test.dump"].keyId = "artifact-test-unknown";
  assert.throws(
    () => worker.verifyManifestEnvelope(keyIdSubstitution, options),
    /sidecar|key.?id|key|signature/i,
    "a sidecar key ID different from the signed artifact record must fail",
  );

  const missingSidecar = structuredClone(envelope);
  delete missingSidecar.sidecars["postgres/worker-test.dump"];
  assert.throws(
    () => worker.verifyManifestEnvelope(missingSidecar, options),
    /sidecar|missing|artifact/i,
    "a manifest artifact without its signature sidecar must fail",
  );
});

test("protected worker files use open-follow protection and reject hardlinks, mode or owner drift", () => {
  requireContract("protected file API", [
    ["export admitProtectedFileStat", typeof worker.admitProtectedFileStat === "function"],
    ["open by descriptor", /\bfs\.openSync\s*\(|\bopenSync\s*\(/.test(workerSource)],
    ["O_NOFOLLOW", /\bO_NOFOLLOW\b/.test(workerSource)],
    ["post-open fstat", /\bfstatSync\s*\(/.test(workerSource)],
    ["hardlink count admission", /\bnlink\b/.test(workerSource)],
  ]);

  const safe = protectedFileStat();
  assert.doesNotThrow(() => worker.admitProtectedFileStat(safe, protectedFilePolicy()));
  assert.throws(
    () => worker.admitProtectedFileStat(protectedFileStat({ nlink: 2 }), protectedFilePolicy()),
    /hardlink|link/i,
  );
  assert.throws(
    () => worker.admitProtectedFileStat(protectedFileStat({ mode: 0o100640 }), protectedFilePolicy()),
    /mode|permission/i,
  );
  assert.throws(
    () => worker.admitProtectedFileStat(protectedFileStat({ uid: 65532 }), protectedFilePolicy()),
    /owner|uid|root/i,
  );
  assert.throws(
    () => worker.admitProtectedFileStat(protectedFileStat({ gid: 65532 }), protectedFilePolicy()),
    /owner|gid|root/i,
  );
  assert.throws(
    () => worker.admitProtectedFileStat(protectedFileStat({
      isFile: () => false,
      isSymbolicLink: () => true,
    }), protectedFilePolicy()),
    /symlink|regular file|type/i,
  );
});

test("root-owned mode 0700 backup roots are readable by the confined socketless worker", () => {
  const body = workerCreateBody({
    action: "backup.prune.plan",
    command: "backup-prune-plan",
    imageRef: `registry.invalid/platform/docker-action-worker@sha256:${"6".repeat(64)}`,
    hostPath: "/srv/platform/backups",
    intentId: "intent.worker-red-test",
    receiptDigest: "7".repeat(64),
    mountAttestation: {
      access: "ro",
      containerPath: "/data/backups",
      device: 17,
      hostPath: "/srv/platform/backups",
      inode: 29,
      kind: "directory",
      mode: 0o700,
      ownerGid: 0,
      ownerUid: 0,
      symlinkFree: true,
    },
  });

  assert.ok(body.Env.includes(`PLATFORM_BACKUP_ROOT_MODE=${0o700}`));
  assert.deepEqual(body.HostConfig.Binds, ["/srv/platform/backups:/data/backups:ro"]);
  assert.equal(body.HostConfig.ReadonlyRootfs, true);
  assert.equal(body.HostConfig.NetworkMode, "none");
  assert.equal(body.HostConfig.Privileged, false);
  assert.deepEqual(body.HostConfig.CapAdd, []);
  assert.deepEqual(body.HostConfig.CapDrop, ["ALL"]);
  assert.equal(
    body.User,
    "0:0",
    "UID 65532 cannot traverse a genuinely root-owned 0700 backup root; a 0755 fixture would hide this production failure",
  );
});

test("worker stdout normalization is bounded and exposes only artifact counts and digests", () => {
  requireContract("bounded worker result API", [
    ["export normalizeWorkerResult", typeof worker.normalizeWorkerResult === "function"],
    ["export MAX_WORKER_STDOUT_BYTES", Number.isSafeInteger(worker.MAX_WORKER_STDOUT_BYTES)],
    ["normalizer is used by the stdout path", occurrences(workerSource, "normalizeWorkerResult") >= 2],
    ["stdout byte length is checked", /Buffer\.byteLength\s*\([^)]*\)[\s\S]{0,160}MAX_WORKER_STDOUT_BYTES|MAX_WORKER_STDOUT_BYTES[\s\S]{0,160}Buffer\.byteLength\s*\(/.test(workerSource)],
    ["raw manifest ID arrays are absent from stdout construction", !/\b(?:retainedManifestIds|expiredManifestIds)\b/.test(workerSource)],
  ]);
  assert.ok(worker.MAX_WORKER_STDOUT_BYTES >= 512 && worker.MAX_WORKER_STDOUT_BYTES <= 4096);

  const summary = boundedPruneSummary();
  const normalized = worker.normalizeWorkerResult("backup-prune-plan", summary);
  assert.deepEqual(normalized, summary);
  assert.ok(Buffer.byteLength(JSON.stringify(normalized)) <= worker.MAX_WORKER_STDOUT_BYTES);

  for (const detailArray of [
    { retainedManifestIds: ["manifest-retained"] },
    { expiredManifestIds: ["manifest-expired"] },
    { candidateArtifactPaths: ["postgres/worker-test.dump"] },
    { artifacts: [{ path: "postgres/worker-test.dump" }] },
  ]) {
    assert.throws(
      () => worker.normalizeWorkerResult("backup-prune-plan", { ...summary, ...detailArray }),
      /unsupported|detail|array|field|schema/i,
      "stdout must never carry an unbounded detail array",
    );
  }
  assert.throws(
    () => worker.normalizeWorkerResult("backup-prune-plan", {
      ...summary,
      artifactSetSha256: "not-a-digest",
    }),
    /digest|sha256|schema/i,
  );
});

test("fixed action map exposes only named worker commands for apply, restore and offsite", () => {
  const expected = {
    "backup.prune.plan": "backup-prune-plan",
    "backup.prune.apply": "backup-prune-apply",
    "restore.drill.full": "restore-drill-full",
    "backup.offsite.sync": "backup-offsite-sync",
  };
  requireContract("fixed worker action allowlist", Object.entries(expected).flatMap(([action, command]) => [
    [`${action} is modeled`, ACTIONS[action]?.modeled === true],
    [`${action} command is ${command}`, ACTIONS[action]?.workerCommand === command],
  ]));
});

test("prune apply accepts only an exact sealed plan and quarantines before committed deletion", () => {
  requireContract("sealed prune transition wiring", [
    ["export planPruneTransition", typeof worker.planPruneTransition === "function"],
    ["export applyPruneTransition", typeof worker.applyPruneTransition === "function"],
    ["plan transition is used by an action path", occurrences(workerSource, "planPruneTransition") >= 2],
    ["apply transition is used by an action path", occurrences(workerSource, "applyPruneTransition") >= 2],
    ["quarantine uses an atomic rename", /quarantine/i.test(workerSource) && /\b(?:fs\.)?renameSync\s*\(/.test(workerSource)],
  ]);
  const unsignedPlan = {
    schema: "platform.backup-prune-sealed-plan/v1",
    planId: "prune-plan-worker-test",
    artifactCount: 2,
    artifactSetSha256: "a".repeat(64),
    candidatePaths: [
      "postgres/expired-one.dump",
      "manifests/manifest-expired.json",
    ],
  };
  const sealed = worker.planPruneTransition(
    { phase: "empty" },
    { type: "seal", plan: unsignedPlan },
    { keyId: "prune-test-v1", key: PRUNE_TEST_KEY },
  );
  assert.equal(sealed.phase, "sealed");
  assert.equal(sealed.plan.seal.algorithm, "HMAC-SHA256");
  assert.equal(sealed.plan.seal.keyId, "prune-test-v1");
  assert.match(sealed.plan.seal.digest, /^[a-f0-9]{64}$/);
  assert.match(sealed.plan.seal.value, /^[A-Za-z0-9_-]{43}$/);

  assert.throws(
    () => worker.planPruneTransition(
      sealed,
      { type: "seal", plan: { ...unsignedPlan, artifactSetSha256: "b".repeat(64) } },
      { keyId: "prune-test-v1", key: PRUNE_TEST_KEY },
    ),
    /phase|sealed|substitution|transition/i,
  );
  assert.throws(
    () => worker.applyPruneTransition(
      sealed,
      {
        type: "commit-delete",
        planDigest: sealed.plan.seal.digest,
        quarantineDigest: "c".repeat(64),
      },
      { keys: { "prune-test-v1": PRUNE_TEST_KEY } },
    ),
    /quarantine|phase|barrier|transition/i,
    "deletion may not skip the quarantine transition",
  );

  const quarantined = worker.applyPruneTransition(
    sealed,
    {
      type: "quarantine",
      planDigest: sealed.plan.seal.digest,
      quarantineDigest: "c".repeat(64),
      artifactCount: 2,
    },
    { keys: { "prune-test-v1": PRUNE_TEST_KEY } },
  );
  assert.equal(quarantined.phase, "quarantined");
  assert.equal(quarantined.deletionCommitted, false);

  assert.throws(
    () => worker.applyPruneTransition(
      quarantined,
      {
        type: "commit-delete",
        planDigest: "d".repeat(64),
        quarantineDigest: quarantined.quarantineDigest,
      },
      { keys: { "prune-test-v1": PRUNE_TEST_KEY } },
    ),
    /digest|sealed|substitution/i,
  );

  const applied = worker.applyPruneTransition(
    quarantined,
    {
      type: "commit-delete",
      planDigest: sealed.plan.seal.digest,
      quarantineDigest: quarantined.quarantineDigest,
    },
    { keys: { "prune-test-v1": PRUNE_TEST_KEY } },
  );
  assert.equal(applied.phase, "applied");
  assert.equal(applied.deletionCommitted, true);
  assert.throws(
    () => worker.applyPruneTransition(applied, { type: "arbitrary-delete" }, {
      keys: { "prune-test-v1": PRUNE_TEST_KEY },
    }),
    /unsupported|transition|event/i,
  );
});

test("restore state machine enforces prepare-restore-verify-barrier and reverse cleanup", () => {
  requireContract("restore transition wiring", [
    ["export transitionRestorePhase", typeof worker.transitionRestorePhase === "function"],
    ["export reverseCleanupOrder", typeof worker.reverseCleanupOrder === "function"],
    ["restore transition is used by an action path", occurrences(workerSource, "transitionRestorePhase") >= 2],
    ["reverse cleanup is used by an action path", occurrences(workerSource, "reverseCleanupOrder") >= 2],
    ["cleanup is guaranteed by finally", /\bfinally\s*\{/.test(workerSource)],
  ]);
  const cleanupStack = ["postgres", "mariadb", "minio"];
  const created = {
    phase: "created",
    cleanupStack,
    verifiedArtifactSetSha256: "e".repeat(64),
  };

  assert.throws(
    () => worker.transitionRestorePhase(created, { type: "barrier-passed" }),
    /phase|prepare|transition|barrier/i,
  );
  const prepared = worker.transitionRestorePhase(created, { type: "prepare-complete" });
  assert.equal(prepared.phase, "prepared");
  const restored = worker.transitionRestorePhase(prepared, { type: "restore-complete" });
  assert.equal(restored.phase, "restored");
  const verified = worker.transitionRestorePhase(restored, {
    type: "verify-complete",
    restoredArtifactSetSha256: created.verifiedArtifactSetSha256,
  });
  assert.equal(verified.phase, "verified");

  assert.throws(
    () => worker.transitionRestorePhase(verified, {
      type: "barrier-passed",
      restoredArtifactSetSha256: "f".repeat(64),
    }),
    /barrier|digest|artifact|substitution/i,
  );
  const barrier = worker.transitionRestorePhase(verified, {
    type: "barrier-passed",
    restoredArtifactSetSha256: created.verifiedArtifactSetSha256,
  });
  assert.equal(barrier.phase, "barrier-passed");
  assert.deepEqual(worker.reverseCleanupOrder(barrier.cleanupStack), ["minio", "mariadb", "postgres"]);
  assert.throws(
    () => worker.transitionRestorePhase(barrier, { type: "shell", command: "true" }),
    /unsupported|transition|event/i,
  );
});

test("offsite state machine binds idempotency and preserves remote-unknown ambiguity", () => {
  requireContract("offsite transition wiring", [
    ["export transitionOffsiteAttempt", typeof worker.transitionOffsiteAttempt === "function"],
    ["offsite transition is used by an action path", occurrences(workerSource, "transitionOffsiteAttempt") >= 2],
    ["idempotency domain separator", workerSource.includes("platform-offsite-sync-v1\\n")],
    ["remote-unknown is an explicit state", workerSource.includes("remote-unknown")],
  ]);
  const manifestDigest = "1".repeat(64);
  const idempotencyKey = sha256(`platform-offsite-sync-v1\n${manifestDigest}\n`);
  const begin = {
    type: "begin",
    idempotencyKey,
    manifestDigest,
  };
  const idle = {
    phase: "idle",
    idempotencyKey: null,
    manifestDigest: null,
    snapshotId: null,
  };

  assert.throws(
    () => worker.transitionOffsiteAttempt(idle, { ...begin, idempotencyKey: "2".repeat(64) }),
    /idempotency|manifest|digest/i,
  );
  const inFlight = worker.transitionOffsiteAttempt(idle, begin);
  assert.equal(inFlight.phase, "in-flight");
  assert.equal(inFlight.idempotencyKey, idempotencyKey);

  const complete = worker.transitionOffsiteAttempt(inFlight, {
    type: "commit",
    idempotencyKey,
    manifestDigest,
    snapshotId: "3".repeat(64),
  });
  assert.equal(complete.phase, "complete");
  assert.deepEqual(
    worker.transitionOffsiteAttempt(complete, begin),
    complete,
    "replaying the exact completed idempotency key must not create another remote snapshot",
  );

  const remoteUnknown = worker.transitionOffsiteAttempt(inFlight, {
    type: "transport-unknown",
    idempotencyKey,
    manifestDigest,
  });
  assert.equal(remoteUnknown.phase, "remote-unknown");
  assert.equal(remoteUnknown.retryAllowed, false);
  assert.throws(
    () => worker.transitionOffsiteAttempt(remoteUnknown, begin),
    /remote-unknown|reconcile|retry/i,
    "an ambiguous remote result must not be retried blindly",
  );
  const reconciled = worker.transitionOffsiteAttempt(remoteUnknown, {
    type: "resolve-remote",
    idempotencyKey,
    manifestDigest,
    snapshotId: "3".repeat(64),
  });
  assert.equal(reconciled.phase, "complete");
  assert.throws(
    () => worker.transitionOffsiteAttempt(reconciled, { type: "arbitrary-upload" }),
    /unsupported|transition|event/i,
  );
});

async function importWorkerWithoutCliSideEffects() {
  const savedArgv = process.argv;
  const savedExitCode = process.exitCode;
  const savedStderrWrite = process.stderr.write;
  let capturedStderr = "";
  let observedExitCode;
  try {
    process.argv = [process.execPath, "docker-action-worker-unit-import"];
    process.exitCode = undefined;
    process.stderr.write = (chunk, ...args) => {
      capturedStderr += String(chunk);
      const callback = args.find((entry) => typeof entry === "function");
      if (callback) callback();
      return true;
    };
    const namespace = await import(`${pathToFileURL(workerPath).href}?worker-contract-red=1`);
    observedExitCode = process.exitCode;
    return { namespace, stderr: capturedStderr, exitCode: observedExitCode };
  } finally {
    process.argv = savedArgv;
    process.stderr.write = savedStderrWrite;
    process.exitCode = savedExitCode;
  }
}

function requireWorkerExports(...names) {
  const missing = names.filter((name) => typeof worker[name] !== "function");
  assert.equal(
    missing.length,
    0,
    `docker-action-worker pure API is missing export(s): ${missing.join(", ")}`,
  );
}

function requireContract(label, checks) {
  const missing = checks.filter(([, present]) => !present).map(([name]) => name);
  assert.equal(missing.length, 0, `${label} is incomplete: ${missing.join("; ")}`);
}

function occurrences(source, token) {
  return source.split(token).length - 1;
}

function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function signedManifestEnvelope() {
  const artifactPath = "postgres/worker-test.dump";
  const artifactSha256 = "4".repeat(64);
  const unsigned = {
    schema: "platform.backup-manifest/v1",
    id: "manifest-worker-test",
    jobId: "job-worker-test",
    operation: "backup",
    scope: { kind: "platform", id: "platform" },
    resources: [{
      id: "database:postgres",
      externalId: "postgres",
      kind: "database",
      projectId: "platform",
      name: "postgres",
      engine: "postgres",
    }],
    artifacts: [{
      id: "artifact-worker-test",
      resourceId: "database:postgres",
      path: artifactPath,
      sha256: artifactSha256,
      sizeBytes: 128,
      signatureKeyId: "artifact-test-v1",
    }],
    coverage: {
      requiredResourceIds: ["database:postgres"],
      artifactResourceIds: ["database:postgres"],
      missingResourceIds: [],
      complete: true,
    },
    createdAt: "2026-07-26T12:00:00.000Z",
  };
  const digest = backupDocumentDigest(unsigned);
  const manifestMac = crypto.createHmac("sha256", MANIFEST_TEST_KEY)
    .update(`platform-backup-manifest-v1\n${unsigned.id}\n${digest}\n`)
    .digest("base64url");
  const artifactName = path.basename(artifactPath);
  const artifactMac = crypto.createHmac("sha256", ARTIFACT_TEST_KEY)
    .update(`platform-postgres-backup-v1\n${artifactName}\n${artifactSha256}\n`)
    .digest("base64url");
  return {
    manifest: {
      ...unsigned,
      signature: {
        algorithm: "HMAC-SHA256",
        keyId: "manifest-test-v1",
        digest,
        value: manifestMac,
      },
    },
    sidecars: {
      [artifactPath]: {
        version: 1,
        algorithm: "HMAC-SHA256",
        keyId: "artifact-test-v1",
        artifact: artifactName,
        sha256: artifactSha256,
        signature: artifactMac,
      },
    },
  };
}

function manifestVerificationOptions() {
  return {
    manifestKeys: { "manifest-test-v1": MANIFEST_TEST_KEY },
    artifactKeys: { "artifact-test-v1": ARTIFACT_TEST_KEY },
  };
}

function protectedFileStat(overrides = {}) {
  return {
    isFile: () => true,
    isSymbolicLink: () => false,
    dev: 17,
    ino: 29,
    mode: 0o100600,
    nlink: 1,
    uid: 0,
    gid: 0,
    size: 128,
    ...overrides,
  };
}

function protectedFilePolicy() {
  return {
    expectedUid: 0,
    expectedGid: 0,
    expectedMode: 0o600,
    maximumBytes: 2 * 1024 * 1024,
  };
}

function boundedPruneSummary() {
  return {
    schema: "platform.backup-prune-plan/v1",
    mode: "plan",
    planId: "prune-plan-worker-test",
    planSha256: "5".repeat(64),
    completeManifestCount: 45,
    retainedManifestCount: 42,
    expiredManifestCount: 3,
    artifactCount: 9,
    artifactSetSha256: "6".repeat(64),
    mutationPerformed: false,
  };
}
