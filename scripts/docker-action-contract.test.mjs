import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import * as contract from "./docker-action-contract.mjs";
import { createBrokerCore } from "./docker-action-broker.mjs";

const NOW = Date.parse("2026-07-28T12:00:00.000Z");
const CAPABILITY_KEY = Buffer.from("capability-v2-contract-key-material".repeat(2));
const TRUST_KEY = Buffer.from("runtime-intent-v2-trust-key-material".repeat(2));
const REQUEST_SCHEMA_V2 = "platform.docker-action.request/v2";
const RESPONSE_SCHEMA_V2 = "platform.docker-action.response/v2";
const ACTIVE_RECEIPT_SCHEMA_V2 = "platform.docker-active-receipt/v2";
const REQUEST_MAC_DOMAIN = `${REQUEST_SCHEMA_V2}\0`;
const RESPONSE_MAC_DOMAIN = `${RESPONSE_SCHEMA_V2}\0`;

const SCHEDULER_ACTION_NAMES = Object.freeze([
  "backup.catalog",
  "backup.job.execute",
  "backup.prune.plan",
  "backup.prune.apply",
  "restore.drill.full",
  "backup.offsite.sync",
]);
const EVIDENCE_ACTION_NAMES = Object.freeze(["evidence.runtime.snapshot"]);
const REQUEST_KEYS = Object.freeze([
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
]);
const RESPONSE_KEYS = Object.freeze([
  "action",
  "errorCode",
  "mac",
  "requestId",
  "requestSha256",
  "result",
  "resultSha256",
  "schema",
  "status",
  "statusCode",
]);
const ACTION_PROFILE_KEYS = Object.freeze([
  "jobOperations",
  "mountIds",
  "networkIds",
  "profileId",
  "profileSha256",
  "quarantineVolumeIds",
  "scratchVolumeIds",
  "secretFileIds",
  "workerImageId",
  "workerImageRef",
]);
const ACTIVE_RECEIPT_KEYS = Object.freeze([
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
]);

test("RED v2: scheduler and runtime-evidence registries are disjoint, complete, modeled and uniquely bound", () => {
  assert.ok(
    contract.SCHEDULER_ACTIONS && typeof contract.SCHEDULER_ACTIONS === "object",
    "the product must export the six-action SCHEDULER_ACTIONS registry",
  );
  assert.ok(
    contract.EVIDENCE_ACTIONS && typeof contract.EVIDENCE_ACTIONS === "object",
    "the product must export the disjoint EVIDENCE_ACTIONS registry",
  );

  assert.deepEqual(Object.keys(contract.SCHEDULER_ACTIONS), SCHEDULER_ACTION_NAMES);
  assert.deepEqual(Object.keys(contract.EVIDENCE_ACTIONS), EVIDENCE_ACTION_NAMES);
  assert.deepEqual(
    Object.keys(contract.ACTIONS),
    [...SCHEDULER_ACTION_NAMES, ...EVIDENCE_ACTION_NAMES],
    "ACTIONS must be only the exact union of the two disjoint registries",
  );

  for (const action of SCHEDULER_ACTION_NAMES) {
    assert.strictEqual(contract.ACTIONS[action], contract.SCHEDULER_ACTIONS[action]);
  }
  for (const action of EVIDENCE_ACTION_NAMES) {
    assert.strictEqual(contract.ACTIONS[action], contract.EVIDENCE_ACTIONS[action]);
  }

  const entries = Object.entries(contract.ACTIONS);
  for (const [action, entry] of entries) {
    assert.equal(entry.modeled, true, `${action} must have an implemented fixed model`);
    assert.match(entry.capabilityId, /^[a-z][a-z0-9.-]+\.v2$/);
    assert.match(entry.capabilityFile, /^\/run\/secrets\/[a-z0-9_]+$/);
    assert.match(entry.profileId, /^[a-z][a-z0-9._-]+$/);
  }
  assertUnique(entries.map(([, entry]) => entry.capabilityId), "capabilityId");
  assertUnique(entries.map(([, entry]) => entry.capabilityFile), "capabilityFile");
  assertUnique(entries.map(([, entry]) => entry.profileId), "profileId");
});

test("RED v2: request schema has exact keys and rejects extensions", () => {
  const trusted = requestTrustedFixture("backup.catalog");
  const unsigned = contract.buildUnsignedRequest("backup.catalog", {}, trusted, {
    now: NOW,
    requestId: "123e4567-e89b-42d3-a456-426614174000",
    nonce: "A".repeat(43),
  });
  const signed = contract.signActionRequest(unsigned, CAPABILITY_KEY);

  assert.deepEqual(Object.keys(unsigned).sort(), REQUEST_KEYS.filter((key) => key !== "mac").sort());
  assert.deepEqual(Object.keys(signed).sort(), [...REQUEST_KEYS].sort());
  const admitted = contract.normalizeActionRequest(signed, trusted, CAPABILITY_KEY, { now: NOW });
  assert.equal(admitted.action, "backup.catalog");
  assert.equal(admitted.activeReceiptSha256, trusted.receiptDigest);
  assert.equal(admitted.capabilityId, contract.ACTIONS["backup.catalog"].capabilityId);
  assert.equal(admitted.combinedRenderSha256, trusted.receipt.combinedRenderSha256);
  assert.equal(admitted.nonce, signed.nonce);
  assert.deepEqual(admitted.parameters, {});
  assert.equal(admitted.requestId, signed.requestId);
  assert.equal(admitted.runtimeIntentId, trusted.intent.intentId);

  const injected = contract.signActionRequest({ ...unsigned, rawDockerArgs: ["run", "--privileged"] }, CAPABILITY_KEY);
  assert.throws(
    () => contract.normalizeActionRequest(injected, trusted, CAPABILITY_KEY, { now: NOW }),
    /unsupported or missing fields/,
  );
  assert.equal(unsigned.schema, REQUEST_SCHEMA_V2);
  assert.equal(contract.REQUEST_SCHEMA, REQUEST_SCHEMA_V2);
});

test("RED v2: request MAC is canonical and domain-separated", () => {
  const trusted = requestTrustedFixture("backup.catalog");
  const unsigned = {
    ...contract.buildUnsignedRequest("backup.catalog", {}, trusted, {
      now: NOW,
      requestId: "123e4567-e89b-42d3-a456-426614174000",
      nonce: "A".repeat(43),
    }),
    schema: REQUEST_SCHEMA_V2,
  };
  const signed = contract.signActionRequest(unsigned, CAPABILITY_KEY);
  const expectedMac = requestMac(unsigned, CAPABILITY_KEY);

  assert.equal(signed.mac, expectedMac);
  assert.equal(
    contract.signActionRequest(Object.fromEntries(Object.entries(unsigned).reverse()), CAPABILITY_KEY).mac,
    expectedMac,
    "property insertion order must not change the domain-separated request MAC",
  );
  assert.notEqual(
    expectedMac,
    crypto.createHmac("sha256", CAPABILITY_KEY).update(contract.canonicalJson(unsigned)).digest("hex"),
    "v1-compatible bare canonical JSON must not authenticate as a v2 request",
  );
});

test("RED v2: typed job parameters preserve real identifiers and reject normalization or aliases", () => {
  const trusted = requestTrustedFixture("backup.job.execute");
  const accepted = [
    {
      jobFileName: "0123456789abcdef.json",
      jobId: "0123456789abcdef",
      jobOperation: "backup",
      jobSha256: "1".repeat(64),
    },
    {
      jobFileName: "scheduled-platform-20260728-120000-a1b2c3.json",
      jobId: "scheduled-platform-20260728-120000-a1b2c3",
      jobOperation: "backup",
      jobSha256: "2".repeat(64),
    },
    {
      jobFileName: "job-0123456789abcdef.json",
      jobId: "job-0123456789abcdef",
      jobOperation: "restore-drill",
      jobSha256: "3".repeat(64),
    },
  ];

  for (const [index, parameters] of accepted.entries()) {
    const request = signedRequest("backup.job.execute", parameters, trusted, index);
    const normalized = contract.normalizeActionRequest(request, trusted, CAPABILITY_KEY, { now: NOW });
    assert.deepEqual(Object.keys(normalized.parameters).sort(), [
      "jobFileName",
      "jobId",
      "jobOperation",
      "jobSha256",
    ]);
    assert.deepEqual(normalized.parameters, parameters, "admitted job identity must be byte-exact");
  }

  const base = accepted[0];
  const invalid = [
    ["missing field", omit(base, "jobSha256")],
    ["extra alias field", { ...base, jobHash: base.jobSha256 }],
    ["leading whitespace", { ...base, jobId: ` ${base.jobId}` }],
    ["trailing whitespace", { ...base, jobId: `${base.jobId} ` }],
    ["case normalization", { ...base, jobId: base.jobId.toUpperCase() }],
    ["operation case", { ...base, jobOperation: "Backup" }],
    ["operation whitespace", { ...base, jobOperation: "backup " }],
    ["operation alias", { ...base, jobOperation: "restore" }],
    ["parent traversal", { ...base, jobFileName: `../${base.jobFileName}` }],
    ["nested traversal", { ...base, jobFileName: `queued/${base.jobFileName}` }],
    ["backslash traversal", { ...base, jobFileName: `queued\\${base.jobFileName}` }],
    ["filename case", { ...base, jobFileName: base.jobFileName.toUpperCase() }],
    ["filename alias", { ...base, jobFileName: "job-alias.json" }],
    ["digest case", { ...base, jobSha256: "A".repeat(64) }],
    ["digest whitespace", { ...base, jobSha256: `${base.jobSha256} ` }],
  ];
  for (const [label, parameters] of invalid) {
    const request = signedRequest("backup.job.execute", parameters, trusted, 20);
    assert.throws(
      () => contract.normalizeActionRequest(request, trusted, CAPABILITY_KEY, { now: NOW }),
      undefined,
      label,
    );
  }
});

test("RED v2: broker core emits the exact authenticated response wire contract", async () => {
  const trusted = requestTrustedFixture("backup.prune.plan");
  const request = signedRequest("backup.prune.plan", {}, trusted, 30);
  const result = { mode: "plan", mutationPerformed: false };
  const replayStore = {
    acquire() {
      return { preserve() {}, recordWorker() {}, release() {} };
    },
    admitActivation() {},
    admitTrustedContext() {},
    consume() {},
  };
  const core = createBrokerCore({
    trustedContextProvider: async () => trusted,
    capabilityProvider: async () => CAPABILITY_KEY,
    engine: { execute: async () => result },
    replayStore,
    now: () => NOW,
    operationTimeoutMs: 100,
  });

  const wire = await core.handle(Buffer.from(JSON.stringify(request)));
  const response = wire.body;
  const requestSha256 = contract.sha256(contract.canonicalJson(request));
  const resultSha256 = contract.sha256(contract.canonicalJson(result));

  assert.equal(wire.statusCode, 200);
  assert.deepEqual(Object.keys(response).sort(), [...RESPONSE_KEYS].sort());
  assert.equal(response.schema, RESPONSE_SCHEMA_V2);
  assert.equal(response.status, "completed");
  assert.equal(response.statusCode, 200);
  assert.equal(response.errorCode, null);
  assert.equal(response.action, request.action);
  assert.equal(response.requestId, request.requestId);
  assert.equal(response.requestSha256, requestSha256);
  assert.equal(response.resultSha256, resultSha256);
  assert.deepEqual(response.result, result);
  assert.equal(response.mac, responseMac(omit(response, "mac"), CAPABILITY_KEY));
});

test("RED v2: response signing binds request and result digests and exact fields", () => {
  assert.equal(
    typeof contract.signActionResponse,
    "function",
    "the product must expose response signing for the v2 wire contract",
  );
  assert.equal(
    typeof contract.normalizeActionResponse,
    "function",
    "the client-visible contract must expose fail-closed response normalization",
  );

  const trusted = requestTrustedFixture("backup.prune.plan");
  const request = signedRequest("backup.prune.plan", {}, trusted, 40);
  const result = { mode: "plan", mutationPerformed: false };
  const unsigned = {
    schema: RESPONSE_SCHEMA_V2,
    status: "completed",
    statusCode: 200,
    errorCode: null,
    action: request.action,
    requestId: request.requestId,
    requestSha256: contract.sha256(contract.canonicalJson(request)),
    result,
    resultSha256: contract.sha256(contract.canonicalJson(result)),
  };
  const response = contract.signActionResponse(unsigned, CAPABILITY_KEY);

  assert.deepEqual(Object.keys(response).sort(), [...RESPONSE_KEYS].sort());
  assert.equal(response.mac, responseMac(unsigned, CAPABILITY_KEY));
  assert.equal(
    contract.signActionResponse(Object.fromEntries(Object.entries(unsigned).reverse()), CAPABILITY_KEY).mac,
    response.mac,
    "property insertion order must not change the domain-separated response MAC",
  );
  assert.notEqual(
    response.mac,
    crypto.createHmac("sha256", CAPABILITY_KEY).update(contract.canonicalJson(unsigned)).digest("hex"),
    "bare canonical JSON must not authenticate as a v2 response",
  );
  assert.deepEqual(
    contract.normalizeActionResponse(response, request, CAPABILITY_KEY),
    response,
  );

  const signedMutations = [
    ["extra field", { ...unsigned, extension: "not-allowed" }],
    ["cross-action", { ...unsigned, action: "backup.catalog" }],
    ["cross-request ID", { ...unsigned, requestId: "123e4567-e89b-42d3-a456-426614174999" }],
    ["request digest", { ...unsigned, requestSha256: "0".repeat(64) }],
    ["result without matching digest", { ...unsigned, result: { mode: "apply", mutationPerformed: true } }],
    ["result digest", { ...unsigned, resultSha256: "0".repeat(64) }],
  ];
  for (const [label, mutation] of signedMutations) {
    const candidate = { ...mutation, mac: responseMac(mutation, CAPABILITY_KEY) };
    assert.throws(
      () => contract.normalizeActionResponse(candidate, request, CAPABILITY_KEY),
      undefined,
      label,
    );
  }
  assert.throws(
    () => contract.normalizeActionResponse({ ...response, mac: "0".repeat(64) }, request, CAPABILITY_KEY),
    undefined,
    "MAC mutation",
  );
});

test("RED v2: active receipt admits only exact complete profiles and sorted live references", () => {
  const receipt = activeReceiptFixture();
  const normalized = contract.normalizeActiveReceipt(receipt, { now: NOW });

  assert.equal(contract.ACTIVE_RECEIPT_SCHEMA, ACTIVE_RECEIPT_SCHEMA_V2);
  assert.equal(normalized.schema, ACTIVE_RECEIPT_SCHEMA_V2);
  assert.deepEqual(Object.keys(receipt).sort(), [...ACTIVE_RECEIPT_KEYS].sort());
  assert.deepEqual(Object.keys(receipt.resources).sort(), [
    "actionProfiles",
    "backupResources",
    "containers",
    "mounts",
    "networks",
    "secretFiles",
    "volumes",
  ]);
  assert.deepEqual(Object.keys(receipt.resources.actionProfiles), SCHEDULER_ACTION_NAMES);
  for (const action of SCHEDULER_ACTION_NAMES) {
    assert.deepEqual(
      Object.keys(receipt.resources.actionProfiles[action]).sort(),
      [...ACTION_PROFILE_KEYS].sort(),
      action,
    );
    assert.deepEqual(
      receipt.resources.actionProfiles[action].networkIds,
      expectedNetworkIds(action),
      `${action} network authority`,
    );
  }
  assertUnique(
    SCHEDULER_ACTION_NAMES.map((action) => receipt.resources.actionProfiles[action].profileId),
    "receipt profileId",
  );
  assertUnique(
    SCHEDULER_ACTION_NAMES.map((action) => receipt.resources.actionProfiles[action].profileSha256),
    "receipt profileSha256",
  );
  assert.deepEqual(Object.keys(receipt.resources.networks["offsite.egress"]).sort(), [
    "driver",
    "externalEgress",
    "internal",
    "name",
    "networkId",
    "optionsSha256",
  ]);
  assert.deepEqual(Object.keys(receipt.resources.secretFiles["capability.backup.catalog"]).sort(), [
    "canonicalPath",
    "device",
    "inode",
    "mode",
    "ownerGid",
    "ownerUid",
    "sha256",
    "symlinkFree",
  ]);
  assert.deepEqual(Object.keys(receipt.resources.volumes["backup.quarantine"]).sort(), [
    "driver",
    "labelsSha256",
    "name",
    "optionsSha256",
  ]);

  const invalid = [
    ["top-level extension", (value) => { value.extension = true; }],
    ["resources extension", (value) => { value.resources.extension = {}; }],
    ["missing resources map", (value) => { delete value.resources.secretFiles; }],
    ["missing scheduler action", (value) => { delete value.resources.actionProfiles["backup.catalog"]; }],
    ["runtime evidence mixed into scheduler profiles", (value) => {
      value.resources.actionProfiles["evidence.runtime.snapshot"] = structuredClone(value.resources.actionProfiles["backup.catalog"]);
    }],
    ["action profile extension", (value) => { value.resources.actionProfiles["backup.catalog"].extension = true; }],
    ["profile digest mismatch", (value) => {
      value.resources.actionProfiles["backup.catalog"].profileSha256 = "0".repeat(64);
    }, false],
    ["duplicate profile identity", (value) => {
      value.resources.actionProfiles["backup.catalog"].profileId =
        value.resources.actionProfiles["backup.job.execute"].profileId;
    }],
    ["duplicate job operation", (value) => {
      value.resources.actionProfiles["backup.job.execute"].jobOperations = ["backup", "backup"];
    }],
    ["unsorted job operations", (value) => {
      value.resources.actionProfiles["backup.job.execute"].jobOperations = ["restore-drill", "backup"];
    }],
    ["job operation on fixed action", (value) => {
      value.resources.actionProfiles["backup.catalog"].jobOperations = ["backup"];
    }],
    ["dangling mount", (value) => {
      value.resources.actionProfiles["backup.catalog"].mountIds = ["missing.mount"];
    }],
    ["duplicate mount", (value) => {
      value.resources.actionProfiles["backup.catalog"].mountIds = ["backup.root", "backup.root"];
    }],
    ["unsorted mounts", (value) => {
      value.resources.actionProfiles["backup.job.execute"].mountIds = ["jobs.running", "backup.root"];
    }],
    ["dangling secret file", (value) => {
      value.resources.actionProfiles["backup.catalog"].secretFileIds = ["missing.secret"];
    }],
    ["duplicate secret file", (value) => {
      const id = value.resources.actionProfiles["backup.catalog"].secretFileIds[0];
      value.resources.actionProfiles["backup.catalog"].secretFileIds = [id, id];
    }],
    ["unsorted secret files", (value) => {
      value.resources.actionProfiles["backup.offsite.sync"].secretFileIds.reverse();
    }],
    ["dangling quarantine volume", (value) => {
      value.resources.actionProfiles["backup.prune.apply"].quarantineVolumeIds = ["missing.volume"];
    }],
    ["duplicate scratch volume", (value) => {
      value.resources.actionProfiles["restore.drill.full"].scratchVolumeIds = [
        "restore.scratch",
        "restore.scratch",
      ];
    }],
    ["duplicate network", (value) => {
      value.resources.actionProfiles["backup.catalog"].networkIds = [
        "platform_db_admin",
        "platform_db_admin",
      ];
    }],
    ["unsorted networks", (value) => {
      value.resources.actionProfiles["backup.catalog"].networkIds.reverse();
    }],
    ["dangling network", (value) => {
      value.resources.actionProfiles["backup.offsite.sync"].networkIds = ["missing.network"];
    }],
    ["egress network on non-offsite action", (value) => {
      value.resources.actionProfiles["backup.catalog"].networkIds = ["offsite.egress"];
    }],
    ["offsite action without exact egress", (value) => {
      value.resources.actionProfiles["backup.offsite.sync"].networkIds = [];
    }],
    ["external egress flag on an internal network", (value) => {
      value.resources.networks.platform_db_admin.externalEgress = true;
    }],
    ["non-internal database network", (value) => {
      value.resources.networks.platform_db_admin.internal = false;
    }],
    ["network extension", (value) => { value.resources.networks["offsite.egress"].extension = true; }],
    ["secret extension", (value) => {
      value.resources.secretFiles["capability.backup.catalog"].extension = true;
    }],
    ["volume extension", (value) => { value.resources.volumes["backup.quarantine"].extension = true; }],
  ];
  for (const [label, mutate, reseal = true] of invalid) {
    const candidate = structuredClone(receipt);
    mutate(candidate);
    if (reseal) resealActionProfiles(candidate);
    assert.throws(
      () => contract.normalizeActiveReceipt(candidate, { now: NOW }),
      undefined,
      label,
    );
  }
});

test("RED v2: signed runtime intent detects every Release-owned receipt reference mutation", () => {
  const receipt = activeReceiptFixture();
  const normalized = contract.normalizeActiveReceipt(receipt, { now: NOW });
  const intent = contract.signRuntimeIntent({
    schema: contract.RUNTIME_INTENT_SCHEMA,
    activeReceiptSha256: contract.sha256(contract.canonicalJson(normalized)),
    activationBundleSha256: receipt.activationBundleSha256,
    allowedActions: [...SCHEDULER_ACTION_NAMES],
    candidateId: receipt.candidateId,
    combinedRenderSha256: receipt.combinedRenderSha256,
    dastChainSha256: receipt.dastChainSha256,
    environment: receipt.environment,
    expiresAt: new Date(NOW + 30 * 60_000).toISOString(),
    generation: receipt.generation,
    intentId: "intent.release-v2",
    issuedAt: new Date(NOW - 30_000).toISOString(),
    releaseId: receipt.releaseId,
    targetId: receipt.targetId,
  }, TRUST_KEY);

  const trusted = contract.normalizeTrustedContext(intent, receipt, TRUST_KEY, { now: NOW });
  assert.equal(trusted.receiptDigest, intent.activeReceiptSha256);

  const mutations = [
    ["profileSha256", (value) => {
      value.resources.actionProfiles["backup.catalog"].profileSha256 = "d".repeat(64);
    }],
    ["workerImageId", (value) => {
      value.resources.actionProfiles["backup.catalog"].workerImageId = `sha256:${"b".repeat(64)}`;
    }],
    ["workerImageRef", (value) => {
      value.resources.actionProfiles["backup.catalog"].workerImageRef =
        `registry.example/platform/other-worker@sha256:${"c".repeat(64)}`;
    }],
    ["coherent worker image substitution", (value) => {
      value.resources.actionProfiles["backup.catalog"].workerImageId = `sha256:${"8".repeat(64)}`;
      value.resources.actionProfiles["backup.catalog"].workerImageRef =
        `registry.example/platform/docker-action-substitute@sha256:${"8".repeat(64)}`;
    }],
    ["secret sha256", (value) => {
      value.resources.secretFiles["capability.backup.catalog"].sha256 = "9".repeat(64);
    }],
    ["mount inode", (value) => { value.resources.mounts["backup.root"].inode += 1; }],
    ["network identity", (value) => {
      value.resources.networks["offsite.egress"].networkId = "9".repeat(64);
    }],
    ["volume options", (value) => {
      value.resources.volumes["backup.quarantine"].optionsSha256 = "f".repeat(64);
    }],
  ];
  for (const [label, mutate] of mutations) {
    const candidate = structuredClone(receipt);
    mutate(candidate);
    assert.throws(
      () => contract.normalizeTrustedContext(intent, candidate, TRUST_KEY, { now: NOW }),
      undefined,
      label,
    );
  }
});

function requestTrustedFixture(action) {
  const receipt = activeReceiptFixture();
  return Object.freeze({
    intent: Object.freeze({
      allowedActions: Object.freeze([action]),
      intentId: "intent.release-v2",
    }),
    receipt,
    receiptDigest: contract.sha256(contract.canonicalJson(receipt)),
  });
}

function signedRequest(action, parameters, trusted, index) {
  const suffix = String(index).padStart(12, "0");
  const unsigned = contract.buildUnsignedRequest(action, parameters, trusted, {
    now: NOW,
    requestId: `123e4567-e89b-42d3-a456-${suffix}`,
    nonce: Buffer.alloc(32, index + 1).toString("base64url"),
  });
  return contract.signActionRequest(unsigned, CAPABILITY_KEY);
}

function activeReceiptFixture() {
  const actionProfiles = {};
  const secretFiles = {};
  for (const [index, action] of SCHEDULER_ACTION_NAMES.entries()) {
    const capabilitySecretId = `capability.${action}`;
    const digest = (index + 1).toString(16).repeat(64);
    const profileId = contract.SCHEDULER_ACTIONS?.[action]?.profileId ?? `scheduler.${action}.v2`;
    secretFiles[capabilitySecretId] = {
      canonicalPath: `/run/secrets/docker_action_${action.replaceAll(".", "_")}`,
      device: 100,
      inode: 1000 + index,
      mode: 0o400,
      ownerGid: 0,
      ownerUid: 0,
      sha256: digest,
      symlinkFree: true,
    };
    const unsignedProfile = {
      jobOperations: action === "backup.job.execute" ? ["backup", "restore-drill"] : [],
      mountIds: action === "backup.job.execute" ? ["backup.root", "jobs.running"] : ["backup.root"],
      networkIds: expectedNetworkIds(action),
      profileId,
      quarantineVolumeIds: action === "backup.prune.apply" ? ["backup.quarantine"] : [],
      scratchVolumeIds: action === "restore.drill.full" ? ["restore.scratch"] : [],
      secretFileIds: action === "backup.offsite.sync"
        ? [capabilitySecretId, "offsite.restic.credentials"].sort()
        : [capabilitySecretId],
      workerImageId: `sha256:${digest}`,
      workerImageRef: `registry.example/platform/docker-action-${index + 1}@sha256:${digest}`,
    };
    actionProfiles[action] = {
      ...unsignedProfile,
      profileSha256: contract.sha256(contract.canonicalJson(unsignedProfile)),
    };
  }
  secretFiles["offsite.restic.credentials"] = {
    canonicalPath: "/run/secrets/restic_repository_credentials",
    device: 100,
    inode: 2000,
    mode: 0o400,
    ownerGid: 0,
    ownerUid: 0,
    sha256: "d".repeat(64),
    symlinkFree: true,
  };

  return {
    schema: ACTIVE_RECEIPT_SCHEMA_V2,
    activationBundleSha256: "a".repeat(64),
    candidateId: "candidate.v2",
    combinedRenderSha256: "b".repeat(64),
    dastChainSha256: "c".repeat(64),
    environment: "production",
    expiresAt: new Date(NOW + 60 * 60_000).toISOString(),
    generation: 2,
    issuedAt: new Date(NOW - 60_000).toISOString(),
    receiptId: "receipt.v2",
    releaseId: "release.v2",
    resources: {
      actionProfiles,
      backupResources: {
        "source:platform": {
          externalId: "platform",
          kind: "source",
          name: "platform",
          projectId: "platform",
          sourceDirectory: "platform",
        },
      },
      containers: {},
      mounts: {
        "backup.root": {
          access: "ro",
          canonicalPath: "/srv/platform/backups",
          containerPath: "/data/backups",
          device: 42,
          inode: 4242,
          kind: "directory",
          mode: 0o755,
          ownerGid: 0,
          ownerUid: 0,
          symlinkFree: true,
        },
        "jobs.running": {
          access: "ro",
          canonicalPath: "/srv/platform/project-state/backup-jobs/running",
          containerPath: "/var/www/project-state",
          device: 42,
          inode: 4243,
          kind: "directory",
          mode: 0o700,
          ownerGid: 0,
          ownerUid: 0,
          symlinkFree: true,
        },
      },
      networks: {
        platform_db_admin: {
          driver: "bridge",
          externalEgress: false,
          internal: true,
          name: "platform-db-admin",
          networkId: "a".repeat(64),
          optionsSha256: "b".repeat(64),
        },
        platform_storage: {
          driver: "bridge",
          externalEgress: false,
          internal: true,
          name: "platform-storage",
          networkId: "c".repeat(64),
          optionsSha256: "d".repeat(64),
        },
        "offsite.egress": {
          driver: "bridge",
          externalEgress: true,
          internal: false,
          name: "platform-offsite-egress",
          networkId: "e".repeat(64),
          optionsSha256: "f".repeat(64),
        },
      },
      secretFiles,
      volumes: {
        "backup.quarantine": {
          driver: "local",
          labelsSha256: "1".repeat(64),
          name: "platform-backup-quarantine",
          optionsSha256: "2".repeat(64),
        },
        "restore.scratch": {
          driver: "local",
          labelsSha256: "3".repeat(64),
          name: "platform-restore-scratch",
          optionsSha256: "4".repeat(64),
        },
      },
    },
    sourceRenderSha256: "5".repeat(64),
    targetId: "platform.primary",
    treeSha256: "6".repeat(64),
  };
}

function responseMac(unsigned, key) {
  return crypto
    .createHmac("sha256", key)
    .update(RESPONSE_MAC_DOMAIN)
    .update(contract.canonicalJson(unsigned))
    .digest("hex");
}

function requestMac(unsigned, key) {
  return crypto
    .createHmac("sha256", key)
    .update(REQUEST_MAC_DOMAIN)
    .update(contract.canonicalJson(unsigned))
    .digest("hex");
}

function expectedNetworkIds(action) {
  if (action === "backup.offsite.sync") return ["offsite.egress"];
  if (["backup.catalog", "backup.job.execute", "restore.drill.full"].includes(action)) {
    return ["platform_db_admin", "platform_storage"];
  }
  return [];
}

function resealActionProfiles(receipt) {
  for (const profile of Object.values(receipt.resources.actionProfiles)) {
    if (!profile || typeof profile !== "object" || Array.isArray(profile)) continue;
    const unsigned = Object.fromEntries(Object.entries(profile).filter(([key]) => key !== "profileSha256"));
    profile.profileSha256 = contract.sha256(contract.canonicalJson(unsigned));
  }
}

function omit(value, key) {
  return Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
}

function assertUnique(values, label) {
  assert.equal(new Set(values).size, values.length, `${label} values must be unique`);
}
