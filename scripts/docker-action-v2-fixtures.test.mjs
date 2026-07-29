import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  ACTIVE_RECEIPT_RESOURCE_KEYS,
  ACTIVE_RECEIPT_SCHEMA_V2,
  ALL_ACTION_NAMES,
  EXPECTED_ACTION_BINDINGS,
  EXPECTED_ACTION_PHASES,
  EXPECTED_PHASE_PROFILES,
  REQUEST_SCHEMA_V2,
  SCHEDULER_ACTION_NAMES,
  buildFixtureSignedActionRequestV2,
  buildFixtureUnsignedActionRequestV2,
  buildRawActiveReceiptV2,
  canonicalFixtureJson,
  capabilityFileId,
  fixtureCapabilityKey,
  fixtureSha256,
  phaseDigest,
  profileDigest,
} from "./docker-action-v2-fixtures.mjs";

test("fixture oracle has exact v2 schemas, resource maps and sealed profiles", () => {
  const receipt = buildRawActiveReceiptV2();
  assert.equal(receipt.schema, ACTIVE_RECEIPT_SCHEMA_V2);
  assert.deepEqual(
    Object.keys(receipt.resources).sort(),
    [...ACTIVE_RECEIPT_RESOURCE_KEYS].sort(),
  );
  assert.deepEqual(
    Object.keys(receipt.resources.actionProfiles).sort(),
    [...SCHEDULER_ACTION_NAMES].sort(),
  );
  assert.deepEqual(
    Object.keys(receipt.resources.phaseProfiles).sort(),
    Object.keys(EXPECTED_PHASE_PROFILES).sort(),
  );
  for (const [action, profile] of Object.entries(receipt.resources.actionProfiles)) {
    assert.equal(profile.profileId, EXPECTED_ACTION_BINDINGS[action].profileId);
    assert.equal(profile.profileSha256, profileDigest(profile), `${action} profile digest`);
  }
  for (const [phaseId, profile] of Object.entries(receipt.resources.phaseProfiles)) {
    assert.equal(profile.phaseId, phaseId);
    assert.equal(profile.phaseSha256, phaseDigest(profile), `${phaseId} phase digest`);
    assert.match(profile.workerImageRef, /@sha256:[a-f0-9]{64}$/);
    assert.match(profile.workerImageId, /^sha256:[a-f0-9]{64}$/);
  }
});

test("fixture oracle assigns every phase to one exact action or job operation", () => {
  const owners = new Map();
  for (const [action, plan] of Object.entries(EXPECTED_ACTION_PHASES)) {
    for (const phaseId of plan.phaseIds) addOwner(owners, phaseId, action);
    for (const [operation, phaseIds] of Object.entries(plan.operationPhaseIds)) {
      for (const phaseId of phaseIds) addOwner(owners, phaseId, `${action}:${operation}`);
    }
  }
  assert.deepEqual([...owners.keys()].sort(), Object.keys(EXPECTED_PHASE_PROFILES).sort());
  for (const [phaseId, phaseOwners] of owners) {
    assert.equal(phaseOwners.length, 1, `${phaseId} has ambiguous authority`);
  }
  assert.deepEqual(
    EXPECTED_ACTION_PHASES["backup.job.execute"].operationPhaseIds,
    {
      backup: ["job.backup.capture"],
      "restore-drill": ["job.restore.verify"],
    },
  );
  assert.deepEqual(
    EXPECTED_ACTION_PHASES["restore.drill.full"].phaseIds,
    ["restore.capture", "restore.verify"],
  );
});

test("fixture oracle binds action-distinct capability bytes to their exact broker files", () => {
  const receipt = buildRawActiveReceiptV2();
  const digests = [];
  for (const action of ALL_ACTION_NAMES) {
    const key = fixtureCapabilityKey(action);
    const file = receipt.resources.capabilityFiles[capabilityFileId(action)];
    assert.equal(file.brokerPath, EXPECTED_ACTION_BINDINGS[action].capabilityFile);
    assert.equal(file.sha256, fixtureSha256(key));
    digests.push(file.sha256);
  }
  assert.equal(new Set(digests).size, ALL_ACTION_NAMES.length);
});

test("fixture oracle keeps queue broker-only, secrets split and quarantine on the backup filesystem", () => {
  const receipt = buildRawActiveReceiptV2();
  const queue = receipt.resources.claimedJobSources["jobs.running"];
  assert.deepEqual(queue, {
    brokerRoot: "/run/platform/backup-jobs/running",
    maximumBytes: 128 * 1024,
    volumeId: "jobs.queue",
    volumeSubpath: "running",
  });
  assert.equal(
    receipt.resources.volumes["jobs.queue"].engineName,
    "platform_infra_vps_backup_scheduler_jobs",
  );
  assert.equal(
    Object.values(receipt.resources.workerSecretSets)
      .some(({ volumeId }) => volumeId === "jobs.queue"),
    false,
  );
  assert.notEqual(
    receipt.resources.workerSecretSets["manifest.signing"].volumeId,
    receipt.resources.workerSecretSets["manifest.verification"].volumeId,
  );
  assert.deepEqual(EXPECTED_PHASE_PROFILES["job.restore.verify"].networkIds, []);
  assert.deepEqual(EXPECTED_PHASE_PROFILES["restore.verify"].networkIds, []);
  assert.deepEqual(EXPECTED_PHASE_PROFILES["offsite.sync"].networkIds, ["platform_egress"]);
  const quarantine = receipt.resources.writableSubpaths["backup.quarantine"];
  assert.equal(quarantine.mountId, "backup.root.rw");
  assert.equal(quarantine.relativePath, ".quarantine");
  assert.equal(quarantine.device, receipt.resources.mounts["backup.root.rw"].device);
  assert.equal(Object.hasOwn(receipt.resources.volumes, "backup.quarantine"), false);
});

test("fixture request/v2 builder is independent, exact and domain-separated", () => {
  const receipt = buildRawActiveReceiptV2();
  const trustedContext = {
    intent: { intentId: "intent.release-v2" },
    receipt,
    receiptDigest: fixtureSha256(canonicalFixtureJson(receipt)),
  };
  const unsigned = buildFixtureUnsignedActionRequestV2("backup.prune.plan", {}, {
    index: 7,
    trustedContext,
  });
  const key = fixtureCapabilityKey("backup.prune.plan");
  const signed = buildFixtureSignedActionRequestV2("backup.prune.plan", {}, {
    capabilityKey: key,
    index: 7,
    trustedContext,
  });
  assert.equal(unsigned.schema, REQUEST_SCHEMA_V2);
  assert.equal(unsigned.capabilityId, EXPECTED_ACTION_BINDINGS["backup.prune.plan"].capabilityId);
  assert.deepEqual(
    Object.keys(signed).sort(),
    [...Object.keys(unsigned), "mac"].sort(),
  );
  const expected = crypto.createHmac("sha256", key)
    .update(`${REQUEST_SCHEMA_V2}\0`)
    .update(canonicalFixtureJson(unsigned))
    .digest("hex");
  assert.equal(signed.mac, expected);
  assert.notEqual(
    signed.mac,
    crypto.createHmac("sha256", key).update(canonicalFixtureJson(unsigned)).digest("hex"),
  );
});

function addOwner(owners, phaseId, owner) {
  const values = owners.get(phaseId) ?? [];
  values.push(owner);
  owners.set(phaseId, values);
}
