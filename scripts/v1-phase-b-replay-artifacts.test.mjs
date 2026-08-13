import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  CORE_LEDGER_CONSUMPTION_KEYS,
  FROZEN_CORE_ADMISSION_SHA256,
  REPLAY_ARTIFACTS_VERIFIED_NON_AUTHORITATIVE,
  canonicalJson,
  deriveReplayArtifactKeys,
  verifyV1PhaseBReplayArtifacts,
} from "./v1-phase-b-replay-artifacts.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.dirname(HERE);
const MODULE = path.join(HERE, "v1-phase-b-replay-artifacts.mjs");
const CORE = path.join(HERE, "v1-brownfield-admission.mjs");
const COMMON_SCHEMA = path.join(REPO, "governance", "schemas", "v1-brownfield-common-tuple.schema.json");
const SCHEMAS = [
  "v1-phase-b-replay-claim.schema.json",
  "v1-phase-b-install-journal-entry.schema.json",
  "v1-phase-b-install-journal-terminal.schema.json",
  "v1-phase-b-bootstrap-execution-receipt.schema.json",
].map((name) => path.join(REPO, "governance", "schemas", name));
const require = createRequire(path.join(REPO, "vendor", "json-schema", "package.json"));
const Ajv2020 = require("ajv/dist/2020");
const addFormats = require("ajv-formats");

function h(value) {
  return crypto.createHash("sha256")
    .update(Buffer.isBuffer(value) ? value : String(value))
    .digest("hex");
}

function nonce(label) {
  return crypto.createHash("sha256").update(label).digest().toString("base64url");
}

function bytes(document) {
  return Buffer.from(canonicalJson(document) + "\n", "utf8");
}

function clone(value) {
  return structuredClone(value);
}

function bindingFrom(expected, keys) {
  return {
    authorizationEnvelopeSha256: expected.authorizationEnvelopeSha256,
    authorizationExpiresAt: expected.authorizationExpiresAt,
    authorizationId: expected.authorizationId,
    authorizationIssuedAt: expected.authorizationIssuedAt,
    claimId: keys.claimId,
    claimObjectPath: keys.claimObjectPath,
    journalParentIdentitySha256: expected.journalParentIdentitySha256,
    journalRecordPath: keys.journalRecordPath,
    journalStorePath: keys.journalStorePath,
    ledgerEntryKeySha256: keys.ledgerEntryKeySha256,
    ledgerId: expected.ledgerId,
    ledgerParentPath: expected.ledgerParentPath,
    nonce: expected.nonce,
    packageBytesSha256: expected.packageBytesSha256,
    packageInputObservationSha256: expected.packageInputObservationSha256,
    packageManifestSha256: expected.packageManifestSha256,
    policySha256: expected.policySha256,
    preinstallTupleSha256: expected.preinstallTupleSha256,
    receiptId: expected.receiptId,
    receiptObjectKeySha256: keys.receiptObjectKeySha256,
    receiptObjectPath: keys.receiptObjectPath,
    receiptStorePath: keys.receiptStorePath,
    transactionId: expected.transactionId,
  };
}

function identity({ kind, pathname, sha256, sizeBytes, seed, device, filesystem, mount }) {
  return {
    descriptorNoFollow: true,
    deviceIdentity: device,
    fileType: "REGULAR_FILE",
    filesystemUuid: filesystem,
    gid: 0,
    identityReceiptSha256: h(seed + ":identity-receipt"),
    inode: seed === "claim" ? "701" : "702",
    kind,
    mode: "0400",
    mountId: mount,
    nlink: 1,
    path: pathname,
    sha256,
    sizeBytes,
    symlink: false,
    uid: 0,
  };
}

function makeFixture() {
  const expected = {
    schema: "platform.v1-phase-b-replay-artifact-expectation/v1",
    authorizationEnvelopeSha256: h("phase-b-envelope"),
    authorizationExpiresAt: "2026-08-11T10:05:00.000Z",
    authorizationId: "phase-b-authorization:fixture-001",
    authorizationIssuedAt: "2026-08-11T09:59:00.000Z",
    claimNegativeLookupReceiptSha256: h("claim-negative-lookup"),
    journalNegativeLookupReceiptSha256: h("journal-negative-lookup"),
    journalParentDeviceIdentity: "device:journal-parent",
    journalParentFilesystemUuid: h("journal-parent-filesystem"),
    journalParentIdentitySha256: h("journal-parent-identity"),
    journalParentMountId: "812",
    ledgerAncestrySha256: h("ledger-ancestry"),
    ledgerId: "platform-v1-phase-b-installer-ledger",
    ledgerParentDeviceIdentity: "device:ledger-parent",
    ledgerParentFilesystemUuid: h("ledger-parent-filesystem"),
    ledgerParentIdentitySha256: h("ledger-parent-identity"),
    ledgerParentMountId: "811",
    ledgerParentPath: "/var/lib",
    nonce: nonce("phase-b-replay"),
    packageBytesSha256: h("package-bytes"),
    packageInputObservationSha256: h("authenticated-package-input-observation"),
    packageManifestSha256: h("package-manifest"),
    policySha256: h("phase-b-policy"),
    preinstallTupleSha256: h("preinstall-tuple"),
    receiptId: "install-receipt:fixture-001",
    receiptNegativeLookupReceiptSha256: h("receipt-negative-lookup"),
    receiptParentIdentitySha256: h("receipt-parent-identity"),
    steps: [
      {
        inputDigestSha256: h("mkdir-input"),
        operation: "CREATE_REQUIRED_DIRECTORY",
        stepId: "install-step:001",
        targetPath: "/srv/platform-infrastructure",
      },
      {
        inputDigestSha256: h("binary-input"),
        operation: "MATERIALIZE_PINNED_ARTIFACT",
        stepId: "install-step:002",
        targetPath: "/usr/local/libexec/platform-v1-brownfield-admission",
      },
      {
        inputDigestSha256: h("verification-input"),
        operation: "VERIFY_POSTINSTALL_ANCESTRY",
        stepId: "install-step:003",
        targetPath: null,
      },
    ],
    transactionId: h("transaction"),
  };
  const keys = deriveReplayArtifactKeys(expected);
  Object.assign(expected, keys);
  const binding = bindingFrom(expected, keys);
  const claim = {
    schema: "platform.v1-phase-b-replay-claim/v1",
    binding,
    createdAt: "2026-08-11T10:00:00.000Z",
    ledgerAncestrySha256: expected.ledgerAncestrySha256,
    ledgerParentIdentitySha256: expected.ledgerParentIdentitySha256,
    ledgerParentPath: "/var/lib",
    sequence: 0,
    state: "CLAIMED",
    writeContract: {
      atomicCreateExclusiveRequired: true,
      claimNegativeLookupReceiptSha256: expected.claimNegativeLookupReceiptSha256,
      descriptorNoFollowRequired: true,
      fileFsyncRequired: true,
      firstWriteRequired: true,
      openFlags: ["O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_WRONLY"],
      openat2ResolveBeneathNoSymlinks: true,
      openat2ResolveNoXdev: true,
      parentFsyncRequired: true,
      rollbackAllowed: false,
      resumeAllowed: false,
    },
  };
  const claimArtifact = bytes(claim);
  const journalEntries = [];
  let previousArtifactSha256 = h(claimArtifact);
  expected.steps.forEach((step, index) => {
    const sequence = index + 1;
    const entry = {
      schema: "platform.v1-phase-b-install-journal-entry/v1",
      activationPerformed: false,
      appendContract: {
        appendOnlyRequired: true,
        createdExclusiveRequired: sequence === 1,
        descriptorNoFollowRequired: true,
        fileFsyncRequired: true,
        noTruncateRequired: true,
        openFlags: sequence === 1
          ? ["O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_WRONLY"]
          : ["O_APPEND", "O_NOFOLLOW", "O_WRONLY"],
        parentFsyncRequired: sequence === 1,
        replacementAllowed: false,
      },
      binding,
      dataRollbackAuthority: false,
      entryIdSha256: h([
        "phase-b-journal-entry-v1", keys.ledgerEntryKeySha256,
        String(sequence), previousArtifactSha256, step.inputDigestSha256,
      ].join("\0")),
      previousArtifactSha256,
      recordedAt: `2026-08-11T10:00:0${sequence + 1}.000Z`,
      resumeAllowed: false,
      rollbackAttempted: false,
      sequence,
      state: "INSTALLING",
      step,
    };
    const artifact = bytes(entry);
    journalEntries.push(artifact);
    previousArtifactSha256 = h(artifact);
  });
  const terminal = {
    schema: "platform.v1-phase-b-install-journal-terminal/v1",
    activationPerformed: false,
    appendContract: {
      appendOnlyRequired: true,
      descriptorNoFollowRequired: true,
      fileFsyncRequired: true,
      noTruncateRequired: true,
      openFlags: ["O_APPEND", "O_NOFOLLOW", "O_WRONLY"],
      replacementAllowed: false,
    },
    binding,
    dataRollbackAuthority: false,
    failure: null,
    journalEntryCount: expected.steps.length,
    previousArtifactSha256,
    recordedAt: "2026-08-11T10:00:06.000Z",
    resumeAllowed: false,
    rollbackAttempted: false,
    sequence: expected.steps.length + 1,
    state: "INSTALLED_NON_ACTIVATING",
    terminal: true,
    terminalIdSha256: h([
      "phase-b-journal-terminal-v1", keys.ledgerEntryKeySha256,
      String(expected.steps.length + 1), previousArtifactSha256,
      "INSTALLED_NON_ACTIVATING",
    ].join("\0")),
  };
  const terminalArtifact = bytes(terminal);
  const journalArtifact = Buffer.concat([...journalEntries, terminalArtifact]);
  const claimIdentity = identity({
    kind: "REPLAY_CLAIM",
    pathname: keys.claimObjectPath,
    sha256: h(claimArtifact),
    sizeBytes: claimArtifact.length,
    seed: "claim",
    device: expected.ledgerParentDeviceIdentity,
    filesystem: expected.ledgerParentFilesystemUuid,
    mount: expected.ledgerParentMountId,
  });
  const journalIdentity = identity({
    kind: "LEDGER_RECORD",
    pathname: keys.journalRecordPath,
    sha256: h(journalArtifact),
    sizeBytes: journalArtifact.length,
    seed: "journal",
    device: expected.journalParentDeviceIdentity,
    filesystem: expected.journalParentFilesystemUuid,
    mount: expected.journalParentMountId,
  });
  const executionReceipt = {
    schema: "platform.v1-phase-b-bootstrap-execution-receipt/v1",
    activationPerformed: false,
    binding,
    claimArtifactSha256: h(claimArtifact),
    claimCreatedAt: claim.createdAt,
    claimSizeBytes: claimArtifact.length,
    claimWrite: {
      atomicCreateExclusive: true,
      descriptorNoFollow: true,
      fileFsyncCompleted: true,
      objectIdentity: claimIdentity,
      parentFsyncCompleted: true,
    },
    consumedAt: "2026-08-11T10:00:00.500Z",
    dataRollbackAuthority: false,
    failureTerminal: true,
    firstNonClaimMutationAt: journalEntries.length
      ? JSON.parse(journalEntries[0]).recordedAt
      : terminal.recordedAt,
    firstWritePath: keys.claimObjectPath,
    journalArtifactSha256: h(journalArtifact),
    journalEntryCount: journalEntries.length,
    journalRecordSizeBytes: journalArtifact.length,
    journalRecordWrittenAt: terminal.recordedAt,
    journalWrite: {
      appendOnly: true,
      createdExclusive: true,
      descriptorNoFollow: true,
      fileFsyncCompleted: true,
      journalNegativeLookupReceiptSha256: expected.journalNegativeLookupReceiptSha256,
      journalParentIdentitySha256: expected.journalParentIdentitySha256,
      objectIdentity: journalIdentity,
      parentFsyncCompleted: true,
    },
    mutationScope: "PINNED_CONTROL_PLANE_INSTALL_ONLY",
    receiptPreparedAt: "2026-08-11T10:00:07.000Z",
    receiptWriteRequirements: {
      createdExclusiveRequired: true,
      descriptorNoFollowRequired: true,
      fileFsyncRequired: true,
      openFlags: ["O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_WRONLY"],
      parentFsyncRequired: true,
      receiptNegativeLookupReceiptSha256: expected.receiptNegativeLookupReceiptSha256,
      receiptParentIdentitySha256: expected.receiptParentIdentitySha256,
    },
    replayRejected: true,
    resumeAllowed: false,
    rollbackAttempted: false,
    sequence: terminal.sequence + 1,
    state: terminal.state,
    terminalArtifactSha256: h(terminalArtifact),
  };
  return {
    expected,
    claim,
    claimArtifact,
    journalEntries,
    journalArtifact,
    terminal,
    terminalArtifact,
    executionReceipt,
    executionReceiptArtifact: bytes(executionReceipt),
    keys,
  };
}

function verify(fixture) {
  return verifyV1PhaseBReplayArtifacts({
    expected: fixture.expected,
    claimArtifact: fixture.claimArtifact,
    journalArtifact: fixture.journalArtifactOverride
      ?? Buffer.concat([...fixture.journalEntries, fixture.terminalArtifact]),
    executionReceiptArtifact: fixture.executionReceiptArtifact,
  });
}

function rebuild(fixture) {
  fixture.claimArtifact = bytes(fixture.claim);
  fixture.journalEntries = [];
  let previous = h(fixture.claimArtifact);
  fixture.expected.steps.forEach((step, index) => {
    const sequence = index + 1;
    const entry = clone(JSON.parse(makeFixture().journalEntries[index]));
    entry.binding = clone(fixture.claim.binding);
    entry.step = clone(step);
    entry.sequence = sequence;
    entry.previousArtifactSha256 = previous;
    entry.entryIdSha256 = h([
      "phase-b-journal-entry-v1", fixture.keys.ledgerEntryKeySha256,
      String(sequence), previous, step.inputDigestSha256,
    ].join("\0"));
    const artifact = bytes(entry);
    fixture.journalEntries.push(artifact);
    previous = h(artifact);
  });
  fixture.terminal.binding = clone(fixture.claim.binding);
  fixture.terminal.previousArtifactSha256 = previous;
  fixture.terminal.journalEntryCount = fixture.journalEntries.length;
  fixture.terminal.sequence = fixture.journalEntries.length + 1;
  fixture.terminal.terminalIdSha256 = h([
    "phase-b-journal-terminal-v1", fixture.keys.ledgerEntryKeySha256,
    String(fixture.terminal.sequence), previous, fixture.terminal.state,
  ].join("\0"));
  fixture.terminalArtifact = bytes(fixture.terminal);
  const journalArtifact = Buffer.concat([...fixture.journalEntries, fixture.terminalArtifact]);
  fixture.journalArtifact = journalArtifact;
  fixture.executionReceipt.binding = clone(fixture.claim.binding);
  fixture.executionReceipt.claimArtifactSha256 = h(fixture.claimArtifact);
  fixture.executionReceipt.claimSizeBytes = fixture.claimArtifact.length;
  Object.assign(fixture.executionReceipt.claimWrite.objectIdentity, {
    path: fixture.keys.claimObjectPath,
    sha256: h(fixture.claimArtifact),
    sizeBytes: fixture.claimArtifact.length,
  });
  fixture.executionReceipt.journalArtifactSha256 = h(journalArtifact);
  fixture.executionReceipt.journalEntryCount = fixture.journalEntries.length;
  fixture.executionReceipt.journalRecordSizeBytes = journalArtifact.length;
  Object.assign(fixture.executionReceipt.journalWrite.objectIdentity, {
    path: fixture.keys.journalRecordPath,
    sha256: h(journalArtifact),
    sizeBytes: journalArtifact.length,
  });
  fixture.executionReceipt.sequence = fixture.terminal.sequence + 1;
  fixture.executionReceipt.state = fixture.terminal.state;
  fixture.executionReceipt.terminalArtifactSha256 = h(fixture.terminalArtifact);
  fixture.executionReceiptArtifact = bytes(fixture.executionReceipt);
  return fixture;
}

function rebindAndRebuild(fixture) {
  fixture.claim.binding = bindingFrom(fixture.expected, fixture.keys);
  fixture.executionReceipt.binding = clone(fixture.claim.binding);
  return rebuild(fixture);
}

test("accepts exact canonical claim, chained append journal, terminal and execution receipt bytes", () => {
  const result = verify(makeFixture());
  assert.deepEqual(result, {
    schema: "platform.v1-phase-b-replay-artifacts-verification/v1",
    activation: false,
    authoritative: false,
    claimArtifactSha256: h(makeFixture().claimArtifact),
    dataRollback: false,
    executionReceiptArtifactSha256: h(makeFixture().executionReceiptArtifact),
    journalArtifactSha256: h(makeFixture().journalArtifact),
    mutation: false,
    nativeMaterializationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    nativeMaterializationVerified: false,
    replayArtifactBytesVerified: true,
    status: REPLAY_ARTIFACTS_VERIFIED_NON_AUTHORITATIVE,
    stdoutAuthority: false,
    terminalState: "INSTALLED_NON_ACTIVATING",
    trustedNativeLauncherRequired: true,
  });
  assert.equal(Object.isFrozen(result), true);
});

test("accepts a terminal failure without granting resume, rollback, activation, or data rollback", () => {
  const fixture = makeFixture();
  fixture.expected.steps = fixture.expected.steps.slice(0, 2);
  fixture.terminal.state = "FAILED_TERMINAL";
  fixture.terminal.failure = {
    code: "TARGET_IDENTITY_MISMATCH",
    evidenceSha256: h("failure-evidence"),
    failedStepId: fixture.expected.steps.at(-1).stepId,
  };
  fixture.executionReceipt.state = "FAILED_TERMINAL";
  rebuild(fixture);
  const result = verify(fixture);
  assert.equal(result.terminalState, "FAILED_TERMINAL");
  assert.equal(result.mutation, false);
  assert.equal(result.activation, false);
  assert.equal(result.dataRollback, false);
});

test("rejects noncanonical bytes, duplicate JSON keys, extra properties, and non-Buffer inputs", () => {
  assert.throws(() => canonicalJson(new Date()), /plain JSON objects/);
  const pretty = makeFixture();
  pretty.claimArtifact = Buffer.from(JSON.stringify(pretty.claim, null, 2) + "\n");
  assert.throws(() => verify(pretty), /canonical JSON bytes/);

  const duplicate = makeFixture();
  const canonical = duplicate.claimArtifact.toString("utf8");
  duplicate.claimArtifact = Buffer.from(canonical.replace("{", "{\"schema\":\"duplicate\","));
  assert.throws(() => verify(duplicate), /canonical JSON bytes/);

  const extra = makeFixture();
  extra.claim.unexpected = true;
  extra.claimArtifact = bytes(extra.claim);
  assert.throws(() => verify(extra), /schema validation failed/);

  const text = makeFixture();
  text.claimArtifact = text.claimArtifact.toString("utf8");
  assert.throws(() => verify(text), /must be raw Buffer bytes/);

  const bom = makeFixture();
  bom.claimArtifact = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bom.claimArtifact]);
  assert.throws(() => verify(bom), /valid JSON|canonical JSON bytes/);

  const doubleLf = makeFixture();
  doubleLf.claimArtifact = Buffer.concat([doubleLf.claimArtifact, Buffer.from("\n")]);
  assert.throws(() => verify(doubleLf), /canonical JSON bytes/);

  const oversized = makeFixture();
  oversized.claimArtifact = Buffer.alloc((4 * 1024 * 1024) + 1, 0x20);
  assert.throws(() => verify(oversized), /size boundary/);

  const tooMany = makeFixture();
  tooMany.journalArtifactOverride = Buffer.from("{}\n".repeat(4098), "utf8");
  assert.throws(() => verify(tooMany), /bounded record count/);

  const ambiguousJournal = makeFixture();
  ambiguousJournal.journalArtifactOverride = Buffer.concat([
    ambiguousJournal.journalArtifact,
    Buffer.from("\n"),
  ]);
  assert.throws(() => verify(ambiguousJournal), /canonical JSONL|empty|record/i);
});

test("uses unambiguous canonical JSONL with exactly one LF delimiter per append record", () => {
  const fixture = makeFixture();
  const records = [...fixture.journalEntries, fixture.terminalArtifact];
  records.forEach((record) => {
    assert.equal(record.at(-1), 0x0a);
    assert.equal(record.subarray(0, -1).includes(0x0a), false);
    assert.deepEqual(bytes(JSON.parse(record)), record);
  });
  const journal = Buffer.concat(records);
  assert.equal(journal.filter((byte) => byte === 0x0a).length, records.length);
});

test("rejects any binding drift and re-derives both domain-separated path keys", () => {
  for (const key of [
    "transactionId", "authorizationId", "authorizationEnvelopeSha256", "nonce",
    "policySha256", "preinstallTupleSha256", "packageBytesSha256",
    "packageManifestSha256", "packageInputObservationSha256", "ledgerEntryKeySha256",
    "claimObjectPath", "journalRecordPath", "receiptId", "receiptObjectKeySha256",
    "receiptObjectPath",
  ]) {
    const fixture = makeFixture();
    fixture.claim.binding[key] = key === "nonce" ? nonce("drift") : h("drift:" + key);
    fixture.claimArtifact = bytes(fixture.claim);
    assert.throws(() => verify(fixture), /binding|domain-separated|canonical replay/i, key);
  }

  const fixture = makeFixture();
  fixture.expected.ledgerEntryKeySha256 = h("caller-forged-ledger-key");
  assert.throws(() => verify(fixture), /domain-separated ledger entry key/);

  const typeConfusion = makeFixture();
  typeConfusion.expected.packageManifestSha256 = typeConfusion.expected.packageBytesSha256;
  assert.throws(() => verify(typeConfusion), /typed hashes.*pairwise distinct/);
});

test("rejects broken sequence, artifact hash chain, timestamp monotonicity and step coverage", () => {
  const sequence = makeFixture();
  const entry = JSON.parse(sequence.journalEntries[1]);
  entry.sequence = 9;
  sequence.journalEntries[1] = bytes(entry);
  assert.throws(() => verify(sequence), /contiguous|sequence/);

  const chain = makeFixture();
  const chained = JSON.parse(chain.journalEntries[1]);
  chained.previousArtifactSha256 = h("wrong-prior");
  chain.journalEntries[1] = bytes(chained);
  assert.throws(() => verify(chain), /hash chain/);

  const time = makeFixture();
  const timed = JSON.parse(time.journalEntries[1]);
  timed.recordedAt = "2026-08-11T10:00:01.000Z";
  time.journalEntries[1] = bytes(timed);
  assert.throws(() => verify(time), /timestamps.*strictly monotonic/i);

  const step = makeFixture();
  const changed = JSON.parse(step.journalEntries[0]);
  changed.step.inputDigestSha256 = h("substituted-input");
  step.journalEntries[0] = bytes(changed);
  assert.throws(() => verify(step), /exact expected install step/);
});

test("enforces the immutable authorization window across every causal replay timestamp", () => {
  const exactBoundaries = makeFixture();
  exactBoundaries.expected.authorizationIssuedAt = exactBoundaries.claim.createdAt;
  exactBoundaries.executionReceipt.consumedAt = exactBoundaries.claim.createdAt;
  exactBoundaries.expected.authorizationExpiresAt = exactBoundaries.executionReceipt.receiptPreparedAt;
  rebindAndRebuild(exactBoundaries);
  assert.equal(verify(exactBoundaries).status, REPLAY_ARTIFACTS_VERIFIED_NON_AUTHORITATIVE);

  const beforeIssue = makeFixture();
  beforeIssue.expected.authorizationIssuedAt = "2026-08-11T10:00:00.001Z";
  rebindAndRebuild(beforeIssue);
  assert.throws(() => verify(beforeIssue), /timestamps.*monotonic|authorization/i);

  const claimAfterConsume = makeFixture();
  claimAfterConsume.claim.createdAt = "2026-08-11T10:00:00.600Z";
  claimAfterConsume.executionReceipt.claimCreatedAt = claimAfterConsume.claim.createdAt;
  rebuild(claimAfterConsume);
  assert.throws(() => verify(claimAfterConsume), /timestamps.*monotonic/i);

  const consumeAfterMutation = makeFixture();
  consumeAfterMutation.executionReceipt.consumedAt = "2026-08-11T10:00:03.000Z";
  consumeAfterMutation.executionReceiptArtifact = bytes(consumeAfterMutation.executionReceipt);
  assert.throws(() => verify(consumeAfterMutation), /timestamps.*monotonic/i);

  const firstMutationDrift = makeFixture();
  firstMutationDrift.executionReceipt.firstNonClaimMutationAt = "2026-08-11T10:00:03.000Z";
  firstMutationDrift.executionReceiptArtifact = bytes(firstMutationDrift.executionReceipt);
  assert.throws(() => verify(firstMutationDrift), /timestamps.*monotonic/i);

  const journalBeforeTerminal = makeFixture();
  journalBeforeTerminal.executionReceipt.journalRecordWrittenAt = "2026-08-11T10:00:05.999Z";
  journalBeforeTerminal.executionReceiptArtifact = bytes(journalBeforeTerminal.executionReceipt);
  assert.throws(() => verify(journalBeforeTerminal), /timestamps.*monotonic/i);

  const receiptAfterExpiry = makeFixture();
  receiptAfterExpiry.executionReceipt.receiptPreparedAt = "2026-08-11T10:05:00.001Z";
  receiptAfterExpiry.executionReceiptArtifact = bytes(receiptAfterExpiry.executionReceipt);
  assert.throws(() => verify(receiptAfterExpiry), /timestamps.*monotonic/i);
});

test("derives every leaf path from domain-separated digests, never from raw opaque IDs", () => {
  const fixture = makeFixture();
  const adversarial = {
    ...fixture.expected,
    authorizationId: "phase-b/authorization/../../raw-id",
    receiptId: "install-receipt/../../raw-id",
  };
  const keys = deriveReplayArtifactKeys(adversarial);
  assert.match(keys.claimObjectPath, /^\/var\/lib\/\.platform-v1-phase-b-claim-[a-f0-9]{64}$/);
  assert.match(keys.journalRecordPath, /^\/var\/lib\/platform-infrastructure\/v1-phase-b-ledger\/[a-f0-9]{64}\.json$/);
  assert.match(keys.receiptObjectPath, /^\/var\/lib\/platform-infrastructure\/v1-install-receipts\/sha256\/[a-f0-9]{64}\.json$/);
  for (const pathname of [keys.claimObjectPath, keys.journalRecordPath, keys.receiptObjectPath]) {
    assert.doesNotMatch(pathname, /raw-id|\.\./);
  }
});

test("rejects each execution-receipt binding independently", () => {
  const mutations = [
    (r) => { r.claimArtifactSha256 = h("wrong-claim"); },
    (r) => { r.claimSizeBytes += 1; },
    (r) => { r.journalArtifactSha256 = h("wrong-journal"); },
    (r) => { r.journalRecordSizeBytes += 1; },
    (r) => { r.journalEntryCount += 1; },
    (r) => { r.terminalArtifactSha256 = h("wrong-terminal"); },
    (r) => { r.sequence += 1; },
    (r) => { r.firstWritePath = `/var/lib/.platform-v1-phase-b-claim-${h("other")}`; },
    (r) => { r.journalWrite.journalNegativeLookupReceiptSha256 = h("wrong-negative"); },
    (r) => { r.journalWrite.journalParentIdentitySha256 = h("wrong-journal-parent"); },
    (r) => { r.receiptWriteRequirements.receiptNegativeLookupReceiptSha256 = h("wrong-receipt-negative"); },
    (r) => { r.receiptWriteRequirements.receiptParentIdentitySha256 = h("wrong-receipt-parent"); },
  ];
  mutations.forEach((mutate, index) => {
    const fixture = makeFixture();
    mutate(fixture.executionReceipt);
    fixture.executionReceiptArtifact = bytes(fixture.executionReceipt);
    assert.throws(() => verify(fixture), /execution receipt|identity/i, String(index));
  });
});

test("rejects claim-not-first, resume, rollback, activation, replacement and missing durability controls", () => {
  const cases = [
    ["claim", (f) => { f.claim.sequence = 1; }],
    ["claim", (f) => { f.claim.writeContract.firstWriteRequired = false; }],
    ["claim", (f) => { f.claim.writeContract.atomicCreateExclusiveRequired = false; }],
    ["claim", (f) => { f.claim.writeContract.descriptorNoFollowRequired = false; }],
    ["claim", (f) => { f.claim.writeContract.fileFsyncRequired = false; }],
    ["claim", (f) => { f.claim.writeContract.parentFsyncRequired = false; }],
    ["entry", (f) => {
      const entry = JSON.parse(f.journalEntries[0]);
      entry.resumeAllowed = true;
      f.journalEntries[0] = bytes(entry);
    }],
    ["entry", (f) => {
      const entry = JSON.parse(f.journalEntries[0]);
      entry.appendContract.replacementAllowed = true;
      f.journalEntries[0] = bytes(entry);
    }],
    ["terminal", (f) => { f.terminal.rollbackAttempted = true; }],
    ["terminal", (f) => { f.terminal.activationPerformed = true; }],
    ["receipt", (f) => { f.executionReceipt.dataRollbackAuthority = true; }],
    ["receipt", (f) => { f.executionReceipt.receiptWriteRequirements.createdExclusiveRequired = false; }],
  ];
  for (const [where, mutate] of cases) {
    const fixture = makeFixture();
    mutate(fixture);
    if (where === "claim") fixture.claimArtifact = bytes(fixture.claim);
    if (where === "terminal") fixture.terminalArtifact = bytes(fixture.terminal);
    if (where === "receipt") fixture.executionReceiptArtifact = bytes(fixture.executionReceipt);
    assert.throws(() => verify(fixture), /claim|first|resume|rollback|activation|replacement|durab|exclusive|authority|schema/i);
  }
});

test("rejects identity/path/hash/size drift and does not claim receipt materialization", () => {
  const journalParentBinding = makeFixture();
  journalParentBinding.expected.journalParentIdentitySha256 = h("substituted-journal-parent");
  assert.throws(() => verify(journalParentBinding), /journal parent identity/i);

  const claimIdentity = makeFixture();
  claimIdentity.executionReceipt.claimWrite.objectIdentity.mountId = "999";
  claimIdentity.executionReceiptArtifact = bytes(claimIdentity.executionReceipt);
  assert.throws(() => verify(claimIdentity), /trusted ledger parent filesystem/);

  const journalIdentity = makeFixture();
  journalIdentity.executionReceipt.journalWrite.objectIdentity.sha256 = h("wrong-journal");
  journalIdentity.executionReceiptArtifact = bytes(journalIdentity.executionReceipt);
  assert.throws(() => verify(journalIdentity), /journal object identity/);

  const sameObject = makeFixture();
  sameObject.expected.journalParentDeviceIdentity = sameObject.expected.ledgerParentDeviceIdentity;
  sameObject.expected.journalParentFilesystemUuid = sameObject.expected.ledgerParentFilesystemUuid;
  sameObject.expected.journalParentMountId = sameObject.expected.ledgerParentMountId;
  Object.assign(sameObject.executionReceipt.journalWrite.objectIdentity, {
    deviceIdentity: sameObject.expected.ledgerParentDeviceIdentity,
    filesystemUuid: sameObject.expected.ledgerParentFilesystemUuid,
    inode: sameObject.executionReceipt.claimWrite.objectIdentity.inode,
    mountId: sameObject.expected.ledgerParentMountId,
  });
  sameObject.executionReceiptArtifact = bytes(sameObject.executionReceipt);
  assert.throws(() => verify(sameObject), /distinct filesystem objects/);

  const typedIdentityConfusion = makeFixture();
  typedIdentityConfusion.executionReceipt.claimWrite.objectIdentity.identityReceiptSha256 =
    typedIdentityConfusion.expected.packageBytesSha256;
  typedIdentityConfusion.executionReceiptArtifact = bytes(typedIdentityConfusion.executionReceipt);
  assert.throws(() => verify(typedIdentityConfusion), /typed hashes.*pairwise distinct/i);

  const result = verify(makeFixture());
  assert.equal(result.nativeMaterializationVerified, false);
  assert.equal(result.nativeMaterializationStatus, "EXTERNAL_ROOT_CONSUMER_REQUIRED");
  assert.equal(Object.hasOwn(result, "receiptObjectIdentity"), false);
});

test("schemas are closed and the module exposes the frozen core ledger key parity", () => {
  for (const filename of SCHEMAS) {
    const schema = JSON.parse(fs.readFileSync(filename, "utf8"));
    assert.equal(schema.additionalProperties, false, path.basename(filename));
    assert.equal(schema.type, "object", path.basename(filename));
  }
  const coreSource = fs.readFileSync(CORE, "utf8");
  assert.equal(h(Buffer.from(coreSource)), FROZEN_CORE_ADMISSION_SHA256);
  const ledgerFunction = coreSource.match(
    /function exactPhaseBLedgerConsumption[\s\S]+?exactObject\(value, "Phase B replay-ledger consumption", \[([\s\S]+?)\]\);/,
  );
  assert.ok(ledgerFunction, "frozen core ledger validator was not found");
  const frozenCoreKeys = [...ledgerFunction[1].matchAll(/"([A-Za-z][A-Za-z0-9]+)"/g)]
    .map((match) => match[1]);
  assert.deepEqual(frozenCoreKeys, CORE_LEDGER_CONSUMPTION_KEYS);
  for (const key of CORE_LEDGER_CONSUMPTION_KEYS) {
    assert.match(coreSource, new RegExp(`(?:\"|')${key}(?:\"|')`), key);
  }
  assert.deepEqual(CORE_LEDGER_CONSUMPTION_KEYS, [
    "atomicCreateExclusive", "authorizationEnvelopeSha256", "authorizationId", "claimArtifactSha256",
    "claimCreatedAt", "claimDurablyCommitted", "claimFileFsyncCompleted", "claimId",
    "claimNegativeLookupReceiptSha256", "claimObjectIdentity", "claimObjectPath", "claimParentFsyncCompleted",
    "claimSizeBytes", "consumedAt", "failureTerminal", "firstNonClaimMutationAt", "firstWritePath",
    "journalArtifactSha256", "journalNegativeLookupReceiptSha256", "journalObjectIdentity",
    "journalParentIdentitySha256", "journalRecordCreatedExclusive", "journalRecordFsyncCompleted",
    "journalRecordPath", "journalRecordSizeBytes", "journalRecordWrittenAt", "ledgerAncestrySha256",
    "ledgerEntryKeySha256", "ledgerId", "ledgerParentIdentitySha256", "ledgerParentPath", "nonce",
    "receiptArtifactSha256", "receiptCreatedExclusive", "receiptFsyncCompleted", "receiptNegativeLookupReceiptSha256",
    "receiptObjectIdentity", "receiptObjectKeySha256", "receiptObjectPath", "receiptParentIdentitySha256",
    "receiptSizeBytes", "receiptStorePath", "receiptWrittenAt", "replayRejected", "schema", "state",
  ]);
});

test("all four schemas compile in strict Ajv2020 and accept the exact runtime fixture", () => {
  const fixture = makeFixture();
  const documents = [
    fixture.claim,
    JSON.parse(fixture.journalEntries[0]),
    fixture.terminal,
    fixture.executionReceipt,
  ];
  SCHEMAS.forEach((filename, index) => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormats(ajv);
    ajv.addSchema(JSON.parse(fs.readFileSync(COMMON_SCHEMA, "utf8")));
    const validate = ajv.compile(JSON.parse(fs.readFileSync(filename, "utf8")));
    assert.equal(validate(documents[index]), true, JSON.stringify(validate.errors));
  });
});

test("schema primitives exactly reject runtime-invalid paths, nonces, decimals, and timestamps", () => {
  const fixture = makeFixture();
  const validDocuments = [
    fixture.claim,
    JSON.parse(fixture.journalEntries[0]),
    fixture.terminal,
    fixture.executionReceipt,
  ];
  const validators = SCHEMAS.map((filename) => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormats(ajv);
    ajv.addSchema(JSON.parse(fs.readFileSync(COMMON_SCHEMA, "utf8")));
    return ajv.compile(JSON.parse(fs.readFileSync(filename, "utf8")));
  });

  validDocuments.forEach((document, index) => {
    const changed = clone(document);
    changed.binding.nonce = "_".repeat(43);
    assert.equal(validators[index](changed), false, `nonce schema ${index}`);
  });

  for (const invalidPath of ["/srv//x", "/srv/./x", "/srv/../x", "/srv/x/"]) {
    const changed = clone(validDocuments[1]);
    changed.step.targetPath = invalidPath;
    assert.equal(validators[1](changed), false, invalidPath);
  }

  const hugeDecimal = clone(validDocuments[3]);
  hugeDecimal.claimWrite.objectIdentity.inode = "9007199254740992";
  assert.equal(validators[3](hugeDecimal), false, "unsafe decimal");

  const timestampFields = ["createdAt", "recordedAt", "recordedAt", "receiptPreparedAt"];
  validDocuments.forEach((document, index) => {
    const changed = clone(document);
    changed[timestampFields[index]] = "2026-08-11T23:59:60.000Z";
    assert.equal(validators[index](changed), false, `leap-second timestamp schema ${index}`);
  });
});

test("implementation is validate-only and contains no write, signing, minting, child process, network, Docker, or activation sink", () => {
  const source = fs.readFileSync(MODULE, "utf8");
  assert.doesNotMatch(source, /node:child_process|node:net|node:http|node:https|node:dgram/);
  assert.doesNotMatch(source, /\b(?:exec|execFile|spawn|fork|sign|generateKeyPair|randomBytes|randomUUID)Sync?\s*\(/);
  assert.doesNotMatch(source, /\b(?:writeFile|appendFile|rename|unlink|rm|mkdir|chmod|chown|copyFile|createWriteStream)Sync?\s*\(/);
  assert.doesNotMatch(source, /docker|systemctl|sudo\s|\bactivate\b/i);
  assert.doesNotMatch(source, /--journal-entry|--terminal\b|journalEntryArtifacts/);
  assert.match(source, /journalArtifact/);
  assert.match(source, /O_NONBLOCK/);
});

test("CLI requires explicit --verify, reads canonical files no-follow, and exits 78 after validation", () => {
  const fixture = makeFixture();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "v1-replay-artifacts-"));
  try {
    const write = (name, content) => {
      const filename = path.join(directory, name);
      fs.writeFileSync(filename, content);
      return filename;
    };
    const expected = write("expected.json", bytes(fixture.expected));
    const claim = write("claim.json", fixture.claimArtifact);
    const journal = write("journal.jsonl", fixture.journalArtifact);
    const receipt = write("receipt.json", fixture.executionReceiptArtifact);
    const args = [
      MODULE, "--verify", "--expected", expected, "--claim", claim,
      "--journal", journal, "--execution-receipt", receipt,
    ];
    const result = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.equal(result.status, 78, result.stderr);
    assert.equal(JSON.parse(result.stdout).status, REPLAY_ARTIFACTS_VERIFIED_NON_AUTHORITATIVE);

    const implicit = spawnSync(process.execPath, args.filter((value) => value !== "--verify"), { encoding: "utf8" });
    assert.notEqual(implicit.status, 0);
    assert.match(implicit.stderr, /--verify/);

    const symlink = path.join(directory, "claim-link.json");
    fs.symlinkSync(claim, symlink);
    const linked = spawnSync(process.execPath, args.map((value) => value === claim ? symlink : value), { encoding: "utf8" });
    assert.notEqual(linked.status, 78);
    assert.match(linked.stderr, /non-symlink|safe capture|O_NOFOLLOW/);

    const aliasedArgs = args.map((value) => value === journal ? claim : value);
    const aliased = spawnSync(process.execPath, aliasedArgs, { encoding: "utf8" });
    assert.notEqual(aliased.status, 78);
    assert.match(aliased.stderr, /distinct filesystem objects/);

    const hardlink = path.join(directory, "receipt-hardlink.json");
    fs.linkSync(receipt, hardlink);
    const hardlinked = spawnSync(
      process.execPath,
      args.map((value) => value === receipt ? hardlink : value),
      { encoding: "utf8" },
    );
    assert.notEqual(hardlinked.status, 78);
    assert.match(hardlinked.stderr, /singly linked/);
    fs.unlinkSync(hardlink);

    const fifo = path.join(directory, "claim.fifo");
    const fifoCreated = spawnSync("/usr/bin/mkfifo", [fifo], { encoding: "utf8" });
    assert.equal(fifoCreated.status, 0, fifoCreated.stderr);
    const fifoResult = spawnSync(
      process.execPath,
      args.map((value) => value === claim ? fifo : value),
      { encoding: "utf8", timeout: 3000 },
    );
    assert.equal(fifoResult.signal, null, "FIFO input must fail without blocking");
    assert.notEqual(fifoResult.status, 78);
    assert.match(fifoResult.stderr, /regular non-symlink/);

    const maxPlusOne = write("max-plus-one.json", Buffer.alloc((4 * 1024 * 1024) + 1, 0x20));
    const oversized = spawnSync(
      process.execPath,
      args.map((value) => value === claim ? maxPlusOne : value),
      { encoding: "utf8" },
    );
    assert.notEqual(oversized.status, 78);
    assert.match(oversized.stderr, /bounded regular/);

    const replacement = write("expected-replacement.json", bytes(fixture.expected));
    const raceHook = write("race-hook.cjs", Buffer.from([
      "const fs = require('node:fs');",
      "const original = fs.readSync;",
      "const target = fs.statSync(process.env.RACE_PATH);",
      "let swapped = false;",
      "fs.readSync = function (...args) {",
      "  const result = original.apply(this, args);",
      "  const current = fs.fstatSync(args[0]);",
      "  if (!swapped && current.dev === target.dev && current.ino === target.ino) {",
      "    swapped = true;",
      "    fs.renameSync(process.env.RACE_PATH, process.env.RACE_OLD);",
      "    fs.renameSync(process.env.RACE_REPLACEMENT, process.env.RACE_PATH);",
      "  }",
      "  return result;",
      "};",
      "require('node:module').syncBuiltinESMExports();",
      "",
    ].join("\n"), "utf8"));
    const raced = spawnSync(
      process.execPath,
      ["--require", raceHook, ...args],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          RACE_OLD: path.join(directory, "expected-original.json"),
          RACE_PATH: expected,
          RACE_REPLACEMENT: replacement,
        },
      },
    );
    assert.notEqual(raced.status, 78, raced.stderr);
    assert.match(raced.stderr, /changed during safe capture|safe capture failed/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
