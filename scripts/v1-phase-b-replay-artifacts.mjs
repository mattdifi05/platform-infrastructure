#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

export const REPLAY_ARTIFACTS_VERIFIED_NON_AUTHORITATIVE =
  "VERIFIED-NON-AUTHORITATIVE";
export const FROZEN_CORE_ADMISSION_SHA256 =
  "11d1a252d90eccd3561fd19675a9c2b7646cd9df1ba9b16f85b57f406c2cd9a8";

export const CORE_LEDGER_CONSUMPTION_KEYS = Object.freeze([
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

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.dirname(HERE);
const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$/;
const OPAQUE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{7,255}$/;
const POSITIVE_DECIMAL = /^[1-9][0-9]*$/;
const EXPECTATION_SCHEMA = "platform.v1-phase-b-replay-artifact-expectation/v1";
const LEDGER_ID = "platform-v1-phase-b-installer-ledger";
const JOURNAL_STORE = "/var/lib/platform-infrastructure/v1-phase-b-ledger";
const RECEIPT_STORE = "/var/lib/platform-infrastructure/v1-install-receipts/sha256";
const EXPECTED_KEYS = Object.freeze([
  "authorizationEnvelopeSha256", "authorizationExpiresAt", "authorizationId", "authorizationIssuedAt",
  "claimId", "claimNegativeLookupReceiptSha256",
  "claimObjectPath", "journalNegativeLookupReceiptSha256", "journalParentDeviceIdentity",
  "journalParentFilesystemUuid", "journalParentIdentitySha256", "journalParentMountId", "journalRecordPath",
  "journalStorePath",
  "ledgerAncestrySha256", "ledgerEntryKeySha256", "ledgerId", "ledgerParentDeviceIdentity",
  "ledgerParentFilesystemUuid", "ledgerParentIdentitySha256", "ledgerParentMountId", "ledgerParentPath",
  "nonce", "packageBytesSha256", "packageInputObservationSha256", "packageManifestSha256", "policySha256",
  "preinstallTupleSha256", "receiptId", "receiptNegativeLookupReceiptSha256",
  "receiptObjectKeySha256", "receiptObjectPath", "receiptParentIdentitySha256", "receiptStorePath", "schema", "steps",
  "transactionId",
]);
const BINDING_KEYS = Object.freeze([
  "authorizationEnvelopeSha256", "authorizationExpiresAt", "authorizationId", "authorizationIssuedAt",
  "claimId", "claimObjectPath", "journalParentIdentitySha256", "journalRecordPath", "journalStorePath",
  "ledgerEntryKeySha256", "ledgerId", "ledgerParentPath", "nonce", "packageBytesSha256", "packageInputObservationSha256",
  "packageManifestSha256", "policySha256", "preinstallTupleSha256", "receiptId",
  "receiptObjectKeySha256", "receiptObjectPath", "receiptStorePath", "transactionId",
]);
const STEP_KEYS = Object.freeze(["inputDigestSha256", "operation", "stepId", "targetPath"]);
const STEP_OPERATIONS = new Set([
  "CREATE_REQUIRED_DIRECTORY", "MATERIALIZE_PINNED_ARTIFACT", "VERIFY_MATERIALIZED_IDENTITY",
  "VERIFY_PRIVILEGE_POLICY", "VERIFY_POSTINSTALL_ANCESTRY", "VERIFY_RESOURCE_OUTCOME",
]);

const require = createRequire(path.join(REPO, "vendor", "json-schema", "package.json"));
const Ajv2020 = require("ajv/dist/2020");
const addFormats = require("ajv-formats");
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(JSON.parse(fs.readFileSync(
  path.join(REPO, "governance", "schemas", "v1-brownfield-common-tuple.schema.json"),
  "utf8",
)));
const schemaFiles = Object.freeze({
  claim: "v1-phase-b-replay-claim.schema.json",
  entry: "v1-phase-b-install-journal-entry.schema.json",
  terminal: "v1-phase-b-install-journal-terminal.schema.json",
  receipt: "v1-phase-b-bootstrap-execution-receipt.schema.json",
});
const validators = Object.fromEntries(Object.entries(schemaFiles).map(([kind, filename]) => {
  const schema = JSON.parse(fs.readFileSync(path.join(REPO, "governance", "schemas", filename), "utf8"));
  return [kind, ajv.compile(schema)];
}));

function invalid(message) {
  throw new Error(message);
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      invalid("Canonical JSON accepts only plain JSON objects.");
    }
    const result = {};
    for (const key of Object.keys(value).sort()) {
      if (value[key] === undefined) invalid("Canonical JSON cannot contain undefined values.");
      result[key] = stable(value[key]);
    }
    return result;
  }
  if (
    value === null || typeof value === "string" || typeof value === "boolean"
    || (typeof value === "number" && Number.isFinite(value))
  ) return value;
  invalid("Canonical JSON contains an unsupported value.");
}

export function canonicalJson(value) {
  return JSON.stringify(stable(value));
}

function canonicalEqual(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function deepFreeze(value) {
  if (ArrayBuffer.isView(value)) return value;
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function shaBytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function domainSeparatedSha256(domain, ...values) {
  return shaBytes(Buffer.from([domain, ...values].join("\0"), "utf8"));
}

function exactObject(value, keys, label) {
  if (
    !value || typeof value !== "object" || Array.isArray(value)
    || !canonicalEqual(Object.keys(value).sort(), [...keys].sort())
  ) invalid(`${label} does not use the exact closed schema.`);
  return value;
}

function exactSha(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    invalid(`${label} must be one lowercase SHA256.`);
  }
  return value;
}

function exactIdentifier(value, label, expression = IDENTIFIER) {
  if (typeof value !== "string" || !expression.test(value)) invalid(`${label} is not canonical.`);
  return value;
}

function exactNonce(value, label) {
  if (typeof value !== "string" || !NONCE.test(value)) invalid(`${label} is not one canonical nonce.`);
  const raw = Buffer.from(value, "base64url");
  if (raw.length !== 32 || raw.toString("base64url") !== value) {
    invalid(`${label} is not one canonical nonce.`);
  }
  return value;
}

function exactPositiveDecimal(value, label) {
  if (typeof value !== "string" || !POSITIVE_DECIMAL.test(value)) {
    invalid(`${label} must be one positive decimal string.`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || String(parsed) !== value) {
    invalid(`${label} exceeds the exact integer range.`);
  }
  return value;
}

function exactTimestamp(value, label) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    invalid(`${label} must be one canonical UTC timestamp.`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    invalid(`${label} must be one canonical UTC timestamp.`);
  }
  return milliseconds;
}

function exactPath(value, label) {
  if (
    typeof value !== "string" || !/^\/(?:[A-Za-z0-9._/-]+)?$/.test(value)
    || value.includes("//") || value.split("/").some((part) => part === "." || part === "..")
    || (value !== "/" && value.endsWith("/")) || path.posix.normalize(value) !== value
    || Buffer.byteLength(value, "utf8") > 4096
  ) invalid(`${label} must be one canonical absolute path.`);
  return value;
}

export function deriveReplayArtifactKeys(value = {}) {
  const ledgerEntryKeySha256 = domainSeparatedSha256(
    "phase-b-ledger-v1", value.authorizationId, value.nonce, value.transactionId,
    value.policySha256, value.preinstallTupleSha256,
  );
  const receiptObjectKeySha256 = domainSeparatedSha256(
    "install-receipt-v1", value.receiptId, value.transactionId,
  );
  return deepFreeze({
    claimId: `phase-b-claim:${ledgerEntryKeySha256}`,
    claimObjectPath: `/var/lib/.platform-v1-phase-b-claim-${ledgerEntryKeySha256}`,
    journalRecordPath: `${JOURNAL_STORE}/${ledgerEntryKeySha256}.json`,
    journalStorePath: JOURNAL_STORE,
    ledgerEntryKeySha256,
    receiptObjectKeySha256,
    receiptObjectPath: `${RECEIPT_STORE}/${receiptObjectKeySha256}.json`,
    receiptStorePath: RECEIPT_STORE,
  });
}

function validateExpectation(value) {
  exactObject(value, EXPECTED_KEYS, "Replay artifact expectation");
  if (value.schema !== EXPECTATION_SCHEMA || value.ledgerId !== LEDGER_ID || value.ledgerParentPath !== "/var/lib") {
    invalid("Replay artifact expectation identity is invalid.");
  }
  for (const key of [
    "authorizationEnvelopeSha256", "claimNegativeLookupReceiptSha256", "journalNegativeLookupReceiptSha256",
    "journalParentFilesystemUuid", "journalParentIdentitySha256", "ledgerAncestrySha256",
    "ledgerEntryKeySha256", "ledgerParentFilesystemUuid", "ledgerParentIdentitySha256",
    "packageBytesSha256", "packageInputObservationSha256", "packageManifestSha256", "policySha256",
    "preinstallTupleSha256", "receiptNegativeLookupReceiptSha256", "receiptObjectKeySha256",
    "receiptParentIdentitySha256", "transactionId",
  ]) exactSha(value[key], `Expectation ${key}`);
  exactIdentifier(value.authorizationId, "Expectation authorization ID", OPAQUE_IDENTIFIER);
  exactIdentifier(value.receiptId, "Expectation receipt ID", OPAQUE_IDENTIFIER);
  exactIdentifier(value.ledgerParentDeviceIdentity, "Expectation ledger parent device identity");
  exactIdentifier(value.journalParentDeviceIdentity, "Expectation journal parent device identity");
  exactPositiveDecimal(value.ledgerParentMountId, "Expectation ledger parent mount ID");
  exactPositiveDecimal(value.journalParentMountId, "Expectation journal parent mount ID");
  exactNonce(value.nonce, "Expectation nonce");
  const issuedAt = exactTimestamp(value.authorizationIssuedAt, "Expectation authorization issue time");
  const expiresAt = exactTimestamp(value.authorizationExpiresAt, "Expectation authorization expiry time");
  if (issuedAt >= expiresAt) invalid("Expectation authorization window is empty or reversed.");
  exactPath(value.claimObjectPath, "Expectation claim object path");
  exactPath(value.journalStorePath, "Expectation journal store path");
  exactPath(value.journalRecordPath, "Expectation journal record path");
  exactPath(value.receiptStorePath, "Expectation receipt store path");
  exactPath(value.receiptObjectPath, "Expectation receipt object path");
  const derived = deriveReplayArtifactKeys(value);
  for (const key of Object.keys(derived)) {
    if (value[key] !== derived[key]) invalid(`Expectation ${key} is not the exact domain-separated ledger entry key or path.`);
  }
  if (!Array.isArray(value.steps) || value.steps.length < 1 || value.steps.length > 4096) {
    invalid("Expectation must contain one bounded non-empty install step sequence.");
  }
  const stepIds = new Set();
  value.steps.forEach((step, index) => {
    exactObject(step, STEP_KEYS, `Expectation step ${index}`);
    exactSha(step.inputDigestSha256, `Expectation step ${index} input digest`);
    exactIdentifier(step.stepId, `Expectation step ${index} ID`);
    if (!STEP_OPERATIONS.has(step.operation)) invalid(`Expectation step ${index} operation is invalid.`);
    if (step.targetPath !== null) exactPath(step.targetPath, `Expectation step ${index} target path`);
    if (stepIds.has(step.stepId)) invalid("Expectation install step IDs must be unique.");
    stepIds.add(step.stepId);
  });
  const distinctEvidence = [
    value.authorizationEnvelopeSha256,
    value.claimNegativeLookupReceiptSha256,
    value.journalNegativeLookupReceiptSha256,
    value.journalParentIdentitySha256,
    value.ledgerAncestrySha256,
    value.ledgerEntryKeySha256,
    value.ledgerParentIdentitySha256,
    value.packageBytesSha256,
    value.packageInputObservationSha256,
    value.packageManifestSha256,
    value.policySha256,
    value.preinstallTupleSha256,
    value.receiptNegativeLookupReceiptSha256,
    value.receiptObjectKeySha256,
    value.receiptParentIdentitySha256,
    value.transactionId,
  ];
  if (new Set(distinctEvidence).size !== distinctEvidence.length) {
    invalid("Replay artifact typed hashes and absence receipts must be pairwise distinct.");
  }
  return deepFreeze({ document: value, expiresAt, issuedAt, typedHashes: distinctEvidence });
}

function expectedBinding(expected) {
  return Object.fromEntries(BINDING_KEYS.map((key) => [key, expected[key]]));
}

function parseCanonicalArtifact(input, kind, label) {
  if (!Buffer.isBuffer(input)) invalid(`${label} must be raw Buffer bytes.`);
  if (input.length < 3 || input.length > MAX_ARTIFACT_BYTES) {
    invalid(`${label} exceeds the exact artifact size boundary.`);
  }
  const snapshot = Buffer.from(input);
  let document;
  try {
    document = JSON.parse(snapshot.toString("utf8"));
  } catch {
    invalid(`${label} is not valid JSON.`);
  }
  const exactBytes = Buffer.from(canonicalJson(document) + "\n", "utf8");
  if (!snapshot.equals(exactBytes)) invalid(`${label} must be exact canonical JSON bytes with one trailing LF.`);
  const validator = validators[kind];
  if (!validator(document)) {
    const details = validator.errors.slice(0, 6)
      .map((error) => `${error.instancePath || "/"} ${error.message}`).join("; ");
    invalid(`${label} schema validation failed: ${details}.`);
  }
  return deepFreeze({ bytes: snapshot, document, sha256: shaBytes(snapshot), sizeBytes: snapshot.length });
}

function parseCanonicalJournal(input) {
  if (!Buffer.isBuffer(input)) invalid("Install journal must be raw Buffer bytes.");
  if (input.length < 6 || input.length > MAX_ARTIFACT_BYTES) {
    invalid("Install journal exceeds the exact artifact size boundary.");
  }
  const snapshot = Buffer.from(input);
  if (snapshot.at(-1) !== 0x0a) {
    invalid("Install journal must be unambiguous canonical JSONL ending in exactly one LF per record.");
  }
  const records = [];
  let start = 0;
  for (let index = 0; index < snapshot.length; index += 1) {
    if (snapshot[index] !== 0x0a) continue;
    if (index === start) invalid("Install journal contains an empty or ambiguous JSONL record.");
    records.push(snapshot.subarray(start, index + 1));
    if (records.length > 4097) invalid("Install journal exceeds the bounded record count.");
    start = index + 1;
  }
  if (start !== snapshot.length || records.length < 2) {
    invalid("Install journal must contain INSTALLING entries followed by one terminal record.");
  }
  const entries = records.slice(0, -1).map((record, index) => (
    parseCanonicalArtifact(record, "entry", `Install journal entry ${index + 1}`)
  ));
  const terminal = parseCanonicalArtifact(records.at(-1), "terminal", "Install journal terminal");
  return deepFreeze({
    bytes: snapshot,
    entries,
    sha256: shaBytes(snapshot),
    sizeBytes: snapshot.length,
    terminal,
  });
}

function validateBinding(value, expected, label) {
  const exact = expectedBinding(expected);
  if (!canonicalEqual(value, exact)) {
    if (value?.journalParentIdentitySha256 !== exact.journalParentIdentitySha256) {
      invalid(`${label} journal parent identity differs from the exact expected ledger binding.`);
    }
    invalid(`${label} does not preserve the exact transaction/authorization/nonce/policy/preinstall/package/input-digest/ledger binding.`);
  }
}

function expectedEntryId(entry, expected) {
  return domainSeparatedSha256(
    "phase-b-journal-entry-v1", expected.ledgerEntryKeySha256, String(entry.sequence),
    entry.previousArtifactSha256, entry.step.inputDigestSha256,
  );
}

function expectedTerminalId(terminal, expected) {
  return domainSeparatedSha256(
    "phase-b-journal-terminal-v1", expected.ledgerEntryKeySha256, String(terminal.sequence),
    terminal.previousArtifactSha256, terminal.state,
  );
}

function validateIdentity(value, { kind, pathname, sha256, sizeBytes, device, filesystem, mount }, label) {
  exactIdentifier(value.deviceIdentity, `${label} device identity`);
  exactSha(value.filesystemUuid, `${label} filesystem UUID`);
  exactSha(value.identityReceiptSha256, `${label} identity receipt`);
  exactPositiveDecimal(value.inode, `${label} inode`);
  exactPositiveDecimal(value.mountId, `${label} mount ID`);
  exactPath(value.path, `${label} path`);
  if (
    value.kind !== kind || value.path !== pathname || value.sha256 !== sha256 || value.sizeBytes !== sizeBytes
    || value.deviceIdentity !== device || value.filesystemUuid !== filesystem || value.mountId !== mount
    || value.descriptorNoFollow !== true || value.fileType !== "REGULAR_FILE" || value.uid !== 0
    || value.gid !== 0 || value.mode !== "0400" || value.nlink !== 1 || value.symlink !== false
  ) invalid(`${label} does not bind the exact artifact bytes on its trusted parent filesystem.`);
}

export function verifyV1PhaseBReplayArtifacts({
  expected,
  claimArtifact,
  journalArtifact,
  executionReceiptArtifact,
} = {}) {
  const expectationState = validateExpectation(structuredClone(expected));
  const expectation = expectationState.document;
  const claim = parseCanonicalArtifact(claimArtifact, "claim", "Replay claim");
  const journal = parseCanonicalJournal(journalArtifact);
  const entries = journal.entries;
  const terminal = journal.terminal;
  const receipt = parseCanonicalArtifact(executionReceiptArtifact, "receipt", "Bootstrap execution receipt");

  validateBinding(claim.document.binding, expectation, "Replay claim binding");
  if (
    claim.document.sequence !== 0 || claim.document.state !== "CLAIMED"
    || claim.document.ledgerParentPath !== expectation.ledgerParentPath
    || claim.document.ledgerParentIdentitySha256 !== expectation.ledgerParentIdentitySha256
    || claim.document.ledgerAncestrySha256 !== expectation.ledgerAncestrySha256
    || claim.document.writeContract.claimNegativeLookupReceiptSha256 !== expectation.claimNegativeLookupReceiptSha256
  ) invalid("Replay claim is not the exact pre-authorized canonical replay first write.");

  let previousSha256 = claim.sha256;
  let previousTime = exactTimestamp(claim.document.createdAt, "Replay claim creation time");
  entries.forEach((artifact, index) => {
    const entry = artifact.document;
    const sequence = index + 1;
    validateBinding(entry.binding, expectation, `Install journal entry ${sequence} binding`);
    if (entry.sequence !== sequence) invalid("Install journal sequence must be contiguous from one.");
    if (entry.previousArtifactSha256 !== previousSha256) invalid("Install journal artifact hash chain is invalid.");
    if (!canonicalEqual(entry.step, expectation.steps[index])) {
      invalid(`Install journal entry ${sequence} is not the exact expected install step.`);
    }
    if (entry.entryIdSha256 !== expectedEntryId(entry, expectation)) {
      invalid(`Install journal entry ${sequence} ID does not bind its exact hash-chain input.`);
    }
    const first = sequence === 1;
    const expectedFlags = first
      ? ["O_CREAT", "O_EXCL", "O_NOFOLLOW", "O_WRONLY"]
      : ["O_APPEND", "O_NOFOLLOW", "O_WRONLY"];
    if (
      entry.appendContract.createdExclusiveRequired !== first
      || entry.appendContract.parentFsyncRequired !== first
      || !canonicalEqual(entry.appendContract.openFlags, expectedFlags)
    ) invalid("Install journal append contract does not preserve first-create versus append-only semantics.");
    const time = exactTimestamp(entry.recordedAt, `Install journal entry ${sequence} time`);
    if (time <= previousTime) invalid("Replay artifact timestamps must be strictly monotonic.");
    previousTime = time;
    previousSha256 = artifact.sha256;
  });
  if (entries.length > expectation.steps.length) invalid("Install journal contains an unauthorized extra install step.");

  validateBinding(terminal.document.binding, expectation, "Install journal terminal binding");
  if (
    terminal.document.sequence !== entries.length + 1
    || terminal.document.journalEntryCount !== entries.length
  ) invalid("Install journal terminal sequence/count is not contiguous.");
  if (terminal.document.previousArtifactSha256 !== previousSha256) {
    invalid("Install journal terminal breaks the artifact hash chain.");
  }
  if (terminal.document.terminalIdSha256 !== expectedTerminalId(terminal.document, expectation)) {
    invalid("Install journal terminal ID does not bind the exact terminal hash-chain input.");
  }
  const terminalTime = exactTimestamp(terminal.document.recordedAt, "Install journal terminal time");
  if (terminalTime <= previousTime) invalid("Replay artifact timestamps must be strictly monotonic.");
  if (terminal.document.state === "INSTALLED_NON_ACTIVATING") {
    if (entries.length !== expectation.steps.length || terminal.document.failure !== null) {
      invalid("Installed terminal state requires exact complete step coverage and no failure payload.");
    }
  } else {
    if (
      !terminal.document.failure || entries.length > expectation.steps.length
      || terminal.document.failure.failedStepId !== entries.at(-1)?.document.step.stepId
    ) invalid("Failed terminal state must bind the last attempted authorized install step.");
  }

  const journalSha256 = journal.sha256;
  const execution = receipt.document;
  validateBinding(execution.binding, expectation, "Bootstrap execution receipt binding");
  if (
    execution.sequence !== terminal.document.sequence + 1 || execution.state !== terminal.document.state
    || execution.claimArtifactSha256 !== claim.sha256 || execution.claimSizeBytes !== claim.sizeBytes
    || execution.journalArtifactSha256 !== journalSha256 || execution.journalRecordSizeBytes !== journal.sizeBytes
    || execution.journalEntryCount !== entries.length || execution.terminalArtifactSha256 !== terminal.sha256
    || execution.firstWritePath !== expectation.claimObjectPath
    || execution.journalWrite.journalNegativeLookupReceiptSha256 !== expectation.journalNegativeLookupReceiptSha256
    || execution.journalWrite.journalParentIdentitySha256 !== expectation.journalParentIdentitySha256
    || execution.receiptWriteRequirements.receiptNegativeLookupReceiptSha256
      !== expectation.receiptNegativeLookupReceiptSha256
    || execution.receiptWriteRequirements.receiptParentIdentitySha256 !== expectation.receiptParentIdentitySha256
  ) invalid("Bootstrap execution receipt does not cross-bind the exact claim, journal, terminal, or ledger keys.");
  validateIdentity(execution.claimWrite.objectIdentity, {
    kind: "REPLAY_CLAIM", pathname: expectation.claimObjectPath, sha256: claim.sha256,
    sizeBytes: claim.sizeBytes, device: expectation.ledgerParentDeviceIdentity,
    filesystem: expectation.ledgerParentFilesystemUuid, mount: expectation.ledgerParentMountId,
  }, "Replay claim object identity on the trusted ledger parent filesystem");
  validateIdentity(execution.journalWrite.objectIdentity, {
    kind: "LEDGER_RECORD", pathname: expectation.journalRecordPath, sha256: journalSha256,
    sizeBytes: journal.sizeBytes, device: expectation.journalParentDeviceIdentity,
    filesystem: expectation.journalParentFilesystemUuid, mount: expectation.journalParentMountId,
  }, "Install journal object identity on the trusted journal parent filesystem");
  if (
    execution.claimWrite.objectIdentity.identityReceiptSha256
      === execution.journalWrite.objectIdentity.identityReceiptSha256
  ) invalid("Replay claim and journal object identity receipts must be distinct.");
  if (
    execution.claimWrite.objectIdentity.deviceIdentity
      === execution.journalWrite.objectIdentity.deviceIdentity
    && execution.claimWrite.objectIdentity.filesystemUuid
      === execution.journalWrite.objectIdentity.filesystemUuid
    && execution.claimWrite.objectIdentity.inode === execution.journalWrite.objectIdentity.inode
  ) invalid("Replay claim and journal must be distinct filesystem objects.");
  const allTypedHashes = [
    ...expectationState.typedHashes,
    claim.sha256,
    ...entries.map((entry) => entry.sha256),
    ...entries.map((entry) => entry.document.entryIdSha256),
    journal.sha256,
    terminal.sha256,
    terminal.document.terminalIdSha256,
    receipt.sha256,
    execution.claimWrite.objectIdentity.identityReceiptSha256,
    execution.journalWrite.objectIdentity.identityReceiptSha256,
    ...(terminal.document.failure === null ? [] : [terminal.document.failure.evidenceSha256]),
  ];
  if (new Set(allTypedHashes).size !== allTypedHashes.length) {
    invalid("Replay artifact typed hashes and identity receipts must be pairwise distinct.");
  }

  const claimTime = exactTimestamp(execution.claimCreatedAt, "Execution receipt claim time");
  const consumedTime = exactTimestamp(execution.consumedAt, "Execution receipt consume time");
  const mutationTime = exactTimestamp(execution.firstNonClaimMutationAt, "Execution receipt first mutation time");
  const journalTime = exactTimestamp(execution.journalRecordWrittenAt, "Execution receipt journal time");
  const preparedTime = exactTimestamp(execution.receiptPreparedAt, "Execution receipt preparation time");
  const firstEntryTime = exactTimestamp(entries[0].document.recordedAt, "First journal entry time");
  if (
    execution.claimCreatedAt !== claim.document.createdAt || mutationTime !== firstEntryTime
    || journalTime !== terminalTime
    || !(expectationState.issuedAt <= claimTime
      && claimTime <= consumedTime && consumedTime < mutationTime
      && mutationTime <= journalTime && journalTime <= terminalTime
      && terminalTime <= preparedTime
      && preparedTime <= expectationState.expiresAt)
  ) invalid("Claim, consume, first non-claim mutation, journal, and receipt timestamps are not strictly monotonic.");

  return deepFreeze({
    schema: "platform.v1-phase-b-replay-artifacts-verification/v1",
    activation: false,
    authoritative: false,
    claimArtifactSha256: claim.sha256,
    dataRollback: false,
    executionReceiptArtifactSha256: receipt.sha256,
    journalArtifactSha256: journalSha256,
    mutation: false,
    nativeMaterializationStatus: "EXTERNAL_ROOT_CONSUMER_REQUIRED",
    nativeMaterializationVerified: false,
    replayArtifactBytesVerified: true,
    status: REPLAY_ARTIFACTS_VERIFIED_NON_AUTHORITATIVE,
    stdoutAuthority: false,
    terminalState: terminal.document.state,
    trustedNativeLauncherRequired: true,
  });
}

function readBoundedDescriptor(descriptor, boundaryBytes, label) {
  const chunks = [];
  let total = 0;
  while (total < boundaryBytes) {
    const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, boundaryBytes - total));
    const count = fs.readSync(descriptor, chunk, 0, chunk.length, null);
    if (count === 0) return Buffer.concat(chunks, total);
    chunks.push(chunk.subarray(0, count));
    total += count;
  }
  invalid(`${label} grew beyond the exact read boundary.`);
}

function snapshotFile(filename, label) {
  if (typeof filename !== "string" || !path.isAbsolute(filename) || path.resolve(filename) !== filename) {
    invalid(`${label} path must be explicit, absolute, and canonical.`);
  }
  let initial;
  try {
    initial = fs.lstatSync(filename, { bigint: true });
  } catch (error) {
    invalid(`${label} safe capture failed: ${String(error?.message ?? error)}`);
  }
  if (!initial.isFile() || initial.isSymbolicLink() || initial.nlink !== 1n
      || initial.size < 3n || initial.size > BigInt(MAX_ARTIFACT_BYTES)) {
    invalid(`${label} must be one bounded regular non-symlink singly linked file.`);
  }
  if (typeof fs.constants.O_NOFOLLOW !== "number" || fs.constants.O_NOFOLLOW === 0
      || typeof fs.constants.O_NONBLOCK !== "number" || fs.constants.O_NONBLOCK === 0) {
    invalid(`${label} cannot be captured without O_NOFOLLOW and O_NONBLOCK.`);
  }
  let descriptor;
  try {
    descriptor = fs.openSync(
      filename,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    );
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.dev !== initial.dev || before.ino !== initial.ino
        || before.size !== initial.size || before.mtimeNs !== initial.mtimeNs || before.ctimeNs !== initial.ctimeNs) {
      invalid(`${label} changed before safe capture.`);
    }
    const bytes = readBoundedDescriptor(descriptor, MAX_ARTIFACT_BYTES + 1, label);
    const after = fs.fstatSync(descriptor, { bigint: true });
    const finalPath = fs.lstatSync(filename, { bigint: true });
    if (BigInt(bytes.length) !== before.size || !after.isFile() || after.nlink !== 1n
        || after.dev !== before.dev || after.ino !== before.ino
        || after.size !== before.size || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs
        || !finalPath.isFile() || finalPath.isSymbolicLink() || finalPath.nlink !== 1n
        || finalPath.dev !== before.dev || finalPath.ino !== before.ino || finalPath.size !== before.size
        || finalPath.mtimeNs !== before.mtimeNs || finalPath.ctimeNs !== before.ctimeNs) {
      invalid(`${label} changed during safe capture.`);
    }
    return Object.freeze({
      bytes,
      filesystemObjectKey: `${String(before.dev)}\0${String(before.ino)}`,
    });
  } catch (error) {
    invalid(`${label} safe capture failed: ${String(error?.message ?? error)}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function usage() {
  return "usage: node scripts/v1-phase-b-replay-artifacts.mjs --verify --expected ABSOLUTE.json --claim ABSOLUTE.json --journal ABSOLUTE.jsonl --execution-receipt ABSOLUTE.json";
}

function parseCli(argv) {
  if (argv[0] !== "--verify") invalid(usage());
  const options = {};
  for (let index = 1; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!flag?.startsWith("--") || !value || value.startsWith("--")) invalid(usage());
    if (flag === "--expected" || flag === "--claim" || flag === "--journal" || flag === "--execution-receipt") {
      const key = flag.slice(2);
      if (Object.hasOwn(options, key)) invalid(usage());
      options[key] = value;
    } else invalid(usage());
  }
  if (!options.expected || !options.claim || !options.journal || !options["execution-receipt"]) invalid(usage());
  return options;
}

function parseExpectedBytes(input) {
  if (!Buffer.isBuffer(input)) invalid("Replay expectation must be raw Buffer bytes.");
  let document;
  try {
    document = JSON.parse(input.toString("utf8"));
  } catch {
    invalid("Replay expectation is not valid JSON.");
  }
  if (!input.equals(Buffer.from(canonicalJson(document) + "\n", "utf8"))) {
    invalid("Replay expectation must be exact canonical JSON bytes with one trailing LF.");
  }
  return document;
}

function main() {
  const options = parseCli(process.argv.slice(2));
  const expectedSnapshot = snapshotFile(options.expected, "Replay expectation");
  const claimSnapshot = snapshotFile(options.claim, "Replay claim");
  const journalSnapshot = snapshotFile(options.journal, "Install journal");
  const receiptSnapshot = snapshotFile(options["execution-receipt"], "Bootstrap execution receipt");
  const snapshots = [
    expectedSnapshot, claimSnapshot, journalSnapshot, receiptSnapshot,
  ];
  if (new Set(snapshots.map((snapshot) => snapshot.filesystemObjectKey)).size !== snapshots.length) {
    invalid("Replay expectation, claim, journal entries, terminal, and receipt must be distinct filesystem objects.");
  }
  const result = verifyV1PhaseBReplayArtifacts({
    expected: parseExpectedBytes(expectedSnapshot.bytes),
    claimArtifact: claimSnapshot.bytes,
    journalArtifact: journalSnapshot.bytes,
    executionReceiptArtifact: receiptSnapshot.bytes,
  });
  process.stdout.write(canonicalJson(result) + "\n");
  process.exitCode = 78;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(String(error?.message ?? error) + "\n");
    process.exitCode = 1;
  }
}
