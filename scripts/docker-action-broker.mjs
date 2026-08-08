#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  ACTIONS,
  MAX_PHASE_OUTPUT_BYTES,
  MAX_REQUEST_BYTES,
  RESPONSE_SCHEMA,
  canonicalJson,
  normalizeActionRequest,
  normalizeActionResponse,
  normalizeTrustedContext,
  sha256,
  signActionResponse,
} from "./docker-action-contract.mjs";
import {
  normalizeActivationPolicy,
  verifyActivationEnvelope,
} from "./docker-action-activation.mjs";
import {
  assertExactSemanticHelperInspect,
  bindSemanticHelperImageInspect,
  buildSemanticHelperPlan,
} from "./docker-action-helper-plan.mjs";

const DEFAULT_SOCKET_PATH = "/run/platform/docker-action-broker/broker.sock";
const DEFAULT_STATE_DIR = "/var/lib/platform/docker-action-broker";
const DEFAULT_INTENT_FILE = "/run/platform/docker-action-trust/runtime-intent.json";
const DEFAULT_RECEIPT_FILE = "/run/platform/docker-action-trust/active-receipt.json";
const DEFAULT_TRUST_KEY_FILE = "/run/secrets/docker_action_runtime_intent_trust_key";
const DEFAULT_ACTIVATION_POLICY_FILE = "/opt/platform-docker-broker/docker-action-activation-policy.json";
const DEFAULT_ACTIVATION_CAS_ROOT = "/run/platform/docker-action-activation/by-bundle-sha256";
const DEFAULT_TIMEOUT_MS = 4 * 60 * 60_000;
const MAX_TRUST_DOCUMENT_BYTES = 2 * 1024 * 1024;
const MAX_ENGINE_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_REPLAY_ENTRIES = 4096;
const MAX_REPLAY_LEDGER_BYTES = 1024 * 1024;
const MAX_LEASE_STATE_BYTES = MAX_TRUST_DOCUMENT_BYTES + MAX_REQUEST_BYTES + 64 * 1024;
const CLEANUP_TIMEOUT_MS = 10_000;
const MAX_WORKER_ENV_ENTRY_BYTES = 32 * 1024;
const MAX_WORKER_ENV_TOTAL_BYTES = 64 * 1024;
const SEMANTIC_WORKER_RESULT_SCHEMA = "platform.docker-worker.result/v2";
const SEMANTIC_WORKER_ROLES_BY_PHASE = Object.freeze({
  "catalog.capture": Object.freeze(["evidence-finalizer", "helper-preparer"]),
  "job.backup.capture": Object.freeze(["evidence-finalizer", "helper-preparer"]),
  "job.restore.verify": Object.freeze(["artifact-resolver", "evidence-finalizer", "helper-preparer", "scratch-cleaner", "scratch-preparer"]),
  "offsite.sync": Object.freeze(["artifact-resolver", "evidence-finalizer", "helper-preparer"]),
  "prune.apply": Object.freeze(["standalone"]),
  "prune.plan": Object.freeze(["standalone"]),
  "restore.capture": Object.freeze(["evidence-finalizer", "helper-preparer"]),
  "restore.verify": Object.freeze(["evidence-finalizer", "helper-preparer", "scratch-cleaner", "scratch-preparer"]),
});
const LEASE_SCHEMA_V2 = "platform.docker-action.lease/v2";
const LEASE_JOURNAL_SCHEMA_V2 = "platform.docker-action.lease-journal-entry/v2";
const ZERO_SHA256 = "0".repeat(64);
const LEASE_EVENT_FIELDS = Object.freeze({
  "snapshot-materialized": Object.freeze({
    required: ["phaseId", "snapshot"],
    optional: ["requestSha256"],
  }),
  "worker-recorded": Object.freeze({
    required: [
      "action",
      "phaseId",
      "phaseProfileSha256",
      "receiptDigest",
      "resourceName",
    ],
    optional: ["claimedBackupResources", "requestSha256", "snapshot"],
  }),
  "worker-created": Object.freeze({
    required: ["phaseId", "resourceName", "workerId"],
    optional: [],
  }),
  "worker-result-recorded": Object.freeze({
    required: ["phaseId", "resourceName", "workerId", "workerResultSha256"],
    optional: [],
  }),
  "worker-deleted": Object.freeze({
    required: ["phaseId", "resourceName", "workerId"],
    optional: [],
  }),
  "role-worker-recorded": Object.freeze({
    required: ["action", "phaseId", "phaseProfileSha256", "receiptDigest", "resourceName", "workerRole"],
    optional: ["artifactBinding", "claimedBackupResources", "helperResultsSnapshot", "requestSha256", "snapshot"],
  }),
  "role-worker-created": Object.freeze({
    required: ["phaseId", "resourceName", "workerId", "workerRole"],
    optional: [],
  }),
  "role-worker-start-attempted": Object.freeze({
    required: ["mutationClass", "phaseId", "resourceName", "workerId", "workerRole"],
    optional: [],
  }),
  "role-worker-result-recorded": Object.freeze({
    required: ["phaseId", "resourceName", "workerId", "workerResultSha256", "workerRole"],
    optional: [],
  }),
  "role-worker-deleted": Object.freeze({
    required: ["phaseId", "resourceName", "workerId", "workerRole"],
    optional: [],
  }),
  "scratch-bootstrap-recorded": Object.freeze({
    required: ["action", "engine", "phaseId", "phaseProfileSha256", "receiptDigest", "resourceName", "workerRole"],
    optional: ["claimedBackupResources", "requestSha256", "snapshot"],
  }),
  "scratch-bootstrap-created": Object.freeze({
    required: ["engine", "phaseId", "resourceName", "workerId", "workerRole"],
    optional: [],
  }),
  "scratch-bootstrap-start-attempted": Object.freeze({
    required: ["engine", "phaseId", "resourceName", "workerId", "workerRole"],
    optional: [],
  }),
  "scratch-bootstrap-result-recorded": Object.freeze({
    required: ["engine", "phaseId", "resourceName", "workerId", "workerResultSha256", "workerRole"],
    optional: [],
  }),
  "scratch-bootstrap-deleted": Object.freeze({
    required: ["engine", "phaseId", "resourceName", "workerId", "workerRole"],
    optional: [],
  }),
  "scratch-materialized": Object.freeze({
    required: ["engine", "phaseId", "relativePath"],
    optional: ["requestSha256"],
  }),
  "scratch-cleaned": Object.freeze({
    required: ["engine", "phaseId", "relativePath"],
    optional: ["requestSha256"],
  }),
  "helper-recorded": Object.freeze({
    required: ["action", "bodySha256", "helperPlanSha256", "helperProfileId", "imageRuntimeConfigSha256", "ordinal", "phaseId", "phaseProfileSha256", "receiptDigest", "resourceName"],
    optional: ["artifactBinding", "claimedBackupResources", "requestSha256", "snapshot"],
  }),
  "helper-created": Object.freeze({
    required: ["helperProfileId", "phaseId", "resourceName", "workerId"],
    optional: [],
  }),
  "helper-start-attempted": Object.freeze({
    required: ["helperProfileId", "phaseId", "remoteAttempt", "resourceName", "workerId"],
    optional: [],
  }),
  "helper-started": Object.freeze({
    required: ["helperProfileId", "phaseId", "resourceName", "workerId"],
    optional: [],
  }),
  "helper-ready": Object.freeze({
    required: ["helperProfileId", "phaseId", "resourceName", "workerId"],
    optional: [],
  }),
  "helper-result-recorded": Object.freeze({
    required: ["helperProfileId", "phaseId", "resourceName", "workerId", "workerResultSha256"],
    optional: [],
  }),
  "helper-deleted": Object.freeze({
    required: ["helperProfileId", "phaseId", "resourceName", "workerId"],
    optional: [],
  }),
  "helper-results-materialized": Object.freeze({
    required: ["helperResultsSnapshot", "phaseId"],
    optional: ["requestSha256"],
  }),
  "helper-results-seal-intent": Object.freeze({
    required: ["phaseId"],
    optional: ["requestSha256"],
  }),
  "helper-results-intent-cleaned": Object.freeze({
    required: ["phaseId"],
    optional: ["requestSha256"],
  }),
  "helper-results-cleaned": Object.freeze({
    required: ["helperResultsSnapshot", "phaseId"],
    optional: ["requestSha256"],
  }),
  "snapshot-cleaned": Object.freeze({
    required: ["phaseId", "snapshot"],
    optional: ["requestSha256"],
  }),
  "action-result-recorded": Object.freeze({
    required: ["resultSha256"],
    optional: ["requestSha256"],
  }),
  "action-completed": Object.freeze({
    required: ["resultSha256"],
    optional: ["requestSha256"],
  }),
  "response-undelivered": Object.freeze({
    required: ["resultSha256"],
    optional: ["requestSha256"],
  }),
  "remote-effect-unknown": Object.freeze({
    required: ["phaseId", "resourceName", "workerId"],
    optional: [],
  }),
  "local-effect-unknown": Object.freeze({
    required: ["phaseId", "resourceName", "workerId"],
    optional: [],
  }),
});

export class PersistentReplayStore {
  constructor(stateDir = DEFAULT_STATE_DIR, {
    now = () => Date.now(),
    bootId = crypto.randomBytes(24).toString("hex"),
    expectedUid = 0,
    expectedGid = 0,
    io = fs,
  } = {}) {
    this.stateDir = path.resolve(stateDir);
    this.replayDir = path.join(this.stateDir, "replay");
    this.activationReplayDir = path.join(this.stateDir, "activation-replay");
    this.journalRoot = path.join(this.stateDir, "journal");
    this.lockPath = path.join(this.stateDir, "active.lock");
    this.generationPath = path.join(this.stateDir, "active-generation.json");
    this.activationPath = path.join(this.stateDir, "active-activation.json");
    this.now = now;
    this.bootId = bootId;
    this.expectedUid = expectedUid;
    this.expectedGid = expectedGid;
    this.io = io;
    if (!/^[a-f0-9]{48}$/.test(String(bootId ?? ""))
      || !Number.isSafeInteger(expectedUid) || expectedUid < 0
      || !Number.isSafeInteger(expectedGid) || expectedGid < 0
      || typeof now !== "function" || !io || typeof io !== "object") {
      throw new TypeError("broker replay store policy is invalid");
    }
    ensurePrivateDirectoryWithIo(io, this.stateDir, { expectedUid, expectedGid });
    const recovering = io.existsSync(this.lockPath);
    for (const directory of [this.replayDir, this.activationReplayDir, this.journalRoot]) {
      ensurePrivateDirectoryWithIo(io, directory, {
        create: !recovering,
        expectedUid,
        expectedGid,
      });
    }
  }

  consume(request) {
    const { count, bytes } = this.purgeExpired();
    if (count >= MAX_REPLAY_ENTRIES || bytes >= MAX_REPLAY_LEDGER_BYTES) {
      throw brokerError(503, "replay ledger capacity is exhausted");
    }
    const id = crypto.createHash("sha256").update(`${request.requestId}\0${request.nonce}`).digest("hex");
    const file = path.join(this.replayDir, id);
    let descriptor;
    try {
      descriptor = this.io.openSync(file, safeCreateFlags(this.io), 0o600);
      this.io.writeFileSync(descriptor, Buffer.from(`${canonicalJson({
        expiresAt: new Date(this.now() + 24 * 60 * 60_000).toISOString(),
      })}\n`));
      this.io.fsyncSync(descriptor);
    } catch (error) {
      if (error?.code === "EEXIST") throw brokerError(409, "request replay rejected");
      throw error;
    } finally {
      if (descriptor !== undefined) this.io.closeSync(descriptor);
    }
    this.syncDirectory(this.replayDir);
  }

  admitTrustedContext(trusted) {
    const next = {
      generation: trusted.intent.generation,
      intentId: trusted.intent.intentId,
      receiptDigest: trusted.receiptDigest,
    };
    const current = this.readStateJson(this.generationPath, { optional: true });
    if (current && (next.generation < current.generation
      || (next.generation === current.generation
        && (next.intentId !== current.intentId || next.receiptDigest !== current.receiptDigest)))) {
      throw brokerError(409, "runtime trust generation rollback or substitution rejected");
    }
    if (!current || next.generation > current.generation) this.writeStateJsonAtomic(this.generationPath, next, { replace: Boolean(current) });
  }

  admitActivation(activation, trusted) {
    if (!activation || activation.envelopeSha256 !== trusted?.intent?.activationBundleSha256
      || activation.runtimeIntentId !== trusted?.intent?.intentId
      || activation.generation !== trusted?.intent?.generation
      || activation.releaseId !== trusted?.intent?.releaseId
      || activation.candidateId !== trusted?.intent?.candidateId
      || activation.environment !== trusted?.intent?.environment
      || activation.targetId !== trusted?.intent?.targetId
      || activation.sourceRenderSha256 !== trusted?.receipt?.sourceRenderSha256
      || activation.combinedRenderSha256 !== trusted?.receipt?.combinedRenderSha256
      || activation.dastChainSha256 !== trusted?.receipt?.dastChainSha256
      || activation.treeSha256 !== trusted?.receipt?.treeSha256) {
      throw brokerError(403, "provider/admin activation does not bind the trusted runtime context");
    }
    const next = {
      schema: "platform.docker-action.active-activation/v1",
      activationId: activation.activationId,
      envelopeSha256: activation.envelopeSha256,
      generation: activation.generation,
      nonce: activation.nonce,
      previousActiveSha256: activation.previousActiveSha256,
      requestId: activation.requestId,
    };
    const current = this.readStateJson(this.activationPath, { optional: true });
    if (current?.envelopeSha256 === next.envelopeSha256) {
      if (canonicalJson(current) !== canonicalJson(next)) {
        throw brokerError(409, "active activation digest was substituted");
      }
      return;
    }
    if (current) {
      if (next.generation !== current.generation + 1
        || next.previousActiveSha256 !== current.envelopeSha256) {
        throw brokerError(409, "activation rollback, gap or ABA transition rejected");
      }
    } else if (next.generation !== 1 || next.previousActiveSha256 !== "0".repeat(64)) {
      throw brokerError(409, "activation journal has no trusted genesis");
    }
    const replayNames = this.io.readdirSync(this.activationReplayDir);
    if (replayNames.length >= MAX_REPLAY_ENTRIES) throw brokerError(503, "activation replay journal capacity is exhausted");
    const requestIdentitySha256 = crypto.createHash("sha256").update(`${next.requestId}\0${next.nonce}`).digest("hex");
    for (const name of replayNames) {
      if (!/^[a-f0-9]{64}$/.test(name)) throw new Error("activation replay journal contains an unexpected entry");
      const prior = this.readStateJson(path.join(this.activationReplayDir, name));
      if (prior.requestIdentitySha256 === requestIdentitySha256) throw brokerError(409, "activation request replay rejected");
      if (prior.envelopeSha256 === next.envelopeSha256) throw brokerError(409, "activation ABA replay rejected");
    }
    const replayFile = path.join(this.activationReplayDir, next.envelopeSha256);
    let descriptor;
    try {
      descriptor = this.io.openSync(replayFile, safeCreateFlags(this.io), 0o600);
      this.io.writeFileSync(descriptor, Buffer.from(`${canonicalJson({
        activationId: next.activationId,
        envelopeSha256: next.envelopeSha256,
        generation: next.generation,
        requestIdentitySha256,
      })}\n`));
      this.io.fsyncSync(descriptor);
    } catch (error) {
      if (error?.code === "EEXIST") throw brokerError(409, "activation ABA replay rejected");
      throw error;
    } finally {
      if (descriptor !== undefined) this.io.closeSync(descriptor);
    }
    this.syncDirectory(this.activationReplayDir);
    this.writeStateJsonAtomic(this.activationPath, next, { replace: Boolean(current) });
  }

  acquire(request, trusted) {
    if (this.io.existsSync(this.lockPath)) {
      throw brokerError(409, "another Docker action is running or requires remote reconciliation");
    }
    if (!isPlainRecord(request) || !isPlainRecord(trusted)
      || !isPlainRecord(trusted.intent) || !isPlainRecord(trusted.receipt)
      || request.action !== String(request.action ?? "")
      || request.requestId !== String(request.requestId ?? "")
      || trusted.intent.intentId !== String(trusted.intent.intentId ?? "")
      || !/^[a-f0-9]{64}$/.test(String(trusted.receiptDigest ?? ""))
      || sha256(canonicalJson(trusted.receipt)) !== trusted.receiptDigest) {
      throw new TypeError("broker lease lineage is invalid");
    }
    const requestCopy = cloneCanonicalValue(request);
    const trustedCopy = cloneCanonicalValue(trusted);
    const requestSha256 = sha256(canonicalJson(requestCopy));
    const startedAtMs = this.now();
    if (!Number.isFinite(startedAtMs)) throw new TypeError("broker lease clock is invalid");
    const startedAt = new Date(startedAtMs).toISOString();
    const leaseId = sha256(canonicalJson({
      bootId: this.bootId,
      entropy: crypto.randomBytes(32).toString("hex"),
      requestSha256,
      startedAt,
    }));
    const journalDirectory = path.join(this.journalRoot, leaseId);
    const record = {
      schema: LEASE_SCHEMA_V2,
      bootId: this.bootId,
      leaseId,
      request: requestCopy,
      requestId: request.requestId,
      action: request.action,
      intentId: trusted.intent.intentId,
      receiptDigest: trusted.receiptDigest,
      requestSha256,
      startedAt,
      expiresAt: new Date(startedAtMs + 24 * 60 * 60_000).toISOString(),
      journalEntryCount: 0,
      journalHeadSha256: ZERO_SHA256,
      recoveryIntent: null,
      trusted: trustedCopy,
    };
    let journalCreated = false;
    let lockCreated = false;
    let descriptor;
    try {
      this.io.mkdirSync(journalDirectory, { mode: 0o700 });
      journalCreated = true;
      validatePrivateDirectoryWithIo(this.io, journalDirectory, {
        expectedUid: this.expectedUid,
        expectedGid: this.expectedGid,
      });
      this.syncDirectory(this.journalRoot);
      descriptor = this.io.openSync(this.lockPath, safeCreateFlags(this.io), 0o600);
      lockCreated = true;
      this.io.writeFileSync(descriptor, Buffer.from(`${canonicalJson(record)}\n`));
      this.io.fsyncSync(descriptor);
    } catch (error) {
      if (error?.code === "EEXIST") {
        throw brokerError(409, "another Docker action is running or requires remote reconciliation");
      }
      throw error;
    } finally {
      if (descriptor !== undefined) this.io.closeSync(descriptor);
      if (!lockCreated && journalCreated
        && this.io.existsSync(journalDirectory)
        && this.io.readdirSync(journalDirectory).length === 0) {
        this.io.rmdirSync(journalDirectory);
        this.syncDirectory(this.journalRoot);
      }
    }
    this.syncDirectory(this.stateDir);
    const lineage = freezeCanonicalValue({
      action: record.action,
      intentId: record.intentId,
      receiptDigest: record.receiptDigest,
      request: record.request,
      requestId: record.requestId,
      requestSha256: record.requestSha256,
    });
    let closed = false;
    let terminal = null;
    return Object.freeze({
      lineage,
      recordRecoveryIntent: (value) => {
        if (closed || terminal) throw new Error("broker lease is closed or terminal");
        if (record.journalEntryCount !== 0) {
          throw new Error("broker lease recovery intent must precede journal materialization");
        }
        if (!isPlainRecord(value)
          || !hasExactKeys(value, ["phaseId", "snapshot"])
          || !isLogicalLeaseId(value.phaseId)) {
          throw new TypeError("broker lease recovery intent is invalid");
        }
        const snapshot = cloneCanonicalValue(normalizeSealedSnapshot(value.snapshot));
        if (snapshot.requestSha256 !== record.requestSha256) {
          throw new TypeError("broker lease recovery intent request lineage is invalid");
        }
        const nextIntent = {
          phaseId: value.phaseId,
          requestSha256: record.requestSha256,
          snapshot,
        };
        if (record.recoveryIntent
          && canonicalJson(record.recoveryIntent) !== canonicalJson(nextIntent)) {
          throw new Error("broker lease recovery intent substitution rejected");
        }
        const next = { ...record, recoveryIntent: nextIntent };
        this.installLeaseHead(next);
        Object.assign(record, next);
        return freezeCanonicalValue(nextIntent);
      },
      recordEvent: (event) => {
        if (closed || terminal) throw new Error("broker lease is closed or terminal; journal append rejected");
        const entry = this.appendLeaseEvent(record, event);
        if (["action-completed", "local-effect-unknown", "response-undelivered", "remote-effect-unknown"].includes(entry.event)) {
          terminal = entry.event;
        }
        return entry;
      },
      recordWorker: (event) => {
        if (closed || terminal) throw new Error("broker lease is closed or terminal; journal append rejected");
        return this.appendLeaseEvent(record, { event: "worker-recorded", ...event });
      },
      release: () => {
        if (closed) return;
        if (terminal === "remote-effect-unknown") {
          throw new Error("remote effect is unknown and requires manual reconciliation");
        }
        if (terminal === "local-effect-unknown") {
          throw new Error("local effect is unknown and requires manual reconciliation");
        }
        if (terminal === "response-undelivered") {
          throw new Error("response was undelivered and requires manual reconciliation");
        }
        if ((record.recoveryIntent && terminal !== "action-completed")
          || (record.journalEntryCount > 0 && terminal !== "action-completed")) {
          throw new Error("broker lease cannot be released before durable action completion");
        }
        closed = true;
        this.unlinkExactStateFile(this.lockPath);
      },
      preserve: () => {
        closed = true;
      },
    });
  }

  async recover(engine) {
    const record = this.readStateJson(this.lockPath, { optional: true });
    if (!record) return { status: "clean" };
    this.validateLeaseRecord(record);
    if (record.bootId === this.bootId) throw new Error("broker has an unexpected live lease before startup");
    const journalEntries = this.readAndValidateJournal(record);
    const terminal = journalEntries.at(-1)?.event ?? null;
    if (terminal === "action-result-recorded") {
      const resultSha256 = journalEntries.at(-1).resultSha256;
      this.appendLeaseEvent(record, {
        event: "response-undelivered",
        requestSha256: record.requestSha256,
        resultSha256,
      });
      throw new Error("response was undelivered and requires manual reconciliation");
    }
    if (terminal === "remote-effect-unknown") {
      throw new Error("remote effect is unknown and requires manual reconciliation");
    }
    if (terminal === "local-effect-unknown") {
      throw new Error("local effect is unknown and requires manual reconciliation");
    }
    if (terminal === "response-undelivered") {
      throw new Error("response was undelivered and requires manual reconciliation");
    }
    if (terminal === "action-completed" || (journalEntries.length === 0 && !record.recoveryIntent)) {
      this.unlinkExactStateFile(this.lockPath);
      return { status: "recovered", resourceName: null };
    }
    if (typeof engine?.recoverLease !== "function") {
      throw new Error("broker cannot recover a prior worker lease");
    }
    const lineage = freezeCanonicalValue({
      action: record.action,
      intentId: record.intentId,
      receiptDigest: record.receiptDigest,
      request: record.request,
      requestId: record.requestId,
      requestSha256: record.requestSha256,
    });
    const recoveryRecord = Object.freeze({
      ...cloneCanonicalValue(record),
      journalEntries: freezeCanonicalValue(journalEntries),
      lineage,
      recordEvent: (event) => this.appendLeaseEvent(record, event),
    });
    await withTimeout(
      (signal) => engine.recoverLease(recoveryRecord, signal),
      CLEANUP_TIMEOUT_MS,
      "worker recovery timed out",
    );
    this.unlinkExactStateFile(this.lockPath);
    const resourceName = [...journalEntries]
      .reverse()
      .find(({ event }) => event === "worker-recorded")?.resourceName ?? null;
    return { status: "recovered", resourceName };
  }

  purgeExpired() {
    const names = this.io.readdirSync(this.replayDir);
    if (names.length > MAX_REPLAY_ENTRIES) throw brokerError(503, "replay ledger entry bound exceeded");
    let count = 0;
    let bytes = 0;
    for (const name of names) {
      if (!/^[a-f0-9]{64}$/.test(name)) throw new Error("unexpected replay ledger entry");
      const file = path.join(this.replayDir, name);
      const stat = this.io.lstatSync(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== this.expectedUid
        || stat.gid !== this.expectedGid || (stat.mode & 0o077) !== 0 || stat.size > 512) {
        throw new Error("replay ledger integrity failure");
      }
      const entry = this.readStateJson(file);
      if (!Number.isFinite(Date.parse(String(entry.expiresAt ?? "")))) throw new Error("replay ledger timestamp is invalid");
      if (Date.parse(entry.expiresAt) < this.now()) {
        this.unlinkExactStateFile(file);
      } else {
        count += 1;
        bytes += stat.size;
      }
    }
    return { count, bytes };
  }

  readStateJson(file, { optional = false, maximumBytes = MAX_LEASE_STATE_BYTES } = {}) {
    let descriptor;
    try {
      descriptor = this.io.openSync(file, safeReadFlags(this.io));
    } catch (error) {
      if (optional && error?.code === "ENOENT") return null;
      throw error;
    }
    try {
      const before = this.io.fstatSync(descriptor, { bigint: true });
      if (!before.isFile() || before.nlink !== 1n
        || before.gid !== BigInt(this.expectedGid) || before.uid !== BigInt(this.expectedUid)
        || (before.mode & 0o777n) !== 0o600n || before.size < 2n
        || before.size > BigInt(maximumBytes)) {
        throw new Error("broker state file integrity failure");
      }
      const first = readDescriptorWithIo(this.io, descriptor, Number(before.size));
      const second = readDescriptorWithIo(this.io, descriptor, Number(before.size));
      const after = this.io.fstatSync(descriptor, { bigint: true });
      if (!["dev", "ino", "size", "mtimeNs", "ctimeNs", "mode", "uid", "gid", "nlink"].every((field) => before[field] === after[field])
        || first.length !== second.length || !crypto.timingSafeEqual(first, second)) {
        throw new Error("broker state file changed while being read");
      }
      const text = first.toString("utf8");
      const value = JSON.parse(text);
      if (text !== `${canonicalJson(value)}\n`) {
        throw new Error("broker state file is not canonical JSON");
      }
      return value;
    } finally {
      this.io.closeSync(descriptor);
    }
  }

  readJournalJson(file) {
    const before = this.io.lstatSync(file, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
      || before.gid !== BigInt(this.expectedGid) || before.uid !== BigInt(this.expectedUid)
      || (before.mode & 0o777n) !== 0o600n || before.size < 2n
      || before.size > BigInt(MAX_TRUST_DOCUMENT_BYTES)) {
      throw new Error("lease journal entry file integrity failure");
    }
    const first = this.io.readFileSync(file);
    const second = this.io.readFileSync(file);
    const after = this.io.lstatSync(file, { bigint: true });
    if (!["dev", "ino", "size", "mtimeNs", "ctimeNs", "mode", "uid", "gid", "nlink"]
      .every((field) => before[field] === after[field])
      || first.length !== Number(before.size) || second.length !== first.length
      || !crypto.timingSafeEqual(first, second)) {
      throw new Error("lease journal entry changed while being read");
    }
    const text = first.toString("utf8");
    const value = JSON.parse(text);
    if (text !== `${canonicalJson(value)}\n`) {
      throw new Error("lease journal entry is not canonical JSON");
    }
    return value;
  }

  writeStateJsonAtomic(file, value, { replace = false } = {}) {
    const directory = path.dirname(file);
    const temporary = path.join(directory, `.state-${process.pid}-${crypto.randomBytes(12).toString("hex")}`);
    let descriptor;
    try {
      descriptor = this.io.openSync(temporary, safeCreateFlags(this.io), 0o600);
      this.io.writeFileSync(descriptor, Buffer.from(`${canonicalJson(value)}\n`));
      this.io.fsyncSync(descriptor);
      this.io.closeSync(descriptor);
      descriptor = undefined;
      if (!replace && this.io.existsSync(file)) throw new Error("broker state generation already exists");
      this.io.renameSync(temporary, file);
      this.syncDirectory(directory);
    } finally {
      if (descriptor !== undefined) this.io.closeSync(descriptor);
      if (this.io.existsSync(temporary)) {
        this.io.unlinkSync(temporary);
        this.syncDirectory(directory);
      }
    }
  }

  unlinkExactStateFile(file) {
    const stat = this.io.lstatSync(file, { bigint: true });
    if (!stat?.isFile() || stat.isSymbolicLink()
      || statInteger(stat.nlink) !== 1
      || statInteger(stat.uid) !== this.expectedUid
      || statInteger(stat.gid) !== this.expectedGid
      || (statInteger(stat.mode) & 0o777) !== 0o600) {
      throw new Error("broker state unlink integrity failure");
    }
    this.io.unlinkSync(file);
    this.syncDirectory(path.dirname(file));
  }

  appendLeaseEvent(record, value) {
    this.validateLeaseRecord(record);
    const current = this.readAndValidateJournal(record);
    const terminal = current.at(-1)?.event;
    if (["action-completed", "local-effect-unknown", "response-undelivered", "remote-effect-unknown"].includes(terminal)) {
      throw new Error("broker lease journal is terminal; append rejected");
    }
    const event = normalizeLeaseEvent(value, record);
    if (record.recoveryIntent && ["snapshot-materialized", "snapshot-cleaned"].includes(event.event)
      && (event.phaseId !== record.recoveryIntent.phaseId
        || canonicalJson(event.snapshot) !== canonicalJson(record.recoveryIntent.snapshot))) {
      throw new Error("broker lease recovery intent substitution rejected");
    }
    const entry = {
      schema: LEASE_JOURNAL_SCHEMA_V2,
      leaseId: record.leaseId,
      sequence: record.journalEntryCount,
      previousEntrySha256: record.journalHeadSha256,
      recordedAt: new Date(this.now()).toISOString(),
      requestId: record.requestId,
      requestSha256: record.requestSha256,
      action: record.action,
      ...event,
    };
    validateLeaseEventProgression([...current, entry], record);
    const journalDirectory = path.join(this.journalRoot, record.leaseId);
    const file = path.join(
      journalDirectory,
      `${String(entry.sequence).padStart(16, "0")}.json`,
    );
    let descriptor;
    try {
      descriptor = this.io.openSync(file, safeCreateFlags(this.io), 0o600);
      this.io.writeFileSync(descriptor, Buffer.from(`${canonicalJson(entry)}\n`));
      this.io.fsyncSync(descriptor);
    } finally {
      if (descriptor !== undefined) this.io.closeSync(descriptor);
    }
    this.syncDirectory(journalDirectory);
    const next = {
      ...record,
      journalEntryCount: record.journalEntryCount + 1,
      journalHeadSha256: sha256(canonicalJson(entry)),
      recoveryIntent: ["snapshot-materialized", "snapshot-cleaned"].includes(event.event)
        ? null
        : record.recoveryIntent,
    };
    this.installLeaseHead(next);
    Object.assign(record, next);
    return freezeCanonicalValue(entry);
  }

  installLeaseHead(record) {
    const temporary = path.join(
      this.stateDir,
      `active.lock.${process.pid}-${crypto.randomBytes(16).toString("hex")}.tmp`,
    );
    let descriptor;
    try {
      descriptor = this.io.openSync(temporary, safeCreateFlags(this.io), 0o600);
      this.io.writeFileSync(descriptor, Buffer.from(`${canonicalJson(record)}\n`));
      this.io.fsyncSync(descriptor);
      this.io.closeSync(descriptor);
      descriptor = undefined;
      this.io.renameSync(temporary, this.lockPath);
      this.syncDirectory(this.stateDir);
    } finally {
      if (descriptor !== undefined) this.io.closeSync(descriptor);
      if (this.io.existsSync(temporary)) {
        this.io.unlinkSync(temporary);
        this.syncDirectory(this.stateDir);
      }
    }
  }

  readAndValidateJournal(record) {
    const journalDirectory = path.join(this.journalRoot, record.leaseId);
    try {
      validatePrivateDirectoryWithIo(this.io, journalDirectory, {
        expectedUid: this.expectedUid,
        expectedGid: this.expectedGid,
      });
      const expectedNames = Array.from(
        { length: record.journalEntryCount },
        (_, index) => `${String(index).padStart(16, "0")}.json`,
      );
      const names = this.io.readdirSync(journalDirectory).map(String).sort();
      if (canonicalJson(names) !== canonicalJson(expectedNames)) {
        throw new Error("lease journal inventory or sequence is corrupt");
      }
      let previousEntrySha256 = ZERO_SHA256;
      const entries = names.map((name, sequence) => {
        const entry = this.readJournalJson(path.join(journalDirectory, name));
        validateStoredLeaseEvent(entry, record, { previousEntrySha256, sequence });
        previousEntrySha256 = sha256(canonicalJson(entry));
        return entry;
      });
      if (previousEntrySha256 !== record.journalHeadSha256) {
        throw new Error("lease journal head digest is corrupt");
      }
      validateLeaseEventProgression(entries, record);
      if (record.recoveryIntent && entries.some(({ event, phaseId }) => (
        phaseId === record.recoveryIntent.phaseId
          && ["snapshot-materialized", "snapshot-cleaned"].includes(event)
      ))) {
        throw new Error("lease journal conflicts with its recovery intent");
      }
      return entries;
    } catch (error) {
      if (/lease journal/i.test(String(error?.message ?? ""))) throw error;
      throw new Error(`broker lease journal integrity failure: ${error?.message ?? error}`, { cause: error });
    }
  }

  validateLeaseRecord(record) {
    const keys = [
      "action",
      "bootId",
      "expiresAt",
      "intentId",
      "journalEntryCount",
      "journalHeadSha256",
      "leaseId",
      "receiptDigest",
      "recoveryIntent",
      "request",
      "requestId",
      "requestSha256",
      "schema",
      "startedAt",
      "trusted",
    ];
    if (!isPlainRecord(record) || !hasExactKeys(record, keys)
      || record.schema !== LEASE_SCHEMA_V2
      || !/^[a-f0-9]{48}$/.test(String(record.bootId ?? ""))
      || !/^[a-f0-9]{64}$/.test(String(record.leaseId ?? ""))
      || !/^[a-f0-9]{64}$/.test(String(record.receiptDigest ?? ""))
      || !/^[a-f0-9]{64}$/.test(String(record.requestSha256 ?? ""))
      || !/^[a-f0-9]{64}$/.test(String(record.journalHeadSha256 ?? ""))
      || !Number.isSafeInteger(record.journalEntryCount)
      || record.journalEntryCount < 0 || record.journalEntryCount > MAX_REPLAY_ENTRIES
      || !Number.isFinite(Date.parse(String(record.startedAt ?? "")))
      || !Number.isFinite(Date.parse(String(record.expiresAt ?? "")))
      || !isPlainRecord(record.request) || !isPlainRecord(record.trusted)
      || !isPlainRecord(record.trusted.intent) || !isPlainRecord(record.trusted.receipt)
      || record.action !== record.request.action
      || record.requestId !== record.request.requestId
      || record.intentId !== record.trusted.intent.intentId
      || record.receiptDigest !== record.trusted.receiptDigest
      || sha256(canonicalJson(record.trusted.receipt)) !== record.receiptDigest
      || sha256(canonicalJson(record.request)) !== record.requestSha256) {
      throw new Error("broker recovery lease or journal head is malformed");
    }
    if (record.journalEntryCount === 0 && record.journalHeadSha256 !== ZERO_SHA256) {
      throw new Error("broker recovery lease journal head is inconsistent");
    }
    if (record.recoveryIntent !== null) {
      if (!isPlainRecord(record.recoveryIntent)
        || !hasExactKeys(record.recoveryIntent, ["phaseId", "requestSha256", "snapshot"])
        || !isLogicalLeaseId(record.recoveryIntent.phaseId)
        || record.recoveryIntent.requestSha256 !== record.requestSha256
        || canonicalJson(normalizeSealedSnapshot(record.recoveryIntent.snapshot))
          !== canonicalJson(record.recoveryIntent.snapshot)) {
        throw new Error("broker recovery lease recovery intent is malformed");
      }
    }
  }

  syncDirectory(directory) {
    const descriptor = this.io.openSync(directory, safeDirectoryFlags(this.io));
    try {
      this.io.fsyncSync(descriptor);
    } finally {
      this.io.closeSync(descriptor);
    }
  }
}

function safeCreateFlags(io) {
  return io.constants.O_WRONLY
    | io.constants.O_CREAT
    | io.constants.O_EXCL
    | (io.constants.O_NOFOLLOW ?? 0);
}

function safeReadFlags(io) {
  return io.constants.O_RDONLY | (io.constants.O_NOFOLLOW ?? 0);
}

function safeDirectoryFlags(io) {
  return io.constants.O_RDONLY
    | (io.constants.O_DIRECTORY ?? 0)
    | (io.constants.O_NOFOLLOW ?? 0);
}

function cloneCanonicalValue(value) {
  return JSON.parse(canonicalJson(value));
}

function freezeCanonicalValue(value) {
  const copy = cloneCanonicalValue(value);
  const freeze = (candidate) => {
    if (!candidate || typeof candidate !== "object" || Object.isFrozen(candidate)) return candidate;
    for (const child of Object.values(candidate)) freeze(child);
    return Object.freeze(candidate);
  };
  return freeze(copy);
}

function ensurePrivateDirectoryWithIo(io, directory, {
  create = true,
  expectedUid,
  expectedGid,
}) {
  if (!io.existsSync(directory)) {
    if (!create) throw new Error(`broker state directory is missing: ${directory}`);
    io.mkdirSync(directory, { recursive: true, mode: 0o700 });
  }
  validatePrivateDirectoryWithIo(io, directory, { expectedUid, expectedGid });
}

function validatePrivateDirectoryWithIo(io, directory, { expectedUid, expectedGid }) {
  const stat = io.lstatSync(directory, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()
    || stat.uid !== BigInt(expectedUid) || stat.gid !== BigInt(expectedGid)
    || (stat.mode & 0o777n) !== 0o700n
    || path.resolve(String(io.realpathSync(directory))) !== directory) {
    throw new Error(`broker state directory integrity failure: ${directory}`);
  }
}

function readDescriptorWithIo(io, descriptor, size) {
  const result = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const count = io.readSync(descriptor, result, offset, size - offset, offset);
    if (count < 1) throw new Error("broker state file ended before its declared size");
    offset += count;
  }
  return result;
}

function isLogicalLeaseId(value) {
  return /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/.test(String(value ?? ""));
}

function normalizeLeaseEvent(value, record) {
  if (!isPlainRecord(value) || typeof value.event !== "string") {
    throw new TypeError("broker lease journal event is invalid");
  }
  const policy = LEASE_EVENT_FIELDS[value.event];
  if (!policy) throw new TypeError("broker lease journal event is unsupported");
  const required = [...new Set(["event", ...policy.required])];
  const optional = [...new Set(policy.optional.filter((field) => !required.includes(field)))];
  if (!hasExactKeys(value, required, optional)) {
    throw new TypeError("broker lease journal event fields are not exact");
  }
  const normalized = cloneCanonicalValue(value);
  if (optional.includes("requestSha256") && normalized.requestSha256 === undefined) {
    normalized.requestSha256 = record.requestSha256;
  }
  if (Object.hasOwn(normalized, "requestSha256")
    && normalized.requestSha256 !== record.requestSha256) {
    throw new TypeError("broker lease journal request lineage is invalid");
  }
  if (Object.hasOwn(normalized, "action") && normalized.action !== record.action) {
    throw new TypeError("broker lease journal action lineage is invalid");
  }
  if (Object.hasOwn(normalized, "receiptDigest")
    && normalized.receiptDigest !== record.receiptDigest) {
    throw new TypeError("broker lease journal receipt lineage is invalid");
  }
  if (Object.hasOwn(normalized, "phaseId") && !isLogicalLeaseId(normalized.phaseId)) {
    throw new TypeError("broker lease journal phase identity is invalid");
  }
  if (Object.hasOwn(normalized, "resourceName")
    && !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(String(normalized.resourceName ?? ""))) {
    throw new TypeError("broker lease journal resource identity is invalid");
  }
  for (const field of [
    "bodySha256",
    "helperPlanSha256",
    "imageRuntimeConfigSha256",
    "phaseProfileSha256",
    "resultSha256",
    "workerId",
    "workerResultSha256",
  ]) {
    if (Object.hasOwn(normalized, field)
      && !/^[a-f0-9]{64}$/.test(String(normalized[field] ?? ""))) {
      throw new TypeError(`broker lease journal ${field} is invalid`);
    }
  }
  if (Object.hasOwn(normalized, "workerRole")
    && !["artifact-resolver", "evidence-finalizer", "helper-preparer", "scratch-cleaner", "scratch-preparer", "standalone"]
      .includes(normalized.workerRole)) {
    throw new TypeError("broker lease journal worker role is invalid");
  }
  if (Object.hasOwn(normalized, "helperProfileId")
    && !/^helper\.(?:capture|restore|offsite)\.[a-z0-9.-]{1,120}$/.test(normalized.helperProfileId)) {
    throw new TypeError("broker lease journal helper profile identity is invalid");
  }
  if (Object.hasOwn(normalized, "engine")
    && !["mariadb", "minio", "postgres"].includes(normalized.engine)) {
    throw new TypeError("broker lease journal scratch engine is invalid");
  }
  if (Object.hasOwn(normalized, "ordinal")
    && (!Number.isSafeInteger(normalized.ordinal) || normalized.ordinal < 0 || normalized.ordinal > 255)) {
    throw new TypeError("broker lease journal helper ordinal is invalid");
  }
  if (Object.hasOwn(normalized, "remoteAttempt") && typeof normalized.remoteAttempt !== "boolean") {
    throw new TypeError("broker lease journal helper remote-attempt policy is invalid");
  }
  if (Object.hasOwn(normalized, "mutationClass")
    && !["local-nonidempotent", "none"].includes(normalized.mutationClass)) {
    throw new TypeError("broker lease journal mutation class is invalid");
  }
  if (Object.hasOwn(normalized, "relativePath") && !isExactRelativeBackupPath(normalized.relativePath)) {
    throw new TypeError("broker lease journal relative path is invalid");
  }
  const recordedEvents = new Set([
    "helper-recorded",
    "role-worker-recorded",
    "scratch-bootstrap-recorded",
    "worker-recorded",
  ]);
  if (recordedEvents.has(normalized.event)) {
    const phase = record.trusted?.receipt?.resources?.phaseProfiles?.[normalized.phaseId];
    if (!phase || phase.phaseSha256 !== normalized.phaseProfileSha256) {
      throw new TypeError("broker lease journal phase profile lineage is invalid");
    }
    const isClaimedJob = record.action === "backup.job.execute";
    const hasClaimedResources = Object.hasOwn(normalized, "claimedBackupResources");
    const hasSnapshot = Object.hasOwn(normalized, "snapshot");
    if (isClaimedJob !== hasClaimedResources || isClaimedJob !== hasSnapshot
      || (hasClaimedResources && (!isPlainRecord(normalized.claimedBackupResources)
        || Object.keys(normalized.claimedBackupResources).length < 1))) {
      throw new TypeError("broker lease journal claimed resource lineage is incomplete");
    }
    for (const [id, resource] of Object.entries(normalized.claimedBackupResources ?? {})) {
      const admitted = record.trusted.receipt.resources?.backupResources?.[id];
      if (!isPlainRecord(admitted) || canonicalJson(resource) !== canonicalJson(admitted)) {
        throw new TypeError("broker lease journal claimed resource lineage is invalid");
      }
    }
  }
  if (Object.hasOwn(normalized, "snapshot")) {
    normalized.snapshot = cloneCanonicalValue(normalizeSealedSnapshot(normalized.snapshot));
    if (normalized.snapshot.requestSha256 !== record.requestSha256) {
      throw new TypeError("broker lease journal snapshot lineage is invalid");
    }
  }
  if (Object.hasOwn(normalized, "helperResultsSnapshot")) {
    normalized.helperResultsSnapshot = cloneCanonicalValue(
      normalizeHelperResultsSnapshot(normalized.helperResultsSnapshot),
    );
    if (normalized.helperResultsSnapshot.requestSha256 !== record.requestSha256
      || normalized.helperResultsSnapshot.action !== record.action
      || normalized.helperResultsSnapshot.phaseId !== normalized.phaseId) {
      throw new TypeError("broker lease journal helper-results snapshot lineage is invalid");
    }
  }
  if (Object.hasOwn(normalized, "artifactBinding")) {
    validateBrokerArtifactBinding(normalized.artifactBinding, {
      consumerRequestSha256: record.requestSha256,
    });
  }
  return normalized;
}

function validateStoredLeaseEvent(entry, record, { previousEntrySha256, sequence }) {
  if (!isPlainRecord(entry) || entry.schema !== LEASE_JOURNAL_SCHEMA_V2
    || entry.leaseId !== record.leaseId || entry.sequence !== sequence
    || entry.previousEntrySha256 !== previousEntrySha256
    || entry.requestId !== record.requestId
    || entry.requestSha256 !== record.requestSha256
    || entry.action !== record.action
    || !Number.isFinite(Date.parse(String(entry.recordedAt ?? "")))) {
    throw new Error("lease journal entry chain or identity is corrupt");
  }
  const policy = LEASE_EVENT_FIELDS[entry.event];
  if (!policy) throw new Error("lease journal entry event is corrupt");
  const common = [
    "action",
    "event",
    "leaseId",
    "previousEntrySha256",
    "recordedAt",
    "requestId",
    "requestSha256",
    "schema",
    "sequence",
  ];
  const required = [...new Set([...common, ...policy.required])];
  const optional = [...new Set(policy.optional.filter((field) => !required.includes(field)))];
  if (!hasExactKeys(entry, required, optional)) {
    throw new Error("lease journal entry fields are corrupt");
  }
  const payload = Object.fromEntries(
    Object.entries(entry).filter(([key]) => !common.includes(key)
      || key === "event"
      || (key === "action" && policy.required.includes("action"))),
  );
  normalizeLeaseEvent(payload, record);
}

function validateLeaseEventProgression(entries, record) {
  const helpers = new Map();
  const helperResultsIntents = new Set();
  const helperResultsSnapshots = new Map();
  const roleWorkers = new Map();
  const scratch = new Map();
  const scratchCleaned = new Set();
  const scratchWorkers = new Map();
  const snapshots = new Map();
  const workers = new Map();
  let actionResultSha256 = null;
  let terminal = false;
  for (const [index, entry] of entries.entries()) {
    if (terminal) throw new Error("lease journal contains a post-terminal entry");
    if (actionResultSha256 !== null
      && !["action-completed", "response-undelivered"].includes(entry.event)) {
      throw new Error("lease journal contains a post-result nonterminal entry");
    }
    if (entry.event === "snapshot-materialized") {
      if (snapshots.has(entry.phaseId)) {
        throw new Error("lease journal snapshot materialization is duplicated");
      }
      snapshots.set(entry.phaseId, canonicalJson(entry.snapshot));
    } else if (entry.event === "worker-recorded") {
      if (workers.has(entry.resourceName)) throw new Error("lease journal contains a duplicate worker record");
      if (entry.snapshot
        && snapshots.get(entry.phaseId) !== canonicalJson(entry.snapshot)) {
        throw new Error("lease journal worker snapshot progression is corrupt");
      }
      workers.set(entry.resourceName, {
        created: false,
        deleted: false,
        phaseId: entry.phaseId,
        resultRecorded: false,
        snapshot: entry.snapshot ? canonicalJson(entry.snapshot) : null,
        workerId: null,
      });
    } else if (["worker-created", "worker-result-recorded", "worker-deleted"].includes(entry.event)) {
      const worker = workers.get(entry.resourceName);
      if (!worker || worker.phaseId !== entry.phaseId || worker.deleted) {
        throw new Error("lease journal worker progression is corrupt");
      }
      if (entry.event === "worker-created") {
        if (worker.created) throw new Error("lease journal worker creation is duplicated");
        worker.created = true;
        worker.workerId = entry.workerId;
      } else if (entry.event === "worker-result-recorded") {
        if (!worker.created || worker.resultRecorded || worker.workerId !== entry.workerId) {
          throw new Error("lease journal worker result identity is corrupt");
        }
        worker.resultRecorded = true;
      } else {
        if (worker.workerId && worker.workerId !== entry.workerId) {
          throw new Error("lease journal worker deletion identity is corrupt");
        }
        worker.workerId = entry.workerId;
        worker.deleted = true;
      }
    }
    if (entry.event === "role-worker-recorded") {
      if (roleWorkers.has(entry.resourceName)) throw new Error("lease journal contains a duplicate role worker");
      if (entry.snapshot && snapshots.get(entry.phaseId) !== canonicalJson(entry.snapshot)) {
        throw new Error("lease journal role worker claimed snapshot progression is corrupt");
      }
      if (entry.helperResultsSnapshot
        && helperResultsSnapshots.get(entry.phaseId) !== canonicalJson(entry.helperResultsSnapshot)) {
        throw new Error("lease journal role worker helper-results progression is corrupt");
      }
      roleWorkers.set(entry.resourceName, {
        created: false,
        deleted: false,
        phaseId: entry.phaseId,
        resultRecorded: false,
        startAttempted: false,
        mutationClass: null,
        workerId: null,
        workerRole: entry.workerRole,
      });
    } else if (["role-worker-created", "role-worker-start-attempted", "role-worker-result-recorded", "role-worker-deleted"].includes(entry.event)) {
      const worker = roleWorkers.get(entry.resourceName);
      if (!worker || worker.phaseId !== entry.phaseId || worker.workerRole !== entry.workerRole || worker.deleted) {
        throw new Error("lease journal role worker progression is corrupt");
      }
      if (entry.event === "role-worker-created") {
        if (worker.created) throw new Error("lease journal role worker creation is duplicated");
        worker.created = true;
        worker.workerId = entry.workerId;
      } else if (entry.event === "role-worker-start-attempted") {
        const expectedClass = ["artifact-resolver", "evidence-finalizer"].includes(entry.workerRole)
          || (entry.phaseId === "prune.apply" && entry.workerRole === "standalone")
          ? "local-nonidempotent"
          : "none";
        if (!worker.created || worker.startAttempted || worker.workerId !== entry.workerId
          || entry.mutationClass !== expectedClass) {
          throw new Error("lease journal role worker start-attempt identity is corrupt");
        }
        worker.startAttempted = true;
        worker.mutationClass = entry.mutationClass;
      } else if (entry.event === "role-worker-result-recorded") {
        if (!worker.created || !worker.startAttempted || worker.resultRecorded || worker.workerId !== entry.workerId) {
          throw new Error("lease journal role worker result identity is corrupt");
        }
        worker.resultRecorded = true;
      } else {
        if (!worker.created || worker.workerId !== entry.workerId) {
          throw new Error("lease journal role worker deletion identity is corrupt");
        }
        worker.deleted = true;
      }
    }
    if (entry.event === "scratch-bootstrap-recorded") {
      if (scratchWorkers.has(entry.resourceName)) throw new Error("lease journal contains a duplicate scratch bootstrap");
      scratchWorkers.set(entry.resourceName, {
        created: false,
        deleted: false,
        engine: entry.engine,
        phaseId: entry.phaseId,
        resultRecorded: false,
        startAttempted: false,
        workerId: null,
        workerRole: entry.workerRole,
      });
    } else if (["scratch-bootstrap-created", "scratch-bootstrap-start-attempted", "scratch-bootstrap-result-recorded", "scratch-bootstrap-deleted"].includes(entry.event)) {
      const worker = scratchWorkers.get(entry.resourceName);
      if (!worker || worker.phaseId !== entry.phaseId || worker.engine !== entry.engine
        || worker.workerRole !== entry.workerRole || worker.deleted) {
        throw new Error("lease journal scratch bootstrap progression is corrupt");
      }
      if (entry.event === "scratch-bootstrap-created") {
        if (worker.created) throw new Error("lease journal scratch bootstrap creation is duplicated");
        worker.created = true;
        worker.workerId = entry.workerId;
      } else if (entry.event === "scratch-bootstrap-start-attempted") {
        if (!worker.created || worker.startAttempted || worker.workerId !== entry.workerId) {
          throw new Error("lease journal scratch bootstrap start-attempt identity is corrupt");
        }
        worker.startAttempted = true;
      } else if (entry.event === "scratch-bootstrap-result-recorded") {
        if (!worker.created || !worker.startAttempted || worker.resultRecorded || worker.workerId !== entry.workerId) {
          throw new Error("lease journal scratch bootstrap result identity is corrupt");
        }
        worker.resultRecorded = true;
      } else {
        if (!worker.created || worker.workerId !== entry.workerId) {
          throw new Error("lease journal scratch bootstrap deletion identity is corrupt");
        }
        worker.deleted = true;
      }
    }
    if (entry.event === "scratch-materialized") {
      const completed = [...scratchWorkers.values()].some((worker) => (
        worker.phaseId === entry.phaseId && worker.engine === entry.engine
          && worker.workerRole === "scratch-preparer" && worker.resultRecorded
      ));
      if (!completed || scratch.has(`${entry.phaseId}\0${entry.engine}`)) {
        throw new Error("lease journal scratch materialization progression is corrupt");
      }
      scratch.set(`${entry.phaseId}\0${entry.engine}`, entry.relativePath);
    } else if (entry.event === "scratch-cleaned") {
      const key = `${entry.phaseId}\0${entry.engine}`;
      const completed = [...scratchWorkers.values()].some((worker) => (
        worker.phaseId === entry.phaseId && worker.engine === entry.engine
          && worker.workerRole === "scratch-cleaner" && worker.resultRecorded
      ));
      const preparerIntent = [...scratchWorkers.values()].some((worker) => (
        worker.phaseId === entry.phaseId && worker.engine === entry.engine
          && worker.workerRole === "scratch-preparer"
      ));
      if (!completed || scratchCleaned.has(key)
        || (scratch.get(key) !== entry.relativePath && !preparerIntent)) {
        throw new Error("lease journal scratch cleanup progression is corrupt");
      }
      scratch.delete(key);
      scratchCleaned.add(key);
    }
    if (entry.event === "helper-recorded") {
      if (helpers.has(entry.resourceName)) throw new Error("lease journal contains a duplicate helper record");
      helpers.set(entry.resourceName, {
        created: false,
        deleted: false,
        helperProfileId: entry.helperProfileId,
        phaseId: entry.phaseId,
        ready: false,
        remoteAttempted: false,
        resultRecorded: false,
        startAttempted: false,
        started: false,
        workerId: null,
      });
    } else if (["helper-created", "helper-start-attempted", "helper-started", "helper-ready", "helper-result-recorded", "helper-deleted"].includes(entry.event)) {
      const helper = helpers.get(entry.resourceName);
      if (!helper || helper.phaseId !== entry.phaseId
        || helper.helperProfileId !== entry.helperProfileId || helper.deleted) {
        throw new Error("lease journal helper progression is corrupt");
      }
      if (entry.event === "helper-created") {
        if (helper.created) throw new Error("lease journal helper creation is duplicated");
        helper.created = true;
        helper.workerId = entry.workerId;
      } else if (entry.event === "helper-start-attempted") {
        if (!helper.created || helper.startAttempted || helper.started || helper.workerId !== entry.workerId
          || entry.remoteAttempt !== (entry.helperProfileId === "helper.offsite.restic")) {
          throw new Error("lease journal helper start-attempt identity is corrupt");
        }
        helper.startAttempted = true;
        helper.remoteAttempted = entry.remoteAttempt;
      } else if (entry.event === "helper-started") {
        if (!helper.created || !helper.startAttempted || helper.started || helper.workerId !== entry.workerId) {
          throw new Error("lease journal helper start identity is corrupt");
        }
        helper.started = true;
      } else if (entry.event === "helper-ready") {
        if (!helper.started || helper.ready || !entry.helperProfileId.endsWith(".server")
          || helper.workerId !== entry.workerId) {
          throw new Error("lease journal helper readiness identity is corrupt");
        }
        helper.ready = true;
      } else if (entry.event === "helper-result-recorded") {
        const serverReady = !entry.helperProfileId.endsWith(".server") || helper.ready;
        if (!helper.started || !serverReady || helper.resultRecorded || helper.workerId !== entry.workerId) {
          throw new Error("lease journal helper result identity is corrupt");
        }
        helper.resultRecorded = true;
      } else {
        if (!helper.created || helper.workerId !== entry.workerId) {
          throw new Error("lease journal helper deletion identity is corrupt");
        }
        helper.deleted = true;
      }
    }
    if (entry.event === "helper-results-seal-intent") {
      if (helperResultsIntents.has(entry.phaseId) || helperResultsSnapshots.has(entry.phaseId)
        || [...helpers.values()].some((helper) => (
          helper.phaseId === entry.phaseId && (!helper.resultRecorded || !helper.deleted)
        ))) {
        throw new Error("lease journal helper-results seal intent progression is corrupt");
      }
      helperResultsIntents.add(entry.phaseId);
    } else if (entry.event === "helper-results-materialized") {
      if (!helperResultsIntents.has(entry.phaseId) || helperResultsSnapshots.has(entry.phaseId)
        || [...helpers.values()].some((helper) => (
          helper.phaseId === entry.phaseId && (!helper.resultRecorded || !helper.deleted)
        ))) {
        throw new Error("lease journal helper-results materialization progression is corrupt");
      }
      helperResultsSnapshots.set(entry.phaseId, canonicalJson(entry.helperResultsSnapshot));
    } else if (entry.event === "helper-results-cleaned") {
      if (helperResultsSnapshots.get(entry.phaseId) !== canonicalJson(entry.helperResultsSnapshot)) {
        throw new Error("lease journal helper-results cleanup progression is corrupt");
      }
      helperResultsSnapshots.delete(entry.phaseId);
      helperResultsIntents.delete(entry.phaseId);
    } else if (entry.event === "helper-results-intent-cleaned") {
      if (!helperResultsIntents.has(entry.phaseId) || helperResultsSnapshots.has(entry.phaseId)) {
        throw new Error("lease journal helper-results intent cleanup progression is corrupt");
      }
      helperResultsIntents.delete(entry.phaseId);
    }
    if (entry.event === "snapshot-cleaned") {
      const materialized = snapshots.get(entry.phaseId);
      const recoveryOnlyCleanup = index === 0 && entries.length >= 1;
      if ((!materialized && !recoveryOnlyCleanup)
        || (materialized && materialized !== canonicalJson(entry.snapshot))
        || [...workers.values()].some(
          (worker) => worker.phaseId === entry.phaseId && !worker.deleted,
        )) {
        throw new Error("lease journal snapshot cleanup progression is corrupt");
      }
      snapshots.delete(entry.phaseId);
    }
    if (entry.event === "remote-effect-unknown") {
      const worker = workers.get(entry.resourceName) ?? helpers.get(entry.resourceName);
      if (!worker || worker.phaseId !== entry.phaseId
        || worker.workerId !== entry.workerId || !worker.deleted
        || (helpers.has(entry.resourceName) && !worker.remoteAttempted)) {
        throw new Error("lease journal remote-effect identity is corrupt");
      }
    }
    if (entry.event === "local-effect-unknown") {
      const worker = roleWorkers.get(entry.resourceName);
      if (!worker || worker.phaseId !== entry.phaseId || worker.workerId !== entry.workerId
        || !worker.deleted || !worker.startAttempted
        || worker.mutationClass !== "local-nonidempotent") {
        throw new Error("lease journal local-effect identity is corrupt");
      }
    }
    if (["action-result-recorded", "action-completed", "response-undelivered"].includes(entry.event)
      && ([...workers.values()].some(({ deleted, resultRecorded }) => !deleted || !resultRecorded)
        || [...roleWorkers.values()].some(({ deleted, resultRecorded }) => !deleted || !resultRecorded)
        || [...scratchWorkers.values()].some(({ deleted, resultRecorded }) => !deleted || !resultRecorded)
        || [...helpers.values()].some(({ deleted, resultRecorded }) => !deleted || !resultRecorded)
        || snapshots.size > 0 || scratch.size > 0 || helperResultsIntents.size > 0
        || helperResultsSnapshots.size > 0)) {
      throw new Error("lease journal completed before resource cleanup");
    }
    if (entry.event === "action-result-recorded") {
      if (actionResultSha256 !== null) throw new Error("lease journal action result is duplicated");
      actionResultSha256 = entry.resultSha256;
    } else if (["action-completed", "response-undelivered"].includes(entry.event)
      && actionResultSha256 !== null && entry.resultSha256 !== actionResultSha256) {
      throw new Error("lease journal terminal result digest differs from recorded result");
    }
    if (["action-completed", "local-effect-unknown", "response-undelivered", "remote-effect-unknown"].includes(entry.event)) {
      if (index !== entries.length - 1) throw new Error("lease journal terminal entry is not final");
      terminal = true;
    }
  }
  if (entries.some((entry) => entry.requestSha256 !== record.requestSha256)) {
    throw new Error("lease journal request lineage is corrupt");
  }
}

export function createDockerActionBroker({
  socketPath = DEFAULT_SOCKET_PATH,
  stateDir = DEFAULT_STATE_DIR,
  trustedContextProvider = defaultTrustedContextProvider,
  capabilityProvider = defaultCapabilityProvider,
  claimedJobSnapshotProvider = defaultClaimedJobSnapshotProvider,
  engine,
  helperResultsFileStoreFactory = createHelperResultsFileStore,
  now = () => Date.now(),
  operationTimeoutMs = DEFAULT_TIMEOUT_MS,
  replayStore,
  semanticExecutorFactory = createSemanticHelperActionExecutor,
  semanticExecutorOptions = {},
  serverFactory = net.createServer,
  snapshotFileStoreFactory = createSnapshotFileStore,
  transport = new FixedDockerEngineTransport(),
} = {}) {
  if (!Number.isInteger(operationTimeoutMs) || operationTimeoutMs < 1 || operationTimeoutMs > 24 * 60 * 60_000) {
    throw new Error("Docker action timeout is invalid");
  }
  if (typeof serverFactory !== "function" || typeof snapshotFileStoreFactory !== "function"
    || typeof helperResultsFileStoreFactory !== "function"
    || typeof semanticExecutorFactory !== "function"
    || !isPlainRecord(semanticExecutorOptions)) {
    throw new TypeError("Docker action broker assembly dependencies are invalid");
  }
  const activeReplayStore = replayStore ?? new PersistentReplayStore(stateDir, { now });
  let activeEngine = engine;
  if (activeEngine === undefined) {
    const snapshotFileStore = semanticExecutorOptions.snapshotFileStore
      ?? snapshotFileStoreFactory({
        expectedGid: 0,
        expectedUid: 0,
        storageRoot: path.resolve(stateDir),
      });
    const helperResultsFileStore = semanticExecutorOptions.helperResultsFileStore
      ?? helperResultsFileStoreFactory({
        expectedGid: 0,
        expectedUid: 0,
        storageRoot: path.resolve(stateDir),
      });
    activeEngine = semanticExecutorFactory({
      ...semanticExecutorOptions,
      claimedJobSnapshotProvider,
      helperResultsFileStore,
      snapshotFileStore,
      transport,
    });
  }
  const core = createBrokerCore({
    trustedContextProvider,
    capabilityProvider,
    engine: activeEngine,
    replayStore: activeReplayStore,
    now,
    operationTimeoutMs,
  });
  const server = serverFactory((connection) => serveBrokerConnection(connection, core));
  server.on("listening", () => fs.chmodSync(socketPath, 0o660));
  server.socketPath = socketPath;
  server.prepareSocket = () => prepareSocket(socketPath);
  server.initialize = () => activeReplayStore.recover(activeEngine);
  return server;
}

export function encodeActionResponseFrame(body) {
  return Buffer.from(`${canonicalJson(body)}\n`);
}

export function createBrokerCore({
  trustedContextProvider,
  capabilityProvider,
  engine,
  replayStore,
  now = () => Date.now(),
  operationTimeoutMs = DEFAULT_TIMEOUT_MS,
}) {
  if (typeof trustedContextProvider !== "function" || typeof capabilityProvider !== "function" || typeof engine?.execute !== "function") {
    throw new TypeError("broker dependencies are incomplete");
  }
  return Object.freeze({
    async handle(frame, { deliveryMode = "immediate", peerState = null } = {}) {
      if (peerState !== null
        && (!peerState || typeof peerState !== "object" || typeof peerState.lost !== "boolean")) {
        throw new TypeError("broker peer state is invalid");
      }
      if (!["explicit", "immediate"].includes(deliveryMode)) {
        throw new TypeError("broker delivery mode is invalid");
      }
      let parsed;
      try {
        if (!Buffer.isBuffer(frame)) frame = Buffer.from(String(frame));
        if (frame.length < 2 || frame.length > MAX_REQUEST_BYTES) throw brokerError(413, "request size is invalid");
        parsed = JSON.parse(frame.toString("utf8"));
      } catch (error) {
        if (error?.statusCode) throw error;
        throw brokerError(400, "request is not valid JSON");
      }
      if (!frame.equals(Buffer.from(canonicalJson(parsed)))) {
        throw brokerError(400, "request wire frame is not canonical JSON");
      }

      const action = typeof parsed?.action === "string" ? parsed.action : "";
      if (!/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+$/.test(action)) {
        throw brokerError(403, "action grammar is invalid");
      }
      const contract = ACTIONS[action];
      if (!contract) throw brokerError(403, "action is not authorized");

      // No Engine method is reachable before the complete trust, schema,
      // action-capability and MAC admission sequence below succeeds.
      const trusted = await trustedContextProvider({ now: now() });
      replayStore.admitActivation(trusted.activation, trusted);
      replayStore.admitTrustedContext(trusted);
      const capabilityKey = await capabilityProvider(action, contract);
      normalizeActionRequest(parsed, trusted, capabilityKey, { now: now() });
      const request = parsed;
      const requestSha256 = sha256(canonicalJson(request));
      replayStore.consume(request);
      const lease = replayStore.acquire(request, trusted);
      const controller = new AbortController();
      const deliveryState = { abandoned: false };
      let pendingCompletion = null;
      let terminalFinalized = false;
      let terminalSettlementStarted = false;
      let completedResultSha256 = null;
      const executionLease = Object.freeze({
        ...lease,
        recordEvent(event) {
          if (pendingCompletion) {
            throw new Error("broker action completion is already pending delivery");
          }
          if (event?.event === "action-completed") {
            pendingCompletion = freezeCanonicalValue(event);
            return pendingCompletion;
          }
          if (typeof lease.recordEvent !== "function") {
            throw new TypeError("broker lease journal dependency is incomplete");
          }
          return lease.recordEvent(event);
        },
        recordWorker(event) {
          if (pendingCompletion) {
            throw new Error("broker action completion is already pending delivery");
          }
          if (typeof lease.recordWorker !== "function") {
            throw new TypeError("broker lease worker journal dependency is incomplete");
          }
          return lease.recordWorker(event);
        },
      });
      const validatePendingCompletion = (resultSha256) => {
        if (!pendingCompletion) return;
        if (!hasExactKeys(pendingCompletion, ["event", "resultSha256"], ["requestSha256"])
          || pendingCompletion.event !== "action-completed"
          || !/^[a-f0-9]{64}$/.test(String(pendingCompletion.resultSha256 ?? ""))
          || (pendingCompletion.requestSha256 !== undefined
            && pendingCompletion.requestSha256 !== requestSha256)
          || pendingCompletion.resultSha256 !== resultSha256) {
          throw new Error("broker action completion does not match the returned result");
        }
      };
      const finalizeTerminal = (resultSha256, { undelivered }) => {
        if (terminalSettlementStarted) return;
        terminalSettlementStarted = true;
        validatePendingCompletion(resultSha256);
        if (undelivered) {
          try {
            if (typeof lease.recordEvent !== "function") {
              throw new TypeError("broker lease journal dependency is incomplete");
            }
            lease.recordEvent({
              event: "response-undelivered",
              requestSha256,
              resultSha256,
            });
            terminalFinalized = true;
          } finally {
            lease.preserve();
          }
          return;
        }
        try {
          if (pendingCompletion) {
            if (typeof lease.recordEvent !== "function") {
              throw new TypeError("broker lease journal dependency is incomplete");
            }
            lease.recordEvent(pendingCompletion);
            terminalFinalized = true;
          }
          terminalFinalized = true;
          lease.release();
        } catch (error) {
          lease.preserve();
          if (error && typeof error === "object") error.preserveLease = true;
          throw error;
        }
      };
      let timeout;
      const operation = Promise.resolve().then(async () => {
        let executionCompleted = false;
        try {
          const engineResult = await engine.execute(request.action, {
            lease: executionLease,
            parameters: request.parameters,
            request,
            requestId: request.requestId,
            requestSha256,
            signal: controller.signal,
            trusted,
          });
          executionCompleted = true;
          const result = sanitizeResult(engineResult);
          completedResultSha256 = sha256(canonicalJson(result));
          const response = normalizeActionResponse(signActionResponse({
            action: request.action,
            errorCode: null,
            requestId: request.requestId,
            requestSha256,
            result,
            resultSha256: completedResultSha256,
            schema: RESPONSE_SCHEMA,
            status: "completed",
            statusCode: 200,
          }, capabilityKey), request, capabilityKey);
          encodeActionResponseFrame(response);
          pendingCompletion ??= freezeCanonicalValue({
            event: "action-completed",
            requestSha256,
            resultSha256: completedResultSha256,
          });
          validatePendingCompletion(completedResultSha256);
          if (typeof lease.recordEvent !== "function") {
            throw new TypeError("broker lease journal dependency is incomplete");
          }
          lease.recordEvent({
            event: "action-result-recorded",
            requestSha256,
            resultSha256: completedResultSha256,
          });
          const delivery = Object.freeze({
            delivered() {
              finalizeTerminal(completedResultSha256, {
                undelivered: deliveryState.abandoned || peerState?.lost === true,
              });
            },
            undelivered() {
              finalizeTerminal(completedResultSha256, { undelivered: true });
            },
          });
          if (deliveryMode === "immediate" || deliveryState.abandoned || peerState?.lost === true) {
            if (deliveryState.abandoned || peerState?.lost === true) delivery.undelivered();
            else delivery.delivered();
          }
          return {
            statusCode: 200,
            body: response,
            ...(deliveryMode === "explicit" ? { delivery } : {}),
          };
        } catch (error) {
          if (pendingCompletion && !terminalSettlementStarted) {
            try {
              const resultSha256 = completedResultSha256 ?? pendingCompletion.resultSha256;
              validatePendingCompletion(resultSha256);
              lease.recordEvent({
                event: "response-undelivered",
                requestSha256,
                resultSha256,
              });
              terminalFinalized = true;
            } catch {
              // The original failure remains authoritative; the active lease is
              // still preserved even if a terminal journal append cannot finish.
            }
            error.preserveLease = true;
          } else if (terminalSettlementStarted && !terminalFinalized) {
            error.preserveLease = true;
          }
          const semanticRejection = error?.semanticRejection === true
            && Number.isSafeInteger(error.statusCode)
            && error.statusCode >= 400
            && error.statusCode <= 599
            && /^[A-Z][A-Z0-9_]{2,63}$/.test(String(error.errorCode ?? ""));
          if (semanticRejection) {
            const result = null;
            const response = normalizeActionResponse(signActionResponse({
              action: request.action,
              errorCode: error.errorCode,
              requestId: request.requestId,
              requestSha256,
              result,
              resultSha256: sha256(canonicalJson(result)),
              schema: RESPONSE_SCHEMA,
              status: "rejected",
              statusCode: error.statusCode,
            }, capabilityKey), request, capabilityKey);
            encodeActionResponseFrame(response);
            if (executionCompleted || error.preserveLease) lease.preserve();
            else lease.release();
            return {
              statusCode: error.statusCode,
              body: response,
            };
          }
          if (executionCompleted || error?.preserveLease) lease.preserve();
          else lease.release();
          throw error;
        }
      });
      operation.catch(() => {});
      try {
        return await Promise.race([
          operation,
          new Promise((_, reject) => {
            timeout = setTimeout(() => {
              deliveryState.abandoned = true;
              controller.abort();
              reject(brokerError(504, "Docker action timed out"));
            }, operationTimeoutMs);
          }),
        ]);
      } finally {
        clearTimeout(timeout);
      }
    },
  });
}

export class FixedDockerEngineTransport {
  constructor(socketPath = "/var/run/docker.sock") {
    this.socketPath = socketPath;
  }

  createWorker(name, body, signal) {
    return this.#request("POST", `/containers/create?name=${encodeURIComponent(name)}`, body, signal);
  }

  createHelper(name, body, signal) {
    return this.#request("POST", `/containers/create?name=${encodeURIComponent(name)}`, body, signal);
  }

  inspectNetwork(id, signal) {
    assertEngineId(id);
    return this.#request("GET", `/networks/${encodeURIComponent(id)}`, undefined, signal);
  }

  inspectVolume(name, signal) {
    assertEngineId(name);
    return this.#request("GET", `/volumes/${encodeURIComponent(name)}`, undefined, signal);
  }

  inspectContainer(id, signal) {
    assertEngineId(id);
    return this.#request("GET", `/containers/${encodeURIComponent(id)}/json`, undefined, signal);
  }

  inspectHelper(id, signal) {
    assertEngineId(id);
    return this.#request("GET", `/containers/${encodeURIComponent(id)}/json`, undefined, signal);
  }

  inspectHelperImage(id, signal) {
    if (!/^sha256:[a-f0-9]{64}$/.test(String(id ?? ""))) {
      throw brokerError(502, "helper image ID is invalid");
    }
    return this.#request("GET", `/images/${encodeURIComponent(id)}/json`, undefined, signal);
  }

  async inspectContainerForRecovery(id, signal) {
    assertEngineId(id);
    const value = await this.#request("GET", `/containers/${encodeURIComponent(id)}/json`, undefined, signal, new Set([200, 404]));
    return value?.Id ? value : null;
  }

  async inspectHelperForRecovery(id, signal) {
    assertEngineId(id);
    const value = await this.#request("GET", `/containers/${encodeURIComponent(id)}/json`, undefined, signal, new Set([200, 404]));
    return value?.Id ? value : null;
  }

  startContainer(id, signal) {
    assertEngineId(id);
    return this.#request("POST", `/containers/${encodeURIComponent(id)}/start`, undefined, signal, new Set([204, 304]));
  }

  startHelper(id, signal) {
    assertEngineId(id);
    return this.#request("POST", `/containers/${encodeURIComponent(id)}/start`, undefined, signal, new Set([204, 304]));
  }

  waitContainer(id, signal) {
    assertEngineId(id);
    return this.#request("POST", `/containers/${encodeURIComponent(id)}/wait?condition=not-running`, undefined, signal);
  }

  waitHelper(id, signal) {
    assertEngineId(id);
    return this.#request("POST", `/containers/${encodeURIComponent(id)}/wait?condition=not-running`, undefined, signal);
  }

  logsContainer(id, signal) {
    assertEngineId(id);
    return this.#request("GET", `/containers/${encodeURIComponent(id)}/logs?stdout=1&stderr=1`, undefined, signal, new Set([200]), false);
  }

  logsHelper(id, signal) {
    assertEngineId(id);
    return this.#request("GET", `/containers/${encodeURIComponent(id)}/logs?stdout=1&stderr=1`, undefined, signal, new Set([200]), false);
  }

  deleteContainer(id, signal) {
    assertEngineId(id);
    return this.#request("DELETE", `/containers/${encodeURIComponent(id)}?force=1&v=1`, undefined, signal, new Set([204, 404]));
  }

  deleteHelper(id, signal) {
    assertEngineId(id);
    return this.#request("DELETE", `/containers/${encodeURIComponent(id)}?force=1&v=1`, undefined, signal, new Set([204, 404]));
  }

  #request(method, requestPath, body, signal, accepted = new Set([200, 201]), parseJson = true) {
    const payload = body === undefined ? null : Buffer.from(canonicalJson(body));
    return new Promise((resolve, reject) => {
      let settled = false;
      const resolveOnce = (value) => {
        if (settled) return;
        settled = true;
        resolve(value);
      };
      const rejectOnce = (error) => {
        if (settled) return;
        settled = true;
        reject(error);
      };
      const request = http.request({
        socketPath: this.socketPath,
        method,
        path: requestPath,
        signal,
        headers: payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {},
      }, (response) => {
        const chunks = [];
        let length = 0;
        response.on("aborted", () => rejectOnce(brokerError(502, "Engine response was aborted")));
        response.on("error", () => rejectOnce(brokerError(502, "Engine response stream failed")));
        response.on("data", (chunk) => {
          if (settled) return;
          length += chunk.length;
          if (length > MAX_ENGINE_RESPONSE_BYTES) {
            request.destroy(brokerError(502, "Engine response is oversized"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => {
          if (settled) return;
          const bytes = Buffer.concat(chunks);
          if (!accepted.has(response.statusCode)) return rejectOnce(brokerError(502, `fixed Engine request failed (${response.statusCode})`));
          if (!parseJson || bytes.length === 0) return resolveOnce(bytes);
          try {
            resolveOnce(JSON.parse(bytes.toString("utf8")));
          } catch {
            rejectOnce(brokerError(502, "Engine response is malformed"));
          }
        });
      });
      request.on("error", rejectOnce);
      if (payload) request.write(payload);
      request.end();
    });
  }
}

export function loadProtectedJson(file, maximumBytes = MAX_TRUST_DOCUMENT_BYTES) {
  return JSON.parse(readProtectedFile(file, maximumBytes).toString("utf8"));
}

export function readClaimedJobSnapshot(input, { io = fs } = {}) {
  if (!isPlainRecord(input) || !hasExactKeys(input, ["parameters", "policy", "source", "sourceId"])) {
    throw new TypeError("claimed job reader input is invalid");
  }
  const { parameters, policy, source, sourceId } = input;
  if (!isPlainRecord(parameters)
    || !hasExactKeys(parameters, ["jobFileName", "jobId", "jobOperation", "jobSha256"])
    || typeof parameters.jobId !== "string"
    || !/^[a-z0-9][a-z0-9-]{15,127}$/.test(parameters.jobId)
    || typeof parameters.jobFileName !== "string"
    || parameters.jobFileName !== `${parameters.jobId}.json`
    || path.basename(parameters.jobFileName) !== parameters.jobFileName
    || typeof parameters.jobOperation !== "string"
    || !["backup", "restore-drill"].includes(parameters.jobOperation)
    || typeof parameters.jobSha256 !== "string"
    || !/^[a-f0-9]{64}$/.test(parameters.jobSha256)) {
    throw new TypeError("claimed job filename, identity, operation or digest is invalid");
  }
  if (sourceId !== "jobs.running" || !isPlainRecord(source)
    || !hasExactKeys(source, [
      "brokerRoot",
      "maximumBytes",
      "snapshotContainerPath",
      "snapshotVolumeId",
      "snapshotVolumeSubpath",
      "volumeId",
      "volumeSubpath",
    ])
    || source.volumeId !== "jobs.queue"
    || source.volumeSubpath !== "running"
    || source.snapshotVolumeId !== "broker.state"
    || source.snapshotVolumeSubpath !== "claimed-jobs"
    || source.snapshotContainerPath !== "/run/platform/claimed-job/job.json"
    || !Number.isSafeInteger(source.maximumBytes)
    || source.maximumBytes < 1
    || source.maximumBytes > 1024 * 1024) {
    throw new TypeError("claimed job source policy is invalid");
  }
  const brokerRoot = source.brokerRoot;
  if (typeof brokerRoot !== "string" || brokerRoot.includes("\0")
    || !path.isAbsolute(brokerRoot) || path.resolve(brokerRoot) !== brokerRoot
    || path.normalize(brokerRoot) !== brokerRoot) {
    throw new TypeError("claimed job source root is not an exact canonical path");
  }
  if (!isPlainRecord(policy)
    || !hasExactKeys(policy, [
      "expectedMode",
      "maximumBytes",
      "parentRoot",
    ], ["expectedGid", "expectedUid"])
    || policy.parentRoot !== brokerRoot
    || policy.maximumBytes !== source.maximumBytes
    || policy.expectedMode !== 0o600) {
    throw new TypeError("claimed job reader policy does not match its source root");
  }
  const expectedUid = policy.expectedUid ?? 0;
  const expectedGid = policy.expectedGid ?? 0;
  if (!isUnixIdentity(expectedUid) || !isUnixIdentity(expectedGid)) {
    throw new TypeError("claimed job owner policy is invalid");
  }
  if (!io || typeof io !== "object"
    || !["closeSync", "fstatSync", "lstatSync", "openSync", "readSync"]
      .every((method) => typeof io[method] === "function")
    || !Number.isInteger(io.constants?.O_RDONLY)
    || !Number.isInteger(io.constants?.O_NOFOLLOW)
    || io.constants.O_NOFOLLOW === 0) {
    throw new TypeError("claimed job reader requires an injected no-follow filesystem interface");
  }

  const rootStat = io.lstatSync(brokerRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()
    || statInteger(rootStat.uid) !== expectedUid || statInteger(rootStat.gid) !== expectedGid
    || (statInteger(rootStat.mode) & 0o777) !== 0o700) {
    throw new Error("claimed job root directory owner or private mode is unsafe");
  }

  const leaf = path.join(brokerRoot, parameters.jobFileName);
  if (path.dirname(leaf) !== brokerRoot || path.basename(leaf) !== parameters.jobFileName) {
    throw new Error("claimed job filename is not an exact leaf basename");
  }
  const leafStat = io.lstatSync(leaf);
  const leafSize = statInteger(leafStat.size);
  if (!leafStat.isFile() || leafStat.isSymbolicLink()
    || statInteger(leafStat.nlink) !== 1
    || statInteger(leafStat.uid) !== expectedUid || statInteger(leafStat.gid) !== expectedGid
    || (statInteger(leafStat.mode) & 0o777) !== policy.expectedMode
    || leafSize < 1 || leafSize > policy.maximumBytes
    || !hasStableTimestamps(leafStat)) {
    throw new Error("claimed job leaf owner, private mode, link count, type or size is invalid");
  }
  let descriptor;
  let bytes;
  try {
    descriptor = io.openSync(
      leaf,
      io.constants.O_RDONLY | io.constants.O_NOFOLLOW,
    );
    const before = io.fstatSync(descriptor);
    const size = statInteger(before.size);
    if (!before.isFile() || before.isSymbolicLink()
      || statInteger(before.nlink) !== 1
      || statInteger(before.uid) !== expectedUid || statInteger(before.gid) !== expectedGid
      || (statInteger(before.mode) & 0o777) !== policy.expectedMode
      || size < 1 || size > policy.maximumBytes
      || !hasStableTimestamps(before)
      || !sameClaimedJobMetadata(leafStat, before)) {
      throw new Error("claimed job leaf owner, private mode, link count, type or size is invalid");
    }
    const first = readClaimedJobDescriptor(io, descriptor, size);
    const second = readClaimedJobDescriptor(io, descriptor, size);
    const after = io.fstatSync(descriptor);
    if (!sameClaimedJobMetadata(before, after)) {
      throw new Error("claimed job descriptor metadata changed while being read");
    }
    if (first.length !== second.length || !crypto.timingSafeEqual(first, second)) {
      throw new Error("claimed job content changed between descriptor reads");
    }
    bytes = first;
  } finally {
    if (descriptor !== undefined) io.closeSync(descriptor);
  }

  let document;
  try {
    document = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    assertClaimedJobDocument(document, parameters);
  } catch {
    throw new Error("claimed job bytes are not a valid typed JSON job document");
  }
  if (sha256(bytes) !== parameters.jobSha256) {
    throw new Error("claimed job byte sha256 does not exactly match the request");
  }
  return Object.freeze({
    bytes,
    jobFileName: parameters.jobFileName,
    jobId: parameters.jobId,
    jobOperation: parameters.jobOperation,
    jobSha256: parameters.jobSha256,
    sourceId,
  });
}

function assertClaimedJobDocument(document, parameters) {
  const requiredKeys = [
    "createdAt",
    "environment",
    "finishedAt",
    "id",
    "operation",
    "reportPaths",
    "requestedBy",
    "resources",
    "resultSummary",
    "schema",
    "scope",
    "startedAt",
    "status",
    "updatedAt",
  ];
  if (!isPlainRecord(document)
    || !hasExactKeys(document, requiredKeys, ["manifestPath", "sourceManifestPath"])
    || document.schema !== "platform.backup-job/v1"
    || document.id !== parameters.jobId
    || document.operation !== parameters.jobOperation
    || !isExactText(document.requestedBy, /^[A-Za-z0-9@._:+/-]+$/, 200)
    || !isExactText(document.environment, /^[a-z0-9-]+$/, 32)
    || document.status !== "running"
    || !isExactIsoTime(document.createdAt) || !isExactIsoTime(document.updatedAt)
    || !isNullableExactIsoTime(document.startedAt) || !isNullableExactIsoTime(document.finishedAt)
    || typeof document.resultSummary !== "string" || document.resultSummary.length > 500
    || !Array.isArray(document.reportPaths) || document.reportPaths.length > 32
    || document.reportPaths.some((candidate) => !isExactRelativeBackupPath(candidate))) {
    throw new Error("claimed job typed schema, identity, operation, status or timestamps are invalid");
  }
  if (!isPlainRecord(document.scope)
    || !hasExactKeys(document.scope, ["id", "kind"])
    || !["application", "platform"].includes(document.scope.kind)
    || (document.scope.kind === "platform"
      ? document.scope.id !== "platform"
      : !isProjectIdentifier(document.scope.id))) {
    throw new Error("claimed job scope is invalid");
  }
  if (!Array.isArray(document.resources) || document.resources.length < 1
    || document.resources.length > 256) {
    throw new Error("claimed job resources are invalid");
  }
  const resourceIds = new Set();
  for (const resource of document.resources) {
    assertClaimedJobResource(resource, document.scope);
    if (resourceIds.has(resource.id)) throw new Error("claimed job contains a duplicate resource");
    resourceIds.add(resource.id);
  }
  if (document.operation === "restore-drill") {
    if (!isExactRelativeBackupPath(document.sourceManifestPath)
      || !document.sourceManifestPath.startsWith("manifests/")) {
      throw new Error("claimed restore job source manifest is invalid");
    }
  } else if (Object.hasOwn(document, "sourceManifestPath")) {
    throw new Error("claimed backup job contains a restore source manifest");
  }
  if (Object.hasOwn(document, "manifestPath")
    && !isExactRelativeBackupPath(document.manifestPath)) {
    throw new Error("claimed job manifest path is invalid");
  }
}

function assertClaimedJobResource(resource, scope) {
  if (!isPlainRecord(resource) || typeof resource.kind !== "string") {
    throw new Error("claimed job resource is invalid");
  }
  const kindKeys = {
    database: ["engine", "externalId", "id", "kind", "name", "projectId"],
    source: ["externalId", "id", "kind", "name", "projectId", "sourceDirectory"],
    storage: ["externalId", "id", "kind", "name", "projectId"],
    "platform-state": ["externalId", "id", "kind", "name", "projectId"],
  }[resource.kind];
  if (!kindKeys || !hasExactKeys(resource, kindKeys)
    || !isGeneralIdentifier(resource.externalId)
    || resource.id !== `${resource.kind}:${resource.externalId}`
    || !isProjectIdentifier(resource.projectId)
    || !isExactText(resource.name, /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$/, 128)
    || (scope.kind === "application" && resource.projectId !== scope.id)
    || (resource.kind === "platform-state" && resource.projectId !== "platform")
    || (resource.kind === "database" && !["postgres", "mariadb"].includes(resource.engine))
    || (resource.kind === "source"
      && !isExactText(resource.sourceDirectory, /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$/, 128))) {
    throw new Error("claimed job resource identity is invalid");
  }
}

function isGeneralIdentifier(value) {
  return isExactText(value, /^[a-z0-9](?:[a-z0-9._:-]{0,158}[a-z0-9])?$/, 160);
}

function isProjectIdentifier(value) {
  return isExactText(value, /^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$/, 80);
}

function isExactText(value, pattern, maximumLength) {
  return typeof value === "string" && value.length > 0 && value.length <= maximumLength
    && value.trim() === value && pattern.test(value);
}

function isExactIsoTime(value) {
  if (typeof value !== "string") return false;
  const time = new Date(value);
  return Number.isFinite(time.getTime()) && time.toISOString() === value;
}

function isNullableExactIsoTime(value) {
  return value === null || isExactIsoTime(value);
}

function isExactRelativeBackupPath(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 512
    && value.trim() === value && !value.includes("\0") && !value.includes("\\")
    && !value.startsWith("/")
    && value.split("/").every((part) => part && part !== "." && part !== "..");
}

function readClaimedJobDescriptor(io, descriptor, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const count = io.readSync(descriptor, bytes, offset, size - offset, offset);
    if (!Number.isInteger(count) || count < 1 || count > size - offset) {
      throw new Error("claimed job changed before a complete descriptor read");
    }
    offset += count;
  }
  return bytes;
}

function sameClaimedJobMetadata(before, after) {
  try {
    return [
      "dev",
      "ino",
      "mode",
      "uid",
      "gid",
      "nlink",
      "size",
      "mtimeMs",
      "ctimeMs",
      "birthtimeMs",
    ].every((field) => Object.is(before[field], after[field]))
      && before.isFile() === after.isFile();
  } catch {
    return false;
  }
}

function hasStableTimestamps(stat) {
  return ["mtimeMs", "ctimeMs", "birthtimeMs"]
    .every((field) => typeof stat[field] === "number" && Number.isFinite(stat[field]));
}

function statInteger(value) {
  const number = typeof value === "bigint" ? Number(value) : value;
  return Number.isSafeInteger(number) ? number : Number.NaN;
}

function isUnixIdentity(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffff_ffff;
}

function isPlainRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value, required, optional = []) {
  const keys = Object.keys(value).sort();
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key))
    && keys.every((key) => allowed.has(key))
    && keys.length >= required.length
    && keys.length <= required.length + optional.length;
}

export function createSnapshotFileStore({
  expectedUid = 0,
  expectedGid = 0,
  io = fs,
  storageRoot,
} = {}) {
  if (!isUnixIdentity(expectedUid) || !isUnixIdentity(expectedGid)) {
    throw new TypeError("snapshot store owner policy is invalid");
  }
  const requiredMethods = [
    "closeSync",
    "existsSync",
    "fstatSync",
    "fsyncSync",
    "lstatSync",
    "mkdirSync",
    "openSync",
    "readdirSync",
    "realpathSync",
    "rmdirSync",
    "unlinkSync",
    "writeSync",
  ];
  if (!io || typeof io !== "object"
    || requiredMethods.some((method) => typeof io[method] !== "function")
    || !io.constants
    || ["O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_WRONLY", "O_CREAT", "O_EXCL"]
      .some((name) => !Number.isInteger(io.constants[name]))) {
    throw new TypeError("snapshot store requires a complete injected filesystem interface");
  }
  if (storageRoot !== undefined && (
    typeof storageRoot !== "string"
    || storageRoot.includes("\0")
    || !path.isAbsolute(storageRoot)
    || path.normalize(storageRoot) !== storageRoot
  )) {
    throw new TypeError("snapshot store local storage root is not an exact canonical path");
  }

  return Object.freeze({
    async seal(snapshotValue, authorityValue) {
      const snapshot = normalizeSnapshotInput(snapshotValue);
      const authority = normalizeSnapshotAuthority(authorityValue, snapshot);
      const bytes = Buffer.from(snapshot.bytes);
      let materialized = false;
      let writeStarted = false;
      const pins = [];
      let ancestorPin;
      let claimedPin;
      let leaf;
      let leafDescriptor;
      let leafIdentity;
      let requestDirectory;
      let requestIdentity;
      let requestPin;
      try {
        const mountpoint = authority.volumeInspect.Mountpoint;
        const materializationRoot = storageRoot ?? mountpoint;
        const ancestor = path.dirname(materializationRoot);
        const claimedJobsDirectory = path.join(
          materializationRoot,
          authority.source.snapshotVolumeSubpath,
        );
        requestDirectory = path.join(claimedJobsDirectory, authority.requestSha256);
        leaf = path.join(requestDirectory, "job.json");
        assertSnapshotPathLayout({
          ancestor,
          claimedJobsDirectory,
          leaf,
          mountpoint: materializationRoot,
          requestDirectory,
          requestSha256: authority.requestSha256,
          subpath: authority.source.snapshotVolumeSubpath,
        });
        const hostLeaf = snapshotHostLeaf(authority);

        if (storageRoot === undefined) {
          ancestorPin = openSnapshotDirectory(io, ancestor, {
            expectedGid,
            expectedUid,
            label: "mount ancestor",
          });
          pins.push(ancestorPin);
        }
        const mountPin = openSnapshotDirectory(io, materializationRoot, {
          expectedGid,
          expectedUid,
          label: storageRoot === undefined
            ? "Engine Mountpoint"
            : "broker.state local mountpoint",
        });
        pins.push(mountPin);

        if (!io.existsSync(claimedJobsDirectory)) {
          io.mkdirSync(claimedJobsDirectory, { mode: 0o700 });
          io.fsyncSync(mountPin.descriptor);
        }
        claimedPin = openSnapshotDirectory(io, claimedJobsDirectory, {
          expectedGid,
          expectedUid,
          label: "claimed-jobs directory",
        });
        pins.push(claimedPin);

        if (io.existsSync(requestDirectory)) {
          throw new Error("snapshot request directory already exists; replay or collision rejected");
        }
        io.mkdirSync(requestDirectory, { mode: 0o700 });
        io.fsyncSync(claimedPin.descriptor);
        materialized = true;
        requestIdentity = io.lstatSync(requestDirectory, { bigint: true });
        requestPin = openSnapshotDirectory(io, requestDirectory, {
          expectedGid,
          expectedUid,
          label: "request snapshot directory",
        });
        pins.push(requestPin);

        leafDescriptor = io.openSync(
          leaf,
          io.constants.O_WRONLY
            | io.constants.O_CREAT
            | io.constants.O_EXCL
            | io.constants.O_NOFOLLOW,
          0o400,
        );
        leafIdentity = io.fstatSync(leafDescriptor, { bigint: true });
        assertSnapshotLeafStat(leafIdentity, expectedUid, expectedGid, 0);
        mountPin.settled = io.fstatSync(mountPin.descriptor, { bigint: true });
        assertSnapshotDirectoryStat(mountPin.settled, expectedUid, expectedGid, mountPin.label);
        claimedPin.settled = io.fstatSync(claimedPin.descriptor, { bigint: true });
        assertSnapshotDirectoryStat(claimedPin.settled, expectedUid, expectedGid, claimedPin.label);
        requestPin.settled = io.fstatSync(requestPin.descriptor, { bigint: true });
        assertSnapshotDirectoryStat(requestPin.settled, expectedUid, expectedGid, requestPin.label);
        writeStarted = true;
        writeSnapshotBytes(io, leafDescriptor, bytes);
        io.fsyncSync(leafDescriptor);
        io.closeSync(leafDescriptor);
        leafDescriptor = undefined;
        io.fsyncSync(requestPin.descriptor);

        revalidateSnapshotDirectories(io, [mountPin, claimedPin, requestPin], {
          expectedGid,
          expectedUid,
        });
        if (ancestorPin) {
          revalidateSnapshotDirectories(io, [ancestorPin], {
            expectedGid,
            expectedUid,
          });
        }
        const leafStat = io.lstatSync(leaf, { bigint: true });
        assertSnapshotLeafStat(leafStat, expectedUid, expectedGid, bytes.length);
        if (path.resolve(String(io.realpathSync(leaf))) !== leaf) {
          throw new Error("snapshot leaf realpath escaped its exact authority path");
        }
        const requestInventory = io.readdirSync(requestDirectory).map(String).sort();
        if (canonicalJson(requestInventory) !== canonicalJson(["job.json"])) {
          throw new Error("snapshot request directory inventory is not exact");
        }

        const sealed = Object.freeze({
          containerPath: authority.source.snapshotContainerPath,
          hostPath: hostLeaf,
          jobFileName: snapshot.jobFileName,
          jobId: snapshot.jobId,
          jobOperation: snapshot.jobOperation,
          jobSha256: snapshot.jobSha256,
          requestSha256: authority.requestSha256,
          snapshotVolumeId: authority.source.snapshotVolumeId,
          snapshotVolumeMountpoint: mountpoint,
          snapshotVolumeName: authority.volumeInspect.Name,
          snapshotVolumeSubpath: authority.source.snapshotVolumeSubpath,
          sourceId: snapshot.sourceId,
        });
        closeSnapshotPins(io, pins);
        return sealed;
      } catch (error) {
        if (leafDescriptor !== undefined) {
          try {
            io.closeSync(leafDescriptor);
          } catch {}
        }
        if (materialized && !writeStarted) {
          rollbackUnwrittenSnapshot(io, {
            claimedPin,
            leaf,
            leafIdentity,
            requestDirectory,
            requestIdentity,
            requestPin,
          });
        }
        closeSnapshotPins(io, pins);
        if (materialized && error && typeof error === "object") error.preserveLease = true;
        throw error;
      }
    },

    async cleanup(sealedValue) {
      const sealed = normalizeSealedSnapshot(sealedValue);
      const mountpoint = sealed.snapshotVolumeMountpoint;
      const materializationRoot = storageRoot ?? mountpoint;
      const claimedJobsDirectory = path.join(
        materializationRoot,
        sealed.snapshotVolumeSubpath,
      );
      const requestDirectory = path.join(claimedJobsDirectory, sealed.requestSha256);
      const leaf = path.join(requestDirectory, "job.json");
      const hostLeaf = path.join(
        mountpoint,
        sealed.snapshotVolumeSubpath,
        sealed.requestSha256,
        "job.json",
      );
      if (sealed.hostPath !== hostLeaf
        || sealed.containerPath !== "/run/platform/claimed-job/job.json") {
        throw snapshotPreserveError("sealed snapshot path lineage is invalid");
      }
      const pins = [];
      try {
        const ancestor = path.dirname(materializationRoot);
        assertSnapshotPathLayout({
          ancestor,
          claimedJobsDirectory,
          leaf,
          mountpoint: materializationRoot,
          requestDirectory,
          requestSha256: sealed.requestSha256,
          subpath: sealed.snapshotVolumeSubpath,
        });
        if (storageRoot === undefined) {
          pins.push(openSnapshotDirectory(io, ancestor, {
            expectedGid,
            expectedUid,
            label: "snapshot cleanup mount ancestor",
          }));
        }
        pins.push(openSnapshotDirectory(io, materializationRoot, {
          expectedGid,
          expectedUid,
          label: storageRoot === undefined
            ? "snapshot cleanup Engine Mountpoint"
            : "snapshot cleanup broker.state local mountpoint",
        }));
        const claimedPin = openSnapshotDirectory(io, claimedJobsDirectory, {
          expectedGid,
          expectedUid,
          label: "snapshot cleanup claimed-jobs directory",
        });
        pins.push(claimedPin);
        const requestPin = openSnapshotDirectory(io, requestDirectory, {
          expectedGid,
          expectedUid,
          label: "snapshot cleanup request directory",
        });
        pins.push(requestPin);

        const leafStat = io.lstatSync(leaf, { bigint: true });
        assertSnapshotLeafStat(leafStat, expectedUid, expectedGid);
        if (path.resolve(String(io.realpathSync(leaf))) !== leaf) {
          throw new Error("snapshot cleanup leaf realpath escaped its exact authority path");
        }
        const inventory = io.readdirSync(requestDirectory).map(String).sort();
        if (canonicalJson(inventory) !== canonicalJson(["job.json"])) {
          throw new Error("snapshot cleanup request inventory is not exact");
        }
        for (const pin of pins) {
          pin.settled = io.fstatSync(pin.descriptor, { bigint: true });
          revalidateSnapshotDirectory(io, pin, { expectedGid, expectedUid });
        }

        io.unlinkSync(leaf);
        io.fsyncSync(requestPin.descriptor);
        io.closeSync(requestPin.descriptor);
        requestPin.closed = true;
        io.rmdirSync(requestDirectory);
        io.fsyncSync(claimedPin.descriptor);
        closeSnapshotPins(io, pins);
      } catch (error) {
        closeSnapshotPins(io, pins);
        if (error && typeof error === "object") error.preserveLease = true;
        throw error;
      }
    },
  });
}

export function createHelperResultsFileStore({
  expectedUid = 0,
  expectedGid = 0,
  io = fs,
  storageRoot,
} = {}) {
  if (!isUnixIdentity(expectedUid) || !isUnixIdentity(expectedGid)
    || typeof storageRoot !== "string" || !path.isAbsolute(storageRoot)
    || path.normalize(storageRoot) !== storageRoot || storageRoot.includes("\0")
    || !io || typeof io !== "object"
    || ["closeSync", "existsSync", "fstatSync", "fsyncSync", "lstatSync", "mkdirSync",
      "openSync", "readSync", "readdirSync", "realpathSync", "rmdirSync", "unlinkSync",
      "writeSync"].some((method) => typeof io[method] !== "function")
    || !Number.isInteger(io.constants?.O_RDONLY)
    || !Number.isInteger(io.constants?.O_WRONLY)
    || !Number.isInteger(io.constants?.O_CREAT)
    || !Number.isInteger(io.constants?.O_EXCL)
    || !Number.isInteger(io.constants?.O_DIRECTORY)
    || !Number.isInteger(io.constants?.O_NOFOLLOW)
    || io.constants.O_NOFOLLOW === 0) {
    throw new TypeError("helper-results store policy is invalid");
  }
  const root = path.resolve(storageRoot);
  const base = path.join(root, "helper-results");
  const validateRoot = (directory, label) => {
    const stat = io.lstatSync(directory, { bigint: true });
    assertSnapshotDirectoryStat(stat, expectedUid, expectedGid, label);
    if (path.resolve(String(io.realpathSync(directory))) !== directory) {
      throw new Error(`${label} realpath escaped its exact authority path`);
    }
  };
  const createChild = (parent, child, label) => {
    if (io.existsSync(child)) throw new Error(`${label} already exists; replay or collision rejected`);
    const parentDescriptor = io.openSync(
      parent,
      io.constants.O_RDONLY | io.constants.O_DIRECTORY | io.constants.O_NOFOLLOW,
    );
    try {
      io.mkdirSync(child, { mode: 0o700 });
      io.fsyncSync(parentDescriptor);
    } finally {
      io.closeSync(parentDescriptor);
    }
    validateRoot(child, label);
  };
  const ensureBase = () => {
    validateRoot(root, "helper-results storage root");
    if (!io.existsSync(base)) createChild(root, base, "helper-results directory");
    else validateRoot(base, "helper-results directory");
  };
  const syncDirectory = (directory) => {
    const descriptor = io.openSync(
      directory,
      io.constants.O_RDONLY | io.constants.O_DIRECTORY | io.constants.O_NOFOLLOW,
    );
    try { io.fsyncSync(descriptor); } finally { io.closeSync(descriptor); }
  };
  const normalizePartialAuthority = (authority) => {
    if (!isPlainRecord(authority) || !hasExactKeys(authority, [
      "action", "phaseId", "requestId", "requestSha256",
    ]) || !isLogicalLeaseId(authority.phaseId)
      || !/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+$/.test(String(authority.action ?? ""))
      || typeof authority.requestId !== "string" || authority.requestId.length < 1
      || authority.requestId.length > 256
      || !/^[a-f0-9]{64}$/.test(String(authority.requestSha256 ?? ""))) {
      throw new TypeError("helper-results partial cleanup authority is invalid");
    }
    return authority;
  };

  return Object.freeze({
    async seal(value, authority) {
      if (!isPlainRecord(value) || !isPlainRecord(authority)
        || !hasExactKeys(authority, [
          "action", "phaseId", "requestId", "requestSha256", "volumeId", "volumeInspect",
        ])
        || value.schema !== "platform.docker-helper-results/v1"
        || value.action !== authority.action || value.phaseId !== authority.phaseId
        || value.requestId !== authority.requestId
        || value.requestSha256 !== authority.requestSha256
        || !Array.isArray(value.helpers)
        || !isLogicalLeaseId(authority.phaseId)
        || !/^[a-f0-9]{64}$/.test(String(authority.requestSha256 ?? ""))
        || authority.volumeId !== "broker.state"
        || !isPlainRecord(authority.volumeInspect)
        || typeof authority.volumeInspect.Mountpoint !== "string"
        || !path.isAbsolute(authority.volumeInspect.Mountpoint)
        || typeof authority.volumeInspect.Name !== "string") {
        throw new TypeError("helper-results snapshot authority is invalid");
      }
      const bytes = Buffer.from(`${canonicalJson(value)}\n`);
      if (bytes.length < 2 || bytes.length > 512 * 1024) {
        throw new TypeError("helper-results snapshot size is invalid");
      }
      ensureBase();
      const requestDirectory = path.join(base, authority.requestSha256);
      const phaseDirectory = path.join(requestDirectory, authority.phaseId);
      createChild(base, requestDirectory, "helper-results request directory");
      let phaseCreated = false;
      let descriptor;
      const leaf = path.join(phaseDirectory, "results.json");
      try {
        createChild(requestDirectory, phaseDirectory, "helper-results phase directory");
        phaseCreated = true;
        descriptor = io.openSync(
          leaf,
          io.constants.O_WRONLY | io.constants.O_CREAT | io.constants.O_EXCL | io.constants.O_NOFOLLOW,
          0o400,
        );
        assertSnapshotLeafStat(io.fstatSync(descriptor, { bigint: true }), expectedUid, expectedGid, 0);
        writeSnapshotBytes(io, descriptor, bytes);
        io.fsyncSync(descriptor);
        io.closeSync(descriptor);
        descriptor = undefined;
        const phaseDescriptor = io.openSync(
          phaseDirectory,
          io.constants.O_RDONLY | io.constants.O_DIRECTORY | io.constants.O_NOFOLLOW,
        );
        try {
          io.fsyncSync(phaseDescriptor);
        } finally {
          io.closeSync(phaseDescriptor);
        }
        assertSnapshotLeafStat(io.lstatSync(leaf, { bigint: true }), expectedUid, expectedGid, bytes.length);
        if (canonicalJson(io.readdirSync(phaseDirectory).map(String).sort()) !== canonicalJson(["results.json"])) {
          throw new Error("helper-results phase inventory is not exact");
        }
        const relativePath = `helper-results/${authority.requestSha256}/${authority.phaseId}/results.json`;
        return Object.freeze({
          action: authority.action,
          containerPath: "/run/platform/helper-results/results.json",
          hostPath: path.join(authority.volumeInspect.Mountpoint, ...relativePath.split("/")),
          phaseId: authority.phaseId,
          relativePath,
          requestId: authority.requestId,
          requestSha256: authority.requestSha256,
          schema: "platform.docker-helper-results.snapshot/v1",
          sha256: sha256(bytes),
          sizeBytes: bytes.length,
          volumeId: authority.volumeId,
          volumeName: authority.volumeInspect.Name,
        });
      } catch (error) {
        if (descriptor !== undefined) {
          try { io.closeSync(descriptor); } catch {}
        }
        if (io.existsSync(leaf)) io.unlinkSync(leaf);
        if (phaseCreated && io.existsSync(phaseDirectory)
          && io.readdirSync(phaseDirectory).length === 0) io.rmdirSync(phaseDirectory);
        if (io.existsSync(requestDirectory)
          && io.readdirSync(requestDirectory).length === 0) io.rmdirSync(requestDirectory);
        if (error && typeof error === "object") error.preserveLease = true;
        throw error;
      }
    },

    async cleanupPartial(value) {
      const authority = normalizePartialAuthority(value);
      validateRoot(root, "helper-results storage root");
      if (!io.existsSync(base)) return Object.freeze({ status: "absent" });
      validateRoot(base, "helper-results directory");
      const requestDirectory = path.join(base, authority.requestSha256);
      const phaseDirectory = path.join(requestDirectory, authority.phaseId);
      const leaf = path.join(phaseDirectory, "results.json");
      if (!io.existsSync(requestDirectory)) return Object.freeze({ status: "absent" });
      validateRoot(requestDirectory, "helper-results partial request directory");
      const requestInventory = io.readdirSync(requestDirectory).map(String).sort();
      if (canonicalJson(requestInventory) !== canonicalJson([])
        && canonicalJson(requestInventory) !== canonicalJson([authority.phaseId])) {
        throw new Error("helper-results partial request inventory is not exact");
      }
      if (io.existsSync(phaseDirectory)) {
        validateRoot(phaseDirectory, "helper-results partial phase directory");
        const phaseInventory = io.readdirSync(phaseDirectory).map(String).sort();
        if (canonicalJson(phaseInventory) !== canonicalJson([])
          && canonicalJson(phaseInventory) !== canonicalJson(["results.json"])) {
          throw new Error("helper-results partial phase inventory is not exact");
        }
        if (io.existsSync(leaf)) {
          const leafStat = io.lstatSync(leaf, { bigint: true });
          assertSnapshotLeafStat(leafStat, expectedUid, expectedGid);
          if (leafStat.size > 512n * 1024n
            || path.resolve(String(io.realpathSync(leaf))) !== leaf) {
            throw new Error("helper-results partial leaf size or realpath is unsafe");
          }
          io.unlinkSync(leaf);
          syncDirectory(phaseDirectory);
        }
        if (io.readdirSync(phaseDirectory).length !== 0) {
          throw new Error("helper-results partial phase inventory changed during cleanup");
        }
        io.rmdirSync(phaseDirectory);
        syncDirectory(requestDirectory);
      }
      if (io.readdirSync(requestDirectory).length !== 0) {
        throw new Error("helper-results partial request inventory changed during cleanup");
      }
      io.rmdirSync(requestDirectory);
      syncDirectory(base);
      return Object.freeze({ status: "cleaned" });
    },

    async cleanup(value) {
      if (!isPlainRecord(value) || !hasExactKeys(value, [
        "action", "containerPath", "hostPath", "phaseId", "relativePath", "requestId",
        "requestSha256", "schema", "sha256", "sizeBytes", "volumeId", "volumeName",
      ]) || value.schema !== "platform.docker-helper-results.snapshot/v1"
        || value.containerPath !== "/run/platform/helper-results/results.json"
        || value.volumeId !== "broker.state"
        || value.relativePath !== `helper-results/${value.requestSha256}/${value.phaseId}/results.json`
        || !/^[a-f0-9]{64}$/.test(String(value.requestSha256 ?? ""))
        || !/^[a-f0-9]{64}$/.test(String(value.sha256 ?? ""))
        || !Number.isSafeInteger(value.sizeBytes) || value.sizeBytes < 2) {
        throw new TypeError("sealed helper-results snapshot is invalid");
      }
      const requestDirectory = path.join(base, value.requestSha256);
      const phaseDirectory = path.join(requestDirectory, value.phaseId);
      const leaf = path.join(phaseDirectory, "results.json");
      validateRoot(requestDirectory, "helper-results request directory");
      validateRoot(phaseDirectory, "helper-results phase directory");
      const leafStat = io.lstatSync(leaf, { bigint: true });
      assertSnapshotLeafStat(leafStat, expectedUid, expectedGid, value.sizeBytes);
      const descriptor = io.openSync(leaf, io.constants.O_RDONLY | io.constants.O_NOFOLLOW);
      try {
        const opened = io.fstatSync(descriptor, { bigint: true });
        assertSnapshotLeafStat(opened, expectedUid, expectedGid, value.sizeBytes);
        const bytes = readDescriptorWithIo(io, descriptor, value.sizeBytes);
        if (sha256(bytes) !== value.sha256) throw new Error("helper-results snapshot digest changed before cleanup");
      } finally {
        io.closeSync(descriptor);
      }
      io.unlinkSync(leaf);
      const phaseDescriptor = io.openSync(phaseDirectory, io.constants.O_RDONLY | io.constants.O_DIRECTORY | io.constants.O_NOFOLLOW);
      try { io.fsyncSync(phaseDescriptor); } finally { io.closeSync(phaseDescriptor); }
      io.rmdirSync(phaseDirectory);
      const requestDescriptor = io.openSync(requestDirectory, io.constants.O_RDONLY | io.constants.O_DIRECTORY | io.constants.O_NOFOLLOW);
      try { io.fsyncSync(requestDescriptor); } finally { io.closeSync(requestDescriptor); }
      if (io.readdirSync(requestDirectory).length === 0) io.rmdirSync(requestDirectory);
      syncDirectory(base);
      return Object.freeze({ status: "cleaned" });
    },
  });
}

function normalizeHelperResultsSnapshot(value) {
  if (!isPlainRecord(value) || !hasExactKeys(value, [
    "action", "containerPath", "hostPath", "phaseId", "relativePath", "requestId",
    "requestSha256", "schema", "sha256", "sizeBytes", "volumeId", "volumeName",
  ]) || value.schema !== "platform.docker-helper-results.snapshot/v1"
    || value.containerPath !== "/run/platform/helper-results/results.json"
    || value.volumeId !== "broker.state"
    || !isLogicalLeaseId(value.phaseId)
    || !/^[a-f0-9]{64}$/.test(String(value.requestSha256 ?? ""))
    || !/^[a-f0-9]{64}$/.test(String(value.sha256 ?? ""))
    || !Number.isSafeInteger(value.sizeBytes) || value.sizeBytes < 2
    || value.relativePath !== `helper-results/${value.requestSha256}/${value.phaseId}/results.json`
    || typeof value.hostPath !== "string" || !path.isAbsolute(value.hostPath)) {
    throw new TypeError("sealed helper-results snapshot is invalid");
  }
  return value;
}

function normalizeSnapshotInput(value) {
  if (isPlainRecord(value) && Object.hasOwn(value, "hostPath")) {
    throw new TypeError("claimed snapshot host path is not caller-controlled authority");
  }
  if (!isPlainRecord(value)
    || !hasExactKeys(value, [
      "bytes",
      "jobFileName",
      "jobId",
      "jobOperation",
      "jobSha256",
      "sourceId",
    ])
    || !Buffer.isBuffer(value.bytes)
    || value.bytes.length < 1
    || value.sourceId !== "jobs.running"
    || value.jobFileName !== `${value.jobId}.json`
    || !["backup", "restore-drill"].includes(value.jobOperation)
    || !/^[a-f0-9]{64}$/.test(String(value.jobSha256 ?? ""))
    || sha256(value.bytes) !== value.jobSha256) {
    throw new TypeError("claimed snapshot input is invalid");
  }
  return value;
}

function normalizeSnapshotAuthority(value, snapshot) {
  if (!isPlainRecord(value)
    || !hasExactKeys(value, ["request", "requestId", "requestSha256", "source", "volumeInspect"])
    || !isPlainRecord(value.request)
    || value.requestId !== value.request.requestId
    || value.requestSha256 !== sha256(canonicalJson(value.request))
    || !/^[a-f0-9]{64}$/.test(String(value.requestSha256 ?? ""))
    || value.request.action !== "backup.job.execute"
    || canonicalJson(value.request.parameters) !== canonicalJson({
      jobFileName: snapshot.jobFileName,
      jobId: snapshot.jobId,
      jobOperation: snapshot.jobOperation,
      jobSha256: snapshot.jobSha256,
    })) {
    throw new TypeError("snapshot request authority is invalid");
  }
  const source = value.source;
  if (!isPlainRecord(source)
    || !hasExactKeys(source, [
      "brokerRoot",
      "maximumBytes",
      "snapshotContainerPath",
      "snapshotVolumeId",
      "snapshotVolumeSubpath",
      "volumeId",
      "volumeSubpath",
    ])
    || source.snapshotContainerPath !== "/run/platform/claimed-job/job.json"
    || source.snapshotVolumeId !== "broker.state"
    || source.snapshotVolumeSubpath !== "claimed-jobs"
    || source.volumeId !== "jobs.queue"
    || source.volumeSubpath !== "running"
    || !Number.isSafeInteger(source.maximumBytes)
    || snapshot.bytes.length > source.maximumBytes) {
    throw new TypeError("snapshot claimed-job source subpath authority is invalid");
  }
  const inspect = value.volumeInspect;
  const expectedVolumeName = "platform_infra_vps_docker_action_broker_state";
  if (!isPlainRecord(inspect)
    || !hasExactKeys(inspect, ["Driver", "Labels", "Mountpoint", "Name", "Options", "Scope"])
    || inspect.Name !== expectedVolumeName
    || inspect.Driver !== "local"
    || inspect.Scope !== "local"
    || canonicalJson(inspect.Labels) !== canonicalJson({
      "com.docker.compose.volume": expectedVolumeName,
      "com.platform.volume-authority": "docker-action-broker-v2",
    })
    || canonicalJson(inspect.Options) !== canonicalJson({})
    || typeof inspect.Mountpoint !== "string"
    || inspect.Mountpoint.includes("\0")
    || !path.isAbsolute(inspect.Mountpoint)
    || path.normalize(inspect.Mountpoint) !== inspect.Mountpoint) {
    throw new TypeError("snapshot broker.state volume authority is invalid");
  }
  return value;
}

function snapshotHostLeaf(authority) {
  const mountpoint = authority.volumeInspect.Mountpoint;
  const requestDirectory = path.join(
    mountpoint,
    authority.source.snapshotVolumeSubpath,
    authority.requestSha256,
  );
  const leaf = path.join(requestDirectory, "job.json");
  if (path.dirname(path.dirname(requestDirectory)) !== mountpoint
    || path.basename(path.dirname(requestDirectory))
      !== authority.source.snapshotVolumeSubpath
    || path.basename(requestDirectory) !== authority.requestSha256
    || [requestDirectory, leaf].some((candidate) => candidate.includes("\0")
      || !path.isAbsolute(candidate)
      || path.normalize(candidate) !== candidate)) {
    throw new Error("snapshot Engine host path escaped its exact volume authority");
  }
  return leaf;
}

function normalizeSealedSnapshot(value) {
  const keys = [
    "containerPath",
    "hostPath",
    "jobFileName",
    "jobId",
    "jobOperation",
    "jobSha256",
    "requestSha256",
    "snapshotVolumeId",
    "snapshotVolumeMountpoint",
    "snapshotVolumeName",
    "snapshotVolumeSubpath",
    "sourceId",
  ];
  if (!isPlainRecord(value) || !hasExactKeys(value, keys)
    || value.sourceId !== "jobs.running"
    || value.snapshotVolumeId !== "broker.state"
    || value.snapshotVolumeSubpath !== "claimed-jobs"
    || value.snapshotVolumeName !== "platform_infra_vps_docker_action_broker_state"
    || value.jobFileName !== `${value.jobId}.json`
    || !["backup", "restore-drill"].includes(value.jobOperation)
    || !/^[a-f0-9]{64}$/.test(String(value.jobSha256 ?? ""))
    || !/^[a-f0-9]{64}$/.test(String(value.requestSha256 ?? ""))
    || typeof value.snapshotVolumeMountpoint !== "string"
    || !path.isAbsolute(value.snapshotVolumeMountpoint)
    || path.normalize(value.snapshotVolumeMountpoint) !== value.snapshotVolumeMountpoint) {
    throw snapshotPreserveError("sealed snapshot record is invalid");
  }
  return value;
}

function assertSnapshotPathLayout({
  ancestor,
  claimedJobsDirectory,
  leaf,
  mountpoint,
  requestDirectory,
  requestSha256,
  subpath,
}) {
  if (path.dirname(mountpoint) !== ancestor
    || path.join(mountpoint, subpath) !== claimedJobsDirectory
    || path.join(claimedJobsDirectory, requestSha256) !== requestDirectory
    || path.join(requestDirectory, "job.json") !== leaf
    || [ancestor, mountpoint, claimedJobsDirectory, requestDirectory, leaf]
      .some((candidate) => candidate.includes("\0") || !path.isAbsolute(candidate)
        || path.normalize(candidate) !== candidate)) {
    throw new Error("snapshot path authority escaped its exact layout");
  }
}

function openSnapshotDirectory(io, directory, { expectedUid, expectedGid, label }) {
  const pathStat = io.lstatSync(directory, { bigint: true });
  assertSnapshotDirectoryStat(pathStat, expectedUid, expectedGid, label);
  if (path.resolve(String(io.realpathSync(directory))) !== directory) {
    throw new Error(`${label} realpath escaped its exact authority path`);
  }
  const descriptor = io.openSync(
    directory,
    io.constants.O_RDONLY | io.constants.O_DIRECTORY | io.constants.O_NOFOLLOW,
  );
  try {
    const initial = io.fstatSync(descriptor, { bigint: true });
    assertSnapshotDirectoryStat(initial, expectedUid, expectedGid, label);
    if (!sameSnapshotIdentity(pathStat, initial)) {
      throw new Error(`${label} pathname and descriptor identities diverged`);
    }
    return { closed: false, descriptor, directory, initial, label, settled: initial };
  } catch (error) {
    io.closeSync(descriptor);
    throw error;
  }
}

function revalidateSnapshotDirectory(io, pin, policy) {
  revalidateSnapshotDirectories(io, [pin], policy);
}

function revalidateSnapshotDirectories(io, pins, { expectedUid, expectedGid }) {
  const observations = pins.map((pin) => {
    const descriptorStat = io.fstatSync(pin.descriptor, { bigint: true });
    const pathStat = io.lstatSync(pin.directory, { bigint: true });
    return {
      descriptorCtimeNs: descriptorStat.ctimeNs,
      descriptorMtimeNs: descriptorStat.mtimeNs,
      descriptorStat,
      pathCtimeNs: pathStat.ctimeNs,
      pathMtimeNs: pathStat.mtimeNs,
      pathStat,
      pin,
      resolved: path.resolve(String(io.realpathSync(pin.directory))),
    };
  });
  for (const { descriptorStat, pathStat, pin } of observations) {
    if (!pathStat?.isDirectory?.()
      || pathStat.isSymbolicLink?.()
      || pathStat.dev !== descriptorStat.dev
      || pathStat.ino !== descriptorStat.ino) {
      throw new Error(`${pin.label} pathname no longer resolves to the pinned directory`);
    }
  }
  for (const { pin, resolved } of observations) {
    if (resolved !== pin.directory) {
      throw new Error(`${pin.label} realpath no longer resolves to its canonical authority`);
    }
  }
  for (const {
    descriptorCtimeNs,
    descriptorMtimeNs,
    pathCtimeNs,
    pathMtimeNs,
    pin,
  } of observations) {
    if (descriptorMtimeNs !== pin.settled.mtimeNs
      || pathMtimeNs !== descriptorMtimeNs) {
      throw new Error(`${pin.label} pinned directory settled mtimeNs changed`);
    }
    if (descriptorCtimeNs !== pin.settled.ctimeNs
      || pathCtimeNs !== descriptorCtimeNs) {
      throw new Error(`${pin.label} pinned directory settled ctimeNs changed`);
    }
  }
  for (const { descriptorStat, pathStat, pin } of observations) {
    assertSnapshotDirectoryStat(descriptorStat, expectedUid, expectedGid, pin.label);
    assertSnapshotDirectoryStat(pathStat, expectedUid, expectedGid, pin.label);
    if (!sameSnapshotIdentity(descriptorStat, pathStat)) {
      throw new Error(`${pin.label} pathname metadata diverged from the pinned directory`);
    }
    io.readdirSync(pin.directory);
  }
}

function assertSnapshotDirectoryStat(stat, expectedUid, expectedGid, label) {
  if (!stat?.isDirectory?.() || stat.isSymbolicLink?.()
    || stat.uid !== BigInt(expectedUid) || stat.gid !== BigInt(expectedGid)
    || (stat.mode & 0o777n) !== 0o700n) {
    throw new Error(`${label} owner, mode, symlink or type is unsafe`);
  }
}

function assertSnapshotLeafStat(stat, expectedUid, expectedGid, expectedSize) {
  if (!stat?.isFile?.() || stat.isSymbolicLink?.()
    || stat.uid !== BigInt(expectedUid) || stat.gid !== BigInt(expectedGid)
    || stat.nlink !== 1n || (stat.mode & 0o777n) !== 0o400n
    || (expectedSize !== undefined && stat.size !== BigInt(expectedSize))) {
    throw new Error("snapshot leaf owner, mode, hardlink, type or size is invalid");
  }
}

function sameSnapshotIdentity(left, right) {
  return [
    "dev",
    "ino",
    "mode",
    "uid",
    "gid",
    "nlink",
    "size",
    "mtimeNs",
    "ctimeNs",
  ].every((field) => left[field] === right[field])
    && left.isDirectory() === right.isDirectory()
    && left.isSymbolicLink() === right.isSymbolicLink();
}

function writeSnapshotBytes(io, descriptor, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const count = io.writeSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (!Number.isInteger(count) || count < 1 || count > bytes.length - offset) {
      throw new Error("snapshot descriptor write made no bounded progress");
    }
    offset += count;
  }
}

function rollbackUnwrittenSnapshot(io, {
  claimedPin,
  leaf,
  leafIdentity,
  requestDirectory,
  requestIdentity,
  requestPin,
}) {
  try {
    if (leafIdentity && leaf) {
      const currentLeaf = io.lstatSync(leaf, { bigint: true });
      if (currentLeaf?.isFile?.()
        && !currentLeaf.isSymbolicLink?.()
        && currentLeaf.dev === leafIdentity.dev
        && currentLeaf.ino === leafIdentity.ino
        && currentLeaf.size === 0n
        && path.resolve(String(io.realpathSync(leaf))) === leaf) {
        io.unlinkSync(leaf);
        if (requestPin && !requestPin.closed) {
          io.fsyncSync(requestPin.descriptor);
        }
      }
    }
    const baseline = requestPin?.initial ?? requestIdentity;
    if (!baseline || !requestDirectory) return;
    const currentRequest = io.lstatSync(requestDirectory, { bigint: true });
    if (!currentRequest?.isDirectory?.()
      || currentRequest.isSymbolicLink?.()
      || currentRequest.dev !== baseline.dev
      || currentRequest.ino !== baseline.ino
      || path.resolve(String(io.realpathSync(requestDirectory))) !== requestDirectory
      || io.readdirSync(requestDirectory).length !== 0) {
      return;
    }
    if (requestPin && !requestPin.closed) {
      io.closeSync(requestPin.descriptor);
      requestPin.closed = true;
    }
    io.rmdirSync(requestDirectory);
    if (claimedPin && !claimedPin.closed) io.fsyncSync(claimedPin.descriptor);
  } catch {}
}

function closeSnapshotPins(io, pins) {
  for (let index = pins.length - 1; index >= 0; index -= 1) {
    const pin = pins[index];
    if (pin.closed) continue;
    try {
      io.closeSync(pin.descriptor);
    } catch {}
    pin.closed = true;
  }
}

function snapshotPreserveError(message) {
  const error = new Error(message);
  error.preserveLease = true;
  return error;
}

export function readProtectedFile(file, maximumBytes = 4096, { expectedUid = 0, expectedGid = 0, parentRoot = "/" } = {}) {
  const resolved = path.resolve(file);
  assertProtectedParentChain(path.dirname(resolved), { expectedUid, expectedGid, parentRoot });
  let descriptor;
  try {
    descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.isSymbolicLink?.() || before.nlink !== 1 || before.uid !== expectedUid || before.gid !== expectedGid
      || before.size < 1 || before.size > maximumBytes || (before.mode & 0o077) !== 0 || (before.mode & 0o400) === 0) {
      throw new Error("protected input ownership, links, permissions or size are invalid");
    }
    const first = readDescriptor(descriptor, before.size);
    const second = readDescriptor(descriptor, before.size);
    const after = fs.fstatSync(descriptor);
    const stable = ["dev", "ino", "size", "mtimeMs", "ctimeMs", "mode", "uid", "gid", "nlink"]
      .every((field) => before[field] === after[field]);
    if (!stable || first.length !== second.length || !crypto.timingSafeEqual(first, second)) {
      throw new Error("protected input changed while being read");
    }
    return first;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function assertProtectedParentChain(directory, { expectedUid, expectedGid, parentRoot }) {
  let current = path.resolve(directory);
  const stop = path.resolve(parentRoot);
  const prefix = stop === path.parse(stop).root ? stop : `${stop}${path.sep}`;
  if (current !== stop && !current.startsWith(prefix)) throw new Error("protected input parent escaped its trusted root");
  while (true) {
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== expectedUid || stat.gid !== expectedGid || (stat.mode & 0o022) !== 0) {
      throw new Error("protected input parent directory is unsafe");
    }
    if (current === stop) break;
    const parent = path.dirname(current);
    if (parent === current) throw new Error("protected input parent did not reach its trusted root");
    current = parent;
  }
}

async function defaultTrustedContextProvider({ now }) {
  const intent = loadProtectedJson(process.env.DOCKER_ACTION_RUNTIME_INTENT_FILE || DEFAULT_INTENT_FILE);
  const receipt = loadProtectedJson(process.env.DOCKER_ACTION_ACTIVE_RECEIPT_FILE || DEFAULT_RECEIPT_FILE);
  const key = readProtectedFile(process.env.DOCKER_ACTION_RUNTIME_INTENT_TRUST_KEY_FILE || DEFAULT_TRUST_KEY_FILE);
  const trusted = normalizeTrustedContext(intent, receipt, key, { now });
  const policy = normalizeActivationPolicy(loadProtectedJson(DEFAULT_ACTIVATION_POLICY_FILE, 64 * 1024));
  const activationPath = path.join(DEFAULT_ACTIVATION_CAS_ROOT, `${trusted.intent.activationBundleSha256}.dsse.json`);
  const activationBytes = readProtectedFile(activationPath, MAX_TRUST_DOCUMENT_BYTES, {
    parentRoot: DEFAULT_ACTIVATION_CAS_ROOT,
  });
  const activation = verifyActivationEnvelope(activationBytes, policy, {
    activationEnvelopeSha256: trusted.intent.activationBundleSha256,
    candidateId: trusted.receipt.candidateId,
    combinedRenderSha256: trusted.receipt.combinedRenderSha256,
    dastChainSha256: trusted.receipt.dastChainSha256,
    environment: trusted.receipt.environment,
    generation: trusted.receipt.generation,
    releaseId: trusted.receipt.releaseId,
    runtimeIntentId: trusted.intent.intentId,
    sourceRenderSha256: trusted.receipt.sourceRenderSha256,
    targetId: trusted.receipt.targetId,
    treeSha256: trusted.receipt.treeSha256,
  }, { now });
  return Object.freeze({ ...trusted, activation });
}

async function defaultCapabilityProvider(action, contract) {
  if (!ACTIONS[action] || ACTIONS[action] !== contract) throw brokerError(403, "capability action mismatch");
  return readProtectedFile(contract.capabilityFile);
}

export function createSemanticActionExecutor({
  transport = new FixedDockerEngineTransport(),
  randomBytes = crypto.randomBytes,
  cleanupTimeoutMs = CLEANUP_TIMEOUT_MS,
  claimedJobSnapshotProvider = defaultClaimedJobSnapshotProvider,
  snapshotFileStore = createSnapshotFileStore(),
} = {}) {
  if (!Number.isInteger(cleanupTimeoutMs) || cleanupTimeoutMs < 1 || cleanupTimeoutMs > 60_000
    || typeof randomBytes !== "function" || typeof claimedJobSnapshotProvider !== "function"
    || !transport || typeof transport !== "object" || !snapshotFileStore
    || typeof snapshotFileStore !== "object") {
    throw new TypeError("semantic action executor policy is invalid");
  }

  const executePhaseInternal = async (action, phaseId, context) => {
    const admission = normalizeSemanticExecution(action, context);
    const plannedPhaseIds = semanticPhaseIds(admission);
    if (!plannedPhaseIds.includes(phaseId)) {
      throw brokerError(403, "semantic phase identity is not owned by the admitted action");
    }
    return executeSemanticWorkerPhase({
      admission,
      claimedJobSnapshotProvider,
      cleanupTimeoutMs,
      phaseId,
      randomBytes,
      snapshotFileStore,
      transport,
    });
  };

  return Object.freeze({
    async execute(action, context) {
      const contract = ACTIONS[action];
      if (!contract?.modeled) throw brokerError(422, "action is not modeled");
      const admission = normalizeSemanticExecution(action, context);
      if (contract.engineAction === "runtimeSnapshot") {
        return executeSemanticRuntimeSnapshot(admission, transport);
      }
      const phases = [];
      for (const phaseId of semanticPhaseIds(admission)) {
        phases.push(await executeSemanticWorkerPhase({
          admission,
          claimedJobSnapshotProvider,
          cleanupTimeoutMs,
          phaseId,
          randomBytes,
          snapshotFileStore,
          transport,
        }));
      }
      const result = semanticActionResult(admission, phases);
      recordSemanticCompletion(admission, result);
      return result;
    },

    async executePhase(action, phaseId, context) {
      const phase = await executePhaseInternal(action, phaseId, context);
      const admission = normalizeSemanticExecution(action, context);
      const result = semanticActionResult(admission, [phase]);
      recordSemanticCompletion(admission, result);
      return result;
    },

    async recoverLease(record, signal) {
      return recoverSemanticLease({
        cleanupTimeoutMs,
        record,
        signal,
        snapshotFileStore,
        transport,
      });
    },
  });
}

export function createSemanticHelperActionExecutor({
  transport = new FixedDockerEngineTransport(),
  randomBytes = crypto.randomBytes,
  cleanupTimeoutMs = CLEANUP_TIMEOUT_MS,
  claimedJobSnapshotProvider = defaultClaimedJobSnapshotProvider,
  helperResultsFileStore,
  readinessWait = defaultReadinessWait,
  snapshotFileStore = createSnapshotFileStore(),
} = {}) {
  if (!Number.isInteger(cleanupTimeoutMs) || cleanupTimeoutMs < 1 || cleanupTimeoutMs > 60_000
    || typeof randomBytes !== "function" || typeof claimedJobSnapshotProvider !== "function"
    || typeof readinessWait !== "function" || !transport || typeof transport !== "object"
    || !snapshotFileStore || typeof snapshotFileStore !== "object"
    || !helperResultsFileStore || typeof helperResultsFileStore !== "object"
    || typeof helperResultsFileStore.seal !== "function"
    || typeof helperResultsFileStore.cleanup !== "function"
    || typeof helperResultsFileStore.cleanupPartial !== "function") {
    throw new TypeError("semantic helper action executor policy is invalid");
  }
  return Object.freeze({
    async execute(action, context) {
      const contract = ACTIONS[action];
      if (!contract?.modeled) throw brokerError(422, "action is not modeled");
      const admission = normalizeSemanticExecution(action, context);
      if (contract.engineAction === "runtimeSnapshot") {
        return executeSemanticRuntimeSnapshot(admission, transport);
      }
      const phases = [];
      let priorBinding = null;
      for (const phaseId of semanticPhaseIds(admission)) {
        const phase = await executeSemanticHelperPhase({
          admission,
          claimedJobSnapshotProvider,
          cleanupTimeoutMs,
          helperResultsFileStore,
          phaseId,
          priorBinding,
          randomBytes,
          readinessWait,
          snapshotFileStore,
          transport,
        });
        phases.push(phase);
        if (phase.output?.artifactBinding) priorBinding = phase.output.artifactBinding;
      }
      const result = semanticActionResult(admission, phases);
      recordSemanticCompletion(admission, result);
      return result;
    },

    async recoverLease(record, signal) {
      return recoverSemanticHelperLease({
        cleanupTimeoutMs,
        helperResultsFileStore,
        randomBytes,
        readinessWait,
        record,
        signal,
        snapshotFileStore,
        transport,
      });
    },
  });
}

async function executeSemanticHelperPhase({
  admission,
  claimedJobSnapshotProvider,
  cleanupTimeoutMs,
  helperResultsFileStore,
  phaseId,
  priorBinding,
  randomBytes,
  readinessWait,
  snapshotFileStore,
  transport,
}) {
  const { action, context, parameters, request, requestId, requestSha256, trusted } = admission;
  const receipt = trusted.receipt;
  const phase = receipt.resources.phaseProfiles[phaseId];
  const sourceId = admission.actionProfile.claimedJobSourceId;
  let claimedBackupResources = null;
  let capturedSnapshot = null;
  let sealedSnapshot = null;
  let helperResultsSnapshot = null;
  let binding = priorBinding;
  const materializedScratch = new Set();
  let localMutationAttempt = null;
  let journalStarted = false;
  let failure = null;
  let phaseOutput = null;

  try {
    if (sourceId !== null) {
      const source = receipt.resources.claimedJobSources[sourceId];
      capturedSnapshot = await claimedJobSnapshotProvider({
        parameters: cloneCanonicalValue(parameters),
        source,
        sourceId,
      });
      claimedBackupResources = admitClaimedJobResources(capturedSnapshot, parameters, receipt);
    }
    const authority = semanticPhaseAuthority(
      receipt,
      action,
      phaseId,
      claimedBackupResources ?? undefined,
      { includeHelperResultsStorage: true },
    );
    const preflight = await preflightSemanticPhase({
      action,
      authority,
      phase,
      receipt,
      signal: context.signal,
      transport,
    });
    if (sourceId !== null) {
      const source = receipt.resources.claimedJobSources[sourceId];
      const predicted = semanticSnapshotRecord(capturedSnapshot, {
        requestSha256,
        source,
        volumeInspect: preflight.volumes[source.snapshotVolumeId],
      });
      if (typeof context.lease.recordRecoveryIntent === "function") {
        context.lease.recordRecoveryIntent({ phaseId, snapshot: predicted });
        journalStarted = true;
      }
      const observed = await snapshotFileStore.seal(capturedSnapshot, {
        request,
        requestId,
        requestSha256,
        source,
        volumeInspect: preflight.volumes[source.snapshotVolumeId],
      });
      if (canonicalJson(observed) !== canonicalJson(predicted)) {
        throw snapshotPreserveError("sealed snapshot identity differs from its admitted recovery intent");
      }
      sealedSnapshot = observed;
      context.lease.recordEvent({ event: "snapshot-materialized", phaseId, requestSha256, snapshot: sealedSnapshot });
      journalStarted = true;
    }

    if (["job.restore.verify", "offsite.sync"].includes(phaseId)) {
      binding = (await executeSemanticRoleWorker({
        admission,
        onLocalMutationAttempt: (attempt) => { localMutationAttempt = attempt; },
        artifactBinding: null,
        claimedBackupResources,
        cleanupTimeoutMs,
        helperResultsSnapshot: null,
        phaseId,
        randomBytes,
        role: "artifact-resolver",
        scratchEngine: null,
        sealedSnapshot,
        transport,
      })).output;
      journalStarted = true;
    }
    const plan = buildSemanticHelperPlan({
      claimedBackupResources,
      phaseId,
      priorBinding: binding,
      receipt,
      requestSha256,
    });
    const helperPlanSha256 = sha256(canonicalJson(plan));

    if (plan.helpers.length > 0) {
      await executeSemanticRoleWorker({
        admission,
        onLocalMutationAttempt: (attempt) => { localMutationAttempt = attempt; },
        artifactBinding: null,
        claimedBackupResources,
        cleanupTimeoutMs,
        helperResultsSnapshot: null,
        phaseId,
        randomBytes,
        role: "helper-preparer",
        scratchEngine: null,
        sealedSnapshot,
        transport,
      });
      journalStarted = true;
    }

    const scratchEngines = [...new Set(
      plan.helpers.filter((helper) => helper.paths.scratchRelativePath !== null).map((helper) => helper.engine),
    )].sort();
    for (const engine of scratchEngines) {
      await executeSemanticRoleWorker({
        admission,
        onLocalMutationAttempt: (attempt) => { localMutationAttempt = attempt; },
        artifactBinding: null,
        claimedBackupResources,
        cleanupTimeoutMs,
        helperResultsSnapshot: null,
        phaseId,
        randomBytes,
        role: "scratch-preparer",
        scratchEngine: engine,
        sealedSnapshot,
        transport,
      });
      const relativePath = `requests/${requestSha256}/${phaseId}/${engine}`;
      context.lease.recordEvent({ event: "scratch-materialized", engine, phaseId, relativePath, requestSha256 });
      materializedScratch.add(engine);
      journalStarted = true;
    }

    const helperResults = await executeSemanticHelpers({
      admission,
      artifactBinding: binding,
      cleanupTimeoutMs,
      claimedBackupResources,
      helperPlanSha256,
      plan,
      readinessWait,
      sealedSnapshot,
      transport,
    });
    journalStarted ||= plan.helpers.length > 0;

    for (const engine of [...materializedScratch].reverse()) {
      await executeSemanticRoleWorker({
        admission,
        onLocalMutationAttempt: (attempt) => { localMutationAttempt = attempt; },
        artifactBinding: null,
        claimedBackupResources,
        cleanupTimeoutMs,
        helperResultsSnapshot: null,
        phaseId,
        randomBytes,
        role: "scratch-cleaner",
        scratchEngine: engine,
        sealedSnapshot,
        transport,
      });
      const relativePath = `requests/${requestSha256}/${phaseId}/${engine}`;
      context.lease.recordEvent({ event: "scratch-cleaned", engine, phaseId, relativePath, requestSha256 });
      materializedScratch.delete(engine);
    }

    if (phaseId === "prune.plan" || phaseId === "prune.apply") {
      phaseOutput = (await executeSemanticRoleWorker({
        admission,
        onLocalMutationAttempt: (attempt) => { localMutationAttempt = attempt; },
        artifactBinding: null,
        claimedBackupResources,
        cleanupTimeoutMs,
        helperResultsSnapshot: null,
        phaseId,
        randomBytes,
        role: "standalone",
        scratchEngine: null,
        sealedSnapshot,
        transport,
      })).output;
    } else {
      const aggregate = {
        action,
        helpers: helperResults,
        phaseId,
        requestId,
        requestSha256,
        schema: "platform.docker-helper-results/v1",
      };
      const brokerStateInspect = preflight.volumes["broker.state"];
      if (!brokerStateInspect) throw brokerError(409, "helper-results storage volume was not preflighted");
      context.lease.recordEvent({
        event: "helper-results-seal-intent",
        phaseId,
        requestSha256,
      });
      journalStarted = true;
      helperResultsSnapshot = await helperResultsFileStore.seal(aggregate, {
        action,
        phaseId,
        requestId,
        requestSha256,
        volumeId: "broker.state",
        volumeInspect: brokerStateInspect,
      });
      context.lease.recordEvent({
        event: "helper-results-materialized",
        helperResultsSnapshot,
        phaseId,
        requestSha256,
      });
      phaseOutput = (await executeSemanticRoleWorker({
        admission,
        onLocalMutationAttempt: (attempt) => { localMutationAttempt = attempt; },
        artifactBinding: binding,
        claimedBackupResources,
        cleanupTimeoutMs,
        helperResultsSnapshot,
        phaseId,
        randomBytes,
        role: "evidence-finalizer",
        scratchEngine: null,
        sealedSnapshot,
        transport,
      })).output;
      await helperResultsFileStore.cleanup(helperResultsSnapshot);
      context.lease.recordEvent({
        event: "helper-results-cleaned",
        helperResultsSnapshot,
        phaseId,
        requestSha256,
      });
      helperResultsSnapshot = null;
    }
  } catch (error) {
    failure = error;
  }

  let cleanupFailure = null;
  for (const engine of [...materializedScratch].reverse()) {
    try {
      await executeSemanticRoleWorker({
        admission,
        onLocalMutationAttempt: (attempt) => { localMutationAttempt = attempt; },
        artifactBinding: null,
        claimedBackupResources,
        cleanupTimeoutMs,
        helperResultsSnapshot: null,
        phaseId,
        randomBytes,
        role: "scratch-cleaner",
        scratchEngine: engine,
        sealedSnapshot,
        transport,
      });
      const relativePath = `requests/${requestSha256}/${phaseId}/${engine}`;
      context.lease.recordEvent({ event: "scratch-cleaned", engine, phaseId, relativePath, requestSha256 });
      materializedScratch.delete(engine);
    } catch (error) {
      cleanupFailure ??= error;
    }
  }
  if (helperResultsSnapshot) {
    try {
      await helperResultsFileStore.cleanup(helperResultsSnapshot);
      context.lease.recordEvent({ event: "helper-results-cleaned", helperResultsSnapshot, phaseId, requestSha256 });
      helperResultsSnapshot = null;
    } catch (error) {
      cleanupFailure ??= error;
    }
  }
  if (sealedSnapshot) {
    try {
      await snapshotFileStore.cleanup(sealedSnapshot);
      context.lease.recordEvent({ event: "snapshot-cleaned", phaseId, requestSha256, snapshot: sealedSnapshot });
      sealedSnapshot = null;
    } catch (error) {
      cleanupFailure ??= error;
    }
  }
  if (cleanupFailure) {
    cleanupFailure.preserveLease = true;
    throw cleanupFailure;
  }
  if (failure) {
    if (journalStarted || localMutationAttempt) failure.preserveLease = true;
    if (localMutationAttempt?.cleanupComplete) {
      try {
        context.lease.recordEvent({
          event: "local-effect-unknown",
          phaseId: localMutationAttempt.phaseId,
          resourceName: localMutationAttempt.resourceName,
          workerId: localMutationAttempt.workerId,
        });
        failure.localEffectUnknown = true;
      } catch (terminalError) {
        terminalError.preserveLease = true;
        throw terminalError;
      }
    }
    throw failure;
  }
  return {
    output: phaseOutput,
    outputSchema: phase.outputSchema,
    outputSha256: sha256(canonicalJson(phaseOutput)),
    phaseId,
    status: "completed",
  };
}

function semanticClaimedJournalFields(claimedBackupResources, sealedSnapshot) {
  return claimedBackupResources
    ? { claimedBackupResources, snapshot: sealedSnapshot }
    : {};
}

async function executeSemanticRoleWorker({
  admission,
  artifactBinding,
  claimedBackupResources,
  cleanupTimeoutMs,
  helperResultsSnapshot,
  onLocalMutationAttempt = null,
  phaseId,
  randomBytes,
  role,
  scratchEngine,
  sealedSnapshot,
  transport,
}) {
  const { action, context, parameters, request, requestId, requestSha256, trusted } = admission;
  const phase = trusted.receipt.resources.phaseProfiles[phaseId];
  const body = workerCreateBody({
    action,
    artifactBinding: artifactBinding ?? undefined,
    claimedBackupResources: claimedBackupResources ?? undefined,
    claimedJobSnapshot: sealedSnapshot ?? undefined,
    helperResultsSnapshot: helperResultsSnapshot ?? undefined,
    parameters,
    phaseId,
    request,
    requestId,
    requestSha256,
    scratchEngine: scratchEngine ?? undefined,
    trusted,
    workerRole: role,
  });
  const entropy = randomBytes(12);
  if (!Buffer.isBuffer(entropy) || entropy.length !== 12) {
    throw new TypeError("semantic role worker name entropy is invalid");
  }
  const engineSlug = scratchEngine ? `-${scratchEngine}` : "";
  const resourceName = `platform-role-${phaseId.replaceAll(".", "-")}-${role}${engineSlug}-${entropy.toString("hex")}`;
  if (resourceName.length > 127) throw new TypeError("semantic role worker name is oversized");
  const scratchRole = role === "scratch-preparer" || role === "scratch-cleaner";
  const eventPrefix = scratchRole ? "scratch-bootstrap" : "role-worker";
  const record = {
    action,
    event: `${eventPrefix}-recorded`,
    phaseId,
    phaseProfileSha256: phase.phaseSha256,
    receiptDigest: trusted.receiptDigest,
    requestSha256,
    resourceName,
    workerRole: role,
    ...(scratchRole ? { engine: scratchEngine } : {}),
    ...semanticClaimedJournalFields(claimedBackupResources, sealedSnapshot),
    ...(!scratchRole && artifactBinding ? { artifactBinding } : {}),
    ...(!scratchRole && helperResultsSnapshot ? { helperResultsSnapshot } : {}),
  };
  context.lease.recordEvent(record);
  let createAttempted = false;
  const mutationClass = ["artifact-resolver", "evidence-finalizer"].includes(role)
    || (phaseId === "prune.apply" && role === "standalone")
    ? "local-nonidempotent"
    : "none";
  let startAttempted = false;
  let localMutationAttempt = null;
  let workerId = "";
  let result;
  let failure = null;
  try {
    requireSemanticTransport(transport, "createWorker");
    createAttempted = true;
    const created = await transport.createWorker(resourceName, body, context.signal);
    workerId = String(created?.Id ?? "");
    assertSemanticWorkerId(workerId);
    context.lease.recordEvent({
      event: `${eventPrefix}-created`,
      phaseId,
      resourceName,
      workerId,
      workerRole: role,
      ...(scratchRole ? { engine: scratchEngine } : {}),
    });
    requireSemanticTransport(transport, "inspectContainer");
    const inspect = await transport.inspectContainer(workerId, context.signal);
    assertExactSemanticWorkerInspect(inspect, {
      body,
      id: workerId,
      name: resourceName,
      phase,
      receipt: trusted.receipt,
      sealedSnapshot,
    });
    context.lease.recordEvent({
      event: `${eventPrefix}-start-attempted`,
      ...(scratchRole ? { engine: scratchEngine } : { mutationClass }),
      phaseId,
      resourceName,
      workerId,
      workerRole: role,
    });
    startAttempted = true;
    localMutationAttempt = mutationClass === "local-nonidempotent"
      ? { cleanupComplete: false, phaseId, resourceName, workerId }
      : null;
    if (localMutationAttempt && typeof onLocalMutationAttempt === "function") {
      onLocalMutationAttempt(localMutationAttempt);
    }
    requireSemanticTransport(transport, "startContainer");
    await transport.startContainer(workerId, context.signal);
    requireSemanticTransport(transport, "waitContainer");
    const waited = await transport.waitContainer(workerId, context.signal);
    if (!Number.isSafeInteger(Number(waited?.StatusCode)) || Number(waited.StatusCode) !== 0) {
      throw brokerError(500, `${role} worker failed`);
    }
    requireSemanticTransport(transport, "logsContainer");
    const logs = await transport.logsContainer(workerId, context.signal);
    result = parseSemanticWorkerOutput(logs, {
      action,
      parameters,
      phase,
      phaseId,
      requestId,
      requestSha256,
      workerRole: role,
    });
    context.lease.recordEvent({
      event: `${eventPrefix}-result-recorded`,
      phaseId,
      resourceName,
      workerId,
      workerResultSha256: sha256(canonicalJson(result)),
      workerRole: role,
      ...(scratchRole ? { engine: scratchEngine } : {}),
    });
  } catch (error) {
    failure = error;
  }
  let cleanupFailure = null;
  if (createAttempted) {
    try {
      const deletedId = await withTimeout(async (signal) => {
        let id = workerId;
        if (!id) {
          requireSemanticTransport(transport, "inspectContainerForRecovery");
          const inspect = await transport.inspectContainerForRecovery(resourceName, signal);
          if (!inspect) return null;
          id = String(inspect.Id ?? "");
          assertSemanticWorkerId(id);
          assertExactSemanticWorkerInspect(inspect, {
            body,
            id,
            name: resourceName,
            phase,
            receipt: trusted.receipt,
            sealedSnapshot,
          });
        }
        requireSemanticTransport(transport, "deleteContainer");
        await transport.deleteContainer(id, signal);
        return id;
      }, cleanupTimeoutMs, `${role} worker cleanup timed out`);
      if (deletedId) {
        context.lease.recordEvent({
          event: `${eventPrefix}-deleted`,
          phaseId,
          resourceName,
          workerId: deletedId,
          workerRole: role,
          ...(scratchRole ? { engine: scratchEngine } : {}),
        });
        if (localMutationAttempt) localMutationAttempt.cleanupComplete = true;
      }
    } catch (error) {
      cleanupFailure = error;
    }
  }
  if (cleanupFailure) {
    cleanupFailure.preserveLease = true;
    throw cleanupFailure;
  }
  if (failure) {
    if (mutationClass === "local-nonidempotent" && startAttempted) {
      failure.localEffectUnknown = true;
    }
    failure.preserveLease = true;
    throw failure;
  }
  return result;
}

async function executeSemanticHelpers({
  admission,
  artifactBinding,
  cleanupTimeoutMs,
  claimedBackupResources,
  helperPlanSha256,
  plan,
  readinessWait,
  sealedSnapshot,
  transport,
}) {
  const { action, context, requestSha256, trusted } = admission;
  const phaseId = plan.phaseId;
  const phase = trusted.receipt.resources.phaseProfiles[phaseId];
  const active = [];
  const createdByProfile = new Map();
  const results = [];
  let failure = null;
  let remoteUnknown = null;
  try {
    for (const planned of plan.helpers) {
      requireSemanticTransport(transport, "inspectHelperImage");
      const imageInspect = await transport.inspectHelperImage(planned.imageId, context.signal);
      const bound = bindSemanticHelperImageInspect(planned, imageInspect);
      const helper = resolveDeferredSemanticHelper(bound, createdByProfile);
      const { bodySha256, imageRuntimeConfigSha256 } = helper;
      context.lease.recordEvent({
        action,
        ...(artifactBinding ? { artifactBinding } : {}),
        bodySha256,
        event: "helper-recorded",
        helperPlanSha256,
        helperProfileId: helper.helperProfileId,
        imageRuntimeConfigSha256,
        ordinal: helper.ordinal,
        phaseId,
        phaseProfileSha256: phase.phaseSha256,
        receiptDigest: trusted.receiptDigest,
        requestSha256,
        resourceName: helper.name,
        ...semanticClaimedJournalFields(claimedBackupResources, sealedSnapshot),
      });
      const state = {
        createAttempted: false,
        helper,
        remoteAttempted: false,
        workerId: "",
      };
      active.push(state);
      requireSemanticTransport(transport, "createHelper");
      state.createAttempted = true;
      const created = await transport.createHelper(helper.name, helper.body, context.signal);
      const workerId = String(created?.Id ?? "");
      assertSemanticWorkerId(workerId);
      state.workerId = workerId;
      createdByProfile.set(helper.helperProfileId, workerId);
      context.lease.recordEvent({
        event: "helper-created",
        helperProfileId: helper.helperProfileId,
        phaseId,
        resourceName: helper.name,
        workerId,
      });
      requireSemanticTransport(transport, "inspectHelper");
      const inspect = await transport.inspectHelper(workerId, context.signal);
      assertExactSemanticHelperInspect(inspect, { ...helper, body: helper.body });
      const remoteAttempt = helper.lifecycle.remoteEffect === "ambiguous-preserve-lease-no-retry";
      context.lease.recordEvent({
        event: "helper-start-attempted",
        helperProfileId: helper.helperProfileId,
        phaseId,
        remoteAttempt,
        resourceName: helper.name,
        workerId,
      });
      state.remoteAttempted = remoteAttempt;
      requireSemanticTransport(transport, "startHelper");
      await transport.startHelper(workerId, context.signal);
      context.lease.recordEvent({
        event: "helper-started",
        helperProfileId: helper.helperProfileId,
        phaseId,
        resourceName: helper.name,
        workerId,
      });
      let helperResult;
      if (helper.lifecycle.waitForExit === false) {
        await waitForSemanticHelperReadiness({
          helper,
          readinessWait,
          signal: context.signal,
          transport,
          workerId,
        });
        context.lease.recordEvent({
          event: "helper-ready",
          helperProfileId: helper.helperProfileId,
          phaseId,
          resourceName: helper.name,
          workerId,
        });
        helperResult = normalizeSemanticHelperResult({ helper, logs: Buffer.alloc(0), statusCode: 0 });
      } else {
        requireSemanticTransport(transport, "waitHelper");
        const waited = await transport.waitHelper(workerId, context.signal);
        const statusCode = Number(waited?.StatusCode);
        requireSemanticTransport(transport, "logsHelper");
        const logs = await transport.logsHelper(workerId, context.signal);
        helperResult = normalizeSemanticHelperResult({ helper, logs, statusCode });
      }
      context.lease.recordEvent({
        event: "helper-result-recorded",
        helperProfileId: helper.helperProfileId,
        phaseId,
        resourceName: helper.name,
        workerId,
        workerResultSha256: sha256(canonicalJson(helperResult)),
      });
      results.push(helperResult);
    }
  } catch (error) {
    failure = error;
    remoteUnknown = [...active].reverse().find(({ remoteAttempted }) => remoteAttempted) ?? null;
  }

  let cleanupFailure = null;
  for (const state of [...active].reverse()) {
    try {
      const deletedId = await withTimeout(async (signal) => {
        let id = state.workerId;
        let inspect;
        if (id) {
          requireSemanticTransport(transport, "inspectHelper");
          inspect = await transport.inspectHelper(id, signal);
        } else {
          requireSemanticTransport(transport, "inspectHelperForRecovery");
          inspect = await transport.inspectHelperForRecovery(state.helper.name, signal);
          if (!inspect) return null;
          id = String(inspect.Id ?? "");
          assertSemanticWorkerId(id);
          context.lease.recordEvent({
            event: "helper-created",
            helperProfileId: state.helper.helperProfileId,
            phaseId,
            resourceName: state.helper.name,
            workerId: id,
          });
        }
        assertExactSemanticHelperInspect(inspect, { ...state.helper, body: state.helper.body });
        requireSemanticTransport(transport, "deleteHelper");
        await transport.deleteHelper(id, signal);
        return id;
      }, cleanupTimeoutMs, "semantic helper cleanup timed out");
      if (deletedId) {
        state.workerId = deletedId;
        context.lease.recordEvent({
          event: "helper-deleted",
          helperProfileId: state.helper.helperProfileId,
          phaseId,
          resourceName: state.helper.name,
          workerId: deletedId,
        });
      }
    } catch (error) {
      cleanupFailure ??= error;
    }
  }
  if (remoteUnknown && !cleanupFailure) {
    try {
      context.lease.recordEvent({
        event: "remote-effect-unknown",
        phaseId,
        resourceName: remoteUnknown.helper.name,
        workerId: remoteUnknown.workerId,
      });
    } catch (error) {
      cleanupFailure = error;
    }
  }
  if (cleanupFailure) {
    cleanupFailure.preserveLease = true;
    throw cleanupFailure;
  }
  if (failure) {
    if (remoteUnknown) failure.remoteEffectUnknown = true;
    failure.preserveLease = true;
    throw failure;
  }
  return results;
}

function resolveDeferredSemanticHelper(helper, createdByProfile) {
  if (helper.body) return helper;
  const deferred = helper.deferredBody;
  const requiredProfile = deferred?.requires?.helperProfileId;
  const workerId = createdByProfile.get(requiredProfile);
  if (!isPlainRecord(deferred) || deferred.networkModePrefix !== "container:"
    || deferred.requires?.value !== "containerId"
    || !/^[a-f0-9]{64}$/.test(String(workerId ?? ""))) {
    throw brokerError(409, "deferred semantic helper dependency is unresolved");
  }
  const body = cloneCanonicalValue(deferred.baseBody);
  body.HostConfig.NetworkMode = `container:${workerId}`;
  return Object.freeze({
    ...helper,
    body: freezeCanonicalValue(body),
    bodySha256: sha256(canonicalJson(body)),
    expectedInspect: freezeCanonicalValue(deferred.expectedInspect),
  });
}

async function waitForSemanticHelperReadiness({ helper, readinessWait, signal, transport, workerId }) {
  const policy = helper.lifecycle.readiness;
  if (!isPlainRecord(policy) || policy.kind !== "container-health"
    || policy.expectedHealth !== "healthy" || !Number.isSafeInteger(policy.maximumAttempts)
    || policy.maximumAttempts < 1 || policy.maximumAttempts > 120
    || !Number.isSafeInteger(policy.intervalMs) || policy.intervalMs < 1 || policy.intervalMs > 10_000) {
    throw brokerError(409, "semantic helper readiness policy is invalid");
  }
  for (let attempt = 0; attempt < policy.maximumAttempts; attempt += 1) {
    requireSemanticTransport(transport, "inspectHelper");
    const inspect = await transport.inspectHelper(workerId, signal);
    assertExactSemanticHelperInspect(inspect, { ...helper, body: helper.body });
    if (inspect.State?.Health?.Status === "healthy") return;
    if (["unhealthy", "exited", "dead"].includes(inspect.State?.Health?.Status)
      || inspect.State?.Running === false) {
      throw brokerError(500, `${helper.helperProfileId} readiness failed`);
    }
    if (attempt + 1 < policy.maximumAttempts) {
      await readinessWait(policy.intervalMs, signal);
    }
  }
  throw brokerError(504, `${helper.helperProfileId} readiness timed out`);
}

function defaultReadinessWait(milliseconds, signal) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(resolve, milliseconds);
    const abort = () => {
      clearTimeout(timeout);
      reject(brokerError(504, "semantic helper readiness was aborted"));
    };
    if (signal?.aborted) return abort();
    signal?.addEventListener?.("abort", abort, { once: true });
  });
}

async function recoverSemanticHelperLease({
  cleanupTimeoutMs,
  helperResultsFileStore,
  randomBytes,
  readinessWait,
  record,
  signal,
  snapshotFileStore,
  transport,
}) {
  const newEvents = new Set([
    "helper-created", "helper-deleted", "helper-recorded", "helper-ready",
    "helper-result-recorded", "helper-results-cleaned", "helper-results-intent-cleaned",
    "helper-results-materialized", "helper-results-seal-intent",
    "helper-start-attempted", "helper-started", "role-worker-created", "role-worker-deleted",
    "role-worker-recorded", "role-worker-result-recorded", "role-worker-start-attempted", "scratch-bootstrap-created",
    "scratch-bootstrap-deleted", "scratch-bootstrap-recorded", "scratch-bootstrap-result-recorded",
    "scratch-bootstrap-start-attempted", "scratch-cleaned", "scratch-materialized",
  ]);
  if (!record?.journalEntries?.some((entry) => newEvents.has(entry.event))) {
    return recoverSemanticLease({
      cleanupTimeoutMs,
      record,
      signal,
      snapshotFileStore,
      transport,
    });
  }
  if (!isPlainRecord(record) || !isPlainRecord(record.request)
    || !isPlainRecord(record.trusted) || !Array.isArray(record.journalEntries)
    || typeof record.recordEvent !== "function") {
    throw new Error("semantic helper recovery lease lineage is invalid");
  }
  const admission = Object.freeze({
    action: record.action,
    actionProfile: record.trusted.receipt.resources.actionProfiles[record.action],
    context: {
      lease: { recordEvent: record.recordEvent },
      signal,
    },
    parameters: record.request.parameters,
    request: record.request,
    requestId: record.requestId,
    requestSha256: record.requestSha256,
    trusted: record.trusted,
  });
  const roleWorkers = new Map();
  const helpers = new Map();
  const helperCreatedIds = new Map();
  const scratchWorkers = new Map();
  const scratchOutstanding = new Map();
  const helperSnapshots = new Map();
  const helperResultIntents = new Set();
  const claimedSnapshots = new Map();
  const cleanedScratchKeys = new Set();
  let localAttempt = null;
  let remoteAttempt = null;
  for (const entry of record.journalEntries) {
    if (entry.event === "snapshot-materialized") claimedSnapshots.set(entry.phaseId, entry.snapshot);
    if (entry.event === "snapshot-cleaned") claimedSnapshots.delete(entry.phaseId);
    if (entry.event === "helper-results-seal-intent") helperResultIntents.add(entry.phaseId);
    if (entry.event === "helper-results-materialized") helperSnapshots.set(entry.phaseId, entry.helperResultsSnapshot);
    if (entry.event === "helper-results-cleaned") {
      helperSnapshots.delete(entry.phaseId);
      helperResultIntents.delete(entry.phaseId);
    }
    if (entry.event === "helper-results-intent-cleaned") helperResultIntents.delete(entry.phaseId);
    if (entry.event === "scratch-materialized") scratchOutstanding.set(`${entry.phaseId}\0${entry.engine}`, entry);
    if (entry.event === "scratch-cleaned") {
      const key = `${entry.phaseId}\0${entry.engine}`;
      cleanedScratchKeys.add(key);
      scratchOutstanding.delete(key);
    }
    if (entry.event === "role-worker-recorded") {
      roleWorkers.set(entry.resourceName, {
        deleted: false,
        entry,
        mutationClass: null,
        resultRecorded: false,
        startAttempted: false,
        workerId: null,
      });
    } else if (entry.event === "role-worker-created") {
      const state = roleWorkers.get(entry.resourceName);
      if (state) state.workerId = entry.workerId;
    } else if (entry.event === "role-worker-start-attempted") {
      const state = roleWorkers.get(entry.resourceName);
      if (state) {
        state.startAttempted = true;
        state.mutationClass = entry.mutationClass;
      }
    } else if (entry.event === "role-worker-result-recorded") {
      const state = roleWorkers.get(entry.resourceName);
      if (state) state.resultRecorded = true;
    } else if (entry.event === "role-worker-deleted") {
      const state = roleWorkers.get(entry.resourceName);
      if (state) state.deleted = true;
    }
    if (entry.event === "scratch-bootstrap-recorded") {
      scratchWorkers.set(entry.resourceName, {
        deleted: false,
        entry,
        startAttempted: false,
        workerId: null,
      });
    } else if (entry.event === "scratch-bootstrap-created") {
      const state = scratchWorkers.get(entry.resourceName);
      if (state) state.workerId = entry.workerId;
    } else if (entry.event === "scratch-bootstrap-start-attempted") {
      const state = scratchWorkers.get(entry.resourceName);
      if (state) state.startAttempted = true;
    } else if (entry.event === "scratch-bootstrap-deleted") {
      const state = scratchWorkers.get(entry.resourceName);
      if (state) state.deleted = true;
    }
    if (entry.event === "helper-recorded") {
      helpers.set(entry.resourceName, { deleted: false, entry, workerId: null });
    } else if (entry.event === "helper-created") {
      const state = helpers.get(entry.resourceName);
      if (state) {
        state.workerId = entry.workerId;
        helperCreatedIds.set(entry.helperProfileId, entry.workerId);
      }
    } else if (entry.event === "helper-deleted") {
      const state = helpers.get(entry.resourceName);
      if (state) state.deleted = true;
    } else if (entry.event === "helper-start-attempted" && entry.remoteAttempt) {
      remoteAttempt = { resourceName: entry.resourceName, workerId: entry.workerId, phaseId: entry.phaseId };
    }
  }
  for (const state of roleWorkers.values()) {
    if (state.startAttempted && state.mutationClass === "local-nonidempotent") {
      localAttempt = {
        phaseId: state.entry.phaseId,
        resourceName: state.entry.resourceName,
        workerId: state.workerId,
      };
    }
  }
  for (const state of scratchWorkers.values()) {
    if (state.entry.workerRole !== "scratch-preparer") continue;
    const key = `${state.entry.phaseId}\0${state.entry.engine}`;
    if (cleanedScratchKeys.has(key)) continue;
    scratchOutstanding.set(key, {
      engine: state.entry.engine,
      phaseId: state.entry.phaseId,
      relativePath: `requests/${record.requestSha256}/${state.entry.phaseId}/${state.entry.engine}`,
      requestSha256: record.requestSha256,
    });
  }

  const pending = [];
  for (const state of roleWorkers.values()) {
    if (state.deleted) continue;
    const entry = state.entry;
    const phase = record.trusted.receipt.resources.phaseProfiles[entry.phaseId];
    const body = workerCreateBody({
      action: record.action,
      artifactBinding: entry.artifactBinding,
      claimedBackupResources: entry.claimedBackupResources,
      claimedJobSnapshot: entry.snapshot,
      helperResultsSnapshot: entry.helperResultsSnapshot,
      parameters: record.request.parameters,
      phaseId: entry.phaseId,
      request: record.request,
      requestId: record.requestId,
      requestSha256: record.requestSha256,
      trusted: record.trusted,
      workerRole: entry.workerRole,
    });
    requireSemanticTransport(transport, "inspectContainerForRecovery");
    const inspect = await transport.inspectContainerForRecovery(entry.resourceName, signal);
    if (!inspect) {
      if (state.workerId) throw new Error("semantic role worker recovery inspect is missing");
      continue;
    }
    const id = String(inspect.Id ?? "");
    if (state.workerId && state.workerId !== id) throw new Error("semantic role worker recovery ID differs from journal");
    assertExactSemanticWorkerInspect(inspect, {
      body, id, name: entry.resourceName, phase, receipt: record.trusted.receipt, sealedSnapshot: entry.snapshot,
    });
    pending.push({
      deleteMethod: "deleteContainer",
      event: { event: "role-worker-deleted", phaseId: entry.phaseId, resourceName: entry.resourceName, workerId: id, workerRole: entry.workerRole },
      id,
    });
  }
  for (const state of scratchWorkers.values()) {
    if (state.deleted) continue;
    const entry = state.entry;
    const phase = record.trusted.receipt.resources.phaseProfiles[entry.phaseId];
    const body = workerCreateBody({
      action: record.action,
      claimedBackupResources: entry.claimedBackupResources,
      claimedJobSnapshot: entry.snapshot,
      parameters: record.request.parameters,
      phaseId: entry.phaseId,
      request: record.request,
      requestId: record.requestId,
      requestSha256: record.requestSha256,
      scratchEngine: entry.engine,
      trusted: record.trusted,
      workerRole: entry.workerRole,
    });
    requireSemanticTransport(transport, "inspectContainerForRecovery");
    const inspect = await transport.inspectContainerForRecovery(entry.resourceName, signal);
    if (!inspect) {
      if (state.workerId) throw new Error("scratch bootstrap recovery inspect is missing");
      continue;
    }
    const id = String(inspect.Id ?? "");
    if (state.workerId && state.workerId !== id) throw new Error("scratch bootstrap recovery ID differs from journal");
    assertExactSemanticWorkerInspect(inspect, {
      body, id, name: entry.resourceName, phase, receipt: record.trusted.receipt, sealedSnapshot: entry.snapshot,
    });
    pending.push({
      deleteMethod: "deleteContainer",
      event: { engine: entry.engine, event: "scratch-bootstrap-deleted", phaseId: entry.phaseId, resourceName: entry.resourceName, workerId: id, workerRole: entry.workerRole },
      id,
    });
  }
  for (const state of helpers.values()) {
    if (state.deleted) continue;
    const entry = state.entry;
    const plan = buildSemanticHelperPlan({
      claimedBackupResources: entry.claimedBackupResources ?? null,
      phaseId: entry.phaseId,
      priorBinding: entry.artifactBinding ?? null,
      receipt: record.trusted.receipt,
      requestSha256: record.requestSha256,
    });
    if (sha256(canonicalJson(plan)) !== entry.helperPlanSha256) throw new Error("semantic helper recovery plan digest differs from journal");
    const planned = plan.helpers.find((helper) => helper.helperProfileId === entry.helperProfileId && helper.ordinal === entry.ordinal);
    if (!planned || planned.name !== entry.resourceName) throw new Error("semantic helper recovery plan identity differs from journal");
    requireSemanticTransport(transport, "inspectHelperImage");
    const imageInspect = await transport.inspectHelperImage(planned.imageId, signal);
    const bound = bindSemanticHelperImageInspect(planned, imageInspect);
    if (bound.imageRuntimeConfigSha256 !== entry.imageRuntimeConfigSha256) {
      throw new Error("semantic helper recovery image runtime config differs from journal");
    }
    const helper = resolveDeferredSemanticHelper(bound, helperCreatedIds);
    if (helper.bodySha256 !== entry.bodySha256) throw new Error("semantic helper recovery body digest differs from journal");
    requireSemanticTransport(transport, "inspectHelperForRecovery");
    const inspect = await transport.inspectHelperForRecovery(entry.resourceName, signal);
    if (!inspect) {
      if (state.workerId) throw new Error("semantic helper recovery inspect is missing");
      continue;
    }
    const id = String(inspect.Id ?? "");
    if (state.workerId && state.workerId !== id) throw new Error("semantic helper recovery ID differs from journal");
    assertExactSemanticHelperInspect(inspect, { ...helper, body: helper.body });
    pending.push({
      deleteMethod: "deleteHelper",
      event: { event: "helper-deleted", helperProfileId: helper.helperProfileId, phaseId: entry.phaseId, resourceName: entry.resourceName, workerId: id },
      id,
    });
  }
  for (const item of pending.reverse()) {
    requireSemanticTransport(transport, item.deleteMethod);
    await transport[item.deleteMethod](item.id, signal);
    record.recordEvent(item.event);
  }

  for (const entry of [...scratchOutstanding.values()].reverse()) {
    const source = [...scratchWorkers.values()].find((state) => (
      state.entry.phaseId === entry.phaseId && state.entry.engine === entry.engine
    ))?.entry;
    await executeSemanticRoleWorker({
      admission,
      artifactBinding: null,
      claimedBackupResources: source?.claimedBackupResources ?? null,
      cleanupTimeoutMs,
      helperResultsSnapshot: null,
      phaseId: entry.phaseId,
      randomBytes,
      role: "scratch-cleaner",
      scratchEngine: entry.engine,
      sealedSnapshot: source?.snapshot ?? claimedSnapshots.get(entry.phaseId) ?? null,
      transport,
    });
    record.recordEvent({
      engine: entry.engine,
      event: "scratch-cleaned",
      phaseId: entry.phaseId,
      relativePath: entry.relativePath,
      requestSha256: record.requestSha256,
    });
  }
  for (const [phaseId, snapshot] of helperSnapshots) {
    await helperResultsFileStore.cleanup(snapshot);
    record.recordEvent({ event: "helper-results-cleaned", helperResultsSnapshot: snapshot, phaseId, requestSha256: record.requestSha256 });
    helperResultIntents.delete(phaseId);
  }
  for (const phaseId of helperResultIntents) {
    await helperResultsFileStore.cleanupPartial({
      action: record.action,
      phaseId,
      requestId: record.requestId,
      requestSha256: record.requestSha256,
    });
    record.recordEvent({
      event: "helper-results-intent-cleaned",
      phaseId,
      requestSha256: record.requestSha256,
    });
  }
  for (const [phaseId, snapshot] of claimedSnapshots) {
    await snapshotFileStore.cleanup(snapshot);
    record.recordEvent({ event: "snapshot-cleaned", phaseId, requestSha256: record.requestSha256, snapshot });
  }
  if (remoteAttempt) {
    record.recordEvent({ event: "remote-effect-unknown", ...remoteAttempt });
    throw new Error("remote effect is unknown and requires manual reconciliation");
  }
  if (localAttempt) {
    record.recordEvent({ event: "local-effect-unknown", ...localAttempt });
    throw new Error("local effect is unknown and requires manual reconciliation");
  }
  return Object.freeze({ status: "recovered" });
}

async function defaultClaimedJobSnapshotProvider({ parameters, source, sourceId }) {
  return readClaimedJobSnapshot({
    parameters,
    policy: {
      expectedGid: 0,
      expectedMode: 0o600,
      expectedUid: 0,
      maximumBytes: source.maximumBytes,
      parentRoot: source.brokerRoot,
    },
    source,
    sourceId,
  });
}

function normalizeSemanticExecution(action, context) {
  if (!isPlainRecord(context) || !isPlainRecord(context.request)
    || !isPlainRecord(context.parameters) || !isPlainRecord(context.trusted)
    || !isPlainRecord(context.trusted.intent) || !isPlainRecord(context.trusted.receipt)
    || !context.lease || typeof context.lease !== "object"
    || typeof context.lease.recordEvent !== "function"
    || typeof context.lease.recordWorker !== "function") {
    throw brokerError(403, "semantic request, trust or lease lineage is invalid");
  }
  if (canonicalJson(context.parameters) !== canonicalJson(context.request.parameters)) {
    throw brokerError(403, "semantic caller parameters do not match the signed request");
  }
  if (context.request.action !== action
    || context.requestId !== context.request.requestId
    || context.requestSha256 !== sha256(canonicalJson(context.request))
    || context.request.runtimeIntentId !== context.trusted.intent.intentId
    || context.request.activeReceiptSha256 !== context.trusted.receiptDigest
    || context.trusted.receiptDigest !== sha256(canonicalJson(context.trusted.receipt))) {
    throw brokerError(403, "semantic request, trust or lease lineage is invalid");
  }
  const contract = ACTIONS[action];
  const actionProfile = context.trusted.receipt.resources?.actionProfiles?.[action];
  const runtimeEvidence = contract?.engineAction === "runtimeSnapshot";
  if (!contract
    || (runtimeEvidence && actionProfile !== undefined)
    || (!runtimeEvidence && (!isPlainRecord(actionProfile)
      || actionProfile.profileId !== contract.profileId))) {
    throw brokerError(403, "semantic action profile identity is invalid");
  }
  if (context.lease.lineage !== undefined) {
    const expectedLineage = {
      action,
      intentId: context.trusted.intent.intentId,
      receiptDigest: context.trusted.receiptDigest,
      request: context.request,
      requestId: context.requestId,
      requestSha256: context.requestSha256,
    };
    if (canonicalJson(context.lease.lineage) !== canonicalJson(expectedLineage)) {
      throw brokerError(403, "semantic lease does not bind the full signed request");
    }
  }
  return Object.freeze({
    action,
    actionProfile: runtimeEvidence ? null : actionProfile,
    context,
    parameters: context.parameters,
    request: context.request,
    requestId: context.requestId,
    requestSha256: context.requestSha256,
    trusted: context.trusted,
  });
}

function semanticPhaseIds(admission) {
  const { action, actionProfile, parameters } = admission;
  const phaseIds = action === "backup.job.execute"
    ? actionProfile.operationPhaseIds?.[parameters.jobOperation]
    : actionProfile.phaseIds;
  if (!Array.isArray(phaseIds) || phaseIds.length < 1
    || phaseIds.some((phaseId) => typeof phaseId !== "string"
      || !admission.trusted.receipt.resources.phaseProfiles?.[phaseId])) {
    throw brokerError(403, "semantic action phase plan is invalid");
  }
  return [...phaseIds];
}

function semanticActionResult(admission, phases) {
  return {
    schema: "platform.docker-action.result/v2",
    action: admission.action,
    job: admission.action === "backup.job.execute"
      ? cloneCanonicalValue(admission.parameters)
      : null,
    phases: phases.map((phase) => cloneCanonicalValue(phase)),
    status: "completed",
  };
}

async function executeSemanticRuntimeSnapshot(admission, transport) {
  const output = await runtimeSnapshot(
    admission.trusted.receipt.resources.containers,
    transport,
    admission.context.signal,
  );
  const encodedOutput = canonicalJson(output);
  if (!isPlainRecord(output)
    || output.schema !== "platform.docker-runtime-snapshot/v2"
    || !isPlainRecord(output.resources)
    || Buffer.byteLength(encodedOutput) > MAX_PHASE_OUTPUT_BYTES) {
    throw brokerError(502, "runtime snapshot output schema or size is invalid");
  }
  const result = semanticActionResult(admission, [{
    output,
    outputSchema: "platform.docker-runtime-snapshot/v2",
    outputSha256: sha256(encodedOutput),
    phaseId: "evidence.runtime.snapshot",
    status: "completed",
  }]);
  recordSemanticCompletion(admission, result);
  return result;
}

function recordSemanticCompletion(admission, result) {
  try {
    admission.context.lease.recordEvent({
      event: "action-completed",
      requestSha256: admission.requestSha256,
      resultSha256: sha256(canonicalJson(result)),
    });
  } catch (error) {
    error.preserveLease = true;
    throw error;
  }
}

async function executeSemanticWorkerPhase({
  admission,
  claimedJobSnapshotProvider,
  cleanupTimeoutMs,
  phaseId,
  randomBytes,
  snapshotFileStore,
  transport,
}) {
  const { action, context, parameters, request, requestId, requestSha256, trusted } = admission;
  const receipt = trusted.receipt;
  const phase = receipt.resources.phaseProfiles[phaseId];
  const sourceId = admission.actionProfile.claimedJobSourceId;
  let capturedSnapshot = null;
  let claimedBackupResources = null;
  if (sourceId !== null) {
    const source = receipt.resources.claimedJobSources[sourceId];
    capturedSnapshot = await claimedJobSnapshotProvider({
      parameters: cloneCanonicalValue(parameters),
      source,
      sourceId,
    });
    claimedBackupResources = admitClaimedJobResources(
      capturedSnapshot,
      parameters,
      receipt,
    );
  }
  const effectiveAuthority = semanticPhaseAuthority(
    receipt,
    action,
    phaseId,
    claimedBackupResources ?? undefined,
  );
  const preflight = await preflightSemanticPhase({
    action,
    authority: effectiveAuthority,
    phase,
    receipt,
    signal: context.signal,
    transport,
  });
  let sealedSnapshot = null;
  let snapshotMayExist = false;
  let createAttempted = false;
  let workerId = "";
  let resourceName = "";
  let body;
  let phaseResult;
  let failure = null;
  let journalStarted = false;

  try {
    if (sourceId !== null) {
      const source = receipt.resources.claimedJobSources[sourceId];
      const predicted = semanticSnapshotRecord(capturedSnapshot, {
        requestSha256,
        source,
        volumeInspect: preflight.volumes[source.snapshotVolumeId],
      });
      if (typeof context.lease.recordRecoveryIntent === "function") {
        context.lease.recordRecoveryIntent({ phaseId, snapshot: predicted });
        journalStarted = true;
      }
      sealedSnapshot = predicted;
      snapshotMayExist = true;
      const observed = await snapshotFileStore.seal(capturedSnapshot, {
        request,
        requestId,
        requestSha256,
        source,
        volumeInspect: preflight.volumes[source.snapshotVolumeId],
      });
      if (canonicalJson(observed) !== canonicalJson(predicted)) {
        throw snapshotPreserveError("sealed snapshot identity differs from its admitted recovery intent");
      }
      context.lease.recordEvent({
        event: "snapshot-materialized",
        phaseId,
        requestSha256,
        snapshot: sealedSnapshot,
      });
      journalStarted = true;
    }

    body = workerCreateBody({
      action,
      claimedBackupResources: claimedBackupResources ?? undefined,
      claimedJobSnapshot: sealedSnapshot ?? undefined,
      parameters,
      phaseId,
      request,
      requestId,
      requestSha256,
      trusted,
    });
    const entropy = randomBytes(12);
    if (!Buffer.isBuffer(entropy) || entropy.length !== 12) {
      throw new TypeError("semantic worker name entropy is invalid");
    }
    resourceName = `platform-action-${phaseId.replaceAll(".", "-")}-${entropy.toString("hex")}`;
    context.lease.recordWorker({
      action,
      phaseId,
      phaseProfileSha256: phase.phaseSha256,
      receiptDigest: trusted.receiptDigest,
      requestSha256,
      resourceName,
      ...(claimedBackupResources ? { claimedBackupResources } : {}),
      ...(sealedSnapshot ? { snapshot: sealedSnapshot } : {}),
    });
    journalStarted = true;

    requireSemanticTransport(transport, "createWorker");
    createAttempted = true;
    const created = await transport.createWorker(resourceName, body, context.signal);
    workerId = String(created?.Id ?? "");
    assertSemanticWorkerId(workerId);
    context.lease.recordEvent({
      event: "worker-created",
      phaseId,
      resourceName,
      workerId,
    });

    requireSemanticTransport(transport, "inspectContainer");
    const inspect = await transport.inspectContainer(workerId, context.signal);
    assertExactSemanticWorkerInspect(inspect, {
      body,
      id: workerId,
      name: resourceName,
      phase,
      receipt,
      sealedSnapshot,
    });
    requireSemanticTransport(transport, "startContainer");
    await transport.startContainer(workerId, context.signal);
    requireSemanticTransport(transport, "waitContainer");
    const waited = await transport.waitContainer(workerId, context.signal);
    const statusCode = Number(waited?.StatusCode);
    if (!Number.isSafeInteger(statusCode) || statusCode !== 0) {
      throw brokerError(500, `${phaseId} worker failed with status ${Number.isSafeInteger(statusCode) ? statusCode : "invalid"}`);
    }
    requireSemanticTransport(transport, "logsContainer");
    const logs = await transport.logsContainer(workerId, context.signal);
    const workerResult = parseSemanticWorkerOutput(logs, {
      action,
      parameters,
      phase,
      phaseId,
      requestId,
    });
    context.lease.recordEvent({
      event: "worker-result-recorded",
      phaseId,
      resourceName,
      workerId,
      workerResultSha256: sha256(canonicalJson(workerResult)),
    });
    phaseResult = {
      output: workerResult.output,
      outputSchema: phase.outputSchema,
      outputSha256: sha256(canonicalJson(workerResult.output)),
      phaseId,
      status: "completed",
    };
  } catch (error) {
    failure = error;
  }

  let cleanupFailure = null;
  let deletedWorkerId = null;
  if (createAttempted) {
    try {
      deletedWorkerId = await withTimeout(async (cleanupSignal) => {
        requireSemanticTransport(transport, "deleteContainer");
        if (workerId) {
          await transport.deleteContainer(workerId, cleanupSignal);
          return workerId;
        }
        requireSemanticTransport(transport, "inspectContainerForRecovery");
        const inspect = await transport.inspectContainerForRecovery(resourceName, cleanupSignal);
        if (!inspect) return null;
        const recoveredId = String(inspect.Id ?? "");
        assertSemanticWorkerId(recoveredId);
        assertExactSemanticWorkerInspect(inspect, {
          body,
          id: recoveredId,
          name: resourceName,
          phase,
          receipt,
          sealedSnapshot,
        });
        await transport.deleteContainer(recoveredId, cleanupSignal);
        return recoveredId;
      }, cleanupTimeoutMs, "semantic worker cleanup timed out");
      if (deletedWorkerId) {
        context.lease.recordEvent({
          event: "worker-deleted",
          phaseId,
          resourceName,
          workerId: deletedWorkerId,
        });
      }
    } catch (error) {
      cleanupFailure = error;
    }
  }

  if (snapshotMayExist && !cleanupFailure) {
    try {
      if (typeof snapshotFileStore.cleanup !== "function") {
        throw new TypeError("semantic snapshot cleanup dependency is incomplete");
      }
      await withTimeout(
        () => snapshotFileStore.cleanup(sealedSnapshot),
        cleanupTimeoutMs,
        "semantic snapshot cleanup timed out",
      );
      context.lease.recordEvent({
        event: "snapshot-cleaned",
        phaseId,
        requestSha256,
        snapshot: sealedSnapshot,
      });
    } catch (error) {
      cleanupFailure = error;
    }
  }

  if (failure?.remoteEffectUnknown === true && !cleanupFailure && deletedWorkerId) {
    try {
      context.lease.recordEvent({
        event: "remote-effect-unknown",
        phaseId,
        resourceName,
        workerId: deletedWorkerId,
      });
    } catch (error) {
      cleanupFailure = error;
    }
  }
  if (cleanupFailure) {
    cleanupFailure.preserveLease = true;
    throw cleanupFailure;
  }
  if (failure) {
    if (journalStarted || createAttempted) failure.preserveLease = true;
    throw failure;
  }
  return phaseResult;
}

async function preflightSemanticPhase({ action, authority, phase, receipt, signal, transport }) {
  if (!isPlainRecord(phase) || phase.phaseId !== String(phase.phaseId ?? "")) {
    throw brokerError(403, "semantic phase profile is invalid");
  }
  const networks = {};
  for (const logicalId of authority.effectiveNetworkIds) {
    const authority = receipt.resources.networks[logicalId];
    requireSemanticTransport(transport, "inspectNetwork");
    networks[logicalId] = await transport.inspectNetwork(authority.engineId, signal);
  }
  const volumeIds = [
    ...Object.keys(authority.resources.volumes),
    ...phase.workerSecretSetIds.map(
      (secretSetId) => receipt.resources.workerSecretSets[secretSetId].volumeId,
    ),
    ...authority.effectiveHelperSecretSetIds.map(
      (secretSetId) => receipt.resources.workerSecretSets[secretSetId].volumeId,
    ),
    ...phase.scratchVolumeIds,
  ];
  const actionProfile = receipt.resources.actionProfiles[action];
  if (actionProfile.claimedJobSourceId !== null) {
    const source = receipt.resources.claimedJobSources[actionProfile.claimedJobSourceId];
    volumeIds.unshift(source.volumeId, source.snapshotVolumeId);
  }
  const volumes = {};
  for (const logicalId of [...new Set(volumeIds)]) {
    const authority = receipt.resources.volumes[logicalId];
    requireSemanticTransport(transport, "inspectVolume");
    volumes[logicalId] = await transport.inspectVolume(authority.engineName, signal);
  }
  for (const logicalId of authority.effectiveNetworkIds) {
    assertExactNetworkInspect(
      networks[logicalId],
      receipt.resources.networks[logicalId],
      logicalId,
    );
  }
  for (const logicalId of [...new Set(volumeIds)]) {
    assertExactVolumeInspect(
      volumes[logicalId],
      receipt.resources.volumes[logicalId],
      logicalId,
    );
  }
  return Object.freeze({ networks: Object.freeze(networks), volumes: Object.freeze(volumes) });
}

function requireSemanticTransport(transport, method) {
  if (typeof transport?.[method] !== "function") {
    throw new TypeError(`semantic Engine transport is missing ${method}`);
  }
}

async function recoverSemanticLease({ record, signal, snapshotFileStore, transport }) {
  if (!isPlainRecord(record) || !isPlainRecord(record.request)
    || !isPlainRecord(record.trusted) || !Array.isArray(record.journalEntries)
    || typeof record.recordEvent !== "function"
    || record.action !== record.request.action
    || record.requestSha256 !== sha256(canonicalJson(record.request))
    || record.receiptDigest !== record.trusted.receiptDigest
    || record.receiptDigest !== sha256(canonicalJson(record.trusted.receipt))) {
    throw new Error("semantic recovery lease lineage is invalid");
  }
  const admission = Object.freeze({
    action: record.action,
    actionProfile: record.trusted.receipt.resources.actionProfiles[record.action],
    parameters: record.request.parameters,
    request: record.request,
    requestId: record.requestId,
    requestSha256: record.requestSha256,
    trusted: record.trusted,
  });
  const allowedPhaseIds = new Set(semanticPhaseIds(admission));
  const workers = new Map();
  const snapshots = new Map();
  const cleanedSnapshots = new Set();
  const snapshotKey = (value) => canonicalJson(value);
  for (const entry of record.journalEntries) {
    if (!allowedPhaseIds.has(entry.phaseId) && entry.event !== "action-completed") {
      throw new Error("semantic recovery journal contains an unowned phase");
    }
    if (entry.event === "snapshot-materialized") snapshots.set(snapshotKey(entry.snapshot), entry.snapshot);
    if (entry.event === "snapshot-cleaned") cleanedSnapshots.add(snapshotKey(entry.snapshot));
    if (entry.event === "worker-recorded") {
      workers.set(entry.resourceName, {
        createdId: null,
        deleted: false,
        entry,
      });
    } else if (entry.event === "worker-created") {
      const worker = workers.get(entry.resourceName);
      if (!worker) throw new Error("semantic recovery worker journal is incomplete");
      worker.createdId = entry.workerId;
    } else if (entry.event === "worker-deleted") {
      const worker = workers.get(entry.resourceName);
      if (!worker) throw new Error("semantic recovery worker deletion is orphaned");
      worker.deleted = true;
    }
  }
  if (record.recoveryIntent) {
    if (!allowedPhaseIds.has(record.recoveryIntent.phaseId)) {
      throw new Error("semantic recovery snapshot phase is not owned by the action");
    }
    validateSemanticSnapshotForRequest(
      record.recoveryIntent.snapshot,
      admission,
      record.recoveryIntent.phaseId,
    );
    snapshots.set(snapshotKey(record.recoveryIntent.snapshot), record.recoveryIntent.snapshot);
  }

  const pendingWorkers = [...workers.values()].filter(({ deleted }) => !deleted).reverse();
  const inspected = [];
  for (const worker of pendingWorkers) {
    const { entry } = worker;
    const phase = record.trusted.receipt.resources.phaseProfiles[entry.phaseId];
    if (!phase || phase.phaseSha256 !== entry.phaseProfileSha256
      || entry.receiptDigest !== record.receiptDigest
      || entry.requestSha256 !== record.requestSha256) {
      throw new Error("semantic recovery worker lineage is invalid");
    }
    const sealedSnapshot = entry.snapshot ?? null;
    if (sealedSnapshot) validateSemanticSnapshotForRequest(sealedSnapshot, admission, entry.phaseId);
    const body = workerCreateBody({
      action: record.action,
      claimedBackupResources: entry.claimedBackupResources,
      claimedJobSnapshot: sealedSnapshot ?? undefined,
      parameters: record.request.parameters,
      phaseId: entry.phaseId,
      request: record.request,
      requestId: record.requestId,
      requestSha256: record.requestSha256,
      trusted: record.trusted,
    });
    requireSemanticTransport(transport, "inspectContainerForRecovery");
    const inspect = await transport.inspectContainerForRecovery(entry.resourceName, signal);
    if (!inspect) throw new Error("semantic recovery worker inspect is missing");
    const observedId = String(inspect.Id ?? "");
    assertSemanticWorkerId(observedId);
    if (worker.createdId && worker.createdId !== observedId) {
      throw new Error("semantic recovery worker identity does not match its journal");
    }
    assertExactSemanticWorkerInspect(inspect, {
      body,
      id: observedId,
      name: entry.resourceName,
      phase,
      receipt: record.trusted.receipt,
      sealedSnapshot,
    });
    inspected.push({ entry, id: observedId });
  }

  for (const worker of inspected) {
    requireSemanticTransport(transport, "deleteContainer");
    await transport.deleteContainer(worker.id, signal);
    record.recordEvent({
      event: "worker-deleted",
      phaseId: worker.entry.phaseId,
      resourceName: worker.entry.resourceName,
      workerId: worker.id,
    });
  }
  for (const [key, snapshot] of snapshots) {
    if (cleanedSnapshots.has(key)) continue;
    if (typeof snapshotFileStore.cleanup !== "function") {
      throw new TypeError("semantic snapshot cleanup dependency is incomplete");
    }
    await snapshotFileStore.cleanup(snapshot);
    const phaseId = record.recoveryIntent?.snapshot
      && snapshotKey(record.recoveryIntent.snapshot) === key
      ? record.recoveryIntent.phaseId
      : record.journalEntries.find(
          (entry) => entry.event === "snapshot-materialized"
            && snapshotKey(entry.snapshot) === key,
        )?.phaseId;
    if (!phaseId) throw new Error("semantic recovery snapshot phase is missing");
    record.recordEvent({
      event: "snapshot-cleaned",
      phaseId,
      requestSha256: record.requestSha256,
      snapshot,
    });
  }
  return Object.freeze({ status: "recovered" });
}

export function workerCreateBody(input) {
  if (isPlainRecord(input) && Object.hasOwn(input, "phaseId")) {
    return semanticWorkerCreateBody(input);
  }
  return legacyWorkerCreateBody(input ?? {});
}

function semanticWorkerCreateBody({
  action,
  artifactBinding,
  claimedBackupResources,
  claimedJobSnapshot,
  helperResultsSnapshot,
  parameters,
  phaseId,
  request,
  requestId,
  requestSha256,
  scratchEngine,
  trusted,
  workerRole,
}) {
  if (!isPlainRecord(request) || !isPlainRecord(parameters) || !isPlainRecord(trusted)
    || !isPlainRecord(trusted.intent) || !isPlainRecord(trusted.receipt)
    || request.action !== action || request.requestId !== requestId
    || requestSha256 !== sha256(canonicalJson(request))
    || canonicalJson(parameters) !== canonicalJson(request.parameters)
    || request.runtimeIntentId !== trusted.intent.intentId
    || request.activeReceiptSha256 !== trusted.receiptDigest
    || trusted.receiptDigest !== sha256(canonicalJson(trusted.receipt))) {
    throw brokerError(403, "semantic worker request authority is invalid");
  }
  const receipt = trusted.receipt;
  const actionProfile = receipt.resources?.actionProfiles?.[action];
  const phase = receipt.resources?.phaseProfiles?.[phaseId];
  if (!isPlainRecord(actionProfile) || !isPlainRecord(phase)
    || phase.phaseId !== phaseId || !semanticProfileOwnsPhase(actionProfile, phaseId, parameters)) {
    throw brokerError(403, "semantic worker phase authority is invalid");
  }
  const roleAware = workerRole !== undefined;
  if (roleAware && !SEMANTIC_WORKER_ROLES_BY_PHASE[phaseId]?.includes(workerRole)) {
    throw brokerError(403, "semantic worker role is outside phase authority");
  }
  const requiresSnapshot = actionProfile.claimedJobSourceId !== null;
  if (requiresSnapshot !== Boolean(claimedJobSnapshot)) {
    throw brokerError(403, "semantic worker claimed-job snapshot ownership is invalid");
  }
  if (claimedJobSnapshot) {
    validateSemanticSnapshotForRequest(claimedJobSnapshot, {
      action,
      actionProfile,
      parameters,
      request,
      requestId,
      requestSha256,
      trusted,
    }, phaseId);
  }

  const authority = semanticPhaseAuthority(
    receipt,
    action,
    phaseId,
    claimedBackupResources,
    { includeHelperResultsStorage: roleAware },
  );
  const authorityJson = canonicalJson(authority);
  const env = [
    "HOME=/tmp",
    "LANG=C.UTF-8",
    "NODE_ENV=production",
    `PLATFORM_DOCKER_ACTION=${action}`,
    `PLATFORM_DOCKER_PHASE_AUTHORITY_BASE64=${Buffer.from(authorityJson).toString("base64url")}`,
    `PLATFORM_DOCKER_PHASE_AUTHORITY_SHA256=${sha256(authorityJson)}`,
    `PLATFORM_DOCKER_PHASE_ID=${phaseId}`,
    `PLATFORM_DOCKER_REQUEST_ID=${requestId}`,
  ];
  if (roleAware) {
    env.push(
      `PLATFORM_DOCKER_REQUEST_SHA256=${requestSha256}`,
      `PLATFORM_DOCKER_WORKER_ROLE=${workerRole}`,
    );
    const requiresHelperResults = workerRole === "evidence-finalizer";
    if (requiresHelperResults !== Boolean(helperResultsSnapshot)
      || (helperResultsSnapshot && (
        helperResultsSnapshot.schema !== "platform.docker-helper-results.snapshot/v1"
        || helperResultsSnapshot.action !== action
        || helperResultsSnapshot.phaseId !== phaseId
        || helperResultsSnapshot.requestId !== requestId
        || helperResultsSnapshot.requestSha256 !== requestSha256
        || helperResultsSnapshot.containerPath !== "/run/platform/helper-results/results.json"
        || !/^[a-f0-9]{64}$/.test(String(helperResultsSnapshot.sha256 ?? ""))
      ))) {
      throw brokerError(403, "semantic worker helper-results snapshot authority is invalid");
    }
    if (helperResultsSnapshot) {
      env.push(
        `PLATFORM_DOCKER_HELPER_RESULTS_PATH=${helperResultsSnapshot.containerPath}`,
        `PLATFORM_DOCKER_HELPER_RESULTS_SHA256=${helperResultsSnapshot.sha256}`,
      );
    }
    const requiresBinding = workerRole === "evidence-finalizer"
      && ["job.restore.verify", "restore.verify", "offsite.sync"].includes(phaseId);
    if (requiresBinding !== Boolean(artifactBinding) || (artifactBinding && !isPlainRecord(artifactBinding))) {
      throw brokerError(403, "semantic worker artifact binding authority is invalid");
    }
    if (artifactBinding) {
      const bindingJson = canonicalJson(artifactBinding);
      env.push(
        `PLATFORM_DOCKER_ARTIFACT_BINDING_BASE64=${Buffer.from(bindingJson).toString("base64url")}`,
        `PLATFORM_DOCKER_ARTIFACT_BINDING_SHA256=${sha256(bindingJson)}`,
      );
    }
    const requiresScratchEngine = workerRole === "scratch-preparer" || workerRole === "scratch-cleaner";
    if (requiresScratchEngine !== Boolean(scratchEngine)
      || (scratchEngine && !["mariadb", "minio", "postgres"].includes(scratchEngine))) {
      throw brokerError(403, "semantic worker scratch engine authority is invalid");
    }
    if (scratchEngine) env.push(`PLATFORM_DOCKER_SCRATCH_ENGINE=${scratchEngine}`);
    if (workerRole === "evidence-finalizer"
      && ["catalog.capture", "job.backup.capture", "restore.capture"].includes(phaseId)) {
      env.push(`PLATFORM_DOCKER_REQUEST_ISSUED_AT=${request.issuedAt}`);
    }
  }
  if (claimedJobSnapshot) {
    env.push(
      `PLATFORM_CLAIMED_JOB_FILE_NAME=${claimedJobSnapshot.jobFileName}`,
      `PLATFORM_CLAIMED_JOB_ID=${claimedJobSnapshot.jobId}`,
      `PLATFORM_CLAIMED_JOB_OPERATION=${claimedJobSnapshot.jobOperation}`,
      `PLATFORM_CLAIMED_JOB_PATH=${claimedJobSnapshot.containerPath}`,
      `PLATFORM_CLAIMED_JOB_SHA256=${claimedJobSnapshot.jobSha256}`,
      `PLATFORM_CLAIMED_JOB_SOURCE_ID=${claimedJobSnapshot.sourceId}`,
    );
  }
  if (phase.writableSubpathIds.includes("backup.quarantine")) {
    env.push("PLATFORM_BACKUP_QUARANTINE_RELATIVE_PATH=.quarantine");
  }
  assertSemanticEnvironmentBounds(env);

  const roleMountIds = !roleAware || ["evidence-finalizer", "standalone"].includes(workerRole)
    ? phase.mountIds
    : workerRole === "artifact-resolver"
      ? phase.mountIds.filter((mountId) => ["backup.root.ro", "report.root.rw"].includes(mountId))
      : workerRole === "helper-preparer"
        ? phase.mountIds.filter((mountId) => ["backup.root.rw", "report.root.rw"].includes(mountId))
        : [];
  const binds = roleMountIds.map((mountId) => {
    const mount = receipt.resources.mounts[mountId];
    return `${mount.canonicalPath}:${mount.containerPath}:${mount.access}`;
  });
  if (claimedJobSnapshot) {
    binds.push(`${claimedJobSnapshot.hostPath}:${claimedJobSnapshot.containerPath}:ro`);
  }
  if (helperResultsSnapshot) {
    binds.push(`${helperResultsSnapshot.hostPath}:${helperResultsSnapshot.containerPath}:ro`);
  }
  const baseHostConfig = legacyWorkerCreateBody({
    action: "backup.prune.plan",
    command: "backup-prune-plan",
    hostPath: "/srv/platform/backups",
    imageRef: `worker@sha256:${"0".repeat(64)}`,
    intentId: "semantic-base",
    mountAttestation: {
      access: "ro",
      containerPath: "/data/backups",
      device: 1,
      hostPath: "/srv/platform/backups",
      inode: 1,
      kind: "directory",
      mode: 0o700,
      ownerGid: 0,
      ownerUid: 0,
      symlinkFree: true,
    },
    receiptDigest: "0".repeat(64),
  }).HostConfig;
  const namedMounts = [
    ...(["artifact-resolver", "evidence-finalizer", "standalone"].includes(workerRole)
      || !roleAware ? phase.workerSecretSetIds : []).map((secretSetId) => {
      const secretSet = receipt.resources.workerSecretSets[secretSetId];
      return {
        Type: "volume",
        Source: receipt.resources.volumes[secretSet.volumeId].engineName,
        Target: secretSet.containerRoot,
        ReadOnly: true,
        VolumeOptions: { NoCopy: true },
      };
    }),
    ...(["scratch-preparer", "scratch-cleaner"].includes(workerRole)
      ? phase.scratchVolumeIds : !roleAware ? phase.scratchVolumeIds : []).map((volumeId) => ({
      Type: "volume",
      Source: receipt.resources.volumes[volumeId].engineName,
      Target: receipt.resources.volumes[volumeId].containerPath,
      ReadOnly: false,
      VolumeOptions: { NoCopy: true },
    })),
  ];
  return {
    Image: phase.workerImageRef,
    Entrypoint: roleAware
      ? ["node", "/opt/platform-docker-worker/docker-action-worker.mjs"]
      : [
          "node",
          "--import",
          "/opt/platform-docker-worker/docker-action-worker-runtime-guard.mjs",
          "/opt/platform-docker-worker/docker-action-worker.mjs",
        ],
    Cmd: [phase.command],
    Env: env,
    User: "0:0",
    WorkingDir: "/opt/platform-docker-worker",
    NetworkDisabled: true,
    AttachStdin: false,
    AttachStdout: false,
    AttachStderr: false,
    OpenStdin: false,
    StdinOnce: false,
    Tty: false,
    Labels: {
      "com.platform.active-receipt-sha256": trusted.receiptDigest,
      "com.platform.docker-action": action,
      "com.platform.docker-action-profile": actionProfile.profileId,
      "com.platform.docker-action-profile-sha256": actionProfile.profileSha256,
      "com.platform.docker-phase": phaseId,
      "com.platform.docker-phase-sha256": phase.phaseSha256,
      "com.platform.runtime-intent": trusted.intent.intentId,
      ...(roleAware ? { "com.platform.docker-worker-role": workerRole } : {}),
    },
    HostConfig: {
      ...baseHostConfig,
      Binds: binds,
      CapAdd: workerRole === "scratch-preparer"
        ? ["CHOWN"]
        : workerRole === "scratch-cleaner"
          ? ["DAC_OVERRIDE"]
          : [],
      Mounts: namedMounts,
      NetworkMode: "none",
    },
    NetworkingConfig: {
      EndpointsConfig: {},
    },
  };
}

function legacyWorkerCreateBody({ action, command, imageRef, hostPath, intentId, receiptDigest, mountAttestation }) {
  if (action !== "backup.prune.plan" || command !== "backup-prune-plan") throw brokerError(500, "worker policy mismatch");
  if (!mountAttestation || mountAttestation.hostPath !== hostPath || mountAttestation.access !== "ro"
    || mountAttestation.containerPath !== "/data/backups" || mountAttestation.ownerUid !== 0
    || mountAttestation.ownerGid !== 0 || mountAttestation.kind !== "directory" || mountAttestation.symlinkFree !== true) {
    throw brokerError(500, "worker mount attestation mismatch");
  }
  return {
    Image: imageRef,
    Entrypoint: ["node", "/opt/platform-docker-worker/docker-action-worker.mjs"],
    Cmd: [command],
    Env: [
      "HOME=/tmp",
      "LANG=C.UTF-8",
      "NODE_ENV=production",
      `PLATFORM_BACKUP_ROOT_DEVICE=${mountAttestation.device}`,
      `PLATFORM_BACKUP_ROOT_INODE=${mountAttestation.inode}`,
      `PLATFORM_BACKUP_ROOT_MODE=${mountAttestation.mode}`,
    ],
    User: "65532:65532",
    WorkingDir: "/opt/platform-docker-worker",
    NetworkDisabled: true,
    AttachStdin: false,
    AttachStdout: false,
    AttachStderr: false,
    OpenStdin: false,
    StdinOnce: false,
    Tty: false,
    Labels: {
      "com.platform.docker-action": action,
      "com.platform.runtime-intent": intentId,
      "com.platform.active-receipt-sha256": receiptDigest,
    },
    HostConfig: {
      Annotations: null,
      AutoRemove: false,
      Binds: [`${hostPath}:/data/backups:ro`],
      BlkioDeviceReadBps: null,
      BlkioDeviceReadIOps: null,
      BlkioDeviceWriteBps: null,
      BlkioDeviceWriteIOps: null,
      BlkioWeight: 0,
      BlkioWeightDevice: null,
      CapAdd: [],
      CapDrop: ["ALL"],
      Cgroup: "",
      CgroupnsMode: "private",
      CgroupParent: "",
      ConsoleSize: [0, 0],
      CpuCount: 0,
      CpuPercent: 0,
      CpuPeriod: 0,
      CpuQuota: 0,
      CpuRealtimePeriod: 0,
      CpuRealtimeRuntime: 0,
      CpuShares: 0,
      CpusetCpus: "",
      CpusetMems: "",
      DeviceCgroupRules: [],
      Devices: [],
      DeviceRequests: [],
      DiskQuota: 0,
      Dns: [],
      DnsOptions: [],
      DnsSearch: [],
      ExtraHosts: [],
      GroupAdd: [],
      IOMaximumBandwidth: 0,
      IOMaximumIOps: 0,
      Init: false,
      IpcMode: "private",
      Isolation: "",
      KernelMemory: 0,
      KernelMemoryTCP: 0,
      Links: [],
      LogConfig: { Type: "json-file", Config: { "max-file": "1", "max-size": "1m" } },
      Memory: 134217728,
      MemoryReservation: 0,
      MemorySwap: 134217728,
      MemorySwappiness: null,
      Mounts: [],
      NanoCpus: 250000000,
      NetworkMode: "none",
      OomKillDisable: false,
      OomScoreAdj: 0,
      PidMode: "",
      PidsLimit: 96,
      PortBindings: {},
      Privileged: false,
      PublishAllPorts: false,
      ReadonlyRootfs: true,
      ReadonlyPaths: ["/proc/asound", "/proc/acpi", "/proc/interrupts", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi", "/sys/firmware"],
      RestartPolicy: { Name: "no", MaximumRetryCount: 0 },
      Runtime: "runc",
      SecurityOpt: ["no-new-privileges:true"],
      ShmSize: 67108864,
      StorageOpt: {},
      Sysctls: {},
      Tmpfs: { "/tmp": "rw,noexec,nosuid,nodev,size=32m,mode=700" },
      Ulimits: [{ Name: "nofile", Soft: 1024, Hard: 1024 }],
      UsernsMode: "",
      UTSMode: "",
      VolumeDriver: "",
      VolumesFrom: [],
      MaskedPaths: ["/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi", "/sys/devices/virtual/powercap", "/sys/firmware"],
    },
    NetworkingConfig: { EndpointsConfig: {} },
  };
}

function semanticProfileOwnsPhase(actionProfile, phaseId, parameters) {
  if (actionProfile.phaseIds?.includes(phaseId)) return true;
  return Array.isArray(actionProfile.operationPhaseIds?.[parameters?.jobOperation])
    && actionProfile.operationPhaseIds[parameters.jobOperation].includes(phaseId);
}

function semanticPhaseAuthority(
  receipt,
  action,
  phaseId,
  claimedBackupResources,
  { includeHelperResultsStorage = false } = {},
) {
  const resources = receipt?.resources;
  const actionProfile = resources?.actionProfiles?.[action];
  const phase = resources?.phaseProfiles?.[phaseId];
  if (!isPlainRecord(resources) || !isPlainRecord(actionProfile) || !isPlainRecord(phase)
    || !semanticProfileOwnsPhase(actionProfile, phaseId, {
      jobOperation: action === "backup.job.execute"
        ? Object.entries(actionProfile.operationPhaseIds ?? {})
          .find(([, ids]) => Array.isArray(ids) && ids.includes(phaseId))?.[0]
        : undefined,
    })) {
    throw brokerError(403, "semantic effective phase authority is not owned by the receipt");
  }

  let backupResourceIds;
  if (action === "backup.job.execute") {
    if (!isPlainRecord(claimedBackupResources)
      || Object.keys(claimedBackupResources).length < 1) {
      throw brokerError(403, "claimed-job effective resource authority is missing");
    }
    backupResourceIds = Object.keys(claimedBackupResources);
    for (const id of backupResourceIds) {
      if (!isPlainRecord(resources.backupResources?.[id])
        || canonicalJson(claimedBackupResources[id])
          !== canonicalJson(resources.backupResources[id])) {
        throw brokerError(403, `claimed-job effective resource ${id} is not receipt-bound`);
      }
    }
  } else if (action === "backup.catalog" || action === "restore.drill.full") {
    backupResourceIds = Object.keys(resources.backupResources ?? {});
  } else if (action === "backup.prune.plan" || action === "backup.prune.apply"
    || action === "backup.offsite.sync") {
    backupResourceIds = [];
  } else {
    throw brokerError(403, "semantic effective resource policy is not modeled");
  }
  const backupResourceIdSet = new Set(backupResourceIds);
  const backupResources = Object.fromEntries(backupResourceIds.map(
    (id) => [id, cloneCanonicalValue(resources.backupResources[id])],
  ));

  const effectiveEndpointIds = [];
  for (const id of phase.endpointIds) {
    const endpoint = resources.serviceEndpoints?.[id];
    if (!isPlainRecord(endpoint) || endpoint.endpointId !== id) {
      throw brokerError(403, `semantic service endpoint ${id} is dangling`);
    }
    if (endpoint.backupResourceId === null) {
      if (action === "backup.offsite.sync") effectiveEndpointIds.push(id);
    } else if (backupResourceIdSet.has(endpoint.backupResourceId)) {
      effectiveEndpointIds.push(id);
    }
  }
  const serviceEndpoints = Object.fromEntries(effectiveEndpointIds.map(
    (id) => [id, cloneCanonicalValue(resources.serviceEndpoints[id])],
  ));

  const selectedBackupResources = Object.values(backupResources);
  const effectiveHelperProfileIds = [];
  for (const id of phase.helperProfileIds) {
    const helper = resources.helperProfiles?.[id];
    if (!isPlainRecord(helper) || helper.helperProfileId !== id) {
      throw brokerError(403, `semantic helper profile ${id} is dangling`);
    }
    const selected = helper.resourceKind === null
      ? action === "backup.offsite.sync"
      : selectedBackupResources.some((resource) => (
        resource.kind === helper.resourceKind
          && (resource.engine ?? resource.externalId) === helper.engine
      ));
    if (selected) effectiveHelperProfileIds.push(id);
  }
  const helperProfiles = Object.fromEntries(effectiveHelperProfileIds.map(
    (id) => [id, cloneCanonicalValue(resources.helperProfiles[id])],
  ));

  const referencedNetworkIds = new Set();
  for (const endpoint of Object.values(serviceEndpoints)) {
    if (endpoint.networkId !== null) referencedNetworkIds.add(endpoint.networkId);
  }
  for (const helper of Object.values(helperProfiles)) {
    if (helper.networkId !== null) referencedNetworkIds.add(helper.networkId);
  }
  for (const id of referencedNetworkIds) {
    if (!phase.networkIds.includes(id) || !isPlainRecord(resources.networks?.[id])) {
      throw brokerError(403, `semantic effective network ${id} is not phase-bound`);
    }
  }
  const effectiveNetworkIds = phase.networkIds.filter((id) => referencedNetworkIds.has(id));

  const effectiveHelperSecretSetIds = [];
  for (const value of [
    ...effectiveHelperProfileIds.map((id) => resources.helperProfiles[id].secretSetId),
    ...effectiveEndpointIds.map((id) => resources.serviceEndpoints[id].secretSetId),
  ]) {
    if (value !== null && !effectiveHelperSecretSetIds.includes(value)) {
      effectiveHelperSecretSetIds.push(value);
    }
  }
  const workerSecretSetIdSet = new Set(phase.workerSecretSetIds);
  for (const id of effectiveHelperSecretSetIds) {
    if (workerSecretSetIdSet.has(id) || !isPlainRecord(resources.workerSecretSets?.[id])) {
      throw brokerError(403, `semantic helper secret set ${id} overlaps or is dangling`);
    }
  }
  for (const id of phase.workerSecretSetIds) {
    if (!isPlainRecord(resources.workerSecretSets?.[id])) {
      throw brokerError(403, `semantic worker secret set ${id} is dangling`);
    }
  }

  const workerSecretSets = Object.fromEntries(phase.workerSecretSetIds.map(
    (id) => [id, cloneCanonicalValue(resources.workerSecretSets[id])],
  ));
  const helperSecretSets = Object.fromEntries(effectiveHelperSecretSetIds.map(
    (id) => [id, cloneCanonicalValue(resources.workerSecretSets[id])],
  ));
  const volumeIds = [
    ...phase.workerSecretSetIds.map((id) => resources.workerSecretSets[id].volumeId),
    ...effectiveHelperSecretSetIds.map((id) => resources.workerSecretSets[id].volumeId),
    ...phase.scratchVolumeIds,
    ...(includeHelperResultsStorage && effectiveHelperProfileIds.length > 0
      ? ["broker.state"]
      : []),
  ];
  if (includeHelperResultsStorage && effectiveHelperProfileIds.length > 0
    && !isPlainRecord(resources.volumes?.["broker.state"])) {
    throw brokerError(403, "semantic helper-results storage volume is missing");
  }
  return {
    schema: "platform.docker-worker.phase-authority/v2",
    action,
    actionProfile: cloneCanonicalValue(actionProfile),
    effectiveEndpointIds,
    effectiveHelperProfileIds,
    effectiveHelperSecretSetIds,
    effectiveNetworkIds,
    phaseProfile: cloneCanonicalValue(phase),
    resources: {
      backupResources,
      helperProfiles,
      helperSecretSets,
      mounts: Object.fromEntries(
        phase.mountIds.map((id) => [id, cloneCanonicalValue(resources.mounts[id])]),
      ),
      networks: Object.fromEntries(
        effectiveNetworkIds.map((id) => [id, cloneCanonicalValue(resources.networks[id])]),
      ),
      serviceEndpoints,
      volumes: Object.fromEntries(
        [...new Set(volumeIds)].map(
          (id) => [id, cloneCanonicalValue(resources.volumes[id])],
        ),
      ),
      workerSecretSets,
      writableSubpaths: Object.fromEntries(
        phase.writableSubpathIds.map(
          (id) => [id, cloneCanonicalValue(resources.writableSubpaths[id])],
        ),
      ),
    },
  };
}

function assertSemanticEnvironmentBounds(entries) {
  const sizes = entries.map((entry) => Buffer.byteLength(String(entry)) + 1);
  if (sizes.some((size) => size > MAX_WORKER_ENV_ENTRY_BYTES)
    || sizes.reduce((sum, size) => sum + size, 0) > MAX_WORKER_ENV_TOTAL_BYTES) {
    throw brokerError(413, "semantic worker environment entry is oversized");
  }
}

function semanticSnapshotRecord(value, { requestSha256, source, volumeInspect }) {
  const snapshot = normalizeSnapshotInput(value);
  if (!isPlainRecord(source) || !isPlainRecord(volumeInspect)
    || snapshot.sourceId !== "jobs.running"
    || source.snapshotVolumeId !== "broker.state"
    || source.snapshotVolumeSubpath !== "claimed-jobs"
    || source.snapshotContainerPath !== "/run/platform/claimed-job/job.json") {
    throw new TypeError("semantic claimed-job snapshot authority is invalid");
  }
  const record = {
    containerPath: source.snapshotContainerPath,
    hostPath: path.join(
      volumeInspect.Mountpoint,
      source.snapshotVolumeSubpath,
      requestSha256,
      "job.json",
    ),
    jobFileName: snapshot.jobFileName,
    jobId: snapshot.jobId,
    jobOperation: snapshot.jobOperation,
    jobSha256: snapshot.jobSha256,
    requestSha256,
    snapshotVolumeId: source.snapshotVolumeId,
    snapshotVolumeMountpoint: volumeInspect.Mountpoint,
    snapshotVolumeName: volumeInspect.Name,
    snapshotVolumeSubpath: source.snapshotVolumeSubpath,
    sourceId: snapshot.sourceId,
  };
  return freezeCanonicalValue(normalizeSealedSnapshot(record));
}

function admitClaimedJobResources(value, parameters, receipt) {
  const snapshot = normalizeSnapshotInput(value);
  if (!isPlainRecord(parameters)
    || canonicalJson(parameters) !== canonicalJson({
      jobFileName: snapshot.jobFileName,
      jobId: snapshot.jobId,
      jobOperation: snapshot.jobOperation,
      jobSha256: snapshot.jobSha256,
    })) {
    throw brokerError(403, "claimed-job resource authority does not match the exact request");
  }
  let document;
  try {
    document = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(snapshot.bytes),
    );
    assertClaimedJobDocument(document, parameters);
  } catch {
    throw brokerError(403, "claimed-job resource document is not canonical typed authority");
  }
  if (document.status !== "running") {
    throw brokerError(403, "claimed-job resource document is not in the running state");
  }
  const admitted = receipt?.resources?.backupResources;
  if (!isPlainRecord(admitted)) {
    throw brokerError(403, "active receipt has no claimed-job resource authority");
  }
  const projected = {};
  for (const resource of document.resources) {
    const receiptResource = admitted[resource.id];
    if (!isPlainRecord(receiptResource)
      || canonicalJson(resource) !== canonicalJson({
        id: resource.id,
        ...receiptResource,
      })) {
      throw brokerError(403, `claimed-job resource ${resource.id} does not exactly match the active receipt`);
    }
    projected[resource.id] = cloneCanonicalValue(receiptResource);
  }
  return freezeCanonicalValue(projected);
}

function validateSemanticSnapshotForRequest(value, admission, phaseId) {
  const snapshot = normalizeSealedSnapshot(value);
  const sourceId = admission.actionProfile?.claimedJobSourceId;
  const source = admission.trusted.receipt.resources.claimedJobSources?.[sourceId];
  const volume = admission.trusted.receipt.resources.volumes?.[source?.snapshotVolumeId];
  const expectedParameters = {
    jobFileName: snapshot.jobFileName,
    jobId: snapshot.jobId,
    jobOperation: snapshot.jobOperation,
    jobSha256: snapshot.jobSha256,
  };
  const expectedHostPath = path.join(
    snapshot.snapshotVolumeMountpoint,
    snapshot.snapshotVolumeSubpath,
    snapshot.requestSha256,
    "job.json",
  );
  if (admission.action !== "backup.job.execute"
    || !semanticProfileOwnsPhase(admission.actionProfile, phaseId, admission.parameters)
    || !source || !volume || sourceId !== "jobs.running"
    || snapshot.sourceId !== sourceId
    || snapshot.snapshotVolumeId !== source.snapshotVolumeId
    || snapshot.snapshotVolumeSubpath !== source.snapshotVolumeSubpath
    || snapshot.snapshotVolumeName !== volume.engineName
    || snapshot.containerPath !== source.snapshotContainerPath
    || snapshot.requestSha256 !== admission.requestSha256
    || snapshot.hostPath !== expectedHostPath
    || path.dirname(path.dirname(snapshot.hostPath))
      !== path.join(snapshot.snapshotVolumeMountpoint, snapshot.snapshotVolumeSubpath)
    || canonicalJson(expectedParameters) !== canonicalJson(admission.parameters)) {
    throw snapshotPreserveError("semantic claimed-job snapshot does not match its exact request authority");
  }
  return snapshot;
}

function assertExactNetworkInspect(inspect, authority, logicalId) {
  if (!isPlainRecord(inspect)
    || !hasExactKeys(inspect, [
      "Containers",
      "Driver",
      "IPAM",
      "Id",
      "Internal",
      "Labels",
      "Name",
      "Options",
      "Scope",
    ])
    || inspect.Id !== authority.engineId
    || inspect.Name !== authority.engineName
    || inspect.Driver !== authority.driver
    || inspect.Scope !== authority.scope
    || inspect.Internal !== authority.internal
    || sha256(canonicalJson(inspect.Labels)) !== authority.labelsSha256
    || sha256(canonicalJson(inspect.Options)) !== authority.optionsSha256
    || sha256(canonicalJson(inspect.IPAM)) !== authority.subnetSha256
    || sha256(canonicalJson(inspect.Containers)) !== authority.membershipSha256) {
    throw brokerError(409, `network inspect identity is not exact for ${logicalId}`);
  }
}

function assertExactVolumeInspect(inspect, authority, logicalId) {
  if (!isPlainRecord(inspect)
    || !hasExactKeys(inspect, ["Driver", "Labels", "Mountpoint", "Name", "Options", "Scope"])
    || inspect.Name !== authority.engineName
    || inspect.Driver !== authority.driver
    || inspect.Scope !== authority.scope
    || sha256(canonicalJson(inspect.Labels)) !== authority.labelsSha256
    || sha256(canonicalJson(inspect.Options)) !== authority.optionsSha256
    || typeof inspect.Mountpoint !== "string" || inspect.Mountpoint.includes("\0")
    || !path.isAbsolute(inspect.Mountpoint)
    || path.normalize(inspect.Mountpoint) !== inspect.Mountpoint) {
    throw brokerError(409, `volume inspect identity is not exact for ${logicalId}`);
  }
}

function expectedSemanticInspectMounts(receipt, phase, sealedSnapshot) {
  const binds = phase.mountIds.map((mountId) => {
    const mount = receipt.resources.mounts[mountId];
    return {
      Type: "bind",
      Source: mount.canonicalPath,
      Destination: mount.containerPath,
      Mode: mount.access,
      RW: mount.access !== "ro",
      Propagation: "rprivate",
    };
  });
  if (sealedSnapshot) {
    binds.push({
      Type: "bind",
      Source: sealedSnapshot.hostPath,
      Destination: sealedSnapshot.containerPath,
      Mode: "ro",
      RW: false,
      Propagation: "rprivate",
    });
  }
  const volumes = [
    ...phase.workerSecretSetIds.map((secretSetId) => {
      const secretSet = receipt.resources.workerSecretSets[secretSetId];
      const volume = receipt.resources.volumes[secretSet.volumeId];
      return {
        Type: "volume",
        Name: volume.engineName,
        Source: `/var/lib/docker/volumes/${volume.engineName}/_data`,
        Destination: secretSet.containerRoot,
        Driver: "local",
        Mode: "",
        RW: false,
        Propagation: "",
      };
    }),
    ...phase.scratchVolumeIds.map((volumeId) => {
      const volume = receipt.resources.volumes[volumeId];
      return {
        Type: "volume",
        Name: volume.engineName,
        Source: `/var/lib/docker/volumes/${volume.engineName}/_data`,
        Destination: volume.containerPath,
        Driver: "local",
        Mode: "",
        RW: true,
        Propagation: "",
      };
    }),
  ];
  return [...binds, ...volumes];
}

function expectedSemanticInspectMountsForBody(receipt, body) {
  const binds = body.HostConfig.Binds.map((entry) => {
    const separator = entry.lastIndexOf(":");
    const sourceAndTarget = entry.slice(0, separator);
    const mode = entry.slice(separator + 1);
    const targetSeparator = sourceAndTarget.lastIndexOf(":");
    const source = sourceAndTarget.slice(0, targetSeparator);
    const destination = sourceAndTarget.slice(targetSeparator + 1);
    return {
      Type: "bind",
      Source: source,
      Destination: destination,
      Mode: mode,
      RW: mode !== "ro",
      Propagation: "rprivate",
    };
  });
  const volumeByName = Object.fromEntries(
    Object.values(receipt.resources.volumes).map((volume) => [volume.engineName, volume]),
  );
  const volumes = body.HostConfig.Mounts.map((mount) => {
    const volume = volumeByName[mount.Source];
    if (!volume || mount.Type !== "volume") {
      throw brokerError(409, "semantic worker body contains an unowned named mount");
    }
    return {
      Type: "volume",
      Name: mount.Source,
      Source: `/var/lib/docker/volumes/${mount.Source}/_data`,
      Destination: mount.Target,
      Driver: "local",
      Mode: "",
      RW: mount.ReadOnly !== true,
      Propagation: "",
    };
  });
  return [...binds, ...volumes];
}

function assertExactSemanticWorkerInspect(inspect, {
  body,
  id,
  name,
  phase,
  receipt,
  sealedSnapshot,
}) {
  const config = inspect?.Config ?? {};
  const observedName = String(inspect?.Name ?? "").replace(/^\//, "");
  if (inspect?.Id !== id || observedName !== name || inspect?.Image !== phase.workerImageId
    || config.Image !== body.Image
    || canonicalJson(config.Entrypoint) !== canonicalJson(body.Entrypoint)
    || canonicalJson(config.Cmd) !== canonicalJson(body.Cmd)
    || canonicalJson(config.Env) !== canonicalJson(body.Env)
    || config.User !== body.User || config.WorkingDir !== body.WorkingDir
    || config.NetworkDisabled !== body.NetworkDisabled
    || config.AttachStdin !== false || config.AttachStdout !== false
    || config.AttachStderr !== false || config.OpenStdin !== false
    || config.StdinOnce !== false || config.Tty !== false
    || canonicalJson(config.Labels) !== canonicalJson(body.Labels)) {
    throw brokerError(409, "semantic worker inspect identity is not exact");
  }
  if (canonicalJson(Object.keys(inspect?.HostConfig ?? {}).sort())
      !== canonicalJson(Object.keys(body.HostConfig).sort())
    || canonicalJson(inspect.HostConfig) !== canonicalJson(body.HostConfig)) {
    throw brokerError(409, "semantic worker HostConfig was widened, omitted or normalized");
  }
  if (Object.keys(config.Volumes ?? {}).length || Object.keys(config.ExposedPorts ?? {}).length
    || config.Healthcheck || (config.OnBuild ?? []).length) {
    throw brokerError(409, "semantic worker image configuration exposes an unmodeled surface");
  }
  const expectedMounts = expectedSemanticInspectMountsForBody(receipt, body);
  if (canonicalJson(inspect?.Mounts ?? []) !== canonicalJson(expectedMounts)) {
    throw brokerError(409, "semantic worker inspect mounts are not exact");
  }
  const expectedNetworks = {};
  if (canonicalJson(inspect?.NetworkSettings?.Networks ?? {}) !== canonicalJson(expectedNetworks)) {
    throw brokerError(409, "semantic worker inspect network authority is not exact");
  }
}

function assertSemanticWorkerId(value) {
  if (!/^[a-f0-9]{64}$/.test(String(value ?? ""))) {
    throw brokerError(502, "semantic Engine returned an invalid worker ID");
  }
}

export function assertExactWorkerInspect(inspect, { id, name, body, imageId, hostPath }) {
  const observedName = String(inspect?.Name ?? "").replace(/^\//, "");
  const config = inspect?.Config ?? {};
  const hostConfig = inspect?.HostConfig ?? {};
  if (inspect?.Id !== id || observedName !== name || inspect?.Image !== imageId
    || config.Image !== body.Image || canonicalJson(config.Entrypoint) !== canonicalJson(body.Entrypoint)
    || canonicalJson(config.Cmd) !== canonicalJson(body.Cmd) || canonicalJson(config.Env) !== canonicalJson(body.Env)
    || config.User !== body.User || config.WorkingDir !== body.WorkingDir
    || config.NetworkDisabled !== true || config.AttachStdin !== false || config.AttachStdout !== false
    || config.AttachStderr !== false || config.OpenStdin !== false || config.StdinOnce !== false || config.Tty !== false
    || canonicalJson(config.Labels) !== canonicalJson(body.Labels)) {
    throw brokerError(409, "created worker identity does not match the active receipt");
  }
  if (canonicalJson(Object.keys(hostConfig).sort()) !== canonicalJson(Object.keys(body.HostConfig).sort())
    || canonicalJson(hostConfig) !== canonicalJson(body.HostConfig)) {
    throw brokerError(409, "created worker HostConfig schema or value was widened, omitted or normalized unexpectedly");
  }
  if (hostConfig.NetworkMode === "host" || hostConfig.PidMode === "host" || hostConfig.IpcMode === "host"
    || hostConfig.CgroupnsMode === "host" || hostConfig.Privileged || (hostConfig.Devices ?? []).length
    || (hostConfig.DeviceRequests ?? []).length || (hostConfig.CapAdd ?? []).length || (hostConfig.GroupAdd ?? []).length
    || (hostConfig.DeviceCgroupRules ?? []).length
    || (hostConfig.Links ?? []).length || (hostConfig.VolumesFrom ?? []).length || Object.keys(hostConfig.PortBindings ?? {}).length
    || hostConfig.PublishAllPorts || (hostConfig.Binds ?? []).some((bind) => bind.startsWith("/:") || bind.includes("docker.sock"))) {
    throw brokerError(409, "created worker contains a forbidden host authority");
  }
  const mounts = inspect?.Mounts ?? [];
  if (mounts.length !== 1 || mounts[0]?.Source !== hostPath || mounts[0]?.Destination !== "/data/backups" || mounts[0]?.RW !== false) {
    throw brokerError(409, "created worker mounts do not match the admitted backup root");
  }
  if (Object.keys(config.Volumes ?? {}).length || Object.keys(config.ExposedPorts ?? {}).length
    || config.Healthcheck || (config.OnBuild ?? []).length) throw brokerError(409, "created worker image configuration exposes an unmodeled surface");
  if (Object.keys(inspect?.NetworkSettings?.Networks ?? {}).length !== 0) throw brokerError(409, "created worker unexpectedly joined a network");
}

async function runtimeSnapshot(containers, transport, signal) {
  const observed = {};
  for (const logicalId of Object.keys(containers).sort()) {
    const expected = containers[logicalId];
    const inspect = await transport.inspectContainer(expected.name, signal);
    const containerId = String(inspect?.Id ?? "");
    const observedName = String(inspect?.Name ?? "").replace(/^\//, "");
    const imageRef = String(inspect?.Config?.Image ?? "");
    const imageId = String(inspect?.Image ?? "");
    const state = String(inspect?.State?.Status ?? "");
    const health = String(inspect?.State?.Health?.Status ?? "none");
    const authority = observedContainerAuthority(inspect);
    if (containerId !== expected.containerId || observedName !== expected.name
      || imageRef !== expected.imageRef || imageId !== expected.imageId
      || canonicalJson(inspect?.Config?.Labels ?? {}) !== canonicalJson(expected.labels)
      || canonicalJson(authority) !== canonicalJson(expected.authority)
      || state !== expected.expectedState || health !== expected.expectedHealth) {
      throw brokerError(409, `runtime resource ${logicalId} does not match the active receipt`);
    }
    observed[logicalId] = {
      authoritySha256: sha256(canonicalJson(authority)),
      containerId,
      health,
      imageId,
      imageRef,
      labelsSha256: sha256(canonicalJson(expected.labels)),
      name: expected.name,
      state,
    };
  }
  return {
    schema: "platform.docker-runtime-snapshot/v2",
    resources: observed,
  };
}

function observedContainerAuthority(inspect) {
  const config = inspect?.Config ?? {};
  const host = inspect?.HostConfig ?? {};
  const networkSettings = inspect?.NetworkSettings ?? {};
  const requiredHostKeys = [
    "Binds",
    "CapAdd",
    "CapDrop",
    "CgroupnsMode",
    "DeviceCgroupRules",
    "Devices",
    "DeviceRequests",
    "ExtraHosts",
    "GroupAdd",
    "IpcMode",
    "Links",
    "NetworkMode",
    "PidMode",
    "PortBindings",
    "Privileged",
    "PublishAllPorts",
    "ReadonlyRootfs",
    "Runtime",
    "SecurityOpt",
    "UsernsMode",
    "UTSMode",
    "VolumesFrom",
  ];
  if (!requiredHostKeys.every((key) => Object.hasOwn(host, key))
    || !Object.hasOwn(config, "User") || !Object.hasOwn(networkSettings, "Networks")) {
    throw brokerError(409, "runtime inspect omitted an authority-bearing Docker field");
  }
  const list = (value) => value == null ? [] : Array.isArray(value) ? value : [value];
  const mounts = list(inspect?.Mounts).map((mount) => ({
    type: String(mount?.Type ?? ""),
    source: String(mount?.Source ?? ""),
    destination: String(mount?.Destination ?? ""),
    rw: mount?.RW === true,
  })).sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  return {
    binds: list(host.Binds).map(String),
    capAdd: list(host.CapAdd).map(String),
    capDrop: list(host.CapDrop).map(String),
    cgroupnsMode: String(host.CgroupnsMode ?? ""),
    configSha256: crypto.createHash("sha256").update(canonicalJson(config)).digest("hex"),
    deviceCgroupRules: list(host.DeviceCgroupRules).map(String),
    devices: list(host.Devices).map((item) => canonicalJson(item)),
    deviceRequests: list(host.DeviceRequests).map((item) => canonicalJson(item)),
    extraHosts: list(host.ExtraHosts).map(String),
    groupAdd: list(host.GroupAdd).map(String),
    hostConfigSha256: crypto.createHash("sha256").update(canonicalJson(host)).digest("hex"),
    ipcMode: String(host.IpcMode ?? ""),
    links: list(host.Links).map(String),
    mounts,
    networkMode: String(host.NetworkMode ?? ""),
    networkSettingsSha256: crypto.createHash("sha256").update(canonicalJson(networkSettings)).digest("hex"),
    networks: Object.keys(inspect?.NetworkSettings?.Networks ?? {}).sort(),
    pidMode: String(host.PidMode ?? ""),
    portBindings: host.PortBindings,
    privileged: host.Privileged === true,
    publishAllPorts: host.PublishAllPorts === true,
    readonlyRootfs: host.ReadonlyRootfs === true,
    runtime: String(host.Runtime),
    securityOpt: list(host.SecurityOpt).map(String),
    user: String(config.User ?? ""),
    usernsMode: String(host.UsernsMode ?? ""),
    utsMode: String(host.UTSMode),
    volumesFrom: list(host.VolumesFrom).map(String),
  };
}

export function parseWorkerOutput(bytes, command) {
  if (command !== "backup-prune-plan") throw brokerError(500, "worker output policy mismatch");
  const decoded = decodeDockerLogFrames(bytes, 64 * 1024);
  if (decoded.stderr.length || decoded.stdout.length < 2 || decoded.stdout.length > 64 * 1024) {
    throw brokerError(502, "worker output is missing, oversized or contains stderr");
  }
  const lines = decoded.stdout.toString("utf8").split(/\r?\n/);
  if (lines.at(-1) === "") lines.pop();
  if (lines.length !== 1) throw brokerError(502, "worker must emit exactly one JSON document");
  let value;
  try {
    value = JSON.parse(lines[0]);
  } catch {
    throw brokerError(502, "worker output is malformed");
  }
  const expectedKeys = [
    "completeManifestCount",
    "expiredManifestIds",
    "keepCompleteManifests",
    "mode",
    "mutationPerformed",
    "retainedManifestIds",
    "schema",
  ];
  if (!value || typeof value !== "object" || Array.isArray(value)
    || canonicalJson(Object.keys(value).sort()) !== canonicalJson(expectedKeys)
    || value.schema !== "platform.backup-prune-plan/v1" || value.mode !== "plan"
    || value.keepCompleteManifests !== 42 || value.mutationPerformed !== false
    || !Number.isSafeInteger(value.completeManifestCount) || value.completeManifestCount < 0
    || !Array.isArray(value.retainedManifestIds) || !Array.isArray(value.expiredManifestIds)) {
    throw brokerError(502, "worker output violates the fixed schema");
  }
  const ids = [...value.retainedManifestIds, ...value.expiredManifestIds];
  if (ids.length !== value.completeManifestCount || new Set(ids).size !== ids.length
    || ids.some((id) => !/^[a-z0-9](?:[a-z0-9._:-]{0,158}[a-z0-9])?$/.test(String(id)))) {
    throw brokerError(502, "worker output manifest inventory is inconsistent");
  }
  return value;
}

function parseSemanticWorkerOutput(bytes, {
  action,
  parameters,
  phase,
  phaseId,
  requestId,
  requestSha256,
  workerRole,
}) {
  const decoded = decodeDockerLogFrames(bytes, MAX_PHASE_OUTPUT_BYTES);
  if (decoded.stderr.length || decoded.stdout.length < 2
    || decoded.stdout.length > MAX_PHASE_OUTPUT_BYTES
    || decoded.stdout.at(-1) !== 0x0a
    || decoded.stdout.subarray(0, -1).includes(0x0a)
    || decoded.stdout.subarray(0, -1).includes(0x0d)) {
    throw brokerError(502, "semantic worker output is missing, oversized or contains stderr");
  }
  let value;
  try {
    const text = new TextDecoder("utf-8", { fatal: true })
      .decode(decoded.stdout.subarray(0, -1));
    value = JSON.parse(text);
  } catch {
    throw brokerError(502, "semantic worker result is malformed");
  }
  if (!isPlainRecord(value)
    || !hasExactKeys(value, [
      "action",
      "command",
      "job",
      "output",
      "phaseId",
      "requestId",
      "schema",
      "status",
    ])
    || value.schema !== SEMANTIC_WORKER_RESULT_SCHEMA
    || value.status !== "completed"
    || value.requestId !== requestId
    || value.action !== action
    || value.phaseId !== phaseId
    || value.command !== phase.command) {
    throw brokerError(502, "semantic worker result identity is invalid");
  }
  const expectedJob = action === "backup.job.execute"
    ? {
        jobFileName: parameters.jobFileName,
        jobId: parameters.jobId,
        jobOperation: parameters.jobOperation,
        jobSha256: parameters.jobSha256,
      }
    : null;
  if (canonicalJson(value.job) !== canonicalJson(expectedJob)) {
    throw brokerError(502, "semantic worker result job identity is invalid");
  }
  if (workerRole === "artifact-resolver") {
    validateBrokerArtifactBinding(value.output, {
      consumerRequestSha256: requestSha256,
      verificationKind: "verified-manifest",
    });
  } else if (workerRole === "helper-preparer") {
    if (!isPlainRecord(value.output)
      || !hasExactKeys(value.output, [
        "mutationPerformed", "phaseId", "preparedRelativePaths", "requestSha256", "schema", "status",
      ])
      || value.output.schema !== "platform.docker-worker.helper-preparation/v1"
      || value.output.status !== "completed" || value.output.mutationPerformed !== true
      || value.output.phaseId !== phaseId || value.output.requestSha256 !== requestSha256
      || !Array.isArray(value.output.preparedRelativePaths)
      || value.output.preparedRelativePaths.some((entry) => typeof entry !== "string")
      || canonicalJson(value.output.preparedRelativePaths)
        !== canonicalJson([...value.output.preparedRelativePaths].sort())) {
      throw brokerError(502, "helper preparer result is invalid");
    }
  } else if (["scratch-preparer", "scratch-cleaner"].includes(workerRole)) {
    if (!isPlainRecord(value.output)
      || !hasExactKeys(value.output, [
        "engine", "mutationPerformed", "phaseId", "relativePath", "requestSha256", "role", "schema", "status",
      ])
      || value.output.schema !== "platform.docker-worker.scratch-result/v1"
      || value.output.status !== "completed" || value.output.mutationPerformed !== true
      || value.output.phaseId !== phaseId || value.output.requestSha256 !== requestSha256
      || value.output.role !== workerRole
      || !["mariadb", "minio", "postgres"].includes(value.output.engine)
      || value.output.relativePath
        !== `requests/${requestSha256}/${phaseId}/${value.output.engine}`) {
      throw brokerError(502, "scratch worker result is invalid");
    }
  } else {
    normalizeSemanticPhaseOutput(value.output, {
      allowArtifactBinding: workerRole === "evidence-finalizer",
      outputSchema: phase.outputSchema,
      parameters,
      phaseId,
      requestSha256,
    });
  }
  if (Buffer.byteLength(canonicalJson(value)) > MAX_PHASE_OUTPUT_BYTES) {
    throw brokerError(502, "semantic worker result exceeds the bounded output contract");
  }
  return cloneCanonicalValue(value);
}

function normalizeSemanticPhaseOutput(value, {
  allowArtifactBinding = false,
  outputSchema,
  parameters,
  phaseId,
  requestSha256,
}) {
  if (!isPlainRecord(value) || value.schema !== outputSchema
    || Buffer.byteLength(canonicalJson(value)) > MAX_PHASE_OUTPUT_BYTES) {
    throw brokerError(502, "semantic worker output schema or size is invalid");
  }
  if (phaseId === "prune.plan") {
    const keys = [
      "completeManifestCount",
      "expiredManifestIds",
      "keepCompleteManifests",
      "mode",
      "mutationPerformed",
      "retainedManifestIds",
      "schema",
    ];
    if (!hasExactKeys(value, keys)
      || value.mode !== "plan" || value.keepCompleteManifests !== 42
      || value.mutationPerformed !== false
      || !Number.isSafeInteger(value.completeManifestCount) || value.completeManifestCount < 0
      || !Array.isArray(value.retainedManifestIds) || !Array.isArray(value.expiredManifestIds)) {
      throw brokerError(502, "semantic prune result violates its exact schema");
    }
    const ids = [...value.retainedManifestIds, ...value.expiredManifestIds];
    if (ids.length !== value.completeManifestCount || new Set(ids).size !== ids.length
      || ids.some((id) => !/^[a-z0-9](?:[a-z0-9._:-]{0,158}[a-z0-9])?$/.test(String(id)))) {
      throw brokerError(502, "semantic prune result inventory is invalid");
    }
    return value;
  }
  const expectedKeys = ["evidenceSha256", "mutationPerformed", "schema", "status"];
  if (allowArtifactBinding
    && ["catalog.capture", "job.backup.capture", "restore.capture"].includes(phaseId)) {
    expectedKeys.push("artifactBinding");
  }
  if (["job.backup.capture", "job.restore.verify"].includes(phaseId)) {
    expectedKeys.push("jobId", "jobOperation");
  }
  if (phaseId === "offsite.sync") expectedKeys.push("repositoryOffsite");
  if (!hasExactKeys(value, expectedKeys)
    || value.status !== "passed"
    || !/^[a-f0-9]{64}$/.test(String(value.evidenceSha256 ?? ""))
    || value.mutationPerformed !== true
    || containsArray(value)) {
    throw brokerError(502, "semantic worker output contains an unsupported field, array or digest");
  }
  if (["job.backup.capture", "job.restore.verify"].includes(phaseId)
    && (value.jobId !== parameters.jobId || value.jobOperation !== parameters.jobOperation)) {
    throw brokerError(502, "semantic worker output job identity is invalid");
  }
  if (phaseId === "offsite.sync" && value.repositoryOffsite !== true) {
    throw brokerError(502, "semantic offsite output identity is invalid");
  }
  if (Object.hasOwn(value, "artifactBinding")) {
    validateBrokerArtifactBinding(value.artifactBinding, {
      consumerRequestSha256: requestSha256,
      producerPhaseId: phaseId,
      producerRequestSha256: requestSha256,
      verificationKind: "journaled-phase-result",
    });
    if (value.artifactBinding.verification.evidenceSha256 !== value.evidenceSha256) {
      throw brokerError(502, "semantic capture binding evidence lineage is invalid");
    }
  }
  return value;
}

function validateBrokerArtifactBinding(value, {
  consumerRequestSha256,
  producerPhaseId,
  producerRequestSha256,
  verificationKind,
}) {
  if (!isPlainRecord(value) || !hasExactKeys(value, [
    "artifactSetSha256", "artifacts", "consumerRequestSha256", "manifestRelativePath",
    "manifestSha256", "producerPhaseId", "producerRequestSha256", "schema", "verification",
  ]) || value.schema !== "platform.docker-action.artifact-binding/v1"
    || value.consumerRequestSha256 !== consumerRequestSha256
    || (producerPhaseId !== undefined && value.producerPhaseId !== producerPhaseId)
    || (producerRequestSha256 !== undefined && value.producerRequestSha256 !== producerRequestSha256)
    || !/^[a-f0-9]{64}$/.test(String(value.producerRequestSha256 ?? ""))
    || !/^[a-f0-9]{64}$/.test(String(value.manifestSha256 ?? ""))
    || !/^[a-f0-9]{64}$/.test(String(value.artifactSetSha256 ?? ""))
    || value.manifestRelativePath
      !== `requests/${value.producerRequestSha256}/manifests/${value.producerPhaseId}.json`
    || !isPlainRecord(value.artifacts) || Object.keys(value.artifacts).length < 1
    || value.artifactSetSha256 !== sha256(canonicalJson(value.artifacts))
    || !isPlainRecord(value.verification)
    || !hasExactKeys(value.verification, ["authoritySha256", "evidenceSha256", "kind", "source"])
    || value.verification.kind !== verificationKind
    || !/^[a-f0-9]{64}$/.test(String(value.verification.authoritySha256 ?? ""))
    || !/^[a-f0-9]{64}$/.test(String(value.verification.evidenceSha256 ?? ""))) {
    throw brokerError(502, "artifact binding identity or provenance is invalid");
  }
  for (const [resourceId, artifact] of Object.entries(value.artifacts)) {
    if (!isPlainRecord(artifact)
      || !hasExactKeys(artifact, ["relativePath", "resourceId", "sha256"])
      || artifact.resourceId !== resourceId
      || !/^[a-f0-9]{64}$/.test(String(artifact.sha256 ?? ""))
      || !isExactRelativeBackupPath(artifact.relativePath)) {
      throw brokerError(502, "artifact binding resource entry is invalid");
    }
  }
  return value;
}

function containsArray(value) {
  if (Array.isArray(value)) return true;
  return isPlainRecord(value) && Object.values(value).some(containsArray);
}

export function normalizeSemanticHelperResult({ helper, logs, statusCode }) {
  if (!isPlainRecord(helper) || !Number.isSafeInteger(statusCode)
    || statusCode !== 0 || typeof helper.helperProfileId !== "string"
    || !/^sha256:[a-f0-9]{64}$/.test(String(helper.imageId ?? ""))
    || !isPlainRecord(helper.outputPolicy) || !isPlainRecord(helper.paths)) {
    throw brokerError(502, "semantic helper result identity or exit status is invalid");
  }
  const maximum = Number(helper.outputPolicy.maximumRawBytes
    ?? helper.outputPolicy.maximumSourceBytes
    ?? helper.outputPolicy.maximumReportBytes ?? 64 * 1024);
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1024 * 1024) {
    throw brokerError(502, "semantic helper output is oversized");
  }
  const decoded = decodeDockerLogFrames(logs, maximum);
  if (decoded.stderr.length !== 0) {
    throw brokerError(502, "semantic helper emitted unsupported stderr");
  }
  const outputMode = String(helper.outputPolicy.kind ?? "");
  let artifactRelativePath = null;
  let stdoutBase64 = "";
  if (outputMode === "artifact") {
    if (decoded.stdout.length !== 0
      || !isExactRelativeBackupPath(helper.paths.artifactRelativePath)) {
      throw brokerError(502, "semantic artifact helper emitted unsupported stdout or path");
    }
    artifactRelativePath = helper.paths.artifactRelativePath;
  } else if (outputMode === "none") {
    if (decoded.stdout.length !== 0) {
      throw brokerError(502, "semantic no-output helper emitted unsupported stdout");
    }
  } else if (outputMode === "json") {
    const normalized = normalizeSemanticHelperJson(helper.helperProfileId, decoded.stdout);
    stdoutBase64 = Buffer.from(canonicalJson(normalized)).toString("base64url");
  } else {
    throw brokerError(502, "semantic helper output mode is unsupported");
  }
  return Object.freeze({
    artifactRelativePath,
    exitCode: 0,
    helperProfileId: helper.helperProfileId,
    imageId: helper.imageId,
    outputMode,
    status: "completed",
    stderrSha256: sha256(decoded.stderr),
    stdoutBase64,
  });
}

function normalizeSemanticHelperJson(helperProfileId, bytes) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw brokerError(502, "semantic helper JSON is not valid UTF-8");
  }
  const exactEngineStatus = (engine, source) => {
    let value;
    try { value = JSON.parse(source); } catch { throw brokerError(502, "semantic helper JSON is malformed"); }
    if (!isPlainRecord(value) || !hasExactKeys(value, ["engine", "status"])
      || value.engine !== engine || value.status !== "passed") {
      throw brokerError(502, "semantic helper verification JSON is not exact");
    }
    return { engine, status: "passed" };
  };
  if (helperProfileId === "helper.restore.mariadb.verify") {
    if (!text.endsWith("\n") || text.endsWith("\n\n") || text.slice(0, -1).includes("\r")) {
      throw brokerError(502, "MariaDB verification output framing is invalid");
    }
    return exactEngineStatus("mariadb", text.slice(0, -1));
  }
  if (helperProfileId === "helper.restore.postgres.verify") {
    const trimmed = text.replace(/^[\x09\x0a\x0b\x0c\x0d\x20]+|[\x09\x0a\x0b\x0c\x0d\x20]+$/g, "");
    if (!trimmed) throw brokerError(502, "PostgreSQL verification output is empty");
    return exactEngineStatus("postgres", trimmed);
  }
  if (helperProfileId === "helper.restore.minio.verify") {
    if (bytes.length !== 0) throw brokerError(502, "MinIO diff reported an object difference");
    return { differences: 0, engine: "minio", status: "passed" };
  }
  if (helperProfileId === "helper.offsite.restic") {
    if (!text.endsWith("\n")) throw brokerError(502, "Restic NDJSON lacks its terminal LF");
    const lines = text.slice(0, -1).split("\n");
    if (!lines.length || lines.some((line) => line.length < 2 || line.includes("\r"))) {
      throw brokerError(502, "Restic NDJSON framing is invalid");
    }
    let summary = null;
    for (const [index, line] of lines.entries()) {
      let event;
      try { event = JSON.parse(line); } catch { throw brokerError(502, "Restic NDJSON event is malformed"); }
      if (!isPlainRecord(event) || typeof event.message_type !== "string") {
        throw brokerError(502, "Restic NDJSON event identity is invalid");
      }
      if (event.message_type === "summary") {
        if (summary || index !== lines.length - 1
          || !/^[a-f0-9]{64}$/.test(String(event.snapshot_id ?? ""))) {
          throw brokerError(502, "Restic terminal summary is duplicated, reordered or invalid");
        }
        summary = event;
      } else if (summary) {
        throw brokerError(502, "Restic emitted an event after its terminal summary");
      }
    }
    if (!summary) throw brokerError(502, "Restic terminal summary is missing");
    return { messageType: "summary", snapshotId: summary.snapshot_id, status: "passed" };
  }
  throw brokerError(502, "semantic helper JSON normalizer is unsupported");
}

function decodeDockerLogFrames(value, maximumPayloadBytes = MAX_ENGINE_RESPONSE_BYTES) {
  if (!Buffer.isBuffer(value)) throw brokerError(502, "worker log stream is not a Buffer");
  if (!Number.isSafeInteger(maximumPayloadBytes) || maximumPayloadBytes < 0
    || maximumPayloadBytes > MAX_ENGINE_RESPONSE_BYTES) {
    throw brokerError(502, "worker log stream bound is invalid");
  }
  const bytes = value;
  if (bytes.length > MAX_ENGINE_RESPONSE_BYTES) {
    throw brokerError(502, "worker log stream is oversized");
  }
  const stdout = [];
  const stderr = [];
  let stdoutLength = 0;
  let stderrLength = 0;
  let payloadLength = 0;
  let offset = 0;
  while (offset < bytes.length) {
    if (bytes.length - offset < 8) throw brokerError(502, "worker log frame is truncated");
    const stream = bytes[offset];
    if (![1, 2].includes(stream) || bytes[offset + 1] !== 0 || bytes[offset + 2] !== 0 || bytes[offset + 3] !== 0) {
      throw brokerError(502, "worker log frame header is invalid");
    }
    const length = bytes.readUInt32BE(offset + 4);
    offset += 8;
    if (length > MAX_ENGINE_RESPONSE_BYTES || length > bytes.length - offset) {
      throw brokerError(502, "worker log frame length is invalid");
    }
    payloadLength += length;
    if (payloadLength > maximumPayloadBytes) throw brokerError(502, "worker log payload is oversized");
    if (stream === 1) {
      stdoutLength += length;
      if (stdoutLength > MAX_ENGINE_RESPONSE_BYTES) throw brokerError(502, "worker stdout is oversized");
      stdout.push(bytes.subarray(offset, offset + length));
    } else {
      stderrLength += length;
      if (stderrLength > MAX_ENGINE_RESPONSE_BYTES) throw brokerError(502, "worker stderr is oversized");
      stderr.push(bytes.subarray(offset, offset + length));
    }
    offset += length;
  }
  return { stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) };
}

async function withTimeout(operation, timeoutMs, message) {
  const controller = new AbortController();
  let timeout;
  try {
    return await Promise.race([
      Promise.resolve().then(() => operation(controller.signal)),
      new Promise((_, reject) => {
        timeout = setTimeout(() => {
          controller.abort();
          reject(brokerError(504, message));
        }, timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

function assertEngineId(id) {
  if (!/^[a-f0-9]{64}$/.test(String(id ?? "")) && !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(String(id ?? ""))) {
    throw brokerError(502, "Engine returned an invalid resource ID");
  }
}

export function serveBrokerConnection(connection, core) {
  let chunks = [];
  let length = 0;
  let complete = false;
  const peerState = { delivery: null, lost: false };
  const markPeerLost = () => {
    peerState.lost = true;
    if (peerState.delivery) {
      try { peerState.delivery.undelivered(); } catch {}
    }
  };
  connection.setTimeout(5000, () => {
    if (!complete) connection.destroy();
  });
  connection.on("data", async (chunk) => {
    if (complete) return;
    length += chunk.length;
    if (length > MAX_REQUEST_BYTES + 1) {
      complete = true;
      return respond(connection, 413, "request is oversized");
    }
    chunks.push(chunk);
    const frame = Buffer.concat(chunks);
    const newline = frame.indexOf(0x0a);
    if (newline === -1) return;
    complete = true;
    connection.setTimeout(0);
    if (newline !== frame.length - 1) return respond(connection, 400, "exactly one request frame is required");
    try {
      const response = await core.handle(frame.subarray(0, newline), {
        deliveryMode: "explicit",
        peerState,
      });
      peerState.delivery = response.delivery ?? null;
      if (peerState.lost) {
        peerState.delivery?.undelivered();
        return;
      }
      try {
        writeResponse(connection, response.statusCode, response.body, () => {
          try {
            if (peerState.lost) peerState.delivery?.undelivered();
            else peerState.delivery?.delivered();
          } catch {
            connection.destroy();
          }
        });
      } catch {
        markPeerLost();
        connection.destroy();
      }
    } catch (error) {
      respond(connection, Number(error?.statusCode) || 500, String(error?.message ?? "request failed"));
    } finally {
      chunks = [];
    }
  });
  connection.on("close", () => { if (complete) markPeerLost(); });
  connection.on("error", () => { if (complete) markPeerLost(); });
}

function respond(connection, statusCode, message) {
  writeResponse(connection, statusCode, {
    schema: "platform.docker-action.response/v1",
    status: "rejected",
    error: message,
  });
}

function writeResponse(connection, statusCode, body, callback) {
  connection.end(encodeActionResponseFrame({ statusCode, ...body }), callback);
}

function sanitizeResult(value) {
  if (value === undefined) return {};
  const encoded = canonicalJson(value);
  if (Buffer.byteLength(encoded) > MAX_ENGINE_RESPONSE_BYTES) throw brokerError(500, "action result is oversized");
  return JSON.parse(encoded);
}

function readDescriptor(descriptor, size) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const count = fs.readSync(descriptor, bytes, offset, size - offset, offset);
    if (count === 0) break;
    offset += count;
  }
  if (offset !== size) throw brokerError(409, "protected input changed while being read");
  return bytes;
}

function ensurePrivateDirectory(directory, { expectedUid = 0, expectedGid = 0 } = {}) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== expectedUid || stat.gid !== expectedGid || (stat.mode & 0o077) !== 0) {
    throw new Error(`broker state directory is not private: ${directory}`);
  }
}

function prepareSocket(socketPath) {
  const directory = path.dirname(path.resolve(socketPath));
  ensurePrivateDirectory(directory);
  const existing = fs.lstatSync(socketPath, { throwIfNoEntry: false });
  if (existing) {
    if (!existing.isSocket() || existing.isSymbolicLink()) throw new Error("refusing to replace a non-socket broker path");
    fs.unlinkSync(socketPath);
  }
}

function brokerError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

async function main() {
  const socketPath = process.env.DOCKER_ACTION_BROKER_SOCKET || DEFAULT_SOCKET_PATH;
  const server = createDockerActionBroker({ socketPath });
  await server.initialize();
  server.prepareSocket();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, resolve);
  });
  const stop = () => server.close(() => {
    const stat = fs.lstatSync(socketPath, { throwIfNoEntry: false });
    if (stat?.isSocket()) fs.unlinkSync(socketPath);
    process.exit(0);
  });
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error.message ?? error}\n`);
    process.exitCode = 1;
  });
}
