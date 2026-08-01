#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  ACTIONS,
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
const CLEANUP_TIMEOUT_MS = 10_000;

export class PersistentReplayStore {
  constructor(stateDir = DEFAULT_STATE_DIR, {
    now = () => Date.now(),
    bootId = crypto.randomBytes(24).toString("hex"),
    expectedUid = 0,
    expectedGid = 0,
  } = {}) {
    this.stateDir = path.resolve(stateDir);
    this.replayDir = path.join(this.stateDir, "replay");
    this.activationReplayDir = path.join(this.stateDir, "activation-replay");
    this.lockPath = path.join(this.stateDir, "active.lock");
    this.generationPath = path.join(this.stateDir, "active-generation.json");
    this.activationPath = path.join(this.stateDir, "active-activation.json");
    this.now = now;
    this.bootId = bootId;
    this.expectedUid = expectedUid;
    this.expectedGid = expectedGid;
    ensurePrivateDirectory(this.stateDir, { expectedUid, expectedGid });
    ensurePrivateDirectory(this.replayDir, { expectedUid, expectedGid });
    ensurePrivateDirectory(this.activationReplayDir, { expectedUid, expectedGid });
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
      descriptor = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
      fs.writeFileSync(descriptor, `${JSON.stringify({ expiresAt: new Date(this.now() + 24 * 60 * 60_000).toISOString() })}\n`);
      fs.fsyncSync(descriptor);
    } catch (error) {
      if (error?.code === "EEXIST") throw brokerError(409, "request replay rejected");
      throw error;
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
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
      || activation.dastChainSha256 !== trusted?.receipt?.dastChainSha256) {
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
    const replayNames = fs.readdirSync(this.activationReplayDir);
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
      descriptor = fs.openSync(replayFile, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
      fs.writeFileSync(descriptor, `${canonicalJson({
        activationId: next.activationId,
        envelopeSha256: next.envelopeSha256,
        generation: next.generation,
        requestIdentitySha256,
      })}\n`);
      fs.fsyncSync(descriptor);
    } catch (error) {
      if (error?.code === "EEXIST") throw brokerError(409, "activation ABA replay rejected");
      throw error;
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
    const replayDirectory = fs.openSync(this.activationReplayDir, fs.constants.O_RDONLY);
    try {
      fs.fsyncSync(replayDirectory);
    } finally {
      fs.closeSync(replayDirectory);
    }
    this.writeStateJsonAtomic(this.activationPath, next, { replace: Boolean(current) });
  }

  acquire(request, trusted) {
    const record = {
      schema: "platform.docker-action.lease/v1",
      bootId: this.bootId,
      requestId: request.requestId,
      action: request.action,
      intentId: trusted.intent.intentId,
      receiptDigest: trusted.receiptDigest,
      startedAt: new Date(this.now()).toISOString(),
      expiresAt: new Date(this.now() + 24 * 60 * 60_000).toISOString(),
      resourceName: null,
      worker: null,
    };
    let descriptor;
    try {
      descriptor = fs.openSync(this.lockPath, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
      fs.writeFileSync(descriptor, `${canonicalJson(record)}\n`);
      fs.fsyncSync(descriptor);
    } catch (error) {
      if (error?.code === "EEXIST") throw brokerError(409, "another Docker action is running");
      throw error;
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
    let closed = false;
    return Object.freeze({
      recordWorker: ({ resourceName, body, imageId, hostPath }) => {
        if (closed || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(String(resourceName ?? ""))) {
          throw new Error("broker lease resource name is invalid");
        }
        record.resourceName = resourceName;
        record.worker = { body, imageId, hostPath };
        this.writeStateJsonAtomic(this.lockPath, record, { replace: true });
      },
      release: () => {
        if (closed) return;
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
    if (record.schema !== "platform.docker-action.lease/v1" || !record.bootId || !record.requestId
      || !record.action || !record.intentId || !/^[a-f0-9]{64}$/.test(String(record.receiptDigest ?? ""))
      || !Number.isFinite(Date.parse(record.expiresAt))) {
      throw new Error("broker recovery lease is malformed");
    }
    if (record.bootId === this.bootId) throw new Error("broker has an unexpected live lease before startup");
    if (record.resourceName) {
      if (typeof engine?.recoverLease !== "function") throw new Error("broker cannot recover a prior worker lease");
      await withTimeout((signal) => engine.recoverLease(record, signal), CLEANUP_TIMEOUT_MS, "worker recovery timed out");
    }
    this.unlinkExactStateFile(this.lockPath);
    return { status: "recovered", resourceName: record.resourceName };
  }

  purgeExpired() {
    const names = fs.readdirSync(this.replayDir);
    if (names.length > MAX_REPLAY_ENTRIES) throw brokerError(503, "replay ledger entry bound exceeded");
    let count = 0;
    let bytes = 0;
    for (const name of names) {
      if (!/^[a-f0-9]{64}$/.test(name)) throw new Error("unexpected replay ledger entry");
      const file = path.join(this.replayDir, name);
      const stat = fs.lstatSync(file);
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

  readStateJson(file, { optional = false } = {}) {
    let descriptor;
    try {
      descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    } catch (error) {
      if (optional && error?.code === "ENOENT") return null;
      throw error;
    }
    try {
      const before = fs.fstatSync(descriptor);
      if (!before.isFile() || before.nlink !== 1 || before.uid !== this.expectedUid
        || before.gid !== this.expectedGid || (before.mode & 0o077) !== 0 || before.size < 2 || before.size > 4096) {
        throw new Error("broker state file integrity failure");
      }
      const first = readDescriptor(descriptor, before.size);
      const second = readDescriptor(descriptor, before.size);
      const after = fs.fstatSync(descriptor);
      if (!["dev", "ino", "size", "mtimeMs", "ctimeMs", "mode", "uid", "gid", "nlink"].every((field) => before[field] === after[field])
        || first.length !== second.length || !crypto.timingSafeEqual(first, second)) {
        throw new Error("broker state file changed while being read");
      }
      return JSON.parse(first.toString("utf8"));
    } finally {
      fs.closeSync(descriptor);
    }
  }

  writeStateJsonAtomic(file, value, { replace = false } = {}) {
    const temporary = path.join(this.stateDir, `.state-${process.pid}-${crypto.randomBytes(12).toString("hex")}`);
    try {
      fs.writeFileSync(temporary, `${canonicalJson(value)}\n`, { flag: "wx", mode: 0o600 });
      const descriptor = fs.openSync(temporary, fs.constants.O_RDONLY);
      try {
        fs.fsyncSync(descriptor);
      } finally {
        fs.closeSync(descriptor);
      }
      if (!replace && fs.existsSync(file)) throw new Error("broker state generation already exists");
      fs.renameSync(temporary, file);
      const directory = fs.openSync(this.stateDir, fs.constants.O_RDONLY);
      try {
        fs.fsyncSync(directory);
      } finally {
        fs.closeSync(directory);
      }
    } finally {
      fs.rmSync(temporary, { force: true });
    }
  }

  unlinkExactStateFile(file) {
    const stat = fs.lstatSync(file, { throwIfNoEntry: false });
    if (!stat?.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== this.expectedUid
      || stat.gid !== this.expectedGid || (stat.mode & 0o077) !== 0) {
      throw new Error("broker state unlink integrity failure");
    }
    fs.unlinkSync(file);
    const directory = fs.openSync(path.dirname(file), fs.constants.O_RDONLY);
    try {
      fs.fsyncSync(directory);
    } finally {
      fs.closeSync(directory);
    }
  }
}

export function createDockerActionBroker({
  socketPath = DEFAULT_SOCKET_PATH,
  stateDir = DEFAULT_STATE_DIR,
  trustedContextProvider = defaultTrustedContextProvider,
  capabilityProvider = defaultCapabilityProvider,
  engine = createFixedDockerEngine(),
  now = () => Date.now(),
  operationTimeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!Number.isInteger(operationTimeoutMs) || operationTimeoutMs < 1 || operationTimeoutMs > 24 * 60 * 60_000) {
    throw new Error("Docker action timeout is invalid");
  }
  const replayStore = new PersistentReplayStore(stateDir, { now });
  const core = createBrokerCore({ trustedContextProvider, capabilityProvider, engine, replayStore, now, operationTimeoutMs });
  const server = net.createServer((connection) => serveConnection(connection, core));
  server.on("listening", () => fs.chmodSync(socketPath, 0o660));
  server.socketPath = socketPath;
  server.prepareSocket = () => prepareSocket(socketPath);
  server.initialize = () => replayStore.recover(engine);
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
    async handle(frame) {
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
      let timeout;
      const operation = Promise.resolve().then(async () => {
        let executionCompleted = false;
        try {
          const engineResult = await engine.execute(request.action, {
            lease,
            parameters: request.parameters,
            request,
            requestId: request.requestId,
            requestSha256,
            signal: controller.signal,
            trusted,
          });
          executionCompleted = true;
          const result = sanitizeResult(engineResult);
          const response = normalizeActionResponse(signActionResponse({
            action: request.action,
            errorCode: null,
            requestId: request.requestId,
            requestSha256,
            result,
            resultSha256: sha256(canonicalJson(result)),
            schema: RESPONSE_SCHEMA,
            status: "completed",
            statusCode: 200,
          }, capabilityKey), request, capabilityKey);
          encodeActionResponseFrame(response);
          lease.release();
          return {
            statusCode: 200,
            body: response,
          };
        } catch (error) {
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

export function createFixedDockerEngine({
  transport = new FixedDockerEngineTransport(),
  randomBytes = crypto.randomBytes,
  cleanupTimeoutMs = CLEANUP_TIMEOUT_MS,
} = {}) {
  return Object.freeze({
    async recoverLease(record, signal) {
      if (!record?.resourceName || !record?.worker?.body || !record?.worker?.imageId || !record?.worker?.hostPath) {
        throw new Error("worker recovery record is incomplete");
      }
      const inspect = await transport.inspectContainerForRecovery(record.resourceName, signal);
      if (!inspect) return { status: "absent" };
      assertExactWorkerInspect(inspect, {
        id: inspect.Id,
        name: record.resourceName,
        body: record.worker.body,
        imageId: record.worker.imageId,
        hostPath: record.worker.hostPath,
      });
      await transport.deleteContainer(inspect.Id, signal);
      return { status: "deleted", id: inspect.Id };
    },
    async execute(action, context) {
      const contract = ACTIONS[action];
      if (!contract?.modeled) throw brokerError(422, "action is not modeled");
      if (contract.engineAction === "runtimeSnapshot") {
        return runtimeSnapshot(context.trusted.receipt.resources.containers, transport, context.signal);
      }
      if (contract.workerCommand) {
        return executeFixedWorkerAction(action, contract, context, {
          transport,
          randomBytes,
          cleanupTimeoutMs,
        });
      }
      throw brokerError(422, "action is not modeled");
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

  inspectContainer(id, signal) {
    assertEngineId(id);
    return this.#request("GET", `/containers/${encodeURIComponent(id)}/json`, undefined, signal);
  }

  async inspectContainerForRecovery(id, signal) {
    assertEngineId(id);
    const value = await this.#request("GET", `/containers/${encodeURIComponent(id)}/json`, undefined, signal, new Set([200, 404]));
    return value?.Id ? value : null;
  }

  startContainer(id, signal) {
    assertEngineId(id);
    return this.#request("POST", `/containers/${encodeURIComponent(id)}/start`, undefined, signal, new Set([204, 304]));
  }

  waitContainer(id, signal) {
    assertEngineId(id);
    return this.#request("POST", `/containers/${encodeURIComponent(id)}/wait?condition=not-running`, undefined, signal);
  }

  logsContainer(id, signal) {
    assertEngineId(id);
    return this.#request("GET", `/containers/${encodeURIComponent(id)}/logs?stdout=1&stderr=1&tail=200`, undefined, signal, new Set([200]), false);
  }

  deleteContainer(id, signal) {
    assertEngineId(id);
    return this.#request("DELETE", `/containers/${encodeURIComponent(id)}?force=1&v=1`, undefined, signal, new Set([204, 404]));
  }

  #request(method, requestPath, body, signal, accepted = new Set([200, 201]), parseJson = true) {
    const payload = body === undefined ? null : Buffer.from(canonicalJson(body));
    return new Promise((resolve, reject) => {
      const request = http.request({
        socketPath: this.socketPath,
        method,
        path: requestPath,
        signal,
        headers: payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {},
      }, (response) => {
        const chunks = [];
        let length = 0;
        response.on("data", (chunk) => {
          length += chunk.length;
          if (length > MAX_ENGINE_RESPONSE_BYTES) {
            request.destroy(brokerError(502, "Engine response is oversized"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => {
          const bytes = Buffer.concat(chunks);
          if (!accepted.has(response.statusCode)) return reject(brokerError(502, `fixed Engine request failed (${response.statusCode})`));
          if (!parseJson || bytes.length === 0) return resolve(bytes);
          try {
            resolve(JSON.parse(bytes.toString("utf8")));
          } catch {
            reject(brokerError(502, "Engine response is malformed"));
          }
        });
      });
      request.on("error", reject);
      if (payload) request.write(payload);
      request.end();
    });
  }
}

export function loadProtectedJson(file, maximumBytes = MAX_TRUST_DOCUMENT_BYTES) {
  return JSON.parse(readProtectedFile(file, maximumBytes).toString("utf8"));
}

export function readClaimedJobSnapshot(input, { io } = {}) {
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

  const rootStat = io.lstatSync(brokerRoot, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()
    || statInteger(rootStat.uid) !== expectedUid || statInteger(rootStat.gid) !== expectedGid
    || (statInteger(rootStat.mode) & 0o777) !== 0o700) {
    throw new Error("claimed job root directory owner or private mode is unsafe");
  }

  const leaf = path.join(brokerRoot, parameters.jobFileName);
  if (path.dirname(leaf) !== brokerRoot || path.basename(leaf) !== parameters.jobFileName) {
    throw new Error("claimed job filename is not an exact leaf basename");
  }
  let descriptor;
  let bytes;
  try {
    descriptor = io.openSync(
      leaf,
      io.constants.O_RDONLY | io.constants.O_NOFOLLOW,
    );
    const before = io.fstatSync(descriptor, { bigint: true });
    const size = statInteger(before.size);
    if (!before.isFile() || before.isSymbolicLink()
      || statInteger(before.nlink) !== 1
      || statInteger(before.uid) !== expectedUid || statInteger(before.gid) !== expectedGid
      || (statInteger(before.mode) & 0o777) !== policy.expectedMode
      || size < 1 || size > policy.maximumBytes
      || !hasNanosecondTimestamps(before)) {
      throw new Error("claimed job leaf owner, private mode, link count, type or size is invalid");
    }
    const first = readClaimedJobDescriptor(io, descriptor, size);
    const second = readClaimedJobDescriptor(io, descriptor, size);
    const after = io.fstatSync(descriptor, { bigint: true });
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
    || !["queued", "running", "done", "failed"].includes(document.status)
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
      "mtimeNs",
      "ctimeNs",
      "birthtimeNs",
    ].every((field) => before[field] === after[field]);
  } catch {
    return false;
  }
}

function hasNanosecondTimestamps(stat) {
  return ["mtimeNs", "ctimeNs", "birthtimeNs"]
    .every((field) => typeof stat[field] === "bigint");
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
    activationBundleSha256: trusted.intent.activationBundleSha256,
    candidateId: trusted.receipt.candidateId,
    combinedRenderSha256: trusted.receipt.combinedRenderSha256,
    dastChainSha256: trusted.receipt.dastChainSha256,
    environment: trusted.receipt.environment,
    generation: trusted.receipt.generation,
    releaseId: trusted.receipt.releaseId,
    runtimeIntentId: trusted.intent.intentId,
    sourceRenderSha256: trusted.receipt.sourceRenderSha256,
    targetId: trusted.receipt.targetId,
  }, { now });
  return Object.freeze({ ...trusted, activation });
}

async function defaultCapabilityProvider(action, contract) {
  if (!ACTIONS[action] || ACTIONS[action] !== contract) throw brokerError(403, "capability action mismatch");
  return readProtectedFile(contract.capabilityFile);
}

export async function executeFixedWorkerAction(action, contract, context, {
  transport,
  randomBytes,
  cleanupTimeoutMs = CLEANUP_TIMEOUT_MS,
}) {
  if (action !== "backup.prune.plan" || contract.workerCommand !== "backup-prune-plan") {
    throw brokerError(422, "worker action is not modeled");
  }
  const receipt = context.trusted.receipt;
  const mount = receipt.resources.mounts["backup.root"];
  if (!mount || mount.access !== "ro" || mount.containerPath !== "/data/backups") {
    throw brokerError(403, "active receipt is missing the exact read-only backup root");
  }
  const hostPath = mount.hostPath;
  const worker = receipt.resources.workerImage;
  const name = `platform-action-prune-plan-${randomBytes(12).toString("hex")}`;
  const body = workerCreateBody({
    action,
    command: contract.workerCommand,
    imageRef: worker.imageRef,
    hostPath,
    intentId: context.trusted.intent.intentId,
    receiptDigest: context.trusted.receiptDigest,
    mountAttestation: mount,
  });
  let id = "";
  let createAttempted = false;
  context.lease.recordWorker({ resourceName: name, body, imageId: worker.imageId, hostPath });
  try {
    createAttempted = true;
    const created = await transport.createWorker(name, body, context.signal);
    id = String(created?.Id ?? "");
    assertEngineId(id);
    const inspect = await transport.inspectContainer(id, context.signal);
    assertExactWorkerInspect(inspect, { id, name, body, imageId: worker.imageId, hostPath });
    await transport.startContainer(id, context.signal);
    const waited = await transport.waitContainer(id, context.signal);
    const statusCode = Number(waited?.StatusCode);
    const logs = await transport.logsContainer(id, context.signal);
    if (statusCode !== 0) throw brokerError(500, `fixed worker failed (${Number.isInteger(statusCode) ? statusCode : "invalid"})`);
    return parseWorkerOutput(logs, contract.workerCommand);
  } finally {
    if (createAttempted) {
      try {
        await withTimeout(async (signal) => {
          if (id) {
            await transport.deleteContainer(id, signal);
            return;
          }
          const inspect = await transport.inspectContainerForRecovery(name, signal);
          if (!inspect) return;
          assertExactWorkerInspect(inspect, { id: inspect.Id, name, body, imageId: worker.imageId, hostPath });
          await transport.deleteContainer(inspect.Id, signal);
        }, cleanupTimeoutMs, "worker cleanup timed out");
      } catch (error) {
        error.preserveLease = true;
        throw error;
      }
    }
  }
}

export function workerCreateBody({ action, command, imageRef, hostPath, intentId, receiptDigest, mountAttestation }) {
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
      containerId,
      name: expected.name,
      imageRef,
      imageId,
      labels: expected.labels,
      authority,
      state,
      health,
    };
  }
  return { resources: observed };
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
  const decoded = decodeDockerLogFrames(bytes);
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

function decodeDockerLogFrames(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value ?? "");
  const stdout = [];
  const stderr = [];
  let offset = 0;
  while (offset < bytes.length) {
    if (bytes.length - offset < 8) throw brokerError(502, "worker log frame is truncated");
    const stream = bytes[offset];
    if (![1, 2].includes(stream) || bytes[offset + 1] !== 0 || bytes[offset + 2] !== 0 || bytes[offset + 3] !== 0) {
      throw brokerError(502, "worker log frame header is invalid");
    }
    const length = bytes.readUInt32BE(offset + 4);
    offset += 8;
    if (length > 64 * 1024 || offset + length > bytes.length) throw brokerError(502, "worker log frame length is invalid");
    (stream === 1 ? stdout : stderr).push(bytes.subarray(offset, offset + length));
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

function serveConnection(connection, core) {
  let chunks = [];
  let length = 0;
  let complete = false;
  connection.setTimeout(5000, () => connection.destroy());
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
    if (newline !== frame.length - 1) return respond(connection, 400, "exactly one request frame is required");
    try {
      const response = await core.handle(frame.subarray(0, newline));
      writeResponse(connection, response.statusCode, response.body);
    } catch (error) {
      respond(connection, Number(error?.statusCode) || 500, String(error?.message ?? "request failed"));
    } finally {
      chunks = [];
    }
  });
  connection.on("error", () => {});
}

function respond(connection, statusCode, message) {
  writeResponse(connection, statusCode, {
    schema: "platform.docker-action.response/v1",
    status: "rejected",
    error: message,
  });
}

function writeResponse(connection, statusCode, body) {
  connection.end(encodeActionResponseFrame({ statusCode, ...body }));
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
