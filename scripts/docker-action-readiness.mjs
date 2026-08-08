#!/usr/bin/env node
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  ACTIVE_RECEIPT_SCHEMA,
  RUNTIME_INTENT_SCHEMA,
  canonicalJson,
  normalizeTrustedContext,
} from "./docker-action-contract.mjs";
import {
  normalizeActivationPolicy,
  verifyActivationEnvelope,
} from "./docker-action-activation.mjs";
import {
  loadProtectedJson,
  readProtectedFile,
} from "./docker-action-broker.mjs";

const DEFAULT_SOCKET_PATH = "/run/platform/docker-action-broker/broker.sock";
const DEFAULT_INTENT_FILE = "/run/platform/docker-action-trust/runtime-intent.json";
const DEFAULT_RECEIPT_FILE = "/run/platform/docker-action-trust/active-receipt.json";
const DEFAULT_TRUST_KEY_FILE = "/run/secrets/docker_action_runtime_intent_trust_key";
const DEFAULT_ACTIVATION_POLICY_FILE = "/opt/platform-docker-broker/docker-action-activation-policy.json";
const DEFAULT_ACTIVATION_CAS_ROOT = "/run/platform/docker-action-activation/by-bundle-sha256";
const MAX_TRUST_DOCUMENT_BYTES = 2 * 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/;
const LOGICAL_ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const BROKER_PROBE_RESPONSE = Object.freeze({
  error: "action grammar is invalid",
  schema: "platform.docker-action.response/v1",
  status: "rejected",
  statusCode: 403,
});
const BROKER_PROBE_RESPONSE_FRAME = Buffer.from(`${canonicalJson(BROKER_PROBE_RESPONSE)}\n`);
const MAX_PROBE_RESPONSE_BYTES = 1024;

export function evaluateBrokerReadiness(input) {
  const failures = [];
  const source = plainRecord(input) ? input : {};
  const socket = plainRecord(source.socket) ? source.socket : {};
  const runtimeIntent = plainRecord(source.runtimeIntent) ? source.runtimeIntent : {};
  const runtimeIntentDocument = plainRecord(runtimeIntent.document) ? runtimeIntent.document : {};
  const activeReceipt = plainRecord(source.activeReceipt) ? source.activeReceipt : {};
  const activeReceiptDocument = plainRecord(activeReceipt.document) ? activeReceipt.document : {};
  const activation = plainRecord(source.activation) ? source.activation : {};
  const expected = plainRecord(source.expected) ? source.expected : {};

  requireInvariant(failures, socket.exists === true, "broker socket is missing");
  requireInvariant(failures, socket.isSocket === true, "broker socket path is not a Unix socket");
  requireInvariant(failures, socket.ownerUid === 0 && socket.ownerGid === 0, "broker socket is not root-owned");

  requireInvariant(failures, LOGICAL_ID.test(String(expected.intentId ?? "")), "expected runtime intent identity is invalid");
  requireInvariant(failures, SHA256.test(String(expected.activeReceiptSha256 ?? "")), "expected active receipt digest is invalid");
  requireInvariant(failures, SHA256.test(String(expected.combinedRenderSha256 ?? "")), "expected combined render digest is invalid");

  requireInvariant(failures, runtimeIntent.trusted === true, "runtime intent was not authenticated");
  requireInvariant(failures, runtimeIntentDocument.schema === RUNTIME_INTENT_SCHEMA, "runtime intent schema is invalid");
  requireInvariant(failures, runtimeIntentDocument.intentId === expected.intentId, "runtime intent identity does not match readiness expectation");
  requireInvariant(
    failures,
    runtimeIntentDocument.combinedRenderSha256 === expected.combinedRenderSha256,
    "runtime intent render digest does not match readiness expectation",
  );

  requireInvariant(failures, activeReceipt.trusted === true, "active receipt was not authenticated");
  requireInvariant(failures, activeReceiptDocument.schema === ACTIVE_RECEIPT_SCHEMA, "active receipt schema is invalid");
  requireInvariant(failures, activeReceipt.sha256 === expected.activeReceiptSha256, "active receipt digest does not match readiness expectation");
  requireInvariant(failures, activeReceiptDocument.intentId === expected.intentId, "active receipt is not bound to the runtime intent");
  requireInvariant(
    failures,
    activeReceiptDocument.combinedRenderSha256 === expected.combinedRenderSha256,
    "active receipt render digest does not match readiness expectation",
  );

  requireInvariant(failures, activation.trusted === true, "provider activation was not authenticated");
  requireInvariant(failures, activation.status === "active", "provider activation is not active");
  requireInvariant(failures, activation.intentId === expected.intentId, "provider activation is not bound to the runtime intent");
  requireInvariant(
    failures,
    activation.activeReceiptSha256 === expected.activeReceiptSha256,
    "provider activation is not bound to the active receipt",
  );
  requireInvariant(
    failures,
    activation.combinedRenderSha256 === expected.combinedRenderSha256,
    "provider activation render digest does not match readiness expectation",
  );

  return { ready: failures.length === 0, failures };
}

export function buildProductionReadinessInput({ environment = process.env, now = Date.now() } = {}) {
  const intentFile = environment.DOCKER_ACTION_RUNTIME_INTENT_FILE || DEFAULT_INTENT_FILE;
  const receiptFile = environment.DOCKER_ACTION_ACTIVE_RECEIPT_FILE || DEFAULT_RECEIPT_FILE;
  const trustKeyFile = environment.DOCKER_ACTION_RUNTIME_INTENT_TRUST_KEY_FILE || DEFAULT_TRUST_KEY_FILE;
  const activationPolicyFile = DEFAULT_ACTIVATION_POLICY_FILE;
  const activationCasRoot = DEFAULT_ACTIVATION_CAS_ROOT;
  const intent = loadProtectedJson(intentFile);
  const receipt = loadProtectedJson(receiptFile);
  const trustKey = readProtectedFile(trustKeyFile);
  const trusted = normalizeTrustedContext(intent, receipt, trustKey, { now });
  const activationPolicy = normalizeActivationPolicy(loadProtectedJson(activationPolicyFile, 64 * 1024));
  const activationFile = path.join(activationCasRoot, `${trusted.intent.activationBundleSha256}.dsse.json`);
  const activationBytes = readProtectedFile(activationFile, MAX_TRUST_DOCUMENT_BYTES, {
    parentRoot: activationCasRoot,
  });
  const verifiedActivation = verifyActivationEnvelope(activationBytes, activationPolicy, {
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

  return readinessInput({
    socket: observeSocket(environment.DOCKER_ACTION_BROKER_SOCKET || DEFAULT_SOCKET_PATH),
    trusted,
    verifiedActivation,
  });
}

export function probeBrokerProtocol(socketPath, { timeoutMs = 1500 } = {}) {
  if (typeof socketPath !== "string" || !path.isAbsolute(socketPath) || socketPath.includes("\0")
    || path.resolve(socketPath) !== socketPath || path.normalize(socketPath) !== socketPath) {
    throw new TypeError("broker readiness socket path is invalid");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 4000) {
    throw new TypeError("broker readiness timeout is invalid");
  }
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath });
    const chunks = [];
    let length = 0;
    let settled = false;
    const timer = setTimeout(() => {
      finish(new Error("broker readiness protocol deadline elapsed"));
    }, timeoutMs);
    const finish = (error = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve(Object.freeze({ connected: true, protocol: "platform.docker-action.response/v1" }));
    };

    socket.once("connect", () => {
      try {
        socket.end(Buffer.from("{}\n"));
      } catch (error) {
        finish(error);
      }
    });
    socket.on("data", (chunk) => {
      if (settled) return;
      length += chunk.length;
      if (length > MAX_PROBE_RESPONSE_BYTES) {
        finish(new Error("broker readiness response is oversized"));
        return;
      }
      chunks.push(chunk);
    });
    socket.once("end", () => {
      if (settled) return;
      const frame = Buffer.concat(chunks, length);
      if (!frame.equals(BROKER_PROBE_RESPONSE_FRAME)) {
        finish(new Error("broker readiness protocol response is invalid"));
        return;
      }
      finish();
    });
    socket.once("error", finish);
    socket.once("close", () => {
      if (!settled) finish(new Error("broker readiness connection closed without a protocol response"));
    });
  });
}

function readinessInput({ socket, trusted, verifiedActivation }) {
  const expected = Object.freeze({
    intentId: trusted.intent.intentId,
    activeReceiptSha256: trusted.receiptDigest,
    combinedRenderSha256: trusted.receipt.combinedRenderSha256,
  });
  return {
    socket,
    runtimeIntent: {
      trusted: true,
      document: {
        schema: trusted.intent.schema,
        intentId: trusted.intent.intentId,
        combinedRenderSha256: trusted.intent.combinedRenderSha256,
      },
    },
    activeReceipt: {
      trusted: true,
      sha256: trusted.receiptDigest,
      document: {
        schema: trusted.receipt.schema,
        intentId: trusted.intent.intentId,
        combinedRenderSha256: trusted.receipt.combinedRenderSha256,
      },
    },
    activation: {
      trusted: true,
      status: "active",
      intentId: verifiedActivation.runtimeIntentId,
      activeReceiptSha256: trusted.receiptDigest,
      combinedRenderSha256: verifiedActivation.combinedRenderSha256,
    },
    expected,
  };
}

function fixtureReadinessInput(file, socketPath) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 2
    || stat.size > MAX_TRUST_DOCUMENT_BYTES || (stat.mode & 0o077) !== 0) {
    throw new Error("readiness fixture ownership, links, permissions or size are invalid");
  }
  const source = JSON.parse(fs.readFileSync(file, "utf8"));
  const reportedSocket = plainRecord(source?.socket) ? source.socket : {};
  return {
    ...source,
    socket: observeSocket(socketPath, {
      ownerUid: reportedSocket.ownerUid,
      ownerGid: reportedSocket.ownerGid,
    }),
  };
}

function observeSocket(socketPath, reportedOwner = null) {
  try {
    const stat = fs.lstatSync(socketPath);
    return {
      exists: true,
      isSocket: stat.isSocket() && !stat.isSymbolicLink(),
      ownerUid: reportedOwner ? reportedOwner.ownerUid : stat.uid,
      ownerGid: reportedOwner ? reportedOwner.ownerGid : stat.gid,
    };
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    return {
      exists: false,
      isSocket: false,
      ownerUid: reportedOwner ? reportedOwner.ownerUid : -1,
      ownerGid: reportedOwner ? reportedOwner.ownerGid : -1,
    };
  }
}

function requireInvariant(failures, condition, message) {
  if (!condition) failures.push(message);
}

function plainRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

async function main() {
  if (process.argv.length !== 3 || process.argv[2] !== "--require-trusted-activation") {
    throw new Error("Usage: docker-action-readiness.mjs --require-trusted-activation");
  }
  const socketPath = process.env.DOCKER_ACTION_BROKER_SOCKET || DEFAULT_SOCKET_PATH;
  const fixtureFile = process.env.DOCKER_ACTION_READINESS_INPUT_FILE;
  if (fixtureFile && (process.env.NODE_ENV !== "test"
    || process.env.DOCKER_ACTION_READINESS_TEST_ONLY !== "1")) {
    throw new Error("readiness fixture input is test-only");
  }
  const input = fixtureFile
    ? fixtureReadinessInput(fixtureFile, socketPath)
    : buildProductionReadinessInput();
  const result = evaluateBrokerReadiness(input);
  if (!result.ready) throw new Error(`Docker action broker is not ready: ${result.failures.join("; ")}`);
  await probeBrokerProtocol(socketPath);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error?.message || error}\n`);
    process.exitCode = 1;
  });
}
