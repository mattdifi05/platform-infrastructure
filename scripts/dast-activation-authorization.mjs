#!/usr/bin/env node
import crypto from "node:crypto";

import { canonicalConsumerChallenge } from "./deployment-receipt-policy.mjs";
import { exactGitSha, exactRepository } from "./release-artifact-policy.mjs";
import { canonicalJson } from "./runtime-intent-policy.mjs";

export const DAST_ACTIVATION_AUTHORIZATION_SCHEMA = "platform-dast-activation-authorization/v1";
export const DAST_ACTIVATION_CHAIN_SCHEMA = "platform.docker-dast-chain/v2";

const AUTHORIZATION_FIELDS = [
  "chain",
  "chainSha256",
  "consumerChallenge",
  "generatedAt",
  "schema",
  "status",
];

const CHAIN_FIELDS = [
  "commitSha",
  "consumerChallengeSha256",
  "providerMetadataSha256",
  "providerReceiptSha256",
  "providerRunAttempt",
  "providerRunId",
  "reportArtifactArchiveSha256",
  "reportArtifactId",
  "reportEvidenceSha256",
  "repository",
  "runtimeIntentSha256",
  "runtimeInventorySha256",
  "scanRequestSha256",
  "schema",
  "sigstoreBundleSha256",
  "sigstoreSubject",
  "target",
  "targetServingInventoryHash",
  "treeSha",
  "verdict",
];

const EXPECTED_FIELDS = [
  "commitSha",
  "consumerChallenge",
  "providerMetadataSha256",
  "providerReceiptSha256",
  "providerRunAttempt",
  "providerRunId",
  "reportArtifactArchiveSha256",
  "reportArtifactId",
  "reportEvidenceSha256",
  "repository",
  "runtimeIntentSha256",
  "runtimeInventorySha256",
  "scanRequestSha256",
  "sigstoreBundleSha256",
  "sigstoreSubject",
  "target",
  "targetServingInventoryHash",
  "treeSha",
];

function invalid(message) {
  throw new Error(message);
}

function exactObject(value, label, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    invalid(`${label} must be one object.`);
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    invalid(`${label} does not use the exact closed schema.`);
  }
  return value;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    invalid(`${label} must be one exact lowercase SHA256.`);
  }
  return value;
}

function canonicalGitSha(value, label) {
  const canonical = exactGitSha(value, label);
  if (typeof value !== "string" || value !== canonical) {
    invalid(`${label} must be one canonical lowercase full Git SHA.`);
  }
  return canonical;
}

function canonicalRepository(value, label = "repository") {
  const canonical = exactRepository(value);
  if (typeof value !== "string" || value !== canonical) {
    invalid(`${label} must use exact owner/name syntax without normalization.`);
  }
  return canonical;
}

function canonicalTarget(value, label) {
  if (typeof value !== "string" || !value || /[\0\r\n]/.test(value)) {
    invalid(`${label} must be one exact HTTPS origin.`);
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    invalid(`${label} must be one valid HTTPS origin.`);
  }
  if (
    parsed.protocol !== "https:"
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
    || parsed.pathname !== "/"
    || value !== parsed.origin
  ) {
    invalid(`${label} must be one canonical HTTPS origin without credentials, path, query, fragment, or trailing slash.`);
  }
  return value;
}

function canonicalDecimalId(value, label) {
  if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) {
    invalid(`${label} must be one canonical positive numeric identifier string.`);
  }
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1 || String(number) !== value) {
    invalid(`${label} must remain within the exact safe integer identity range.`);
  }
  return value;
}

function expectedDecimalId(value, label) {
  return canonicalDecimalId(String(value ?? ""), label);
}

function canonicalPositiveInteger(value, label) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    invalid(`${label} must be one positive safe integer.`);
  }
  return value;
}

function expectedPositiveInteger(value, label) {
  const number = typeof value === "number" ? value : Number(String(value ?? ""));
  if (!Number.isSafeInteger(number) || number < 1 || String(number) !== String(value)) {
    invalid(`${label} must be one canonical positive safe integer.`);
  }
  return number;
}

function canonicalTimestamp(value, label) {
  if (typeof value !== "string" || !value) invalid(`${label} must be one canonical UTC timestamp.`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    invalid(`${label} must be one canonical UTC timestamp.`);
  }
  return value;
}

function exactSigstoreSubject(value, label) {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > 512
    || value !== value.trim()
    || /[\0\r\n]/.test(value)
  ) {
    invalid(`${label} must be one exact bounded Sigstore subject.`);
  }
  return value;
}

function exactCanonicalChallenge(value, label) {
  let challenge;
  try {
    challenge = canonicalConsumerChallenge(value);
  } catch (error) {
    invalid(`${label} is invalid: ${String(error?.message ?? error)}`);
  }
  if (canonicalJson(value) !== canonicalJson(challenge)) {
    invalid(`${label} must already use its exact canonical field types and values.`);
  }
  return challenge;
}

function sha256Canonical(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function dastActivationChainSha256(chain) {
  return sha256Canonical(chain);
}

export function validateDastActivationAuthorization(authorization, expected) {
  exactObject(authorization, "DAST activation authorization", AUTHORIZATION_FIELDS);
  exactObject(expected, "Expected DAST activation bindings", EXPECTED_FIELDS);
  if (
    authorization.schema !== DAST_ACTIVATION_AUTHORIZATION_SCHEMA
    || authorization.status !== "READY"
  ) {
    invalid("DAST activation authorization schema/status is invalid.");
  }

  const challenge = exactCanonicalChallenge(
    authorization.consumerChallenge,
    "DAST activation consumer challenge",
  );
  const expectedChallenge = exactCanonicalChallenge(
    expected.consumerChallenge,
    "Expected DAST activation consumer challenge",
  );
  if (canonicalJson(challenge) !== canonicalJson(expectedChallenge)) {
    invalid("DAST activation authorization does not bind the exact trusted consumer challenge.");
  }

  const chain = exactObject(authorization.chain, "DAST activation chain", CHAIN_FIELDS);
  if (chain.schema !== DAST_ACTIVATION_CHAIN_SCHEMA || chain.verdict !== "pass") {
    invalid("DAST activation chain schema/verdict is invalid.");
  }

  const canonical = {
    repository: canonicalRepository(chain.repository, "DAST activation repository"),
    commitSha: canonicalGitSha(chain.commitSha, "DAST activation commit SHA"),
    treeSha: canonicalGitSha(chain.treeSha, "DAST activation tree SHA"),
    target: canonicalTarget(chain.target, "DAST activation target"),
    runtimeIntentSha256: exactSha256(chain.runtimeIntentSha256, "DAST runtime intent SHA256"),
    runtimeInventorySha256: exactSha256(chain.runtimeInventorySha256, "DAST runtime inventory SHA256"),
    targetServingInventoryHash: exactSha256(
      chain.targetServingInventoryHash,
      "DAST target-serving inventory hash",
    ),
    consumerChallengeSha256: exactSha256(
      chain.consumerChallengeSha256,
      "DAST consumer challenge SHA256",
    ),
    scanRequestSha256: exactSha256(chain.scanRequestSha256, "DAST scan request SHA256"),
    providerReceiptSha256: exactSha256(chain.providerReceiptSha256, "DAST provider receipt SHA256"),
    providerMetadataSha256: exactSha256(
      chain.providerMetadataSha256,
      "DAST provider metadata SHA256",
    ),
    providerRunId: canonicalDecimalId(chain.providerRunId, "DAST provider run ID"),
    providerRunAttempt: canonicalPositiveInteger(
      chain.providerRunAttempt,
      "DAST provider run attempt",
    ),
    reportArtifactId: canonicalDecimalId(chain.reportArtifactId, "DAST report artifact ID"),
    reportArtifactArchiveSha256: exactSha256(
      chain.reportArtifactArchiveSha256,
      "DAST report artifact archive SHA256",
    ),
    reportEvidenceSha256: exactSha256(chain.reportEvidenceSha256, "DAST report evidence SHA256"),
    sigstoreBundleSha256: exactSha256(
      chain.sigstoreBundleSha256,
      "DAST Sigstore bundle SHA256",
    ),
    sigstoreSubject: exactSigstoreSubject(chain.sigstoreSubject, "DAST Sigstore subject"),
  };

  const trusted = {
    repository: canonicalRepository(expected.repository, "Expected DAST repository"),
    commitSha: canonicalGitSha(expected.commitSha, "Expected DAST commit SHA"),
    treeSha: canonicalGitSha(expected.treeSha, "Expected DAST tree SHA"),
    target: canonicalTarget(expected.target, "Expected DAST target"),
    runtimeIntentSha256: exactSha256(expected.runtimeIntentSha256, "Expected runtime intent SHA256"),
    runtimeInventorySha256: exactSha256(
      expected.runtimeInventorySha256,
      "Expected runtime inventory SHA256",
    ),
    targetServingInventoryHash: exactSha256(
      expected.targetServingInventoryHash,
      "Expected target-serving inventory hash",
    ),
    consumerChallengeSha256: sha256Canonical(expectedChallenge),
    scanRequestSha256: exactSha256(expected.scanRequestSha256, "Expected DAST scan request SHA256"),
    providerReceiptSha256: exactSha256(
      expected.providerReceiptSha256,
      "Expected DAST provider receipt SHA256",
    ),
    providerMetadataSha256: exactSha256(
      expected.providerMetadataSha256,
      "Expected DAST provider metadata SHA256",
    ),
    providerRunId: expectedDecimalId(expected.providerRunId, "Expected DAST provider run ID"),
    providerRunAttempt: expectedPositiveInteger(
      expected.providerRunAttempt,
      "Expected DAST provider run attempt",
    ),
    reportArtifactId: expectedDecimalId(expected.reportArtifactId, "Expected DAST report artifact ID"),
    reportArtifactArchiveSha256: exactSha256(
      expected.reportArtifactArchiveSha256,
      "Expected DAST report artifact archive SHA256",
    ),
    reportEvidenceSha256: exactSha256(
      expected.reportEvidenceSha256,
      "Expected DAST report evidence SHA256",
    ),
    sigstoreBundleSha256: exactSha256(
      expected.sigstoreBundleSha256,
      "Expected DAST Sigstore bundle SHA256",
    ),
    sigstoreSubject: exactSigstoreSubject(expected.sigstoreSubject, "Expected DAST Sigstore subject"),
  };

  if (canonical.consumerChallengeSha256 !== trusted.consumerChallengeSha256) {
    invalid("DAST activation chain consumer challenge digest is not bound to the exact canonical challenge.");
  }
  for (const [field, value] of Object.entries(trusted)) {
    if (field === "consumerChallengeSha256") continue;
    if (canonical[field] !== value) {
      invalid(`DAST activation chain ${field} is not bound to the exact trusted evidence.`);
    }
  }

  const expectedChainSha256 = sha256Canonical(chain);
  if (
    exactSha256(authorization.chainSha256, "DAST activation chain SHA256")
      !== expectedChainSha256
  ) {
    invalid("DAST activation authorization does not bind the exact canonical chain bytes.");
  }
  canonicalTimestamp(authorization.generatedAt, "DAST activation authorization generatedAt");
  return authorization;
}
