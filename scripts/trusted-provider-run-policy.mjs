#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { snapshotJsonArtifact } from "./stable-json-artifact.mjs";

function invalid(message) { throw new Error(message); }

function exactRepository(value, label = "trusted producer repository") {
  const text = String(value ?? "");
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(text)) invalid(`${label} is invalid.`);
  return text;
}

function exactWorkflowPath(value) {
  const text = String(value ?? "");
  if (!/^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/.test(text)) invalid("trusted producer workflow path is invalid.");
  return text;
}

function exactSourceRef(value) {
  const text = String(value ?? "");
  if (text !== "refs/heads/main") {
    invalid("trusted producer source ref must be exact main.");
  }
  return text;
}

function exactRunId(value) {
  const text = String(value ?? "");
  if (!/^[1-9][0-9]*$/.test(text)) invalid("trusted producer run ID is invalid.");
  return text;
}

function exactRunAttempt(value) {
  const text = String(value ?? "");
  if (!/^[1-9][0-9]*$/.test(text)) invalid("trusted producer run attempt is invalid.");
  return Number(text);
}

function exactGitSha(value, label = "trusted producer workflow SHA") {
  const text = String(value ?? "");
  if (!/^[a-f0-9]{40}$/.test(text)) invalid(`${label} is invalid.`);
  return text;
}

export function trustedProducerConfiguration(policy) {
  if (
    policy?.status !== "READY"
    || typeof policy?.trustedVerifierChannel !== "string"
    || !policy.trustedVerifierChannel
    || policy.selfAssertedAnnotationsAccepted !== false
  ) {
    invalid(`EXTERNAL-PENDING: ${policy?.reason ?? "trusted deployment verifier channel is not configured"}`);
  }
  const producer = policy.trustedProducer;
  try {
    return {
      repository: exactRepository(producer?.repository),
      workflowPath: exactWorkflowPath(producer?.workflowPath),
      workflowSha: exactGitSha(producer?.workflowSha),
      sourceRef: exactSourceRef(producer?.sourceRef),
      event: String(producer?.event ?? "") === "workflow_dispatch" ? "workflow_dispatch" : invalid("trusted producer event must be workflow_dispatch."),
    };
  } catch (error) {
    invalid(`EXTERNAL-PENDING: ${String(error?.message ?? error)}`);
  }
}

export function validateTrustedProviderRun(run, { policy, runId, runAttempt, deploymentReceipt = null } = {}) {
  const configured = trustedProducerConfiguration(policy);
  const expectedRunId = exactRunId(runId);
  const expectedRunAttempt = exactRunAttempt(runAttempt);
  const workflowSha = exactGitSha(run?.head_sha);
  const actualRef = `refs/heads/${String(run?.head_branch ?? "")}`;
  if (
    exactRunId(run?.id) !== expectedRunId
    || exactRunAttempt(run?.run_attempt) !== expectedRunAttempt
    || run?.repository?.full_name !== configured.repository
    || run?.head_repository?.full_name !== configured.repository
    || run?.path !== configured.workflowPath
    || workflowSha !== configured.workflowSha
    || actualRef !== configured.sourceRef
    || run?.event !== configured.event
    || run?.status !== "completed"
    || run?.conclusion !== "success"
  ) {
    invalid("Trusted provider run metadata does not match the configured successful workflow/repository/ref/run identity.");
  }
  const producer = {
    repository: configured.repository,
    workflowPath: configured.workflowPath,
    sourceRef: configured.sourceRef,
    event: configured.event,
    runId: expectedRunId,
    runAttempt: expectedRunAttempt,
    workflowSha: configured.workflowSha,
  };
  if (deploymentReceipt !== null) {
    const candidate = deploymentReceipt?.producer;
    const exactKeys = ["event", "repository", "runAttempt", "runId", "sourceRef", "workflowPath", "workflowSha"];
    if (
      !candidate
      || JSON.stringify(Object.keys(candidate).sort()) !== JSON.stringify(exactKeys)
      || exactKeys.some((key) => candidate[key] !== producer[key])
    ) {
      invalid("Trusted deployment receipt does not bind the authenticated provider run identity.");
    }
  }
  return producer;
}

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--")) invalid(`Invalid or missing value for ${key ?? "argument"}.`);
    result[key.slice(2)] = value;
  }
  return result;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const snapshots = [];
  try {
    const policy = snapshotJsonArtifact(options.policy, { label: "deployment admission policy", maxBytes: 1024 * 1024 });
    snapshots.push(policy);
    if (!options.metadata) {
      process.stdout.write(`${JSON.stringify(trustedProducerConfiguration(policy.document))}\n`);
      return;
    }
    const metadata = snapshotJsonArtifact(options.metadata, { label: "trusted provider run metadata", maxBytes: 4 * 1024 * 1024 });
    snapshots.push(metadata);
    if (options.metadataSha256 && metadata.sha256 !== options.metadataSha256) invalid("Trusted provider run metadata SHA256 mismatch.");
    let deploymentReceipt = null;
    if (options.deploymentReceipt) {
      const receipt = snapshotJsonArtifact(options.deploymentReceipt, { label: "trusted deployment receipt", maxBytes: 16 * 1024 * 1024 });
      snapshots.push(receipt);
      deploymentReceipt = receipt.document;
    }
    const producer = validateTrustedProviderRun(metadata.document, {
      policy: policy.document,
      runId: options.runId,
      runAttempt: options.runAttempt,
      deploymentReceipt,
    });
    process.stdout.write(`${JSON.stringify({ status: "READY", producer, metadataSha256: metadata.sha256 })}\n`);
  } finally {
    for (const snapshot of snapshots.reverse()) snapshot.cleanup();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
