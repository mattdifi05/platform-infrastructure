#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { ACTIVATION_BUNDLE_ENTRY_LIMITS } from "./activation-bundle.mjs";
import { projectProviderRunMetadata, validateActivationPromotion } from "./activation-promotion-policy.mjs";
import { canonicalJson } from "./runtime-intent-policy.mjs";

const sha = (character) => character.repeat(64);
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const jsonArtifact = (document, sourcePath) => {
  const bytes = Buffer.from(`${canonicalJson(document)}\n`);
  return {
    document,
    sourcePath,
    snapshotPath: `/snapshots${sourcePath}`,
    sha256: hash(bytes),
    sizeBytes: bytes.length,
  };
};
const fileArtifact = (bytes, sourcePath) => ({
  bytes: Buffer.from(bytes),
  sourcePath,
  snapshotPath: `/snapshots${sourcePath}`,
  sha256: hash(bytes),
  sizeBytes: bytes.length,
});

const repository = "owner/repo";
const runtimeIntentSha256 = sha("b");
const releaseContextSha256 = sha("c");
const deploymentReceiptSha256 = sha("d");
const requestId = `activation:${deploymentReceiptSha256}:${releaseContextSha256}`;
const consumerChallenge = {
  consumerRepository: repository,
  consumerRunId: "123456",
  consumerRunAttempt: 2,
  consumerJob: "deploy-vps",
  challengeNonce: sha("f"),
};
const dastProvider = {
  repository: "owner/dast-provider",
  workflowPath: ".github/workflows/dast-provider.yml",
  workflowSha: "d".repeat(40),
  sourceRef: "refs/heads/main",
  event: "workflow_dispatch",
  runId: "456789",
  runAttempt: 4,
  job: "dast-countersign",
};
const dastSigstoreSubject = `https://github.com/${dastProvider.repository}/${dastProvider.workflowPath}@${dastProvider.sourceRef}`;
const dastProviderMetadata = jsonArtifact({
  id: Number(dastProvider.runId),
  run_attempt: dastProvider.runAttempt,
  repository: { full_name: dastProvider.repository },
  head_repository: { full_name: dastProvider.repository },
  path: dastProvider.workflowPath,
  head_branch: "main",
  head_sha: dastProvider.workflowSha,
  event: dastProvider.event,
  status: "completed",
  conclusion: "success",
}, "/fixtures/dast-provider-run.json");
const dastProviderAttestationBundle = fileArtifact(
  Buffer.from("provider DAST sigstore bundle\n"),
  "/fixtures/dast-provider-attestation.bundle.jsonl",
);
const semanticVerdict = {
  policy: "zap-baseline-no-risk-alerts/v1",
  status: "passed",
  siteCount: 1,
  alertCount: 0,
  highestRiskCode: 0,
};
const validatedReportEvidence = {
  artifactName: "dast-scan-request-123456-2-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  engineImage: `ghcr.io/zaproxy/zap-stable@sha256:${sha("6")}`,
  files: {
    json: { path: "zap-baseline.json", sha256: sha("8"), bytes: 100 },
    html: { path: "zap-baseline.html", sha256: sha("7"), bytes: 100 },
    xml: { path: "zap-baseline.xml", sha256: sha("9"), bytes: 100 },
  },
  semanticVerdict,
};
const dastProviderReceipt = jsonArtifact({
  version: 1,
  kind: "platform-dast-verification/v1",
  status: "passed",
  scanRequestSha256: sha("1"),
  repository,
  commitSha: "b".repeat(40),
  treeSha: "c".repeat(40),
  target: "https://staging.example.com",
  consumerChallenge,
  runtimeIntentSha256,
  runtimeInventorySha256: sha("2"),
  targetServingInventoryHash: sha("3"),
  targetServingServices: ["control-center", "project-router", "traefik"],
  reportArtifact: {
    id: "987654",
    name: "dast-scan-request-123456-2-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    archiveSha256: sha("4"),
    repository,
    runId: "123456",
    runAttempt: 2,
  },
  reportEvidenceSha256: hash(Buffer.from(JSON.stringify(validatedReportEvidence))),
  validatedReportEvidence,
  providerValidation: {
    independent: true,
    parser: "platform-provider-zap-report-set/v1",
    status: "passed",
  },
  semanticVerdict,
  candidateProducer: {
    repository,
    workflowPath: ".github/workflows/enterprise-infra.yml",
    workflowSha: "b".repeat(40),
    sourceRef: "refs/heads/main",
    event: "workflow_dispatch",
    runId: "123456",
    runAttempt: 2,
    job: "dast-zap",
  },
  provider: dastProvider,
  generatedAt: "2026-08-01T12:00:00.000Z",
}, "/fixtures/dast-provider-verification.json");

function authorizationArtifact(mutator = null) {
  const chain = {
    schema: "platform.docker-dast-chain/v2",
    repository,
    commitSha: dastProviderReceipt.document.commitSha,
    treeSha: dastProviderReceipt.document.treeSha,
    target: dastProviderReceipt.document.target,
    runtimeIntentSha256,
    runtimeInventorySha256: dastProviderReceipt.document.runtimeInventorySha256,
    targetServingInventoryHash: dastProviderReceipt.document.targetServingInventoryHash,
    consumerChallengeSha256: hash(Buffer.from(canonicalJson(consumerChallenge))),
    scanRequestSha256: dastProviderReceipt.document.scanRequestSha256,
    providerReceiptSha256: dastProviderReceipt.sha256,
    providerMetadataSha256: dastProviderMetadata.sha256,
    providerRunId: dastProvider.runId,
    providerRunAttempt: dastProvider.runAttempt,
    reportArtifactId: dastProviderReceipt.document.reportArtifact.id,
    reportArtifactArchiveSha256: dastProviderReceipt.document.reportArtifact.archiveSha256,
    reportEvidenceSha256: dastProviderReceipt.document.reportEvidenceSha256,
    sigstoreBundleSha256: dastProviderAttestationBundle.sha256,
    sigstoreSubject: dastSigstoreSubject,
    verdict: "pass",
  };
  const document = {
    schema: "platform-dast-activation-authorization/v1",
    status: "READY",
    consumerChallenge,
    chain,
    chainSha256: hash(Buffer.from(canonicalJson(chain))),
    generatedAt: "2026-08-01T12:10:00.000Z",
  };
  if (mutator) mutator(document);
  return jsonArtifact(document, "/fixtures/dast-activation-authorization.json");
}

const dastAuthorization = authorizationArtifact();
const trustedRoot = fileArtifact(Buffer.from("trusted root\n"), "/fixtures/trusted-root.json");
const policy = jsonArtifact({
  version: 1,
  status: "READY",
  requiredReceiptKind: "platform-activation-promotion/v2",
  selfAssertedAnnotationsAccepted: false,
  trustedRootSha256: trustedRoot.sha256,
  trustedProducer: {
    repository: "owner/activation-promoter",
    workflowPath: ".github/workflows/promote.yml",
    workflowSha: "a".repeat(40),
    sourceRef: "refs/heads/main",
    event: "workflow_dispatch",
    artifactName: "platform-promoted-activation",
  },
  reason: null,
}, "/fixtures/policy.json");
const providerMetadata = jsonArtifact({
  id: 789012,
  run_attempt: 3,
  repository: { full_name: "owner/activation-promoter" },
  head_repository: { full_name: "owner/activation-promoter" },
  path: ".github/workflows/promote.yml",
  head_branch: "main",
  head_sha: "a".repeat(40),
  event: "workflow_dispatch",
  status: "completed",
  conclusion: "success",
  html_url: "https://github.example/owner/activation-promoter/actions/runs/789012",
}, "/fixtures/promoter.json");
const releaseBundle = fileArtifact(Buffer.from("promoted release activation bundle\n"), "/fixtures/release-activation.bundle");

function manifestArtifact(mutator = null) {
  const document = {
    schema: "platform-activation-bundle-manifest/v2",
    requestId,
    releaseContextSha256,
    runtimeIntentSha256,
    entries: Object.keys(ACTIVATION_BUNDLE_ENTRY_LIMITS).sort().map((name, index) => ({
      name,
      sha256: name === "dast-activation-authorization.json"
        ? dastAuthorization.sha256
        : name === "dast-provider-verification.json"
          ? dastProviderReceipt.sha256
          : name === "trusted-deployment-admission.json"
            ? deploymentReceiptSha256
          : String((index % 9) + 1).repeat(64),
      sizeBytes: 1,
    })),
  };
  if (mutator) mutator(document);
  return jsonArtifact(document, "/fixtures/release-activation-bundle-manifest.json");
}

const releaseBundleManifest = manifestArtifact();
const releaseBundleManifestSha256 = hash(Buffer.from(canonicalJson(releaseBundleManifest.document)));

function envelopeArtifact(mutator = null) {
  const payload = {
    schema: "platform.docker-runtime-activation/v2",
    activationId: "activation.1",
    candidateId: "candidate.v1",
    combinedRenderSha256: sha("a"),
    dast: dastAuthorization.document.chain,
    dastAuthorizationSha256: dastAuthorization.sha256,
    environment: "production",
    expiresAt: "2026-08-01T12:25:00.000Z",
    generation: 7,
    issuedAt: "2026-08-01T12:15:00.000Z",
    issuer: "https://fulcio.provider.example",
    nonce: Buffer.alloc(32, 7).toString("base64url"),
    notBefore: "2026-08-01T12:16:00.000Z",
    previousActiveSha256: sha("0"),
    releaseBundleManifestSha256,
    releaseBundleSha256: releaseBundle.sha256,
    releaseId: "release.v1",
    requestId: "123e4567-e89b-42d3-a456-426614174000",
    runtimeIntentId: "intent.v1",
    sourceRenderSha256: sha("e"),
    subject: "spiffe://provider.example/admin/platform-activation",
    targetId: "platform.primary",
    treeSha256: hash(Buffer.from(`platform-git-tree-sha1/v1\0${dastProviderReceipt.document.treeSha}`)),
  };
  if (mutator) mutator(payload);
  const bytes = Buffer.from(`${canonicalJson({
    payload: Buffer.from(canonicalJson(payload)).toString("base64"),
    payloadType: "application/vnd.platform.docker-runtime-activation.v2+json",
    signatures: [{ keyid: sha("a"), sig: Buffer.alloc(64, 3).toString("base64") }],
  })}\n`);
  return fileArtifact(bytes, "/fixtures/docker-runtime-activation.dsse.json");
}

const dockerActivationEnvelope = envelopeArtifact();
const activationAdmission = fileArtifact(
  Buffer.from("activation promoter sigstore bundle\n"),
  "/fixtures/activation-admission.jsonl",
);

function receiptArtifact(mutator = null) {
  const document = {
    schema: "platform-activation-promotion/v2",
    status: "READY",
    requestId,
    releaseContextSha256,
    runtimeIntentSha256,
    dastProviderReceiptSha256: dastProviderReceipt.sha256,
    dastAuthorizationSha256: dastAuthorization.sha256,
    dastChainSha256: dastAuthorization.document.chainSha256,
    generatedAt: "2026-08-01T12:20:00.000Z",
    consumer: {
      repository,
      runId: "123456",
      runAttempt: 2,
      job: "deploy-vps",
      challengeNonce: consumerChallenge.challengeNonce,
    },
    producer: {
      repository: "owner/activation-promoter",
      workflowPath: ".github/workflows/promote.yml",
      workflowSha: "a".repeat(40),
      sourceRef: "refs/heads/main",
      event: "workflow_dispatch",
      runId: "789012",
      runAttempt: 3,
    },
    releaseBundle: {
      schema: "platform-activation-bundle-descriptor/v2",
      sha256: releaseBundle.sha256,
      sizeBytes: releaseBundle.sizeBytes,
      manifestSha256: releaseBundleManifestSha256,
    },
    dockerActivationEnvelope: {
      schema: "platform-docker-runtime-activation-envelope-descriptor/v1",
      sha256: dockerActivationEnvelope.sha256,
      sizeBytes: dockerActivationEnvelope.sizeBytes,
      payloadType: "application/vnd.platform.docker-runtime-activation.v2+json",
      runtimeIntentId: "intent.v1",
      generation: 7,
      dastAuthorizationSha256: dastAuthorization.sha256,
      dastChainSha256: dastAuthorization.document.chainSha256,
    },
    cas: {
      schema: "platform-activation-cas-installation/v2",
      releaseBundleObject: `sha256/${releaseBundle.sha256}`,
      releaseBundleManifestObject: `sha256/${releaseBundleManifestSha256}`,
      dockerActivationEnvelopeObject: `sha256/${dockerActivationEnvelope.sha256}`,
      dastAuthorizationObject: `sha256/${dastAuthorization.sha256}`,
      installed: true,
      immutable: true,
      providerAttested: true,
    },
  };
  if (mutator) mutator(document);
  return jsonArtifact(document, "/fixtures/activation-promotion-receipt.json");
}

const verifiedSubjects = [];
function verifyAttestation(options) {
  verifiedSubjects.push([
    options.subject,
    options.expectedSubjectDigest,
    options.bundle,
    options.trustedRoot,
  ]);
  return {
    status: "passed",
    verified: true,
    selfHostedRunnerDenied: true,
    offlineBundleVerified: true,
    resultCount: 1,
  };
}

const base = {
  policy,
  receipt: receiptArtifact(),
  providerMetadata,
  releaseBundle,
  releaseBundleManifest,
  dockerActivationEnvelope,
  activationAdmission,
  trustedRoot,
  dastAuthorization,
  dastProviderReceipt,
  dastProviderMetadata,
  dastProviderAttestationBundle,
  repository,
  consumerRunId: "123456",
  consumerRunAttempt: 2,
  providerRunId: "789012",
  providerRunAttempt: 3,
  verifyAttestation,
};

const result = validateActivationPromotion(base);
assert.equal(result.status, "READY");
assert.equal(result.releaseBundle.sha256, releaseBundle.sha256);
assert.equal(result.dockerActivationEnvelope.sha256, dockerActivationEnvelope.sha256);
assert.equal(result.dastProviderReceiptSha256, dastProviderReceipt.sha256);
assert.equal(result.dastAuthorizationSha256, dastAuthorization.sha256);
assert.equal(result.dastChainSha256, dastAuthorization.document.chainSha256);
assert.equal(result.activationAdmission.sha256, activationAdmission.sha256);
assert.equal(result.attestationResultCount, 4);
assert.equal(Object.hasOwn(result, "bundle"), false);
assert.equal(Object.hasOwn(result, "dastReceiptSha256"), false);
assert.notEqual(result.releaseBundle.sha256, result.dockerActivationEnvelope.sha256);
assert.notEqual(result.dastProviderReceiptSha256, result.dastAuthorizationSha256);
assert.notEqual(result.dastAuthorizationSha256, result.dastChainSha256);
assert.deepEqual(verifiedSubjects, [
  [dastAuthorization.snapshotPath, dastAuthorization.sha256, activationAdmission.snapshotPath, trustedRoot.snapshotPath],
  [releaseBundle.snapshotPath, releaseBundle.sha256, activationAdmission.snapshotPath, trustedRoot.snapshotPath],
  [dockerActivationEnvelope.snapshotPath, dockerActivationEnvelope.sha256, activationAdmission.snapshotPath, trustedRoot.snapshotPath],
  [base.receipt.snapshotPath, base.receipt.sha256, activationAdmission.snapshotPath, trustedRoot.snapshotPath],
]);
assert.deepEqual(Object.keys(projectProviderRunMetadata(providerMetadata.document)).sort(), [
  "conclusion", "event", "head_branch", "head_repository", "head_sha", "id", "path", "repository", "run_attempt", "status",
]);

const cases = [
  ["legacy policy kind", (value) => { value.policy.document.requiredReceiptKind = "platform-activation-promotion/v1"; }],
  ["legacy promotion receipt", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.schema = "platform-activation-promotion/v1"; }); }],
  ["request ID context substitution with coherent downstream artifacts", (value) => {
    const substitutedRequestId = `activation:${deploymentReceiptSha256}:${sha("a")}`;
    value.releaseBundleManifest = manifestArtifact((manifest) => { manifest.requestId = substitutedRequestId; });
    const substitutedManifestSha256 = hash(Buffer.from(canonicalJson(value.releaseBundleManifest.document)));
    value.dockerActivationEnvelope = envelopeArtifact((payload) => {
      payload.releaseBundleManifestSha256 = substitutedManifestSha256;
    });
    value.receipt = receiptArtifact((receipt) => {
      receipt.requestId = substitutedRequestId;
      receipt.releaseBundle.manifestSha256 = substitutedManifestSha256;
      receipt.dockerActivationEnvelope.sha256 = value.dockerActivationEnvelope.sha256;
      receipt.dockerActivationEnvelope.sizeBytes = value.dockerActivationEnvelope.sizeBytes;
      receipt.cas.releaseBundleManifestObject = `sha256/${substitutedManifestSha256}`;
      receipt.cas.dockerActivationEnvelopeObject = `sha256/${value.dockerActivationEnvelope.sha256}`;
    });
  }],
  ["request ID deployment substitution with coherent downstream artifacts", (value) => {
    const substitutedRequestId = `activation:${sha("a")}:${releaseContextSha256}`;
    value.releaseBundleManifest = manifestArtifact((manifest) => { manifest.requestId = substitutedRequestId; });
    const substitutedManifestSha256 = hash(Buffer.from(canonicalJson(value.releaseBundleManifest.document)));
    value.dockerActivationEnvelope = envelopeArtifact((payload) => {
      payload.releaseBundleManifestSha256 = substitutedManifestSha256;
    });
    value.receipt = receiptArtifact((receipt) => {
      receipt.requestId = substitutedRequestId;
      receipt.releaseBundle.manifestSha256 = substitutedManifestSha256;
      receipt.dockerActivationEnvelope.sha256 = value.dockerActivationEnvelope.sha256;
      receipt.dockerActivationEnvelope.sizeBytes = value.dockerActivationEnvelope.sizeBytes;
      receipt.cas.releaseBundleManifestObject = `sha256/${substitutedManifestSha256}`;
      receipt.cas.dockerActivationEnvelopeObject = `sha256/${value.dockerActivationEnvelope.sha256}`;
    });
  }],
  ["self-asserted policy", (value) => { value.policy.document.selfAssertedAnnotationsAccepted = true; }],
  ["wrong promoter run", (value) => { value.providerMetadata.document.id = 789013; }],
  ["wrong consumer", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.consumer.runId = "654321"; }); }],
  ["numeric consumer run ID", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.consumer.runId = 123456; }); }],
  ["numeric promoter run ID", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.producer.runId = 789012; }); }],
  ["raw receipt substituted", (value) => { value.dastProviderReceipt = authorizationArtifact(); }],
  ["wrong raw DAST digest", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.dastProviderReceiptSha256 = sha("0"); }); }],
  ["raw report fingerprint drift", (value) => {
    value.dastProviderReceipt = jsonArtifact({
      ...dastProviderReceipt.document,
      reportEvidenceSha256: sha("0"),
    }, dastProviderReceipt.sourcePath);
  }],
  ["raw semantic evidence drift", (value) => {
    const evidence = structuredClone(dastProviderReceipt.document.validatedReportEvidence);
    evidence.semanticVerdict.siteCount = 2;
    value.dastProviderReceipt = jsonArtifact({
      ...dastProviderReceipt.document,
      validatedReportEvidence: evidence,
      reportEvidenceSha256: hash(Buffer.from(JSON.stringify(evidence))),
    }, dastProviderReceipt.sourcePath);
  }],
  ["candidate producer drift", (value) => {
    value.dastProviderReceipt = jsonArtifact({
      ...dastProviderReceipt.document,
      candidateProducer: { ...dastProviderReceipt.document.candidateProducer, job: "deploy-vps" },
    }, dastProviderReceipt.sourcePath);
  }],
  ["wrong authorization digest", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.dastAuthorizationSha256 = sha("0"); }); }],
  ["raw receipt used as authorization", (value) => { value.dastAuthorization = dastProviderReceipt; }],
  ["authorization projection drift", (value) => {
    value.dastAuthorization = authorizationArtifact((authorization) => {
      authorization.chain.providerReceiptSha256 = sha("0");
      authorization.chainSha256 = hash(Buffer.from(canonicalJson(authorization.chain)));
    });
  }],
  ["authorization chain digest drift", (value) => {
    value.dastAuthorization = authorizationArtifact((authorization) => { authorization.chainSha256 = sha("0"); });
  }],
  ["DAST metadata substituted", (value) => {
    value.dastProviderMetadata = jsonArtifact({ substituted: true }, dastProviderMetadata.sourcePath);
  }],
  ["DAST Sigstore bundle substituted", (value) => {
    value.dastProviderAttestationBundle = fileArtifact(Buffer.from("other bundle\n"), dastProviderAttestationBundle.sourcePath);
  }],
  ["manifest authorization mismatch", (value) => {
    value.releaseBundleManifest = manifestArtifact((manifest) => {
      manifest.entries.find(({ name }) => name === "dast-activation-authorization.json").sha256 = sha("0");
    });
  }],
  ["manifest raw receipt mismatch", (value) => {
    value.releaseBundleManifest = manifestArtifact((manifest) => {
      manifest.entries.find(({ name }) => name === "dast-provider-verification.json").sha256 = sha("0");
    });
  }],
  ["wrong release bundle", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.releaseBundle.sha256 = sha("0"); }); }],
  ["wrong release manifest", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.releaseBundle.manifestSha256 = sha("0"); }); }],
  ["wrong envelope", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.dockerActivationEnvelope.sha256 = sha("0"); }); }],
  ["release bundle reused as envelope", (value) => {
    value.receipt = receiptArtifact((receipt) => { receipt.dockerActivationEnvelope.sha256 = releaseBundle.sha256; });
  }],
  ["envelope authorization mismatch", (value) => {
    value.dockerActivationEnvelope = envelopeArtifact((payload) => { payload.dastAuthorizationSha256 = sha("0"); });
    value.receipt = receiptArtifact((receipt) => {
      receipt.dockerActivationEnvelope.sha256 = value.dockerActivationEnvelope.sha256;
      receipt.dockerActivationEnvelope.sizeBytes = value.dockerActivationEnvelope.sizeBytes;
      receipt.cas.dockerActivationEnvelopeObject = `sha256/${value.dockerActivationEnvelope.sha256}`;
    });
  }],
  ["envelope release bundle mismatch", (value) => {
    value.dockerActivationEnvelope = envelopeArtifact((payload) => { payload.releaseBundleSha256 = sha("0"); });
    value.receipt = receiptArtifact((receipt) => {
      receipt.dockerActivationEnvelope.sha256 = value.dockerActivationEnvelope.sha256;
      receipt.dockerActivationEnvelope.sizeBytes = value.dockerActivationEnvelope.sizeBytes;
      receipt.cas.dockerActivationEnvelopeObject = `sha256/${value.dockerActivationEnvelope.sha256}`;
    });
  }],
  ["envelope manifest mismatch", (value) => {
    value.dockerActivationEnvelope = envelopeArtifact((payload) => { payload.releaseBundleManifestSha256 = sha("0"); });
    value.receipt = receiptArtifact((receipt) => {
      receipt.dockerActivationEnvelope.sha256 = value.dockerActivationEnvelope.sha256;
      receipt.dockerActivationEnvelope.sizeBytes = value.dockerActivationEnvelope.sizeBytes;
      receipt.cas.dockerActivationEnvelopeObject = `sha256/${value.dockerActivationEnvelope.sha256}`;
    });
  }],
  ["envelope DAST chain mismatch", (value) => {
    value.dockerActivationEnvelope = envelopeArtifact((payload) => {
      payload.dast = { ...payload.dast, reportEvidenceSha256: sha("0") };
    });
    value.receipt = receiptArtifact((receipt) => {
      receipt.dockerActivationEnvelope.sha256 = value.dockerActivationEnvelope.sha256;
      receipt.dockerActivationEnvelope.sizeBytes = value.dockerActivationEnvelope.sizeBytes;
      receipt.cas.dockerActivationEnvelopeObject = `sha256/${value.dockerActivationEnvelope.sha256}`;
    });
  }],
  ["legacy envelope media type", (value) => {
    const document = JSON.parse(dockerActivationEnvelope.bytes.toString("utf8"));
    document.payloadType = "application/vnd.platform.docker-runtime-activation.v1+json";
    value.dockerActivationEnvelope = fileArtifact(
      Buffer.from(`${canonicalJson(document)}\n`),
      dockerActivationEnvelope.sourcePath,
    );
    value.receipt = receiptArtifact((receipt) => {
      receipt.dockerActivationEnvelope.sha256 = value.dockerActivationEnvelope.sha256;
      receipt.dockerActivationEnvelope.sizeBytes = value.dockerActivationEnvelope.sizeBytes;
      receipt.dockerActivationEnvelope.payloadType = document.payloadType;
      receipt.cas.dockerActivationEnvelopeObject = `sha256/${value.dockerActivationEnvelope.sha256}`;
    });
  }],
  ["CAS not installed", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.cas.installed = false; }); }],
  ["legacy CAS", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.cas.schema = "platform-activation-cas-installation/v1"; }); }],
  ["CAS mutable", (value) => { value.receipt = receiptArtifact((receipt) => { receipt.cas.immutable = false; }); }],
  ["CAS bundle/envelope swap", (value) => {
    value.receipt = receiptArtifact((receipt) => { receipt.cas.dockerActivationEnvelopeObject = `sha256/${releaseBundle.sha256}`; });
  }],
  ["untrusted root", (value) => { value.trustedRoot = fileArtifact(Buffer.from("other root\n"), "/fixtures/other-root.json"); }],
  ["mutable subject path instead of snapshot", (value) => {
    value.dastAuthorization = { ...dastAuthorization, snapshotPath: dastAuthorization.sourcePath };
  }],
  ["incomplete DSSE", (value) => { value.verifyAttestation = () => ({ status: "passed", verified: false }); }],
  ["one missing subject attestation", (value) => {
    value.verifyAttestation = (options) => options.subject === dastAuthorization.snapshotPath
      ? { status: "passed", verified: false }
      : { status: "passed", verified: true, selfHostedRunnerDenied: true, offlineBundleVerified: true, resultCount: 1 };
  }],
  ["promotion predates authorization", (value) => {
    value.receipt = receiptArtifact((receipt) => { receipt.generatedAt = "2026-08-01T12:05:00.000Z"; });
  }],
];

for (const [label, mutate] of cases) {
  const candidate = {
    ...base,
    policy: structuredClone(base.policy),
    providerMetadata: structuredClone(base.providerMetadata),
  };
  mutate(candidate);
  assert.throws(() => validateActivationPromotion(candidate), undefined, label);
}

process.stdout.write(`activation promotion v2 policy tests passed ${cases.length + 15}/${cases.length + 15}\n`);
