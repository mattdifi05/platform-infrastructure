#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createVerifiedReleaseArtifacts } from "./release-subject-manifest.mjs";
import { resolveRegistryDescriptor } from "./release-registry-resolution.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "release-gate-consumer-"));

function writeJson(name, value) {
  const pathname = path.join(temporary, name);
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  fs.writeFileSync(pathname, bytes, { mode: 0o600 });
  return { pathname, bytes, sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
}

function fileHashes(directory, prefix) {
  if (!fs.existsSync(directory)) return new Map();
  return new Map(fs.readdirSync(directory)
    .filter((name) => name.startsWith(prefix) && name.endsWith(".json"))
    .map((name) => {
      const bytes = fs.readFileSync(path.join(directory, name));
      return [name, crypto.createHash("sha256").update(bytes).digest("hex")];
    }));
}

function reportDocuments(directory, prefix) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory)
    .filter((name) => name.startsWith(prefix) && name.endsWith(".json"))
    .map((name) => JSON.parse(fs.readFileSync(path.join(directory, name), "utf8")));
}

try {
  const repository = "owner/repo";
  const commitResult = spawnSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8" });
  assert.equal(commitResult.status, 0, commitResult.stderr);
  const commitSha = commitResult.stdout.trim();
  const platformManifestBytes = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: {
      mediaType: "application/vnd.oci.image.config.v1+json",
      digest: `sha256:${"1".repeat(64)}`,
      size: 321,
    },
    layers: [],
  }));
  const runtimeDigest = `sha256:${crypto.createHash("sha256").update(platformManifestBytes).digest("hex")}`;
  const descriptor = {
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [
      {
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: runtimeDigest,
        size: platformManifestBytes.length,
        platform: { os: "linux", architecture: "amd64" },
      },
      {
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        digest: `sha256:${"d".repeat(64)}`,
        size: 456,
        platform: { os: "unknown", architecture: "unknown" },
        annotations: {
          "vnd.docker.reference.type": "attestation-manifest",
          "vnd.docker.reference.digest": runtimeDigest,
        },
      },
    ],
  };
  const descriptorBytes = Buffer.from(JSON.stringify(descriptor));
  const descriptorPath = path.join(temporary, "registry-descriptor.json");
  fs.writeFileSync(descriptorPath, descriptorBytes, { mode: 0o600 });
  const rootDigest = crypto.createHash("sha256").update(descriptorBytes).digest("hex");
  const image = `ghcr.io/owner/platform-infrastructure-php-apache@sha256:${rootDigest}`;
  const entries = [{ key: "PHP_APACHE_IMAGE", image }];
  const registryResolution = resolveRegistryDescriptor({
    image,
    descriptorBytes,
    expectedPlatforms: ["linux/amd64"],
    platformManifestBytes: { "linux/amd64": platformManifestBytes },
    resolvedAt: "2026-07-21T00:00:00Z",
  });
  const registryArtifact = writeJson("registry-resolution.json", registryResolution);
  const buildkitSbom = {
    "linux/amd64": {
      SPDX: {
        spdxVersion: "SPDX-2.3",
        SPDXID: "SPDXRef-DOCUMENT",
        dataLicense: "CC0-1.0",
        documentNamespace: "https://example.invalid/spdx/release-gate",
        creationInfo: { created: "2026-07-21T00:00:00Z" },
        packages: [{
          SPDXID: "SPDXRef-Package-openssl",
          name: "openssl",
          versionInfo: "3.0.0",
          externalRefs: [{ referenceType: "purl", referenceLocator: "pkg:apk/alpine/openssl@3.0.0" }],
        }],
      },
    },
  };
  const buildkitArtifact = writeJson("buildkit-sbom.spdx.json", buildkitSbom);
  const generationVerification = {
    status: "passed",
    verified: true,
    completeness: "complete",
    repository,
    sourceDigest: commitSha,
    commitSha,
    commitShaMatched: true,
    provider: "github-artifact-attestations",
    signerWorkflow: `${repository}/.github/workflows/release-attestation.yml`,
    sourceRef: "refs/heads/main",
    releaseImages: [image],
    attestations: [{
      status: "passed",
      verified: true,
      completeness: "complete",
      repository,
      signerWorkflow: `${repository}/.github/workflows/release-attestation.yml`,
      sourceDigest: commitSha,
      sourceRef: "refs/heads/main",
      predicateType: "https://slsa.dev/provenance/v1",
      certOidcIssuer: "https://token.actions.githubusercontent.com",
      certificateFingerprints: ["f".repeat(64)],
      verifiedTimestampCount: 1,
      subjects: [{ name: "ghcr.io/owner/platform-infrastructure-php-apache", sha256: rootDigest }],
    }],
  };
  const artifacts = createVerifiedReleaseArtifacts({
    entries,
    repository,
    commitSha,
    releaseName: "consumer-test",
    workflowRunId: "1",
    workflowRunUrl: "https://example.invalid/run/1",
    verification: generationVerification,
    buildkitSbom,
    buildkitSbomBytes: buildkitArtifact.bytes,
    registryResolution,
    registryResolutionSha256: registryArtifact.sha256,
    registryDescriptorBytes: descriptorBytes,
    expectedPlatforms: ["linux/amd64"],
    generatedAt: "2026-07-21T00:00:00.000Z",
    serialNumber: "urn:uuid:123e4567-e89b-42d3-a456-426614174000",
  });
  const manifestArtifact = writeJson("release-subjects.json", artifacts.manifest);
  const sbomArtifact = writeJson("release-sbom.cdx.json", artifacts.sbom);
  const evidenceBundleArtifact = writeJson("release-subject-evidence.json", artifacts.evidenceBundle);
  const sourceArchivePath = path.join(temporary, "source-archive.tar");
  const archiveResult = spawnSync("git", ["-C", root, "-c", "tar.umask=0000", "archive", "--format=tar", `--output=${sourceArchivePath}`, commitSha], { encoding: "utf8" });
  assert.equal(archiveResult.status, 0, archiveResult.stderr);
  const sourceArchiveBytes = fs.readFileSync(sourceArchivePath);
  const sourceArchiveSha256 = crypto.createHash("sha256").update(sourceArchiveBytes).digest("hex");
  assert.equal(manifestArtifact.sha256.length, 64);
  assert.equal(sbomArtifact.sha256, artifacts.manifest.sbom.sha256);

  const fakeGh = path.join(temporary, "fake-gh.mjs");
  fs.writeFileSync(fakeGh, `#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
const subject = process.argv[4];
const predicateIndex = process.argv.indexOf("--predicate-type");
const predicateType = process.argv[predicateIndex + 1];
let name;
let digest;
if (subject.startsWith("oci://")) {
  const match = subject.match(/^oci:\\/\\/(.+)@sha256:([a-f0-9]{64})$/);
  name = match[1];
  digest = match[2];
} else {
  name = subject.split("/").at(-1);
  digest = crypto.createHash("sha256").update(fs.readFileSync(subject)).digest("hex");
}
process.stdout.write(JSON.stringify([{ verificationResult: {
  signature: { certificate: { testCertificate: true } },
  verifiedTimestamps: [{ source: "test" }],
  statement: { predicateType, subject: [{ name, digest: { sha256: digest } }] },
	} }]));
	`, { mode: 0o700 });

  const productionReleaseTrust = fs.readFileSync(path.join(root, "scripts", "release-trust.mjs"), "utf8");
  assert.doesNotMatch(productionReleaseTrust, /GITHUB_CLI_BIN|PLATFORM_RELEASE_TRUST_TEST_MODE/,
    "production verification must not expose an environment-controlled verifier override");
  const fixtureRoot = path.join(temporary, "repo");
  fs.cpSync(root, fixtureRoot, {
    recursive: true,
    filter(source) {
      const relative = path.relative(root, source);
      const topLevel = relative.split(path.sep)[0];
      return ![".git", ".tmp", "backups", "node_modules", "reports"].includes(topLevel);
    },
  });
  const gitDirectoryResult = spawnSync("git", ["-C", root, "rev-parse", "--absolute-git-dir"], { encoding: "utf8" });
  assert.equal(gitDirectoryResult.status, 0, gitDirectoryResult.stderr);
  fs.writeFileSync(path.join(fixtureRoot, ".git"), `gitdir: ${gitDirectoryResult.stdout.trim()}\n`, { mode: 0o600 });
  const fixtureReleaseTrustPath = path.join(fixtureRoot, "scripts", "release-trust.mjs");
  const fixtureReleaseTrust = fs.readFileSync(fixtureReleaseTrustPath, "utf8");
  const pinnedVerifierDeclaration = 'verifierBinary = "/usr/local/bin/gh"';
  assert.equal(fixtureReleaseTrust.split(pinnedVerifierDeclaration).length, 2,
    "test fixture expected one pinned verifier declaration");
  fs.writeFileSync(
    fixtureReleaseTrustPath,
    fixtureReleaseTrust.replace(pinnedVerifierDeclaration, `verifierBinary = ${JSON.stringify(fakeGh)}`),
    { mode: 0o600 },
  );
  const readyPolicy = {
    version: 1,
    status: "READY",
    trustedVerifierChannel: "external-admission-controller/prod",
    trustedOpsImageRepository: "ghcr.io/owner/platform-infrastructure-ops",
    trustedProducer: {
      repository: "owner/trusted-admission",
      workflowPath: ".github/workflows/produce-admission.yml",
      workflowSha: "4".repeat(40),
      sourceRef: "refs/heads/main",
      event: "workflow_dispatch",
    },
    reason: "Disposable hostile fixture: policy readiness must never replace receipts.",
    requiredReceiptKind: "platform-trusted-deployment-admission/v1",
    selfAssertedAnnotationsAccepted: false,
  };
  fs.writeFileSync(
    path.join(fixtureRoot, "governance", "deployment-admission.json"),
    `${JSON.stringify(readyPolicy, null, 2)}\n`,
    { mode: 0o600 },
  );

  const commonArgs = [
    path.join(fixtureRoot, "scripts", "infra-ops.mjs"),
    "release-artifact-gate",
    "--imageManifest", manifestArtifact.pathname,
    "--sbom", sbomArtifact.pathname,
    "--sourceArchive", sourceArchivePath,
    "--subjectEvidenceBundle", evidenceBundleArtifact.pathname,
    "--releaseSha", commitSha,
    "--repo", repository,
    "--sourceRef", "refs/heads/main",
  ];
  const environment = {
    ...process.env,
    GH_TOKEN: "release-gate-consumer-test-token",
  };
  const localChecks = path.join(fixtureRoot, "reports", "local-checks");
  const positive = spawnSync(process.execPath, commonArgs, { cwd: fixtureRoot, env: environment, encoding: "utf8" });
  assert.equal(positive.status, 1);
  assert.match(positive.stderr, /EXTERNAL-PENDING: exact artifact, deployment, and authenticated provider-run inputs are required/);
  assert.doesNotMatch(positive.stderr, /Exact per-subject registry resolution is required/);
  assert.doesNotMatch(positive.stdout, /Release artifact and trusted deployment admission gate passed/);
  const defaultGateReports = reportDocuments(localChecks, "release-artifact-gate-");
  assert.ok(defaultGateReports.length > 0, "failed default gate must emit diagnostic local-check evidence");
  assert.ok(defaultGateReports.every((report) => report.status === "failed"),
    "READY policy without deployment/provider receipts must never mint a PASS report");

  const gateReportsBeforeArtifactOnly = fileHashes(localChecks, "release-artifact-gate-");
  const producerReceipt = path.join(temporary, "producer-artifact-receipt.json");
  const artifactOnly = spawnSync(process.execPath, [
    ...commonArgs,
    "--artifactVerificationOnly",
    "--receiptOutput", producerReceipt,
  ], {
    cwd: fixtureRoot, env: environment, encoding: "utf8",
  });
  assert.equal(artifactOnly.status, 0, artifactOnly.stderr);
  assert.match(artifactOnly.stdout, /Artifact-only release verification passed/);
  assert.match(artifactOnly.stdout, /EXTERNAL-PENDING/);
  assert.deepEqual(fileHashes(localChecks, "release-artifact-gate-"), gateReportsBeforeArtifactOnly,
    "artifact-only verification must not mint or overwrite a release-artifact-gate PASS report");
  const cryptoOnlyReports = [...fileHashes(localChecks, "release-artifact-crypto-only-").keys()];
  assert.ok(cryptoOnlyReports.length > 0, "artifact-only verification must be phase-scoped in local evidence");
  const artifactReceipt = JSON.parse(fs.readFileSync(producerReceipt, "utf8"));
  assert.equal(artifactReceipt.sourceArchiveSha256, sourceArchiveSha256);
  assert.match(artifactReceipt.provenance.manifestVerificationFingerprint, /^[a-f0-9]{64}$/);
  assert.equal(artifactReceipt.generatedAt, artifacts.manifest.generatedAt);

  const reverifiedReceipt = path.join(temporary, "consumer-artifact-receipt.json");
  const reverify = spawnSync(process.execPath, [
    ...commonArgs,
    "--artifactVerificationOnly",
    "--receiptOutput", reverifiedReceipt,
  ], { cwd: fixtureRoot, env: environment, encoding: "utf8" });
  assert.equal(reverify.status, 0, reverify.stderr);
  assert.deepEqual(fs.readFileSync(reverifiedReceipt), fs.readFileSync(producerReceipt),
    "the consumer must regenerate the exact provider-bound artifact receipt bytes");

  const tamperedBundle = structuredClone(artifacts.evidenceBundle);
  const tampered = JSON.parse(Buffer.from(tamperedBundle.subjects[0].registryResolutionBase64, "base64").toString("utf8"));
  tampered.platforms[0].size += 1;
  const tamperedBytes = Buffer.from(`${JSON.stringify(tampered, null, 2)}\n`);
  tamperedBundle.subjects[0].registryResolutionBase64 = tamperedBytes.toString("base64");
  tamperedBundle.subjects[0].registryResolutionSha256 = crypto.createHash("sha256").update(tamperedBytes).digest("hex");
  const tamperedArtifact = writeJson("release-subject-evidence-tampered.json", tamperedBundle);
  const negativeArgs = [...commonArgs];
  negativeArgs[negativeArgs.indexOf(evidenceBundleArtifact.pathname)] = tamperedArtifact.pathname;
  const negative = spawnSync(process.execPath, negativeArgs, { cwd: fixtureRoot, env: environment, encoding: "utf8" });
  assert.equal(negative.status, 1);
  assert.match(negative.stderr, /differs from exact descriptor resolution/);
  assert.doesNotMatch(negative.stderr, /EXTERNAL-PENDING/);

  process.stdout.write("release artifact gate consumer tests passed 8/8; trusted channel remains EXTERNAL-PENDING without authenticated receipts\n");
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
