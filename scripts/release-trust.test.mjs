#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  buildGithubAttestationVerifyArgs,
  parseCryptographicallyVerifiedGithubOutput,
  verifyGithubAttestation,
} from "./release-trust.mjs";

const digest = "a".repeat(64);
const sourceDigest = "b".repeat(40);
const repository = "mattdifi05/platform-infrastructure";
const signerWorkflow = `${repository}/.github/workflows/release-attestation.yml`;
const sourceRef = "refs/heads/main";
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "release-trust-test-"));
const fakeGh = path.join(tmp, "gh");
const argsFile = path.join(tmp, "args.txt");

const verifiedFixture = [{
  verificationResult: {
    signature: {
      certificate: {
        rawBytes: "synthetic-certificate-used-only-after-fake-cli-exit-success",
        sourceRepository: repository,
      },
    },
    verifiedTimestamps: [{ type: "transparency-log", integratedTime: 1 }],
    statement: {
      _type: "https://in-toto.io/Statement/v1",
      predicateType: "https://slsa.dev/provenance/v1",
      subject: [{ name: "ghcr.io/example/image", digest: { sha256: digest } }],
      predicate: {},
    },
  },
}];

fs.writeFileSync(fakeGh, `#!/bin/sh
printf '%s\n' "$@" > "$FAKE_GH_ARGS_FILE"
if [ "\${FAKE_GH_MODE:-pass}" = fail ]; then
  echo 'cryptographic verification rejected' >&2
  exit 1
fi
printf '%s' "$FAKE_GH_OUTPUT"
`, { mode: 0o700 });

process.env.PLATFORM_RELEASE_TRUST_TEST_MODE = "1";
process.env.GITHUB_CLI_BIN = fakeGh;
process.env.FAKE_GH_ARGS_FILE = argsFile;
process.env.FAKE_GH_OUTPUT = JSON.stringify(verifiedFixture);

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  process.stdout.write(`ok ${passed} - ${name}\n`);
}

const baseOptions = {
  subject: `oci://ghcr.io/example/image@sha256:${digest}`,
  expectedSubjectDigest: digest,
  expectedSubjectName: "ghcr.io/example/image",
  repository,
  signerWorkflow,
  sourceDigest,
  sourceRef,
};

try {
  test("builds exact GitHub/Sigstore verifier policy", () => {
    const args = buildGithubAttestationVerifyArgs(baseOptions);
    for (const required of [
      "--repo",
      "--signer-workflow",
      "--source-digest",
      "--signer-digest",
      "--source-ref",
      "--cert-oidc-issuer",
      "--predicate-type",
      "--deny-self-hosted-runners",
      "--format",
    ]) {
      assert.ok(args.includes(required), `missing ${required}`);
    }
  });

  test("accepts only output produced after verifier success", () => {
    const result = verifyGithubAttestation(baseOptions);
    assert.equal(result.verified, true);
    assert.equal(result.verifiedTimestampCount, 1);
    assert.equal(result.commitSha, sourceDigest);
    const args = fs.readFileSync(argsFile, "utf8").split(/\r?\n/).filter(Boolean);
    assert.ok(args.includes(signerWorkflow));
    assert.ok(args.includes(sourceDigest));
  });

  test("rejects a legacy self-asserted verified report", () => {
    assert.throws(() => parseCryptographicallyVerifiedGithubOutput(JSON.stringify({
      verified: true,
      repository,
      commitSha: sourceDigest,
      subjects: [{ name: "example/image", digest }],
    }), { expectedSubjectDigest: digest }), /non-empty result array|verificationResult/);
  });

  test("rejects an unsigned SLSA statement", () => {
    assert.throws(() => parseCryptographicallyVerifiedGithubOutput(JSON.stringify([{
      _type: "https://in-toto.io/Statement/v1",
      predicateType: "https://slsa.dev/provenance/v1",
      subject: [{ name: "example/image", digest: { sha256: digest } }],
    }]), { expectedSubjectDigest: digest }), /verificationResult/);
  });

  test("rejects missing signing certificate", () => {
    const fixture = structuredClone(verifiedFixture);
    delete fixture[0].verificationResult.signature.certificate;
    assert.throws(() => parseCryptographicallyVerifiedGithubOutput(JSON.stringify(fixture), { expectedSubjectDigest: digest }), /certificate/);
  });

  test("rejects missing transparency witness", () => {
    const fixture = structuredClone(verifiedFixture);
    fixture[0].verificationResult.verifiedTimestamps = [];
    assert.throws(() => parseCryptographicallyVerifiedGithubOutput(JSON.stringify(fixture), { expectedSubjectDigest: digest }), /transparency-log|timestamp/);
  });

  test("rejects wrong predicate", () => {
    const fixture = structuredClone(verifiedFixture);
    fixture[0].verificationResult.statement.predicateType = "https://example.invalid/predicate";
    assert.throws(() => parseCryptographicallyVerifiedGithubOutput(JSON.stringify(fixture), { expectedSubjectDigest: digest }), /predicate type/);
  });

  test("rejects wrong subject digest", () => {
    assert.throws(() => parseCryptographicallyVerifiedGithubOutput(JSON.stringify(verifiedFixture), {
      expectedSubjectDigest: "c".repeat(64),
    }), /does not cover/);
  });

  test("rejects the right digest under a different subject name", () => {
    assert.throws(() => parseCryptographicallyVerifiedGithubOutput(JSON.stringify(verifiedFixture), {
      expectedSubjectDigest: digest,
      expectedSubjectName: "ghcr.io/attacker/image",
    }), /exact subject/);
  });

  test("rejects verifier command failure", () => {
    process.env.FAKE_GH_MODE = "fail";
    assert.throws(() => verifyGithubAttestation(baseOptions), /cryptographic verification failed/);
    delete process.env.FAKE_GH_MODE;
  });

  test("rejects repository widening", () => {
    assert.throws(() => buildGithubAttestationVerifyArgs({ ...baseOptions, repository: "owner/repo/extra" }), /owner\/name/);
  });

  test("rejects signer workflow outside the repository", () => {
    assert.throws(() => buildGithubAttestationVerifyArgs({
      ...baseOptions,
      signerWorkflow: "attacker/repo/.github/workflows/release.yml",
    }), /exact workflow path/);
  });

  test("rejects abbreviated commit identity", () => {
    assert.throws(() => buildGithubAttestationVerifyArgs({ ...baseOptions, sourceDigest: "abc123" }), /40-character/);
  });

  test("rejects mutable OCI subjects", () => {
    assert.throws(() => buildGithubAttestationVerifyArgs({ ...baseOptions, subject: "oci://ghcr.io/example/image:latest" }), /digest-pinned/);
  });

  test("requires bundle and trusted root together", () => {
    const bundle = path.join(tmp, "bundle.jsonl");
    fs.writeFileSync(bundle, "{}\n");
    assert.throws(() => buildGithubAttestationVerifyArgs({ ...baseOptions, bundle }), /both an attestation bundle/);
  });

  test("passes signed offline bundle and trusted root to the verifier", () => {
    const bundle = path.join(tmp, "bundle.jsonl");
    const trustedRoot = path.join(tmp, "trusted-root.jsonl");
    fs.writeFileSync(bundle, "{}\n");
    fs.writeFileSync(trustedRoot, "{}\n");
    const args = buildGithubAttestationVerifyArgs({ ...baseOptions, bundle, trustedRoot });
    assert.equal(args.at(args.indexOf("--bundle") + 1), bundle);
    assert.equal(args.at(args.indexOf("--custom-trusted-root") + 1), trustedRoot);
  });

  process.stdout.write(`release trust tests passed ${passed}/${passed}\n`);
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
