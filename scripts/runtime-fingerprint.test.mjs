import assert from "node:assert/strict";
import test from "node:test";
import { evaluateRuntimeFingerprint, runtimeConfigurationSha256 } from "./runtime-fingerprint.mjs";

const commit = "a".repeat(40);
const tree = "b".repeat(40);
const configHash = "c".repeat(64);
const imageId = `sha256:${"d".repeat(64)}`;
const workloadLockSha256 = "e".repeat(64);
const deploymentId = "deploy-20260721-0001";
const deploymentStartedAt = "2026-07-21T20:00:00.000Z";
const renderSha256 = "0".repeat(64);
const candidateId = "1".repeat(64);
const services = [{ service: "api", configHash, imageId, imageRef: `registry.example/api@sha256:${"f".repeat(64)}` }];
const expected = {
  candidate: {
    schema: "platform.release-candidate/v1",
    id: candidateId,
    repository: "owner/platform-infrastructure",
    commit,
    tree,
    clean: true,
    projectName: "platform",
    workloadLockSha256,
    renderSha256,
    trusted: true,
  },
  deploymentId,
  deploymentStartedAt,
  serviceConfigSha256: runtimeConfigurationSha256(services),
  services,
};
const actual = {
  checkoutCommit: commit,
  checkoutTree: tree,
  clean: true,
  project: "platform",
  workloadLockSha256,
  renderSha256,
  containers: [{
    name: "platform-api",
    service: "api",
    project: "platform",
    configHash,
    imageId,
    imageRef: services[0].imageRef,
    state: "running",
    health: "healthy",
    exitCode: 0,
    startedAt: "2026-07-21T20:00:01.000Z",
    runtimeCommit: commit,
    runtimeTree: tree,
    runtimeCandidateId: candidateId,
    runtimeDeploymentId: deploymentId,
    runtimeRenderSha256: renderSha256,
    runtimeWorkloadLockSha256: workloadLockSha256,
  }],
};

test("exact deployment-bound runtime identity passes", () => {
  const result = evaluateRuntimeFingerprint(expected, actual);
  assert.equal(result.status, "passed");
  assert.deepEqual(result.issues, []);
  assert.match(result.fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(result.actual.configurationSha256, expected.serviceConfigSha256);
});

test("adversarial valid image-ID substitution fails closed", () => {
  const containers = [{ ...actual.containers[0], imageId: `sha256:${"1".repeat(64)}` }];
  const result = evaluateRuntimeFingerprint(expected, { ...actual, containers });
  assert.match(result.issues.join(","), /image-id-mismatch:api/);
});

test("image-reference and configuration substitutions fail closed", () => {
  const containers = [{
    ...actual.containers[0],
    imageRef: `registry.example/api@sha256:${"2".repeat(64)}`,
    configHash: "3".repeat(64),
  }];
  const issues = evaluateRuntimeFingerprint(expected, { ...actual, containers }).issues.join(",");
  assert.match(issues, /image-ref-mismatch:api/);
  assert.match(issues, /config-hash-mismatch:api/);
  assert.match(issues, /observed-configuration-mismatch/);
});

test("checkout and observed container commit/tree substitutions fail closed", () => {
  const containers = [{ ...actual.containers[0], runtimeCommit: "4".repeat(40), runtimeTree: "5".repeat(40) }];
  const result = evaluateRuntimeFingerprint(expected, {
    ...actual,
    checkoutCommit: "6".repeat(40),
    checkoutTree: "7".repeat(40),
    containers,
  });
  const issues = result.issues.join(",");
  assert.match(issues, /checkout-commit-mismatch/);
  assert.match(issues, /checkout-tree-mismatch/);
  assert.match(issues, /runtime-commit-mismatch:api/);
  assert.match(issues, /runtime-tree-mismatch:api/);
});

test("deployment-ID and workload-lock substitutions fail closed", () => {
  const containers = [{
    ...actual.containers[0],
    runtimeDeploymentId: "deploy-20260721-other",
    runtimeWorkloadLockSha256: "8".repeat(64),
  }];
  const result = evaluateRuntimeFingerprint(expected, {
    ...actual,
    workloadLockSha256: "9".repeat(64),
    containers,
  });
  const issues = result.issues.join(",");
  assert.match(issues, /observed-workload-lock-mismatch/);
  assert.match(issues, /runtime-deployment-mismatch:api/);
  assert.match(issues, /runtime-workload-lock-mismatch:api/);
});

test("candidate-ID and canonical Compose render substitutions fail closed", () => {
  const containers = [{
    ...actual.containers[0],
    runtimeCandidateId: "2".repeat(64),
    runtimeRenderSha256: "3".repeat(64),
  }];
  const result = evaluateRuntimeFingerprint(expected, {
    ...actual,
    renderSha256: "4".repeat(64),
    containers,
  });
  const issues = result.issues.join(",");
  assert.match(issues, /observed-render-mismatch/);
  assert.match(issues, /runtime-candidate-mismatch:api/);
  assert.match(issues, /runtime-render-mismatch:api/);
});

test("a container from before the declared deployment event fails closed", () => {
  const containers = [{ ...actual.containers[0], startedAt: "2026-07-21T19:59:59.999Z" }];
  assert.match(evaluateRuntimeFingerprint(expected, { ...actual, containers }).issues.join(","), /container-predates-deployment:api/);
});

test("missing, duplicate and unexpected services fail closed", () => {
  const missing = evaluateRuntimeFingerprint(expected, { ...actual, containers: [] });
  assert.match(missing.issues.join(","), /missing-service:api/);
  const duplicate = evaluateRuntimeFingerprint(expected, { ...actual, containers: [...actual.containers, { ...actual.containers[0], name: "platform-api-copy" }] });
  assert.match(duplicate.issues.join(","), /duplicate-service:api/);
  const extra = evaluateRuntimeFingerprint(expected, { ...actual, containers: [...actual.containers, { ...actual.containers[0], name: "other", service: "other" }] });
  assert.match(extra.issues.join(","), /unexpected-service:other/);
});

test("dirty worktree and unhealthy runtime fail closed", () => {
  const result = evaluateRuntimeFingerprint(expected, {
    ...actual,
    clean: false,
    containers: [{ ...actual.containers[0], health: "unhealthy" }],
  });
  assert.match(result.issues.join(","), /worktree-not-clean/);
  assert.match(result.issues.join(","), /service-unhealthy:api/);
});

test("expected-running requires exact healthy state", () => {
  for (const health of ["none", "starting", "", "arbitrary"]) {
    const result = evaluateRuntimeFingerprint(expected, {
      ...actual,
      containers: [{ ...actual.containers[0], health }],
    });
    assert.match(result.issues.join(","), /service-unhealthy:api/, `health=${JSON.stringify(health)}`);
  }
});

test("an explicitly expected one-shot service must complete with exit code zero", () => {
  const oneShotServices = [{ ...services[0], expectedState: "completed" }];
  const oneShotExpected = {
    ...expected,
    serviceConfigSha256: runtimeConfigurationSha256(oneShotServices),
    services: oneShotServices,
  };
  const completed = [{ ...actual.containers[0], state: "exited", health: "none", exitCode: 0 }];
  assert.equal(evaluateRuntimeFingerprint(oneShotExpected, { ...actual, containers: completed }).status, "passed");
  const failed = [{ ...completed[0], exitCode: 1 }];
  assert.match(evaluateRuntimeFingerprint(oneShotExpected, { ...actual, containers: failed }).issues.join(","), /service-not-completed:api/);
});

test("target manifest rejects a self-inconsistent configuration digest", () => {
  assert.throws(
    () => evaluateRuntimeFingerprint({ ...expected, serviceConfigSha256: "9".repeat(64) }, actual),
    /target configuration digest does not match/,
  );
});
