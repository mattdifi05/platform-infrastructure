import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  evaluateBrownfieldControlPlane,
  parseBrownfieldControlPlaneCompose,
} from "./v1-brownfield-control-plane-policy.mjs";

const root = path.resolve(import.meta.dirname, "..");
const policy = JSON.parse(fs.readFileSync(
  path.join(root, "governance", "v1-brownfield-control-plane.json"),
  "utf8",
));
const composeText = fs.readFileSync(path.join(root, "compose.v1-control-plane.yaml"), "utf8");

test("PB01 policy consumes only the canonical complete baseline contract", () => {
  const report = evaluateBrownfieldControlPlane({
    policy,
    composeText,
    liveBaseline: { schema: "platform-live-preservation-baseline/v1", complete: true },
  });
  assert.equal(report.status, "LOCAL-NOT-PREPARED");
  assert.equal(report.deploymentAuthorized, false);
  assert.equal(report.rawBrokerEligible, false);
  assert.deepEqual(report.actions, []);
  assert.equal(report.candidateEvidenceClass, "STRUCTURAL-EXPECTATION-NOT-OBSERVATION");
  assert.ok(report.providerGates.every((gate) => gate.status === "EXTERNAL-PENDING"));
  assert.match(report.failures.join("\n"), /platform\.live-preservation-baseline\/v1|closed schema/i);
});

test("PB02 governance distinguishes total, named, and anonymous volume floors", () => {
  assert.equal(policy.preservation.preserveAllExistingVolumes, true);
  assert.equal(policy.preservation.preserveAllExistingNamedVolumes, true);
  assert.equal(policy.preservation.preserveAllExistingAnonymousVolumes, true);
  assert.deepEqual(policy.preservation.minimumObservedVolumes, {
    total: 139,
    named: 12,
    anonymous: 127,
  });
  assert.equal(Object.hasOwn(policy.preservation, "minimumObservedNamedVolumes"), false);
  assert.equal(JSON.stringify(policy).includes('"minimumObservedNamedVolumes":139'), false);
});

test("PB03 Compose-local singleton does not claim live raw-broker eligibility", () => {
  const compose = parseBrownfieldControlPlaneCompose(composeText);
  assert.deepEqual(compose.rawSocketOwners, ["docker-action-broker"]);
  const report = evaluateBrownfieldControlPlane({
    policy,
    composeText,
    liveBaseline: null,
  });
  assert.equal(report.status, "LOCAL-NOT-PREPARED");
  assert.equal(report.rawBrokerEligible, false);
  assert.match(report.blockingConditions.join("\n"), /complete canonical baseline|live authority/i);
});

test("PB04 unresolved rendered binds and secret files remain explicit blockers", () => {
  const report = evaluateBrownfieldControlPlane({ policy, composeText, liveBaseline: null });
  assert.match(report.blockingConditions.join("\n"), /rendered compose/i);
  assert.match(report.blockingConditions.join("\n"), /secret.*identit/i);
  assert.match(report.blockingConditions.join("\n"), /secret file sources remain unresolved/i);
  assert.equal(report.deploymentAuthorized, false);
});

test("PB05 the local contract can never report prepared, satisfied, ready, or authorized", () => {
  assert.equal(policy.status, "LOCAL-NOT-PREPARED");
  assert.equal(policy.deploymentAuthority, false);
  assert.equal(policy.rawBrokerEligibility, false);
  const report = evaluateBrownfieldControlPlane({ policy, composeText, liveBaseline: null });
  assert.equal(report.ok, false);
  assert.equal(report.status, "LOCAL-NOT-PREPARED");
  assert.equal(report.deploymentAuthorized, false);
  assert.equal(report.rawBrokerEligible, false);
  assert.doesNotMatch(JSON.stringify(report), /PREREQUISITES-SATISFIED|\"status\":\"READY\"|deploymentAuthorized\":true/);
});

test("the isolated source model remains exact and cannot widen authority", () => {
  const compose = parseBrownfieldControlPlaneCompose(composeText);
  assert.equal(compose.name, "platform_infra_v1_control");
  assert.deepEqual(Object.keys(compose.services).sort(), [
    "docker-action-activation-sidecar",
    "docker-action-broker",
  ]);
  assert.deepEqual(Object.keys(compose.volumes).sort(), [
    "backup_scheduler_jobs",
    "docker_action_activation_cas",
    "docker_action_broker_socket",
    "docker_action_broker_state",
  ]);
  assert.deepEqual(Object.keys(compose.networks), []);
  assert.ok(!composeText.includes("container_name:"));

  for (const mutant of [
    composeText.replace("name: platform_infra_v1_control", "name: platform_infra_vps"),
    composeText.replace("network_mode: none", "network_mode: bridge"),
    composeText.replace("  docker_action_broker_state: {}", "  docker_action_broker_state:\n    external: true"),
    composeText.replace("read_only: true", "read_only: false"),
    composeText.replace("@sha256:${PLATFORM_DOCKER_ACTION_BROKER_IMAGE_SHA256:?set broker image sha256}", ":latest"),
  ]) {
    const report = evaluateBrownfieldControlPlane({ policy, composeText: mutant, liveBaseline: null });
    assert.equal(report.structurallyValid, false);
    assert.equal(report.status, "LOCAL-NOT-PREPARED");
    assert.equal(report.deploymentAuthorized, false);
  }
});
