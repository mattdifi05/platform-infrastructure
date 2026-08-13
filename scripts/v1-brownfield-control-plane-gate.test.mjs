import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  sealLivePreservationBaseline,
  validateLivePreservationBaseline,
} from "./live-preservation-baseline.mjs";
import {
  ACTIVATION_SCOPE,
  CANDIDATE_EXPECTATIONS,
  CONTROL_PROJECT_NAME,
  MUTATION_SERVICES,
  PROVIDER_GATES,
  comparePreservation,
  evaluateApplyPrerequisites,
  inspectBrownfieldBaseline,
  planBrownfieldControlPlane,
} from "./v1-brownfield-control-plane-gate.mjs";

const HASH = "a".repeat(64);
const REAL_BASELINE = path.resolve(
  import.meta.dirname,
  "..",
  "reports",
  "preservation-baselines",
  "live-server-20260809T041407Z.json",
);
const SCRIPT = path.join(import.meta.dirname, "v1-brownfield-control-plane-gate.mjs");

function identity(index, { type = "directory", mode = "0755" } = {}) {
  return {
    type,
    device: "1",
    inode: String(index + 1),
    uid: 0,
    gid: 0,
    mode,
    nlink: 1,
  };
}

function canonicalContainer(index) {
  const suffix = String(index + 1).padStart(2, "0");
  const digest = (index + 1).toString(16).padStart(64, "0");
  return {
    id: digest,
    name: `legacy-container-${suffix}`,
    project: null,
    service: null,
    imageRef: `registry.invalid/legacy-${suffix}@sha256:${digest}`,
    imageId: `sha256:${digest}`,
    createdAt: "2026-08-09T04:00:00.000Z",
    state: "running",
    health: "healthy",
    exitCode: 0,
    configHash: digest,
    configuredUser: "0:0",
    effectiveUid: 0,
    effectiveGid: 0,
    readOnlyRootfs: true,
    privileged: false,
    mounts: [],
    networks: [],
    ports: [],
    environmentKeys: [],
  };
}

function canonicalVolume(index) {
  const anonymous = index >= 12;
  const name = anonymous
    ? (index + 1000).toString(16).padStart(64, "0")
    : `legacy_named_${String(index + 1).padStart(3, "0")}`;
  return {
    name,
    nameClass: anonymous ? "ANONYMOUS" : "NAMED",
    driver: "local",
    scope: "local",
    mountpoint: `/var/lib/docker/volumes/${name}/_data`,
    createdAt: "2026-08-09T03:00:00.000Z",
    optionsSha256: HASH,
    labelsSha256: HASH,
    composeProject: null,
    composeVolume: null,
    fsIdentity: identity(index + 100),
    observedBytes: 0,
    attachments: [],
    dangling: true,
  };
}

function completeCanonicalBaseline() {
  const containers = Array.from({ length: 34 }, (_, index) => canonicalContainer(index))
    .sort((left, right) => left.name.localeCompare(right.name));
  const volumes = Array.from({ length: 139 }, (_, index) => canonicalVolume(index))
    .sort((left, right) => left.name.localeCompare(right.name));
  return sealLivePreservationBaseline({
    schema: "platform.live-preservation-baseline/v1",
    baselineId: "0".repeat(64),
    scope: "platform-infrastructure",
    evidenceClass: "SYNTHETIC-TEST",
    synthetic: true,
    complete: true,
    status: "COMPLETE-PRESERVATION-BASELINE",
    gateAdmissible: false,
    mutationAuthority: false,
    effect: "DENY-ONLY",
    identityObservationMode: "POINT-IN-TIME",
    capturedAt: {
      startedAt: "2026-08-09T04:14:07.000Z",
      completedAt: "2026-08-09T04:15:07.000Z",
    },
    host: {
      hostname: "synthetic-host",
      machineIdSha256: HASH,
      bootId: "00000000-0000-4000-8000-000000000001",
      sshHostKeySha256: HASH,
      dockerDaemonId: "SYNTHETIC-DAEMON-ID",
      dockerRootDir: "/var/lib/docker",
      dockerRootIdentity: identity(1),
      os: {
        id: "ubuntu",
        versionId: "26.04",
        kernel: "7.0.0-test",
        architecture: "x86_64",
      },
      principal: { uid: 1000, gid: 1000 },
    },
    source: {
      kind: "SYNTHETIC",
      referenceSha256: HASH,
      captureOutputs: [{ kind: "synthetic-fixture", callIdSha256: HASH, outputSha256: HASH }],
      capturedProjectionDigests: [{ kind: "docker-volume-full-inventory", sha256: HASH }],
      rawEvidenceCommitted: false,
      secretValuesCaptured: false,
      collectionMutatedLive: false,
    },
    policy: {
      unknownResourceDisposition: "PRESERVE",
      missingResourceDisposition: "STOP",
      changedResourceDisposition: "STOP",
      globalTeardownAllowed: false,
      removeOrphansAllowed: false,
      pruneAllowed: false,
      foreignResourceMutationAllowed: false,
    },
    redaction: {
      secretValuesCaptured: false,
      environmentValuesCaptured: false,
      databaseRowsCaptured: false,
      privateKeysCaptured: false,
      environmentKeyNamesCaptured: true,
    },
    summary: {
      containers: 34,
      volumes: 139,
      attachedVolumes: 0,
      danglingVolumes: 139,
      namedVolumes: 12,
      anonymousVolumes: 127,
      bindMounts: 0,
      sourceRoots: 0,
      networks: 0,
      hostListeners: 0,
      databases: 0,
      applications: 1,
      secretMetadataRecords: 0,
    },
    checkouts: [],
    composeProjects: [],
    containers,
    volumes,
    bindMounts: [],
    sourceRoots: [],
    networks: [],
    hostListeners: [],
    databases: [],
    secretMetadata: [],
    logicalRecoveryAnchors: [{
      id: "synthetic-legacy-estate",
      displayName: "Synthetic legacy estate",
      mappingState: "MAPPED",
      sourceRootRefs: [],
      sourceBindRefs: [],
      containerRefs: containers.map((entry) => entry.name),
      databaseRefs: [],
      storageRefs: volumes.map((entry) => entry.name),
      configRefs: [],
      secretMetadataRefs: [],
    }],
    digests: {
      checkoutsSha256: "0".repeat(64),
      composeProjectsSha256: "0".repeat(64),
      containersSha256: "0".repeat(64),
      volumesSha256: "0".repeat(64),
      bindMountsSha256: "0".repeat(64),
      sourceRootsSha256: "0".repeat(64),
      networksSha256: "0".repeat(64),
      hostListenersSha256: "0".repeat(64),
      databasesSha256: "0".repeat(64),
      secretMetadataSha256: "0".repeat(64),
      logicalRecoveryAnchorsSha256: "0".repeat(64),
    },
    deficiencies: [],
  });
}

function addBind(baseline, {
  source,
  destination,
  containerName = baseline.containers[0].name,
  classification = "HOST-API",
  type = "directory",
  mode = "0755",
  readOnly = true,
}) {
  const changed = structuredClone(baseline);
  const container = changed.containers.find((entry) => entry.name === containerName);
  container.mounts.push({ kind: "bind", sourceRef: source, destination, readOnly, propagation: "" });
  container.mounts.sort((left, right) => (
    `${left.destination}\0${left.kind}\0${left.sourceRef}`
      .localeCompare(`${right.destination}\0${right.kind}\0${right.sourceRef}`)
  ));
  changed.bindMounts.push({
    source,
    canonicalPath: source,
    classification,
    lstatIdentity: identity(600 + changed.bindMounts.length, { type, mode }),
    targetIdentity: identity(700 + changed.bindMounts.length, { type, mode }),
    contentSha256: null,
    consumers: [{ containerName, destination, readOnly }],
  });
  changed.bindMounts.sort((left, right) => left.source.localeCompare(right.source));
  changed.logicalRecoveryAnchors[0].sourceBindRefs.push(source);
  changed.logicalRecoveryAnchors[0].sourceBindRefs.sort((left, right) => left.localeCompare(right));
  changed.summary.bindMounts = changed.bindMounts.length;
  return sealLivePreservationBaseline(changed);
}

function incompleteBaseline() {
  const baseline = completeCanonicalBaseline();
  baseline.complete = false;
  baseline.status = "INCOMPLETE-NO-GO";
  baseline.volumes[0].fsIdentity = null;
  baseline.deficiencies = [{
    code: "MISSING-FS-IDENTITY",
    resourceClass: "volume",
    resourceId: baseline.volumes[0].name,
    field: "fsIdentity",
    reason: "Synthetic incomplete negative fixture.",
  }];
  return sealLivePreservationBaseline(baseline);
}

test("PB01 canonical baseline is the only accepted shape and incomplete live evidence stops", () => {
  const complete = completeCanonicalBaseline();
  assert.equal(validateLivePreservationBaseline(complete, { requireComplete: true }).complete, true);

  const reference = planBrownfieldControlPlane({ preBaseline: complete });
  assert.equal(reference.status, "LOCAL-NOT-PREPARED");
  assert.doesNotMatch(reference.blockingConditions.join("\n"), /schema must be platform\.live-preservation-baseline/);

  const privateShape = planBrownfieldControlPlane({
    preBaseline: { schema: "platform-live-preservation-baseline/v1", complete: true },
  });
  assert.equal(privateShape.status, "LOCAL-NOT-PREPARED");
  assert.match(privateShape.blockingConditions.join("\n"), /platform\.live-preservation-baseline\/v1|closed schema/i);

  const incomplete = planBrownfieldControlPlane({ preBaseline: incompleteBaseline() });
  assert.match(incomplete.blockingConditions.join("\n"), /INCOMPLETE-NO-GO|complete preservation/i);

  if (fs.existsSync(REAL_BASELINE)) {
    const live = JSON.parse(fs.readFileSync(REAL_BASELINE, "utf8"));
    const livePlan = planBrownfieldControlPlane({ preBaseline: live });
    assert.equal(livePlan.status, "LOCAL-NOT-PREPARED");
    assert.match(livePlan.blockingConditions.join("\n"), /INCOMPLETE-NO-GO|complete preservation/i);
    assert.match(livePlan.authorityConflicts.join("\n"), /raw-docker-socket:enterprise-backup-scheduler/);
    assert.match(livePlan.authorityConflicts.join("\n"), /host-parent-authority:enterprise-(?:cadvisor|node-exporter)/);
  }
});

test("PB02 volume accounting is 139 total, 12 named, and 127 anonymous", () => {
  const baseline = completeCanonicalBaseline();
  assert.deepEqual(
    {
      total: baseline.summary.volumes,
      named: baseline.summary.namedVolumes,
      anonymous: baseline.summary.anonymousVolumes,
    },
    { total: 139, named: 12, anonymous: 127 },
  );
  const plan = planBrownfieldControlPlane({ preBaseline: baseline });
  assert.doesNotMatch(plan.blockingConditions.join("\n"), /volume floor/i);

  const forged = structuredClone(baseline);
  forged.summary.namedVolumes = 139;
  const stopped = planBrownfieldControlPlane({ preBaseline: sealLivePreservationBaseline(forged) });
  assert.match(stopped.blockingConditions.join("\n"), /summary does not match/i);
});

test("PB03 every existing raw Docker or host-parent authority blocks the additive broker", () => {
  const raw = addBind(completeCanonicalBaseline(), {
    source: "/var/run/docker.sock",
    destination: "/var/run/docker.sock",
    classification: "SOCKET",
    type: "socket",
    mode: "0660",
    readOnly: false,
  });
  const rawInspection = inspectBrownfieldBaseline(raw);
  assert.match(rawInspection.authorityConflicts.join("\n"), /raw-docker-socket:legacy-container-01/);
  assert.match(planBrownfieldControlPlane({ preBaseline: raw }).blockingConditions.join("\n"), /raw-docker-socket/);

  for (const source of ["/", "/run", "/var/run", "/var/lib/docker"]) {
    const hostParent = addBind(completeCanonicalBaseline(), {
      source,
      destination: source === "/" ? "/host" : source,
    });
    assert.match(
      planBrownfieldControlPlane({ preBaseline: hostParent }).blockingConditions.join("\n"),
      /host-parent-authority/,
      source,
    );
  }
});

test("PB04 canonical bind sources and candidate bind targets collide fail-closed", () => {
  const sourceCollision = addBind(completeCanonicalBaseline(), {
    source: "/srv/platform-infrastructure/platform-activation",
    destination: "/legacy/active.json",
    classification: "CONFIG",
    type: "regular-file",
    mode: "0440",
  });
  const sourcePlan = planBrownfieldControlPlane({ preBaseline: sourceCollision });
  assert.match(sourcePlan.bindCollisions.join("\n"), /candidate-source/);
  assert.deepEqual(sourcePlan.actions, []);

  const targetCollision = addBind(completeCanonicalBaseline(), {
    source: "/srv/legacy/runtime-intent.json",
    destination: "/run/platform/docker-action-trust/runtime-intent.json",
    classification: "CONFIG",
    type: "regular-file",
    mode: "0440",
  });
  const targetPlan = planBrownfieldControlPlane({ preBaseline: targetCollision });
  assert.match(targetPlan.bindCollisions.join("\n"), /candidate-target/);
  assert.deepEqual(targetPlan.actions, []);

  const secretTargetCollision = addBind(completeCanonicalBaseline(), {
    source: "/srv/legacy/secret-key",
    destination: "/run/secrets/docker_action_runtime_intent_trust_key",
    classification: "SECRET-METADATA",
    type: "regular-file",
    mode: "0400",
  });
  assert.match(
    planBrownfieldControlPlane({ preBaseline: secretTargetCollision }).bindCollisions.join("\n"),
    /candidate-target:.*\/run\/secrets\/docker_action_runtime_intent_trust_key/,
  );
});

test("PB05 expectations are structural only and cannot fabricate observed identity or eligibility", () => {
  assert.equal(CONTROL_PROJECT_NAME, "platform_infra_v1_control");
  assert.deepEqual(MUTATION_SERVICES, [
    "docker-action-activation-sidecar",
    "docker-action-broker",
  ]);
  assert.deepEqual(ACTIVATION_SCOPE.replaceableServices, []);
  const serialized = JSON.stringify(CANDIDATE_EXPECTATIONS);
  assert.doesNotMatch(serialized, /sourceIdentity|device|inode|imageId|configHash|running-healthy|exited-0/);
  assert.match(serialized, /STRUCTURAL-EXPECTATION-NOT-OBSERVATION/);

  const plan = planBrownfieldControlPlane({ preBaseline: completeCanonicalBaseline() });
  assert.equal(plan.status, "LOCAL-NOT-PREPARED");
  assert.equal(plan.referenceOnly, true);
  assert.equal(plan.executionAuthorized, false);
  assert.equal(plan.rawBrokerEligible, false);
  assert.deepEqual(plan.actions, []);
  assert.equal(plan.candidateEvidenceClass, "STRUCTURAL-EXPECTATION-NOT-OBSERVATION");
  assert.deepEqual(plan.providerGates, PROVIDER_GATES);
  assert.ok(plan.providerGates.every((gate) => gate.status === "EXTERNAL-PENDING"));
  assert.doesNotMatch(JSON.stringify(plan), /PREREQUISITES-SATISFIED|\"status\":\"READY\"|executionAuthorized\":true/);

  const forged = evaluateApplyPrerequisites({
    plan,
    providerPolicy: { status: "READY", authenticated: true },
    providerBinding: { status: "READY", authenticated: true },
    signedJournal: { status: "SIGNED", signatureVerified: true },
    preBaseline: completeCanonicalBaseline(),
  });
  assert.equal(forged.status, "STOP");
  assert.equal(forged.prerequisitesSatisfied, false);
  assert.equal(forged.executionAuthorized, false);
  assert.ok(forged.providerGates.every((gate) => gate.status === "EXTERNAL-PENDING"));
});

test("canonical preservation comparison never becomes mutation authority", () => {
  const baseline = completeCanonicalBaseline();
  const comparison = comparePreservation({ preBaseline: baseline, postBaseline: baseline });
  assert.equal(comparison.status, "PASS-PRESERVATION-ONLY");
  assert.equal(comparison.mutationAuthorized, false);

  const changed = structuredClone(baseline);
  changed.containers[0].state = "exited";
  const stopped = comparePreservation({ preBaseline: baseline, postBaseline: sealLivePreservationBaseline(changed) });
  assert.equal(stopped.status, "STOP");
});

test("CLI apply always stops before any executor and plan remains non-prepared", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-brownfield-gate-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, "input.json");
  fs.writeFileSync(input, `${JSON.stringify({ preBaseline: completeCanonicalBaseline() })}\n`);

  const planned = spawnSync(process.execPath, [SCRIPT, "plan", "--input", input], { encoding: "utf8" });
  assert.notEqual(planned.status, 0);
  assert.match(planned.stdout, /LOCAL-NOT-PREPARED/);
  assert.doesNotMatch(planned.stdout + planned.stderr, /docker compose|docker create|docker start/i);

  const applied = spawnSync(process.execPath, [SCRIPT, "apply", "--input", input], { encoding: "utf8" });
  assert.equal(applied.status, 78);
  assert.match(applied.stdout, /LOCAL-NOT-PREPARED|STOP/);
  assert.doesNotMatch(applied.stdout + applied.stderr, /docker compose|docker create|docker start/i);
});
