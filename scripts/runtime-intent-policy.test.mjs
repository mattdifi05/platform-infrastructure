#!/usr/bin/env node
import assert from "node:assert/strict";
import {
  canonicalJson,
  PRODUCTION_PROJECT_NAME,
  runtimeIntentSha256,
  validateRuntimeIntent,
} from "./runtime-intent-policy.mjs";

const repository = "owner/repo";
const commitSha = "a".repeat(40);
const treeSha = "b".repeat(40);
const sourceArchiveSha256 = "c".repeat(64);
const artifactImage = `ghcr.io/owner/platform-infrastructure-control-center@sha256:${"d".repeat(64)}`;
const schedulerImage = `ghcr.io/owner/platform-infrastructure-backup-scheduler@sha256:${"7".repeat(64)}`;
const opsImage = `ghcr.io/owner/platform-infrastructure-ops@sha256:${"e".repeat(64)}`;
const opsImageId = `sha256:${"f".repeat(64)}`;
const artifactSubjects = [
  { key: "CONTROL_CENTER_IMAGE", image: artifactImage },
  { key: "PLATFORM_BACKUP_SCHEDULER_IMAGE", image: schedulerImage },
];
const artifactPlatformImageIds = {
  CONTROL_CENTER_IMAGE: `sha256:${"4".repeat(64)}`,
  PLATFORM_BACKUP_SCHEDULER_IMAGE: `sha256:${"8".repeat(64)}`,
};
const opsRunner = { image: opsImage, imageId: opsImageId };
const persistentVolumes = [{
  name: "enterprise_local_registry_data",
  createdAt: "2026-07-21T00:00:00.000Z",
  driver: "local",
  scope: "local",
  options: {},
  labels: {
    "platform.infrastructure.managed": "true",
    "platform.infrastructure.purpose": "local-registry",
  },
  mountpoint: "/var/lib/docker/volumes/enterprise_local_registry_data/_data",
  owner: { uid: 0, gid: 0, mode: "0755" },
}];
const intent = {
  version: 2,
  kind: "platform-runtime-intent/v2",
  repository,
  commitSha,
  treeSha,
  sourceArchiveSha256,
  projectName: PRODUCTION_PROJECT_NAME,
  environmentSha256: "1".repeat(64),
  hostedWorkloadLockSha256: null,
  sourceRenderSha256: "2".repeat(64),
  combinedComposeSha256: "3".repeat(64),
  persistentVolumes,
  services: [
    {
      service: "backup-scheduler",
      image: schedulerImage,
      admission: { kind: "artifact-subject", subjectKey: "PLATFORM_BACKUP_SCHEDULER_IMAGE" },
      expectedLocalImageId: `sha256:${"8".repeat(64)}`,
    },
    {
      service: "control-center",
      image: artifactImage,
      admission: { kind: "artifact-subject", subjectKey: "CONTROL_CENTER_IMAGE" },
      expectedLocalImageId: `sha256:${"4".repeat(64)}`,
    },
    {
      service: "traefik",
      image: `docker.io/library/traefik@sha256:${"5".repeat(64)}`,
      admission: { kind: "external-digest", sourceKey: "TRAEFIK_IMAGE" },
      expectedLocalImageId: `sha256:${"6".repeat(64)}`,
    },
  ],
  targetServingServices: ["control-center", "traefik"],
};
const options = { repository, commitSha, treeSha, sourceArchiveSha256, artifactSubjects, artifactPlatformImageIds, opsRunner };

const validated = validateRuntimeIntent(intent, options);
assert.equal(validated.sha256, runtimeIntentSha256(intent));
assert.equal(
  canonicalJson({ z: [3, { b: true, a: null }], a: "x" }),
  '{"a":"x","z":[3,{"a":null,"b":true}]}',
);
assert.equal(runtimeIntentSha256(intent), runtimeIntentSha256(JSON.parse(JSON.stringify(intent))));
assert.throws(() => validateRuntimeIntent({ ...intent, extra: true }, options), /closed schema/);
assert.throws(() => validateRuntimeIntent({ ...intent, commitSha: "9".repeat(40) }, options), /binding/);
assert.throws(() => validateRuntimeIntent({ ...intent, projectName: "attacker" }, options), /projectName/);
assert.throws(() => validateRuntimeIntent({ ...intent, environmentSha256: "bad" }, options), /environment/);
assert.throws(() => validateRuntimeIntent({ ...intent, targetServingServices: ["traefik", "control-center"] }, options), /sorted/);
assert.throws(() => validateRuntimeIntent({ ...intent, targetServingServices: ["missing"] }, options), /subset/);
assert.throws(() => validateRuntimeIntent({
  ...intent,
  persistentVolumes: persistentVolumes.map((volume) => ({ ...volume, driver: "local-persist" })),
}, options), /name, driver and scope/);
assert.throws(() => validateRuntimeIntent({
  ...intent,
  persistentVolumes: persistentVolumes.map((volume) => ({
    ...volume,
    owner: { ...volume.owner, mode: "0777" },
  })),
}, options), /root-owned/);
assert.throws(() => validateRuntimeIntent({
  ...intent,
  services: intent.services.map((entry) => entry.service === "control-center"
    ? { ...entry, image: `ghcr.io/owner/attacker@sha256:${"d".repeat(64)}` }
    : entry),
}, options), /artifact release subject/);
assert.throws(() => validateRuntimeIntent({
  ...intent,
  services: intent.services.map((entry) => entry.service === "backup-scheduler"
    ? { ...entry, expectedLocalImageId: `sha256:${"9".repeat(64)}` }
    : entry),
}, options), /platform image ID/);
assert.throws(() => validateRuntimeIntent({
  ...intent,
  services: intent.services.map((entry) => entry.service === "backup-scheduler"
    ? { ...entry, image: opsImage, admission: { kind: "ops-runner" }, expectedLocalImageId: opsImageId }
    : entry),
}, options), /may not reuse|may not execute/);
assert.throws(() => validateRuntimeIntent({
  ...intent,
  services: intent.services.filter((entry) => entry.service !== "control-center"),
}, options), /complete artifact release subject set/);
assert.throws(() => validateRuntimeIntent({
  ...intent,
  services: [...intent.services, { ...intent.services[2] }],
}, options), /duplicated/);

process.stdout.write("runtime intent policy tests passed 16/16\n");
