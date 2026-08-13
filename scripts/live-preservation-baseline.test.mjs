import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  compareLivePreservationBaseline,
  sealLivePreservationBaseline,
  validateLivePreservationBaseline,
} from "./live-preservation-baseline.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const SCHEMA = path.join(ROOT, "governance", "schemas", "live-preservation-baseline.schema.json");
const REAL_BASELINE_OVERRIDE = process.env.LIVE_PRESERVATION_BASELINE_PATH;
const REAL_BASELINE = REAL_BASELINE_OVERRIDE
  ? path.resolve(REAL_BASELINE_OVERRIDE)
  : path.join(ROOT, "reports", "preservation-baselines", "live-server-20260809T041407Z.json");
const HASH = "a".repeat(64);

function fsIdentity(index, { mode = "0755", type = "directory" } = {}) {
  return {
    type,
    device: String(100 + index),
    inode: String(1000 + index),
    uid: 0,
    gid: 0,
    mode,
    nlink: 2,
  };
}

function syntheticBaseline({ complete = true } = {}) {
  const containerNames = Array.from({ length: 34 }, (_, index) => `legacy-app-${String(index).padStart(3, "0")}`);
  const anonymousNames = Array.from({ length: 127 }, (_, index) => (index + 1).toString(16).padStart(64, "0"));
  const namedNames = Array.from({ length: 12 }, (_, index) => `enterprise_volume_${String(index).padStart(3, "0")}`);
  const volumeNames = [...anonymousNames, ...namedNames].sort();
  const attachedNames = new Set(volumeNames.slice(0, 15));

  const containers = containerNames.map((name, index) => {
    const volume = volumeNames[index < 15 ? index : 0];
    const mounts = index < 15
      ? [{ kind: "volume", sourceRef: volume, destination: "/data", readOnly: false, propagation: "rprivate" }]
      : [];
    if (index < 2) {
      mounts.push({
        kind: "bind",
        sourceRef: `/srv/apps/app-${index}`,
        destination: "/srv/app",
        readOnly: false,
        propagation: "rprivate",
      });
    }
    return {
      id: (index + 1000).toString(16).padStart(64, "0"),
      name,
      project: "legacy_live",
      service: `service-${String(index).padStart(3, "0")}`,
      imageRef: `registry.invalid/legacy/app-${index}@sha256:${(index + 2000).toString(16).padStart(64, "0")}`,
      imageId: `sha256:${(index + 3000).toString(16).padStart(64, "0")}`,
      createdAt: "2026-08-09T03:00:00.000Z",
      state: "running",
      health: "healthy",
      exitCode: 0,
      configHash: (index + 4000).toString(16).padStart(64, "0"),
      configuredUser: "1000:1000",
      effectiveUid: 1000,
      effectiveGid: 1000,
      readOnlyRootfs: false,
      privileged: false,
      mounts: mounts.sort((left, right) => left.destination.localeCompare(right.destination)),
      networks: [{
        networkRef: "enterprise_net",
        endpointId: (index + 5000).toString(16).padStart(64, "0"),
        ipv4: `172.30.0.${index + 2}/24`,
        ipv6: "",
        macAddress: `02:42:ac:1e:00:${(index + 2).toString(16).padStart(2, "0")}`,
        aliases: [name],
      }],
      ports: index === 0
        ? [{ protocol: "tcp", containerPort: 8080, hostIp: "127.0.0.1", hostPort: 18080 }]
        : [],
      environmentKeys: ["APP_ENV", "DATABASE_URL_FILE"],
    };
  });

  const volumes = volumeNames.map((name, index) => {
    const attached = attachedNames.has(name);
    const containerIndex = attached ? volumeNames.indexOf(name) : -1;
    return {
      name,
      nameClass: /^[a-f0-9]{64}$/.test(name) ? "ANONYMOUS" : "NAMED",
      driver: "local",
      scope: "local",
      mountpoint: `/var/lib/docker/volumes/${name}/_data`,
      createdAt: "2026-08-01T00:00:00.000Z",
      optionsSha256: HASH,
      labelsSha256: HASH,
      composeProject: name.startsWith("enterprise_") ? "legacy_live" : "",
      composeVolume: name.startsWith("enterprise_") ? name.replace(/^enterprise_/, "") : "",
      fsIdentity: fsIdentity(index + 20),
      observedBytes: index * 1024,
      attachments: attached
        ? [{ containerName: containerNames[containerIndex], destination: "/data", readOnly: false }]
        : [],
      dangling: !attached,
    };
  });

  const bindMounts = [0, 1].map((index) => ({
    source: `/srv/apps/app-${index}`,
    canonicalPath: `/srv/apps/app-${index}`,
    classification: "APPLICATION-DATA",
    lstatIdentity: fsIdentity(index + 200),
    targetIdentity: fsIdentity(index + 200),
    contentSha256: null,
    consumers: [{ containerName: containerNames[index], destination: "/srv/app", readOnly: false }],
  }));

  const networks = [{
    id: "b".repeat(64),
    name: "enterprise_net",
    driver: "bridge",
    scope: "local",
    internal: false,
    attachable: false,
    ingress: false,
    ipam: [{ subnet: "172.30.0.0/24", gateway: "172.30.0.1" }],
    optionsSha256: HASH,
    labelsSha256: HASH,
    endpoints: containers.map((container) => ({
      containerName: container.name,
      endpointId: container.networks[0].endpointId,
      ipv4: container.networks[0].ipv4,
      ipv6: container.networks[0].ipv6,
      macAddress: container.networks[0].macAddress,
      aliases: container.networks[0].aliases,
    })),
  }];

  const document = {
    schema: "platform.live-preservation-baseline/v1",
    baselineId: "0".repeat(64),
    scope: "platform-infrastructure",
    evidenceClass: "SYNTHETIC-TEST",
    synthetic: true,
    complete,
    status: complete ? "COMPLETE-PRESERVATION-BASELINE" : "INCOMPLETE-NO-GO",
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
      dockerRootIdentity: fsIdentity(1),
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
      containers: containers.length,
      volumes: volumes.length,
      attachedVolumes: volumes.filter((volume) => !volume.dangling).length,
      danglingVolumes: volumes.filter((volume) => volume.dangling).length,
      namedVolumes: volumes.filter((volume) => volume.nameClass === "NAMED").length,
      anonymousVolumes: volumes.filter((volume) => volume.nameClass === "ANONYMOUS").length,
      bindMounts: bindMounts.length,
      sourceRoots: bindMounts.length,
      networks: networks.length,
      hostListeners: 1,
      databases: 3,
      applications: 3,
      secretMetadataRecords: 2,
    },
    checkouts: [{
      id: "active-live",
      role: "ACTIVE-LIVE",
      path: "/srv/platform-infrastructure",
      commit: "c".repeat(40),
      tree: "d".repeat(40),
      branch: "main",
      dirty: false,
      dirtyPathCount: 0,
      statusSha256: HASH,
      fsIdentity: fsIdentity(2),
    }],
    composeProjects: [{
      name: "legacy_live",
      workingDirectories: ["/srv/platform-infrastructure"],
      configFiles: [{
        path: "/srv/platform-infrastructure/compose.yaml",
        sensitivity: "NON-SECRET-CONFIG",
        contentCaptured: true,
        sha256: HASH,
        fsIdentity: fsIdentity(3, { mode: "0644", type: "regular-file" }),
      }],
      containerNames,
    }],
    containers,
    volumes,
    bindMounts,
    sourceRoots: bindMounts.map((entry, index) => ({
      path: entry.source,
      fsIdentity: fsIdentity(index + 200),
      observedBytes: 4096 * (index + 1),
      fileCount: 10 * (index + 1),
      mounted: true,
    })),
    networks,
    hostListeners: [{ protocol: "tcp", address: "127.0.0.1", port: 18080, ownerClass: "docker-proxy", uid: 0 }],
    databases: [{
      id: "mariadb:app_a",
      engine: "MARIADB",
      engineVersion: "12.3.2",
      serverContainer: containerNames[0],
      name: "app_a",
      kind: "APPLICATION",
      owner: "app_a",
      tableCount: 10,
      catalogSha256: HASH,
      storageRefs: [volumeNames[0]],
    }, {
      id: "postgres:keycloak",
      engine: "POSTGRESQL",
      engineVersion: "18.4",
      serverContainer: containerNames[1],
      name: "keycloak",
      kind: "PLATFORM",
      owner: "keycloak",
      tableCount: 91,
      catalogSha256: HASH,
      storageRefs: [volumeNames[1]],
    }, {
      id: "redis:0",
      engine: "REDIS",
      engineVersion: "8.6.4",
      serverContainer: containerNames[2],
      name: "0",
      kind: "PLATFORM",
      owner: null,
      tableCount: null,
      catalogSha256: HASH,
      storageRefs: [volumeNames[2]],
    }],
    secretMetadata: [{
      id: "secret-metadata:app-a",
      kind: "ENV-FILE",
      path: "/srv/platform-infrastructure/.env.app-a",
      fsIdentity: fsIdentity(900, { mode: "0600", type: "regular-file" }),
      environmentKeys: ["APP_A_DATABASE_PASSWORD"],
      contentCaptured: false,
      valuesCaptured: false,
    }, {
      id: "secret-metadata:app-b",
      kind: "SECRET-FILE",
      path: "/srv/platform-infrastructure/secrets/app-b-password",
      fsIdentity: fsIdentity(901, { mode: "0600", type: "regular-file" }),
      environmentKeys: [],
      contentCaptured: false,
      valuesCaptured: false,
    }],
    logicalRecoveryAnchors: [{
      id: "app-a",
      displayName: "Application A",
      mappingState: "MAPPED",
      sourceRootRefs: ["/srv/apps/app-0"],
      sourceBindRefs: ["/srv/apps/app-0"],
      containerRefs: [containerNames[0]],
      databaseRefs: ["mariadb:app_a"],
      storageRefs: [volumeNames[0]],
      configRefs: ["/srv/platform-infrastructure/compose.yaml"],
      secretMetadataRefs: ["secret-metadata:app-a"],
    }, {
      id: "app-b",
      displayName: "Application B",
      mappingState: "MAPPED",
      sourceRootRefs: ["/srv/apps/app-1"],
      sourceBindRefs: ["/srv/apps/app-1"],
      containerRefs: [containerNames[1]],
      databaseRefs: ["postgres:keycloak"],
      storageRefs: [volumeNames[1]],
      configRefs: ["/srv/platform-infrastructure/compose.yaml"],
      secretMetadataRefs: ["secret-metadata:app-b"],
    }, {
      id: "shared-cache",
      displayName: "Shared cache",
      mappingState: "MAPPED",
      sourceRootRefs: [],
      sourceBindRefs: [],
      containerRefs: containerNames.slice(2),
      databaseRefs: ["redis:0"],
      storageRefs: volumeNames.slice(2),
      configRefs: ["/srv/platform-infrastructure/compose.yaml"],
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
    deficiencies: complete ? [] : [{
      code: "SYNTHETIC-MISSING-EVIDENCE",
      resourceClass: "volume",
      resourceId: volumeNames[0],
      field: "fsIdentity",
      reason: "Synthetic negative fixture deliberately omits complete evidence.",
    }],
  };

  if (!complete) document.volumes[0].fsIdentity = null;
  return sealLivePreservationBaseline(document);
}

function clone(value) {
  return structuredClone(value);
}

function assertClosedObjectSchemas(value, location = "$") {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertClosedObjectSchemas(entry, `${location}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (value.type === "object") {
    assert.equal(value.additionalProperties, false, `${location} must reject additional properties`);
    assert.deepEqual(
      [...(value.required ?? [])].sort(),
      Object.keys(value.properties ?? {}).sort(),
      `${location} must require every declared property`,
    );
  }
  Object.entries(value).forEach(([key, entry]) => assertClosedObjectSchemas(entry, `${location}.${key}`));
}

test("published preservation baseline schema is closed and deny-only", () => {
  const schema = JSON.parse(readFileSync(SCHEMA, "utf8"));
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(schema.$id, "urn:platform-infrastructure:schema:live-preservation-baseline:v1");
  assert.equal(schema.properties.gateAdmissible.const, false);
  assert.equal(schema.properties.mutationAuthority.const, false);
  assert.equal(schema.properties.effect.const, "DENY-ONLY");
  assert.equal(schema.$defs.policy.properties.unknownResourceDisposition.const, "PRESERVE");
  const completeProperties = schema.allOf[1].then.properties;
  assert.equal(completeProperties.logicalRecoveryAnchors.items.properties.mappingState.const, "MAPPED");
  assert.equal(completeProperties.databases.items.properties.kind.not.const, "UNMAPPED");
  assert.equal(completeProperties.bindMounts.items.properties.classification.not.const, "UNKNOWN-PRESERVE");
  assertClosedObjectSchemas(schema);
});

test("complete 34-container/139-volume fixture validates but never authorizes mutation", () => {
  const baseline = syntheticBaseline();
  const result = validateLivePreservationBaseline(baseline, { requireComplete: true });
  assert.equal(result.complete, true);
  assert.equal(result.status, "COMPLETE-PRESERVATION-BASELINE");
  assert.equal(result.gateAdmissible, false);
  assert.equal(result.mutationAuthority, false);
  assert.deepEqual(result.summary, {
    containers: 34,
    volumes: 139,
    attachedVolumes: 15,
    danglingVolumes: 124,
    namedVolumes: 12,
    anonymousVolumes: 127,
    bindMounts: 2,
    sourceRoots: 2,
    networks: 1,
    hostListeners: 1,
    databases: 3,
    applications: 3,
    secretMetadataRecords: 2,
  });
});

test("complete evidence rejects incomplete logical mappings and uncovered persistent resources", () => {
  const mutations = [
    (value) => { value.logicalRecoveryAnchors[0].mappingState = "PARTIAL"; },
    (value) => { value.databases[0].kind = "UNMAPPED"; },
    (value) => { value.bindMounts[0].classification = "UNKNOWN-PRESERVE"; },
    (value) => { value.logicalRecoveryAnchors.at(-1).containerRefs.pop(); },
    (value) => { value.logicalRecoveryAnchors.at(-1).storageRefs.pop(); },
    (value) => { value.logicalRecoveryAnchors[0].databaseRefs = []; },
    (value) => { value.logicalRecoveryAnchors.forEach((anchor) => { anchor.sourceRootRefs = []; anchor.sourceBindRefs = []; }); },
    (value) => { value.logicalRecoveryAnchors.forEach((anchor) => { anchor.configRefs = []; }); },
    (value) => { value.logicalRecoveryAnchors.forEach((anchor) => { anchor.secretMetadataRefs = []; }); },
  ];
  for (const mutate of mutations) {
    const baseline = syntheticBaseline();
    mutate(baseline);
    assert.throws(
      () => validateLivePreservationBaseline(sealLivePreservationBaseline(baseline), { requireComplete: true }),
      /complete=true/i,
    );
  }
});

test("timestamps reject impossible calendar dates instead of accepting Date.parse normalization", () => {
  const baseline = syntheticBaseline();
  baseline.capturedAt.startedAt = "2026-02-31T04:14:07.000Z";
  assert.throws(
    () => validateLivePreservationBaseline(sealLivePreservationBaseline(baseline)),
    /real UTC timestamp/i,
  );
});

test("incomplete evidence remains valid as a historical record and is NO-GO", () => {
  const baseline = syntheticBaseline({ complete: false });
  const result = validateLivePreservationBaseline(baseline);
  assert.equal(result.complete, false);
  assert.equal(result.status, "INCOMPLETE-NO-GO");
  assert.equal(result.comparisonEligible, false);
  assert.throws(
    () => validateLivePreservationBaseline(baseline, { requireComplete: true }),
    /complete preservation evidence/i,
  );
});

test("unknown and authorization-shaped fields fail closed", () => {
  for (const mutate of [
    (value) => { value.allowedMutations = ["legacy-app-000"]; },
    (value) => { value.policy.authorize = true; },
    (value) => { value.volumes[0].approval = "yes"; },
  ]) {
    const baseline = syntheticBaseline();
    mutate(baseline);
    assert.throws(() => validateLivePreservationBaseline(baseline), /unknown field/i);
  }
});

test("secret values cannot be smuggled through environment-key metadata", () => {
  const baseline = syntheticBaseline();
  baseline.containers[0].environmentKeys = ["PASSWORD=not-a-secret-we-can-store"];
  const resealed = sealLivePreservationBaseline(baseline);
  assert.throws(() => validateLivePreservationBaseline(resealed), /environment key/i);
});

test("count, sort, uniqueness, cross-reference, digest, and completeness invariants fail closed", () => {
  const mutations = [
    (value) => { value.summary.volumes = 138; },
    (value) => { value.volumes.reverse(); },
    (value) => { value.volumes[1].name = value.volumes[0].name; },
    (value) => { value.volumes[0].attachments[0].containerName = "missing-container"; },
    (value) => { value.digests.volumesSha256 = "f".repeat(64); },
    (value) => { value.complete = true; value.status = "COMPLETE-PRESERVATION-BASELINE"; value.volumes[0].fsIdentity = null; },
  ];
  for (const mutate of mutations) {
    const baseline = syntheticBaseline();
    mutate(baseline);
    assert.throws(() => validateLivePreservationBaseline(baseline));
  }

  const missingComposeIdentity = syntheticBaseline();
  missingComposeIdentity.containers[0].project = null;
  assert.throws(
    () => validateLivePreservationBaseline(sealLivePreservationBaseline(missingComposeIdentity)),
    /containers\[0\]\.project/,
  );
});

test("preservation comparison detects stopped/removed legacy resources and identity drift", () => {
  const baseline = syntheticBaseline();
  for (const mutate of [
    (value) => { value.containers[0].state = "exited"; },
    (value) => { value.containers.splice(0, 1); value.summary.containers -= 1; },
    (value) => { value.volumes[0].fsIdentity.inode = "999999"; },
    (value) => { value.bindMounts[0].targetIdentity.inode = "999999"; },
    (value) => { value.databases[0].tableCount += 1; },
  ]) {
    const observation = clone(baseline);
    mutate(observation);
    const resealed = sealLivePreservationBaseline(observation);
    const result = compareLivePreservationBaseline(baseline, resealed);
    assert.equal(result.preserved, false);
    assert.equal(result.status, "STOP");
    assert.equal(result.mutationAuthorized, false);
    assert.ok(result.issues.length > 0);
  }
});

test("unknown live resources are preserve-by-default and require a fresh baseline", () => {
  const baseline = syntheticBaseline();
  const observation = clone(baseline);
  const extra = clone(observation.containers.at(-1));
  extra.id = "f".repeat(64);
  extra.name = "unknown-live-container";
  extra.networks[0].endpointId = "e".repeat(64);
  extra.networks[0].aliases = [extra.name];
  observation.containers.push(extra);
  observation.composeProjects[0].containerNames.push(extra.name);
  observation.logicalRecoveryAnchors.at(-1).containerRefs.push(extra.name);
  observation.networks[0].endpoints.push({
    containerName: extra.name,
    endpointId: extra.networks[0].endpointId,
    ipv4: extra.networks[0].ipv4,
    ipv6: extra.networks[0].ipv6,
    macAddress: extra.networks[0].macAddress,
    aliases: extra.networks[0].aliases,
  });
  observation.summary.containers += 1;
  const resealed = sealLivePreservationBaseline(observation);
  const result = compareLivePreservationBaseline(baseline, resealed);
  assert.equal(result.preserved, false);
  assert.equal(result.status, "STOP");
  assert.equal(result.mutationAuthorized, false);
  assert.ok(result.issues.some((issue) => issue.includes("unknown-resource")));
});

test("unchanged complete evidence passes preservation only, never mutation admission", () => {
  const baseline = syntheticBaseline();
  const result = compareLivePreservationBaseline(baseline, clone(baseline));
  assert.deepEqual(result, {
    schema: "platform.live-preservation-comparison/v1",
    preserved: true,
    status: "PASS-PRESERVATION-ONLY",
    mutationAuthorized: false,
    issues: [],
  });
});

test("ignored real transcript baseline is exact about counts and honest about missing evidence", {
  skip: REAL_BASELINE_OVERRIDE || existsSync(REAL_BASELINE)
    ? false
    : "NOT_RUN: ignored real baseline is not available in this checkout",
}, () => {
  const baseline = JSON.parse(readFileSync(REAL_BASELINE, "utf8"));
  const result = validateLivePreservationBaseline(baseline);
  assert.equal(result.complete, false);
  assert.equal(result.status, "INCOMPLETE-NO-GO");
  assert.equal(result.summary.containers, 34);
  assert.equal(result.summary.volumes, 139);
  assert.equal(result.summary.attachedVolumes, 15);
  assert.equal(result.summary.danglingVolumes, 124);
  assert.equal(result.summary.namedVolumes, 12);
  assert.equal(result.summary.anonymousVolumes, 127);
  assert.equal(baseline.volumes.filter((volume) => volume.fsIdentity === null).length, 3);
  assert.deepEqual(
    baseline.volumes.filter((volume) => volume.fsIdentity === null).map((volume) => volume.name),
    [
      "019b0a250908627cc759e7b881a09392f7773025e5b13447ef875106a00dbe7a",
      "01bd32aebb6408723c7e6fc63a2904392f72ae166fb6fddd84f2dd738bac0921",
      "01f8b3d49376643e44b172379d8785c0fc114bdc09c483c51315002236e04eca",
    ],
  );
  assert.ok(baseline.deficiencies.some((entry) => entry.code === "VOLUME_FS_IDENTITY_NOT_RECOVERABLE"));
  for (const code of [
    "LOGICAL_RECOVERY_ANCHORS_INCOMPLETE",
    "LOGICAL_RECOVERY_COVERAGE_INCOMPLETE",
    "UNMAPPED_DATABASES_PRESENT",
    "UNKNOWN_PERSISTENT_BINDS_PRESENT",
  ]) {
    assert.ok(baseline.deficiencies.some((entry) => entry.code === code), `${code} must be explicit`);
  }
  const containers = new Map(baseline.containers.map((entry) => [entry.name, entry]));
  assert.ok(containers.get("enterprise-backup-scheduler").mounts.some((entry) => (
    entry.kind === "bind"
      && entry.sourceRef === "/var/run/docker.sock"
      && entry.destination === "/var/run/docker.sock"
  )));
  assert.ok(containers.get("enterprise-cadvisor").mounts.some((entry) => entry.kind === "bind" && entry.sourceRef === "/"));
  assert.ok(containers.get("enterprise-cadvisor").mounts.some((entry) => entry.kind === "bind" && entry.sourceRef === "/var/lib/docker"));
  assert.ok(containers.get("enterprise-node-exporter").mounts.some((entry) => entry.kind === "bind" && entry.sourceRef === "/"));
  assert.equal(
    baseline.containers.some((entry) => `${entry.name} ${entry.project ?? ""} ${entry.service ?? ""}`.toLowerCase().includes("docker-action-broker")),
    false,
    "a live docker-action-broker identity must not be invented when none was observed",
  );
  assert.throws(
    () => validateLivePreservationBaseline(baseline, { requireComplete: true }),
    /complete preservation evidence/i,
  );
});
