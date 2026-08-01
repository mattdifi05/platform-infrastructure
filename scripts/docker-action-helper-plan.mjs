import crypto from "node:crypto";
import path from "node:path";

const PLAN_SCHEMA = "platform.docker-action.helper-plan/v1";
const BINDING_SCHEMA = "platform.docker-action.artifact-binding/v1";
const DEFERRED_BODY_SCHEMA = "platform.docker-action.deferred-helper-body/v1";
const IMAGE_RUNTIME_SCHEMA = "platform.docker-action.image-runtime-config/v1";
const SHA256 = /^[a-f0-9]{64}$/;
const IMAGE_ID = /^sha256:[a-f0-9]{64}$/;
const ENGINE_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const SAFE_ID = /^[a-z0-9][a-z0-9.-]{0,127}$/;
const INPUT_KEYS = Object.freeze([
  "claimedBackupResources",
  "phaseId",
  "priorBinding",
  "receipt",
  "requestSha256",
]);

const PHASE_HELPERS = deepFreeze({
  "catalog.capture": [
    "helper.capture.mariadb",
    "helper.capture.minio",
    "helper.capture.postgres",
  ],
  "job.backup.capture": [
    "helper.capture.mariadb",
    "helper.capture.minio",
    "helper.capture.postgres",
  ],
  "job.restore.verify": [
    "helper.restore.mariadb.server",
    "helper.restore.mariadb.restore",
    "helper.restore.mariadb.verify",
    "helper.restore.minio.server",
    "helper.restore.minio.restore",
    "helper.restore.minio.verify",
    "helper.restore.postgres.server",
    "helper.restore.postgres.restore",
    "helper.restore.postgres.verify",
  ],
  "offsite.sync": ["helper.offsite.restic"],
  "prune.apply": [],
  "prune.plan": [],
  "restore.capture": [
    "helper.capture.mariadb",
    "helper.capture.minio",
    "helper.capture.postgres",
  ],
  "restore.verify": [
    "helper.restore.mariadb.server",
    "helper.restore.mariadb.restore",
    "helper.restore.mariadb.verify",
    "helper.restore.minio.server",
    "helper.restore.minio.restore",
    "helper.restore.minio.verify",
    "helper.restore.postgres.server",
    "helper.restore.postgres.restore",
    "helper.restore.postgres.verify",
  ],
});

const PROFILE_POLICY = deepFreeze({
  "helper.capture.mariadb": profile({
    engine: "mariadb",
    entrypoint: "/usr/bin/mariadb-dump",
    imageRef: "mariadb:12.3.2@sha256:b1c7bf836e64ed9406a8984af29509f40089d55cea14b32f12c4726a1f17104b",
    networkId: "platform_db_admin",
    operation: "capture",
    outputMode: "artifact",
    resourceKind: "database",
    secretSetId: "mariadb.capture.credentials",
  }),
  "helper.capture.minio": profile({
    engine: "minio",
    entrypoint: "/bin/sh",
    imageRef: "quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727",
    networkId: "platform_storage",
    operation: "capture",
    outputMode: "artifact",
    resourceKind: "storage",
    secretSetId: "minio.capture.credentials",
  }),
  "helper.capture.postgres": profile({
    engine: "postgres",
    entrypoint: "/usr/local/bin/pg_dump",
    imageRef: "postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa",
    networkId: "platform_db_admin",
    operation: "capture",
    outputMode: "artifact",
    resourceKind: "database",
    secretSetId: "postgres.capture.credentials",
  }),
  "helper.offsite.restic": profile({
    engine: "restic",
    entrypoint: "/usr/bin/restic",
    imageRef: "restic/restic:0.18.0@sha256:4cf4a61ef9786f4de53e9de8c8f5c040f33830eb0a10bf3d614410ee2fcb6120",
    networkId: "platform_egress",
    operation: "offsite-sync",
    outputMode: "json",
    resourceKind: null,
    secretSetId: "offsite.credentials",
  }),
  "helper.restore.mariadb.restore": profile({
    engine: "mariadb", entrypoint: "/usr/bin/mariadb", imageRef: "mariadb:12.3.2@sha256:b1c7bf836e64ed9406a8984af29509f40089d55cea14b32f12c4726a1f17104b", operation: "restore", outputMode: "none", resourceKind: "database",
  }),
  "helper.restore.mariadb.server": profile({
    engine: "mariadb", entrypoint: "/usr/local/bin/docker-entrypoint.sh", imageRef: "mariadb:12.3.2@sha256:b1c7bf836e64ed9406a8984af29509f40089d55cea14b32f12c4726a1f17104b", operation: "restore-server", outputMode: "none", resourceKind: "database",
  }),
  "helper.restore.mariadb.verify": profile({
    engine: "mariadb", entrypoint: "/usr/bin/mariadb", imageRef: "mariadb:12.3.2@sha256:b1c7bf836e64ed9406a8984af29509f40089d55cea14b32f12c4726a1f17104b", operation: "verify", outputMode: "json", resourceKind: "database",
  }),
  "helper.restore.minio.restore": profile({
    engine: "minio", entrypoint: "/usr/bin/mc", imageRef: "quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727", operation: "restore", outputMode: "none", resourceKind: "storage",
  }),
  "helper.restore.minio.server": profile({
    engine: "minio", entrypoint: "/usr/bin/minio", imageRef: "quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e", operation: "restore-server", outputMode: "none", resourceKind: "storage",
  }),
  "helper.restore.minio.verify": profile({
    engine: "minio", entrypoint: "/usr/bin/mc", imageRef: "quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727", operation: "verify", outputMode: "json", resourceKind: "storage",
  }),
  "helper.restore.postgres.restore": profile({
    engine: "postgres", entrypoint: "/usr/local/bin/pg_restore", imageRef: "postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa", operation: "restore", outputMode: "none", resourceKind: "database",
  }),
  "helper.restore.postgres.server": profile({
    engine: "postgres", entrypoint: "/usr/local/bin/docker-entrypoint.sh", imageRef: "postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa", operation: "restore-server", outputMode: "none", resourceKind: "database",
  }),
  "helper.restore.postgres.verify": profile({
    engine: "postgres", entrypoint: "/usr/local/bin/psql", imageRef: "postgres:18-alpine@sha256:1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa", operation: "verify", outputMode: "json", resourceKind: "database",
  }),
});

const ENDPOINT_POLICY = deepFreeze({
  "capture.database.mariadb": { engine: "mariadb", networkId: "platform_db_admin", purpose: "capture", resourceId: "database:mariadb", resourceKind: "database", secretSetId: "mariadb.capture.credentials" },
  "capture.database.postgres": { engine: "postgres", networkId: "platform_db_admin", purpose: "capture", resourceId: "database:postgres", resourceKind: "database", secretSetId: "postgres.capture.credentials" },
  "capture.storage.minio": { engine: "minio", networkId: "platform_storage", purpose: "capture", resourceId: "storage:minio", resourceKind: "storage", secretSetId: "minio.capture.credentials" },
  "offsite.repository": { engine: "restic", networkId: "platform_egress", purpose: "offsite", resourceId: null, resourceKind: null, secretSetId: "offsite.credentials" },
});

const RESOURCE_BY_ENGINE = Object.freeze({
  mariadb: "database:mariadb",
  minio: "storage:minio",
  postgres: "database:postgres",
});
const ARTIFACT_NAME = Object.freeze({
  mariadb: "mariadb.sql",
  minio: "objects",
  postgres: "postgres.dump",
});
const SECRET_FILE_KEYS = deepFreeze({
  "mariadb.capture.credentials": ["clientConfig"],
  "minio.capture.credentials": ["accessKey", "secretKey"],
  "offsite.credentials": ["password", "repository"],
  "postgres.capture.credentials": ["pgpass", "serviceConfig"],
});
const JSON_NORMALIZER = deepFreeze({
  "helper.offsite.restic": "restic-terminal-summary-v1",
  "helper.restore.mariadb.verify": "exact-mariadb-verify-v1",
  "helper.restore.minio.verify": "empty-minio-diff-v1",
  "helper.restore.postgres.verify": "exact-postgres-verify-v1",
});
const AGGREGATE_RESULT_POLICY = deepFreeze({
  helperResultKeys: [
    "artifactRelativePath",
    "exitCode",
    "helperProfileId",
    "imageId",
    "outputMode",
    "status",
    "stderrSha256",
    "stdoutBase64",
  ],
  maximumBytes: 524288,
  mode: 0o400,
  ordering: "effective-helper-profile-ids",
  owner: { gid: 0, uid: 0 },
  path: "/run/platform/helper-results/results.json",
  schema: "platform.docker-helper-results/v1",
});

export function buildSemanticHelperPlan(input) {
  exactKeys(input, INPUT_KEYS, "helper plan input");
  const { claimedBackupResources, phaseId, priorBinding, receipt, requestSha256 } = input;
  if (!SHA256.test(String(requestSha256 ?? ""))) fail("helper plan request sha256 is invalid");
  if (!isPlainRecord(receipt) || !isPlainRecord(receipt.resources)) fail("helper plan receipt is invalid");
  if (!Object.hasOwn(PHASE_HELPERS, phaseId)) fail("helper plan phase identity is unsupported");

  const resources = receipt.resources;
  const phaseValue = requiredRecord(resources.phaseProfiles, phaseId, "phase profile");
  if (phaseValue.phaseId !== phaseId
    || canonicalJson(phaseValue.helperProfileIds) !== canonicalJson(PHASE_HELPERS[phaseId])) {
    fail(`phase ${phaseId} canonical helper inventory is invalid`);
  }
  if (!SHA256.test(String(phaseValue.phaseSha256 ?? ""))
    || phaseValue.phaseSha256 !== sha256(canonicalJson(withoutKey(phaseValue, "phaseSha256")))) {
    fail(`phase ${phaseId} digest is invalid`);
  }

  validateHelperRegistry(resources.helperProfiles);
  validateEndpointRegistry(resources);
  const claimed = normalizeClaimedResources(claimedBackupResources, resources.backupResources);
  const selected = selectedResourceIds(claimed, resources.backupResources);
  const binding = normalizePriorBinding(priorBinding, {
    phaseId,
    receipt,
    requestSha256,
    selected,
  });
  const bindingSha256 = binding ? sha256(canonicalJson(binding)) : null;

  const selectedHelperIds = PHASE_HELPERS[phaseId].filter((helperProfileId) => {
    const engine = resources.helperProfiles[helperProfileId].engine;
    const resourceId = RESOURCE_BY_ENGINE[engine] ?? null;
    return resourceId === null || selected.has(resourceId);
  });
  const helpers = selectedHelperIds.map((helperProfileId, ordinal) => buildHelper({
    binding,
    bindingSha256,
    helperProfileId,
    ordinal,
    phase: phaseValue,
    phaseId,
    receipt,
    requestSha256,
    total: selectedHelperIds.length,
  }));

  return deepFreeze({
    schema: PLAN_SCHEMA,
    claimedResourceIds: [...selected].sort(),
    helpers,
    phaseId,
    phaseProfileSha256: phaseValue.phaseSha256,
    priorBindingSha256: bindingSha256,
    requestSha256,
  });
}

export function bindSemanticHelperImageInspect(helper, inspect) {
  if (!isPlainRecord(helper) || !isPlainRecord(inspect)
    || inspect.Id !== helper.imageId || !IMAGE_ID.test(String(inspect.Id ?? ""))
    || !isPlainRecord(inspect.Config)
    || helper.imageRuntimeConfig !== null || helper.imageRuntimeConfigSha256 !== null) {
    fail("helper image runtime inspect identity is invalid or already bound");
  }
  const config = inspect.Config;
  const imageEnv = normalizeImageEnv(config.Env ?? []);
  const imageLabels = normalizeImageLabels(config.Labels ?? {});
  const volumes = normalizeImagePathMap(config.Volumes ?? {}, "volume");
  if (canonicalJson(Object.keys(volumes).sort()) !== canonicalJson([...helper.declaredVolumePaths].sort())) {
    fail("helper image declared volumes do not match exact authority");
  }
  const exposedPorts = normalizeImagePathMap(config.ExposedPorts ?? {}, "port");
  const onBuild = config.OnBuild ?? [];
  if (!Array.isArray(onBuild) || onBuild.length !== 0) {
    fail("helper image OnBuild authority is unsupported");
  }
  const shell = config.Shell ?? [];
  if (!Array.isArray(shell) || shell.length > 8
    || shell.some((value) => typeof value !== "string" || !value || value.length > 256 || value.includes("\0"))) {
    fail("helper image shell metadata is invalid");
  }
  const snapshot = deepFreeze({
    schema: IMAGE_RUNTIME_SCHEMA,
    env: imageEnv,
    exposedPorts,
    healthcheck: normalizeImageHealthcheck(config.Healthcheck ?? null),
    imageId: helper.imageId,
    labels: imageLabels,
    onBuild: [],
    shell: [...shell],
    stopSignal: normalizeNullableImageText(config.StopSignal, "stop signal"),
    user: normalizeNullableImageText(config.User, "user"),
    volumes,
    workingDir: normalizeNullableImageText(config.WorkingDir, "working directory"),
  });
  const snapshotJson = canonicalJson(snapshot);
  if (Buffer.byteLength(snapshotJson) > 131072) fail("helper image runtime snapshot is oversized");
  const imageRuntimeConfigSha256 = sha256(snapshotJson);
  const sourceBody = helper.body ?? helper.deferredBody?.baseBody;
  if (!isPlainRecord(sourceBody)) fail("helper image runtime binding lacks a base body");
  const boundBody = deepFreeze({
    ...sourceBody,
    Env: mergeImageEnv(sourceBody.Env, imageEnv),
    ExposedPorts: exposedPorts,
    Healthcheck: sourceBody.Healthcheck ?? { Test: ["NONE"] },
    Labels: { ...imageLabels, ...sourceBody.Labels },
    OnBuild: [],
    Shell: [...shell],
    StopSignal: snapshot.stopSignal,
    Volumes: volumes,
  });
  assertHardenedBody(boundBody);
  const expectedInspect = {
    ...(helper.expectedInspect ?? helper.deferredBody.expectedInspect),
    imageRuntimeConfigSha256,
  };
  if (helper.body) {
    return deepFreeze({
      ...helper,
      body: boundBody,
      bodySha256: sha256(canonicalJson(boundBody)),
      expectedInspect,
      imageRuntimeConfig: snapshot,
      imageRuntimeConfigSha256,
    });
  }
  return deepFreeze({
    ...helper,
    deferredBody: {
      ...helper.deferredBody,
      baseBody: boundBody,
      expectedInspect,
    },
    imageRuntimeConfig: snapshot,
    imageRuntimeConfigSha256,
  });
}

export function assertExactSemanticHelperInspect(inspect, expected) {
  if (!isPlainRecord(inspect) || !isPlainRecord(expected) || !isPlainRecord(expected.body)
    || !SHA256.test(String(expected.imageRuntimeConfigSha256 ?? ""))) {
    fail("semantic helper exact inspect requires a resolved body");
  }
  const body = expected.body;
  const config = inspect.Config;
  if (!isPlainRecord(config)
    || inspect.Id !== String(inspect.Id ?? "")
    || !SHA256.test(inspect.Id)
    || String(inspect.Name ?? "").replace(/^\//, "") !== expected.name
    || inspect.Image !== expected.imageId
    || config.Image !== body.Image
    || canonicalJson(config.Entrypoint) !== canonicalJson(body.Entrypoint)
    || canonicalJson(config.Cmd) !== canonicalJson(body.Cmd)
    || canonicalJson(config.Env) !== canonicalJson(body.Env)
    || config.User !== body.User
    || config.WorkingDir !== body.WorkingDir
    || config.NetworkDisabled !== body.NetworkDisabled
    || config.AttachStdin !== false || config.AttachStdout !== false
    || config.AttachStderr !== false || config.OpenStdin !== false
    || config.StdinOnce !== false || config.Tty !== false
    || canonicalJson(config.Labels) !== canonicalJson(body.Labels)) {
    fail("semantic helper inspect identity is not exact");
  }
  if (canonicalJson(inspect.HostConfig) !== canonicalJson(body.HostConfig)) {
    fail("semantic helper HostConfig was widened or is not exact");
  }
  const expectedInspect = expected.expectedInspect;
  if (!isPlainRecord(expectedInspect)
    || canonicalJson(inspect.Mounts) !== canonicalJson(expectedInspect.mounts)) {
    fail("semantic helper inspect mounts are not exact");
  }
  if (!matchesExpectedNetworks(inspect.NetworkSettings?.Networks ?? {}, expectedInspect.networks)) {
    fail("semantic helper inspect network authority is not exact");
  }
  if (canonicalJson(config.Volumes ?? {}) !== canonicalJson(body.Volumes)
    || canonicalJson(config.ExposedPorts ?? {}) !== canonicalJson(body.ExposedPorts)
    || canonicalJson(config.OnBuild ?? []) !== canonicalJson(body.OnBuild)
    || canonicalJson(config.Shell ?? []) !== canonicalJson(body.Shell)
    || (config.StopSignal ?? "") !== body.StopSignal
    || canonicalJson(config.Healthcheck ?? null) !== canonicalJson(body.Healthcheck ?? null)) {
    fail("semantic helper image configuration exposes an unmodeled surface");
  }
  assertHardenedBody(body);
  return true;
}

function buildHelper({ binding, bindingSha256, helperProfileId, ordinal, phase, phaseId, receipt, requestSha256, total }) {
  const profileValue = receipt.resources.helperProfiles[helperProfileId];
  const engine = profileValue.engine;
  const resourceId = RESOURCE_BY_ENGINE[engine] ?? null;
  const endpoint = profileValue.operation === "capture" || profileValue.operation === "offsite-sync"
    ? findExactEndpoint(receipt.resources.serviceEndpoints, profileValue)
    : null;
  const paths = helperPaths({ binding, profileValue, helperProfileId, ordinal, phaseId, receipt, requestSha256 });
  const secret = profileValue.secretSetId === null
    ? null
    : normalizeSecretSet(receipt, profileValue.secretSetId);
  const mounts = helperMounts({ binding, paths, profileValue, receipt, secret });
  const command = helperCommand({ endpoint, paths, profileValue, receipt, secret });
  const network = profileValue.networkId === null
    ? null
    : normalizeNetwork(receipt, profileValue.networkId);
  const name = helperName({ helperProfileId, ordinal, phaseId, requestSha256 });
  const labels = {
    "com.platform.docker-helper": helperProfileId,
    "com.platform.docker-helper-phase": phaseId,
    "com.platform.docker-helper-phase-sha256": phase.phaseSha256,
    "com.platform.docker-helper-request-sha256": requestSha256,
  };
  if (bindingSha256) labels["com.platform.docker-helper-binding-sha256"] = bindingSha256;
  const concreteBody = dockerBody({
    cmd: command.cmd,
    entrypoint: profileValue.entrypoint,
    env: command.env,
    healthcheck: helperHealthcheck(profileValue, paths),
    imageRef: profileValue.imageRef,
    labels,
    mounts: mounts.hostConfig,
    network,
    networkDisabled: network === null,
    paths,
    profileValue,
  });
  const isDeferredRestoreClient = ["restore", "verify"].includes(profileValue.operation);
  const body = isDeferredRestoreClient ? null : concreteBody;
  const deferredBody = isDeferredRestoreClient
    ? deepFreeze({
        schema: DEFERRED_BODY_SCHEMA,
        baseBody: {
          ...concreteBody,
          NetworkDisabled: false,
          HostConfig: { ...concreteBody.HostConfig, NetworkMode: null },
        },
        expectedInspect: {
          mounts: mounts.inspect,
          networks: {},
        },
        networkModePrefix: "container:",
        requires: {
          helperProfileId: `helper.restore.${engine}.server`,
          value: "containerId",
        },
      })
    : null;
  if (body) assertHardenedBody(body);

  const localIndex = ["restore-server", "restore", "verify"].indexOf(profileValue.operation);
  const cleanupOrdinal = localIndex >= 0 ? 2 - localIndex : total - 1 - ordinal;
  const lifecycle = helperLifecycle(profileValue);
  const outputPolicy = helperOutputPolicy(profileValue, paths);
  const preconditions = helperPreconditions(profileValue, paths);
  const remoteAttempt = profileValue.operation === "offsite-sync"
    ? {
        idempotencyKey: sha256(`platform-offsite-sync-v1\n${binding.manifestSha256}\n`),
        journalBeforeStart: true,
        manifestSha256: binding.manifestSha256,
        onAmbiguity: "preserve-lease-no-retry",
      }
    : null;
  return deepFreeze({
    body,
    bodySha256: body ? sha256(canonicalJson(body)) : null,
    cleanupOrdinal,
    declaredVolumePaths: profileValue.declaredVolumePaths,
    deferredBody,
    dependsOn: helperDependencies(profileValue),
    endpointId: endpoint?.endpointId ?? null,
    engine,
    expectedInspect: body ? {
      mounts: mounts.inspect,
      networks: expectedNetworks(network),
    } : null,
    helperProfileId,
    imageId: profileValue.imageId,
    imageRuntimeConfig: null,
    imageRuntimeConfigSha256: null,
    lifecycle,
    name,
    networkId: profileValue.networkId,
    operation: profileValue.operation,
    ordinal,
    outputPolicy,
    paths,
    preconditions,
    priorBindingSha256: bindingSha256,
    remoteAttempt,
    resourceId,
    runtimeGid: profileValue.runtimeGid,
    runtimeUid: profileValue.runtimeUid,
    secretFilePaths: secret?.paths ?? [],
    secretSetId: profileValue.secretSetId,
  });
}

function helperPaths({ binding, profileValue, helperProfileId, ordinal, phaseId, receipt, requestSha256 }) {
  const engine = profileValue.engine;
  const reportLeaf = `${String(ordinal).padStart(2, "0")}-${helperProfileId}`;
  const reportRelativePath = safeRelativeJoin("docker-actions", requestSha256, phaseId, "helpers", `${reportLeaf}.json`);
  const artifactRelativePath = engine === "restic"
    ? null
    : binding?.artifacts?.[RESOURCE_BY_ENGINE[engine]]?.relativePath
      ?? safeRelativeJoin("requests", requestSha256, "artifacts", engine, ARTIFACT_NAME[engine]);
  const isRestore = helperProfileId.startsWith("helper.restore.");
  const scratchRelativePath = isRestore
    ? safeRelativeJoin("requests", requestSha256, phaseId, engine)
    : null;
  const isRestoreServer = profileValue.operation === "restore-server";
  const dataContainerPath = isRestoreServer ? profileValue.declaredVolumePaths[0] : null;
  const runContainerPath = isRestoreServer && ["mariadb", "postgres"].includes(engine)
    ? "/run/platform/restore-run"
    : null;
  const socketPath = engine === "mariadb" && isRestoreServer
    ? safeAbsoluteJoin(runContainerPath, "mariadb.sock")
    : engine === "postgres" && isRestoreServer
      ? safeAbsoluteJoin(runContainerPath, ".s.PGSQL.5432")
      : null;
  const offsiteRequestRelativePath = engine === "restic"
    ? safeRelativeJoin("requests", binding.producerRequestSha256)
    : null;
  return deepFreeze({
    artifactContainerPath: artifactRelativePath === null
      ? null
      : `/input/${ARTIFACT_NAME[engine]}`,
    artifactRelativePath,
    dataContainerPath,
    outputContainerPath: artifactRelativePath === null
      ? null
      : `/output/${ARTIFACT_NAME[engine]}`,
    offsiteRequestContainerPath: offsiteRequestRelativePath === null
      ? null
      : `/data/backups/${offsiteRequestRelativePath}`,
    offsiteRequestRelativePath,
    reportContainerPath: null,
    reportRelativePath,
    runContainerPath,
    scratchContainerPath: isRestoreServer ? normalizeScratchVolume(receipt).containerPath : null,
    scratchDataRelativePath: isRestoreServer
      ? safeRelativeJoin(scratchRelativePath, "data")
      : null,
    scratchRelativePath,
    socketPath,
  });
}

function helperMounts({ binding, paths, profileValue, receipt, secret }) {
  const hostConfig = [];
  const inspect = [];
  const backupRo = receipt.resources.mounts?.["backup.root.ro"];
  const backupRw = receipt.resources.mounts?.["backup.root.rw"];

  if (profileValue.operation === "capture") {
    normalizeMount(backupRw, "backup.root.rw", "rw");
    const artifactDirectory = safeAbsoluteJoin(backupRw.canonicalPath, path.posix.dirname(paths.artifactRelativePath));
    addBindMount(hostConfig, inspect, artifactDirectory, "/output", false);
  } else if (profileValue.operation === "offsite-sync") {
    normalizeMount(backupRo, "backup.root.ro", "ro");
    addBindMount(
      hostConfig,
      inspect,
      safeAbsoluteJoin(backupRo.canonicalPath, paths.offsiteRequestRelativePath),
      paths.offsiteRequestContainerPath,
      true,
    );
  } else if (profileValue.operation !== "restore-server") {
    normalizeMount(backupRo, "backup.root.ro", "ro");
    if (!binding) fail("restore helper is missing its prior artifact binding");
    addBindMount(
      hostConfig,
      inspect,
      safeAbsoluteJoin(backupRo.canonicalPath, paths.artifactRelativePath),
      paths.artifactContainerPath,
      true,
    );
  }
  if (profileValue.operation === "restore-server") {
    const scratch = normalizeScratchVolume(receipt);
    hostConfig.push({
      Type: "volume",
      Source: scratch.engineName,
      Target: paths.dataContainerPath,
      ReadOnly: false,
      VolumeOptions: { NoCopy: true, Subpath: paths.scratchDataRelativePath },
    });
    inspect.push({
      Type: "volume",
      Name: scratch.engineName,
      Source: `/var/lib/docker/volumes/${scratch.engineName}/_data/${paths.scratchDataRelativePath}`,
      Destination: paths.dataContainerPath,
      Driver: "local",
      Mode: "",
      RW: true,
      Propagation: "",
    });
  }
  if (secret) {
    hostConfig.push({
      Type: "volume",
      Source: secret.volume.engineName,
      Target: secret.containerRoot,
      ReadOnly: true,
      VolumeOptions: { NoCopy: true },
    });
    inspect.push({
      Type: "volume",
      Name: secret.volume.engineName,
      Source: `/var/lib/docker/volumes/${secret.volume.engineName}/_data`,
      Destination: secret.containerRoot,
      Driver: "local",
      Mode: "",
      RW: false,
      Propagation: "",
    });
  }
  return deepFreeze({ hostConfig, inspect });
}

function helperCommand({ endpoint, paths, profileValue, receipt, secret }) {
  const env = ["HOME=/tmp", "LANG=C.UTF-8"];
  switch (profileValue.helperProfileId) {
    case "helper.capture.mariadb":
      return {
        cmd: [
          `--defaults-extra-file=${secret.byKey.clientConfig}`,
          `--host=${endpoint.host}`,
          `--port=${endpoint.port}`,
          "--ssl",
          "--all-databases",
          "--single-transaction",
          "--routines",
          "--events",
          `--result-file=${paths.outputContainerPath}`,
        ],
        env,
      };
    case "helper.capture.minio":
      return {
        cmd: ["-eu", "-c", [
          `access_key="$(cat -- ${shellLiteral(secret.byKey.accessKey)})"`,
          `secret_key="$(cat -- ${shellLiteral(secret.byKey.secretKey)})"`,
          `/usr/bin/mc alias set source ${shellLiteral(`${endpoint.protocol === "s3-http" ? "http" : "https"}://${endpoint.host}:${endpoint.port}`)} "$access_key" "$secret_key" >/dev/null`,
          `exec /usr/bin/mc mirror --quiet --preserve source ${shellLiteral(paths.outputContainerPath)}`,
        ].join("\n")],
        env,
      };
    case "helper.capture.postgres": {
      return {
        cmd: [
          `--host=${endpoint.host}`,
          `--port=${endpoint.port}`,
          "--dbname=service=platform_capture",
          "--format=custom",
          "--no-owner",
          "--no-privileges",
          `--file=${paths.outputContainerPath}`,
        ],
        env: [
          ...env,
          `PGPASSFILE=${secret.byKey.pgpass}`,
          "PGSERVICE=platform_capture",
          `PGSERVICEFILE=${secret.byKey.serviceConfig}`,
          `PGSSLMODE=${endpoint.tlsMode}`,
        ],
      };
    }
    case "helper.offsite.restic":
      return {
        cmd: [
          "--repository-file", secret.byKey.repository,
          "--password-file", secret.byKey.password,
          "backup", "--json", paths.offsiteRequestContainerPath,
        ],
        env,
      };
    case "helper.restore.mariadb.server":
      return {
        cmd: ["mariadbd", "--bind-address=127.0.0.1", "--port=3306", `--socket=${paths.socketPath}`, `--datadir=${paths.dataContainerPath}`, `--pid-file=${paths.runContainerPath}/mariadb.pid`],
        env: [...env, "MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1", "MARIADB_DATABASE=restore"],
      };
    case "helper.restore.mariadb.restore":
      return { cmd: ["--host=127.0.0.1", "--port=3306", "--protocol=TCP", "--user=root", "--database=restore", `--execute=source ${paths.artifactContainerPath}`], env };
    case "helper.restore.mariadb.verify":
      return { cmd: ["--host=127.0.0.1", "--port=3306", "--protocol=TCP", "--user=root", "--database=restore", "--batch", "--skip-column-names", "--execute=SELECT JSON_OBJECT('engine','mariadb','status','passed')"], env };
    case "helper.restore.postgres.server":
      return {
        cmd: ["postgres", "-c", "listen_addresses=127.0.0.1", "-c", `unix_socket_directories=${paths.runContainerPath}`, "-c", "unix_socket_permissions=0700"],
        env: [...env, `PGDATA=${paths.dataContainerPath}/18/docker`, "POSTGRES_DB=restore", "POSTGRES_HOST_AUTH_METHOD=trust", "POSTGRES_USER=restore"],
      };
    case "helper.restore.postgres.restore":
      return { cmd: ["--host", "127.0.0.1", "--port", "5432", "--username", "restore", "--dbname", "restore", "--no-owner", "--no-privileges", paths.artifactContainerPath], env };
    case "helper.restore.postgres.verify":
      return { cmd: ["--host", "127.0.0.1", "--port", "5432", "--username", "restore", "--dbname", "restore", "--tuples-only", "--no-align", "--command", "SELECT json_build_object('engine','postgres','status','passed')::text"], env };
    case "helper.restore.minio.server":
      return {
        cmd: ["server", paths.dataContainerPath, "--address", "127.0.0.1:9000", "--console-address", "127.0.0.1:9001"],
        env: [...env, "MINIO_ROOT_USER=restore", "MINIO_ROOT_PASSWORD=restore-only-no-live-authority"],
      };
    case "helper.restore.minio.restore":
      return {
        cmd: ["mirror", "--quiet", "--overwrite", paths.artifactContainerPath, "restore"],
        env: [...env, "MC_HOST_restore=http://restore:restore-only-no-live-authority@127.0.0.1:9000"],
      };
    case "helper.restore.minio.verify":
      return {
        cmd: ["diff", "--json", paths.artifactContainerPath, "restore"],
        env: [...env, "MC_HOST_restore=http://restore:restore-only-no-live-authority@127.0.0.1:9000"],
      };
    default:
      fail("helper command policy is unsupported");
  }
}

function dockerBody({ cmd, entrypoint, env, healthcheck, imageRef, labels, mounts, network, networkDisabled, paths, profileValue }) {
  const networkName = network?.engineName ?? "none";
  return {
    Image: imageRef,
    Entrypoint: entrypoint,
    Cmd: cmd,
    Env: env,
    User: `${profileValue.runtimeUid}:${profileValue.runtimeGid}`,
    WorkingDir: "/",
    NetworkDisabled: networkDisabled,
    AttachStdin: false,
    AttachStdout: false,
    AttachStderr: false,
    OpenStdin: false,
    StdinOnce: false,
    Tty: false,
    Labels: labels,
    ...(healthcheck ? { Healthcheck: healthcheck } : {}),
    HostConfig: hardenedHostConfig(mounts, networkName, paths, profileValue),
    NetworkingConfig: {
      EndpointsConfig: network ? { [networkName]: { Aliases: [] } } : {},
    },
  };
}

function hardenedHostConfig(mounts, networkMode, paths, profileValue) {
  const tmpfs = { "/tmp": "rw,noexec,nosuid,nodev,size=67108864,mode=1777" };
  if (profileValue.operation === "restore-server") {
    if (paths.runContainerPath !== null) {
      tmpfs[paths.runContainerPath] = `rw,noexec,nosuid,nodev,size=16777216,mode=0700,uid=${profileValue.runtimeUid},gid=${profileValue.runtimeGid}`;
    }
  } else {
    for (const declaredPath of profileValue.declaredVolumePaths) {
      tmpfs[declaredPath] = `rw,noexec,nosuid,nodev,size=16777216,mode=0700,uid=${profileValue.runtimeUid},gid=${profileValue.runtimeGid}`;
    }
  }
  return {
    Annotations: null,
    AutoRemove: false,
    Binds: [],
    BlkioDeviceReadBps: null,
    BlkioDeviceReadIOps: null,
    BlkioDeviceWriteBps: null,
    BlkioDeviceWriteIOps: null,
    BlkioWeight: 0,
    BlkioWeightDevice: null,
    CapAdd: [],
    CapDrop: ["ALL"],
    Cgroup: "",
    CgroupnsMode: "private",
    CgroupParent: "",
    ConsoleSize: [0, 0],
    CpuCount: 0,
    CpuPercent: 0,
    CpuPeriod: 0,
    CpuQuota: 0,
    CpuRealtimePeriod: 0,
    CpuRealtimeRuntime: 0,
    CpuShares: 0,
    CpusetCpus: "",
    CpusetMems: "",
    DeviceCgroupRules: [],
    Devices: [],
    DeviceRequests: [],
    DiskQuota: 0,
    Dns: [],
    DnsOptions: [],
    DnsSearch: [],
    ExtraHosts: [],
    GroupAdd: [],
    IOMaximumBandwidth: 0,
    IOMaximumIOps: 0,
    Init: false,
    IpcMode: "private",
    Isolation: "",
    KernelMemory: 0,
    KernelMemoryTCP: 0,
    Links: [],
    LogConfig: { Type: "json-file", Config: { "max-file": "1", "max-size": "1m" } },
    Memory: 536870912,
    MemoryReservation: 0,
    MemorySwap: 536870912,
    MemorySwappiness: null,
    Mounts: mounts,
    NanoCpus: 500000000,
    NetworkMode: networkMode,
    OomKillDisable: false,
    OomScoreAdj: 0,
    PidMode: "",
    PidsLimit: 128,
    PortBindings: {},
    Privileged: false,
    PublishAllPorts: false,
    ReadonlyRootfs: true,
    ReadonlyPaths: ["/proc/asound", "/proc/acpi", "/proc/interrupts", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi", "/sys/firmware"],
    RestartPolicy: { Name: "no", MaximumRetryCount: 0 },
    Runtime: "runc",
    SecurityOpt: ["no-new-privileges:true"],
    ShmSize: 67108864,
    StorageOpt: {},
    Sysctls: {},
    Tmpfs: tmpfs,
    Ulimits: [{ Name: "nofile", Soft: 1024, Hard: 1024 }],
    UsernsMode: "",
    UTSMode: "",
    VolumeDriver: "",
    VolumesFrom: [],
    MaskedPaths: ["/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi", "/sys/devices/virtual/powercap", "/sys/firmware"],
  };
}

function assertHardenedBody(body) {
  const host = body.HostConfig;
  const serialized = canonicalJson(body);
  if (!isPlainRecord(host)
    || host.Privileged !== false || host.ReadonlyRootfs !== true
    || canonicalJson(host.CapAdd) !== "[]"
    || canonicalJson(host.CapDrop) !== '["ALL"]'
    || canonicalJson(host.SecurityOpt) !== '["no-new-privileges:true"]'
    || host.PidMode !== "" || host.IpcMode !== "private" || host.CgroupnsMode !== "private"
    || host.PublishAllPorts !== false || Object.keys(host.PortBindings ?? {}).length
    || (host.Devices ?? []).length || (host.DeviceRequests ?? []).length
    || (host.GroupAdd ?? []).length || (host.Links ?? []).length || (host.VolumesFrom ?? []).length
    || !Number.isSafeInteger(host.PidsLimit) || host.PidsLimit < 1
    || !Number.isSafeInteger(host.Memory) || host.Memory < 1
    || !Number.isSafeInteger(host.NanoCpus) || host.NanoCpus < 1
    || serialized.includes("docker.sock") || serialized.includes("/var/run/docker")) {
    fail("semantic helper body is not hardened or contains host authority");
  }
}

function validateHelperRegistry(value) {
  exactKeys(value, Object.keys(PROFILE_POLICY).sort(), "helper profile registry");
  for (const [helperProfileId, policy] of Object.entries(PROFILE_POLICY)) {
    const actual = requiredRecord(value, helperProfileId, "helper profile");
    exactKeys(actual, ["declaredVolumePaths", "engine", "entrypoint", "helperProfileId", "imageId", "imageRef", "networkId", "operation", "outputMode", "resourceKind", "runtimeGid", "runtimeUid", "secretSetId"], `helper profile ${helperProfileId}`);
    const expected = { ...policy, helperProfileId };
    if (canonicalJson(withoutKey(actual, "imageId")) !== canonicalJson(expected)
      || !IMAGE_ID.test(String(actual.imageId ?? ""))) {
      fail(`helper profile ${helperProfileId} canonical identity is invalid`);
    }
  }
}

function validateEndpointRegistry(resources) {
  exactKeys(resources.serviceEndpoints, Object.keys(ENDPOINT_POLICY).sort(), "service endpoint registry");
  for (const [endpointId, policy] of Object.entries(ENDPOINT_POLICY)) {
    const endpoint = requiredRecord(resources.serviceEndpoints, endpointId, "service endpoint");
    exactKeys(endpoint, ["backupResourceId", "engine", "endpointId", "host", "networkId", "port", "protocol", "purpose", "secretSetId", "targetContainerId", "tlsMode"], `service endpoint ${endpointId}`);
    if (endpoint.endpointId !== endpointId || endpoint.engine !== policy.engine
      || endpoint.networkId !== policy.networkId || endpoint.purpose !== policy.purpose
      || endpoint.secretSetId !== policy.secretSetId || endpoint.backupResourceId !== policy.resourceId
      || !SAFE_ID.test(endpoint.host) || !Number.isSafeInteger(endpoint.port)
      || endpoint.port < 1 || endpoint.port > 65535) {
      fail(`service endpoint ${endpointId} canonical authority is invalid`);
    }
    if (policy.resourceId !== null) {
      const resource = requiredRecord(resources.backupResources, policy.resourceId, "backup resource");
      const container = requiredRecord(resources.containers, endpoint.targetContainerId, "target container");
      const network = normalizeNetwork({ resources }, policy.networkId);
      if (resource.kind !== policy.resourceKind
        || (resource.engine ?? "minio") !== policy.engine
        || !container.authority?.networks?.includes(network.engineName)) {
        fail(`service endpoint ${endpointId} live target authority is invalid`);
      }
    } else if (endpoint.targetContainerId !== null) {
      fail(`service endpoint ${endpointId} offsite target is invalid`);
    }
  }
}

function findExactEndpoint(endpoints, helper) {
  const matches = Object.values(endpoints).filter((endpoint) => {
    const resourceKind = endpoint.backupResourceId === null
      ? null
      : ENDPOINT_POLICY[endpoint.endpointId]?.resourceKind;
    return endpoint.engine === helper.engine
      && endpoint.networkId === helper.networkId
      && endpoint.secretSetId === helper.secretSetId
      && resourceKind === helper.resourceKind
      && endpoint.purpose === (helper.operation === "capture" ? "capture" : "offsite");
  });
  if (matches.length !== 1) fail(`helper ${helper.helperProfileId} endpoint identity is ambiguous or missing`);
  return matches[0];
}

function normalizeClaimedResources(value, receiptResources) {
  if (value === null) return null;
  if (!isPlainRecord(value) || !Object.keys(value).length) fail("claimed resource projection is invalid");
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (!Object.hasOwn(receiptResources, key)
      || canonicalJson(value[key]) !== canonicalJson(receiptResources[key])) {
      fail(`claimed resource ${key} does not exactly match the receipt`);
    }
    out[key] = structuredClone(value[key]);
  }
  return deepFreeze(out);
}

function selectedResourceIds(claimed, allResources) {
  const source = claimed ?? allResources;
  return new Set(Object.keys(source).filter((id) => Object.values(RESOURCE_BY_ENGINE).includes(id)));
}

function normalizePriorBinding(value, { phaseId, receipt, requestSha256, selected }) {
  const requiresBinding = ["job.restore.verify", "offsite.sync", "restore.verify"].includes(phaseId);
  if (!requiresBinding) {
    if (value !== null) fail("phase does not own a prior artifact binding");
    return null;
  }
  if (!isPlainRecord(value)) fail("phase requires a prior artifact binding");
  exactKeys(value, ["artifactSetSha256", "artifacts", "consumerRequestSha256", "manifestRelativePath", "manifestSha256", "producerPhaseId", "producerRequestSha256", "schema", "verification"], "prior artifact binding");
  if (value.schema !== BINDING_SCHEMA
    || value.consumerRequestSha256 !== requestSha256
    || !SHA256.test(String(value.producerRequestSha256 ?? ""))
    || !SHA256.test(String(value.artifactSetSha256 ?? ""))
    || !SHA256.test(String(value.manifestSha256 ?? ""))) {
    fail("prior artifact binding lineage or digest is invalid");
  }
  const allowedProducer = phaseId === "restore.verify"
    ? ["restore.capture"]
    : ["catalog.capture", "job.backup.capture", "restore.capture"];
  if (!allowedProducer.includes(value.producerPhaseId)
    || (phaseId === "restore.verify" && value.producerRequestSha256 !== requestSha256)) {
    fail("prior artifact binding cross-phase lineage is invalid");
  }
  const expectedManifest = safeRelativeJoin("requests", value.producerRequestSha256, "manifests", `${value.producerPhaseId}.json`);
  if (value.manifestRelativePath !== expectedManifest) fail("prior artifact binding manifest path is invalid");
  exactKeys(value.verification, ["authoritySha256", "evidenceSha256", "kind", "source"], "prior artifact binding verification");
  const expectedVerification = phaseId === "restore.verify"
    ? {
        authoritySha256: receipt.resources.phaseProfiles["restore.capture"]?.phaseSha256,
        kind: "journaled-phase-result",
        source: "restore.capture",
      }
    : {
        authoritySha256: receipt.resources.workerSecretSets?.["manifest.verification"]?.files?.key?.sha256,
        kind: "verified-manifest",
        source: value.manifestRelativePath,
      };
  if (value.verification.authoritySha256 !== expectedVerification.authoritySha256
    || value.verification.kind !== expectedVerification.kind
    || value.verification.source !== expectedVerification.source
    || !SHA256.test(String(value.verification.authoritySha256 ?? ""))
    || !SHA256.test(String(value.verification.evidenceSha256 ?? ""))) {
    fail("prior artifact binding is synthetic, unsigned or lacks exact verification provenance");
  }
  if (!isPlainRecord(value.artifacts) || !Object.keys(value.artifacts).length) {
    fail("prior artifact binding artifacts are invalid");
  }
  const artifacts = {};
  for (const resourceId of Object.keys(value.artifacts).sort()) {
    if (!Object.hasOwn(receipt.resources.backupResources, resourceId)) {
      fail("prior artifact binding contains an unowned resource");
    }
    const artifact = value.artifacts[resourceId];
    exactKeys(artifact, ["relativePath", "resourceId", "sha256"], `prior artifact ${resourceId}`);
    if (artifact.resourceId !== resourceId || !SHA256.test(String(artifact.sha256 ?? ""))) {
      fail("prior artifact binding resource identity or digest is invalid");
    }
    assertSafeRelativePath(artifact.relativePath, "prior artifact path");
    const engine = Object.entries(RESOURCE_BY_ENGINE).find(([, id]) => id === resourceId)?.[0];
    if (engine) {
      const expectedPath = safeRelativeJoin("requests", value.producerRequestSha256, "artifacts", engine, ARTIFACT_NAME[engine]);
      if (artifact.relativePath !== expectedPath) fail("prior artifact binding path substitution is invalid");
    }
    artifacts[resourceId] = structuredClone(artifact);
  }
  if (value.artifactSetSha256 !== sha256(canonicalJson(artifacts))) {
    fail("prior artifact binding artifact-set digest is invalid");
  }
  for (const resourceId of selected) {
    if (!artifacts[resourceId]) fail(`prior artifact binding is missing ${resourceId}`);
  }
  return deepFreeze({ ...structuredClone(value), artifacts });
}

function normalizeSecretSet(receipt, secretSetId) {
  const set = requiredRecord(receipt.resources.workerSecretSets, secretSetId, "worker secret set");
  exactKeys(set, ["containerRoot", "files", "volumeId"], `secret set ${secretSetId}`);
  assertAbsolutePath(set.containerRoot, `secret set ${secretSetId} root`);
  const expectedFileKeys = SECRET_FILE_KEYS[secretSetId];
  exactKeys(set.files, expectedFileKeys, `secret set ${secretSetId} files`);
  const byKey = {};
  for (const key of expectedFileKeys) {
    const file = set.files[key];
    exactKeys(file, ["device", "inode", "mode", "ownerGid", "ownerUid", "relativePath", "sha256", "symlinkFree"], `secret file ${secretSetId}.${key}`);
    assertSafeRelativePath(file.relativePath, `secret file ${secretSetId}.${key}`);
    if (file.ownerUid !== 0 || file.ownerGid !== 0 || file.mode !== 0o400
      || file.symlinkFree !== true || !SHA256.test(String(file.sha256 ?? ""))) {
      fail(`secret file ${secretSetId}.${key} exact protection is invalid`);
    }
    byKey[key] = safeAbsoluteJoin(set.containerRoot, file.relativePath);
  }
  const volume = requiredRecord(receipt.resources.volumes, set.volumeId, "secret volume");
  normalizeVolume(volume, set.volumeId);
  return deepFreeze({ byKey, containerRoot: set.containerRoot, paths: Object.values(byKey).sort(), volume });
}

function normalizeScratchVolume(receipt) {
  const value = requiredRecord(receipt.resources.volumes, "restore.scratch", "restore scratch volume");
  normalizeVolume(value, "restore.scratch");
  if (value.containerPath !== "/run/platform/restore-scratch") fail("restore scratch container path is invalid");
  return value;
}

function normalizeVolume(value, id) {
  if (!ENGINE_NAME.test(String(value.engineName ?? ""))
    || value.driver !== "local" || value.scope !== "local") {
    fail(`volume ${id} canonical authority is invalid`);
  }
}

function normalizeNetwork(receipt, networkId) {
  const value = requiredRecord(receipt.resources.networks, networkId, "network");
  if (!ENGINE_NAME.test(String(value.engineName ?? ""))
    || !SHA256.test(String(value.engineId ?? ""))
    || value.driver !== "bridge" || value.scope !== "local") {
    fail(`network ${networkId} canonical authority is invalid`);
  }
  return value;
}

function normalizeMount(value, id, access) {
  if (!isPlainRecord(value) || value.access !== access || value.kind !== "host-directory"
    || value.ownerUid !== 0 || value.ownerGid !== 0 || value.mode !== 0o700
    || value.symlinkFree !== true) {
    fail(`mount ${id} canonical authority is invalid`);
  }
  assertAbsolutePath(value.canonicalPath, `mount ${id} path`);
}

function addBindMount(hostConfig, inspect, source, target, readOnly) {
  assertAbsolutePath(source, "helper bind source");
  assertAbsolutePath(target, "helper bind target");
  hostConfig.push({ Type: "bind", Source: source, Target: target, ReadOnly: readOnly, BindOptions: { Propagation: "rprivate" } });
  inspect.push({ Type: "bind", Source: source, Destination: target, Mode: readOnly ? "ro" : "rw", RW: !readOnly, Propagation: "rprivate" });
}

function expectedNetworks(network) {
  return network ? {
    [network.engineName]: { Aliases: [], NetworkID: network.engineId },
  } : {};
}

function matchesExpectedNetworks(observed, expected) {
  if (!isPlainRecord(observed) || !isPlainRecord(expected)
    || canonicalJson(Object.keys(observed).sort()) !== canonicalJson(Object.keys(expected).sort())) {
    return false;
  }
  for (const [name, authority] of Object.entries(expected)) {
    const value = observed[name];
    if (!isPlainRecord(value) || value.NetworkID !== authority.NetworkID
      || (Object.hasOwn(value, "Links") && value.Links !== null
        && (!Array.isArray(value.Links) || value.Links.length > 0))
      || (Object.hasOwn(value, "DriverOpts") && value.DriverOpts !== null
        && (!isPlainRecord(value.DriverOpts) || Object.keys(value.DriverOpts).length > 0))
      || (Object.hasOwn(value, "IPAMConfig") && value.IPAMConfig !== null
        && (!isPlainRecord(value.IPAMConfig) || Object.keys(value.IPAMConfig).length > 0))) {
      return false;
    }
    if (Object.hasOwn(value, "Aliases") && !Array.isArray(value.Aliases)) return false;
  }
  return true;
}

function helperDependencies(profileValue) {
  if (!profileValue.helperProfileId.startsWith("helper.restore.")) return [];
  if (profileValue.operation === "restore-server") return [];
  const prefix = `helper.restore.${profileValue.engine}.`;
  if (profileValue.operation === "restore") return [`${prefix}server`];
  return [`${prefix}server`, `${prefix}restore`];
}

function helperHealthcheck(profileValue, paths) {
  if (profileValue.operation !== "restore-server") return null;
  const command = {
    mariadb: ["CMD", "/usr/bin/mariadb-admin", "--host=127.0.0.1", "--port=3306", "--user=root", "ping", "--silent"],
    minio: ["CMD", "/usr/bin/curl", "-fsS", "http://127.0.0.1:9000/minio/health/live"],
    postgres: ["CMD", "/usr/local/bin/pg_isready", "--host", "127.0.0.1", "--port", "5432"],
  }[profileValue.engine];
  if (!command) fail("restore server readiness policy is unsupported");
  return {
    Test: command,
    Interval: 1_000_000_000,
    Timeout: 2_000_000_000,
    Retries: 60,
    StartPeriod: 1_000_000_000,
  };
}

function helperLifecycle(profileValue) {
  const server = profileValue.operation === "restore-server";
  return {
    cleanup: "reverse-exact-inspect-delete",
    logs: server ? "on-readiness-failure-bounded" : "after-exit-bounded",
    readiness: server ? {
      expectedHealth: "healthy",
      intervalMs: 1000,
      kind: "container-health",
      maximumAttempts: 60,
    } : null,
    remoteEffect: profileValue.operation === "offsite-sync"
      ? "ambiguous-preserve-lease-no-retry"
      : "none",
    waitForExit: !server,
  };
}

function helperOutputPolicy(profileValue, paths) {
  const materialization = {
    atomicRename: true,
    fsync: true,
    input: "sealed-broker-state-snapshot",
    journalBeforeMaterialize: true,
    owner: "socketless-worker-finalizer",
  };
  if (profileValue.outputMode === "artifact") {
    const tree = profileValue.engine === "minio";
    return {
      aggregate: AGGREGATE_RESULT_POLICY,
      artifactPath: paths.outputContainerPath,
      artifactKind: tree ? "tree" : "file",
      canonicalDigestSchema: tree ? "platform.canonical-tree-digest/v1" : "sha256",
      kind: "artifact",
      maximumArtifactBytes: tree ? 2_500_000_000_000 : 1_000_000_000_000,
      maximumEntries: tree ? 5_000_000 : 1,
      maximumReportBytes: 65536,
      maximumSourceBytes: 1048576,
      materialization,
      normalizer: null,
      reportPath: paths.reportRelativePath,
      source: "artifact-inspection",
      specialFiles: "reject",
      symlinks: "reject",
    };
  }
  if (profileValue.outputMode === "json") {
    return {
      aggregate: AGGREGATE_RESULT_POLICY,
      artifactPath: null,
      artifactKind: null,
      canonicalDigestSchema: "canonical-json-sha256",
      kind: "json",
      maximumArtifactBytes: 0,
      maximumEntries: 0,
      maximumReportBytes: 65536,
      maximumSourceBytes: 1048576,
      materialization,
      normalizer: JSON_NORMALIZER[profileValue.helperProfileId],
      reportPath: paths.reportRelativePath,
      source: "docker-logs",
      specialFiles: "reject",
      symlinks: "reject",
    };
  }
  return {
    aggregate: AGGREGATE_RESULT_POLICY,
    artifactPath: null,
    artifactKind: null,
    canonicalDigestSchema: null,
    kind: "none",
    maximumArtifactBytes: 0,
    maximumEntries: 0,
    maximumReportBytes: 65536,
    maximumSourceBytes: 4096,
    materialization,
    normalizer: null,
    reportPath: paths.reportRelativePath,
    source: "exit-status",
    specialFiles: "reject",
    symlinks: "reject",
  };
}

function helperPreconditions(profileValue, paths) {
  const values = [{
    kind: "root-owned-directory",
    mode: 0o700,
    path: path.posix.dirname(paths.reportRelativePath),
    root: "report.root.rw",
  }];
  if (profileValue.operation === "capture") {
    values.unshift({
      kind: "root-owned-directory",
      mode: 0o700,
      path: path.posix.dirname(paths.artifactRelativePath),
      root: "backup.root.rw",
    });
  }
  if (profileValue.operation === "restore-server") {
    values.unshift({
      emptyBeforeServerCreate: true,
      expectedGid: profileValue.runtimeGid,
      expectedUid: profileValue.runtimeUid,
      journalBeforeMaterialize: true,
      kind: "docker-volume-subpath",
      materializeBeforeCreate: true,
      mode: 0o700,
      relativePath: paths.scratchDataRelativePath,
      targetPath: paths.dataContainerPath,
      volumeId: "restore.scratch",
    });
  }
  if (profileValue.helperProfileId === "helper.restore.minio.server") {
    values.push({
      executablePath: "/usr/bin/curl",
      imageId: profileValue.imageId,
      kind: "supply-chain-executable",
      requiredFor: "container-health",
    });
  }
  return deepFreeze(values);
}

function helperName({ helperProfileId, ordinal, phaseId, requestSha256 }) {
  const slug = `${phaseId}-${helperProfileId}`.replaceAll(".", "-");
  const value = `platform-helper-${String(ordinal).padStart(2, "0")}-${slug}-${requestSha256.slice(0, 24)}`;
  if (!ENGINE_NAME.test(value)) fail("deterministic helper name is invalid");
  return value;
}

function profile({ engine, entrypoint, imageRef, networkId = null, operation, outputMode, resourceKind, secretSetId = null }) {
  const declaredVolumePaths = engine === "mariadb"
    ? ["/var/lib/mysql"]
    : engine === "postgres"
      ? ["/var/lib/postgresql"]
      : engine === "minio" && operation === "restore-server"
        ? ["/data"]
        : [];
  const [runtimeUid, runtimeGid] = operation !== "restore-server"
    ? [0, 0]
    : engine === "mariadb"
      ? [999, 999]
      : engine === "postgres"
        ? [70, 70]
        : [1000, 1000];
  return {
    declaredVolumePaths,
    engine,
    entrypoint: [entrypoint],
    imageRef,
    networkId,
    operation,
    outputMode,
    resourceKind,
    runtimeGid,
    runtimeUid,
    secretSetId,
  };
}

function normalizeImageEnv(value) {
  if (!Array.isArray(value) || value.length > 256) fail("helper image environment is oversized");
  const names = new Set();
  return value.map((entry) => {
    if (typeof entry !== "string" || entry.length < 2 || entry.length > 4096
      || entry.includes("\0") || !/^[A-Za-z_][A-Za-z0-9_]*=/.test(entry)) {
      fail("helper image environment entry is invalid");
    }
    const name = entry.slice(0, entry.indexOf("="));
    if (names.has(name)) fail("helper image environment keys are duplicated");
    names.add(name);
    return entry;
  });
}

function mergeImageEnv(planned, inherited) {
  const plannedNames = new Set(planned.map((entry) => entry.slice(0, entry.indexOf("="))));
  return [...planned, ...inherited.filter(
    (entry) => !plannedNames.has(entry.slice(0, entry.indexOf("="))),
  )];
}

function normalizeImageLabels(value) {
  if (value === null) return {};
  if (!isPlainRecord(value) || Object.keys(value).length > 256) {
    fail("helper image labels are invalid or oversized");
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    const item = value[key];
    if (!key || key.length > 256 || key.includes("\0")
      || typeof item !== "string" || item.length > 4096 || item.includes("\0")) {
      fail("helper image label is invalid");
    }
    out[key] = item;
  }
  return out;
}

function normalizeImagePathMap(value, kind) {
  if (value === null) return {};
  if (!isPlainRecord(value) || Object.keys(value).length > 32) {
    fail(`helper image declared ${kind}s are invalid or oversized`);
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (kind === "volume") {
      assertAbsolutePath(key, "helper image declared volume");
    } else {
      const match = /^(\d{1,5})\/(tcp|udp|sctp)$/.exec(key);
      if (!match || Number(match[1]) < 1 || Number(match[1]) > 65535) {
        fail("helper image exposed port metadata is invalid");
      }
    }
    if (value[key] !== null && (!isPlainRecord(value[key]) || Object.keys(value[key]).length)) {
      fail(`helper image declared ${kind} metadata is not empty`);
    }
    out[key] = {};
  }
  return out;
}

function normalizeImageHealthcheck(value) {
  if (value === null) return null;
  if (!isPlainRecord(value)) fail("helper image healthcheck metadata is invalid");
  const cloned = structuredClone(value);
  if (Buffer.byteLength(canonicalJson(cloned)) > 16384) {
    fail("helper image healthcheck metadata is oversized");
  }
  return cloned;
}

function normalizeNullableImageText(value, label) {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string" || value.length > 4096 || value.includes("\0")) {
    fail(`helper image ${label} metadata is invalid`);
  }
  return value;
}

function shellLiteral(value) {
  if (typeof value !== "string" || value.includes("\0")) fail("helper shell path is invalid");
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function safeAbsoluteJoin(root, ...parts) {
  assertAbsolutePath(root, "path root");
  for (const part of parts) assertSafeRelativePath(part, "path segment");
  const value = path.posix.join(root, ...parts);
  if (value !== root && !value.startsWith(`${root}/`)) fail("helper path escaped its admitted root");
  return value;
}

function safeRelativeJoin(...parts) {
  for (const part of parts) assertSafeRelativePath(part, "relative path segment");
  const value = path.posix.join(...parts);
  assertSafeRelativePath(value, "relative helper path");
  return value;
}

function assertAbsolutePath(value, label) {
  if (typeof value !== "string" || value.includes("\0") || !path.posix.isAbsolute(value)
    || path.posix.normalize(value) !== value || value.includes("/../") || value.endsWith("/..")) {
    fail(`${label} is not an exact canonical absolute path`);
  }
}

function assertSafeRelativePath(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.includes("\0")
    || path.posix.isAbsolute(value) || path.posix.normalize(value) !== value
    || value === ".." || value.startsWith("../") || value.includes("/../")) {
    fail(`${label} is not an exact contained relative path`);
  }
}

function requiredRecord(map, key, label) {
  const value = map?.[key];
  if (!isPlainRecord(value)) fail(`${label} ${key} is missing or invalid`);
  return value;
}

function exactKeys(value, expected, label) {
  if (!isPlainRecord(value)
    || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...expected].sort())) {
    fail(`${label} must use the exact supported schema`);
  }
}

function isPlainRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function withoutKey(value, key) {
  return Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (isPlainRecord(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  }
  return value;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function fail(message) {
  throw new Error(message);
}
