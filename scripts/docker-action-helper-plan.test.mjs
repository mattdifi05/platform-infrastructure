import assert from "node:assert/strict";
import test from "node:test";

import {
  assertExactSemanticHelperInspect,
  bindSemanticHelperImageInspect,
  buildSemanticHelperPlan,
} from "./docker-action-helper-plan.mjs";
import {
  buildRawActiveReceiptV2,
  canonicalFixtureJson,
  fixtureSha256,
  resealProfiles,
} from "./docker-action-v2-fixtures.mjs";

const REQUEST_SHA256 = "f".repeat(64);
const PRODUCER_SHA256 = "e".repeat(64);
const SECRET_SENTINEL = "never-copy-this-secret-value";

function planInput(phaseId, overrides = {}) {
  return {
    receipt: buildRawActiveReceiptV2(),
    phaseId,
    requestSha256: REQUEST_SHA256,
    claimedBackupResources: null,
    priorBinding: ["restore.verify", "job.restore.verify", "offsite.sync"].includes(phaseId)
      ? artifactBinding(phaseId)
      : null,
    ...overrides,
  };
}

function artifactBinding(consumerPhaseId = "restore.verify", overrides = {}) {
  const producerRequestSha256 = consumerPhaseId === "restore.verify"
    ? REQUEST_SHA256
    : PRODUCER_SHA256;
  const producerPhaseId = consumerPhaseId === "restore.verify"
    ? "restore.capture"
    : "catalog.capture";
  const root = `requests/${producerRequestSha256}/artifacts`;
  const artifacts = {
    "database:mariadb": {
      relativePath: `${root}/mariadb/mariadb.sql`,
      resourceId: "database:mariadb",
      sha256: "2".repeat(64),
    },
    "database:postgres": {
      relativePath: `${root}/postgres/postgres.dump`,
      resourceId: "database:postgres",
      sha256: "3".repeat(64),
    },
    "storage:minio": {
      relativePath: `${root}/minio/objects`,
      resourceId: "storage:minio",
      sha256: "4".repeat(64),
    },
  };
  const manifestRelativePath = `requests/${producerRequestSha256}/manifests/${producerPhaseId}.json`;
  return {
    schema: "platform.docker-action.artifact-binding/v1",
    artifactSetSha256: fixtureSha256(canonicalFixtureJson(artifacts)),
    artifacts,
    consumerRequestSha256: REQUEST_SHA256,
    manifestRelativePath,
    manifestSha256: "5".repeat(64),
    producerPhaseId,
    producerRequestSha256,
    verification: consumerPhaseId === "restore.verify"
      ? {
          authoritySha256: buildRawActiveReceiptV2().resources.phaseProfiles["restore.capture"].phaseSha256,
          evidenceSha256: "6".repeat(64),
          kind: "journaled-phase-result",
          source: "restore.capture",
        }
      : {
          authoritySha256: buildRawActiveReceiptV2().resources.workerSecretSets["manifest.verification"].files.key.sha256,
          evidenceSha256: "6".repeat(64),
          kind: "verified-manifest",
          source: manifestRelativePath,
        },
    ...overrides,
  };
}

function ids(plan) {
  return plan.helpers.map(({ helperProfileId }) => helperProfileId);
}

function clone(value) {
  return structuredClone(value);
}

function reseal(receipt) {
  return resealProfiles(receipt);
}

test("helper plan has exact causal 3 capture, 9 restore, 1 Restic and 0 prune inventories", () => {
  assert.deepEqual(ids(buildSemanticHelperPlan(planInput("catalog.capture"))), [
    "helper.capture.mariadb",
    "helper.capture.minio",
    "helper.capture.postgres",
  ]);
  assert.deepEqual(ids(buildSemanticHelperPlan(planInput("restore.verify"))), [
    "helper.restore.mariadb.server",
    "helper.restore.mariadb.restore",
    "helper.restore.mariadb.verify",
    "helper.restore.minio.server",
    "helper.restore.minio.restore",
    "helper.restore.minio.verify",
    "helper.restore.postgres.server",
    "helper.restore.postgres.restore",
    "helper.restore.postgres.verify",
  ]);
  assert.deepEqual(ids(buildSemanticHelperPlan(planInput("offsite.sync"))), [
    "helper.offsite.restic",
  ]);
  assert.deepEqual(ids(buildSemanticHelperPlan(planInput("prune.plan"))), []);
});

test("helper inventory deletion, extension and reorder fail closed even after phase reseal", () => {
  for (const mutate of [
    (idsValue) => idsValue.pop(),
    (idsValue) => idsValue.push("helper.offsite.restic"),
    (idsValue) => idsValue.reverse(),
  ]) {
    const receipt = clone(buildRawActiveReceiptV2());
    mutate(receipt.resources.phaseProfiles["restore.verify"].helperProfileIds);
    reseal(receipt);
    assert.throws(
      () => buildSemanticHelperPlan(planInput("restore.verify", { receipt })),
      /canonical helper inventory|helper profile/i,
    );
  }
});

test("capture helpers join endpoints by exact identity and receive least authority", () => {
  const plan = buildSemanticHelperPlan(planInput("catalog.capture"));
  const expected = {
    "helper.capture.mariadb": ["capture.database.mariadb", "platform_db_admin", "mariadb.capture.credentials"],
    "helper.capture.minio": ["capture.storage.minio", "platform_storage", "minio.capture.credentials"],
    "helper.capture.postgres": ["capture.database.postgres", "platform_db_admin", "postgres.capture.credentials"],
  };
  for (const helper of plan.helpers) {
    assert.deepEqual(
      [helper.endpointId, helper.networkId, helper.secretSetId],
      expected[helper.helperProfileId],
    );
    assert.equal(Object.keys(helper.expectedInspect.networks).length, 1);
    assert.equal(helper.body.HostConfig.Mounts.filter(({ Type }) => Type === "volume").length, 1);
    assert.doesNotMatch(JSON.stringify(helper), /docker\.sock|platform_egress/);
  }
  assert.equal(plan.helpers[1].endpointId, "capture.storage.minio");
  assert.equal(plan.helpers[2].endpointId, "capture.database.postgres");
});

test("runtime principals and declared image volumes are exact and never anonymous", () => {
  const capture = buildSemanticHelperPlan(planInput("catalog.capture"));
  const mariadbCapture = capture.helpers.find(({ engine }) => engine === "mariadb");
  const postgresCapture = capture.helpers.find(({ engine }) => engine === "postgres");
  assert.equal(mariadbCapture.body.User, "0:0");
  assert.equal(postgresCapture.body.User, "0:0");
  assert.equal(
    mariadbCapture.body.HostConfig.Tmpfs["/var/lib/mysql"],
    "rw,noexec,nosuid,nodev,size=16777216,mode=0700,uid=0,gid=0",
  );
  assert.equal(
    postgresCapture.body.HostConfig.Tmpfs["/var/lib/postgresql"],
    "rw,noexec,nosuid,nodev,size=16777216,mode=0700,uid=0,gid=0",
  );

  const restore = buildSemanticHelperPlan(planInput("restore.verify"));
  const expectedServers = {
    mariadb: ["999:999", "/var/lib/mysql", 999, 999],
    minio: ["1000:1000", "/data", 1000, 1000],
    postgres: ["70:70", "/var/lib/postgresql", 70, 70],
  };
  for (const [engine, [user, target, expectedUid, expectedGid]] of Object.entries(expectedServers)) {
    const server = restore.helpers.find(
      (helper) => helper.engine === engine && helper.operation === "restore-server",
    );
    assert.equal(server.body.User, user);
    assert.equal(Object.hasOwn(server.body.HostConfig.Tmpfs, target), false);
    const data = server.body.HostConfig.Mounts.find(({ Target }) => Target === target);
    assert.deepEqual(data, {
      ReadOnly: false,
      Source: "platform_docker_action_restore_scratch",
      Target: target,
      Type: "volume",
      VolumeOptions: {
        NoCopy: true,
        Subpath: `requests/${REQUEST_SHA256}/restore.verify/${engine}/data`,
      },
    });
    assert.deepEqual(
      server.preconditions.find(({ kind }) => kind === "docker-volume-subpath"),
      {
        emptyBeforeServerCreate: true,
        expectedGid,
        expectedUid,
        journalBeforeMaterialize: true,
        kind: "docker-volume-subpath",
        materializeBeforeCreate: true,
        mode: 0o700,
        relativePath: `requests/${REQUEST_SHA256}/restore.verify/${engine}/data`,
        targetPath: target,
        volumeId: "restore.scratch",
      },
    );
  }
});

test("claimed resource projection is exact, filters helpers and rejects forged authority", () => {
  const receipt = buildRawActiveReceiptV2();
  const claimedBackupResources = {
    "database:postgres": clone(receipt.resources.backupResources["database:postgres"]),
  };
  const capture = buildSemanticHelperPlan(planInput("job.backup.capture", {
    receipt,
    claimedBackupResources,
  }));
  assert.deepEqual(ids(capture), ["helper.capture.postgres"]);

  claimedBackupResources["database:postgres"].name = "forged";
  assert.throws(
    () => buildSemanticHelperPlan(planInput("job.backup.capture", {
      receipt,
      claimedBackupResources,
    })),
    /claimed resource.*receipt/i,
  );
});

test("paths and names are deterministic, contained, immutable and request-separated", () => {
  const input = planInput("catalog.capture");
  const before = clone(input);
  const first = buildSemanticHelperPlan(input);
  const second = buildSemanticHelperPlan(input);
  assert.deepEqual(first, second);
  assert.deepEqual(input, before);
  assert.ok(Object.isFrozen(first));
  assert.ok(Object.isFrozen(first.helpers[0].body.HostConfig));
  for (const helper of first.helpers) {
    assert.match(helper.paths.artifactRelativePath, new RegExp(`^requests/${REQUEST_SHA256}/artifacts/`));
    assert.match(helper.paths.reportRelativePath, new RegExp(`^docker-actions/${REQUEST_SHA256}/catalog\\.capture/helpers/`));
    assert.match(helper.name, /^platform-helper-[a-z0-9-]{1,110}$/);
  }

  const other = buildSemanticHelperPlan(planInput("catalog.capture", {
    requestSha256: "a".repeat(64),
  }));
  assert.notEqual(first.helpers[0].name, other.helpers[0].name);
  assert.notEqual(first.helpers[0].paths.artifactRelativePath, other.helpers[0].paths.artifactRelativePath);
  assert.throws(
    () => buildSemanticHelperPlan(planInput("catalog.capture", { requestSha256: "../escape" })),
    /request sha256/i,
  );
});

test("restore requires an exact immutable cross-phase artifact binding", () => {
  assert.throws(
    () => buildSemanticHelperPlan(planInput("restore.verify", { priorBinding: null })),
    /prior artifact binding/i,
  );
  for (const priorBinding of [
    artifactBinding("restore.verify", { consumerRequestSha256: "a".repeat(64) }),
    artifactBinding("restore.verify", { producerPhaseId: "catalog.capture" }),
    artifactBinding("restore.verify", { manifestSha256: "not-a-digest" }),
    artifactBinding("restore.verify", { manifestRelativePath: "../manifest.json" }),
    (() => {
      const value = artifactBinding("restore.verify");
      value.artifacts["database:postgres"].relativePath = "requests/forged/postgres.dump";
      return value;
    })(),
  ]) {
    assert.throws(
      () => buildSemanticHelperPlan(planInput("restore.verify", { priorBinding })),
      /binding|manifest|artifact|lineage|path|digest/i,
    );
  }
});

test("restore is server then restore then verify in isolated shared network namespaces", () => {
  const plan = buildSemanticHelperPlan(planInput("restore.verify"));
  for (const engine of ["mariadb", "minio", "postgres"]) {
    const group = plan.helpers.filter((helper) => helper.engine === engine);
    assert.deepEqual(group.map(({ operation }) => operation), ["restore-server", "restore", "verify"]);
    assert.deepEqual(group.map(({ cleanupOrdinal }) => cleanupOrdinal), [2, 1, 0]);
    assert.equal(new Set(group.map(({ paths }) => paths.scratchRelativePath)).size, 1);
  }

  for (const engine of ["mariadb", "minio", "postgres"]) {
    const [server, ...clients] = plan.helpers.filter((helper) => helper.engine === engine);
    assert.equal(server.body.HostConfig.NetworkMode, "none");
    assert.equal(server.body.NetworkDisabled, true);
    for (const client of clients) {
      assert.equal(client.body, null);
      assert.equal(client.deferredBody.schema, "platform.docker-action.deferred-helper-body/v1");
      assert.equal(client.deferredBody.requires.helperProfileId, `helper.restore.${engine}.server`);
      assert.equal(client.deferredBody.requires.value, "containerId");
      assert.equal(client.deferredBody.networkModePrefix, "container:");
      assert.deepEqual(client.deferredBody.baseBody.NetworkingConfig.EndpointsConfig, {});
    }
  }
  for (const helper of plan.helpers) {
    assert.doesNotMatch(JSON.stringify(helper), /capture\.|worker-secrets|docker\.sock|platform_(?:db_admin|storage|egress)/);
  }

  const minio = plan.helpers.filter(({ engine }) => engine === "minio");
  for (const client of minio.slice(1)) {
    assert.equal(client.body, null);
  }
});

test("Restic receives only egress, offsite files and one bound request subtree ro", () => {
  const helper = buildSemanticHelperPlan(planInput("offsite.sync")).helpers[0];
  assert.equal(helper.networkId, "platform_egress");
  assert.equal(helper.secretSetId, "offsite.credentials");
  assert.deepEqual([...helper.secretFilePaths].sort(), [
    "/run/platform/worker-secrets/offsite/password",
    "/run/platform/worker-secrets/offsite/repository",
  ]);
  assert.deepEqual(
    helper.body.HostConfig.Mounts.filter(({ Type }) => Type === "bind").map(({ ReadOnly, Target }) => [Target, ReadOnly]),
    [[`/data/backups/requests/${PRODUCER_SHA256}`, true]],
  );
  assert.equal(helper.body.Cmd.at(-1), `/data/backups/requests/${PRODUCER_SHA256}`);
  assert.doesNotMatch(JSON.stringify(helper.body.HostConfig.Mounts), /"Target":"\/data\/backups"/);
  assert.equal(Object.keys(helper.expectedInspect.networks).length, 1);
});

test("helper bodies contain only secret paths and reject secret-bearing receipt extensions", () => {
  const plan = buildSemanticHelperPlan(planInput("catalog.capture"));
  assert.doesNotMatch(JSON.stringify(plan), new RegExp(SECRET_SENTINEL));

  const receipt = clone(buildRawActiveReceiptV2());
  receipt.resources.workerSecretSets["mariadb.capture.credentials"].files.clientConfig.secretValue = SECRET_SENTINEL;
  assert.throws(
    () => buildSemanticHelperPlan(planInput("catalog.capture", { receipt })),
    /secret file.*exact|unsupported.*secret/i,
  );
});

test("helper HostConfig is hardened and exact inspect rejects widening", () => {
  const plan = buildSemanticHelperPlan(planInput("catalog.capture"));
  for (const unbound of plan.helpers) {
    const helper = bindSemanticHelperImageInspect(unbound, exactImageInspect(unbound));
    const host = helper.body.HostConfig;
    assert.deepEqual(host.CapAdd, []);
    assert.deepEqual(host.CapDrop, ["ALL"]);
    assert.equal(host.Privileged, false);
    assert.equal(host.ReadonlyRootfs, true);
    assert.deepEqual(host.SecurityOpt, ["no-new-privileges:true"]);
    assert.equal(host.PidMode, "");
    assert.equal(host.IpcMode, "private");
    assert.deepEqual(host.Devices, []);
    assert.deepEqual(host.PortBindings, {});
    assert.equal(host.Tmpfs["/tmp"], "rw,noexec,nosuid,nodev,size=67108864,mode=1777");
    assert.deepEqual(
      Object.keys(host.Tmpfs).filter((target) => target !== "/tmp").sort(),
      helper.declaredVolumePaths ?? [],
    );

    const inspect = exactInspect(helper);
    assert.equal(assertExactSemanticHelperInspect(inspect, helper), true);
    for (const mutate of [
      (value) => { value.HostConfig.Privileged = true; },
      (value) => { value.HostConfig.CapAdd = ["SYS_ADMIN"]; },
      (value) => { value.HostConfig.Binds = ["/var/run/docker.sock:/var/run/docker.sock:rw"]; },
      (value) => { value.NetworkSettings.Networks = {}; },
      (value) => { value.Mounts[0].RW = !value.Mounts[0].RW; },
      (value) => { value.Config.Entrypoint = ["/bin/false"]; },
    ]) {
      const widened = clone(inspect);
      mutate(widened);
      assert.throws(
        () => assertExactSemanticHelperInspect(widened, helper),
        /helper.*exact|widened|mount|network|identity/i,
      );
    }
  }
});

test("profile, endpoint and path authority substitutions fail before a body is returned", () => {
  const cases = [
    (receipt) => { receipt.resources.helperProfiles["helper.capture.postgres"].networkId = "platform_storage"; },
    (receipt) => { receipt.resources.helperProfiles["helper.capture.postgres"].entrypoint = ["/bin/sh"]; },
    (receipt) => { receipt.resources.serviceEndpoints["capture.database.postgres"].secretSetId = "mariadb.capture.credentials"; },
    (receipt) => { receipt.resources.mounts["backup.root.rw"].canonicalPath = "/srv/platform/backups/../escape"; },
  ];
  for (const mutate of cases) {
    const receipt = clone(buildRawActiveReceiptV2());
    mutate(receipt);
    assert.throws(
      () => buildSemanticHelperPlan(planInput("catalog.capture", { receipt })),
      /profile|endpoint|mount|path|volume|canonical|authority/i,
    );
  }

  const restoreReceipt = clone(buildRawActiveReceiptV2());
  restoreReceipt.resources.volumes["restore.scratch"].engineName = "../../escape";
  assert.throws(
    () => buildSemanticHelperPlan(planInput("restore.verify", { receipt: restoreReceipt })),
    /volume|path|canonical|authority/i,
  );
});

test("lifecycle, readiness, output and remote ambiguity policies are explicit", () => {
  const restore = buildSemanticHelperPlan(planInput("restore.verify"));
  for (const helper of restore.helpers) {
    if (helper.operation === "restore-server") {
      assert.equal(helper.lifecycle.waitForExit, false);
      assert.deepEqual(helper.lifecycle.readiness, {
        expectedHealth: "healthy",
        intervalMs: 1000,
        kind: "container-health",
        maximumAttempts: 60,
      });
      assert.ok(helper.body?.Healthcheck || helper.deferredBody?.baseBody.Healthcheck);
    } else {
      assert.equal(helper.lifecycle.waitForExit, true);
      assert.equal(helper.lifecycle.readiness, null);
    }
    assert.equal(helper.lifecycle.cleanup, "reverse-exact-inspect-delete");
    assert.ok(["artifact", "json", "none"].includes(helper.outputPolicy.kind));
  }

  const restic = buildSemanticHelperPlan(planInput("offsite.sync")).helpers[0];
  assert.equal(restic.lifecycle.remoteEffect, "ambiguous-preserve-lease-no-retry");
  assert.equal(restic.lifecycle.waitForExit, true);
  assert.equal(restic.outputPolicy.kind, "json");
  assert.equal(restic.outputPolicy.normalizer, "restic-terminal-summary-v1");
  assert.deepEqual(restic.remoteAttempt, {
    idempotencyKey: fixtureSha256(`platform-offsite-sync-v1\n${restic.remoteAttempt.manifestSha256}\n`),
    journalBeforeStart: true,
    manifestSha256: "5".repeat(64),
    onAmbiguity: "preserve-lease-no-retry",
  });
});

test("image, PostgreSQL service files and MinIO commands are operationally bound", () => {
  const receipt = buildRawActiveReceiptV2();
  const capture = buildSemanticHelperPlan(planInput("catalog.capture", { receipt }));
  for (const helper of capture.helpers) {
    assert.equal(helper.body.Image, receipt.resources.helperProfiles[helper.helperProfileId].imageRef);
    assert.notEqual(helper.body.Image, null);
  }

  const postgres = capture.helpers.find(({ engine }) => engine === "postgres");
  assert.deepEqual(postgres.body.Env, [
    "HOME=/tmp",
    "LANG=C.UTF-8",
    "PGPASSFILE=/run/platform/worker-secrets/postgres-capture/.pgpass",
    "PGSERVICE=platform_capture",
    "PGSERVICEFILE=/run/platform/worker-secrets/postgres-capture/pg_service.conf",
    "PGSSLMODE=require",
  ]);
  assert.ok(postgres.body.Cmd.includes("--dbname=service=platform_capture"));
  assert.doesNotMatch(JSON.stringify(postgres.body), /--username=|PGUSER=|PGDATABASE=/);

  const minioCapture = capture.helpers.find(({ engine }) => engine === "minio");
  const script = minioCapture.body.Cmd.at(-1);
  assert.match(script, /\/usr\/bin\/mc alias set source/);
  assert.doesNotMatch(script, /exec \/usr\/bin\/mc alias set/);
  assert.match(script, /exec \/usr\/bin\/mc mirror --quiet/);
  assert.doesNotMatch(script, /mirror --json/);
  assert.deepEqual(minioCapture.outputPolicy, {
    artifactPath: "/output/objects",
    artifactKind: "tree",
    canonicalDigestSchema: "platform.canonical-tree-digest/v1",
    kind: "artifact",
    maximumArtifactBytes: 2_500_000_000_000,
    maximumEntries: 5_000_000,
    maximumReportBytes: 65536,
    maximumSourceBytes: 1048576,
    materialization: {
      atomicRename: true,
      fsync: true,
      input: "sealed-broker-state-snapshot",
      journalBeforeMaterialize: true,
      owner: "socketless-worker-finalizer",
    },
    aggregate: {
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
    },
    reportPath: `docker-actions/${REQUEST_SHA256}/catalog.capture/helpers/01-helper.capture.minio.json`,
    normalizer: null,
    source: "artifact-inspection",
    specialFiles: "reject",
    symlinks: "reject",
  });

  const restore = buildSemanticHelperPlan(planInput("restore.verify", { receipt }));
  const minio = restore.helpers.filter(({ engine }) => engine === "minio");
  assert.ok(minio[0].body.Env.includes("MINIO_ROOT_USER=restore"));
  assert.ok(minio[0].body.Env.includes("MINIO_ROOT_PASSWORD=restore-only-no-live-authority"));
  assert.deepEqual(
    minio[0].preconditions.find(({ kind }) => kind === "supply-chain-executable"),
    {
      executablePath: "/usr/bin/curl",
      imageId: receipt.resources.helperProfiles["helper.restore.minio.server"].imageId,
      kind: "supply-chain-executable",
      requiredFor: "container-health",
    },
  );
  for (const client of minio.slice(1)) {
    assert.ok(client.deferredBody.baseBody.Env.includes(
      "MC_HOST_restore=http://restore:restore-only-no-live-authority@127.0.0.1:9000",
    ));
    assert.equal(
      client.deferredBody.baseBody.HostConfig.Mounts.some(
        ({ Source }) => Source === "platform_docker_action_restore_scratch",
      ),
      false,
      "MinIO clients must use only the isolated server API, never its data directory",
    );
    assert.doesNotMatch(JSON.stringify(client.deferredBody.baseBody.Cmd), /restore-scratch\/data/);
  }
  assert.ok(minio[1].deferredBody.baseBody.Cmd.includes("--quiet"));
  assert.equal(minio[1].deferredBody.baseBody.Cmd.includes("--json"), false);
  assert.deepEqual(minio[2].deferredBody.baseBody.Cmd, [
    "diff",
    "--json",
    "/input/objects",
    "restore",
  ]);
  assert.equal(minio[2].outputPolicy.normalizer, "empty-minio-diff-v1");
  assert.equal(
    restore.helpers.find(({ helperProfileId }) => helperProfileId === "helper.restore.mariadb.verify")
      .outputPolicy.normalizer,
    "exact-mariadb-verify-v1",
  );
  assert.equal(
    restore.helpers.find(({ helperProfileId }) => helperProfileId === "helper.restore.postgres.verify")
      .outputPolicy.normalizer,
    "exact-postgres-verify-v1",
  );
});

test("only restore servers receive exact named scratch data subpaths", () => {
  const restore = buildSemanticHelperPlan(planInput("restore.verify"));
  for (const helper of restore.helpers) {
    const precondition = helper.preconditions.find(({ kind }) => kind === "docker-volume-subpath");
    const scratchMount = (helper.body ?? helper.deferredBody.baseBody).HostConfig.Mounts.find(
      ({ Source }) => Source === "platform_docker_action_restore_scratch",
    );
    if (helper.operation !== "restore-server") {
      assert.equal(precondition, undefined);
      assert.equal(scratchMount, undefined);
    } else {
      assert.equal(precondition.relativePath, `requests/${REQUEST_SHA256}/restore.verify/${helper.engine}/data`);
      assert.equal(scratchMount.VolumeOptions.Subpath, precondition.relativePath);
      assert.equal(scratchMount.Target, helper.paths.dataContainerPath);
    }
  }
});

test("prior binding rejects missing provenance and artifact-set digest substitution", () => {
  const noVerification = artifactBinding();
  delete noVerification.verification;
  const wrongAuthority = artifactBinding();
  wrongAuthority.verification.authoritySha256 = "9".repeat(64);
  const wrongSet = artifactBinding();
  wrongSet.artifactSetSha256 = "8".repeat(64);
  for (const priorBinding of [noVerification, wrongAuthority, wrongSet]) {
    assert.throws(
      () => buildSemanticHelperPlan(planInput("restore.verify", { priorBinding })),
      /binding|verification|synthetic|unsigned|artifact-set|digest/i,
    );
  }
});

test("exact inspect accepts allowlisted Docker runtime network fields but rejects authority fields", () => {
  const unbound = buildSemanticHelperPlan(planInput("catalog.capture")).helpers[0];
  const helper = bindSemanticHelperImageInspect(unbound, exactImageInspect(unbound));
  const inspect = exactInspect(helper);
  const network = inspect.NetworkSettings.Networks[Object.keys(inspect.NetworkSettings.Networks)[0]];
  Object.assign(network, {
    Aliases: [helper.name],
    DriverOpts: null,
    EndpointID: "7".repeat(64),
    Gateway: "172.29.0.1",
    GlobalIPv6Address: "",
    GlobalIPv6PrefixLen: 0,
    IPAMConfig: null,
    IPAddress: "172.29.0.10",
    IPPrefixLen: 24,
    IPv6Gateway: "",
    Links: null,
    MacAddress: "02:42:ac:1d:00:0a",
  });
  assert.equal(assertExactSemanticHelperInspect(inspect, helper), true);

  const widened = clone(inspect);
  widened.NetworkSettings.Networks[Object.keys(widened.NetworkSettings.Networks)[0]].DriverOpts = {
    parent: "eth0",
  };
  assert.throws(
    () => assertExactSemanticHelperInspect(widened, helper),
    /network authority.*exact/i,
  );
});

test("image runtime merge is exact, digest-bound and rejects undeclared authority", () => {
  const unbound = buildSemanticHelperPlan(planInput("catalog.capture")).helpers[0];
  const imageInspect = exactImageInspect(unbound);
  const helper = bindSemanticHelperImageInspect(unbound, imageInspect);
  assert.equal(helper.imageRuntimeConfig.schema, "platform.docker-action.image-runtime-config/v1");
  assert.match(helper.imageRuntimeConfigSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(helper.body.Env.slice(-2), ["PATH=/usr/local/bin:/usr/bin", "IMAGE_DEFAULT=1"]);
  assert.deepEqual(helper.body.Volumes, { "/var/lib/mysql": {} });
  assert.deepEqual(helper.body.ExposedPorts, { "3306/tcp": {} });
  assert.deepEqual(helper.body.Healthcheck, { Test: ["NONE"] });
  assert.equal(helper.expectedInspect.imageRuntimeConfigSha256, helper.imageRuntimeConfigSha256);
  assert.equal(assertExactSemanticHelperInspect(exactInspect(helper), helper), true);

  for (const mutate of [
    (value) => { value.Id = `sha256:${"1".repeat(64)}`; },
    (value) => { value.Config.Volumes["/host"] = {}; },
    (value) => { value.Config.OnBuild = ["RUN attacker"]; },
    (value) => { value.Config.ExposedPorts["70000/tcp"] = {}; },
    (value) => { value.Config.Env.push("PATH=/attacker"); },
  ]) {
    const widened = clone(imageInspect);
    mutate(widened);
    assert.throws(
      () => bindSemanticHelperImageInspect(unbound, widened),
      /image|runtime|volume|OnBuild|port|environment|identity|authority/i,
    );
  }
});

test("every helper has one bounded aggregate handoff and no writable report authority", () => {
  for (const phaseId of ["catalog.capture", "restore.verify", "offsite.sync"]) {
    const plan = buildSemanticHelperPlan(planInput(phaseId));
    for (const helper of plan.helpers) {
      assert.equal(helper.paths.reportContainerPath, null);
      assert.equal(helper.outputPolicy.reportPath, helper.paths.reportRelativePath);
      assert.equal(
        (helper.body ?? helper.deferredBody.baseBody).HostConfig.Mounts.some(
          ({ Destination, Target }) => Destination === "/report" || Target === "/report",
        ),
        false,
      );
      assert.deepEqual(helper.outputPolicy.aggregate, {
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
      assert.equal(Object.hasOwn(helper.outputPolicy, "sealedResultSchema"), false);
      assert.ok(["artifact-inspection", "docker-logs", "exit-status"].includes(helper.outputPolicy.source));
      assert.equal(
        helper.outputPolicy.normalizer === null
          || [
            "empty-minio-diff-v1",
            "exact-mariadb-verify-v1",
            "exact-postgres-verify-v1",
            "restic-terminal-summary-v1",
          ].includes(helper.outputPolicy.normalizer),
        true,
      );
      assert.ok(helper.outputPolicy.maximumSourceBytes > 0);
      assert.deepEqual(helper.outputPolicy.materialization, {
        atomicRename: true,
        fsync: true,
        input: "sealed-broker-state-snapshot",
        journalBeforeMaterialize: true,
        owner: "socketless-worker-finalizer",
      });
      assert.equal(
        helper.preconditions.some(
          ({ kind, path, root }) => kind === "root-owned-directory"
            && root === "report.root.rw"
            && path === pathDirname(helper.paths.reportRelativePath),
        ),
        true,
      );
    }
  }
});

function pathDirname(value) {
  return value.slice(0, value.lastIndexOf("/"));
}

function exactInspect(helper) {
  return {
    Id: "a".repeat(64),
    Name: `/${helper.name}`,
    Image: helper.imageId,
    Config: {
      Image: helper.body.Image,
      Entrypoint: clone(helper.body.Entrypoint),
      Cmd: clone(helper.body.Cmd),
      Env: clone(helper.body.Env),
      User: helper.body.User,
      WorkingDir: helper.body.WorkingDir,
      NetworkDisabled: helper.body.NetworkDisabled,
      AttachStdin: false,
      AttachStdout: false,
      AttachStderr: false,
      OpenStdin: false,
      StdinOnce: false,
      Tty: false,
      Labels: clone(helper.body.Labels),
      Volumes: clone(helper.body.Volumes),
      ExposedPorts: clone(helper.body.ExposedPorts),
      Healthcheck: clone(helper.body.Healthcheck),
      OnBuild: clone(helper.body.OnBuild),
      Shell: clone(helper.body.Shell),
      StopSignal: helper.body.StopSignal,
    },
    HostConfig: clone(helper.body.HostConfig),
    Mounts: clone(helper.expectedInspect.mounts),
    NetworkSettings: { Networks: clone(helper.expectedInspect.networks) },
  };
}

function exactImageInspect(helper) {
  const exposedPorts = helper.engine === "mariadb"
    ? { "3306/tcp": {} }
    : helper.engine === "postgres"
      ? { "5432/tcp": {} }
      : helper.operation === "restore-server" && helper.engine === "minio"
        ? { "9000/tcp": {} }
        : {};
  return {
    Id: helper.imageId,
    Config: {
      Env: ["PATH=/usr/local/bin:/usr/bin", "IMAGE_DEFAULT=1"],
      ExposedPorts: exposedPorts,
      Healthcheck: { Test: ["CMD", "/bin/false"] },
      Labels: { "org.opencontainers.image.vendor": "fixture" },
      OnBuild: null,
      Shell: ["/bin/sh", "-c"],
      StopSignal: "SIGTERM",
      User: "",
      Volumes: Object.fromEntries(helper.declaredVolumePaths.map((target) => [target, {}])),
      WorkingDir: "",
    },
  };
}
