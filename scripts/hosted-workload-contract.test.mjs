#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  resolveCatalog,
  validateGlobalRouteOwnership,
  validateRenderedWorkloads,
  validateWorkloadEnvironmentText,
  validateWorkloadManifest,
  verifyLockFiles,
  verifyRawPolicyReceipt,
} from "./hosted-workload-contract.mjs";
import { brokerPolicySha256, expectedNatsPolicy, expectedRedisPolicy } from "./workload-broker-policy.mjs";

const digest = "a".repeat(64);
const manifest = validateWorkloadManifest({
  version: 1,
  id: "example-app",
  composeFile: "compose.platform.yaml",
  secrets: ["example-app-database-url"],
  migrationRoots: ["postgres/migrations"],
  services: [
    {
      name: "example-app-web",
      role: "web",
      routes: [{ slug: "example", host: "Example.Example.com.", aliases: ["example-alt"], port: 3000 }],
    },
    { name: "example-app-worker", role: "worker" },
  ],
});

const baseService = {
  image: `registry.example/example/app@sha256:${digest}`,
  read_only: true,
  init: true,
  restart: "unless-stopped",
  security_opt: ["no-new-privileges:true"],
  cap_drop: ["ALL"],
  user: "1000:1000",
  pids_limit: 128,
  cpu_shares: 256,
  blkio_config: { weight: 300 },
  ulimits: { nofile: { soft: 8192, hard: 8192 } },
  cpus: 0.5,
  mem_limit: String(256 * 1024 * 1024),
  mem_reservation: String(64 * 1024 * 1024),
  healthcheck: { test: ["CMD", "node", "healthcheck.mjs"] },
  networks: { example_app_ingress: null },
  labels: { "com.platform.workload-id": "example-app", "com.platform.workload-role": "web" },
};

const core = {
  services: { "project-router": { image: `registry.example/router@sha256:${digest}`, networks: { platform_routing: null } } },
  networks: { platform_routing: { internal: true } },
};

function combinedFixture() {
  return {
    services: {
      "project-router": { ...core.services["project-router"], networks: { platform_routing: null, example_app_ingress: null } },
      "example-app-web": {
        ...structuredClone(baseService),
        secrets: [{ source: "example-app-database-url", target: "example-app-database-url" }],
        environment: { DATABASE_URL_FILE: "/run/secrets/example-app-database-url" },
      },
      "example-app-worker": {
        ...structuredClone(baseService),
        networks: { example_app_egress: null },
        labels: { "com.platform.workload-id": "example-app", "com.platform.workload-role": "worker" },
      },
    },
    networks: { platform_routing: { internal: true }, example_app_ingress: { internal: true }, example_app_egress: { internal: false, enable_ipv6: false } },
    secrets: { "example-app-database-url": { external: true } },
  };
}

const lock = { workloads: [manifest], brokerPolicySha256: brokerPolicySha256([manifest]) };
let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  process.stdout.write(`ok ${passed} - ${name}\n`);
}

test("exact hardened workload render passes", () => {
  assert.equal(manifest.version, 1);
  const result = validateRenderedWorkloads({ core, combined: combinedFixture(), lock });
  assert.deepEqual(result.routes, [{
    owner: "example-app",
    workloadId: "example-app",
    slug: "example",
    aliases: ["example-alt"],
    canonicalHost: "example.example.com",
    hosts: ["example.example.com", "example-alt.example.com"],
    service: "example-app-web",
    port: 3000,
    upstream: "http://example-app-web:3000",
  }]);
});
test("build context is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].build = { context: "." };
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot build/);
});
test("mutable image is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].image = "registry.example/example/app:latest";
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /digest-pinned/);
});
test("bind mount is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].volumes = [{ type: "bind", source: "/srv", target: "/app" }];
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /bind mounts are forbidden/);
});
test("host port is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].ports = [{ target: 3000, published: "3000" }];
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /host ports/);
});
test("root user is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].user = "0:0";
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /non-root/);
});
test("literal secret environment is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-web"].environment.DATABASE_URL = "postgres://user:password@postgres/db";
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /sensitive environment/);
});
test("file-backed secret must be external", () => {
  const combined = combinedFixture();
  combined.secrets["example-app-database-url"] = { file: "/tmp/secret" };
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /must be external/);
});
test("platform service mutation is rejected", () => {
  const combined = combinedFixture();
  combined.services["project-router"].privileged = true;
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /changed protected platform service/);
});
test("unauthorized platform network extension is rejected", () => {
  const combined = combinedFixture();
  combined.services["project-router"].networks.evil = null;
  combined.networks.evil = { internal: true };
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /non-workload network/);
});
test("platform service can join only its assigned workload zone", () => {
  const combined = combinedFixture();
  combined.services["project-router"].networks.example_app_cache = null;
  combined.networks.example_app_cache = { internal: true };
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /cannot join workload example-app zone cache/);
});
test("route without dedicated router network is rejected", () => {
  const combined = combinedFixture();
  delete combined.services["project-router"].networks.example_app_ingress;
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /no dedicated network/);
});
test("undeclared service is rejected", () => {
  const combined = combinedFixture();
  combined.services["example-app-shell"] = structuredClone(baseService);
  assert.throws(() => validateRenderedWorkloads({ core, combined, lock }), /exactly match/);
});

function brokerRenderFixture() {
  const services = [
    { name: "tenant-app-cache", role: "worker" },
    { name: "tenant-app-bus", role: "scheduled-worker" },
  ];
  const secrets = ["tenant-app-redis-password", "tenant-app-bus-nats-password"];
  const workload = validateWorkloadManifest({
    version: 1,
    id: "tenant-app",
    composeFile: "compose.yaml",
    services,
    secrets,
    brokers: {
      redis: expectedRedisPolicy("tenant-app"),
      nats: expectedNatsPolicy("tenant-app", [services[1]]),
    },
  });
  const brokerCore = {
    services: {
      redis: { image: "redis@sha256:fixed", command: ["fixed-redis-entrypoint"], secrets: ["redis_password"], networks: { platform_cache: null } },
      nats: { image: "nats@sha256:fixed", command: ["fixed-nats-entrypoint"], secrets: ["nats_password"], networks: { platform_bus: null } },
      "broker-auth-bootstrap": { image: "ops@sha256:fixed", command: ["fixed-broker-bootstrap"], secrets: ["redis_password", "nats_password"], network_mode: "none" },
    },
    networks: { platform_cache: { internal: true }, platform_bus: { internal: true } },
  };
  const cacheService = {
    ...structuredClone(baseService),
    networks: { tenant_app_cache: null },
    labels: { "com.platform.workload-id": "tenant-app", "com.platform.workload-role": "worker" },
    secrets: [{ source: "tenant-app-redis-password", target: "tenant-app-redis-password" }],
    environment: {
      REDIS_HOST: "redis",
      REDIS_PORT: "6379",
      REDIS_USERNAME: workload.brokers.redis.username,
      REDIS_PASSWORD_FILE: "/run/secrets/tenant-app-redis-password",
      REDIS_KEY_PREFIX: "tenant-app:",
      REDIS_CHANNEL_PREFIX: "tenant-app:",
    },
  };
  const natsUser = workload.brokers.nats.users[0];
  const busService = {
    ...structuredClone(baseService),
    networks: { tenant_app_bus: null },
    labels: { "com.platform.workload-id": "tenant-app", "com.platform.workload-role": "scheduled-worker" },
    secrets: [{ source: "tenant-app-bus-nats-password", target: "tenant-app-bus-nats-password" }],
    environment: {
      NATS_HOST: "nats",
      NATS_PORT: "4222",
      NATS_ACCOUNT: workload.brokers.nats.account,
      NATS_USERNAME: natsUser.username,
      NATS_PASSWORD_FILE: "/run/secrets/tenant-app-bus-nats-password",
      NATS_SUBJECT_PREFIX: natsUser.publish[0].slice(0, -1),
      NATS_QUEUE_GROUP: natsUser.queueGroups[0],
    },
  };
  const combined = {
    services: {
      redis: {
        ...structuredClone(brokerCore.services.redis),
        networks: { platform_cache: null, tenant_app_cache: null },
      },
      nats: {
        ...structuredClone(brokerCore.services.nats),
        networks: { platform_bus: null, tenant_app_bus: null },
      },
      "broker-auth-bootstrap": {
        ...structuredClone(brokerCore.services["broker-auth-bootstrap"]),
        secrets: ["redis_password", "nats_password", "tenant-app-redis-password", "tenant-app-bus-nats-password"],
      },
      "tenant-app-cache": cacheService,
      "tenant-app-bus": busService,
    },
    networks: {
      platform_cache: { internal: true },
      platform_bus: { internal: true },
      tenant_app_cache: { internal: true },
      tenant_app_bus: { internal: true },
    },
    secrets: {
      redis_password: { external: true },
      nats_password: { external: true },
      "tenant-app-redis-password": { external: true },
      "tenant-app-bus-nats-password": { external: true },
    },
  };
  return {
    core: brokerCore,
    combined,
    lock: { workloads: [workload], brokerPolicySha256: brokerPolicySha256([workload]) },
  };
}

test("rendered cache and bus consumers bind exact workload broker identities and core secret mounts", () => {
  const fixture = brokerRenderFixture();
  assert.deepEqual(validateRenderedWorkloads(fixture).routes, []);
});

test("rendered broker contract rejects missing identity fields, core secrets and broker command mutation", () => {
  const missingIdentity = brokerRenderFixture();
  delete missingIdentity.combined.services["tenant-app-bus"].environment.NATS_PASSWORD_FILE;
  assert.throws(() => validateRenderedWorkloads(missingIdentity), /NATS connection fields/);

  const missingCoreSecret = brokerRenderFixture();
  missingCoreSecret.combined.services["broker-auth-bootstrap"].secrets = ["redis_password", "nats_password", "tenant-app-bus-nats-password"];
  assert.throws(() => validateRenderedWorkloads(missingCoreSecret), /mount exactly/);

  const mutatedBroker = brokerRenderFixture();
  mutatedBroker.combined.services.nats.command = ["--user", "shared", "--pass", "shared"];
  assert.throws(() => validateRenderedWorkloads(mutatedBroker), /changed protected platform service/);
});
test("duplicate route is rejected at manifest boundary", () => {
  assert.throws(() => validateWorkloadManifest({
    version: 1,
    id: "duplicate-app",
    composeFile: "compose.yaml",
    services: [
      { name: "duplicate-app-one", role: "web", routes: [{ slug: "same", host: "same.example.com", port: 3000 }] },
      { name: "duplicate-app-two", role: "web", routes: [{ slug: "same", host: "same.example.com", port: 3000 }] },
    ],
  }), /Duplicate route/);
});

test("global route collisions are deterministic regardless of manifest order", () => {
  const alpha = validateWorkloadManifest({
    version: 1,
    id: "alpha-app",
    composeFile: "compose.yaml",
    services: [{
      name: "alpha-app-web",
      role: "web",
      routes: [{ slug: "alpha", host: "alpha.example.com", aliases: ["shared"], port: 3000 }],
    }],
  });
  const beta = validateWorkloadManifest({
    version: 1,
    id: "beta-app",
    composeFile: "compose.yaml",
    services: [{
      name: "beta-app-web",
      role: "web",
      routes: [{ slug: "shared", host: "shared.example.net", port: 3001 }],
    }],
  });
  const errors = [];
  for (const workloads of [[alpha, beta], [beta, alpha]]) {
    assert.throws(() => validateGlobalRouteOwnership(workloads), (error) => {
      errors.push(error.message);
      return /slug or alias 'shared'.*alpha-app.*beta-app/.test(error.message);
    });
  }
  assert.equal(errors[0], errors[1]);
});

test("canonical host ownership rejects reserved and normalized duplicates", () => {
  const alpha = validateWorkloadManifest({
    version: 1,
    id: "alpha-app",
    composeFile: "compose.yaml",
    services: [{ name: "alpha-app-web", role: "web", routes: [{ slug: "alpha", host: "ALPHA.example.com.", port: 3000 }] }],
  });
  assert.throws(
    () => validateGlobalRouteOwnership([alpha], { reservedHosts: ["alpha.example.com"] }),
    /host 'alpha\.example\.com'.*platform/,
  );
});

test("global upstream reuse is rejected even when hosts differ", () => {
  const workload = validateWorkloadManifest({
    version: 1,
    id: "example-app",
    composeFile: "compose.yaml",
    services: [{
      name: "example-app-web",
      role: "web",
      routes: [
        { slug: "alpha", host: "alpha.example.com", port: 3000 },
        { slug: "beta", host: "beta.example.com", port: 3000 },
      ],
    }],
  });
  assert.throws(() => validateGlobalRouteOwnership([workload]), /upstream 'example-app-web:3000'/);
});

test("legacy hosted workload locks fail closed", () => {
  assert.throws(
    () => verifyLockFiles({ version: 1, state: "verified", files: [] }),
    /schema 2 and validator hosted-contract-v2/,
  );
});

test("raw policy receipt requires the exact current control set", () => {
  const receipt = {
    workloadContentSha256: "a".repeat(64),
    rawPolicyVersion: "hosted-raw-v1",
    rawPolicyWorkloadContentSha256: "a".repeat(64),
    rawPolicySha256: "b".repeat(64),
    rawPolicyControls: ["deny-env-file", "deny-extends", "deny-include"],
  };
  assert.doesNotThrow(() => verifyRawPolicyReceipt(receipt));
  receipt.rawPolicyControls = ["deny-include"];
  assert.throws(() => verifyRawPolicyReceipt(receipt), /raw source policy receipt/);
});

function catalogFixture(root, appRoot = path.join(root, "workloads", "example-app")) {
  fs.mkdirSync(appRoot, { recursive: true });
  fs.writeFileSync(path.join(appRoot, "manifest.json"), JSON.stringify({
    version: 1,
    id: "example-app",
    composeFile: "compose.yaml",
    services: [{ name: "example-app-web", role: "web" }],
  }));
  fs.writeFileSync(path.join(appRoot, "compose.yaml"), "services: {}\n");
  fs.writeFileSync(path.join(appRoot, "workload.env"), "EXAMPLE_APP_THEME=dark\n");
  const catalogPath = path.join(root, "catalog.json");
  fs.writeFileSync(catalogPath, JSON.stringify({
    version: 1,
    workloads: [{ manifest: "example-app/manifest.json", environmentFile: "example-app/workload.env" }],
  }));
  const coreEnvFile = path.join(root, "core.env");
  const coreFile = path.join(root, "compose.core.yaml");
  fs.writeFileSync(coreEnvFile, "CORE_VALUE=fixture\n");
  fs.writeFileSync(coreFile, "services: {}\n");
  return { catalogPath, coreEnvFile, coreFile };
}

function removeFixtureTree(root) {
  if (!fs.existsSync(root)) return;
  const makeDirectoriesWritable = (directory) => {
    const stat = fs.lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) return;
    fs.chmodSync(directory, 0o700);
    for (const entry of fs.readdirSync(directory)) makeDirectoriesWritable(path.join(directory, entry));
  };
  makeDirectoriesWritable(root);
  fs.rmSync(root, { recursive: true, force: true });
}

test("workload resolver accepts an all-regular contained tree", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-contained-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const fixture = catalogFixture(root);
    const snapshotRoot = path.join(root, "snapshots");
    const result = resolveCatalog({ ...fixture, workloadRoot, coreFiles: [fixture.coreFile], projectName: "fixture", snapshotRoot });
    assert.equal(result.workloads[0].manifestSourcePath, fs.realpathSync.native(path.join(workloadRoot, "example-app", "manifest.json")));
    assert.equal(path.dirname(result.workloads[0].manifestPath), result.snapshotGeneration);
    assert.equal(path.basename(result.snapshotGeneration), `content-${result.workloadContentSha256}`);
    assert.equal(result.snapshotRootIdentity.uid, String(process.getuid?.() ?? result.snapshotRootIdentity.uid));
    assert.equal(result.snapshotRootIdentity.mode, 0o700);
    assert.equal(result.snapshotGenerationIdentity.mode, 0o500);
    assert.match(result.workloadContentSha256, /^[a-f0-9]{64}$/);
    verifyLockFiles(result);
  } finally {
    removeFixtureTree(root);
  }
});

test("workload resolver rejects intermediate and terminal symlinks", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-symlink-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const outside = path.join(root, "outside-app");
    const snapshotRoot = path.join(root, "snapshots");
    fs.mkdirSync(workloadRoot, { recursive: true });
    const fixture = catalogFixture(root, outside);
    fs.symlinkSync(outside, path.join(workloadRoot, "example-app"), "dir");
    assert.throws(
      () => resolveCatalog({ ...fixture, workloadRoot, coreFiles: [fixture.coreFile], projectName: "fixture", snapshotRoot }),
      /symlink component/,
    );
    fs.rmSync(path.join(workloadRoot, "example-app"));
    fs.mkdirSync(path.join(workloadRoot, "example-app"));
    fs.symlinkSync(path.join(outside, "manifest.json"), path.join(workloadRoot, "example-app", "manifest.json"));
    assert.throws(
      () => resolveCatalog({ ...fixture, workloadRoot, coreFiles: [fixture.coreFile], projectName: "fixture", snapshotRoot }),
      /symlink component/,
    );
  } finally {
    removeFixtureTree(root);
  }
});

test("workload resolver rejects symlinked roots and root parents", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-root-link-")));
  try {
    const realParent = path.join(root, "real-parent");
    const workloadRoot = path.join(realParent, "workloads");
    const fixture = catalogFixture(root, path.join(workloadRoot, "example-app"));
    const linkedParent = path.join(root, "linked-parent");
    fs.symlinkSync(realParent, linkedParent, "dir");
    assert.throws(
      () => resolveCatalog({
        ...fixture,
        workloadRoot: path.join(linkedParent, "workloads"),
        coreFiles: [fixture.coreFile],
        projectName: "fixture",
        snapshotRoot: path.join(root, "snapshots-one"),
      }),
      /symlink component/,
    );
    const realSnapshotParent = path.join(root, "real-snapshot-parent");
    fs.mkdirSync(realSnapshotParent);
    const linkedSnapshotParent = path.join(root, "linked-snapshot-parent");
    fs.symlinkSync(realSnapshotParent, linkedSnapshotParent, "dir");
    assert.throws(
      () => resolveCatalog({
        ...fixture,
        workloadRoot,
        coreFiles: [fixture.coreFile],
        projectName: "fixture",
        snapshotRoot: path.join(linkedSnapshotParent, "snapshots"),
      }),
      /symlink component/,
    );
    const linkedRoot = path.join(root, "linked-workloads");
    fs.symlinkSync(workloadRoot, linkedRoot, "dir");
    assert.throws(
      () => resolveCatalog({
        ...fixture,
        workloadRoot: linkedRoot,
        coreFiles: [fixture.coreFile],
        projectName: "fixture",
        snapshotRoot: path.join(root, "snapshots-two"),
      }),
      /symlink component/,
    );
  } finally {
    removeFixtureTree(root);
  }
});

test("activation paths remain bound to immutable snapshots after source replacement", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-snapshot-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const fixture = catalogFixture(root);
    const lock = resolveCatalog({
      ...fixture,
      workloadRoot,
      coreFiles: [fixture.coreFile],
      projectName: "fixture",
      snapshotRoot: path.join(root, "snapshots"),
    });
    const originalCompose = fs.readFileSync(lock.workloads[0].composePath, "utf8");
    fs.writeFileSync(lock.workloads[0].composeSourcePath, "services:\n  hostile:\n    privileged: true\n");
    const replacement = path.join(root, "replacement.yaml");
    fs.writeFileSync(replacement, "services:\n  replaced: {}\n");
    fs.renameSync(replacement, lock.workloads[0].composeSourcePath);
    fs.unlinkSync(lock.workloads[0].composeSourcePath);
    fs.symlinkSync(path.join(root, "hostile.yaml"), lock.workloads[0].composeSourcePath);
    fs.writeFileSync(path.join(root, "hostile.yaml"), "services:\n  linked:\n    privileged: true\n");
    assert.equal(fs.readFileSync(lock.workloads[0].composePath, "utf8"), originalCompose);
    assert.equal(verifyLockFiles(lock), true);
  } finally {
    removeFixtureTree(root);
  }
});

test("optional project metadata is exported as a verified workload-owned snapshot record", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-project-metadata-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const fixture = catalogFixture(root);
    const appRoot = path.join(workloadRoot, "example-app");
    const manifestPath = path.join(appRoot, "manifest.json");
    const manifestDocument = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    manifestDocument.projectMetadataFile = ".platform/project.json";
    fs.writeFileSync(manifestPath, JSON.stringify(manifestDocument));
    fs.mkdirSync(path.join(appRoot, ".platform"));
    fs.writeFileSync(path.join(appRoot, ".platform", "project.json"), '{"name":"Example"}\n');
    const lock = resolveCatalog({
      ...fixture,
      workloadRoot,
      coreFiles: [fixture.coreFile],
      projectName: "fixture",
      snapshotRoot: path.join(root, "snapshots"),
    });
    const record = lock.files.find((item) => item.kind === "project-metadata");
    assert.equal(record.workloadId, "example-app");
    assert.equal(record.path, lock.workloads[0].projectMetadataPath);
    assert.equal(record.sourcePath, lock.workloads[0].projectMetadataSourcePath);
    assert.match(record.sha256, /^[a-f0-9]{64}$/);
    fs.writeFileSync(record.sourcePath, '{"name":"Changed"}\n');
    assert.equal(verifyLockFiles(lock), true);
  } finally {
    removeFixtureTree(root);
  }
});

test("lock verification rejects snapshot parent and generation replacement", () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hosted-snapshot-parent-")));
  try {
    const workloadRoot = path.join(root, "workloads");
    const fixture = catalogFixture(root);
    const lock = resolveCatalog({
      ...fixture,
      workloadRoot,
      coreFiles: [fixture.coreFile],
      projectName: "fixture",
      snapshotRoot: path.join(root, "snapshots"),
    });
    const originalRoot = `${lock.snapshotRoot}.original`;
    fs.renameSync(lock.snapshotRoot, originalRoot);
    fs.symlinkSync(originalRoot, lock.snapshotRoot, "dir");
    assert.throws(() => verifyLockFiles(lock), /symlink component/);
    fs.unlinkSync(lock.snapshotRoot);
    fs.renameSync(originalRoot, lock.snapshotRoot);

    const originalGeneration = `${lock.snapshotGeneration}.original`;
    fs.renameSync(lock.snapshotGeneration, originalGeneration);
    fs.mkdirSync(lock.snapshotGeneration, { mode: 0o700 });
    fs.chmodSync(lock.snapshotGeneration, 0o500);
    assert.throws(() => verifyLockFiles(lock), /identity changed/);
  } finally {
    removeFixtureTree(root);
  }
});

test("workload environment accepts only non-secret prefixed variables", () => {
  assert.deepEqual(
    validateWorkloadEnvironmentText("EXAMPLE_APP_IMAGE=registry.example/app@sha256:abc\nEXAMPLE_APP_SMTP_HOST=smtp.example.test\n", "example-app"),
    ["EXAMPLE_APP_IMAGE", "EXAMPLE_APP_SMTP_HOST"],
  );
  assert.throws(
    () => validateWorkloadEnvironmentText("EXAMPLE_APP_DATABASE_URL=postgres://user:password@postgres/db\n", "example-app"),
    /sensitive variable/,
  );
  assert.throws(
    () => validateWorkloadEnvironmentText("UNSCOPED_IMAGE=registry.example/app@sha256:abc\n", "example-app"),
    /EXAMPLE_APP_/,
  );
});

process.stdout.write(`hosted workload contract tests passed ${passed}/${passed}\n`);
