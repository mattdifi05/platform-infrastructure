#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  resolveCatalog,
  validateRenderedWorkloads,
  validateWorkloadEnvironmentText,
  validateWorkloadManifest,
  verifyLockFiles,
} from "./hosted-workload-contract.mjs";

const digest = "a".repeat(64);
const manifest = validateWorkloadManifest({
  version: 1,
  id: "example-app",
  composeFile: "compose.platform.yaml",
  secrets: ["example-app-database-url"],
  migrationRoots: ["postgres/migrations"],
  services: [
    { name: "example-app-web", role: "web", routes: [{ slug: "example", port: 3000 }] },
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
        networks: { example_app_bus: null },
        labels: { "com.platform.workload-id": "example-app", "com.platform.workload-role": "worker" },
      },
    },
    networks: { platform_routing: { internal: true }, example_app_ingress: { internal: true }, example_app_bus: { internal: true } },
    secrets: { "example-app-database-url": { external: true } },
  };
}

const lock = { workloads: [manifest] };
let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  process.stdout.write(`ok ${passed} - ${name}\n`);
}

test("exact hardened workload render passes", () => {
  assert.equal(manifest.version, 1);
  const result = validateRenderedWorkloads({ core, combined: combinedFixture(), lock });
  assert.deepEqual(result.routes, [{ workloadId: "example-app", slug: "example", service: "example-app-web", port: 3000, upstream: "http://example-app-web:3000" }]);
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
test("duplicate route is rejected at manifest boundary", () => {
  assert.throws(() => validateWorkloadManifest({
    version: 1,
    id: "duplicate-app",
    composeFile: "compose.yaml",
    services: [
      { name: "duplicate-app-one", role: "web", routes: [{ slug: "same", port: 3000 }] },
      { name: "duplicate-app-two", role: "web", routes: [{ slug: "same", port: 3000 }] },
    ],
  }), /Duplicate route/);
});

test("legacy hosted workload locks fail closed", () => {
  assert.throws(
    () => verifyLockFiles({ version: 1, state: "verified", files: [] }),
    /schema 2 and validator hosted-contract-v2/,
  );
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

test("workload resolver accepts an all-regular contained tree", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hosted-contained-"));
  try {
    const workloadRoot = path.join(root, "workloads");
    const fixture = catalogFixture(root);
    const result = resolveCatalog({ ...fixture, workloadRoot, coreFiles: [fixture.coreFile], projectName: "fixture" });
    assert.equal(result.workloads[0].manifestPath, fs.realpathSync.native(path.join(workloadRoot, "example-app", "manifest.json")));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("workload resolver rejects intermediate and terminal symlinks", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hosted-symlink-"));
  try {
    const workloadRoot = path.join(root, "workloads");
    const outside = path.join(root, "outside-app");
    fs.mkdirSync(workloadRoot, { recursive: true });
    const fixture = catalogFixture(root, outside);
    fs.symlinkSync(outside, path.join(workloadRoot, "example-app"), "dir");
    assert.throws(
      () => resolveCatalog({ ...fixture, workloadRoot, coreFiles: [fixture.coreFile], projectName: "fixture" }),
      /symlink component/,
    );
    fs.rmSync(path.join(workloadRoot, "example-app"));
    fs.mkdirSync(path.join(workloadRoot, "example-app"));
    fs.symlinkSync(path.join(outside, "manifest.json"), path.join(workloadRoot, "example-app", "manifest.json"));
    assert.throws(
      () => resolveCatalog({ ...fixture, workloadRoot, coreFiles: [fixture.coreFile], projectName: "fixture" }),
      /symlink component/,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
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
