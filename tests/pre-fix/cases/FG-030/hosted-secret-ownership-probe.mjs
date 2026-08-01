#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const sourceRoot = process.argv[2];
if (!sourceRoot) {
  process.stderr.write("usage: node hosted-secret-ownership-probe.mjs ARCHIVED_SOURCE_ROOT\n");
  process.exit(2);
}

const expectedHashes = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["compose.managed-secrets.yaml", "07c49c5adc4f44cc4b5f93864ab89cbe5b1dacab4e36481b7c7393f0812ebde2"],
  ["SECURITY.md", "b72a0abd090dfa15832d5af3e389edeee50cf5128cbd515e7c74b6a72f4d9cb3"],
]);

function sha256(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

for (const [relativePath, expected] of expectedHashes) {
  const actual = sha256(path.join(sourceRoot, relativePath));
  assert.equal(actual, expected, `source digest mismatch for ${relativePath}`);
}

const contractPath = path.join(sourceRoot, "scripts/hosted-workload-contract.mjs");
const { validateRenderedWorkloads, validateWorkloadManifest } = await import(pathToFileURL(contractPath).href);

const digest = "a".repeat(64);
const logicalAlias = "example-app-database-url";
const secretTarget = "/run/secrets/example-app-database-url";
const manifest = validateWorkloadManifest({
  version: 1,
  id: "example-app",
  composeFile: "compose.platform.yaml",
  secrets: [logicalAlias],
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
  services: {
    "project-router": {
      image: `registry.example/router@sha256:${digest}`,
      networks: { platform_routing: null },
    },
  },
  networks: { platform_routing: { internal: true } },
};

function combinedFixture(physicalName) {
  return {
    services: {
      "project-router": {
        ...core.services["project-router"],
        networks: { platform_routing: null, example_app_ingress: null },
      },
      "example-app-web": {
        ...structuredClone(baseService),
        secrets: [{ source: logicalAlias, target: logicalAlias }],
        environment: { DATABASE_URL_FILE: secretTarget },
      },
      "example-app-worker": {
        ...structuredClone(baseService),
        networks: { example_app_bus: null },
        labels: { "com.platform.workload-id": "example-app", "com.platform.workload-role": "worker" },
      },
    },
    networks: {
      platform_routing: { internal: true },
      example_app_ingress: { internal: true },
      example_app_bus: { internal: true },
    },
    secrets: { [logicalAlias]: { external: true, name: physicalName } },
  };
}

const trustedInventory = new Map([
  ["example-app-database-url", { owner: "example-app", aliases: new Set([logicalAlias]) }],
  ["control_center_vault_keys", { owner: "platform", aliases: new Set() }],
  ["postgres_superuser_password", { owner: "platform-database", aliases: new Set() }],
  ["sibling-app-database-url", { owner: "sibling-app", aliases: new Set(["sibling-app-database-url"]) }],
]);

function referenceOwnershipGate({ workloadId, alias, definition }) {
  if (definition?.external !== true) return { accepted: false, reason: "not-external" };
  const physicalName = definition.name ?? alias;
  const record = trustedInventory.get(physicalName);
  if (!record) return { accepted: false, reason: "unknown-physical-secret" };
  if (record.owner !== workloadId) return { accepted: false, reason: "owner-mismatch" };
  if (!record.aliases.has(alias)) return { accepted: false, reason: "alias-mismatch" };
  return { accepted: true, reason: "owner-bound" };
}

const cases = [
  { category: "OWNED", physicalName: "example-app-database-url", referenceAccepted: true, referenceReason: "owner-bound" },
  { category: "PLATFORM", physicalName: "control_center_vault_keys", referenceAccepted: false, referenceReason: "owner-mismatch" },
  { category: "DATABASE", physicalName: "postgres_superuser_password", referenceAccepted: false, referenceReason: "owner-mismatch" },
  { category: "SIBLING", physicalName: "sibling-app-database-url", referenceAccepted: false, referenceReason: "owner-mismatch" },
  { category: "UNKNOWN", physicalName: "example-app-not-provisioned", referenceAccepted: false, referenceReason: "unknown-physical-secret" },
];

for (const testCase of cases) {
  const combined = combinedFixture(testCase.physicalName);
  const exactResult = validateRenderedWorkloads({ core, combined, lock: { workloads: [manifest] } });
  assert.equal(exactResult.routes.length, 1);
  process.stdout.write(
    `[EXACT-${testCase.category}] logical_alias=${logicalAlias} physical_name=${testCase.physicalName} accepted=true\n`,
  );

  const reference = referenceOwnershipGate({
    workloadId: manifest.id,
    alias: logicalAlias,
    definition: combined.secrets[logicalAlias],
  });
  assert.equal(reference.accepted, testCase.referenceAccepted);
  assert.equal(reference.reason, testCase.referenceReason);
  process.stdout.write(
    `[REFERENCE-${testCase.category}] physical_name=${testCase.physicalName} accepted=${reference.accepted} reason=${reference.reason}\n`,
  );
}

const modeledPhysicalName = combinedFixture("postgres_superuser_password").secrets[logicalAlias].name ?? logicalAlias;
assert.equal(modeledPhysicalName, "postgres_superuser_password");
process.stdout.write(
  `[COMPOSE-MODEL] logical_alias=${logicalAlias} target=${secretTarget} physical_name=${modeledPhysicalName} `
  + "mount_attempt_if_resource_exists=true runtime_resolution_attempted=false value_read=false\n",
);
process.stdout.write(
  "[SAFETY] docker_invoked=false compose_invoked=false network_used=false secret_resource_opened=false secret_value_read=false\n",
);
process.stdout.write("hosted secret physical-ownership probe passed 5/5 exact-validator cases\n");
