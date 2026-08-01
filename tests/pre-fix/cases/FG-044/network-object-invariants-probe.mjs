#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const EXPECTED_HASHES = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/network-segmentation-policy.mjs", "bc21ac9f6b01630925743dd9f226a07476f45aa56fc9c174edce38fd65312636"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["compose.networks.yaml", "f6cfb3b3857c1fd85414fbd7dc29c78a5f96ca9e7d309d8849cbb3400f66d759"],
]);

const LOGICAL_NETWORK = "example_app_egress";
const CASES = [
  {
    id: "CAN-151",
    name: "database-external-alias",
    definition: { external: true, name: "platform_infra_vps_db_admin" },
    detail: "external=true name=platform_infra_vps_db_admin",
  },
  {
    id: "CAN-152",
    name: "routing-external-alias",
    definition: { external: true, name: "platform_infra_vps_routing" },
    detail: "external=true name=platform_infra_vps_routing",
  },
  {
    id: "CAN-153",
    name: "sibling-external-alias",
    definition: { external: true, name: "platform_infra_vps_sibling_app_ingress" },
    detail: "external=true name=platform_infra_vps_sibling_app_ingress",
  },
  {
    id: "CAN-160",
    name: "custom-egress-driver",
    definition: {
      driver: "macvlan",
      driver_opts: { parent: "poc-parent0" },
      enable_ipv6: false,
      ipam: {
        driver: "default",
        config: [{ subnet: "192.0.2.0/24", gateway: "192.0.2.1" }],
      },
    },
    detail: "driver=macvlan parent=poc-parent0 subnet=192.0.2.0/24",
  },
];

const sourceArgument = process.argv[2];
if (!sourceArgument) {
  throw new Error("usage: network-object-invariants-probe.mjs WRAPPER_OWNED_SOURCE");
}

const {
  sourceRoot,
  sentinelPath,
  sentinelText,
  sentinelDevice,
  sentinelInode,
} = validateWrapperOwnedSource(sourceArgument);
const treeBefore = directoryDigest(sourceRoot);
console.log("[+] wrapper-owned source boundary verified");

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(
    sha256File(path.join(sourceRoot, relativePath)),
    expected,
    `${relativePath} is not the expected vulnerable source`,
  );
}
console.log(`[+] verified ${EXPECTED_HASHES.size} embedded vulnerable-source hashes`);

const networkSource = fs.readFileSync(path.join(sourceRoot, "compose.networks.yaml"), "utf8");
assert.match(networkSource, /name: \$\{PLATFORM_NETWORK_PREFIX:-platform_infra_vps\}_routing/);
assert.match(networkSource, /name: \$\{PLATFORM_NETWORK_PREFIX:-platform_infra_vps\}_db_admin/);
console.log("[+] verified tracked database and routing physical network names");

const activationSource = fs.readFileSync(path.join(sourceRoot, "scripts/compose-vps.sh"), "utf8");
assert.match(activationSource, /compose\+=\(-f "\$workload_file"\)/);
assert.match(activationSource, /exec "\$\{compose\[@\]\}" --profile backup "\$@"/);
console.log("[+] verified admitted workload files reach the Compose activation command");

const contractUrl = pathToFileURL(path.join(sourceRoot, "scripts/hosted-workload-contract.mjs")).href;
const segmentationUrl = pathToFileURL(path.join(sourceRoot, "scripts/network-segmentation-policy.mjs")).href;
const { validateRenderedWorkloads } = await import(contractUrl);
const { evaluateNetworkSegmentation } = await import(segmentationUrl);

const control = admissionResult(
  { internal: true },
  validateRenderedWorkloads,
  "platform_db_admin",
);
assert.equal(control.accepted, false, "the foreign logical-key negative control unexpectedly passed");
assert.match(control.error, /uses unauthorized network/);
console.log("[CONTROL] foreign-logical-key admission=rejected");

let vulnerable = 0;
for (const testCase of CASES) {
  const admission = admissionResult(testCase.definition, validateRenderedWorkloads);
  const segmentation = evaluateNetworkSegmentation(segmentationFixture(testCase.definition));
  if (admission.accepted && segmentation.status === "passed") {
    vulnerable += 1;
    console.log(
      `[VULNERABLE] ${testCase.id} ${testCase.name} admission=accepted segmentation=passed ${testCase.detail}`,
    );
    continue;
  }
  if (admission.error) console.error(`[UNEXPECTED] ${testCase.id} admission detail: ${admission.error}`);
  if (segmentation.status !== "passed") {
    console.error(`[UNEXPECTED] ${testCase.id} segmentation detail: ${segmentation.failures.join("; ")}`);
  }
}

assert.equal(vulnerable, CASES.length, "the pinned revision did not accept every network-object instance");
assert.equal(directoryDigest(sourceRoot), treeBefore, "the source snapshot changed during the read-only probe");
const sentinelAfter = fs.lstatSync(sentinelPath);
assert.equal(sentinelAfter.isFile(), true, "the ownership sentinel is no longer a regular file");
assert.equal(sentinelAfter.isSymbolicLink(), false, "the ownership sentinel became a symlink");
assert.equal(sentinelAfter.dev, sentinelDevice, "the ownership sentinel device changed during the probe");
assert.equal(sentinelAfter.ino, sentinelInode, "the ownership sentinel inode changed during the probe");
assert.equal(fs.readFileSync(sentinelPath, "utf8"), sentinelText, "the ownership sentinel changed during the probe");
console.log(`[+] summary vulnerable=${vulnerable} total=${CASES.length} source_tree_unchanged=true`);
console.log("[+] no Docker, Compose, Engine network, packet, service, network, or live target was accessed");

function admissionResult(networkDefinition, validate, logicalNetwork = LOGICAL_NETWORK) {
  const digest = "a".repeat(64);
  const core = {
    services: {
      "project-router": {
        image: `registry.example/platform/router@sha256:${digest}`,
        networks: { platform_routing: null },
      },
    },
    networks: { platform_routing: { internal: true } },
  };
  const combined = structuredClone(core);
  combined.services["example-app-worker"] = {
    image: `registry.example/workloads/example@sha256:${digest}`,
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
    mem_limit: 256 * 1024 * 1024,
    mem_reservation: 64 * 1024 * 1024,
    healthcheck: { test: ["CMD", "true"] },
    networks: { [logicalNetwork]: null },
    labels: {
      "com.platform.workload-id": "example-app",
      "com.platform.workload-role": "worker",
    },
  };
  combined.networks[logicalNetwork] = structuredClone(networkDefinition);
  const lock = {
    workloads: [{
      id: "example-app",
      secrets: [],
      services: [{ name: "example-app-worker", role: "worker", routes: [] }],
    }],
  };

  try {
    validate({ core, combined, lock });
    return { accepted: true };
  } catch (error) {
    return { accepted: false, error: error.message };
  }
}

function segmentationFixture(networkDefinition) {
  const internalNetworkNames = [
    "platform_edge",
    "platform_routing",
    "platform_db_admin",
    "platform_postgres",
    "platform_cache",
    "platform_bus",
    "platform_storage",
    "platform_observability",
    "platform_docker_control",
  ];
  const networks = Object.fromEntries(internalNetworkNames.map((name) => [name, { internal: true }]));
  networks.platform_egress = { enable_ipv6: false };
  networks[LOGICAL_NETWORK] = structuredClone(networkDefinition);

  const services = {
    traefik: service(["platform_edge", "platform_routing"]),
    waf: service(["platform_edge"]),
    "project-router": service(["platform_routing"], {
      environment: { PROJECT_ROUTER_WORKLOAD_LOCK_FILE: "/var/www/project-state/hosted-workloads.lock.json" },
    }),
    "control-center": service(["platform_routing", "platform_db_admin"]),
    postgres: service(["platform_db_admin"]),
    mariadb: service(["platform_db_admin"]),
    redis: service(["platform_cache"]),
    nats: service(["platform_bus"]),
    minio: service(["platform_storage"]),
    prometheus: service(["platform_observability"]),
    loki: service(["platform_observability"]),
    alertmanager: service(["platform_observability"]),
    "platform-alert-dispatcher": service(["platform_observability"]),
    "backup-scheduler": service(["platform_docker_control"]),
    "docker-socket-proxy": service(["platform_docker_control"]),
    phppgadmin: service(["platform_db_admin", "platform_routing"], {
      image: `registry.example/platform/phppgadmin@sha256:${"b".repeat(64)}`,
    }),
    "example-app-worker": service([LOGICAL_NETWORK], {
      labels: {
        "com.platform.workload-id": "example-app",
        "com.platform.workload-role": "worker",
      },
    }),
  };

  return { services, networks };
}

function service(networks, overrides = {}) {
  return {
    image: `registry.example/platform/service@sha256:${"c".repeat(64)}`,
    networks: Object.fromEntries(networks.map((name) => [name, null])),
    environment: {},
    labels: {},
    ...overrides,
  };
}

function validateWrapperOwnedSource(sourceInput) {
  const wrapperInput = requiredEnvironment("FG044_WRAPPER_TEMP_ROOT");
  const sentinelInput = requiredEnvironment("FG044_OWNERSHIP_SENTINEL");
  const ownershipToken = requiredEnvironment("FG044_OWNERSHIP_TOKEN");

  const wrapperPath = path.resolve(wrapperInput);
  const wrapperStat = fs.lstatSync(wrapperPath, { throwIfNoEntry: false });
  assert.ok(wrapperStat?.isDirectory(), "wrapper temporary root is missing");
  assert.equal(wrapperStat.isSymbolicLink(), false, "wrapper temporary root must not be a symlink");
  const wrapperReal = fs.realpathSync(wrapperPath);
  assert.equal(wrapperPath, wrapperReal, "wrapper temporary root must be supplied as its real path");
  assert.match(
    path.basename(wrapperReal),
    /^fg044-(?:guard|run)\.[A-Za-z0-9]+$/,
    "wrapper temporary root does not have the expected mktemp name",
  );

  const sourcePath = path.resolve(sourceInput);
  const sourceStat = fs.lstatSync(sourcePath, { throwIfNoEntry: false });
  assert.ok(sourceStat?.isDirectory(), "archived source directory is missing");
  assert.equal(sourceStat.isSymbolicLink(), false, "archived source must not be a symlink");
  const sourceReal = fs.realpathSync(sourcePath);
  assert.equal(sourceReal, path.join(wrapperReal, "source"), "source must be the exact wrapper-owned source child");

  const sentinelPath = path.resolve(sentinelInput);
  const sentinelStat = fs.lstatSync(sentinelPath, { throwIfNoEntry: false });
  assert.ok(sentinelStat?.isFile(), "ownership sentinel is missing");
  assert.equal(sentinelStat.isSymbolicLink(), false, "ownership sentinel must not be a symlink");
  const sentinelReal = fs.realpathSync(sentinelPath);
  assert.equal(path.dirname(sentinelReal), wrapperReal, "ownership sentinel is outside the wrapper root");
  assert.match(path.basename(sentinelReal), /^\.fg044-owner\.[A-Za-z0-9]+$/);
  const tokenFromName = path.basename(sentinelReal).slice(".fg044-owner.".length);
  assert.equal(ownershipToken, tokenFromName, "ownership token does not match sentinel name");
  const sentinelText = `FG044-OWNER:${ownershipToken}\n`;
  assert.equal(fs.readFileSync(sentinelReal, "utf8"), sentinelText, "ownership sentinel content is invalid");

  return {
    sourceRoot: sourceReal,
    sentinelPath: sentinelReal,
    sentinelText,
    sentinelDevice: sentinelStat.dev,
    sentinelInode: sentinelStat.ino,
  };
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required; invoke through run-from-git-archive.sh`);
  }
  return value;
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function directoryDigest(root) {
  const digest = crypto.createHash("sha256");
  walk(root, "");
  return digest.digest("hex");

  function walk(current, relative) {
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) {
      digest.update(`L\0${relative}\0${fs.readlinkSync(current)}\0`);
      return;
    }
    if (stat.isDirectory()) {
      digest.update(`D\0${relative}\0`);
      for (const name of fs.readdirSync(current).sort()) {
        walk(path.join(current, name), relative ? `${relative}/${name}` : name);
      }
      return;
    }
    assert.equal(stat.isFile(), true, `unsupported archived entry: ${relative}`);
    digest.update(`F\0${relative}\0`);
    digest.update(fs.readFileSync(current));
    digest.update("\0");
  }
}
