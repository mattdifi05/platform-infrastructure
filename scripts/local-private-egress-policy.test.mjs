#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CONSUMER_INVENTORY_SOURCE,
  INVENTORY_SCHEMA,
  bridgeNameForOwner,
  canonicalJson,
  compileManifest,
  readProtectedManifest,
  renderNftProgram,
  validatePolicy,
  validatePreviousManifest,
  validateRender,
  validateRuntimeInventory
} from "./local-private-egress-policy.mjs";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const policyPath = path.join(repositoryRoot, "config", "local-private-egress.json");
const sourceLockPath = path.join(repositoryRoot, "config", "v1-local-private-source-lock.json");
const policyText = fs.readFileSync(policyPath, "utf8");
const sourceLockText = fs.readFileSync(sourceLockPath, "utf8");
const basePolicyDocument = JSON.parse(policyText);
const sourceLock = JSON.parse(sourceLockText);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function networkDefinition(application) {
  return {
    name: application.network.physicalName,
    driver: "bridge",
    attachable: false,
    enable_ipv6: false,
    labels: {
      "com.platform.egress-owner": application.owner,
      "com.platform.trust-zone": "isolated-application-egress"
    },
    driver_opts: { "com.docker.network.bridge.name": application.network.bridgeName },
    ipam: { driver: "default", config: [{ subnet: application.network.subnet, gateway: application.network.gateway }] }
  };
}

function renderDocument(policyDocument = basePolicyDocument) {
  const render = {
    name: policyDocument.projectName,
    services: {},
    networks: {
      enterprise_net: { internal: true },
      platform_db_admin: { internal: true },
      platform_routing: { internal: true }
    }
  };
  for (const application of policyDocument.applications) {
    render.networks[application.network.logicalName] = networkDefinition(application);
    for (const consumer of application.allowedConsumers) {
      render.services[consumer] = {
        cap_drop: ["NET_RAW"],
        networks: Object.fromEntries([
          ...application.requiredInternalNetworks[consumer],
          application.network.logicalName
        ].sort().map((network) => [network, null]))
      };
    }
  }
  return render;
}

function text(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function runtimeNetwork(overrides = {}) {
  return {
    name: "bridge",
    id: "b".repeat(64),
    driver: "bridge",
    scope: "local",
    internal: false,
    attachable: false,
    ingress: false,
    enableIPv6: false,
    bridgeName: "docker0",
    composeProject: "",
    composeNetwork: "",
    composeVersion: "",
    trustZone: "",
    policyOwner: "",
    consumers: [],
    subnets: [{ gateway: "172.17.0.1", subnet: "172.17.0.0/16" }],
    ...overrides
  };
}

function inventoryDocument(renderText, policyDocument = basePolicyDocument, overrides = {}) {
  const networks = overrides.networks ?? [runtimeNetwork()];
  const routes = overrides.routes ?? [
    { family: "ipv4", destination: "192.168.1.0/24", device: "eno1", type: "unicast" },
    { family: "ipv4", destination: "default", device: "eno1", type: "unicast" },
    { family: "ipv6", destination: "default", device: "eno1", type: "unicast" }
  ];
  routes.sort((left, right) => `${left.family}|${left.destination}|${left.device}|${left.type}`
    .localeCompare(`${right.family}|${right.destination}|${right.device}|${right.type}`));
  networks.sort((left, right) => left.name.localeCompare(right.name));
  const containerIds = overrides.containerIds ?? [...new Set(networks.flatMap(({ consumers }) =>
    consumers.map(({ containerId }) => containerId)))].sort();
  return {
    schema: INVENTORY_SCHEMA,
    capturedAt: "2026-09-05T12:00:00Z",
    daemonIdBefore: "daemon-fixture-001",
    daemonIdAfter: "daemon-fixture-001",
    dockerHost: "unix:///var/run/docker.sock",
    sourceLockSha256: policyDocument.ownershipSourceLock.sha256,
    renderSha256: sha256(renderText),
    renderer: structuredClone(sourceLock.compose.renderer),
    networkInventoryComplete: true,
    containerInventoryComplete: true,
    consumerInventorySource: CONSUMER_INVENTORY_SOURCE,
    containerIds,
    routeInventoryComplete: true,
    networkNames: networks.map(({ name }) => name),
    networks,
    routes,
    ...Object.fromEntries(Object.entries(overrides).filter(([key]) => !new Set(["containerIds", "networks", "routes"]).has(key)))
  };
}

function compileFixture({ policyDocument = basePolicyDocument, render = null, inventory = null, previousManifest = null } = {}) {
  const currentPolicyText = text(policyDocument);
  const renderText = text(render ?? renderDocument(policyDocument));
  const inventoryText = text(inventory ?? inventoryDocument(renderText, policyDocument));
  return compileManifest({
    policyText: currentPolicyText,
    sourceLockText,
    renderText,
    inventoryText,
    previousManifestText: previousManifest ? canonicalJson(previousManifest) : null
  });
}

function existingApplicationNetwork(application, overrides = {}) {
  const networkId = overrides.id ?? "f".repeat(64);
  return runtimeNetwork({
    name: application.network.physicalName,
    id: networkId,
    bridgeName: application.network.bridgeName,
    composeProject: basePolicyDocument.projectName,
    composeNetwork: application.network.logicalName,
    composeVersion: sourceLock.compose.renderer.version,
    trustZone: "isolated-application-egress",
    policyOwner: application.owner,
    consumers: application.allowedConsumers.map((serviceName, index) => ({
      attachmentState: "configured-stopped",
      containerId: String(index + 1).repeat(64),
      containerState: "created",
      desiredNetworkId: networkId,
      endpointId: null,
      projectName: basePolicyDocument.projectName,
      serviceName
    })),
    subnets: [{ gateway: application.network.gateway, subnet: application.network.subnet }],
    ...overrides
  });
}

test("tracked proposal validates source ownership and compiles an interface-first fail-closed nft boundary", () => {
  const validated = validatePolicy({ policy: policyText, sourceLock: sourceLockText });
  assert.equal(validated.networkNamePrefix, "platform_infra_greenfield_platform");
  assert.equal(bridgeNameForOwner("fiplatform"), "lpe-fiplatform");
  assert.ok(bridgeNameForOwner("matthewdifilippo").length <= 15);

  const program = renderNftProgram(validated);
  const input = 'iifname "lpe-fiplatform" drop comment "lp-egress/input/fiplatform"';
  const spoof = 'iifname "lpe-fiplatform" ip saddr != 172.31.240.0/28 drop';
  const destination = 'iifname "lpe-fiplatform" ip saddr 172.31.240.0/28 ip daddr @non_public_ipv4 drop';
  assert.match(program, new RegExp(input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.ok(program.indexOf(spoof) < program.indexOf(destination));
  assert.match(program, /\n    type ipv4_addr\n    flags interval\n/);
  assert.match(program, /meta nfproto 10 drop comment "lp-egress\/forward\/fiplatform\/ipv6"/);
  assert.doesNotMatch(program, /type ipv4_addr;|flags interval;|meta nfproto ipv6/);
  assert.doesNotMatch(program, /\b(accept|return)\b.*comment/);
  assert.doesNotMatch(program, /flush ruleset|DOCKER-USER|ufw/i);

  const manifest = compileFixture();
  assert.equal(manifest.status, "admitted");
  assert.equal(manifest.applications[0].runtimeNetworkId, null);
  assert.equal(manifest.nftables.expectedPreimageNormalizedSha256, null);
  assert.equal(validatePreviousManifest(canonicalJson(manifest), validated).applications[0].owner, "fiplatform");
});

test("source-lock ownership rejects cross-app, core and unknown consumers", () => {
  for (const consumer of ["php-stream", "mariadb", "not-a-service"]) {
    const forged = structuredClone(basePolicyDocument);
    forged.applications[0].allowedConsumers = [consumer];
    forged.applications[0].requiredInternalNetworks = { [consumer]: ["enterprise_net"] };
    assert.throws(
      () => validatePolicy({ policy: text(forged), sourceLock: sourceLockText }),
      /belongs to|core or unknown/i
    );
  }
});

test("render binding rejects a foreign project, network identity, sharing, IPv6 and unsafe capabilities", () => {
  const validated = validatePolicy({ policy: policyText, sourceLock: sourceLockText });
  const base = renderDocument();
  const mutations = [
    [(render) => { render.name = "foreign_project"; }, /project name differs/i],
    [(render) => { render.networks.fiplatform_egress.name = "foreign_fiplatform_egress"; }, /foreign physical name/i],
    [(render) => { render.networks.fiplatform_egress.enable_ipv6 = true; }, /IPv6-disabled/i],
    [(render) => { render.networks.fiplatform_egress.internal = true; }, /non-internal/i],
    [(render) => { render.networks.fiplatform_egress.labels["com.platform.egress-owner"] = "stream"; }, /foreign trust-zone or owner/i],
    [(render) => { render.services["php-fiplatform"].cap_drop = []; }, /drop NET_RAW/i],
    [(render) => { render.services["php-fiplatform"].cap_add = "NET_ADMIN"; }, /invalid capability/i],
    [(render) => { render.services["php-fiplatform"].cap_add = ["NET_ADMIN"]; }, /unsafe capabilities/i],
    [(render) => { delete render.services["php-fiplatform"].networks.platform_db_admin; }, /exact required internal and egress/i],
    [(render) => { render.networks.platform_db_admin.internal = false; }, /must declare internal: true/i],
    [(render) => {
      render.networks.platform_egress = { internal: false };
      render.services["php-fiplatform"].networks.platform_egress = null;
    }, /exact required internal and egress/i],
    [(render) => {
      render.services.mariadb = { networks: { fiplatform_egress: null } };
    }, /consumers differ/i]
  ];
  for (const [mutate, pattern] of mutations) {
    const forged = structuredClone(base);
    mutate(forged);
    assert.throws(() => validateRender(text(forged), validated), pattern);
  }
});

test("runtime admission binds daemon, renderer and complete non-overlapping inventories", () => {
  const validated = validatePolicy({ policy: policyText, sourceLock: sourceLockText });
  const renderText = text(renderDocument());
  const rendered = validateRender(renderText, validated);
  const base = inventoryDocument(renderText);
  assert.doesNotThrow(() => validateRuntimeInventory(text(base), validated, rendered));

  const unlabeled = structuredClone(base);
  unlabeled.networks[0].consumers = [{
    attachmentState: "configured-stopped",
    containerId: "a".repeat(64),
    containerState: "exited",
    desiredNetworkId: unlabeled.networks[0].id,
    endpointId: null,
    projectName: null,
    serviceName: null
  }];
  unlabeled.containerIds = ["a".repeat(64)];
  assert.doesNotThrow(
    () => validateRuntimeInventory(text(unlabeled), validated, rendered),
    "unrelated manual containers must remain truthfully represented without invented Compose labels"
  );

  const cases = [
    [(value) => { value.daemonIdAfter = "daemon-fixture-002"; }, /daemon identity changed/i],
    [(value) => { value.renderer.version = "5.5.1"; }, /renderer differs/i],
    [(value) => { value.networkInventoryComplete = false; }, /complete network, container and route/i],
    [(value) => { value.containerInventoryComplete = false; }, /complete network, container and route/i],
    [(value) => { value.consumerInventorySource = "network-inspect-only"; }, /all desired attachments/i],
    [(value) => { value.networks[0].bridgeName = "lpe-fiplatform"; }, /bridge name is already owned/i],
    [(value) => {
      value.networks[0].subnets = [{ gateway: "172.31.240.1", subnet: "172.31.240.0/27" }];
    }, /overlaps Docker network/i],
    [(value) => {
      value.routes.splice(1, 0, { family: "ipv4", destination: "172.31.240.8/32", device: "dummy0", type: "unicast" });
      value.routes.sort((left, right) => `${left.family}|${left.destination}|${left.device}|${left.type}`
        .localeCompare(`${right.family}|${right.destination}|${right.device}|${right.type}`));
    }, /overlaps host route/i]
  ];
  for (const [mutate, pattern] of cases) {
    const forged = structuredClone(base);
    mutate(forged);
    assert.throws(() => validateRuntimeInventory(text(forged), validated, rendered), pattern);
  }
});

test("previous authority admits exact configured-stopped joins then active endpoints, never missing or pending consumers", () => {
  const first = compileFixture();
  const renderText = text(renderDocument());
  const application = basePolicyDocument.applications[0];
  const existing = existingApplicationNetwork(application);
  const routes = [
    { family: "ipv4", destination: "172.31.240.0/28", device: "lpe-fiplatform", type: "unicast" },
    { family: "ipv4", destination: "172.31.240.1/32", device: "lpe-fiplatform", type: "local" },
    { family: "ipv4", destination: "192.168.1.0/24", device: "eno1", type: "unicast" },
    { family: "ipv4", destination: "default", device: "eno1", type: "unicast" }
  ];
  const inventory = inventoryDocument(renderText, basePolicyDocument, { networks: [runtimeNetwork(), existing], routes });

  assert.throws(
    () => compileFixture({ inventory }),
    /lacks exact previous-manifest authority/i
  );
  const reconciled = compileFixture({ inventory, previousManifest: first });
  assert.equal(reconciled.applications[0].runtimeNetworkId, "f".repeat(64));
  assert.equal(reconciled.nftables.expectedPreimageNormalizedSha256, first.nftables.normalizedSha256);

  const activeExisting = existingApplicationNetwork(application);
  activeExisting.consumers = activeExisting.consumers.map((consumer) => ({
    ...consumer,
    attachmentState: "active-endpoint",
    containerState: "running",
    endpointId: "d".repeat(64)
  }));
  const activeInventory = inventoryDocument(renderText, basePolicyDocument, {
    networks: [runtimeNetwork(), activeExisting],
    routes
  });
  const active = compileFixture({ inventory: activeInventory, previousManifest: reconciled });
  assert.equal(active.applications[0].runtimeNetworkId, "f".repeat(64));

  const missingDesiredConsumer = structuredClone(inventory);
  const missingTarget = missingDesiredConsumer.networks.find(({ name }) => name === application.network.physicalName);
  missingTarget.consumers = [];
  missingDesiredConsumer.containerIds = [];
  assert.throws(
    () => compileFixture({ inventory: missingDesiredConsumer, previousManifest: first }),
    /identity or consumers differ/i
  );

  const falsePendingActive = structuredClone(inventory);
  const pendingConsumer = falsePendingActive.networks
    .find(({ name }) => name === application.network.physicalName).consumers[0];
  pendingConsumer.containerState = "running";
  assert.throws(
    () => compileFixture({ inventory: falsePendingActive, previousManifest: first }),
    /configured-stopped attachment is inconsistent/i
  );

  const wrongDesiredNetwork = structuredClone(inventory);
  wrongDesiredNetwork.networks
    .find(({ name }) => name === application.network.physicalName).consumers[0].desiredNetworkId = "e".repeat(64);
  assert.throws(
    () => compileFixture({ inventory: wrongDesiredNetwork, previousManifest: first }),
    /desired network ID differs/i
  );

  const crossAppInventory = structuredClone(inventory);
  crossAppInventory.networks.find(({ name }) => name === application.network.physicalName).consumers[0].serviceName = "php-stream";
  assert.throws(
    () => compileFixture({ inventory: crossAppInventory, previousManifest: first }),
    /identity or consumers differ/i
  );

  const changedIdInventory = structuredClone(inventory);
  changedIdInventory.networks.find(({ name }) => name === application.network.physicalName).id = "e".repeat(64);
  assert.throws(
    () => compileFixture({ inventory: changedIdInventory, previousManifest: reconciled }),
    /network ID differs/i
  );
});

test("a later app opt-in retains the exact existing app while admitting only the absent new target", () => {
  const initial = compileFixture();
  const firstApplication = basePolicyDocument.applications[0];
  const existingRenderText = text(renderDocument());
  const existingInventory = inventoryDocument(existingRenderText, basePolicyDocument, {
    networks: [runtimeNetwork(), existingApplicationNetwork(firstApplication)],
    routes: [
      { family: "ipv4", destination: "172.31.240.0/28", device: "lpe-fiplatform", type: "unicast" },
      { family: "ipv4", destination: "default", device: "eno1", type: "unicast" }
    ]
  });
  const reconciled = compileFixture({ inventory: existingInventory, previousManifest: initial });

  const expanded = structuredClone(basePolicyDocument);
  expanded.applications.push({
    state: "proposed",
    owner: "stream",
    allowedConsumers: ["php-stream"],
    requiredInternalNetworks: {
      "php-stream": ["enterprise_net", "platform_routing"]
    },
    network: {
      logicalName: "stream_egress",
      physicalName: "platform_infra_greenfield_platform_stream_egress",
      bridgeName: "lpe-stream",
      subnet: "172.31.240.16/28",
      gateway: "172.31.240.17"
    }
  });
  const expandedRenderText = text(renderDocument(expanded));
  const expandedInventory = inventoryDocument(expandedRenderText, expanded, {
    networks: [runtimeNetwork(), existingApplicationNetwork(firstApplication)],
    routes: [
      { family: "ipv4", destination: "172.31.240.0/28", device: "lpe-fiplatform", type: "unicast" },
      { family: "ipv4", destination: "default", device: "eno1", type: "unicast" }
    ]
  });
  const next = compileFixture({ policyDocument: expanded, inventory: expandedInventory, previousManifest: reconciled });
  assert.deepEqual(next.applications.map(({ owner, runtimeNetworkId }) => [owner, runtimeNetworkId]), [
    ["fiplatform", "f".repeat(64)],
    ["stream", null]
  ]);

  const changedExistingContract = structuredClone(expanded);
  changedExistingContract.applications[0].requiredInternalNetworks["php-fiplatform"] = [
    "enterprise_net",
    "platform_routing"
  ];
  const changedRenderText = text(renderDocument(changedExistingContract));
  const changedInventory = inventoryDocument(changedRenderText, changedExistingContract, {
    networks: [runtimeNetwork(), existingApplicationNetwork(firstApplication)],
    routes: [
      { family: "ipv4", destination: "172.31.240.0/28", device: "lpe-fiplatform", type: "unicast" },
      { family: "ipv4", destination: "default", device: "eno1", type: "unicast" }
    ]
  });
  assert.throws(
    () => compileFixture({
      policyDocument: changedExistingContract,
      inventory: changedInventory,
      previousManifest: reconciled
    }),
    /fiplatform existing network lacks exact previous-manifest authority/i
  );
});

test("multiple consumers retain distinct internal networks instead of receiving an owner-wide union", () => {
  const expanded = structuredClone(basePolicyDocument);
  expanded.applications.push({
    state: "proposed",
    owner: "stexor",
    allowedConsumers: ["backend", "web"],
    requiredInternalNetworks: {
      backend: ["enterprise_net", "platform_db_admin"],
      web: ["enterprise_net", "platform_routing"]
    },
    network: {
      logicalName: "stexor_egress",
      physicalName: "platform_infra_greenfield_platform_stexor_egress",
      bridgeName: "lpe-stexor",
      subnet: "172.31.240.16/28",
      gateway: "172.31.240.17"
    }
  });
  const validated = validatePolicy({ policy: text(expanded), sourceLock: sourceLockText });
  const render = renderDocument(expanded);
  assert.doesNotThrow(() => validateRender(text(render), validated));

  const siblingSwap = structuredClone(render);
  delete siblingSwap.services.web.networks.platform_routing;
  siblingSwap.services.web.networks.platform_db_admin = null;
  assert.throws(
    () => validateRender(text(siblingSwap), validated),
    /web rendered network attachments differ from its exact required internal and egress networks/i
  );
});

test("CLI validation is read-only and requires absolute authority paths", () => {
  const script = path.join(import.meta.dirname, "local-private-egress-policy.mjs");
  const valid = spawnSync(process.execPath, [
    script, "validate", "--policy", policyPath, "--source-lock", sourceLockPath
  ], { encoding: "utf8" });
  assert.equal(valid.status, 0, valid.stderr);
  assert.equal(JSON.parse(valid.stdout).projectName, "platform_infra_greenfield");

  const relative = spawnSync(process.execPath, [
    script, "validate", "--policy", "config/local-private-egress.json", "--source-lock", sourceLockPath
  ], { encoding: "utf8" });
  assert.notEqual(relative.status, 0);
  assert.match(relative.stderr, /absolute path/i);
});

test("previous-manifest reads reject writable ancestors before opening the protected file", () => {
  const boundary = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "local-private-egress-authority-")));
  const writableParent = path.join(boundary, "candidate");
  const manifestPath = path.join(writableParent, "previous.json");
  try {
    fs.chmodSync(boundary, 0o700);
    fs.mkdirSync(writableParent, { mode: 0o777 });
    fs.chmodSync(writableParent, 0o777);
    fs.writeFileSync(manifestPath, "{}\n", { mode: 0o600 });
    assert.throws(
      () => readProtectedManifest(manifestPath, { requiredUid: process.getuid(), boundary }),
      /writable ancestor/i
    );
    fs.chmodSync(writableParent, 0o700);
    assert.equal(readProtectedManifest(manifestPath, { requiredUid: process.getuid(), boundary }), "{}\n");
  } finally {
    fs.rmSync(boundary, { recursive: true, force: true });
  }
});

function hostBoundarySources() {
  return {
    helper: fs.readFileSync(path.join(import.meta.dirname, "local-private-egress-firewall.sh"), "utf8"),
    installer: fs.readFileSync(path.join(import.meta.dirname, "local-private-egress-install.sh"), "utf8"),
    unit: fs.readFileSync(path.join(repositoryRoot, "systemd", "local-private-egress-firewall.service"), "utf8"),
    dockerServiceDropIn: fs.readFileSync(path.join(repositoryRoot, "systemd", "local-private-egress-docker.service.conf"), "utf8"),
    dockerSocketDropIn: fs.readFileSync(path.join(repositoryRoot, "systemd", "local-private-egress-docker.socket.conf"), "utf8")
  };
}

test("firewall helper owns only one exact table and rejects an unknown preimage", () => {
  const { helper } = hostBoundarySources();
  assert.match(helper, /Refusing to replace an unknown same-name nftables table/);
  assert.match(helper, /exec unshare --net -- .* --apply/);
  assert.match(helper, /delete table inet %s/);
  assert.doesNotMatch(helper, /^\s*(?:nft|"\$NFT_BIN").*flush ruleset/m);
  assert.doesNotMatch(helper, /DOCKER-USER|iptables/);
});

test("Docker boot has hard Requires/After dependencies on the successful guard", () => {
  const { unit, dockerServiceDropIn, dockerSocketDropIn } = hostBoundarySources();
  assert.match(unit, /^Before=docker\.socket docker\.service$/m);
  for (const dropIn of [dockerServiceDropIn, dockerSocketDropIn]) {
    assert.match(dropIn, /^Requires=local-private-egress-firewall\.service$/m);
    assert.match(dropIn, /^After=local-private-egress-firewall\.service$/m);
  }
});

test("a missing manifest fails the guard instead of being skipped", () => {
  const { unit } = hostBoundarySources();
  assert.doesNotMatch(unit, /ConditionPathExists|ExecCondition/);
  assert.match(unit, /^ExecStart=.* --apply --manifest \/etc\/platform-infrastructure\/local-private-egress\.manifest\.json /m);
  assert.match(unit, /^ExecStartPost=.* --verify --manifest \/etc\/platform-infrastructure\/local-private-egress\.manifest\.json$/m);
});

test("every Docker daemon start re-applies the admitted guard", () => {
  const { unit, dockerServiceDropIn } = hostBoundarySources();
  assert.match(unit, /^CapabilityBoundingSet=CAP_NET_ADMIN$/m);
  assert.match(dockerServiceDropIn, /^ExecStartPre=.* --apply .* --confirm APPLY-LOCAL-PRIVATE-EGRESS$/m);
  assert.doesNotMatch(dockerServiceDropIn, /^ExecStartPre=-/m, "Docker start must fail when guard application fails");
});

test("installer refuses foreign targets before round-trip or filesystem mutation", () => {
  const { installer } = hostBoundarySources();
  assert.match(installer, /intentionally does not start it or change the/);
  assert.match(installer, /Refusing to overwrite foreign or drifted installation file/);
  assert.match(installer, /Installed manifest does not match --previous-manifest preimage/);
  const targetPreflight = installer.indexOf('assert_new_or_exact "$ROOT_DIR/scripts/local-private-egress-firewall.sh"');
  const manifestPreflight = installer.indexOf("manifest_action=unchanged");
  const kernelRoundTrip = installer.indexOf('"$ROOT_DIR/scripts/local-private-egress-firewall.sh" --kernel-roundtrip --manifest');
  const firstDirectoryMutation = installer.indexOf('ensure_root_directory "$INSTALL_DIR"', manifestPreflight);
  const firstFileMutation = installer.indexOf('install_if_absent "$ROOT_DIR/scripts/local-private-egress-firewall.sh"');
  assert.ok(targetPreflight > 0 && manifestPreflight > targetPreflight);
  assert.ok(kernelRoundTrip > manifestPreflight);
  assert.ok(firstDirectoryMutation > kernelRoundTrip);
  assert.ok(firstFileMutation > firstDirectoryMutation);
});

test("host boundary shell entrypoints pass POSIX syntax validation", () => {
  for (const shellScript of [
    path.join(import.meta.dirname, "local-private-egress-firewall.sh"),
    path.join(import.meta.dirname, "local-private-egress-install.sh")
  ]) {
    const syntax = spawnSync("sh", ["-n", shellScript], { encoding: "utf8" });
    assert.equal(syntax.status, 0, syntax.stderr);
  }
});

test("maintainability registers only the pre-Docker egress host entrypoints as direct operations", () => {
  const infraOps = fs.readFileSync(path.join(import.meta.dirname, "infra-ops.mjs"), "utf8");
  const directStart = infraOps.indexOf("const directOperationalScripts = new Set([");
  const directEnd = infraOps.indexOf("]);", directStart);
  assert.ok(directStart > 0 && directEnd > directStart, "direct-operation registry is missing");
  const directRegistry = infraOps.slice(directStart, directEnd);
  assert.match(directRegistry, /"local-private-egress-firewall\.sh"/);
  assert.match(directRegistry, /"local-private-egress-install\.sh"/);
  assert.deepEqual(
    [...directRegistry.matchAll(/"(local-private-egress[^"]*\.sh)"/g)].map((match) => match[1]),
    ["local-private-egress-firewall.sh", "local-private-egress-install.sh"],
    "the direct-operation registry must contain only the two required egress host entrypoints"
  );
  assert.doesNotMatch(
    directRegistry,
    /local-private-egress-netns-test\.sh|local-private-egress[^"\n]*\*/,
    "the isolated test must use the existing test suffix and no broad egress wildcard may bypass wrapper checks"
  );

  const wrapperLoop = infraOps.slice(directEnd, infraOps.indexOf("Infrastructure maintainability hygiene checks passed.", directEnd));
  assert.match(
    wrapperLoop,
    /if \(directOperationalScripts\.has\(name\) \|\| \/\(\?:-\|\\\.\)test\\\.sh\$\/\.test\(name\)\) \{/
  );
  assert.match(wrapperLoop, /assertMatch\(text, \/infra-ops\\\.sh\//);
});
