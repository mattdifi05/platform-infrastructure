#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const EXPECTED_HASHES = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/runtime-isolation-policy.mjs", "016063f547fea979866e665f98964d1e3e8fb13fb18eda48a64e3857e6d279ab"],
  ["compose.runtime-isolation.yaml", "69d7383d8f0d499d0580514e30944a6819e14631619f536587420696d2238fc6"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["scripts/hosted-workload-lock.sh", "f87317c017f541796f4144442a07c3c98e0b280aafb11396bd64852571390674"],
  ["project-router/server.mjs", "7ace8ada6839a02abe80b723afa225b83b049789c3fe7e975a4755a32cde65e8"],
]);

const [sourceRootArgument, wrapperRootArgument, wrapperSentinelArgument, preexistingRootArgument] = process.argv.slice(2);
if (!sourceRootArgument || !wrapperRootArgument || !wrapperSentinelArgument || !preexistingRootArgument) {
  throw new Error("direct invocation denied: use run-from-git-archive.sh with its wrapper-owned temporary root");
}

const wrapperRootPath = path.resolve(wrapperRootArgument);
const wrapperRootStat = fs.lstatSync(wrapperRootPath);
assert.equal(wrapperRootStat.isDirectory(), true, "wrapper root is not a directory");
assert.equal(wrapperRootStat.isSymbolicLink(), false, "wrapper root must not be a symbolic link");
const wrapperRoot = fs.realpathSync(wrapperRootPath);
assert.equal(wrapperRoot, wrapperRootPath, "wrapper root must be its physical path");

const sourceRootPath = path.resolve(sourceRootArgument);
const sourceRootStat = fs.lstatSync(sourceRootPath);
assert.equal(sourceRootStat.isDirectory(), true, "source archive is not a directory");
assert.equal(sourceRootStat.isSymbolicLink(), false, "source archive must not be a symbolic link");
const sourceRoot = fs.realpathSync(sourceRootPath);
assert.equal(sourceRoot, path.join(wrapperRoot, "source"), "source archive must be the exact source child");
assert.equal(path.dirname(sourceRoot), wrapperRoot, "source archive escaped the wrapper root");

const wrapperSentinelPath = path.resolve(wrapperSentinelArgument);
const wrapperSentinelStat = fs.lstatSync(wrapperSentinelPath);
assert.equal(wrapperSentinelStat.isFile(), true, "wrapper ownership sentinel is not a regular file");
assert.equal(wrapperSentinelStat.isSymbolicLink(), false, "wrapper ownership sentinel must not be a symbolic link");
assert.equal(fs.realpathSync(wrapperSentinelPath), wrapperSentinelPath, "wrapper ownership sentinel must be its physical path");
assert.equal(path.dirname(wrapperSentinelPath), wrapperRoot, "wrapper ownership sentinel escaped the wrapper root");
const sentinelMatch = path.basename(wrapperSentinelPath).match(/^\.project-router-volumes-from-owner-([0-9a-f]{64})$/);
assert.ok(sentinelMatch, "wrapper ownership sentinel name is invalid");
const ownerToken = sentinelMatch[1];
assert.equal(
  fs.readFileSync(wrapperSentinelPath, "utf8"),
  `project-router-volumes-from:${ownerToken}\n`,
  "wrapper ownership sentinel content is invalid",
);

for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
  const target = path.join(sourceRoot, relativePath);
  const targetStat = fs.lstatSync(target);
  assert.equal(targetStat.isFile(), true, `${relativePath} is not a regular file`);
  assert.equal(targetStat.isSymbolicLink(), false, `${relativePath} must not be a symbolic link`);
  assert.equal(sha256File(target), expectedHash, `unexpected source revision for ${relativePath}`);
}

const preexistingRootPath = path.resolve(preexistingRootArgument);
const preexistingRootStat = fs.lstatSync(preexistingRootPath);
assert.equal(preexistingRootStat.isDirectory(), true, "pre-existing target is not a directory");
assert.equal(preexistingRootStat.isSymbolicLink(), false, "pre-existing target must not be a symbolic link");
const preexistingRoot = fs.realpathSync(preexistingRootPath);
assert.equal(preexistingRoot, path.join(wrapperRoot, "preexisting"), "pre-existing target is not the exact wrapper child");
const preexistingFile = path.join(preexistingRoot, "project-state.json");
const preexistingBefore = fs.lstatSync(preexistingFile);
const preexistingBytes = fs.readFileSync(preexistingFile);
const preexistingHash = sha256Bytes(preexistingBytes);
const preexistingEntries = fs.readdirSync(preexistingRoot).sort();
assert.throws(() => claimOwnedFixture(preexistingRoot, wrapperRoot, ownerToken), /refusing pre-existing fixture target/);
assert.deepEqual(fs.readdirSync(preexistingRoot).sort(), preexistingEntries);
const preexistingAfter = fs.lstatSync(preexistingFile);
assert.equal(preexistingAfter.dev, preexistingBefore.dev, "pre-existing state device changed");
assert.equal(preexistingAfter.ino, preexistingBefore.ino, "pre-existing state inode changed");
assert.deepEqual(fs.readFileSync(preexistingFile), preexistingBytes);
console.log(`[+] negative-control preexisting_target_rejected=true state_preserved=true sha256=${preexistingHash}`);

const fixtureRoot = path.join(wrapperRoot, `fixture-${ownerToken}`);
const fixtureOwnership = claimOwnedFixture(fixtureRoot, wrapperRoot, ownerToken);

try {
  const contractSource = readSource("scripts/hosted-workload-contract.mjs");
  const runtimePolicySource = readSource("scripts/runtime-isolation-policy.mjs");
  const runtimeComposeSource = readSource("compose.runtime-isolation.yaml");
  const composeWrapperSource = readSource("scripts/compose-vps.sh");
  const prepareSource = readSource("scripts/prepare-hosted-workloads.sh");
  const lockSource = readSource("scripts/hosted-workload-lock.sh");
  const routerSource = readSource("project-router/server.mjs");

  assert.match(contractSource, /function assertVolumes\(name, service, workloadId\) \{\n  for \(const volume of service\.volumes \?\? \[\]\)/);
  assert.match(contractSource, /assertVolumes\(name, serviceDefinition, manifest\.id\);/);
  assert.doesNotMatch(contractSource, /volumes_from/, "candidate contract unexpectedly handles volumes_from");
  assert.match(runtimePolicySource, /function volumes\(service\) \{\n  return \(service\?\.volumes \|\| \[\]\)\.map/);
  assert.doesNotMatch(runtimePolicySource, /volumes_from/, "runtime isolation unexpectedly resolves volumes_from");

  const routerBlock = yamlServiceBlock(runtimeComposeSource, "project-router", "mariadb");
  assert.match(routerBlock, /- \.\/project-router:\/app:ro/);
  assert.match(routerBlock, /- \$\{PHP_PROJECTS_DIR:-\.\.\/src\}:\/var\/www\/projects:ro/);
  assert.match(routerBlock, /- \.\/projects-portal\/state:\/var\/www\/project-state:ro/);
  assert.match(routerSource, /PROJECT_STATE_FILE \|\| "\/var\/www\/project-state\/projects\.json"/);
  assert.match(routerSource, /PROJECT_ROUTER_WORKLOAD_LOCK_FILE \|\| "\/var\/www\/project-state\/hosted-workloads\.lock\.json"/);

  assert.match(prepareSource, /HOSTED_WORKLOAD_LOCK="\$resolved" HOSTED_WORKLOAD_ALLOW_RESOLVED=1[\s\S]*compose-vps\.sh" config --format json > "\$combined_render"/);
  assert.match(prepareSource, /hosted-workload-contract\.mjs verify-render[\s\S]*--combinedRender "\$combined_render"/);
  assert.match(lockSource, /compose-files\)[\s\S]*jq -r '\.workloads\[\]\.composePath'/);
  const runtimeOverlayIndex = composeWrapperSource.indexOf("-f compose.runtime-isolation.yaml");
  const workloadFilesIndex = composeWrapperSource.indexOf("compose+=(-f \"$workload_file\")");
  assert.ok(runtimeOverlayIndex > 0 && workloadFilesIndex > runtimeOverlayIndex, "workload files are not appended after the protected runtime overlay");

  const contractModule = await import(pathToFileURL(path.join(sourceRoot, "scripts/hosted-workload-contract.mjs")).href);
  const policyModule = await import(pathToFileURL(path.join(sourceRoot, "scripts/runtime-isolation-policy.mjs")).href);
  assert.equal(typeof contractModule.validateRenderedWorkloads, "function");
  assert.equal(typeof contractModule.validateWorkloadManifest, "function");
  assert.equal(typeof policyModule.evaluateRuntimeIsolation, "function");

  const mountSources = createReadableMountFixture(fixtureRoot);
  const fixture = buildRenderedFixture(contractModule.validateWorkloadManifest, mountSources, true);
  const validation = contractModule.validateRenderedWorkloads({ core: fixture.core, combined: fixture.combined, lock: fixture.lock });
  assert.deepEqual(validation.routes, [{
    workloadId: "fixture-app",
    slug: "fixture",
    service: "fixture-app-web",
    port: 3000,
    upstream: "http://fixture-app-web:3000",
  }]);
  assert.deepEqual(fixture.combined.services["fixture-app-web"].volumes_from, ["project-router:ro"]);
  assert.equal(fixture.combined.services["fixture-app-web"].volumes, undefined);
  console.log("[VULNERABLE] CAN-144 candidate_validator=ACCEPTED volumes_from=project-router:ro direct_volumes=0 protected_service_unchanged=true");

  const policy = policyModule.evaluateRuntimeIsolation(fixture.combined, {
    maxMemoryBytes: 64 * 1024 * 1024 * 1024,
    maxWorkloadMemoryBytes: 8 * 1024 * 1024 * 1024,
  });
  const directBindCheck = findCheck(policy, "workload-no-bind-mounts-fixture-app-web");
  const stateTargetCheck = findCheck(policy, "workload-deny-mount-var-www-project-state-fixture-app-web");
  assert.equal(directBindCheck.status, "passed");
  assert.equal(stateTargetCheck.status, "passed");
  console.log("[+] secondary_policy direct_bind_check=passed project_state_target_check=passed inherited_mounts_inspected=false");

  const inherited = resolveVolumesFrom(fixture.combined, "fixture-app-web");
  assert.deepEqual(inherited.map((mount) => mount.target).sort(), ["/app", "/var/www/project-state", "/var/www/projects"]);
  assert.equal(inherited.every((mount) => mount.read_only === true), true);
  const markers = [
    readThroughMount(inherited, "/app/server.mjs"),
    readThroughMount(inherited, "/var/www/projects/peer-app/package.json"),
    readThroughMount(inherited, "/var/www/project-state/projects.json"),
    readThroughMount(inherited, "/var/www/project-state/hosted-workloads.lock.json"),
  ];
  assert.deepEqual(markers, ["router-source-marker", "peer-project-marker", "project-state-marker", "verified-lock-marker"]);
  console.log("[VULNERABLE] CAN-144 inherited_targets=/app,/var/www/project-state,/var/www/projects inherited_read_only=true readable_fixture_markers=4 peer_source_visible=true state_and_lock_visible=true");

  const directBindFixture = buildRenderedFixture(contractModule.validateWorkloadManifest, mountSources, false);
  directBindFixture.combined.services["fixture-app-web"].volumes = [{
    type: "bind",
    source: mountSources.projects,
    target: "/var/www/projects",
    read_only: true,
  }];
  assert.throws(
    () => contractModule.validateRenderedWorkloads({ core: directBindFixture.core, combined: directBindFixture.combined, lock: directBindFixture.lock }),
    /bind mounts are forbidden/,
  );
  console.log("[+] negative-control candidate_direct_bind=REJECTED closest_control_active=true");

  assert.throws(() => fixedValidateRenderedWorkloads(contractModule.validateRenderedWorkloads, fixture), /service inheritance field volumes_from is forbidden/);
  const baseline = buildRenderedFixture(contractModule.validateWorkloadManifest, mountSources, false);
  const fixedBaseline = fixedValidateRenderedWorkloads(contractModule.validateRenderedWorkloads, baseline);
  assert.equal(fixedBaseline.routes.length, 1);
  console.log("[+] negative-control synthetic_fixed_guard volumes_from=REJECTED baseline_without_inheritance=ACCEPTED fail_closed_before_activation=true");

  const unknownTarget = buildRenderedFixture(contractModule.validateWorkloadManifest, mountSources, true);
  unknownTarget.combined.services["fixture-app-web"].volumes_from = ["missing-service:ro"];
  assert.throws(() => resolveVolumesFrom(unknownTarget.combined, "fixture-app-web"), /unknown volumes_from service/);
  console.log("[+] negative-control unknown_inheritance_target=REJECTED resolver_fail_closed=true");

  const receipt = {
    version: 1,
    revision: "68cd05895b8d479ffb8167344282e7d922958bfc",
    tree: "70031b30316fbaecbb23249491d6ff4e364d65d5",
    canonicalFinding: "CAN-144",
    vulnerable: true,
    candidate: {
      validatorDecision: "ACCEPTED",
      volumesFrom: "project-router:ro",
      directVolumes: 0,
      inheritedTargets: inherited.map((mount) => mount.target).sort(),
      inheritedReadOnly: inherited.every((mount) => mount.read_only),
      readableFixtureMarkers: markers.length,
    },
    negativeControls: {
      directBindRejected: true,
      syntheticFixedGuardRejected: true,
      baselineWithoutInheritanceAccepted: fixedBaseline.routes.length === 1,
      unknownTargetRejected: true,
    },
    safety: {
      dockerCalls: 0,
      composeCalls: 0,
      containersStarted: 0,
      mountsCreated: 0,
      realProjectFilesRead: 0,
      credentialsRead: 0,
      servicesStarted: 0,
      networkAttempts: 0,
    },
  };
  const receiptPath = path.join(fixtureRoot, "project-router-volumes-from-receipt.json");
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  assert.equal(JSON.parse(fs.readFileSync(receiptPath, "utf8")).canonicalFinding, "CAN-144");
  console.log("[+] safety docker_calls=0 compose_calls=0 containers_started=0 mounts_created=0 real_project_files_read=0 credentials_read=0 services_started=0 network_attempts=0");
  console.log("[+] result=VULNERABLE");
} finally {
  cleanupOwnedFixture(fixtureOwnership, wrapperRoot);
}

assert.equal(fs.existsSync(fixtureRoot), false, "sentinel-owned fixture was not removed");
assert.deepEqual(fs.readdirSync(preexistingRoot).sort(), preexistingEntries);
const preservedStat = fs.lstatSync(preexistingFile);
assert.equal(preservedStat.dev, preexistingBefore.dev);
assert.equal(preservedStat.ino, preexistingBefore.ino);
assert.equal(sha256File(preexistingFile), preexistingHash);
console.log("[+] cleanup sentinel_owned_fixture_removed=true preexisting_state_still_present=true");

function readSource(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function yamlServiceBlock(source, name, nextName) {
  const start = source.indexOf(`  ${name}:`);
  const end = source.indexOf(`  ${nextName}:`, start + 1);
  assert.notEqual(start, -1, `${name} service is missing`);
  assert.notEqual(end, -1, `${name} service is unterminated`);
  return source.slice(start, end);
}

function createReadableMountFixture(root) {
  const router = path.join(root, "router-source");
  const projects = path.join(root, "peer-projects");
  const state = path.join(root, "project-state");
  fs.mkdirSync(router, { mode: 0o700 });
  fs.mkdirSync(path.join(projects, "peer-app"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(state, { mode: 0o700 });
  writeMarker(path.join(router, "server.mjs"), "router-source-marker");
  writeMarker(path.join(projects, "peer-app", "package.json"), "peer-project-marker");
  writeMarker(path.join(state, "projects.json"), "project-state-marker");
  writeMarker(path.join(state, "hosted-workloads.lock.json"), "verified-lock-marker");
  return { router, projects, state };
}

function writeMarker(filePath, marker) {
  fs.writeFileSync(filePath, `${marker}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
}

function buildRenderedFixture(validateWorkloadManifest, sources, includeVolumesFrom) {
  const digest = "a".repeat(64);
  const manifest = validateWorkloadManifest({
    version: 1,
    id: "fixture-app",
    composeFile: "compose.platform.yaml",
    services: [{ name: "fixture-app-web", role: "web", routes: [{ slug: "fixture", port: 3000 }] }],
    secrets: [],
    migrationRoots: [],
  });
  const projectRouter = {
    image: `registry.example/router@sha256:${digest}`,
    read_only: true,
    init: true,
    restart: "unless-stopped",
    security_opt: ["no-new-privileges:true"],
    cap_drop: ["ALL"],
    user: "1000:1000",
    cpus: 0.5,
    mem_limit: String(192 * 1024 * 1024),
    mem_reservation: String(48 * 1024 * 1024),
    pids_limit: 192,
    cpu_shares: 1024,
    blkio_config: { weight: 700 },
    ulimits: { nofile: { soft: 16384, hard: 16384 } },
    volumes: [
      { type: "bind", source: sources.router, target: "/app", read_only: true },
      { type: "bind", source: sources.projects, target: "/var/www/projects", read_only: true },
      { type: "bind", source: sources.state, target: "/var/www/project-state", read_only: true },
    ],
    networks: { platform_routing: null },
  };
  const workload = {
    image: `registry.example/fixture/app@sha256:${digest}`,
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
    networks: { fixture_app_ingress: null },
    labels: { "com.platform.workload-id": "fixture-app", "com.platform.workload-role": "web" },
  };
  if (includeVolumesFrom) workload.volumes_from = ["project-router:ro"];
  const core = {
    services: { "project-router": projectRouter },
    networks: { platform_routing: { internal: true } },
  };
  const combined = {
    services: {
      "project-router": { ...structuredClone(projectRouter), networks: { platform_routing: null, fixture_app_ingress: null } },
      "fixture-app-web": workload,
    },
    networks: {
      platform_routing: { internal: true },
      fixture_app_ingress: { internal: true },
    },
    secrets: {},
  };
  return { core, combined, lock: { workloads: [manifest] } };
}

function findCheck(policy, id) {
  const check = policy.checks.find((entry) => entry.id === id);
  assert.ok(check, `runtime policy check ${id} is missing`);
  return check;
}

function resolveVolumesFrom(combined, serviceName) {
  const service = combined.services?.[serviceName];
  assert.ok(service, `service ${serviceName} is missing`);
  const inherited = [];
  for (const rawReference of service.volumes_from ?? []) {
    assert.equal(typeof rawReference, "string", "fixture supports only string volumes_from entries");
    const match = rawReference.match(/^([a-z0-9][a-z0-9_-]*)(?::(ro|rw))?$/);
    assert.ok(match, `invalid volumes_from reference ${rawReference}`);
    const target = combined.services?.[match[1]];
    assert.ok(target, `unknown volumes_from service ${match[1]}`);
    const forcedReadOnly = match[2] === "ro";
    for (const mount of target.volumes ?? []) {
      inherited.push({ ...structuredClone(mount), read_only: forcedReadOnly || mount.read_only === true });
    }
  }
  return inherited;
}

function readThroughMount(mounts, containerPath) {
  const matching = mounts
    .filter((mount) => containerPath === mount.target || containerPath.startsWith(`${mount.target}/`))
    .sort((left, right) => right.target.length - left.target.length)[0];
  assert.ok(matching, `no inherited mount covers ${containerPath}`);
  const suffix = containerPath.slice(matching.target.length).replace(/^\//, "");
  const sourceRootPath = fs.realpathSync(matching.source);
  const hostPath = path.resolve(sourceRootPath, suffix);
  assert.ok(hostPath === sourceRootPath || hostPath.startsWith(`${sourceRootPath}${path.sep}`), "container read escaped the fixture mount");
  const stat = fs.lstatSync(hostPath);
  assert.equal(stat.isFile(), true, "fixture marker is not a regular file");
  assert.equal(stat.isSymbolicLink(), false, "fixture marker must not be a symbolic link");
  return fs.readFileSync(hostPath, "utf8").trim();
}

function fixedValidateRenderedWorkloads(candidateValidator, fixture) {
  const coreNames = new Set(Object.keys(fixture.core.services ?? {}));
  for (const [name, service] of Object.entries(fixture.combined.services ?? {})) {
    if (coreNames.has(name)) continue;
    for (const key of ["volumes_from", "extends"]) {
      if (Object.hasOwn(service, key)) {
        throw new Error(`service inheritance field ${key} is forbidden for ${name}`);
      }
    }
  }
  return candidateValidator({ core: fixture.core, combined: fixture.combined, lock: fixture.lock });
}

function sha256Bytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function sha256File(filePath) {
  return sha256Bytes(fs.readFileSync(filePath));
}

function claimOwnedFixture(targetPath, expectedParent, token) {
  assert.equal(path.dirname(targetPath), expectedParent, "fixture target escaped the wrapper root");
  if (fs.existsSync(targetPath)) {
    throw new Error(`refusing pre-existing fixture target: ${targetPath}`);
  }
  assert.match(path.basename(targetPath), /^fixture-[0-9a-f]{64}$/, "fixture name is not token-bound");
  fs.mkdirSync(targetPath, { recursive: false, mode: 0o700 });
  const targetStat = fs.lstatSync(targetPath);
  assert.equal(targetStat.isDirectory(), true, "claimed fixture target is not a directory");
  assert.equal(targetStat.isSymbolicLink(), false, "claimed fixture target is a symbolic link");
  assert.equal(fs.realpathSync(targetPath), targetPath, "claimed fixture target must be its physical path");
  const sentinelPath = path.join(targetPath, `.project-router-volumes-from-probe-owner-${token}`);
  fs.writeFileSync(sentinelPath, `project-router-volumes-from:${token}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  const sentinelStat = fs.lstatSync(sentinelPath);
  return {
    targetPath,
    targetDevice: targetStat.dev,
    targetInode: targetStat.ino,
    sentinelPath,
    sentinelDevice: sentinelStat.dev,
    sentinelInode: sentinelStat.ino,
    token,
  };
}

function cleanupOwnedFixture(ownership, expectedParent) {
  const targetStat = fs.lstatSync(ownership.targetPath);
  assert.equal(targetStat.isDirectory(), true, "cleanup target is not a directory");
  assert.equal(targetStat.isSymbolicLink(), false, "refusing cleanup through a target symbolic link");
  assert.equal(targetStat.dev, ownership.targetDevice, "refusing cleanup after target device substitution");
  assert.equal(targetStat.ino, ownership.targetInode, "refusing cleanup after target inode substitution");
  assert.equal(fs.realpathSync(ownership.targetPath), ownership.targetPath, "cleanup target is not its physical path");
  assert.equal(path.dirname(ownership.targetPath), expectedParent, "cleanup target escaped the wrapper root");

  const sentinelStat = fs.lstatSync(ownership.sentinelPath);
  assert.equal(sentinelStat.isFile(), true, "cleanup ownership sentinel is not a regular file");
  assert.equal(sentinelStat.isSymbolicLink(), false, "refusing cleanup through a sentinel symbolic link");
  assert.equal(sentinelStat.dev, ownership.sentinelDevice, "refusing cleanup after sentinel device substitution");
  assert.equal(sentinelStat.ino, ownership.sentinelInode, "refusing cleanup after sentinel inode substitution");
  assert.equal(
    fs.readFileSync(ownership.sentinelPath, "utf8"),
    `project-router-volumes-from:${ownership.token}\n`,
    "refusing cleanup without the fixture ownership token",
  );
  fs.rmSync(ownership.targetPath, { recursive: true, force: false });
}
