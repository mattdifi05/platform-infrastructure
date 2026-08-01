#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const EXPECTED_SOURCE_HASHES = new Map([
  ["compose.yaml", "ed630eee1be8350142493307c2647aa98ce67324c93c127a9370a19a24a9d6c7"],
  ["nats/nats-server.conf", "37df49c652875d9ba19a0c5ed5a7446efeed34ce6a7f2f924a724dba446c8a14"],
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/hosted-workload-contract.test.mjs", "a5a92058fe2378695ce43af1067683d873cb7367eff0d98664cc0ff0fa3dde41"],
  ["scripts/network-segmentation-policy.mjs", "bc21ac9f6b01630925743dd9f226a07476f45aa56fc9c174edce38fd65312636"],
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["SERVICE-IDENTITY-AND-TENANCY.md", "d14c9bfcd10febff867d06ed4f9500913df3f01eb43fe5a7861346ee5ded3779"],
]);

function fail(message) {
  throw new Error(message);
}

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function snapshotTree(root) {
  const digest = crypto.createHash("sha256");

  function visit(current, relative) {
    const stat = fs.lstatSync(current);
    if (stat.isDirectory()) {
      digest.update(`directory\0${relative}\0${stat.mode & 0o7777}\0`);
      for (const name of fs.readdirSync(current).sort()) {
        visit(path.join(current, name), relative ? `${relative}/${name}` : name);
      }
      return;
    }
    if (stat.isFile()) {
      const data = fs.readFileSync(current);
      digest.update(`file\0${relative}\0${stat.mode & 0o7777}\0${data.length}\0`);
      digest.update(data);
      digest.update("\0");
      return;
    }
    if (stat.isSymbolicLink()) {
      digest.update(`symlink\0${relative}\0${fs.readlinkSync(current)}\0`);
      return;
    }
    fail(`unsupported archived source entry: ${relative}`);
  }

  visit(root, "");
  return digest.digest("hex");
}

function verifyBoundary(sourceArgument) {
  const wrapperRootInput = process.env.FG055_WRAPPER_TEMP_ROOT;
  const sentinelInput = process.env.FG055_OWNERSHIP_SENTINEL;
  const token = process.env.FG055_OWNERSHIP_TOKEN;
  if (!wrapperRootInput || !sentinelInput || !token) {
    fail("wrapper ownership environment is required; direct invocation is refused");
  }
  if (!/^[A-Za-z0-9]+$/.test(token)) fail("ownership token has invalid syntax");

  const wrapperRoot = path.resolve(wrapperRootInput);
  const source = path.resolve(sourceArgument);
  const sentinel = path.resolve(sentinelInput);
  const rootStat = fs.lstatSync(wrapperRoot);
  const sourceStat = fs.lstatSync(source);
  const sentinelStat = fs.lstatSync(sentinel);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail("wrapper root must be a real directory");
  if (!sourceStat.isDirectory() || sourceStat.isSymbolicLink()) fail("source must be a real directory");
  if (!sentinelStat.isFile() || sentinelStat.isSymbolicLink()) fail("ownership sentinel must be a regular file");

  const realRoot = fs.realpathSync(wrapperRoot);
  const realSource = fs.realpathSync(source);
  const realSentinel = fs.realpathSync(sentinel);
  if (realSource !== path.join(realRoot, "source")) fail("source is not the wrapper-owned source child");
  if (path.dirname(realSentinel) !== realRoot) fail("ownership sentinel is outside the wrapper root");
  if (path.basename(realSentinel) !== `.fg055-owner.${token}`) {
    fail("ownership token does not match sentinel name");
  }
  if (fs.readFileSync(realSentinel, "utf8") !== `FG055-OWNER:${token}\n`) {
    fail("ownership sentinel content is invalid");
  }
  return realSource;
}

function readSource(sourceRoot, relative) {
  const file = path.join(sourceRoot, relative);
  const data = fs.readFileSync(file);
  const expected = EXPECTED_SOURCE_HASHES.get(relative);
  assert.equal(sha256(data), expected, `unexpected archived source hash for ${relative}`);
  return data.toString("utf8");
}

function count(text, expression) {
  return [...text.matchAll(expression)].length;
}

function verifySourceShape(sourceRoot) {
  const compose = readSource(sourceRoot, "compose.yaml");
  const natsConfig = readSource(sourceRoot, "nats/nats-server.conf");
  const contract = readSource(sourceRoot, "scripts/hosted-workload-contract.mjs");
  const contractTest = readSource(sourceRoot, "scripts/hosted-workload-contract.test.mjs");
  const networkPolicy = readSource(sourceRoot, "scripts/network-segmentation-policy.mjs");
  const prepare = readSource(sourceRoot, "scripts/prepare-hosted-workloads.sh");
  const identityContract = readSource(sourceRoot, "SERVICE-IDENTITY-AND-TENANCY.md");

  const natsStart = compose.indexOf("\n  nats:");
  const natsEnd = compose.indexOf("\n  minio:", natsStart);
  assert.ok(natsStart >= 0 && natsEnd > natsStart, "NATS Compose service is missing");
  const natsService = compose.slice(natsStart, natsEnd);
  assert.equal(count(natsService, /--user\b/g), 1, "NATS must expose exactly one global --user flag");
  assert.equal(count(natsService, /--pass\b/g), 1, "NATS must expose exactly one global --pass flag");
  assert.match(natsService, /NATS_PASSWORD=.*NATS_PASSWORD_FILE/);
  assert.match(natsService, /exec nats-server -c \/etc\/nats\/nats-server\.conf --user/);

  assert.match(natsConfig, /^jetstream\s*\{/m, "JetStream configuration is missing");
  assert.doesNotMatch(natsConfig, /^\s*(?:authorization|accounts|system_account)\b/m);
  assert.doesNotMatch(natsConfig, /\b(?:users|permissions)\s*[:={]/m);

  assert.match(contract, /\["nats", new Set\(\["bus"\]\)\]/);
  assert.match(contract, /PLATFORM_NETWORK_EXTENSION_ZONES\.get\(name\)\?\.has\(zone\)/);
  assert.match(contract, /validateRenderedWorkloads/);
  assert.match(contractTest, /example_app_bus/);
  assert.doesNotMatch(contractTest, /subject permissions|system_account|cross-workload NATS/i);
  assert.match(networkPolicy, /\["bus", "nats"\]/);
  assert.match(networkPolicy, /workload-zone-core-/);
  assert.match(prepare, /HOSTED_WORKLOAD_LOCK="\$resolved"/);
  assert.match(prepare, /verify-render/);
  assert.match(identityContract, /one credential and one least-privilege role\s+per workload service/);

  return {
    contractPath: path.join(sourceRoot, "scripts/hosted-workload-contract.mjs"),
    authorizationModel: {
      globalUsers: 1,
      accounts: 0,
      permissionMaps: 0,
      systemAccount: false,
    },
  };
}

function workloadNetwork(id) {
  return `${id.replaceAll("-", "_")}_bus`;
}

function manifestFor(validateWorkloadManifest, id) {
  return validateWorkloadManifest({
    version: 1,
    id,
    composeFile: "compose.platform.yaml",
    secrets: [`${id}-nats-url`],
    services: [{ name: `${id}-worker`, role: "worker" }],
  });
}

function serviceFor(id, digest) {
  const secret = `${id}-nats-url`;
  return {
    image: `registry.example/${id}/worker@sha256:${digest}`,
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
    networks: { [workloadNetwork(id)]: null },
    depends_on: { nats: { condition: "service_healthy" } },
    secrets: [{ source: secret, target: secret }],
    environment: { NATS_URL_FILE: `/run/secrets/${secret}` },
    labels: {
      "com.platform.workload-id": id,
      "com.platform.workload-role": "worker",
    },
  };
}

function createTwoWorkloadFixture(validateWorkloadManifest) {
  const digest = "a".repeat(64);
  const ids = ["alpha-app", "beta-app"];
  const workloads = ids.map((id) => manifestFor(validateWorkloadManifest, id));
  const nats = {
    image: `registry.example/platform/nats@sha256:${digest}`,
    networks: { platform_bus: null },
  };
  const core = {
    services: { nats },
    networks: { platform_bus: { internal: true } },
  };
  const combinedNats = structuredClone(nats);
  for (const id of ids) combinedNats.networks[workloadNetwork(id)] = null;
  const combined = {
    services: {
      nats: combinedNats,
      "alpha-app-worker": serviceFor("alpha-app", digest),
      "beta-app-worker": serviceFor("beta-app", digest),
    },
    networks: {
      platform_bus: { internal: true },
      alpha_app_bus: { internal: true },
      beta_app_bus: { internal: true },
    },
    secrets: {
      "alpha-app-nats-url": { external: true },
      "beta-app-nats-url": { external: true },
    },
  };
  return { ids, core, combined, lock: { workloads } };
}

function sourcePolicyDecision(model, operation, subject) {
  assert.match(operation, /^(?:publish|subscribe)$/);
  assert.ok(typeof subject === "string" && subject.length > 0);
  const unrestrictedGlobalUser = model.globalUsers === 1
    && model.accounts === 0
    && model.permissionMaps === 0;
  return unrestrictedGlobalUser ? "allowed" : "denied";
}

async function main() {
  if (process.argv.length !== 3) fail("usage: nats-workload-authorization-probe.mjs ARCHIVED_SOURCE");
  const sourceRoot = verifyBoundary(process.argv[2]);
  process.stdout.write("[+] wrapper-owned source boundary verified\n");
  const before = snapshotTree(sourceRoot);
  const { contractPath, authorizationModel } = verifySourceShape(sourceRoot);
  process.stdout.write("[+] verified 7 archived source hashes and NATS authorization source shape\n");
  process.stdout.write("[+] verified NATS global_users=1 password_source=file accounts=0 permissions=0 jetstream=enabled\n");
  process.stdout.write("[+] verified workload policy maps every admitted bus zone to the shared NATS service\n");

  const moduleUrl = `${pathToFileURL(contractPath).href}?revision=${REVISION}&tree=${TREE}`;
  const { validateRenderedWorkloads, validateWorkloadManifest } = await import(moduleUrl);
  assert.equal(typeof validateRenderedWorkloads, "function");
  assert.equal(typeof validateWorkloadManifest, "function");

  const fixture = createTwoWorkloadFixture(validateWorkloadManifest);
  const result = validateRenderedWorkloads(fixture);
  assert.deepEqual(result.routes, []);
  assert.deepEqual(Object.keys(fixture.combined.services.nats.networks).sort(), [
    "alpha_app_bus",
    "beta_app_bus",
    "platform_bus",
  ]);
  process.stdout.write("[+] admission workloads=2 isolated_bus_networks=2 shared_brokers=1 result=accepted\n");

  assert.equal(sourcePolicyDecision(authorizationModel, "publish", "alpha.events.created"), "allowed");
  assert.equal(sourcePolicyDecision(authorizationModel, "subscribe", "beta.events.>"), "allowed");
  assert.equal(sourcePolicyDecision(authorizationModel, "publish", "beta.jobs.execute"), "allowed");
  assert.equal(sourcePolicyDecision(authorizationModel, "publish", "$JS.API.STREAM.DELETE.BETA"), "allowed");
  process.stdout.write("[BASELINE] own publish=alpha.events.created subscribe=alpha.events.> source_policy=allowed\n");
  process.stdout.write("[VULNERABLE] cross-subscribe actor=alpha target=beta.events.> source_policy=allowed\n");
  process.stdout.write("[VULNERABLE] cross-publish actor=alpha target=beta.jobs.execute source_policy=allowed\n");
  process.stdout.write("[VULNERABLE] jetstream-admin actor=alpha target=$JS.API.STREAM.DELETE.BETA source_policy=allowed runtime_effect=not-executed\n");
  process.stdout.write("[BOUNDARY] system-subject actor=alpha target=$SYS.> explicit_deny=absent runtime_events=not-asserted\n");

  const after = snapshotTree(sourceRoot);
  assert.equal(after, before, "archived source tree changed during the probe");
  process.stdout.write("[+] summary cross_workload_denials_missing=3 system_subject_deny_missing=true source_tree_unchanged=true\n");
  process.stdout.write("[+] external credential values and active tenancy were not inspected or asserted\n");
  process.stdout.write("[+] no NATS, Docker, Compose, daemon, container, network, credential, SSH, or live target was accessed\n");
}

main().catch((error) => {
  process.stderr.write(`error: ${error.message}\n`);
  process.exitCode = 1;
});
