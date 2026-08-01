#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const EXPECTED_HASHES = new Map([
  ["scripts/hosted-workload-contract.mjs", "5ef4ab7427d942cdb4c254ee6d612cbec1dd6cac65034f4790bd2d6c56b5ec47"],
  ["scripts/hosted-workload-contract.test.mjs", "a5a92058fe2378695ce43af1067683d873cb7367eff0d98664cc0ff0fa3dde41"],
  ["scripts/prepare-hosted-workloads.sh", "c22f5890ab69273447a75eb5044f910126064b825359710800252569895e57c2"],
  ["scripts/compose-vps.sh", "09647e58df4e1b5c9f60de1c6ce2e6ebf800c658617ef40bd399d705def9c713"],
]);

const SOURCE_VARIABLE = "PLATFORM_RECOVERY_MATERIAL";
const RAW_REFERENCE = `\${${SOURCE_VARIABLE}}`;
const BENIGN_DESTINATION = "DISPLAY_THEME";
const SYNTHETIC_VALUE = "synthetic-provenance-sentinel-7f2b9e5d";

const sourceRoot = path.resolve(process.argv[2] ?? "");
if (!process.argv[2] || !fs.statSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error("usage: hosted-interpolation-provenance-probe.mjs /path/to/archived/source");
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expected, `${relativePath} is not the expected vulnerable source`);
}
console.log("[+] verified 4 embedded vulnerable-source hashes");

const contractPath = path.join(sourceRoot, "scripts/hosted-workload-contract.mjs");
const contractSource = fs.readFileSync(contractPath, "utf8");
const prepareSource = fs.readFileSync(path.join(sourceRoot, "scripts/prepare-hosted-workloads.sh"), "utf8");
const composeVpsSource = fs.readFileSync(path.join(sourceRoot, "scripts/compose-vps.sh"), "utf8");
const testSource = fs.readFileSync(path.join(sourceRoot, "scripts/hosted-workload-contract.test.mjs"), "utf8");

const environmentTextValidator = sliceBetween(
  contractSource,
  "export function validateWorkloadEnvironmentText(",
  "function workloadEnvironmentRecord(",
);
const renderedEnvironmentValidator = sliceBetween(
  contractSource,
  "function assertEnvironmentSecrets(",
  "function assertSecrets(",
);
assert.match(environmentTextValidator, /\\\$\\\{\[\^}\]\+\\\}/);
assert.match(renderedEnvironmentValidator, /PASSWORD\|TOKEN\|SECRET\|DATABASE_URL\|NATS_URL/);
assert.doesNotMatch(renderedEnvironmentValidator, /interpol|provenance|sourceVariable/i);
assert.ok(contractSource.includes('fileRecord(composePath, "workload-compose")'));
assert.ok(prepareSource.includes('bash "$SCRIPT_DIR/compose-vps.sh" config --format json > "$combined_render"'));
assert.ok(prepareSource.indexOf('config --format json > "$combined_render"') < prepareSource.indexOf('scripts/hosted-workload-contract.mjs verify-render'));
assert.ok(composeVpsSource.includes('--env-file "$ENV_FILE"'));
assert.ok(composeVpsSource.includes('compose+=(--env-file "$workload_env_file")'));
assert.ok(composeVpsSource.includes('compose+=(-f "$workload_file")'));
assert.ok(composeVpsSource.includes('exec "${compose[@]}" --profile backup "$@"'));
assert.doesNotMatch(testSource, /PLATFORM_RECOVERY_MATERIAL|DISPLAY_THEME|interpolation provenance/i);
console.log("[+] static flow=raw workload Compose -> core/host interpolation -> rendered-only validation -> Compose execution");

const contract = await import(pathToFileURL(contractPath).href);
const { core, combined, lock } = validFixture(contract.validateWorkloadManifest);

assert.deepEqual(
  contract.validateWorkloadEnvironmentText("EXAMPLE_APP_DISPLAY_THEME=light\n", "example-app"),
  ["EXAMPLE_APP_DISPLAY_THEME"],
);
console.log("[+] literal workload-prefixed environment control=ACCEPTED");

assert.throws(
  () => contract.validateWorkloadEnvironmentText(`EXAMPLE_APP_DISPLAY_THEME=${RAW_REFERENCE}\n`, "example-app"),
  /unsupported interpolation/,
);
console.log("[+] raw workload-environment interpolation control=REJECTED");

const renderedValue = renderDirectReference(RAW_REFERENCE, { [SOURCE_VARIABLE]: SYNTHETIC_VALUE });
assert.equal(renderedValue, SYNTHETIC_VALUE);
combined.services["example-app-web"].environment[BENIGN_DESTINATION] = renderedValue;
assert.doesNotMatch(JSON.stringify(combined), new RegExp(SOURCE_VARIABLE));
const validation = contract.validateRenderedWorkloads({ core, combined, lock });
assert.deepEqual(validation.routes, [{
  workloadId: "example-app",
  slug: "example",
  service: "example-app-web",
  port: 3000,
  upstream: "http://example-app-web:3000",
}]);
console.log(`[VULNERABLE] source_reference=${RAW_REFERENCE} destination=${BENIGN_DESTINATION} rendered_sha256=${sha256Text(renderedValue)} validator=ACCEPTED`);

const control = structuredClone(combined);
delete control.services["example-app-web"].environment[BENIGN_DESTINATION];
control.services["example-app-web"].environment.API_TOKEN = renderedValue;
assert.throws(
  () => contract.validateRenderedWorkloads({ core, combined: control, lock }),
  /sensitive environment variable API_TOKEN/,
);
console.log("[+] rendered sensitive-destination control=REJECTED");

console.log("[+] no deployment interpolation variable, env file, Compose engine, Docker daemon, socket, network, or live service was accessed");
console.log("[+] result=VULNERABLE");

function renderDirectReference(reference, environment) {
  const match = /^\$\{([A-Z][A-Z0-9_]*)\}$/.exec(reference);
  assert.ok(match, "fixture must use one direct Compose-style variable reference");
  assert.ok(Object.hasOwn(environment, match[1]), "synthetic render environment is missing the referenced variable");
  return environment[match[1]];
}

function sha256Text(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function validFixture(validateWorkloadManifest) {
  const digest = "a".repeat(64);
  const manifest = validateWorkloadManifest({
    version: 1,
    id: "example-app",
    composeFile: "compose.platform.yaml",
    services: [{ name: "example-app-web", role: "web", routes: [{ slug: "example", port: 3000 }] }],
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
    environment: {},
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
  const combined = {
    services: {
      "project-router": {
        ...structuredClone(core.services["project-router"]),
        networks: { platform_routing: null, example_app_ingress: null },
      },
      "example-app-web": structuredClone(baseService),
    },
    networks: {
      platform_routing: { internal: true },
      example_app_ingress: { internal: true },
    },
  };
  return { core, combined, lock: { workloads: [manifest] } };
}

function sliceBetween(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  assert.ok(end > start, `invalid source marker order: ${startMarker}`);
  return source.slice(start, end);
}
