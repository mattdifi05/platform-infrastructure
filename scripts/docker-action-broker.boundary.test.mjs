import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, "..");
const dockerSocketPath = "/var/run/docker.sock";
const vpsComposeFiles = [
  "compose.yaml",
  "compose.secrets.yaml",
  "compose.waf.yaml",
  "compose.vps.yaml",
  "compose.vps-waf.yaml",
  "compose.backup-scheduler.yaml",
  "compose.runtime.yaml",
  "compose.networks.yaml",
  "compose.runtime-isolation.yaml",
];

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

test("the raw Docker socket belongs only to an immutable, host-private action broker", () => {
  const compose = read("compose.runtime-isolation.yaml");
  const deployment = read("compose.backup-scheduler.yaml");
  const brokerBlock = compose.split("\n  docker-action-broker:\n")[1].split("\n  traefik:\n")[0];

  assert.match(compose, /^\s{2}docker-action-broker:\s*$/m);
  assert.doesNotMatch(`${compose}\n${deployment}`, /docker-operation-gateway|237[56]|AUTH\s*=\s*0|tcp:\/\/|:8787/);
  assert.match(compose, /network_mode:\s*none/);
  assert.match(deployment, /\$\{PLATFORM_DOCKER_ACTION_BROKER_IMAGE_REPOSITORY:\?[^}]+\}@sha256:\$\{PLATFORM_DOCKER_ACTION_BROKER_IMAGE_SHA256:\?[^}]+\}/);
  assert.doesNotMatch(brokerBlock, /-\s+\.\s*:\/infra(?::ro)?/);
  assert.equal((brokerBlock.match(/\/var\/run\/docker\.sock:\/var\/run\/docker\.sock/g) ?? []).length, 1);
});

test("the effective full VPS Compose mount set has exactly one raw Docker authority", () => {
  const services = effectiveComposeServices(vpsComposeFiles);
  const volumeDevices = effectiveComposeVolumeDevices(vpsComposeFiles);
  const owners = [...services.entries()]
    .filter(([, service]) => service.volumes.some((mount) => exposesDockerSocket(mount.source)
      || exposesDockerSocket(volumeDevices.get(mount.source))))
    .map(([name]) => name)
    .sort();

  assert.deepEqual(
    owners,
    ["docker-action-broker"],
    `raw Docker socket owners include bind ancestors or aliases: ${owners.join(",") || "none"}`,
  );
  assert.ok(
    !(services.get("cadvisor")?.volumes ?? []).some((mount) => exposesDockerSocket(mount.source)
      || exposesDockerSocket(volumeDevices.get(mount.source))),
    "cAdvisor must not be a false second owner through /, /run or /var/run",
  );
});

test("the broker process and immutable code are explicitly root-owned", () => {
  const deployment = read("compose.backup-scheduler.yaml");
  const brokerBlock = serviceBlock(deployment, "docker-action-broker");
  const dockerfile = read("docker/docker-action-broker.Dockerfile");
  const broker = read("scripts/docker-action-broker.mjs");

  assert.match(brokerBlock, /^\s{4}user:\s*["']0:0["']\s*$/m, "broker Compose identity must be explicit 0:0");
  assert.match(dockerfile, /chown\s+-R\s+root:root\s+\/opt\/platform-docker-broker\s+\/opt\/platform-docker-worker/);
  assert.match(broker, /expectedUid\s*=\s*0/);
  assert.match(broker, /expectedGid\s*=\s*0/);
});

test("broker readiness validates the trusted activation context, not socket existence alone", () => {
  for (const name of ["compose.backup-scheduler.yaml", "compose.runtime-isolation.yaml"]) {
    const brokerBlock = serviceBlock(read(name), "docker-action-broker");
    const healthcheck = propertyBlock(brokerBlock, "healthcheck");
    assert.match(
      healthcheck,
      /(?:readiness|ready|health).*(?:activation|receipt|trust)|(?:activation|receipt|trust).*(?:readiness|ready|health)/is,
      `${name} broker healthcheck must validate trusted intent, receipt and activation state`,
    );
    assert.doesNotMatch(
      healthcheck,
      /fs\.statSync\([^)]*broker\.sock[^)]*\)\.isSocket\(\)/,
      `${name} broker healthcheck must not trust broker.sock existence alone`,
    );
  }
});

test("the immutable broker image owns its code and exposes no generic Docker-shaped API", () => {
  const dockerfile = read("docker/docker-action-broker.Dockerfile");
  const broker = `${read("scripts/docker-action-broker.mjs")}\n${read("scripts/docker-action-contract.mjs")}\n${read("scripts/docker-action-worker.mjs")}`;

  assert.match(dockerfile, /COPY\s+scripts\/docker-action-broker\.mjs\s+/);
  assert.match(dockerfile, /COPY\s+scripts\/docker-action-worker\.mjs\s+/);
  assert.doesNotMatch(dockerfile, /infra-ops\.(?:mjs|sh)|docker(?:\s|-)cli/);
  assert.doesNotMatch(broker, /infra-ops\.(?:mjs|sh)|spawn(?:Sync)?\(|DOCKER_HOST/);
  assert.doesNotMatch(broker, /\b(?:sudo|tar)\b|archive[-_ ]?extract|child_process/);
  assert.doesNotMatch(broker, /createServer\([^)]*\)\.listen\([^)]*,\s*["']0\.0\.0\.0|\/v\d+(?:\.\d+)?\/containers|\/exec|\/images|\/networks|\/volumes/);
  assert.match(broker, /platform\.docker-action\.request\/v2/);
  assert.match(broker, /platform\.docker-runtime-intent\/v1/);
  assert.match(broker, /platform\.docker-active-receipt\/v2/);
  assert.match(read("policy/docker-action-activation-policy.json"), /"status":"external-pending"/);
});

test("infra-ops.sh remains the executable general host orchestrator", () => {
  const wrapperPath = path.join(root, "scripts", "infra-ops.sh");
  const wrapper = fs.readFileSync(wrapperPath, "utf8");
  const mode = fs.statSync(wrapperPath).mode & 0o777;

  assert.equal(mode, 0o755, `scripts/infra-ops.sh mode must remain 0755, got 0${mode.toString(8)}`);
  assert.match(wrapper, /infra-ops\.mjs/);
  assert.doesNotMatch(wrapper, /docker-action-client\.mjs|<fixed-action>/);
});

test("the container boundary does not globally disable Docker in the host orchestrator", () => {
  const hostOrchestrator = read("scripts/infra-ops.mjs");

  assert.match(hostOrchestrator, /\brun\(["']docker["']/);
  assert.doesNotMatch(
    hostOrchestrator,
    /Raw Docker execution from candidate infra code is disabled|path\.basename\(String\(bin\)\)\s*===\s*["']docker["']/,
    "host infra-ops may orchestrate Docker; only scheduler and worker consumers must use fixed broker actions",
  );
});

function effectiveComposeServices(files) {
  const services = new Map();
  for (const file of files) {
    for (const [name, block] of serviceBlocks(read(file))) {
      const current = services.get(name) ?? { volumes: [] };
      const parsed = parseServiceVolumes(block);
      if (!parsed) {
        services.set(name, current);
        continue;
      }
      if (parsed.mode === "reset" || parsed.mode === "override") current.volumes = [];
      for (const mount of parsed.volumes) {
        const prior = current.volumes.findIndex((item) => item.target === mount.target);
        if (prior === -1) current.volumes.push(mount);
        else current.volumes[prior] = mount;
      }
      services.set(name, current);
    }
  }
  return services;
}

function effectiveComposeVolumeDevices(files) {
  const devices = new Map();
  for (const file of files) {
    for (const [name, block] of topLevelSectionBlocks(read(file), "volumes")) {
      const device = block.match(/^\s{4,}device:\s*(.+?)\s*$/m)?.[1];
      if (device) devices.set(name, unquote(device));
    }
  }
  return devices;
}

function serviceBlocks(source) {
  return topLevelSectionBlocks(source, "services");
}

function topLevelSectionBlocks(source, section) {
  const sectionMarker = source.match(new RegExp(`^${section}:\\s*$`, "m"));
  if (!sectionMarker) return [];
  const bodyStart = sectionMarker.index + sectionMarker[0].length;
  const rest = source.slice(bodyStart);
  const nextTopLevel = rest.search(/^(?!\s|#)[A-Za-z0-9][A-Za-z0-9_-]*:\s*$/m);
  const body = nextTopLevel === -1 ? rest : rest.slice(0, nextTopLevel);
  const markers = [...body.matchAll(/^  ([A-Za-z0-9][A-Za-z0-9_-]*):[^\n]*\n/gm)];
  return markers.map((marker, index) => [
    marker[1],
    body.slice(marker.index + marker[0].length, markers[index + 1]?.index ?? body.length),
  ]);
}

function parseServiceVolumes(block) {
  const match = block.match(/^    volumes:(.*)\n((?:(?: {6,}).*(?:\n|$))*)/m);
  if (!match) return null;
  const declaration = match[1];
  if (/!reset\s*\[\s*\]/.test(declaration)) return { mode: "reset", volumes: [] };
  const mode = /!override/.test(declaration) ? "override" : "merge";
  const lines = match[2].split("\n");
  const volumes = [];
  for (let index = 0; index < lines.length; index += 1) {
    const short = lines[index].match(/^      -\s+(.+?)\s*$/);
    if (!short) continue;
    const value = unquote(short[1]);
    if (!/^(?:type|source|target):\s*/.test(value)) {
      const separator = value.indexOf(":");
      const secondSeparator = value.indexOf(":", separator + 1);
      if (separator > 0) {
        volumes.push({
          source: value.slice(0, separator),
          target: value.slice(separator + 1, secondSeparator === -1 ? undefined : secondSeparator),
        });
      }
      continue;
    }
    const item = [value];
    while (index + 1 < lines.length && /^ {8,}\S/.test(lines[index + 1])) item.push(lines[++index].trim());
    const source = item.find((line) => line.startsWith("source:"))?.slice("source:".length).trim();
    const target = item.find((line) => line.startsWith("target:"))?.slice("target:".length).trim();
    if (source && target) volumes.push({ source: unquote(source), target: unquote(target) });
  }
  return { mode, volumes };
}

function exposesDockerSocket(source) {
  if (!String(source).startsWith("/")) return false;
  const observed = path.posix.normalize(source);
  const normalized = observed === "/run" || observed.startsWith("/run/")
    ? `/var${observed}`
    : observed;
  return normalized === dockerSocketPath || dockerSocketPath.startsWith(`${normalized.replace(/\/$/, "")}/`);
}

function serviceBlock(source, name) {
  const marker = `\n  ${name}:\n`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing service ${name}`);
  const rest = source.slice(start + marker.length);
  const end = rest.search(/\n  [a-zA-Z0-9][a-zA-Z0-9_-]*:\n/);
  return end === -1 ? rest : rest.slice(0, end);
}

function propertyBlock(source, name) {
  const match = source.match(new RegExp(`^    ${name}:.*\\n((?:(?: {6,}).*(?:\\n|$))*)`, "m"));
  assert.ok(match, `missing ${name}`);
  return `${name}:${match[1]}`;
}

function unquote(value) {
  const clean = String(value).trim();
  if ((clean.startsWith('"') && clean.endsWith('"')) || (clean.startsWith("'") && clean.endsWith("'"))) {
    return clean.slice(1, -1);
  }
  return clean;
}
