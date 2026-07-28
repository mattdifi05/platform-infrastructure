import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, "..");

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

test("the raw Docker socket belongs only to an immutable, host-private action broker", () => {
  const compose = read("compose.runtime-isolation.yaml");
  const deployment = read("compose.backup-scheduler.yaml");
  const wrapper = read("scripts/infra-ops.sh");
  const brokerBlock = compose.split("\n  docker-action-broker:\n")[1].split("\n  traefik:\n")[0];

  assert.match(compose, /^\s{2}docker-action-broker:\s*$/m);
  assert.doesNotMatch(`${compose}\n${deployment}`, /docker-operation-gateway|237[56]|AUTH\s*=\s*0|tcp:\/\/|:8787/);
  assert.match(compose, /network_mode:\s*none/);
  assert.match(deployment, /\$\{PLATFORM_DOCKER_ACTION_BROKER_IMAGE_REPOSITORY:\?[^}]+\}@sha256:\$\{PLATFORM_DOCKER_ACTION_BROKER_IMAGE_SHA256:\?[^}]+\}/);
  assert.doesNotMatch(brokerBlock, /-\s+\.\s*:\/infra(?::ro)?/);
  assert.equal((brokerBlock.match(/\/var\/run\/docker\.sock:\/var\/run\/docker\.sock/g) ?? []).length, 1);

  assert.doesNotMatch(wrapper, /(?:^|\s)docker(?:\s|$)/m);
  assert.doesNotMatch(wrapper, /DOCKER_HOST|docker\.sock|PLATFORM_DOCKER_SOCKET|raw mode/i);
  assert.match(wrapper, /docker-action-client\.mjs/);
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
  assert.match(broker, /platform\.docker-action\.request\/v1/);
  assert.match(broker, /platform\.docker-runtime-intent\/v1/);
  assert.match(broker, /platform\.docker-active-receipt\/v1/);
  assert.match(read("policy/docker-action-activation-policy.json"), /"status":"external-pending"/);
});
