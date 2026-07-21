import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("FG-005 documents only the isolation-aware scheduler entrypoint", () => {
  for (const name of ["README.md", "RUNBOOK.md"]) {
    const source = fs.readFileSync(path.join(root, name), "utf8");
    const schedulerBlocks = documentedSchedulerComposeBlocks(source);
    assert.ok(schedulerBlocks.length > 0, `${name} must document scheduler startup`);
    for (const block of schedulerBlocks) {
      if (!/(?:^|\n)\s*(?:docker logs|docker exec)\b/.test(block) || /(?:^|\n)\s*(?:docker compose|docker-compose)\b/.test(block)) {
        assert.match(block, /COMPOSE_ENV_FILE=.*COMPOSE_PROJECT_NAME=.*\\?\n?\s*bash \.\/scripts\/compose-vps\.sh up -d backup-scheduler/);
      }
      assert.doesNotMatch(block, /(?:^|\n)\s*(?:docker compose|docker-compose)\b/);
    }
  }
});

test("FG-005 scanner includes every Compose command block that cites backup-scheduler", () => {
  const injected = "```sh\ndocker compose up --wait backup-scheduler\n```\n";
  assert.equal(documentedSchedulerComposeBlocks(injected).length, 1);
});

test("FG-005 wrapper and scheduler retain the complete isolation boundary", () => {
  const wrapper = fs.readFileSync(path.join(root, "scripts", "compose-vps.sh"), "utf8");
  for (const overlay of [
    "compose.yaml",
    "compose.secrets.yaml",
    "compose.waf.yaml",
    "compose.vps.yaml",
    "compose.vps-waf.yaml",
    "compose.backup-scheduler.yaml",
    "compose.runtime.yaml",
    "compose.networks.yaml",
    "compose.runtime-isolation.yaml",
  ]) assert.match(wrapper, new RegExp(`-f ${overlay.replaceAll(".", "\\.")}`));

  const scheduler = serviceBlock(fs.readFileSync(path.join(root, "compose.backup-scheduler.yaml"), "utf8"), "backup-scheduler");
  assert.match(scheduler, /- \.:\/infra:ro/);
  assert.match(scheduler, /PLATFORM_DOCKER_GATEWAY_URL: http:\/\/docker-operation-gateway:8787/);
  assert.doesNotMatch(scheduler, /\/var\/run\/docker\.sock|DOCKER_HOST|:\/infra(?:\s|$)/m);
  assert.match(scheduler, /- platform_docker_control/);
});

function serviceBlock(source, name) {
  const marker = `\n  ${name}:\n`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing service ${name}`);
  const rest = source.slice(start + marker.length);
  const end = rest.search(/\n  [a-zA-Z0-9][a-zA-Z0-9_-]*:\n/);
  return end === -1 ? rest : rest.slice(0, end);
}

function documentedSchedulerComposeBlocks(source) {
  return [...source.matchAll(/^\s{0,3}```(?:sh|bash|shell|zsh|console)\s*\r?\n([\s\S]*?)^\s{0,3}```\s*$/gim)]
    .map((match) => match[1])
    .filter((block) => /\bbackup-scheduler\b/.test(block)
      && /(?:^|\n)\s*(?:\$\s*)?(?:(?:docker\s+compose|docker-compose)\b|(?:bash|sh)\s+\.\/scripts\/compose-vps\.sh\b)/m.test(block));
}
