import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schedulerCapabilitySecrets = [
  "docker_action_backup_catalog",
  "docker_action_backup_job_execute",
  "docker_action_backup_prune_plan",
  "docker_action_backup_prune_apply",
  "docker_action_restore_drill_full",
  "docker_action_backup_offsite_sync",
];

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

test("FG-005 wrapper retains the complete ordered Compose boundary", () => {
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
});

test("FG-005 scheduler uses a dedicated digest-pinned image without a build or Docker CLI", () => {
  const scheduler = serviceBlock(fs.readFileSync(path.join(root, "compose.backup-scheduler.yaml"), "utf8"), "backup-scheduler");

  assert.match(
    scheduler,
    /^\s{4}image:\s+\$\{PLATFORM_BACKUP_SCHEDULER_IMAGE_REPOSITORY:\?[^}]+\}@sha256:\$\{PLATFORM_BACKUP_SCHEDULER_IMAGE_SHA256:\?[^}]+\}\s*$/m,
  );
  assert.doesNotMatch(scheduler, /^\s{4}build:\s*$|PLATFORM_OPS_IMAGE|docker\/ops\.Dockerfile|docker-cli/im);
  assert.doesNotMatch(scheduler, /\/infra\/scripts\/backup-scheduler\.sh/);
});

test("FG-005 dedicated scheduler image source contains no Docker tooling", () => {
  const dockerDir = path.join(root, "docker");
  const candidates = fs.readdirSync(dockerDir)
    .filter((name) => /backup.*scheduler.*\.Dockerfile$/i.test(name));
  assert.equal(candidates.length, 1, `expected one dedicated backup scheduler Dockerfile, found ${candidates.join(",") || "none"}`);
  const dockerfile = fs.readFileSync(path.join(dockerDir, candidates[0]), "utf8");
  assert.doesNotMatch(dockerfile, /\bdocker-cli(?:-compose)?\b|(?:^|\s)docker(?:\s|$)/m);
});

test("FG-005 scheduler is read-only, Linux-capability-free and host-private", () => {
  const scheduler = serviceBlock(fs.readFileSync(path.join(root, "compose.backup-scheduler.yaml"), "utf8"), "backup-scheduler");

  assert.match(scheduler, /^\s{4}read_only:\s*true\s*$/m);
  assert.match(scheduler, /^\s{4}cap_drop:\s*\n\s{6}-\s*ALL\s*$/m);
  assert.doesNotMatch(scheduler, /^\s{4}cap_add:\s*$/m);
  assert.match(scheduler, /^\s{4}network_mode:\s*none\s*$/m);
  assert.doesNotMatch(scheduler, /^\s{4}networks:\s*$|platform_egress|platform_db_admin|platform_storage/m);
});

test("FG-005 scheduler has no repository, source, storage or offsite credential environment", () => {
  const scheduler = serviceBlock(fs.readFileSync(path.join(root, "compose.backup-scheduler.yaml"), "utf8"), "backup-scheduler");
  assert.doesNotMatch(
    scheduler,
    /\b(?:PLATFORM_INFRA_(?:ROOT|CONTAINER_ROOT|HOST_ROOT)|PROJECT_(?:SOURCE_ROOT|SOURCE_HOST_ROOT|STATE_ROOT|DATABASES_FILE)|NODE_IMAGE|BACKUP_SIGNING_KEYS_FILE|RESTIC_[A-Z0-9_]+|RCLONE_CONFIG|KEYCLOAK_DB_NAME|BACKUP_LOCAL_KEEP_LAST|AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY))\s*:/,
  );
});

test("FG-005 scheduler mounts only its queue, logs and broker UDS", () => {
  const scheduler = serviceBlock(fs.readFileSync(path.join(root, "compose.backup-scheduler.yaml"), "utf8"), "backup-scheduler");
  const mounts = shortVolumeEntries(scheduler);
  const allowed = mounts.filter(({ target }) => target === "/var/log/platform"
    || target === "/run/platform/docker-action-broker"
    || /(?:backup-jobs|backup-scheduler\/queue)$/.test(target));

  assert.deepEqual(
    mounts,
    allowed,
    `scheduler mount allowlist widened: ${mounts.map(({ source, target }) => `${source}->${target}`).join(",")}`,
  );
  assert.equal(mounts.filter(({ target }) => /(?:backup-jobs|backup-scheduler\/queue)$/.test(target)).length, 1, "one exact queue mount is required");
  assert.equal(mounts.filter(({ target }) => target === "/var/log/platform").length, 1, "one exact log mount is required");
  assert.equal(mounts.filter(({ target }) => target === "/run/platform/docker-action-broker").length, 1, "one exact broker UDS mount is required");
  assert.doesNotMatch(
    scheduler,
    /(?:^|\n)\s*-\s+(?:\.|\.\.\/|\$\{PROJECT_SOURCE_DIR|\.\/backups|\.\/reports|\.\/projects-portal\/state|\.\/secrets)(?:[:/]|$)|:\/(?:infra(?:\/|:|\s*$)|project(?:[:/]|$)|var\/www\/project-state(?::|\s*$)|run\/secrets(?:[:/]|$))/m,
  );
});

test("FG-005 scheduler writable paths stay on exact tmpfs and never under /etc", () => {
  const scheduler = serviceBlock(fs.readFileSync(path.join(root, "compose.backup-scheduler.yaml"), "utf8"), "backup-scheduler");
  assert.doesNotMatch(scheduler, /\/etc(?:\/|\b)/, "read-only scheduler must not write crontab, env or health state under /etc");
  assert.match(scheduler, /BACKUP_SCHEDULER_CRON_FILE:\s*\/run\/platform\/backup-scheduler\/[^\s]+/);
  assert.match(scheduler, /BACKUP_SCHEDULER_ENV_FILE:\s*\/run\/platform\/backup-scheduler\/[^\s]+/);
  assert.match(scheduler, /^\s{4}tmpfs:\s*$/m);
  const tmpfsTargets = listEntries(scheduler, "tmpfs").map((entry) => entry.split(":")[0]).sort();
  assert.deepEqual(tmpfsTargets, ["/run/platform/backup-scheduler", "/tmp"]);
});

test("FG-005 scheduler owns exactly six backup capabilities and no evidence snapshot capability", () => {
  const scheduler = serviceBlock(fs.readFileSync(path.join(root, "compose.backup-scheduler.yaml"), "utf8"), "backup-scheduler");
  const sources = [...scheduler.matchAll(/^\s{6}-\s+source:\s*([a-z0-9_]+)\s*$/gm)]
    .map((match) => match[1])
    .sort();

  assert.deepEqual(sources, [...schedulerCapabilitySecrets].sort());
  assert.doesNotMatch(scheduler, /docker_action_evidence_runtime_snapshot/);
  assert.match(scheduler, /DOCKER_ACTION_BROKER_SOCKET: \/run\/platform\/docker-action-broker\/broker\.sock/);
  assert.match(scheduler, /DOCKER_ACTION_RUNTIME_INTENT_ID:/);
  assert.match(scheduler, /DOCKER_ACTION_ACTIVE_RECEIPT_SHA256:/);
  assert.match(scheduler, /DOCKER_ACTION_COMBINED_RENDER_SHA256:/);
  assert.match(scheduler, /docker_action_broker_socket:\/run\/platform\/docker-action-broker:ro/);
  assert.doesNotMatch(scheduler, /\/var\/run\/docker\.sock|DOCKER_HOST/);
  assert.doesNotMatch(scheduler, /docker-action-trust|tcp:\/\/|237[56]|:8787/);
});

function serviceBlock(source, name) {
  const marker = `\n  ${name}:\n`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing service ${name}`);
  const rest = source.slice(start + marker.length);
  const end = rest.search(/\n(?:  )?[a-zA-Z0-9][a-zA-Z0-9_-]*:\n/);
  return end === -1 ? rest : rest.slice(0, end);
}

function documentedSchedulerComposeBlocks(source) {
  return [...source.matchAll(/^\s{0,3}```(?:sh|bash|shell|zsh|console)\s*\r?\n([\s\S]*?)^\s{0,3}```\s*$/gim)]
    .map((match) => match[1])
    .filter((block) => /\bbackup-scheduler\b/.test(block)
      && /(?:^|\n)\s*(?:\$\s*)?(?:(?:docker\s+compose|docker-compose)\b|(?:bash|sh)\s+\.\/scripts\/compose-vps\.sh\b)/m.test(block));
}

function shortVolumeEntries(source) {
  return listEntries(source, "volumes").map((entry) => {
    const [mountSource = "", target = ""] = splitComposeMount(entry);
    return {
      source: mountSource,
      target,
    };
  });
}

function listEntries(source, name) {
  const match = source.match(new RegExp(`^    ${name}:.*\\n((?:(?: {6,}).*(?:\\n|$))*)`, "m"));
  assert.ok(match, `missing ${name}`);
  return [...match[1].matchAll(/^      -\s+(.+?)\s*$/gm)].map((item) => item[1]);
}

function splitComposeMount(value) {
  const parts = [];
  let start = 0;
  let braces = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === "$" && value[index + 1] === "{") {
      braces += 1;
      index += 1;
      continue;
    }
    if (value[index] === "}" && braces > 0) {
      braces -= 1;
      continue;
    }
    if (value[index] === ":" && braces === 0) {
      parts.push(value.slice(start, index));
      start = index + 1;
    }
  }
  parts.push(value.slice(start));
  return parts;
}
