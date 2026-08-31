import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createBackupJobDocument } from "../control-center/backup/contracts.mjs";

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
    if (schedulerBlocks.length === 0) {
      assert.match(
        source,
        /backup-scheduler[^\n]*\n(?:[^\n]*\n){0,2}[^\n]*deploy-vps\.sh/i,
        `${name} must document the trusted scheduler activation path`,
      );
      assert.match(
        source,
        /compose-vps\.sh[^\n]*(?:render|ispezion)/i,
        `${name} must keep the Compose wrapper non-mutating`,
      );
      continue;
    }
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
  const overlays = canonicalComposeFiles(wrapper);

  assert.equal(overlays[0], "compose.yaml");
  assert.equal(overlays.at(-1), "compose.runtime-isolation.yaml");
  assert.ok(
    overlays.indexOf("compose.backup-scheduler.yaml") < overlays.indexOf("compose.runtime-isolation.yaml"),
    "scheduler declaration must precede the authoritative isolation overlay",
  );
  for (const overlay of overlays) {
    assert.ok(fs.statSync(path.join(root, overlay)).isFile(), `missing wrapper overlay ${overlay}`);
  }
});

test("FG-005 scheduler uses a dedicated digest-pinned image as explicit root 0:0", () => {
  const scheduler = serviceBlock(fs.readFileSync(path.join(root, "compose.backup-scheduler.yaml"), "utf8"), "backup-scheduler");

  assert.match(
    scheduler,
    /^\s{4}image:\s+\$\{PLATFORM_BACKUP_SCHEDULER_IMAGE_REPOSITORY:\?[^}]+\}@sha256:\$\{PLATFORM_BACKUP_SCHEDULER_IMAGE_SHA256:\?[^}]+\}\s*$/m,
  );
  assert.doesNotMatch(scheduler, /^\s{4}build:\s*$|PLATFORM_OPS_IMAGE|docker\/ops\.Dockerfile|docker-cli/im);
  assert.doesNotMatch(scheduler, /\/infra\/scripts\/backup-scheduler\.sh/);
  assert.equal(scalarProperty(scheduler, "user"), "0:0");
});

test("FG-005 dedicated scheduler image source contains no Docker tooling", () => {
  const dockerDir = path.join(root, "docker");
  const candidates = fs.readdirSync(dockerDir)
    .filter((name) => name.endsWith(".Dockerfile"))
    .map((name) => ({ name, source: fs.readFileSync(path.join(dockerDir, name), "utf8") }))
    .filter(({ source }) => dockerfileCopies(source, "scripts/backup-scheduler.sh"));
  assert.equal(
    candidates.length,
    1,
    `expected one image recipe that owns backup-scheduler.sh, found ${candidates.map(({ name }) => name).join(",") || "none"}`,
  );
  const instructions = dockerfileInstructions(candidates[0].source);
  assert.match(candidates[0].source, /^ARG NODE_IMAGE=[^\s]+@sha256:[a-f0-9]{64}\s*$/m);
  for (const source of [
    "scripts/backup-scheduler.sh",
    "scripts/backup-queue-control.mjs",
    "scripts/docker-action-client.mjs",
    "scripts/docker-action-contract.mjs",
    "control-center/backup/contracts.mjs",
    "control-center/backup/queue-admission.mjs",
    "control-center/backup/queue-operation-adapter.mjs",
  ]) {
    assert.ok(dockerfileCopies(candidates[0].source, source), `scheduler image is missing ${source}`);
  }
  assert.match(
    candidates[0].source,
    /^COPY --chmod=0444 scripts\/backup-queue-control\.mjs \/opt\/platform-backup-scheduler\/scripts\/backup-queue-control\.mjs$/m,
    "queue control must exist at the scheduler entrypoint's exact INFRA_ROOT path",
  );
  assert.match(
    candidates[0].source,
    /^COPY --chmod=0444 control-center\/backup\/contracts\.mjs control-center\/backup\/queue-admission\.mjs control-center\/backup\/queue-operation-adapter\.mjs \/opt\/platform-backup-scheduler\/control-center\/backup\/$/m,
    "queue control dependencies must preserve their repository-relative import graph",
  );
  assert.match(
    candidates[0].source,
    /^RUN chmod 0555 \/opt\/platform-backup-scheduler\/policy \\\n    && chmod 0444 \/opt\/platform-backup-scheduler\/policy\/local-private-backup-admission\.pub\.pem$/m,
    "the non-root scheduler must be able to traverse the public-key directory",
  );
  const executableSurface = instructions
    .filter(({ opcode }) => ["FROM", "RUN", "ENTRYPOINT", "CMD"].includes(opcode))
    .map(({ value }) => value)
    .join("\n");
  assert.doesNotMatch(executableSurface, /(?:^|[^a-z0-9_-])docker(?:-cli|-compose)?(?:[^a-z0-9_-]|$)/i);
});

test("FG-005 all six scheduler capabilities have local and managed materialization definitions", () => {
  const fileSecrets = fs.readFileSync(path.join(root, "compose.secrets.yaml"), "utf8");
  const managedSecrets = fs.readFileSync(path.join(root, "compose.managed-secrets.yaml"), "utf8");
  const secretManager = fs.readFileSync(path.join(root, "scripts", "infra-secret-manager.mjs"), "utf8");
  const infraOps = fs.readFileSync(path.join(root, "scripts", "infra-ops.mjs"), "utf8");

  for (const name of schedulerCapabilitySecrets) {
    assert.match(fileSecrets, new RegExp(`^  ${name}:\\n    file: \\./secrets/${name}\\.txt$`, "m"), name);
    assert.match(managedSecrets, new RegExp(`^  ${name}:\\n    external: true$`, "m"), name);
    assert.match(secretManager, new RegExp(`\\{ name: "${name}", kind: "opaque", bytes: 48, rotationDays: 90 \\}`), name);
    assert.ok(
      [...infraOps.matchAll(new RegExp(`"${name}"`, "g"))].length >= 2,
      `${name} must be covered by rotation metadata and local-secret validation`,
    );
  }
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

test("FG-005 scheduler mounts only its private queue, logs and broker UDS", () => {
  const scheduler = serviceBlock(fs.readFileSync(path.join(root, "compose.backup-scheduler.yaml"), "utf8"), "backup-scheduler");
  const mounts = shortVolumeEntries(scheduler)
    .sort((left, right) => left.target.localeCompare(right.target));
  assert.deepEqual(
    mounts,
    [
      {
        options: ["ro"],
        readOnly: true,
        source: "docker_action_broker_socket",
        target: "/run/platform/docker-action-broker",
      },
      {
        options: [],
        readOnly: false,
        source: "backup_scheduler_logs",
        target: "/var/log/platform",
      },
      {
        options: [],
        readOnly: false,
        source: "backup_scheduler_jobs",
        target: "/var/www/project-state/backup-jobs",
      },
    ],
    "scheduler mount source, target and options must be exact",
  );
});

test("FG-005 scheduler writable control files stay on bounded hardened tmpfs", () => {
  const scheduler = serviceBlock(fs.readFileSync(path.join(root, "compose.backup-scheduler.yaml"), "utf8"), "backup-scheduler");
  const entrypoint = fs.readFileSync(path.join(root, "scripts", "backup-scheduler.sh"), "utf8");
  const cronFile = mappingScalar(scheduler, "environment", "BACKUP_SCHEDULER_CRON_FILE");
  const envFile = mappingScalar(scheduler, "environment", "BACKUP_SCHEDULER_ENV_FILE");
  for (const [name, value] of [["cron", cronFile], ["environment", envFile]]) {
    assert.ok(
      value.startsWith("/run/platform/backup-scheduler/") && value !== "/run/platform/backup-scheduler/",
      `${name} control file must be below the private scheduler tmpfs`,
    );
  }
  const tmpfs = listEntries(scheduler, "tmpfs")
    .map(parseTmpfsEntry)
    .sort((left, right) => left.target.localeCompare(right.target));
  assert.deepEqual(tmpfs.map(({ target }) => target), ["/run/platform/backup-scheduler", "/tmp"]);
  for (const mount of tmpfs) {
    assert.deepEqual(
      mount.flags,
      ["nodev", "noexec", "nosuid", "rw"],
      `${mount.target} tmpfs flags widened`,
    );
    assert.ok(mount.sizeBytes >= 1024 * 1024 && mount.sizeBytes <= 128 * 1024 * 1024, `${mount.target} tmpfs size is unbounded`);
  }
  assert.match(
    entrypoint,
    /exec crond\b[^\n]*\s-c\s+"\$\(dirname\s+"\$CRON_FILE"\)"/,
    "crond must consume the relocated private tmpfs crontab directory",
  );
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

test("FG-005 execute-backup-job accepts only a claimed queue basename", () => {
  const accepted = runSchedulerWithFakeClient([
    "--run",
    "execute-backup-job",
    "--jobFileName",
    "backup-job-0123456789abcdef.json",
  ]);

  assert.equal(accepted.result.status, 0, `${accepted.result.stdout}\n${accepted.result.stderr}`);
  assert.deepEqual(accepted.clientArguments.slice(1), [
    "execute-backup-job",
    "--jobFileName",
    "backup-job-0123456789abcdef.json",
  ]);

  for (const args of [
    ["--jobId", "0123456789abcdef"],
    ["--jobOperation", "restore-drill"],
    ["--jobSha256", "a".repeat(64)],
    ["--jobFile", "/tmp/attacker.json"],
    ["--jobFileName", "../attacker.json"],
    ["--jobFileName", "/tmp/attacker.json"],
  ]) {
    const rejected = runSchedulerWithFakeClient(["--run", "execute-backup-job", ...args]);
    assert.notEqual(rejected.result.status, 0, `caller-controlled ${args[0]} reached the action client`);
    assert.deepEqual(rejected.clientArguments, [], `${args[0]} must be rejected before invoking the client`);
  }
});

test("LOCAL_PRIVATE scheduler admits catalog, typed jobs and offsite only", () => {
  for (const command of ["backup-platform-catalog", "offsite-backup-restic"]) {
    const accepted = runSchedulerWithFakeClient(["--run", command], {
      BACKUP_SCHEDULER_LOCAL_PRIVATE_FIXED_ACTIONS: "true",
    });
    assert.equal(accepted.result.status, 0, `${accepted.result.stdout}\n${accepted.result.stderr}`);
    assert.equal(accepted.clientArguments.at(-1), command);
  }
  for (const command of ["prune-manifest-backups-plan", "prune-manifest-backups-apply", "full-restore-drill"]) {
    const rejected = runSchedulerWithFakeClient(["--run", command], {
      BACKUP_SCHEDULER_LOCAL_PRIVATE_FIXED_ACTIONS: "true",
    });
    assert.notEqual(rejected.result.status, 0, command);
    assert.deepEqual(rejected.clientArguments, []);
  }
});

test("LOCAL_PRIVATE scheduler cron contains only catalog and the explicitly enabled offsite sync", () => {
  const enabled = renderLocalPrivateSchedulerCron(true);
  assert.match(enabled, /platform-catalog-backup/);
  assert.match(enabled, /backup-platform-catalog/);
  assert.match(enabled, /restic-offsite/);
  assert.match(enabled, /offsite-backup-restic/);
  assert.doesNotMatch(enabled, /prune-manifest|full-restore-drill/);
  assert.equal(enabled.trim().split("\n").length, 2);

  const disabled = renderLocalPrivateSchedulerCron(false);
  assert.match(disabled, /platform-catalog-backup/);
  assert.doesNotMatch(disabled, /restic-offsite|offsite-backup-restic|prune-manifest|full-restore-drill/);
  assert.equal(disabled.trim().split("\n").length, 1);
});

test("LOCAL_PRIVATE non-root scheduler owns its cron spool and uses its real account name", () => {
  const overlay = serviceBlock(
    fs.readFileSync(path.join(root, "compose.local-private-backup.yaml"), "utf8"),
    "backup-scheduler",
  );
  assert.equal(scalarProperty(overlay, "user"), "1000:1000");
  assert.match(
    overlay,
    /^\s{6}BACKUP_SCHEDULER_CRON_FILE: \/run\/platform\/backup-scheduler\/crontabs\/node$/m,
  );
  assert.match(
    overlay,
    /^\s{6}- \/run\/platform\/backup-scheduler:rw,noexec,nosuid,nodev,size=8m,uid=1000,gid=1000,mode=0700$/m,
  );
  assert.match(
    overlay,
    /test -s \/run\/platform\/backup-scheduler\/crontabs\/node/,
  );
  assert.match(
    overlay,
    /test -s \/run\/platform\/backup-scheduler\/local-private-timer\.ready/,
  );
});

test("LOCAL_PRIVATE scheduler executes a due backup through its unprivileged timer without crond", () => {
  const observed = runLocalPrivateTimerTick();
  assert.equal(observed.result.status, 99, `${observed.result.stdout}\n${observed.result.stderr}`);
  assert.deepEqual(
    observed.clientArguments,
    [path.join(root, "scripts", "docker-action-client.mjs"), "backup-platform-catalog"],
    `${observed.result.stdout}\n${observed.result.stderr}\n${observed.timerLog}`,
  );
  assert.equal(observed.timerReady, "platform.local-private-backup-timer/v1");
  assert.equal(observed.crondInvoked, false);
});

test("FG-005 the real queue consumer forwards only its atomically claimed filename", () => {
  const observed = runClaimedQueueWithFakeClient();
  assert.equal(observed.result.status, 0, `${observed.result.stdout}\n${observed.result.stderr}`);
  assert.deepEqual(observed.clientArguments, [
    path.join(root, "scripts", "docker-action-client.mjs"),
    "execute-backup-job",
    "--jobFileName",
    observed.fileName,
  ]);
  assert.equal(observed.clientInvocationCount, 1);
  assert.equal(observed.terminalJob.status, "done");
  assert.equal(observed.queuedExists, false);
  assert.equal(observed.runningExists, false);
});

test("FG-005 an unknown post-admission outcome remains running for manual reconciliation without retry", () => {
  const observed = runClaimedQueueWithFakeClient({
    clientExitCode: 74,
    expectedStatus: "running",
    expectedSummary: "manual-reconciliation",
  });

  assert.equal(observed.result.status, 0, `${observed.result.stdout}\n${observed.result.stderr}`);
  assert.deepEqual(observed.clientArguments, [
    path.join(root, "scripts", "docker-action-client.mjs"),
    "execute-backup-job",
    "--jobFileName",
    observed.fileName,
  ]);
  assert.equal(observed.clientInvocationCount, 1);
  assert.equal(observed.terminalJob.status, "running");
  assert.equal(observed.terminalJob.exitCode, 74);
  assert.match(observed.terminalJob.resultSummary, /manual-reconciliation/i);
  assert.equal(Object.hasOwn(observed.terminalJob, "logPath"), false);
  assert.equal(observed.queuedExists, false);
  assert.equal(observed.runningExists, true);
  assert.equal(observed.doneExists, false);
  assert.equal(observed.failedExists, false);
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
    const [mountSource = "", target = "", options = ""] = splitComposeMount(entry);
    const parsedOptions = options ? options.split(",").sort() : [];
    return {
      source: mountSource,
      target,
      options: parsedOptions,
      readOnly: parsedOptions.includes("ro"),
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

function dockerfileCopies(source, repositoryPath) {
  return dockerfileInstructions(source)
    .filter(({ opcode }) => ["COPY", "ADD"].includes(opcode))
    .some(({ value }) => value.split(/\s+/).includes(repositoryPath));
}

function dockerfileInstructions(source) {
  const logicalLines = [];
  let current = "";
  for (const rawLine of source.replaceAll("\r\n", "\n").split("\n")) {
    const line = rawLine.trim();
    if (!current && (!line || line.startsWith("#"))) continue;
    current += `${current ? " " : ""}${line.replace(/\\\s*$/, "")}`;
    if (/\\\s*$/.test(line)) continue;
    const match = current.match(/^([A-Za-z]+)\s+(.+)$/);
    assert.ok(match, `unsupported Dockerfile instruction: ${current}`);
    logicalLines.push({ opcode: match[1].toUpperCase(), value: match[2].trim() });
    current = "";
  }
  assert.equal(current, "", "unterminated Dockerfile continuation");
  return logicalLines;
}

function canonicalComposeFiles(wrapper) {
  const blocks = [...wrapper.matchAll(/(?:^|\n)\s*compose\+=\(\s*\n([\s\S]*?)\n\s*\)/g)]
    .map((match) => match[1])
    .filter((body) => /(?:^|\n)\s*-f\s+/.test(body));
  assert.equal(blocks.length, 1, "compose-vps.sh must contain one literal canonical overlay block");
  const tokens = blocks[0].trim().split(/\s+/);
  const overlays = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index] === "-p") {
      assert.equal(tokens[++index], '"$PROJECT_NAME"', "canonical project name argument changed");
      continue;
    }
    assert.equal(tokens[index], "-f", `unsupported canonical overlay token ${tokens[index]}`);
    const file = tokens[++index];
    assert.ok(file && !file.includes("$") && !path.isAbsolute(file), `unsupported canonical overlay path ${file}`);
    overlays.push(file);
  }
  return overlays;
}

function scalarProperty(source, name) {
  const match = source.match(new RegExp(`^    ${name}:\\s*(.+?)\\s*$`, "m"));
  assert.ok(match, `missing ${name}`);
  const value = match[1].trim();
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}

function mappingScalar(source, mapping, name) {
  const block = source.match(new RegExp(`^    ${mapping}:\\s*\\n((?:(?: {6,}).*(?:\\n|$))*)`, "m"));
  assert.ok(block, `missing ${mapping}`);
  const property = block[1].match(new RegExp(`^      ${name}:\\s*(.+?)\\s*$`, "m"));
  assert.ok(property, `missing ${mapping}.${name}`);
  return property[1].replace(/^(['"])(.*)\1$/, "$2");
}

function parseTmpfsEntry(entry) {
  const [target, ...options] = entry.split(":");
  assert.ok(target.startsWith("/"), `tmpfs target must be absolute: ${target}`);
  assert.equal(options.length, 1, `tmpfs must have one explicit option list: ${entry}`);
  const parts = options[0].split(",");
  const size = parts.find((part) => part.startsWith("size="));
  assert.ok(size, `tmpfs size is required: ${entry}`);
  const match = size.match(/^size=(\d+)([kmg])$/i);
  assert.ok(match, `unsupported tmpfs size: ${size}`);
  const multiplier = { k: 1024, m: 1024 ** 2, g: 1024 ** 3 }[match[2].toLowerCase()];
  return {
    flags: parts.filter((part) => !part.startsWith("size=")).sort(),
    sizeBytes: Number(match[1]) * multiplier,
    target,
  };
}

function runSchedulerWithFakeClient(arguments_, environment = {}) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "scheduler-client-contract-"));
  const bin = path.join(temporary, "bin");
  const capture = path.join(temporary, "client-arguments.json");
  fs.mkdirSync(bin);
  const fakeNode = path.join(bin, "node");
  fs.writeFileSync(
    fakeNode,
    "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SCHEDULER_CLIENT_CAPTURE\"\n",
    { mode: 0o700 },
  );
  const result = spawnSync("/bin/sh", [path.join(root, "scripts", "backup-scheduler.sh"), ...arguments_], {
    cwd: root,
    encoding: "utf8",
    env: {
      HOME: temporary,
      PATH: bin,
      PLATFORM_INFRA_ROOT: root,
      SCHEDULER_CLIENT_CAPTURE: capture,
      ...environment,
    },
    timeout: 10_000,
  });
  const clientArguments = fs.existsSync(capture)
    ? fs.readFileSync(capture, "utf8").trimEnd().split("\n").filter(Boolean)
    : [];
  fs.rmSync(temporary, { recursive: true, force: true });
  return { result, clientArguments };
}

function renderLocalPrivateSchedulerCron(enableOffsite) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "scheduler-local-private-cron-"));
  const cronFile = path.join(temporary, "runtime", "crontabs", "node");
  const result = spawnSync("/bin/sh", [path.join(root, "scripts", "backup-scheduler.sh")], {
    cwd: root,
    encoding: "utf8",
    env: {
      BACKUP_SCHEDULER_CRON_FILE: cronFile,
      BACKUP_SCHEDULER_DRY_RUN: "true",
      BACKUP_SCHEDULER_ENABLE_OFFSITE: enableOffsite ? "true" : "false",
      BACKUP_SCHEDULER_ENV_FILE: path.join(temporary, "runtime", "backup-scheduler.env"),
      BACKUP_SCHEDULER_JOBS_DIR: path.join(temporary, "jobs"),
      BACKUP_SCHEDULER_LOCAL_PRIVATE_FIXED_ACTIONS: "true",
      BACKUP_SCHEDULER_LOG_DIR: path.join(temporary, "logs"),
      HOME: temporary,
      PATH: process.env.PATH,
      PLATFORM_INFRA_ROOT: root,
    },
    timeout: 10_000,
  });
  try {
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    return fs.readFileSync(cronFile, "utf8");
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

function runClaimedQueueWithFakeClient({
  clientExitCode = 0,
  expectedStatus = "done",
  expectedSummary = "",
} = {}) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "scheduler-claimed-queue-"));
  const bin = path.join(temporary, "bin");
  const jobs = path.join(temporary, "jobs");
  const logs = path.join(temporary, "logs");
  const runtime = path.join(temporary, "runtime");
  const capture = path.join(temporary, "client-arguments.txt");
  const callCapture = path.join(temporary, "client-invocations.txt");
  const fileName = "0123456789abcdef.json";
  const queued = path.join(jobs, "queued", fileName);
  const running = path.join(jobs, "running", fileName);
  const done = path.join(jobs, "done", fileName);
  const failed = path.join(jobs, "failed", fileName);
  const terminal = path.join(jobs, expectedStatus, fileName);
  fs.mkdirSync(path.dirname(queued), { recursive: true });
  fs.mkdirSync(bin);
  fs.writeFileSync(queued, `${JSON.stringify(createBackupJobDocument({
    id: "0123456789abcdef",
    operation: "backup",
    scope: { kind: "platform" },
    resources: [{
      kind: "platform-state",
      externalId: "control-state",
      name: "control-state",
    }],
    requestedBy: "owner@example.test",
    environment: "test",
    createdAt: "2026-07-21T00:00:00.000Z",
  }))}\n`, { mode: 0o600 });

  for (const command of [
    "basename",
    "cat",
    "chmod",
    "date",
    "dirname",
    "find",
    "grep",
    "head",
    "mkdir",
    "mv",
    "sed",
    "sort",
  ]) {
    fs.symlinkSync(findSystemExecutable(command), path.join(bin, command));
  }

  const fakeNode = path.join(bin, "node");
  fs.writeFileSync(
    fakeNode,
    `#!/bin/sh
if [ "\${1:-}" = "$SCHEDULER_EXPECTED_CLIENT" ]; then
  printf 'call\\n' >> "$SCHEDULER_CLIENT_CALL_CAPTURE"
  printf '%s\\n' "$@" > "$SCHEDULER_CLIENT_CAPTURE"
  exit "$SCHEDULER_CLIENT_EXIT_CODE"
fi
exec ${shellQuote(process.execPath)} "$@"
`,
    { mode: 0o700 },
  );
  fs.writeFileSync(path.join(bin, "sleep"), "#!/bin/sh\nexit 99\n", { mode: 0o700 });
  fs.writeFileSync(
    path.join(bin, "crond"),
    `#!/bin/sh
attempt=0
while [ "$attempt" -lt 500 ]; do
  if [ -f "$SCHEDULER_EXPECTED_TERMINAL" ]; then
    if [ -z "$SCHEDULER_EXPECTED_SUMMARY" ] || grep -q "$SCHEDULER_EXPECTED_SUMMARY" "$SCHEDULER_EXPECTED_TERMINAL"; then
      exit 0
    fi
  fi
  /bin/sleep 0.01
  attempt=$((attempt + 1))
done
exit 70
`,
    { mode: 0o700 },
  );

  const result = spawnSync("/bin/sh", [path.join(root, "scripts", "backup-scheduler.sh")], {
    cwd: root,
    encoding: "utf8",
    env: {
      BACKUP_SCHEDULER_CRON_FILE: path.join(runtime, "crontabs", "root"),
      BACKUP_SCHEDULER_ENABLE_OFFSITE: "false",
      BACKUP_SCHEDULER_ENABLE_RETENTION_APPLY: "false",
      BACKUP_SCHEDULER_ENV_FILE: path.join(runtime, "backup-scheduler.env"),
      BACKUP_SCHEDULER_JOBS_DIR: jobs,
      BACKUP_SCHEDULER_LOG_DIR: logs,
      BACKUP_SCHEDULER_QUEUE_POLL_SECONDS: "1",
      DOCKER_ACTION_ACTIVE_RECEIPT_SHA256: "a".repeat(64),
      DOCKER_ACTION_BROKER_SOCKET: "/run/platform/docker-action-broker/broker.sock",
      DOCKER_ACTION_COMBINED_RENDER_SHA256: "b".repeat(64),
      DOCKER_ACTION_RUNTIME_INTENT_ID: "intent.release-test",
      HOME: temporary,
      PATH: bin,
      PLATFORM_INFRA_ROOT: root,
      SCHEDULER_CLIENT_CAPTURE: capture,
      SCHEDULER_CLIENT_CALL_CAPTURE: callCapture,
      SCHEDULER_CLIENT_EXIT_CODE: String(clientExitCode),
      SCHEDULER_EXPECTED_CLIENT: path.join(root, "scripts", "docker-action-client.mjs"),
      SCHEDULER_EXPECTED_SUMMARY: expectedSummary,
      SCHEDULER_EXPECTED_TERMINAL: terminal,
    },
    timeout: 10_000,
  });
  const clientArguments = fs.existsSync(capture)
    ? fs.readFileSync(capture, "utf8").trimEnd().split("\n").filter(Boolean)
    : [];
  const clientInvocationCount = fs.existsSync(callCapture)
    ? fs.readFileSync(callCapture, "utf8").trimEnd().split("\n").filter(Boolean).length
    : 0;
  const terminalJob = fs.existsSync(terminal) ? JSON.parse(fs.readFileSync(terminal, "utf8")) : {};
  const observed = {
    clientArguments,
    clientInvocationCount,
    doneExists: fs.existsSync(done),
    failedExists: fs.existsSync(failed),
    fileName,
    queuedExists: fs.existsSync(queued),
    result,
    runningExists: fs.existsSync(running),
    terminalJob,
  };
  fs.rmSync(temporary, { recursive: true, force: true });
  return observed;
}

function runLocalPrivateTimerTick() {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "scheduler-local-private-timer-"));
  const bin = path.join(temporary, "bin");
  const runtime = path.join(temporary, "runtime");
  const capture = path.join(temporary, "client-arguments.txt");
  const crondCapture = path.join(temporary, "crond-invoked");
  fs.mkdirSync(bin);
  for (const command of ["cat", "chmod", "dirname", "mkdir", "sed", "sh"]) {
    fs.symlinkSync(findSystemExecutable(command), path.join(bin, command));
  }
  fs.writeFileSync(
    path.join(bin, "date"),
    `#!/bin/sh
last=""
for argument in "$@"; do last="$argument"; done
case "$last" in
  +%Y%m%d%H%M) printf '202608311205\\n' ;;
  +%M) printf '05\\n' ;;
  +%H) printf '12\\n' ;;
  *) printf '2026-08-31T12:05:00Z\\n' ;;
esac
`,
    { mode: 0o700 },
  );
  fs.writeFileSync(
    path.join(bin, "node"),
    `#!/bin/sh
if [ "\${1:-}" = "$SCHEDULER_EXPECTED_QUEUE_CONTROL" ]; then
  exit 0
fi
printf '%s\\n' "$@" > "$SCHEDULER_CLIENT_CAPTURE"
`,
    { mode: 0o700 },
  );
  fs.writeFileSync(path.join(bin, "sleep"), "#!/bin/sh\nexit 99\n", { mode: 0o700 });
  fs.writeFileSync(
    path.join(bin, "crond"),
    "#!/bin/sh\n: > \"$SCHEDULER_CROND_CAPTURE\"\nexit 70\n",
    { mode: 0o700 },
  );

  const timerReadyFile = path.join(runtime, "local-private-timer.ready");
  const result = spawnSync("/bin/sh", [path.join(root, "scripts", "backup-scheduler.sh")], {
    cwd: root,
    encoding: "utf8",
    env: {
      BACKUP_SCHEDULER_CATALOG_CRON: "5 * * * *",
      BACKUP_SCHEDULER_CRON_FILE: path.join(runtime, "crontabs", "node"),
      BACKUP_SCHEDULER_ENABLE_OFFSITE: "false",
      BACKUP_SCHEDULER_ENV_FILE: path.join(runtime, "backup-scheduler.env"),
      BACKUP_SCHEDULER_JOBS_DIR: path.join(temporary, "jobs"),
      BACKUP_SCHEDULER_LOCAL_PRIVATE_FIXED_ACTIONS: "true",
      BACKUP_SCHEDULER_LOG_DIR: path.join(temporary, "logs"),
      BACKUP_SCHEDULER_TIMER_READY_FILE: timerReadyFile,
      HOME: temporary,
      PATH: bin,
      PLATFORM_INFRA_ROOT: root,
      SCHEDULER_CLIENT_CAPTURE: capture,
      SCHEDULER_CROND_CAPTURE: crondCapture,
      SCHEDULER_EXPECTED_QUEUE_CONTROL: path.join(root, "scripts", "backup-queue-control.mjs"),
    },
    timeout: 10_000,
  });
  const observed = {
    clientArguments: fs.existsSync(capture)
      ? fs.readFileSync(capture, "utf8").trimEnd().split("\n").filter(Boolean)
      : [],
    crondInvoked: fs.existsSync(crondCapture),
    result,
    timerLog: fs.existsSync(path.join(temporary, "logs", "platform-catalog-backup.log"))
      ? fs.readFileSync(path.join(temporary, "logs", "platform-catalog-backup.log"), "utf8")
      : "",
    timerReady: fs.existsSync(timerReadyFile) ? fs.readFileSync(timerReadyFile, "utf8").trim() : "",
  };
  fs.rmSync(temporary, { recursive: true, force: true });
  return observed;
}

function findSystemExecutable(command) {
  for (const directory of ["/bin", "/usr/bin"]) {
    const candidate = path.join(directory, command);
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new Error(`required local test utility not found: ${command}`);
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}
