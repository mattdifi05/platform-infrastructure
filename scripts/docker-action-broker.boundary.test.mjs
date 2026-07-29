import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, "..");
const dockerSocketPath = "/var/run/docker.sock";

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

test("the static Compose model is derived from the canonical compose-vps.sh order", () => {
  const files = canonicalComposeFiles(read("scripts/compose-vps.sh"));

  assert.ok(files.length > 1, "compose-vps.sh must provide a non-empty ordered overlay set");
  assert.equal(files[0], "compose.yaml");
  assert.ok(files.includes("compose.backup-scheduler.yaml"));
  assert.equal(files.at(-1), "compose.runtime-isolation.yaml");
  for (const file of files) {
    assert.ok(fs.statSync(path.join(root, file)).isFile(), `canonical Compose overlay is missing: ${file}`);
  }
});

test("the fail-closed static model handles short, long, override, reset and named host aliases", () => {
  const model = effectiveComposeModel([
    {
      label: "base.yaml",
      source: `services:
  shorty:
    volumes:
      - /var/run:/host/run:ro
  longy:
    volumes:
      - type: bind
        source: /run/docker.sock
        target: /host/docker.sock
        read_only: true
  aliasy:
    volumes:
      - host_runtime:/host/runtime:ro
volumes:
  host_runtime:
    driver: local
    driver_opts:
      type: none
      o: bind,ro
      device: /var/run
`,
    },
    {
      label: "last.yaml",
      source: `services:
  shorty:
    volumes: !override
      - type: volume
        source: safe_data
        target: /host/run
        read_only: true
  longy:
    volumes: !reset []
volumes:
  safe_data:
`,
    },
  ]);

  assert.deepEqual(
    rawSocketOwners(model),
    ["aliasy"],
    "override/reset must remove inherited authorities while a named-volume host alias remains visible",
  );
  assert.deepEqual(model.services.get("shorty").volumes, [{
    type: "volume",
    source: "safe_data",
    target: "/host/run",
    readOnly: true,
  }]);
  assert.deepEqual(model.services.get("longy").volumes, []);
  assert.equal(model.volumes.get("host_runtime").device, "/var/run");
});

test("the static model expands mount sources, follows volumes_from and resolves explicit volume aliases", () => {
  const model = effectiveComposeModel([
    {
      label: "expanded.yaml",
      source: `services:
  env-owner:
    volumes:
      - \${SOCKET_PARENT}:/host/runtime:ro
  default-owner:
    volumes:
      - \${UNSET_SOCKET_PARENT:-/run}:/host/default-runtime:ro
  inherited-owner:
    volumes_from:
      - env-owner:ro
  named-consumer:
    volumes:
      - project_runtime:/runtime:ro
volumes:
  project_runtime:
    name: \${COMPOSE_PROJECT_NAME}_runtime
  external_runtime:
    external: true
`,
    },
  ], {
    environment: {
      COMPOSE_PROJECT_NAME: "platform_infra_vps",
      SOCKET_PARENT: "/var/run",
    },
  });

  assert.deepEqual(rawSocketOwners(model), ["default-owner", "env-owner", "inherited-owner"]);
  assert.equal(model.volumes.get("project_runtime").name, "platform_infra_vps_runtime");
  assert.equal(model.volumes.get("external_runtime").external, "true");
  assert.equal(effectiveVolumeName(model, "project_runtime"), "platform_infra_vps_runtime");
  assert.throws(() => effectiveVolumeName(model, "external_runtime"), /is external/);
  assert.throws(
    () => exactPrivateVolumeName(model, "project_runtime"),
    /must not define external, name, driver or driver_opts aliases/,
  );
  assert.throws(
    () => exactPrivateVolumeName(model, "external_runtime"),
    /must not define external, name, driver or driver_opts aliases/,
  );

  const unresolved = effectiveComposeModel([{
    label: "unresolved.yaml",
    source: "services:\n  observer:\n    volumes:\n      - ${UNSET_SOCKET_PARENT}:/host/runtime:ro\n",
  }]);
  assert.throws(() => rawSocketOwners(unresolved), /unresolved Compose variable UNSET_SOCKET_PARENT/);

  assert.throws(
    () => effectiveComposeModel([{
      label: "external-volumes-from.yaml",
      source: "services:\n  observer:\n    volumes_from:\n      - container:untrusted-runtime:ro\n",
    }]),
    /unsupported external volumes_from/i,
  );
});

test("the static model rejects Compose volume constructs it cannot prove safe", () => {
  for (const [label, source] of [
    ["inline sequence", "services:\n  app:\n    volumes: [/var/run:/host/run:ro]\n"],
    ["inline mapping", "services:\n  app:\n    volumes:\n      - { type: bind, source: /var/run, target: /host/run }\n"],
    ["missing long target", "services:\n  app:\n    volumes:\n      - type: bind\n        source: /var/run\n"],
    ["unknown tag", "services:\n  app:\n    volumes: !replace\n      - /var/run:/host/run:ro\n"],
  ]) {
    assert.throws(
      () => effectiveComposeModel([{ label: `${label}.yaml`, source }]),
      /unsupported|requires both source and target/i,
      `${label} must fail closed`,
    );
  }
});

test("the effective canonical VPS render has one raw Docker authority", () => {
  const model = canonicalComposeModel();
  const owners = rawSocketOwners(model);

  assert.deepEqual(
    owners,
    ["docker-action-broker"],
    `raw Docker socket owners include bind parents or named-volume aliases: ${owners.join(",") || "none"}`,
  );
  for (const metricsService of ["cadvisor", "node-exporter"]) {
    assert.ok(model.services.has(metricsService), `${metricsService} service disappeared instead of being de-privileged`);
    assert.equal(
      serviceOwnsRawSocket(model, metricsService),
      false,
      `${metricsService} must not regain Docker authority through /, /run, /var/run or a named-volume alias`,
    );
  }
});

test.todo("Package A/B runtime metrics continuity after removing cAdvisor/node-exporter host parents (NOT_RUN)");

test("broker and scheduler share only the root-owned claimed-job queue boundary", () => {
  const model = canonicalComposeModel();
  const owners = [...model.services.entries()]
    .filter(([, service]) => service.volumes.some((mount) => mount.source === "backup_scheduler_jobs"))
    .map(([name, service]) => ({
      name,
      mounts: service.volumes.filter((mount) => mount.source === "backup_scheduler_jobs"),
    }))
    .sort((left, right) => left.name.localeCompare(right.name));

  assert.equal(
    exactPrivateVolumeName(model, "backup_scheduler_jobs"),
    "platform_infra_vps_backup_scheduler_jobs",
    "claimed-job queue identity must be the exact project-private effective volume",
  );
  assert.deepEqual(
    owners,
    [
      {
        name: "backup-scheduler",
        mounts: [{
          type: "volume",
          source: "backup_scheduler_jobs",
          target: "/var/www/project-state/backup-jobs",
          readOnly: false,
        }],
      },
      {
        name: "docker-action-broker",
        mounts: [{
          type: "volume",
          source: "backup_scheduler_jobs",
          target: "/run/platform/backup-jobs",
          readOnly: true,
        }],
      },
    ],
    "scheduler claims queue entries read-write; broker stable-reads the same private volume read-only",
  );
});

test("broker readiness rejects incoherent trusted activation state, not merely a present UDS", async () => {
  const broker = canonicalComposeModel().services.get("docker-action-broker");
  assert.deepEqual(
    broker?.healthcheckTest,
    [
      "CMD",
      "node",
      "/opt/platform-docker-broker/docker-action-readiness.mjs",
      "--require-trusted-activation",
    ],
    "the effective last-overlay healthcheck must invoke the behavioral readiness module with no optional bypass",
  );

  const modulePath = path.join(root, "scripts", "docker-action-readiness.mjs");
  assert.ok(fs.existsSync(modulePath), "missing behaviorally testable broker readiness module");
  assert.equal(
    dockerfileCopyTarget(
      read("docker/docker-action-broker.Dockerfile"),
      "scripts/docker-action-readiness.mjs",
    ),
    "/opt/platform-docker-broker/docker-action-readiness.mjs",
    "the healthcheck command must address the exact immutable module copied into the broker image",
  );
  const readiness = await import(`${pathToFileURL(modulePath).href}?test=${Date.now()}`);
  assert.equal(typeof readiness.evaluateBrokerReadiness, "function");

  const trusted = trustedReadinessInput();
  assert.deepEqual(readiness.evaluateBrokerReadiness(trusted), { ready: true, failures: [] });

  for (const [name, mutate] of [
    ["socket type", (value) => { value.socket.isSocket = false; }],
    ["intent trust", (value) => { value.runtimeIntent.trusted = false; }],
    ["receipt digest", (value) => { value.activeReceipt.sha256 = "f".repeat(64); }],
    ["activation status", (value) => { value.activation.status = "pending"; }],
    ["render tuple", (value) => { value.activeReceipt.document.combinedRenderSha256 = "e".repeat(64); }],
  ]) {
    const candidate = structuredClone(trusted);
    mutate(candidate);
    const result = readiness.evaluateBrokerReadiness(candidate);
    assert.equal(result?.ready, false, `${name} mutation must fail readiness`);
    assert.ok(Array.isArray(result?.failures) && result.failures.length > 0, `${name} must identify a failed invariant`);
  }
});

test("infra-ops.sh remains an executable general host orchestrator", () => {
  const wrapperPath = path.join(root, "scripts", "infra-ops.sh");
  const mode = fs.statSync(wrapperPath).mode & 0o777;
  const result = spawnSync("sh", [wrapperPath, "help"], {
    cwd: root,
    encoding: "utf8",
    env: {
      HOME: os.tmpdir(),
      PATH: process.env.PATH,
    },
    timeout: 10_000,
  });
  const output = `${result.stdout || ""}\n${result.stderr || ""}`;

  assert.equal(mode, 0o755, `scripts/infra-ops.sh mode must remain 0755, got 0${mode.toString(8)}`);
  assert.equal(result.status, 0, output);
  for (const command of ["runtime-isolation-check", "backup-postgres", "vps-preflight"]) {
    assert.match(output, new RegExp(`(?:^|\\s)${command}(?:\\s|$)`), `general command missing from help: ${command}`);
  }
});

test("activation remains external-pending until Release materializes exact v2 values", () => {
  const policy = JSON.parse(read("policy/docker-action-activation-policy.json"));
  assert.equal(policy.status, "external-pending");
});

function canonicalComposeModel() {
  return effectiveComposeModel(canonicalComposeFiles(read("scripts/compose-vps.sh")).map((file) => ({
    label: file,
    source: read(file),
  })), {
    environment: {
      COMPOSE_PROJECT_NAME: "platform_infra_vps",
      DOCKER_ACTION_ACTIVATION_INBOX: "/srv/platform/provider-activation/inbox",
      DOCKER_ACTION_ACTIVE_RECEIPT_FILE: "/srv/platform/trust/active-receipt.json",
      DOCKER_ACTION_RUNTIME_INTENT_FILE: "/srv/platform/trust/runtime-intent.json",
    },
  });
}

function canonicalComposeFiles(wrapper) {
  const blocks = [...wrapper.matchAll(/(?:^|\n)\s*compose\+=\(\s*\n([\s\S]*?)\n\s*\)/g)]
    .map((match) => match[1])
    .filter((body) => /(?:^|\n)\s*-f\s+/.test(body));
  assert.equal(blocks.length, 1, "compose-vps.sh must have one literal canonical -f overlay block");
  const tokens = shellWords(blocks[0], "scripts/compose-vps.sh canonical overlay block");
  const files = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index] === "-p") {
      const projectName = tokens[++index];
      if (!projectName || projectName !== "$PROJECT_NAME") {
        throw new Error(`unsupported canonical Compose project argument: ${projectName || "<missing>"}`);
      }
      continue;
    }
    if (tokens[index] !== "-f") {
      throw new Error(`unsupported token in canonical Compose overlay block: ${tokens[index]}`);
    }
    const file = tokens[++index];
    if (!file || file.startsWith("-") || file.includes("$") || path.isAbsolute(file) || path.normalize(file) !== file) {
      throw new Error(`unsupported canonical Compose overlay path: ${file || "<missing>"}`);
    }
    files.push(file);
  }
  return files;
}

function shellWords(source, label) {
  const words = [];
  let current = "";
  let quote = "";
  let escaped = false;
  for (const character of source) {
    if (escaped) {
      current += character;
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (character === quote) quote = "";
      else current += character;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (/\s/.test(character)) {
      if (current) {
        words.push(current);
        current = "";
      }
      continue;
    }
    if (character === "#" && current === "") {
      throw new Error(`${label} contains an unsupported inline comment`);
    }
    current += character;
  }
  if (escaped || quote) throw new Error(`${label} contains an unterminated shell token`);
  if (current) words.push(current);
  return words;
}

function effectiveComposeModel(documents, options = {}) {
  const model = {
    environment: { ...(options.environment ?? {}) },
    services: new Map(),
    volumes: new Map(),
  };
  for (const document of documents) {
    const parsed = parseComposeDocument(document.source, document.label, model.environment);
    for (const [name, declaration] of parsed.volumes) {
      model.volumes.set(name, {
        ...(model.volumes.get(name) ?? {}),
        ...declaration,
      });
    }
    for (const [name, patch] of parsed.services) {
      const service = model.services.get(name) ?? {
        healthcheckTest: undefined,
        volumes: [],
        volumesFrom: [],
      };
      if (patch.volumeMode === "override" || patch.volumeMode === "reset") service.volumes = [];
      for (const mount of patch.volumes) {
        const prior = service.volumes.findIndex((item) => item.target === mount.target);
        if (prior === -1) service.volumes.push(mount);
        else service.volumes[prior] = mount;
      }
      if (patch.volumesFromPresent) {
        if (patch.volumesFromMode === "override" || patch.volumesFromMode === "reset") service.volumesFrom = [];
        service.volumesFrom.push(...patch.volumesFrom);
      }
      if (patch.healthcheckTest !== undefined) service.healthcheckTest = patch.healthcheckTest;
      model.services.set(name, service);
    }
  }
  return model;
}

function parseComposeDocument(source, label, environment) {
  if (source.includes("\t")) throw new Error(`${label}: tabs are unsupported`);
  const services = new Map();
  for (const [name, block] of sectionEntries(source, "services", label)) {
    services.set(name, parseServiceDefinition(block, `${label}:services.${name}`, environment));
  }
  const volumes = new Map();
  for (const [name, block, declaration] of sectionEntries(source, "volumes", label)) {
    volumes.set(name, parseNamedVolume(block, declaration, `${label}:volumes.${name}`, environment));
  }
  return { services, volumes };
}

function sectionEntries(source, section, label) {
  const lines = source.replaceAll("\r\n", "\n").split("\n");
  const start = lines.findIndex((line) => line === `${section}:`);
  if (start === -1) return [];
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^[^\s#][^:]*:\s*(?:#.*)?$/.test(lines[index])) {
      end = index;
      break;
    }
  }
  const entries = [];
  for (let index = start + 1; index < end;) {
    const line = lines[index];
    if (line.trim() === "" || line.trimStart().startsWith("#")) {
      index += 1;
      continue;
    }
    const marker = line.match(/^  ([A-Za-z0-9][A-Za-z0-9_.-]*):(.*)$/);
    if (!marker) throw new Error(`${label}:${index + 1}: unsupported ${section} entry`);
    let next = index + 1;
    while (next < end && !/^  [A-Za-z0-9][A-Za-z0-9_.-]*:/.test(lines[next])) next += 1;
    entries.push([marker[1], lines.slice(index + 1, next), marker[2].trim()]);
    index = next;
  }
  return entries;
}

function parseServiceDefinition(lines, label, environment) {
  const property = lines.findIndex((line) => /^    volumes:/.test(line));
  let volumeMode = "merge";
  let volumes = [];
  if (property !== -1) {
    const declaration = lines[property].slice(lines[property].indexOf(":") + 1).trim();
    if (declaration === "!override") volumeMode = "override";
    else if (declaration === "!reset []") volumeMode = "reset";
    else if (declaration !== "") throw new Error(`${label}: unsupported volumes declaration ${declaration}`);
    const body = indentedPropertyBody(lines, property, label, "volumes");
    if (volumeMode === "reset") {
      if (body.length > 0) throw new Error(`${label}: !reset [] cannot contain entries`);
    } else {
      volumes = parseMountList(body, label);
    }
  }

  const volumesFromProperty = lines.findIndex((line) => /^    volumes_from:/.test(line));
  const volumesFromPresent = volumesFromProperty !== -1;
  let volumesFromMode = "merge";
  let volumesFrom = [];
  if (volumesFromPresent) {
    const declaration = lines[volumesFromProperty].slice(lines[volumesFromProperty].indexOf(":") + 1).trim();
    if (declaration === "!override") volumesFromMode = "override";
    else if (declaration === "!reset []") volumesFromMode = "reset";
    else if (declaration !== "") throw new Error(`${label}: unsupported volumes_from declaration ${declaration}`);
    const body = indentedPropertyBody(lines, volumesFromProperty, label, "volumes_from");
    if (volumesFromMode === "reset") {
      if (body.length > 0) throw new Error(`${label}: !reset [] cannot contain volumes_from entries`);
    } else {
      volumesFrom = parseVolumesFrom(body, label);
    }
  }

  return {
    healthcheckTest: parseHealthcheckTest(lines, label, environment),
    volumeMode,
    volumes,
    volumesFrom,
    volumesFromMode,
    volumesFromPresent,
  };
}

function indentedPropertyBody(lines, property, label, name) {
  const body = [];
  for (let index = property + 1; index < lines.length; index += 1) {
    if (lines[index].trim() === "" || lines[index].trimStart().startsWith("#")) continue;
    if (/^    \S/.test(lines[index])) break;
    if (!/^ {6,}\S/.test(lines[index])) throw new Error(`${label}: unsupported ${name} indentation`);
    body.push(lines[index]);
  }
  return body;
}

function parseMountList(lines, label) {
  const mounts = [];
  for (let index = 0; index < lines.length;) {
    const marker = lines[index].match(/^      -\s+(.+?)\s*$/);
    if (!marker) throw new Error(`${label}: unsupported volume list item`);
    const head = marker[1];
    if (head.startsWith("{") || head.startsWith("[")) {
      throw new Error(`${label}: unsupported inline volume item`);
    }
    if (/^(?:type|source|target|read_only):(?:\s|$)/.test(head)) {
      const fields = new Map();
      setLongMountField(fields, head, label);
      index += 1;
      while (index < lines.length && /^ {8,}\S/.test(lines[index])) {
        const continuation = lines[index].trim();
        if (!/^(?:type|source|target|read_only):(?:\s|$)/.test(continuation)) {
          throw new Error(`${label}: unsupported long volume field ${continuation}`);
        }
        setLongMountField(fields, continuation, label);
        index += 1;
      }
      const source = fields.get("source");
      const target = fields.get("target");
      if (!source || !target) throw new Error(`${label}: long volume requires both source and target`);
      const type = fields.get("type") || inferMountType(source);
      if (!["bind", "volume"].includes(type)) throw new Error(`${label}: unsupported long volume type ${type}`);
      mounts.push({
        type,
        source,
        target,
        readOnly: fields.get("read_only") === "true",
      });
      continue;
    }
    const parts = splitComposeMount(unquote(head));
    if (parts.length < 2 || parts.length > 3 || !parts[0] || !parts[1]) {
      throw new Error(`${label}: unsupported short volume ${head}`);
    }
    mounts.push({
      type: inferMountType(parts[0]),
      source: parts[0],
      target: parts[1],
      readOnly: parts[2]?.split(",").includes("ro") ?? false,
    });
    index += 1;
  }
  return mounts;
}

function parseVolumesFrom(lines, label) {
  const references = [];
  for (const line of lines) {
    const marker = line.match(/^      -\s+(.+?)\s*$/);
    if (!marker) throw new Error(`${label}: unsupported volumes_from list item`);
    const value = unquote(marker[1]);
    if (value.startsWith("container:")) {
      throw new Error(`${label}: unsupported external volumes_from reference ${value}`);
    }
    const parts = value.split(":");
    if (parts.length > 2 || !/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(parts[0])
      || (parts[1] && !["ro", "rw"].includes(parts[1]))) {
      throw new Error(`${label}: unsupported volumes_from reference ${value}`);
    }
    references.push({ service: parts[0], readOnly: parts[1] === "ro" });
  }
  return references;
}

function parseHealthcheckTest(lines, label, environment) {
  const property = lines.findIndex((line) => /^    healthcheck:/.test(line));
  if (property === -1) return undefined;
  const declaration = lines[property].slice(lines[property].indexOf(":") + 1).trim();
  if (declaration) throw new Error(`${label}: inline healthcheck is unsupported`);
  const body = indentedPropertyBody(lines, property, label, "healthcheck");
  const testIndex = body.findIndex((line) => /^      test:/.test(line));
  if (testIndex === -1) throw new Error(`${label}: healthcheck.test is required`);
  const raw = body[testIndex].slice(body[testIndex].indexOf(":") + 1).trim();
  if (raw) {
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(`${label}: healthcheck.test inline value must be a JSON string array`);
    }
    if (!Array.isArray(parsed) || parsed.length === 0 || parsed.some((value) => typeof value !== "string")) {
      throw new Error(`${label}: healthcheck.test must be a non-empty string array`);
    }
    return parsed;
  }
  const result = [];
  for (let index = testIndex + 1; index < body.length; index += 1) {
    const marker = body[index].match(/^        -\s+(.+?)\s*$/);
    if (!marker) break;
    result.push(unquote(marker[1]));
  }
  if (result.length === 0) throw new Error(`${label}: healthcheck.test list is empty or unsupported`);
  return result;
}

function setLongMountField(fields, line, label) {
  const separator = line.indexOf(":");
  const key = line.slice(0, separator).trim();
  const raw = line.slice(separator + 1).trim();
  if (!raw) throw new Error(`${label}: unsupported nested long volume field ${key}`);
  if (fields.has(key)) throw new Error(`${label}: duplicate long volume field ${key}`);
  const value = unquote(raw);
  if (key === "read_only" && !["true", "false"].includes(value)) {
    throw new Error(`${label}: read_only must be true or false`);
  }
  fields.set(key, value);
}

function parseNamedVolume(lines, declaration, label, environment) {
  if (declaration === "{}" || declaration === "") {
    const result = {};
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
      const property = line.match(/^    ([A-Za-z_][A-Za-z0-9_-]*):(?:\s*(.*))?$/);
      if (!property) throw new Error(`${label}: unsupported named-volume property`);
      const [, key, raw = ""] = property;
      if (key === "driver_opts") {
        if (raw.trim()) throw new Error(`${label}: inline driver_opts are unsupported`);
        result.driver_opts = {};
        index += 1;
        while (index < lines.length && /^ {6,}\S/.test(lines[index])) {
          const option = lines[index].match(/^      ([A-Za-z_][A-Za-z0-9_-]*):\s*(.+?)\s*$/);
          if (!option) throw new Error(`${label}: unsupported driver_opts entry`);
          const value = expandComposeScalar(unquote(option[2]), environment);
          result.driver_opts[option[1]] = value;
          if (option[1] === "device") result.device = value;
          index += 1;
        }
        index -= 1;
      } else if (["driver", "name", "external"].includes(key)) {
        if (!raw.trim()) throw new Error(`${label}: missing value for ${key}`);
        result[key] = key === "external"
          ? unquote(raw)
          : expandComposeScalar(unquote(raw), environment);
      } else {
        throw new Error(`${label}: unsupported named-volume property ${key}`);
      }
    }
    return result;
  }
  throw new Error(`${label}: unsupported named-volume declaration ${declaration}`);
}

function splitComposeMount(value) {
  const parts = [];
  let start = 0;
  let interpolationDepth = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === "$" && value[index + 1] === "{") {
      interpolationDepth += 1;
      index += 1;
      continue;
    }
    if (value[index] === "}" && interpolationDepth > 0) {
      interpolationDepth -= 1;
      continue;
    }
    if (value[index] === ":" && interpolationDepth === 0) {
      parts.push(value.slice(start, index));
      start = index + 1;
    }
  }
  if (interpolationDepth !== 0) throw new Error(`unsupported unterminated Compose interpolation: ${value}`);
  parts.push(value.slice(start));
  return parts;
}

function inferMountType(source) {
  return source.startsWith("/") || source.startsWith(".") || source.startsWith("${") ? "bind" : "volume";
}

function unquote(value) {
  const clean = String(value).trim();
  if ((clean.startsWith('"') && clean.endsWith('"')) || (clean.startsWith("'") && clean.endsWith("'"))) {
    return clean.slice(1, -1);
  }
  if (/^[\[{"'|>&*!]/.test(clean)) throw new Error(`unsupported YAML scalar: ${clean}`);
  return clean;
}

function rawSocketOwners(model) {
  return [...model.services.keys()].filter((name) => serviceOwnsRawSocket(model, name)).sort();
}

function serviceOwnsRawSocket(model, name, ancestry = new Set()) {
  if (ancestry.has(name)) throw new Error(`cyclic volumes_from authority chain at ${name}`);
  const service = model.services.get(name);
  if (!service) throw new Error(`unknown volumes_from service ${name}`);
  const next = new Set(ancestry).add(name);
  if ((service.volumes ?? []).some((mount) => {
    const rawSource = mount.type === "volume" ? model.volumes.get(mount.source)?.device : mount.source;
    const source = rawSource === undefined ? "" : expandComposeScalar(rawSource, model.environment);
    return exposesDockerSocket(source);
  })) return true;
  return (service.volumesFrom ?? []).some((reference) => serviceOwnsRawSocket(model, reference.service, next));
}

function exposesDockerSocket(source) {
  if (!String(source || "").startsWith("/")) return false;
  const observed = path.posix.normalize(source);
  const normalized = observed === "/run" || observed.startsWith("/run/")
    ? `/var${observed}`
    : observed;
  const withoutTrailingSlash = normalized === "/" ? "/" : normalized.replace(/\/+$/, "");
  return withoutTrailingSlash === dockerSocketPath
    || dockerSocketPath.startsWith(withoutTrailingSlash === "/" ? "/" : `${withoutTrailingSlash}/`);
}

function effectiveVolumeName(model, name) {
  const declaration = model.volumes.get(name);
  if (!declaration) throw new Error(`missing named volume ${name}`);
  if (declaration.external === "true" || declaration.external === true) {
    throw new Error(`named volume ${name} is external`);
  }
  if (declaration.name) return expandComposeScalar(declaration.name, model.environment);
  const projectName = expandComposeScalar("${COMPOSE_PROJECT_NAME}", model.environment);
  return `${projectName}_${name}`;
}

function exactPrivateVolumeName(model, name) {
  const declaration = model.volumes.get(name);
  if (!declaration) throw new Error(`missing named volume ${name}`);
  if (Object.keys(declaration).length !== 0) {
    throw new Error(`named volume ${name} must not define external, name, driver or driver_opts aliases`);
  }
  return effectiveVolumeName(model, name);
}

function expandComposeScalar(value, environment = {}) {
  let expanded = String(value);
  for (let pass = 0; pass < 8 && expanded.includes("${"); pass += 1) {
    expanded = expanded.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?])(.*?))?\}/g, (_match, name, operator, fallback = "") => {
      const present = Object.hasOwn(environment, name);
      const actual = present ? String(environment[name]) : "";
      if (!operator) {
        if (!present) throw new Error(`unresolved Compose variable ${name}`);
        return actual;
      }
      if (operator === ":-") return present && actual !== "" ? actual : fallback;
      if (operator === "-") return present ? actual : fallback;
      if (operator === ":?") {
        if (!present || actual === "") throw new Error(`unresolved Compose variable ${name}: ${fallback}`);
        return actual;
      }
      if (operator === "?") {
        if (!present) throw new Error(`unresolved Compose variable ${name}: ${fallback}`);
        return actual;
      }
      throw new Error(`unsupported Compose expansion operator for ${name}`);
    });
  }
  if (expanded.includes("${")) throw new Error(`unsupported nested Compose interpolation: ${expanded}`);
  expanded = expanded.replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (_match, name) => {
    if (!Object.hasOwn(environment, name)) throw new Error(`unresolved Compose variable ${name}`);
    return String(environment[name]);
  });
  return expanded.replaceAll("$$", "$");
}

function dockerfileCopyTarget(source, repositoryPath) {
  const matches = [];
  for (const rawLine of source.replaceAll("\r\n", "\n").split("\n")) {
    const line = rawLine.trim();
    if (!/^COPY\s+/i.test(line)) continue;
    const tokens = line.split(/\s+/);
    if (tokens.length === 3 && tokens[1] === repositoryPath) matches.push(tokens[2]);
  }
  assert.equal(matches.length, 1, `expected one COPY for ${repositoryPath}`);
  return matches[0];
}

function trustedReadinessInput() {
  const intentId = "intent.release-20260728";
  const combinedRenderSha256 = "a".repeat(64);
  const activeReceiptSha256 = "b".repeat(64);
  return {
    socket: {
      exists: true,
      isSocket: true,
      ownerUid: 0,
      ownerGid: 0,
    },
    runtimeIntent: {
      trusted: true,
      document: {
        schema: "platform.docker-runtime-intent/v1",
        intentId,
        combinedRenderSha256,
      },
    },
    activeReceipt: {
      trusted: true,
      sha256: activeReceiptSha256,
      document: {
        schema: "platform.docker-active-receipt/v2",
        intentId,
        combinedRenderSha256,
      },
    },
    activation: {
      trusted: true,
      status: "active",
      intentId,
      activeReceiptSha256,
      combinedRenderSha256,
    },
    expected: {
      intentId,
      activeReceiptSha256,
      combinedRenderSha256,
    },
  };
}
