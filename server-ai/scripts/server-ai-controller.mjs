#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";

export const CONTROLLER_SOCKET = "/run/server-ai-controller/controller.sock";
export const CONTROLLER_REGISTRY = "/etc/server-ai-controller/registry.json";
export const CONTROLLER_MACHINE_ID = "/run/host-machine-id";
export const DOCKER_SOCKET = "/var/run/docker.sock";
export const MAX_REQUEST_BYTES = 1024;
export const ACTION_DEADLINE_MS = 60_000;
export const POLL_MS = 250;
export const PROJECT = "platform_server_ai";
export const SERVICES = Object.freeze([
  Object.freeze({ name: "gf-searxng", service: "searxng" }),
  Object.freeze({ name: "gf-server-ai-observer", service: "server-ai-observer" }),
  Object.freeze({ name: "gf-server-ai-project-source-reader", service: "server-ai-project-source-reader" }),
  Object.freeze({ name: "gf-server-ai-project-query-reader", service: "server-ai-project-query-reader" }),
]);

const SERVICE_POLICIES = Object.freeze({
  searxng: Object.freeze({
    user: "977:977",
    networks: Object.freeze(["platform_server_ai_egress", "platform_server_ai_search"]),
    mounts: Object.freeze([
      Object.freeze({ target: "/etc/searxng", type: "bind", readOnly: true }),
      Object.freeze({ target: "/run/secrets/searxng-settings.yml", type: "bind", readOnly: true, source: "/home/platform_infrastructure/server-ai-provision-20260906/candidates/os-security-20260927/settings.yml" }),
    ]),
    tmpfs: Object.freeze({
      "/tmp": "size=64m,mode=1777",
      "/var/cache/searxng": "size=64m,uid=977,gid=977,mode=0700",
    }),
    memory: 768 * 1024 ** 2,
    memorySwap: 768 * 1024 ** 2,
    memoryReservation: 0,
    nanoCpus: 1_000_000_000,
    pidsLimit: 128,
    deviceRequests: Object.freeze([]),
    devices: Object.freeze([]),
    requiresDockerGroup: false,
    requiredForEnable: false,
  }),
  "server-ai-observer": Object.freeze({
    user: "1000:1000",
    networks: Object.freeze(["platform_server_ai_observer"]),
    mounts: Object.freeze([
      Object.freeze({ target: "/run/secrets/server_ai_observer_token", type: "bind", readOnly: true }),
      Object.freeze({ target: "/run/platform-docker-observer", type: "bind", readOnly: true, source: "/run/platform-docker-observer" }),
    ]),
    tmpfs: Object.freeze({}),
    memory: 128 * 1024 ** 2,
    memorySwap: 128 * 1024 ** 2,
    memoryReservation: 0,
    nanoCpus: 500_000_000,
    pidsLimit: 64,
    deviceRequests: Object.freeze([]),
    devices: Object.freeze([]),
    requiresDockerGroup: true,
    requiredForEnable: true,
  }),
  "server-ai-project-source-reader": Object.freeze({
    user: "1000:1000",
    networks: Object.freeze(["platform_server_ai_project_source"]),
    mounts: Object.freeze([
      Object.freeze({ target: "/projects", type: "bind", readOnly: true, source: "/home/platform_infrastructure/v1-fresh-data/src" }),
      Object.freeze({ target: "/run/secrets/server_ai_project_readers_token", type: "bind", readOnly: true, source: "/etc/platform-infrastructure/server-ai/project-readers-token" }),
    ]),
    tmpfs: Object.freeze({ "/tmp": "size=64m,uid=1000,gid=1000,mode=0700" }),
    memory: 256 * 1024 ** 2,
    memorySwap: 256 * 1024 ** 2,
    memoryReservation: 0,
    nanoCpus: 1_000_000_000,
    pidsLimit: 64,
    deviceRequests: Object.freeze([]), devices: Object.freeze([]),
    requiresDockerGroup: false, requiredForEnable: false,
    platformSource: true,
    readerEntrypoint: Object.freeze(["python3", "-I", "/opt/server-ai-project-reader/source_reader.py"]),
  }),
  "server-ai-project-query-reader": Object.freeze({
    user: "1000:1000",
    networks: Object.freeze(["platform_infra_greenfield_platform_db_admin", "platform_server_ai_project_query"]),
    mounts: Object.freeze([
      Object.freeze({ target: "/run/platform-db-tls", type: "bind", readOnly: true, source: "/home/platform_infrastructure/v1-fresh-runtime/maintenance/20260927/db-tls/clients" }),
      Object.freeze({ target: "/run/secrets/server_ai_project_readers_token", type: "bind", readOnly: true, source: "/etc/platform-infrastructure/server-ai/project-readers-token" }),
      Object.freeze({ target: "/run/secrets/server_ai_fiplatform_mariadb_fiplatform_ro", type: "bind", readOnly: true, source: "/etc/platform-infrastructure/server-ai/db-fiplatform-fiplatform-ro.json" }),
      Object.freeze({ target: "/run/secrets/server_ai_fiplatform_mariadb_u778675014_fip_ro", type: "bind", readOnly: true, source: "/etc/platform-infrastructure/server-ai/db-fiplatform-u778675014-fip-ro.json" }),
      Object.freeze({ target: "/run/secrets/server_ai_workcalendar_mariadb_workcalendar_ro", type: "bind", readOnly: true, source: "/etc/platform-infrastructure/server-ai/db-workcalendar-workcalendar-ro.json" }),
      Object.freeze({ target: "/run/secrets/server_ai_anniversary_mariadb_anniversary_ro", type: "bind", readOnly: true, source: "/etc/platform-infrastructure/server-ai/db-anniversary-anniversary-ro.json" }),
      Object.freeze({ target: "/run/secrets/server_ai_stream_mariadb_stream_ro", type: "bind", readOnly: true, source: "/etc/platform-infrastructure/server-ai/db-stream-stream-ro.json" }),
      Object.freeze({ target: "/run/secrets/server_ai_account_postgres_stexor_ro", type: "bind", readOnly: true, source: "/etc/platform-infrastructure/server-ai/db-stexor-postgres-stexor-ro.json" }),
    ]),
    tmpfs: Object.freeze({ "/tmp": "size=64m,uid=1000,gid=1000,mode=0700" }),
    memory: 256 * 1024 ** 2,
    memorySwap: 256 * 1024 ** 2,
    memoryReservation: 0,
    nanoCpus: 1_000_000_000,
    pidsLimit: 64,
    deviceRequests: Object.freeze([]), devices: Object.freeze([]),
    requiresDockerGroup: false, requiredForEnable: false,
    readerEntrypoint: Object.freeze(["python3", "-I", "/opt/server-ai-project-reader/query_reader.py"]),
  }),
});

const HEX64 = /^[0-9a-f]{64}$/;
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/;
const CONTAINER_ID = /^[0-9a-f]{12,64}$/;
const MACHINE_ID = HEX64;
const PLATFORM_SOURCE_PATH = /^\/var\/lib\/platform-infrastructure\/server-ai-[A-Za-z0-9][A-Za-z0-9._-]{0,127}\/repo$/;
const REQUEST_KEYS = Object.freeze(["machineId"]);

function ownKeys(value) {
  return Object.keys(value).sort();
}

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${ownKeys(value).map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

export function sha256Bytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function fail(message, statusCode = 400) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || canonicalJson(ownKeys(value)) !== canonicalJson([...expected].sort())) {
    throw fail(`${label} has unknown or missing fields`);
  }
}

export function validateRegistry(value) {
  exactKeys(value, ["version", "machineId", "services"], "controller registry");
  if (![1, 2].includes(value.version)) throw fail("controller registry version is unsupported");
  if (!MACHINE_ID.test(String(value.machineId))) throw fail("controller registry machineId is invalid");
  const catalog = value.version === 2 ? SERVICES.slice(0, 2) : SERVICES;
  if (!Array.isArray(value.services) || value.services.length !== catalog.length) {
    throw fail("controller registry services are invalid");
  }
  const seen = new Set();
  value.services.forEach((record, index) => {
    const expected = catalog[index];
    const policy = SERVICE_POLICIES[expected.service];
    const auxiliary = policy.role !== undefined;
    const portable = value.version === 2;
    exactKeys(record, portable
      ? ["name", "service", "imageId", "configHash", "mountSources"]
      : auxiliary
      ? ["name", "service", "imageId", "configHash", "device", "deviceProofSha256"]
      : policy.platformSource
        ? ["name", "service", "imageId", "configHash", "platformSourcePath"]
        : ["name", "service", "imageId", "configHash"], `controller registry service ${index}`);
    if (record.name !== expected.name || record.service !== expected.service || seen.has(record.name)) {
      throw fail("controller registry service identity is invalid");
    }
    if (!IMAGE_ID.test(String(record.imageId)) || !HEX64.test(String(record.configHash))) {
      throw fail("controller registry service attestation is invalid");
    }
    if (auxiliary && (!policy.allowedDevices.includes(record.device) || !HEX64.test(String(record.deviceProofSha256)))) {
      throw fail("controller registry auxiliary device proof is invalid");
    }
    if (policy.platformSource && (typeof record.platformSourcePath !== "string"
      || !PLATFORM_SOURCE_PATH.test(record.platformSourcePath))) {
      throw fail("controller registry platform source binding is invalid");
    }
    if (portable) {
      const targets = policy.mounts.map(mount => mount.target);
      exactKeys(record.mountSources, targets, "controller registry mount sources");
      for (const source of Object.values(record.mountSources)) {
        if (typeof source !== "string" || !/^\/[A-Za-z0-9_./-]+$/.test(source)
          || source.length > 512 || source.includes("//") || source.split("/").some(part => part === "." || part === "..")
          || source === "/" || source.endsWith("/")) throw fail("controller registry mount source is invalid");
      }
      if (record.service === "server-ai-observer" && record.mountSources["/run/platform-docker-observer"] !== "/run/platform-docker-observer") {
        throw fail("controller registry observer socket source is invalid");
      }
    }
    seen.add(record.name);
  });
  return value;
}

function readExactFile(file, { maxBytes, minBytes = 1, ownerUid, modeMask = 0 } = {}) {
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || (ownerUid !== undefined && stat.uid !== ownerUid)
      || (stat.mode & modeMask) !== 0 || stat.size < minBytes || stat.size > maxBytes) throw new Error(`protected file rejected: ${file}`);
    return fs.readFileSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

export function readRegistry(file = CONTROLLER_REGISTRY) {
  const bytes = readExactFile(file, { maxBytes: 64 * 1024, ownerUid: 0, modeMask: 0o133 });
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch {
    throw fail("controller registry JSON is invalid", 503);
  }
  validateRegistry(value);
  if (!bytes.equals(Buffer.from(`${canonicalJson(value)}\n`))) throw fail("controller registry must be canonical JSON", 503);
  return value;
}

export function readHostMachineId(file = CONTROLLER_MACHINE_ID) {
  const bytes = readExactFile(file, { maxBytes: 4096, ownerUid: 0, modeMask: 0o022 });
  const machineId = sha256Bytes(bytes);
  if (!MACHINE_ID.test(machineId)) throw fail("host machine identity is invalid", 503);
  return machineId;
}

export function parseControlRequest(body) {
  const bytes = Buffer.isBuffer(body) ? body : Buffer.from(String(body ?? ""));
  if (bytes.length > MAX_REQUEST_BYTES) throw fail("request body is oversized", 413);
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch {
    throw fail("request body must be JSON");
  }
  exactKeys(value, REQUEST_KEYS, "controller request");
  if (!MACHINE_ID.test(String(value.machineId))) throw fail("request machineId is invalid");
  if (!bytes.equals(Buffer.from(canonicalJson(value)))) throw fail("request must be canonical JSON");
  return value;
}

function healthOf(info) {
  return info?.State?.Health?.Status === "healthy";
}

function noPublishedPorts(info) {
  const ports = info?.NetworkSettings?.Ports;
  if (!ports || typeof ports !== "object" || Array.isArray(ports)) return ports === null || ports === undefined;
  return Object.values(ports).every(value => value === null || Array.isArray(value) && value.length === 0);
}

function projectMount(mount) {
  const result = {
    target: String(mount?.Destination ?? ""),
    type: String(mount?.Type ?? ""),
    readOnly: mount?.RW === false,
  };
  if (result.type === "volume") result.name = String(mount?.Name ?? "");
  if (result.target === "/var/run/docker.sock" || result.target === "/run/platform-docker-observer" || result.target.startsWith("/projects/")
    || result.target === "/run/secrets/searxng-settings.yml"
    || result.target === "/run/platform-db-tls"
    || result.target === "/projects" || result.target === "/platform"
    || result.target === "/run/secrets/server_ai_project_readers_token"
    || result.target.startsWith("/run/secrets/server_ai_fiplatform_mariadb_")
    || result.target === "/run/secrets/server_ai_workcalendar_mariadb_workcalendar_ro"
    || result.target === "/run/secrets/server_ai_anniversary_mariadb_anniversary_ro"
    || result.target === "/run/secrets/server_ai_stream_mariadb_stream_ro"
    || result.target === "/run/secrets/server_ai_account_postgres_stexor_ro") {
    result.source = String(mount?.Source ?? "");
  }
  return result;
}

function projectDeviceRequest(request) {
  return {
    driver: String(request?.Driver ?? ""),
    count: Number(request?.Count),
    deviceIds: Array.isArray(request?.DeviceIDs) ? [...request.DeviceIDs].map(String).sort() : [],
    capabilities: request?.Capabilities ?? null,
    options: request?.Options ?? null,
  };
}

function projectDevice(device) {
  return {
    pathOnHost: String(device?.PathOnHost ?? ""),
    pathInContainer: String(device?.PathInContainer ?? ""),
    cgroupPermissions: String(device?.CgroupPermissions ?? ""),
  };
}

function environmentValue(environment, key) {
  if (!Array.isArray(environment)) return null;
  const entries = environment.filter((entry) => String(entry).startsWith(`${key}=`));
  return entries.length === 1 ? String(entries[0]).slice(key.length + 1) : null;
}

function exactRuntimePolicy(info, expected) {
  const policy = SERVICE_POLICIES[expected.service];
  if (!policy) return false;
  const host = info?.HostConfig;
  const networks = info?.NetworkSettings?.Networks;
  if (!host || !networks || typeof networks !== "object" || Array.isArray(networks)) return false;
  const portable = expected.mountSources !== undefined;
  const mounts = Array.isArray(info.Mounts) ? info.Mounts.map(mount => ({ ...projectMount(mount), ...(portable ? { source: String(mount.Source ?? "") } : {}) })).sort((left, right) => left.target.localeCompare(right.target)) : [];
  const expectedMounts = [
    ...policy.mounts.map(mount => portable ? { ...mount, source: expected.mountSources[mount.target] } : mount),
    ...(policy.platformSource ? [{ target: "/platform", type: "bind", readOnly: true, source: expected.platformSourcePath }] : []),
  ].sort((left, right) => left.target.localeCompare(right.target));
  const deviceRequests = Array.isArray(host.DeviceRequests) ? host.DeviceRequests.map(projectDeviceRequest) : [];
  const devices = Array.isArray(host.Devices) ? host.Devices.map(projectDevice) : [];
  const groupAdd = Array.isArray(host.GroupAdd) ? host.GroupAdd : [];
  const cpuAuxiliary = policy.role !== undefined && expected.device === "CPU";
  const expectedDevices = cpuAuxiliary ? [] : policy.devices;
  const requiresRuntimeGroup = policy.requiresDockerGroup && !cpuAuxiliary;
  const auxiliaryEnvironment = policy.role === undefined || (
    environmentValue(info.Config?.Env, "SERVER_AI_AUX_ROLE") === policy.role
    && policy.allowedDevices.includes(environmentValue(info.Config?.Env, "SERVER_AI_AUX_DEVICE"))
    && environmentValue(info.Config?.Env, "SERVER_AI_AUX_DEVICE") === expected.device
    && environmentValue(info.Config?.Env, "HOME") === "/tmp"
    && environmentValue(info.Config?.Env, "TMPDIR") === "/tmp"
    && environmentValue(info.Config?.Env, "HTTP_PROXY") === null
    && environmentValue(info.Config?.Env, "HTTPS_PROXY") === null
    && environmentValue(info.Config?.Env, "ALL_PROXY") === null
    && environmentValue(info.Config?.Env, "HF_TOKEN") === null
    && environmentValue(info.Config?.Env, "API_KEY") === null
    && canonicalJson(info.Config?.Entrypoint || []) === canonicalJson(["/usr/local/bin/server-ai-openvino-entrypoint"])
    && canonicalJson(info.Config?.Cmd || []) === canonicalJson([])
  );
  const readerEnvironment = policy.readerEntrypoint === undefined || (
    canonicalJson(info.Config?.Entrypoint || []) === canonicalJson(policy.readerEntrypoint)
    && canonicalJson(info.Config?.Cmd || []) === canonicalJson([])
    && environmentValue(info.Config?.Env, "HTTP_PROXY") === null
    && environmentValue(info.Config?.Env, "HTTPS_PROXY") === null
    && environmentValue(info.Config?.Env, "ALL_PROXY") === null
    && environmentValue(info.Config?.Env, "DATABASE_URL") === null
    && environmentValue(info.Config?.Env, "MYSQL_PWD") === null
    && environmentValue(info.Config?.Env, "PGPASSWORD") === null
  );
  return auxiliaryEnvironment && readerEnvironment
    && info.Config?.User === policy.user
    && host.ReadonlyRootfs === true
    && host.Privileged === false
    && host.RestartPolicy?.Name === "unless-stopped"
    && Number(host.Memory) === policy.memory
    && Number(host.MemorySwap) === policy.memorySwap
    && Number(host.MemoryReservation) === policy.memoryReservation
    && Number(host.NanoCpus) === policy.nanoCpus
    && Number(host.PidsLimit) === policy.pidsLimit
    && (policy.shmSize === undefined || Number(host.ShmSize) === policy.shmSize)
    && canonicalJson([...(host.CapDrop || [])].sort()) === canonicalJson(["ALL"])
    && canonicalJson([...(host.CapAdd || [])].sort()) === canonicalJson([])
    && canonicalJson([...(host.SecurityOpt || [])].sort()) === canonicalJson(["no-new-privileges:true"])
    && canonicalJson(host.Tmpfs || {}) === canonicalJson(portable && expected.service === "server-ai-observer" ? { "/tmp": "size=16m,uid=1000,gid=1000,mode=0700" } : policy.tmpfs)
    && canonicalJson(devices) === canonicalJson(expectedDevices)
    && canonicalJson(deviceRequests) === canonicalJson(policy.deviceRequests)
    && canonicalJson(Object.keys(networks).sort()) === canonicalJson([...policy.networks].sort())
    && canonicalJson(mounts) === canonicalJson(expectedMounts)
    && (requiresRuntimeGroup ? groupAdd.length === 1 && /^[1-9][0-9]*$/.test(String(groupAdd[0])) : groupAdd.length === 0);
}

export function attestContainer(info, expected, machineId) {
  if (!info || typeof info !== "object" || !CONTAINER_ID.test(String(info.Id ?? ""))) return { compatible: false, reason: "missing-container-id" };
  const labels = info.Config?.Labels;
  const imageId = String(info.Image ?? "");
  const compatible = info.Name === `/${expected.name}`
    && labels?.["com.docker.compose.project"] === PROJECT
    && labels?.["com.docker.compose.service"] === expected.service
    && labels?.["io.platform.server-ai.machine-id"] === machineId
    && labels?.["com.docker.compose.config-hash"] === expected.configHash
    && imageId === expected.imageId
    && noPublishedPorts(info)
    && exactRuntimePolicy(info, expected);
  return { compatible, reason: compatible ? "trusted" : "identity-or-policy-mismatch" };
}

function serviceRecord(expected, info, compatibility) {
  const state = info?.State;
  const running = state?.Running === true;
  const healthy = healthOf(info);
  let status = "unavailable";
  if (compatibility) {
    if (running && healthy) status = "active";
    else if (running) status = "starting";
    else status = "disabled";
  }
  return {
    name: expected.name, service: expected.service, running, healthy, status,
    ...(expected.device ? { device: expected.device, deviceVerified: compatibility && healthy && HEX64.test(String(expected.deviceProofSha256)) } : {}),
  };
}

function remaining(deadline) {
  return Math.max(0, deadline - Date.now());
}

function sleep(ms, deadline) {
  const delay = Math.min(ms, remaining(deadline));
  if (delay <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, delay));
}

function dockerFailure(message, statusCode = 502) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function createDockerApi(socketPath = DOCKER_SOCKET) {
  const request = (method, requestPath, body, timeoutMs) => new Promise((resolve, reject) => {
    const requestOptions = { socketPath, path: requestPath, method, headers: { accept: "application/json" } };
    if (body !== undefined) {
      requestOptions.headers["content-type"] = "application/json";
      requestOptions.headers["content-length"] = Buffer.byteLength(body);
    }
    const req = http.request(requestOptions, (res) => {
      const chunks = [];
      let length = 0;
      res.on("data", (chunk) => {
        length += chunk.length;
        if (length > 256 * 1024) req.destroy(dockerFailure("Docker response is oversized"));
        else chunks.push(chunk);
      });
      res.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        if (res.statusCode < 200 || res.statusCode >= 300) return reject(dockerFailure(`Docker API returned ${res.statusCode}`));
        if (!raw) return resolve(null);
        try { resolve(JSON.parse(raw)); } catch { reject(dockerFailure("Docker response is invalid")); }
      });
    });
    req.setTimeout(Math.max(1, timeoutMs), () => req.destroy(dockerFailure("Docker API deadline elapsed", 504)));
    req.on("error", reject);
    if (body !== undefined) req.end(body); else req.end();
  });
  return Object.freeze({
    inspectContainer: (name, timeoutMs) => request("GET", `/containers/${name}/json`, undefined, timeoutMs),
    startContainer: (id, timeoutMs) => request("POST", `/containers/${id}/start`, "", timeoutMs),
    stopContainer: (id, timeoutMs) => request("POST", `/containers/${id}/stop?t=15`, "", timeoutMs),
  });
}

async function inspectAll({ docker, registry, machineId, deadline }) {
  const values = [];
  const missing = [];
  for (const record of registry.services) {
    const expected = { ...record };
    let info = null;
    try { info = await docker.inspectContainer(expected.name, remaining(deadline)); }
    catch (error) { if (error?.statusCode === 404 || /404/.test(String(error?.message))) missing.push(expected.name); }
    const attestation = info ? attestContainer(info, expected, machineId) : { compatible: false, reason: "missing" };
    if (!attestation.compatible && !missing.includes(expected.name)) missing.push(`${expected.name}: configurazione Docker non verificata`);
    values.push({ expected, info, attestation });
  }
  return { values, missing };
}

function statusPayload(registry, inspected) {
  const services = inspected.values.map(({ expected, info, attestation }) => serviceRecord(expected, info, attestation.compatible));
  const compatible = inspected.values.every(({ attestation }) => attestation.compatible);
  const unsafe = inspected.values.some(({ info, attestation }) => info && !attestation.compatible);
  const coreCompatible = inspected.values.every(({ expected, info, attestation }) => !SERVICE_POLICIES[expected.service].requiredForEnable || Boolean(info && attestation.compatible));
  const lifecycleSafe = coreCompatible && !unsafe;
  const allStopped = lifecycleSafe && inspected.values.every(({ info, attestation }) => !info || attestation.compatible && info.State?.Running === false);
  const allHealthy = compatible && services.every((service) => service.healthy && service.running);
  const coreHealthy = coreCompatible && inspected.values.every(({ expected, info, attestation }) => !SERVICE_POLICIES[expected.service].requiredForEnable || attestation.compatible && healthOf(info) && info.State?.Running === true);
  const projectReadersHealthy = ["server-ai-project-source-reader", "server-ai-project-query-reader"].every(name => services.some(service => service.service === name && service.running && service.healthy));
  return { machineId: registry.machineId, compatible, coreCompatible, lifecycleSafe, missing: inspected.missing, services, allStopped, allHealthy, coreHealthy, projectReadersHealthy };
}

async function readAndInspect(options) {
  const registry = options.registry ?? readRegistry(options.registryPath);
  validateRegistry(registry);
  const hostMachineId = options.hostMachineId ?? readHostMachineId(options.machineIdPath);
  if (hostMachineId !== registry.machineId) throw fail("host machine identity does not match registry", 503);
  const inspected = await inspectAll({ ...options, registry, machineId: registry.machineId });
  return { registry, inspected, payload: statusPayload(registry, inspected) };
}

async function waitForService({ docker, expected, deadline, wantRunning, wantHealthy }) {
  while (remaining(deadline) > 0) {
    let info;
    try { info = await docker.inspectContainer(expected.name, remaining(deadline)); }
    catch {
      if (!wantRunning) return null;
      info = null;
    }
    const attestation = info && attestContainer(info, expected, expected.machineId);
    if (attestation?.compatible && info.State?.Running === wantRunning && (!wantHealthy || healthOf(info))) return info;
    await sleep(POLL_MS, deadline);
  }
  throw dockerFailure(`service ${expected.name} did not reach the requested state`, 504);
}

async function mutate(action, options) {
  const deadline = Date.now() + ACTION_DEADLINE_MS;
  const { registry, inspected, payload } = await readAndInspect({ ...options, deadline });
  if (action === "enable") {
    if (!payload.lifecycleSafe) throw fail("enable requires trusted core containers and no untrusted registered container", 409);
    for (const item of inspected.values) {
      if (remaining(deadline) <= 0) throw dockerFailure("enable deadline elapsed", 504);
      if (!item.info || !item.attestation.compatible) continue;
      item.expected.machineId = registry.machineId;
      if (item.info.State?.Running !== true) {
        await options.docker.startContainer(item.info.Id, remaining(deadline));
      }
    }
    // Docker health intervals must overlap; waiting before starting the next
    // service would spend three intervals inside a single action deadline.
    for (const item of inspected.values) {
      if (!SERVICE_POLICIES[item.expected.service].requiredForEnable) continue;
      await waitForService({ docker: options.docker, expected: item.expected, deadline, wantRunning: true, wantHealthy: true });
    }
  } else {
    const failures = [];
    for (const item of inspected.values) {
      item.expected.machineId = registry.machineId;
      if (!item.attestation.compatible || item.info?.State?.Running !== true) continue;
      try {
        await options.docker.stopContainer(item.info.Id, remaining(deadline));
        await waitForService({ docker: options.docker, expected: item.expected, deadline, wantRunning: false, wantHealthy: false });
      } catch (error) { failures.push({ service: item.expected.service, error }); }
    }
    const final = await readAndInspect({ ...options, deadline });
    if (!final.payload.allStopped || failures.length) throw dockerFailure("disable could not stop every trusted service", 502);
  }
  const final = await readAndInspect({ ...options, deadline });
  return final.payload;
}

function json(res, statusCode, value) {
  const body = Buffer.from(`${canonicalJson(value)}\n`);
  res.writeHead(statusCode, { "content-type": "application/json; charset=utf-8", "content-length": body.length, "cache-control": "no-store" });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(() => { reject(fail("request body timed out", 408)); req.destroy(); }, 3000);
    deadline.unref();
    let bytes = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_REQUEST_BYTES) {
        reject(fail("request body is oversized", 413));
        req.destroy();
      } else chunks.push(chunk);
    });
    req.on("end", () => { clearTimeout(deadline); resolve(Buffer.concat(chunks)); });
    req.on("error", error => { clearTimeout(deadline); reject(error); });
  });
}

export function createControllerServer({
  socketPath = CONTROLLER_SOCKET,
  registryPath = CONTROLLER_REGISTRY,
  machineIdPath = CONTROLLER_MACHINE_ID,
  dockerSocketPath = DOCKER_SOCKET,
  registry,
  hostMachineId,
  docker = createDockerApi(dockerSocketPath),
  logger = () => {},
} = {}) {
  let mutation = null;
  let activeRequests = 0;
  const handler = async (req, res) => {
    if (activeRequests >= 8) return json(res, 503, { error: "controller_busy" });
    activeRequests += 1;
    try {
      if (req.url !== "/status" && req.url !== "/enable" && req.url !== "/disable") throw fail("controller route is invalid", 404);
      if (req.headers.authorization !== undefined) throw fail("authorization headers are not accepted", 400);
      if (req.url === "/status") {
        if (req.method !== "GET") throw fail("status method is invalid", 405);
        const result = await readAndInspect({ registry, registryPath, machineIdPath, hostMachineId, docker, deadline: Date.now() + 3000 });
        return json(res, 200, result.payload);
      }
      if (req.method !== "POST") throw fail("controller method is invalid", 405);
      if (req.headers["content-type"] !== "application/json") throw fail("controller content type is invalid", 415);
      const body = parseControlRequest(await readBody(req));
      const selected = req.url.slice(1);
      const currentRegistry = registry ?? readRegistry(registryPath);
      if (body.machineId !== currentRegistry.machineId) throw fail("request machine identity does not match registry", 403);
      if (mutation) throw fail("another lifecycle mutation is active", 409);
      const run = mutate(selected, { registry: currentRegistry, registryPath, machineIdPath, hostMachineId, docker });
      mutation = run;
      try { return json(res, 200, await run); }
      finally { mutation = null; }
    } catch (error) {
      logger(error);
      if (!res.destroyed && !res.writableEnded) json(res, Number.isInteger(error?.statusCode) ? error.statusCode : 500, { error: "controller_request_rejected", message: error?.message || "controller request failed" });
    } finally { activeRequests -= 1; }
  };
  const server = http.createServer({ maxHeaderSize: 4096 }, handler);
  server.headersTimeout = 5000;
  server.requestTimeout = 5000;
  server.keepAliveTimeout = 1000;
  server.on("connection", (connection) => connection.setNoDelay(true));
  const start = () => new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      try { fs.chmodSync(socketPath, 0o660); } catch (error) { server.close(); reject(error); return; }
      resolve(server);
    });
  });
  const stop = () => new Promise((resolve) => server.close(resolve));
  return { server, start, stop };
}

async function main() {
  if (process.getuid?.() !== 1000) throw new Error("server-ai-controller must run as UID 1000");
  const existing = fs.lstatSync(CONTROLLER_SOCKET, { throwIfNoEntry: false });
  if (existing) {
    if (!existing.isSocket() || existing.uid !== 1000) throw new Error("Unsafe controller socket path.");
    const stale = await new Promise(resolve => {
      const socket = net.createConnection(CONTROLLER_SOCKET);
      socket.setTimeout(500, () => { socket.destroy(); resolve(false); });
      socket.once("connect", () => { socket.destroy(); resolve(false); });
      socket.once("error", error => resolve(error.code === "ECONNREFUSED"));
    });
    if (!stale) throw new Error("Controller socket is already active.");
    fs.unlinkSync(CONTROLLER_SOCKET);
  }
  const controller = createControllerServer();
  await controller.start();
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
