import { createHash } from "node:crypto";
import {
  constants,
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { dirname } from "node:path";

export const PROJECT_ROUTER_HOST_EXTENSION_FILE = "/run/platform-host-extension/project-router.json";
export const PROJECT_ROUTER_HOST_EXTENSION_SCHEMA = "platform-project-router-host-extension/v1";
export const PLATFORM_RESERVED_PROJECT_SLUGS = Object.freeze([
  "admin",
  "api",
  "auth",
  "docs",
  "portal",
  "projects",
]);

const projectIdPattern = /^[a-z][a-z0-9-]{1,62}$/;
const serviceIdPattern = /^[a-z][a-z0-9-]{1,62}$/;
const extensionLimitBytes = 256 * 1024;

export function emptyProjectRouterHostExtension(hostSuffix) {
  return Object.freeze({
    hostSuffix: validateHostSuffix(hostSuffix),
    services: new Set(),
    routes: new Map(),
    projectUpstreams: new Map(),
  });
}

export function parseProjectRouterHostExtension(value, expectedHostSuffix) {
  assertExactKeys(value, ["hostSuffix", "routes", "schema", "services"]);
  if (value.schema !== PROJECT_ROUTER_HOST_EXTENSION_SCHEMA) {
    throw new Error("Project router host extension schema is unsupported.");
  }
  const hostSuffix = validateHostSuffix(value.hostSuffix);
  if (hostSuffix !== validateHostSuffix(expectedHostSuffix)) {
    throw new Error("Project router host extension suffix differs from the platform host suffix.");
  }
  if (!Array.isArray(value.services) || !Array.isArray(value.routes)) {
    throw new Error("Project router host extension inventories are invalid.");
  }

  const services = new Set();
  let previousService = "";
  for (const service of value.services) {
    if (typeof service !== "string" || !validServiceIdentity(service) || services.has(service)) {
      throw new Error("Project router host extension service inventory is invalid.");
    }
    if (previousService && service.localeCompare(previousService) <= 0) {
      throw new Error("Project router host extension service inventory is not canonical.");
    }
    previousService = service;
    services.add(service);
  }
  const routes = new Map();
  const projectUpstreams = new Map();
  let previousSlug = "";
  for (const route of value.routes) {
    assertExactKeys(route, ["port", "projectSlug", "service", "slug", "sourceSlug", "type"]);
    const { slug, sourceSlug, projectSlug, type, service, port } = route;
    if (!isProjectId(slug)
        || PLATFORM_RESERVED_PROJECT_SLUGS.includes(slug)
        || !isProjectId(sourceSlug)
        || !isProjectId(projectSlug)
        || !["node", "php", "static"].includes(type)
        || !isServiceId(service)
        || !Number.isInteger(port)
        || port < 1 || port > 65535
        || serviceTypePrefix(type) !== service.slice(0, serviceTypePrefix(type).length)
        || !services.has(`${service}:${port}`)
        || routes.has(slug)
        || (previousSlug && slug.localeCompare(previousSlug) <= 0)) {
      throw new Error("Project router host extension route violates the closed route contract.");
    }
    previousSlug = slug;
    const upstream = `http://${service}:${port}`;
    const owner = Object.freeze({ sourceSlug, projectSlug, type, service, port, upstream });
    routes.set(slug, owner);
    const projectKey = `${sourceSlug}/${projectSlug}/${type}`;
    const existing = projectUpstreams.get(projectKey);
    if (existing && existing.upstream !== upstream) {
      throw new Error("Project router host extension assigns a project to multiple upstreams.");
    }
    projectUpstreams.set(projectKey, owner);
  }
  const usedServices = new Set([...routes.values()].map(({ service, port }) => `${service}:${port}`));
  if (services.size !== usedServices.size || [...services].some((service) => !usedServices.has(service))) {
    throw new Error("Project router host extension contains an unowned service.");
  }
  return Object.freeze({ hostSuffix, services, routes, projectUpstreams });
}

export function loadProjectRouterHostExtension({
  filePath,
  expectedSha256,
  hostSuffix,
  testMode = false,
}) {
  const empty = emptyProjectRouterHostExtension(hostSuffix);
  if (!filePath) return empty;
  let descriptor;
  try {
    descriptor = openSync(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch (error) {
    if (error?.code === "ENOENT") return empty;
    throw new Error("Project router host extension cannot be opened safely.");
  }
  try {
    const before = fstatSync(descriptor);
    const pathStat = lstatSync(filePath);
    const parentStat = lstatSync(dirname(filePath));
    if (!before.isFile()
        || pathStat.isSymbolicLink()
        || (!testMode && before.uid !== 0)
        || (!testMode && (!parentStat.isDirectory() || parentStat.isSymbolicLink() || parentStat.uid !== 0
          || (parentStat.mode & 0o022) !== 0))
        || (before.mode & 0o222) !== 0
        || before.size < 2
        || before.size > extensionLimitBytes) {
      throw new Error("Project router host extension must be a root-owned, read-only regular file.");
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (before.dev !== after.dev
        || before.ino !== after.ino
        || before.size !== after.size
        || before.mtimeMs !== after.mtimeMs) {
      throw new Error("Project router host extension changed while being read.");
    }
    const actualSha256 = createHash("sha256").update(bytes).digest("hex");
    if (!/^[a-f0-9]{64}$/.test(String(expectedSha256 || "")) || actualSha256 !== expectedSha256) {
      throw new Error("Project router host extension digest differs from its deployment pin.");
    }
    let parsed;
    try {
      parsed = JSON.parse(bytes.toString("utf8"));
    } catch {
      throw new Error("Project router host extension is not valid JSON.");
    }
    return parseProjectRouterHostExtension(parsed, hostSuffix);
  } finally {
    closeSync(descriptor);
  }
}

function validateHostSuffix(value) {
  if (typeof value !== "string" || value !== value.toLowerCase() || !value.startsWith(".")
      || value.length > 200 || value.endsWith(".")) {
    throw new Error("Project router host suffix is invalid.");
  }
  const labels = value.slice(1).split(".");
  if (labels.length < 2 || labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new Error("Project router host suffix is invalid.");
  }
  return value;
}

function validServiceIdentity(value) {
  const separator = value.lastIndexOf(":");
  if (separator <= 0) return false;
  const service = value.slice(0, separator);
  const port = Number(value.slice(separator + 1));
  return isServiceId(service) && Number.isInteger(port) && port >= 1 && port <= 65535;
}

function isProjectId(value) {
  return typeof value === "string" && projectIdPattern.test(value);
}

function isServiceId(value) {
  return typeof value === "string" && serviceIdPattern.test(value);
}

function serviceTypePrefix(type) {
  if (type === "php") return "php-";
  if (type === "node") return "node-";
  return "static-";
}

function assertExactKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(expected)) {
    throw new Error("Project router host extension has unsupported fields.");
  }
}
