import { createServer, request as httpRequest } from "node:http";
import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
} from "node:fs";
import { isIP } from "node:net";
import path from "node:path";
import { createProjectMetadataReader, ProjectMetadataError } from "./project-metadata.mjs";
import { validateVerifiedWorkloadLock } from "./verified-workload-lock.mjs";
import { parseHostedRouteLock } from "./workload-route-lock.mjs";

const port = Number(process.env.PROJECT_ROUTER_PORT || 8080);
const projectsRoot = process.env.PROJECTS_ROOT || "/var/www/projects";
const stateFile = process.env.PROJECT_STATE_FILE || "/var/www/project-state/projects.json";
const workloadLockFile = process.env.PROJECT_ROUTER_WORKLOAD_LOCK_FILE || "/var/www/project-state/hosted-workloads.lock.json";
const workloadLockMode = explicitWorkloadLockMode(process.env.PROJECT_ROUTER_WORKLOAD_LOCK_MODE);
const workloadLockSha256 = String(process.env.PROJECT_ROUTER_WORKLOAD_LOCK_SHA256 || "").toLowerCase();
const testLoopbackAllowed = process.env.NODE_ENV === "test" && process.env.PROJECT_ROUTER_TEST_ALLOW_LOOPBACK === "true";
const testLegacyDiscoveryAllowed = process.env.NODE_ENV === "test" && process.env.PROJECT_ROUTER_TEST_ALLOW_LEGACY_DISCOVERY === "true";
const localPrivateCompatibilityRequested = explicitLocalPrivateCompatibilityMode(
  process.env.PROJECT_ROUTER_LOCAL_PRIVATE_COMPATIBILITY_MODE,
);
const upstreamTimeoutMs = boundedEnvironmentInteger("PROJECT_ROUTER_UPSTREAM_TIMEOUT_MS", 30_000, 50, 30_000);
const allowedUpstreams = parseAllowedUpstreams(process.env.PROJECT_ROUTER_ALLOWED_UPSTREAMS || "control-center:8080");
const controlCenterUpstream = validateUpstream(process.env.CONTROL_CENTER_UPSTREAM || "http://control-center:8080", "control-center");
const domain = normalizeHost(process.env.DOMAIN || process.env.LOCAL_DOMAIN || "localhost.com");
const adminHost = normalizeHost(process.env.ADMIN_HOST || `portal.${domain}`);
const controlCenterHost = normalizeHost(process.env.CONTROL_CENTER_HOST || process.env.PROJECTS_HOST || adminHost);
const hostSuffix = process.env.PROJECT_HOST_SUFFIX || ".localhost.com";
const legacyDiscoveryRequested = testLegacyDiscoveryAllowed || localPrivateCompatibilityRequested;
const nodeHosts = parsePairs(legacyDiscoveryRequested ? process.env.NODE_PROJECT_HOSTS || "" : "");
const projectUpstreams = parsePairs(legacyDiscoveryRequested ? process.env.PROJECT_UPSTREAMS || "" : "");
const phpProjectUpstreams = parsePairs(legacyDiscoveryRequested ? process.env.PHP_PROJECT_UPSTREAMS || "" : "");
const nodeUpstreams = parsePairs(legacyDiscoveryRequested ? process.env.NODE_PROJECT_UPSTREAMS || "" : "");
const staticUpstreams = parsePairs(legacyDiscoveryRequested ? process.env.STATIC_PROJECT_UPSTREAMS || "" : "");
const projectConfigNames = [".platform/project.json", "platform.project.json"];
const projectMetadataReader = createProjectMetadataReader({
  maxBytes: boundedEnvironmentInteger("PROJECT_METADATA_MAX_BYTES", 256 * 1024, 2, 1024 * 1024),
  maxDepth: boundedEnvironmentInteger("PROJECT_METADATA_MAX_DEPTH", 24, 1, 64),
  maxKeys: boundedEnvironmentInteger("PROJECT_METADATA_MAX_KEYS", 4096, 1, 100_000),
  maxNodes: boundedEnvironmentInteger("PROJECT_METADATA_MAX_NODES", 8192, 1, 200_000),
  maxAliases: boundedEnvironmentInteger("PROJECT_METADATA_MAX_ALIASES", 256, 0, 10_000),
  maxArrayItems: boundedEnvironmentInteger("PROJECT_METADATA_MAX_ARRAY_ITEMS", 2048, 1, 100_000),
  parseTimeoutMs: boundedEnvironmentInteger("PROJECT_METADATA_PARSE_TIMEOUT_MS", 500, 1, 5000),
  maxCacheEntries: boundedEnvironmentInteger("PROJECT_METADATA_CACHE_ENTRIES", 256, 1, 4096),
});
const localPrivateCompatibilityContract = Object.freeze({
  hostSuffix: ".platform-infrastructure.com",
  nodeUpstreams: Object.freeze([
    ["account", "http://node-account:3000"],
    ["opstudents", "http://node-opstudents:3000"],
    ["ui", "http://node-ui:3000"],
  ]),
  phpUpstreams: Object.freeze([
    ["anniversary", "http://php-anniversary:80"],
    ["fiplatform", "http://php-fiplatform:80"],
    ["fireport", "http://php-fiplatform:80"],
    ["matthewdifilippo", "http://php-matthewdifilippo:80"],
    ["stream", "http://php-stream:80"],
    ["workcalendar", "http://php-workcalendar:80"],
  ]),
  allowedUpstreams: Object.freeze([
    "control-center:8080",
    "node-account:3000",
    "node-opstudents:3000",
    "node-ui:3000",
    "php-anniversary:80",
    "php-fiplatform:80",
    "php-matthewdifilippo:80",
    "php-stream:80",
    "php-workcalendar:80",
  ]),
  routeOwnership: Object.freeze([
    Object.freeze(["account", "stexor", "account", "node"]),
    Object.freeze(["anniversary", "anniversary", "anniversary", "php"]),
    Object.freeze(["fiplatform", "fiplatform", "fiplatform", "php"]),
    Object.freeze(["fireport", "fiplatform", "fiplatform", "php"]),
    Object.freeze(["matthewdifilippo", "matthewdifilippo", "matthewdifilippo", "php"]),
    Object.freeze(["opstudents", "opstudents", "opstudents", "node"]),
    Object.freeze(["stream", "stream", "stream", "php"]),
    Object.freeze(["ui", "stexor", "ui", "node"]),
    Object.freeze(["workcalendar", "workcalendar", "workcalendar", "php"]),
  ]),
  reservedPlatformSlugs: Object.freeze([
    "admin",
    "api",
    "auth",
    "docs",
    "portal",
    "projects",
  ]),
});
const localPrivateRouteOwnership = new Map(
  localPrivateCompatibilityContract.routeOwnership.map(
    ([routeSlug, sourceSlug, projectSlug, type]) => [
      routeSlug,
      Object.freeze({ sourceSlug, projectSlug, type }),
    ],
  ),
);
let workloadRouteCache = {
  key: "",
  byHost: new Map(),
  allowed: new Set(),
  trustedEpoch: "",
  projectMetadata: new Map(),
  localPrivateCompatibilityAllowed: false,
};

const server = createServer(async (req, res) => {
  try {
    const host = normalizeHost(req.headers.host || "");
    if (req.url === "/__health") {
      assertPinnedLockUnchanged();
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    if (!host || host === controlCenterHost || (process.env.PROJECTS_HOST && host === normalizeHost(process.env.PROJECTS_HOST))) {
      proxy(req, res, controlCenterUpstream);
      return;
    }

    const workloadRoutes = workloadRoutesFromLock();
    const lockedRoute = workloadRoutes.byHost.get(host);
    if (lockedRoute) {
      if (!isEnabled(lockedRoute)) {
        disabled(res, "Project disabled", host);
        return;
      }
      proxy(req, res, validateUpstream(lockedRoute.upstream, lockedRoute.slug, workloadRoutes.allowed));
      return;
    }

    if (!testLegacyDiscoveryAllowed && !workloadRoutes.localPrivateCompatibilityAllowed) {
      disabled(res, "Project not found", host);
      return;
    }

    const projects = await discoverProjects(workloadRoutes);
    const slug = workloadRoutes.localPrivateCompatibilityAllowed
      ? localPrivateRouteSlugFromHost(host)
      : slugFromHost(host);
    if (!slug) {
      disabled(res, "Project not found", host);
      return;
    }
    const project = projects.find((item) => item.slug === slug)
      || projects.find((item) => item.aliases?.includes(slug) || normalizeHost(item.host) === host);
    if (!project) {
      disabled(res, "Project not found", host);
      return;
    }

    if (!isEnabled(project)) {
      disabled(res, "Project disabled", host);
      return;
    }

    const upstream = dedicatedUpstreamFor(project, workloadRoutes);
    if (!upstream) {
      disabled(res, `${runtimeLabel(project.type)} project has no dedicated upstream`, host, 503);
      return;
    }
    proxy(req, res, upstream);
  } catch {
    console.error("project-router request failed");
    res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    res.end("internal proxy error\n");
  }
});

workloadRoutesFromLock();
server.listen(port, "0.0.0.0", () => {
  console.log(`project-router listening on ${port}`);
});

process.once("SIGTERM", () => server.close(() => process.exit(0)));
process.once("SIGINT", () => server.close(() => process.exit(0)));

function proxy(clientReq, clientRes, upstream) {
  const requestPath = safeProxyPath(clientReq.url || "/");
  if (!requestPath) {
    clientRes.writeHead(400, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
    clientRes.end("invalid request target\n");
    return;
  }
  const headers = { ...clientReq.headers };
  headers.host = clientReq.headers.host || upstream.host;
  headers["x-forwarded-host"] = clientReq.headers.host || "";
  headers["x-forwarded-proto"] = clientReq.headers["x-forwarded-proto"] || "https";

  let upstreamFailureHandled = false;
  const failUpstream = (error) => {
    if (upstreamFailureHandled) return;
    upstreamFailureHandled = true;
    console.error(`project upstream request failed for ${upstream.hostname}:${upstream.port || 80}: ${error?.code || "request-error"}`);
    if (clientRes.destroyed || clientRes.writableEnded) return;
    if (clientRes.headersSent) {
      clientRes.destroy();
      return;
    }
    clientRes.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
    clientRes.end("upstream unavailable\n");
  };

  const proxyReq = httpRequest({
    protocol: upstream.protocol,
    hostname: upstream.hostname,
    port: upstream.port || 80,
    method: clientReq.method,
    path: requestPath,
    headers,
  }, (proxyRes) => {
    proxyRes.once("aborted", () => failUpstream(new Error("upstream response aborted")));
    proxyRes.once("error", failUpstream);
    if (clientRes.destroyed || clientRes.writableEnded) {
      proxyRes.destroy();
      return;
    }
    clientRes.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
    proxyRes.pipe(clientRes);
  });

  proxyReq.once("error", failUpstream);
  const wallClockTimeout = setTimeout(() => proxyReq.destroy(new Error("upstream timeout")), upstreamTimeoutMs);
  wallClockTimeout.unref();
  proxyReq.once("close", () => clearTimeout(wallClockTimeout));
  proxyReq.setTimeout(upstreamTimeoutMs, () => proxyReq.destroy(new Error("upstream timeout")));

  clientReq.pipe(proxyReq);
}

function dedicatedUpstreamFor(project, workloadRoutes) {
  const compatibilityMapped = mappedProjectValue(projectUpstreams, project)
    || mappedProjectValue(upstreamMapForType(project.type), project);
  const mapped = workloadRoutes.localPrivateCompatibilityAllowed
    ? compatibilityMapped
    : project.upstream || compatibilityMapped;
  if (!mapped) return null;
  try {
    const expanded = expandProjectValue(mapped, project);
    const candidate = new URL(expanded);
    if (workloadRoutes.allowed.has(`${candidate.hostname.toLowerCase()}:${Number(candidate.port || 80)}`)) {
      throw new Error("Unsigned project metadata cannot claim a hosted workload endpoint.");
    }
    return validateUpstream(expanded, project.slug);
  } catch {
    console.error(`rejected project upstream for ${project.slug}: service allowlist policy violation`);
    return null;
  }
}

function safeProxyPath(value) {
  const requestTarget = String(value || "");
  if (!requestTarget.startsWith("/") || requestTarget.startsWith("//") || requestTarget.includes("\\")) return "";
  if (/^[a-z][a-z0-9+.-]*:/i.test(requestTarget.slice(1))) return "";
  try {
    const parsed = new URL(requestTarget, "http://router.invalid");
    if (parsed.origin !== "http://router.invalid") return "";
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return "";
  }
}

function parseAllowedUpstreams(value) {
  const allowed = new Set();
  for (const item of String(value || "").split(",")) {
    const token = item.trim().toLowerCase();
    if (!token) continue;
    if (token.includes("://") || token.includes("/") || token.includes("@")) throw new Error("Upstream allowlist entries must be service-id:port.");
    const separator = token.lastIndexOf(":");
    const hostname = separator > 0 ? token.slice(0, separator) : token;
    const portValue = separator > 0 ? token.slice(separator + 1) : "80";
    if (!validUpstreamHost(hostname) || !validPort(portValue)) throw new Error("Invalid upstream allowlist entry.");
    allowed.add(`${hostname}:${Number(portValue)}`);
  }
  if (!allowed.size) throw new Error("Project router upstream allowlist is empty.");
  return allowed;
}

function validateLocalPrivateCompatibility(lock) {
  const expectedLockKeys = [
    "brokerPolicySha256", "coreSemanticPolicy", "projectName", "protectedResourceNames",
    "routes", "state", "validatorVersion", "version", "workloads",
  ];
  const protectedResources = lock?.protectedResourceNames;
  if (workloadLockMode !== "required"
      || !/^[a-f0-9]{64}$/.test(workloadLockSha256)
      || JSON.stringify(Object.keys(lock || {}).sort()) !== JSON.stringify(expectedLockKeys)
      || lock.version !== 4
      || lock.validatorVersion !== "hosted-contract-v4"
      || lock.state !== "verified"
      || lock.projectName !== "platform_infra_vps"
      || lock.brokerPolicySha256 !== "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
      || JSON.stringify(lock.routes) !== "[]"
      || JSON.stringify(lock.workloads) !== "[]"
      || JSON.stringify(Object.keys(lock.coreSemanticPolicy || {}).sort()) !== JSON.stringify(["schema", "sha256"])
      || lock.coreSemanticPolicy.schema !== "platform-no-hosted-core-capability-policy/v2"
      || !/^[a-f0-9]{64}$/.test(String(lock.coreSemanticPolicy.sha256 || ""))
      || JSON.stringify(Object.keys(protectedResources || {}).sort()) !== JSON.stringify(["configs", "networks", "secrets", "services", "volumes"])
      || Object.values(protectedResources).some((names) => !Array.isArray(names)
        || JSON.stringify(names) !== JSON.stringify([...new Set(names)].sort())
        || names.some((name) => typeof name !== "string" || name.length === 0))) {
    throw new Error("LOCAL_PRIVATE compatibility requires the exact pinned zero-workload lock.");
  }

  const exactPairs = (map) => [...map.entries()].sort(([left], [right]) => left.localeCompare(right));
  const fixedRouteSlugs = [...new Set([
    ...localPrivateCompatibilityContract.nodeUpstreams.map(([slug]) => slug),
    ...localPrivateCompatibilityContract.phpUpstreams.map(([slug]) => slug),
  ])].sort();
  if (hostSuffix !== localPrivateCompatibilityContract.hostSuffix
      || nodeHosts.size !== 0
      || projectUpstreams.size !== 0
      || staticUpstreams.size !== 0
      || JSON.stringify(exactPairs(nodeUpstreams)) !== JSON.stringify(localPrivateCompatibilityContract.nodeUpstreams)
      || JSON.stringify(exactPairs(phpProjectUpstreams)) !== JSON.stringify(localPrivateCompatibilityContract.phpUpstreams)
      || JSON.stringify([...allowedUpstreams].sort()) !== JSON.stringify(localPrivateCompatibilityContract.allowedUpstreams)
      || JSON.stringify([...localPrivateRouteOwnership.keys()].sort()) !== JSON.stringify(fixedRouteSlugs)
      || localPrivateCompatibilityContract.reservedPlatformSlugs.some((slug) =>
        localPrivateRouteOwnership.has(slug))
      || controlCenterUpstream.hostname !== "control-center"
      || Number(controlCenterUpstream.port || 80) !== 8080) {
    throw new Error("LOCAL_PRIVATE compatibility route authority differs from the closed V1 map.");
  }
  return true;
}

function validateUpstream(value, label, additionalAllowed = new Set()) {
  let upstream;
  try {
    upstream = new URL(String(value || ""));
  } catch {
    throw new Error(`Invalid upstream URL for ${label}.`);
  }
  const hostname = upstream.hostname.toLowerCase();
  const port = Number(upstream.port || 80);
  if (upstream.protocol !== "http:") throw new Error(`Only internal HTTP upstreams are allowed for ${label}.`);
  if (upstream.username || upstream.password || upstream.search || upstream.hash) throw new Error(`Upstream credentials, query and fragment are forbidden for ${label}.`);
  if (upstream.pathname !== "/") throw new Error(`Upstream base paths are forbidden for ${label}.`);
  if (!validUpstreamHost(hostname) || !validPort(port)) throw new Error(`Invalid upstream service for ${label}.`);
  if (!allowedUpstreams.has(`${hostname}:${port}`) && !additionalAllowed.has(`${hostname}:${port}`)) throw new Error(`Upstream service is not allowlisted for ${label}.`);
  return new URL(`http://${hostname}:${port}/`);
}

function workloadRoutesFromLock() {
  if (workloadRouteCache.key) return workloadRouteCache;
  if (!existsSync(workloadLockFile)) {
    if (workloadLockMode === "required") throw new Error("Required hosted workload lock is unavailable.");
    workloadRouteCache = emptyWorkloadRoutes();
    return workloadRouteCache;
  }
  const bytes = readStableLockFile(workloadLockFile);
  const key = createHash("sha256").update(bytes).digest("hex");
  if (workloadLockMode === "required" && !/^[a-f0-9]{64}$/.test(workloadLockSha256)) {
    throw new Error("Hosted workload lock expected digest is missing.");
  }
  if (workloadLockSha256 && (!/^[a-f0-9]{64}$/.test(workloadLockSha256) || key !== workloadLockSha256)) {
    throw new Error("Hosted workload lock digest differs from the activated receipt.");
  }
  const lock = JSON.parse(bytes.toString("utf8"));
  const parsed = parseHostedRouteLock(lock);
  const localPrivateCompatibilityAllowed = localPrivateCompatibilityRequested
    ? validateLocalPrivateCompatibility(lock)
    : false;
  const verified = lock.workloads.length > 0
    ? validateVerifiedWorkloadLock(lock)
    : { trustedEpoch: key, projectMetadata: new Map() };
  const byHost = new Map();
  const names = new Map();
  const upstreams = new Map();
  const allowed = new Set();
  for (const route of lock.routes) {
    assertExactKeys(route, ["aliases", "canonicalHost", "hosts", "owner", "port", "service", "slug", "upstream", "workloadId"]);
    const owner = String(route?.owner ?? "").toLowerCase();
    const workloadId = String(route?.workloadId ?? "").toLowerCase();
    const slug = String(route?.slug ?? "").toLowerCase();
    const service = String(route?.service ?? "").toLowerCase();
    const port = Number(route?.port);
    const canonicalHost = exactDnsHost(route?.canonicalHost);
    const aliases = exactSlugArray(route?.aliases);
    const suffix = canonicalHost.split(".").slice(1).join(".");
    const expectedHosts = [canonicalHost, ...aliases.map((alias) => suffix ? `${alias}.${suffix}` : alias)];
    const hosts = exactHostArray(route?.hosts);
    if (!validId(owner)
      || !validId(workloadId)
      || owner !== workloadId
      || !validId(slug)
      || canonicalHost.split(".")[0] !== slug
      || JSON.stringify(hosts) !== JSON.stringify(expectedHosts)
      || !validId(service)
      || !service.startsWith(`${workloadId}-`)
      || !validPort(port)
      || route.upstream !== `http://${service}:${port}`) {
      throw new Error("Hosted workload route violates the verified lock contract.");
    }
    const identity = `${workloadId}/${service}/${slug}`;
    if (parsed.routes.get(slug) !== route.upstream) {
      throw new Error("Hosted workload route differs from its policy-bound lineage.");
    }
    for (const name of [slug, ...aliases]) claimRouteValue(names, name, identity);
    for (const host of hosts) claimRouteValue(byHost, host, { ...route, owner, workloadId, slug, aliases, canonicalHost, hosts, service, port });
    claimRouteValue(upstreams, `${service}:${port}`, identity);
    allowed.add(`${service}:${port}`);
  }
  if (parsed.routes.size !== lock.routes.length
      || JSON.stringify([...parsed.allowed].sort()) !== JSON.stringify([...allowed].sort())) {
    throw new Error("Hosted workload route inventory differs from its policy-bound lineage.");
  }
  workloadRouteCache = {
    key,
    byHost,
    allowed,
    trustedEpoch: verified.trustedEpoch,
    projectMetadata: verified.projectMetadata,
    localPrivateCompatibilityAllowed,
  };
  return workloadRouteCache;
}

function assertPinnedLockUnchanged() {
  if (!workloadRouteCache.key) throw new Error("Hosted workload route snapshot was not initialized.");
  if (workloadRouteCache.key === "missing") {
    if (existsSync(workloadLockFile)) throw new Error("Hosted workload lock appeared after startup.");
    return;
  }
  if (!existsSync(workloadLockFile)) throw new Error("Hosted workload lock disappeared after startup.");
  const currentKey = createHash("sha256").update(readStableLockFile(workloadLockFile)).digest("hex");
  if (currentKey !== workloadRouteCache.key) throw new Error("Hosted workload lock changed after startup.");
}

function emptyWorkloadRoutes() {
  return {
    key: "missing",
    byHost: new Map(),
    allowed: new Set(),
    trustedEpoch: "",
    projectMetadata: new Map(),
    localPrivateCompatibilityAllowed: false,
  };
}

function readStableLockFile(filePath) {
  let descriptor;
  try {
    descriptor = openSync(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(descriptor);
    if (!before.isFile() || ![0o400, 0o600].includes(before.mode & 0o777)
      || before.size < 2 || before.size > 1024 * 1024) throw new Error("Invalid hosted workload lock file.");
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
      throw new Error("Hosted workload lock changed while being read.");
    }
    return bytes;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function assertExactKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(expected)) {
    throw new Error("Hosted workload route has unsupported fields.");
  }
}

function exactSlugArray(value) {
  if (!Array.isArray(value)) throw new Error("Hosted workload route aliases are invalid.");
  const normalized = value.map((item) => String(item));
  if (normalized.some((item) => !validId(item)) || JSON.stringify(normalized) !== JSON.stringify([...new Set(normalized)].sort())) {
    throw new Error("Hosted workload route aliases are invalid.");
  }
  return normalized;
}

function exactHostArray(value) {
  if (!Array.isArray(value) || value.length === 0) throw new Error("Hosted workload route hosts are invalid.");
  return value.map((item) => exactDnsHost(item));
}

function exactDnsHost(value) {
  const host = String(value ?? "");
  if (host !== host.toLowerCase() || host.endsWith(".") || host.length > 253 || host.includes(":") || host.includes("*")) {
    throw new Error("Hosted workload route host is invalid.");
  }
  if (host.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new Error("Hosted workload route host is invalid.");
  }
  return host;
}

function claimRouteValue(registry, key, value) {
  if (registry.has(key)) throw new Error("Hosted workload lock has duplicate global route ownership.");
  registry.set(key, value);
}

function validId(value) {
  return /^[a-z][a-z0-9-]{1,62}$/.test(value);
}

function validUpstreamHost(hostname) {
  if (testLoopbackAllowed && (hostname === "127.0.0.1" || hostname === "localhost")) return true;
  if (isIP(hostname) !== 0 || hostname === "localhost" || hostname === "host.docker.internal") return false;
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(hostname);
}

function validPort(value) {
  const portNumber = Number(value);
  return Number.isInteger(portNumber) && portNumber >= 1 && portNumber <= 65535;
}

function upstreamMapForType(type) {
  if (type === "php") return phpProjectUpstreams;
  if (type === "node") return nodeUpstreams;
  if (type === "static") return staticUpstreams;
  return new Map();
}

function runtimeLabel(type) {
  if (type === "php") return "PHP";
  if (type === "static") return "Static";
  return "Node";
}

function mappedProjectValue(map, project) {
  for (const slug of projectSlugs(project)) {
    const mapped = map.get(slug);
    if (mapped) return mapped;
  }
  return "";
}

async function discoverProjects(workloadRoutes = emptyWorkloadRoutes()) {
  if (!existsSync(projectsRoot)) return [];
  const projects = [];
  const seen = new Set();
  for (const entry of readdirSync(projectsRoot, { withFileTypes: true })) {
    if (entry.name === "." || entry.name === "..") continue;
    const slug = slugify(entry.name);
    if (!slug || seen.has(slug) || ["public", "node-modules", "vendor"].includes(slug)) continue;
    const projectPath = path.join(projectsRoot, entry.name);
    if (!safeIsDirectory(projectPath)) continue;
    const isPhp = isPhpProject(projectPath);
    const isNode = existsSync(path.join(projectPath, "package.json"));
    const isStatic = isStaticProject(projectPath);
    let config;
    try {
      config = await readProjectConfig(projectPath, workloadRoutes);
    } catch (error) {
      const code = error instanceof ProjectMetadataError ? error.code : "PROJECT_METADATA_REJECTED";
      console.error(`rejected project metadata for ${slug}: ${code}`);
      continue;
    }
    const configuredType = normalizeProjectType(config.type);
    const configuredUpstream = stringValue(config.upstream);
    const configuredProjects = configuredProjectEntries(config);
    if (configuredProjects.length > 0) {
      const baseAlias = configuredProjects.length === 1 ? slug : "";
      for (const item of configuredProjects) {
        const project = configuredProjectFromEntry({
          item,
          baseConfig: config,
          basePath: projectPath,
          baseSlug: slug,
          baseAlias,
          fallbackType: configuredType || inferredProjectType({ isPhp, isNode, isStatic }),
          fallbackUpstream: configuredUpstream,
        });
        if (!project || seen.has(project.slug)) continue;
        if (!localPrivateProjectOwnershipAllowed(project, workloadRoutes)) {
          console.error("rejected LOCAL_PRIVATE project metadata ownership");
          continue;
        }
        projects.push(project);
        seen.add(project.slug);
      }
      continue;
    }
    if (!isPhp && !isNode && !isStatic) continue;
    const type = configuredType || inferredProjectType({ isPhp, isNode, isStatic });
    const project = {
      name: entry.name,
      slug,
      type,
      host: stringValue(config.host) || nodeHosts.get(slug) || `${slug}${hostSuffix}`,
      path: projectPath,
      aliases: [],
      upstream: configuredUpstream,
      parentSlug: slug,
    };
    if (!localPrivateProjectOwnershipAllowed(project, workloadRoutes)) {
      console.error("rejected LOCAL_PRIVATE project metadata ownership");
      continue;
    }
    projects.push(project);
    seen.add(slug);
  }
  return projects;
}

function localPrivateProjectOwnershipAllowed(project, workloadRoutes) {
  if (!workloadRoutes.localPrivateCompatibilityAllowed) return true;
  const routeSlugs = projectSlugs(project);
  const parentSlug = slugify(project.parentSlug);
  if (routeSlugs.length === 0
      || normalizeHost(project.host) !== `${project.slug}${localPrivateCompatibilityContract.hostSuffix}`) {
    return false;
  }
  return routeSlugs.every((routeSlug) => {
    if (localPrivateCompatibilityContract.reservedPlatformSlugs.includes(routeSlug)) return false;
    const owner = localPrivateRouteOwnership.get(routeSlug);
    return owner !== undefined
      && owner.sourceSlug === parentSlug
      && owner.projectSlug === project.slug
      && owner.type === project.type;
  });
}

function configuredProjectEntries(config) {
  if (Array.isArray(config.projects)) return config.projects;
  if (Array.isArray(config.surfaces)) return config.surfaces;
  return [];
}

function configuredProjectFromEntry({ item, baseConfig, basePath, baseSlug, baseAlias, fallbackType, fallbackUpstream }) {
  if (!item || typeof item !== "object" || Array.isArray(item)) return null;
  const slug = slugify(item.slug || item.id || item.name);
  if (!slug || ["public", "node-modules", "vendor"].includes(slug)) return null;
  const projectPath = resolveProjectPath(basePath, item.path);
  if (!safeIsDirectory(projectPath)) return null;
  const type = normalizeProjectType(item.type) || fallbackType || "node";
  const upstream = stringValue(item.upstream) || fallbackUpstream;
  return {
    name: stringValue(item.name) || slug,
    slug,
    type,
    host: stringValue(item.host) || nodeHosts.get(slug) || `${slug}${hostSuffix}`,
    path: projectPath,
    aliases: projectAliases({ item, baseConfig, baseAlias, slug }),
    upstream,
    parentSlug: baseSlug,
  };
}

function projectAliases({ item, baseConfig, baseAlias, slug }) {
  return Array.from(new Set([
    baseAlias,
    ...arrayOfStrings(baseConfig.aliases),
    ...arrayOfStrings(item.aliases),
  ]
    .map(slugify)
    .filter((alias) => alias && alias !== slug)));
}

function resolveProjectPath(basePath, value) {
  const requested = stringValue(value);
  if (!requested) return basePath;
  const resolved = path.resolve(basePath, requested);
  return resolved === basePath || resolved.startsWith(`${basePath}${path.sep}`) ? resolved : basePath;
}

async function readProjectConfig(projectPath, workloadRoutes) {
  for (const name of projectConfigNames) {
    const configPath = path.join(projectPath, name);
    if (!existsSync(configPath)) continue;
    const signed = workloadRoutes.projectMetadata.get(metadataSourceIdentity(configPath));
    if (signed) {
      return projectMetadataReader.read(signed.path, {
        expectedSha256: signed.sha256,
        expectedSizeBytes: signed.sizeBytes,
        trustedEpoch: workloadRoutes.trustedEpoch,
      });
    }
    if (workloadLockMode === "required" && !workloadRoutes.localPrivateCompatibilityAllowed) {
      throw new ProjectMetadataError("Project metadata is absent from the verified workload lock.", "PROJECT_METADATA_UNSIGNED");
    }
    return projectMetadataReader.read(configPath);
  }
  return {};
}

function metadataSourceIdentity(configPath) {
  const stat = lstatSync(configPath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new ProjectMetadataError("Project metadata must be a regular non-symlink file.", "PROJECT_METADATA_FILE_TYPE");
  }
  return path.join(realpathSync.native(path.dirname(configPath)), path.basename(configPath));
}

function boundedEnvironmentInteger(name, fallback, minimum, maximum) {
  const value = process.env[name] == null || process.env[name] === "" ? fallback : Number(process.env[name]);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}.`);
  }
  return value;
}

function explicitWorkloadLockMode(value) {
  const mode = String(value || "").trim().toLowerCase();
  if (mode !== "required" && mode !== "optional") {
    throw new Error("PROJECT_ROUTER_WORKLOAD_LOCK_MODE must be explicitly set to required or optional.");
  }
  return mode;
}

function explicitLocalPrivateCompatibilityMode(value) {
  const mode = String(value || "").trim().toLowerCase();
  if (mode === "") return false;
  if (mode !== "true") {
    throw new Error("PROJECT_ROUTER_LOCAL_PRIVATE_COMPATIBILITY_MODE must be omitted or true.");
  }
  return true;
}

function stringValue(value) {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeProjectType(value) {
  const normalized = stringValue(value).toLowerCase();
  return normalized === "php" || normalized === "node" || normalized === "static" ? normalized : "";
}

function inferredProjectType({ isPhp, isNode, isStatic }) {
  if (isPhp) return "php";
  if (isNode) return "node";
  if (isStatic) return "static";
  return "";
}

function arrayOfStrings(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === "string") : [];
}

function expandProjectValue(value, project) {
  return String(value)
    .replaceAll("${PROJECT_SLUG}", project.slug)
    .replaceAll("${PROJECT_HOST}", project.host)
    .replaceAll("${PROJECT_HOST_SUFFIX}", hostSuffix)
    .replaceAll("${DOMAIN}", domain);
}

function isPhpProject(projectPath) {
  if (existsSync(path.join(projectPath, "composer.json"))) return true;
  if (existsSync(path.join(projectPath, "public", "index.php"))) return true;
  if (existsSync(path.join(projectPath, "index.php"))) return true;
  try {
    return readdirSync(path.join(projectPath, "public")).some((name) => name.endsWith(".php"));
  } catch {
    return false;
  }
}

function isStaticProject(projectPath) {
  if (existsSync(path.join(projectPath, "public", "index.html"))) return true;
  if (existsSync(path.join(projectPath, "index.html"))) return true;
  return false;
}

function isEnabled(projectOrSlug) {
  const state = readState();
  return !projectSlugs(projectOrSlug).some((slug) => state.projects?.[slug]?.enabled === false);
}

function projectSlugs(projectOrSlug) {
  if (typeof projectOrSlug === "string") return [projectOrSlug];
  return [projectOrSlug.slug, ...(projectOrSlug.aliases || [])].filter(Boolean);
}

function readState() {
  try {
    return JSON.parse(readFileSync(stateFile, "utf8"));
  } catch {
    return { projects: {} };
  }
}

function disabled(res, title, host, status = 404) {
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(`<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title><style>body{margin:0;background:#0b1117;color:#eef5ff;font-family:system-ui;display:grid;place-items:center;min-height:100vh}.box{max-width:560px;padding:28px;border:1px solid #263547;border-radius:10px;background:#121a23}a{color:#76e4c5}</style></head><body><div class="box"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(host)} is managed from the Admin Control Center.</p><p><a href="https://${escapeHtml(controlCenterHost)}/">Open Control Center</a></p></div></body></html>`);
}

function parsePairs(value) {
  const pairs = new Map();
  for (const item of value.split(",")) {
    const trimmed = item.trim();
    if (!trimmed) continue;
    const separatorIndex = trimmed.includes("=") ? trimmed.indexOf("=") : trimmed.indexOf(":");
    if (separatorIndex <= 0) continue;
    const key = slugify(trimmed.slice(0, separatorIndex));
    const val = trimmed.slice(separatorIndex + 1).trim();
    if (key && val) pairs.set(key, val);
  }
  return pairs;
}

function slugFromHost(host) {
  for (const [slug, mappedHost] of nodeHosts) {
    if (normalizeHost(mappedHost) === host) return slug;
  }
  return slugify(host.endsWith(hostSuffix) ? host.slice(0, -hostSuffix.length) : host.split(".")[0] || "");
}

function localPrivateRouteSlugFromHost(host) {
  const suffix = localPrivateCompatibilityContract.hostSuffix;
  if (!host.endsWith(suffix)) return "";
  const slug = host.slice(0, -suffix.length);
  if (!slug || slug.includes(".") || !localPrivateRouteOwnership.has(slug)) return "";
  return slug;
}

function normalizeHost(host) {
  return host.toLowerCase().replace(/:\d+$/, "");
}

function slugify(value) {
  return String(value).trim().toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "");
}

function safeIsDirectory(value) {
  try {
    return statSync(value).isDirectory();
  } catch {
    return false;
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#039;",
  }[char]));
}
