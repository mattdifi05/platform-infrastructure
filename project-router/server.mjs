import { createServer, request as httpRequest } from "node:http";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

const port = Number(process.env.PROJECT_ROUTER_PORT || 8080);
const projectsRoot = process.env.PROJECTS_ROOT || "/var/www/projects";
const stateFile = process.env.PROJECT_STATE_FILE || "/var/www/project-state/projects.json";
const controlCenterUpstream = new URL(process.env.CONTROL_CENTER_UPSTREAM || "http://control-center:8080");
const domain = normalizeHost(process.env.DOMAIN || process.env.LOCAL_DOMAIN || "localhost.com");
const adminHost = normalizeHost(process.env.ADMIN_HOST || `portal.${domain}`);
const controlCenterHost = normalizeHost(process.env.CONTROL_CENTER_HOST || process.env.PROJECTS_HOST || adminHost);
const hostSuffix = process.env.PROJECT_HOST_SUFFIX || ".localhost.com";
const nodeHosts = parsePairs(process.env.NODE_PROJECT_HOSTS || "");
const projectUpstreams = parsePairs(process.env.PROJECT_UPSTREAMS || "");
const phpProjectUpstreams = parsePairs(process.env.PHP_PROJECT_UPSTREAMS || "");
const nodeUpstreams = parsePairs(process.env.NODE_PROJECT_UPSTREAMS || "");
const staticUpstreams = parsePairs(process.env.STATIC_PROJECT_UPSTREAMS || "");
const projectConfigNames = [".platform/project.json", "platform.project.json"];

const server = createServer(async (req, res) => {
  try {
    const host = normalizeHost(req.headers.host || "");
    if (req.url === "/__health") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    if (!host || host === controlCenterHost || (process.env.PROJECTS_HOST && host === normalizeHost(process.env.PROJECTS_HOST))) {
      proxy(req, res, controlCenterUpstream);
      return;
    }

    const projects = discoverProjects();
    const slug = slugFromHost(host);
    const project = projects.find((item) => item.slug === slug || item.aliases?.includes(slug) || normalizeHost(item.host) === host);
    if (!project) {
      disabled(res, "Project not found", host);
      return;
    }

    if (!isEnabled(project)) {
      disabled(res, "Project disabled", host);
      return;
    }

    const upstream = dedicatedUpstreamFor(project);
    if (!upstream) {
      disabled(res, `${runtimeLabel(project.type)} project has no dedicated upstream`, host, 503);
      return;
    }
    proxy(req, res, upstream);
  } catch (error) {
    res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    res.end(`project-router error: ${error instanceof Error ? error.message : String(error)}\n`);
  }
});

server.listen(port, "0.0.0.0", () => {
  console.log(`project-router listening on ${port}`);
});

process.once("SIGTERM", () => server.close(() => process.exit(0)));
process.once("SIGINT", () => server.close(() => process.exit(0)));

function proxy(clientReq, clientRes, upstream) {
  const headers = { ...clientReq.headers };
  headers.host = clientReq.headers.host || upstream.host;
  headers["x-forwarded-host"] = clientReq.headers.host || "";
  headers["x-forwarded-proto"] = clientReq.headers["x-forwarded-proto"] || "https";

  const target = new URL(clientReq.url || "/", upstream);
  const proxyReq = httpRequest({
    protocol: upstream.protocol,
    hostname: upstream.hostname,
    port: upstream.port || 80,
    method: clientReq.method,
    path: `${target.pathname}${target.search}`,
    headers,
  }, (proxyRes) => {
    clientRes.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
    proxyRes.pipe(clientRes);
  });

  proxyReq.on("error", (error) => {
    clientRes.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
    clientRes.end(`upstream unavailable: ${error.message}\n`);
  });

  clientReq.pipe(proxyReq);
}

function dedicatedUpstreamFor(project) {
  const mapped = project.upstream || mappedProjectValue(projectUpstreams, project) || mappedProjectValue(upstreamMapForType(project.type), project);
  return mapped ? new URL(expandProjectValue(mapped, project)) : null;
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

function discoverProjects() {
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
    const config = readProjectConfig(projectPath);
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
        projects.push(project);
        seen.add(project.slug);
      }
      continue;
    }
    if (!isPhp && !isNode && !isStatic) continue;
    const type = configuredType || inferredProjectType({ isPhp, isNode, isStatic });
    projects.push({
      name: entry.name,
      slug,
      type,
      host: stringValue(config.host) || nodeHosts.get(slug) || `${slug}${hostSuffix}`,
      path: projectPath,
      aliases: [],
      upstream: configuredUpstream,
    });
    seen.add(slug);
  }
  return projects;
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

function readProjectConfig(projectPath) {
  for (const name of projectConfigNames) {
    const configPath = path.join(projectPath, name);
    if (!existsSync(configPath)) continue;
    try {
      return JSON.parse(readFileSync(configPath, "utf8"));
    } catch (error) {
      console.error(`invalid project config ${configPath}: ${error instanceof Error ? error.message : String(error)}`);
      return {};
    }
  }
  return {};
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
