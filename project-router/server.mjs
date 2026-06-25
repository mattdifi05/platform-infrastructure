import { createServer, request as httpRequest } from "node:http";
import { spawn } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { connect } from "node:net";
import path from "node:path";

const port = Number(process.env.PROJECT_ROUTER_PORT || 8080);
const projectsRoot = process.env.PROJECTS_ROOT || "/var/www/projects";
const stateFile = process.env.PROJECT_STATE_FILE || "/var/www/project-state/projects.json";
const phpUpstream = new URL(process.env.PHP_UPSTREAM || "http://php-apache:80");
const controlCenterUpstream = new URL(process.env.CONTROL_CENTER_UPSTREAM || "http://control-center:8080");
const hostSuffix = process.env.PROJECT_HOST_SUFFIX || ".localhost.com";
const nodeHosts = parsePairs(process.env.NODE_PROJECT_HOSTS || "");
const nodeUpstreams = parsePairs(process.env.NODE_PROJECT_UPSTREAMS || "");
const nodeCommands = parsePairs(process.env.NODE_PROJECT_COMMANDS || "");
const managed = new Map();

const server = createServer(async (req, res) => {
  try {
    const host = normalizeHost(req.headers.host || "");
    if (req.url === "/__health") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    if (!host || host === normalizeHost(process.env.PROJECTS_HOST || "projects.localhost.com")) {
      proxy(req, res, controlCenterUpstream);
      return;
    }

    const slug = slugFromHost(host);
    const projects = discoverProjects();
    const project = projects.find((item) => item.slug === slug);
    if (!project) {
      disabled(res, "Project not found", host);
      return;
    }

    if (!isEnabled(slug)) {
      disabled(res, "Project disabled", host);
      return;
    }

    if (project.type === "php") {
      proxy(req, res, phpUpstream);
      return;
    }

    const upstream = await nodeUpstream(project);
    if (!upstream) {
      disabled(res, "Node project has no runnable command", host, 503);
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

setInterval(stopDisabledProcesses, 10000).unref();

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

async function nodeUpstream(project) {
  const mapped = nodeUpstreams.get(project.slug);
  if (mapped) return new URL(mapped);

  const existing = managed.get(project.slug);
  if (existing?.process && !existing.process.killed) {
    return new URL(`http://127.0.0.1:${existing.port}`);
  }

  const command = nodeCommands.get(project.slug) || defaultNodeCommand(project.path);
  if (!command) return null;

  const processPort = availableProjectPort(project.slug);
  const child = spawn(command, {
    cwd: project.path,
    shell: true,
    env: {
      ...process.env,
      PORT: String(processPort),
      HOST: "0.0.0.0",
      HOSTNAME: "0.0.0.0",
      NODE_ENV: process.env.NODE_PROJECT_ENV || "development",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  child.stdout.on("data", (chunk) => process.stdout.write(`[${project.slug}] ${chunk}`));
  child.stderr.on("data", (chunk) => process.stderr.write(`[${project.slug}] ${chunk}`));
  child.on("exit", (code, signal) => {
    console.log(`[${project.slug}] exited code=${code ?? ""} signal=${signal ?? ""}`);
    managed.delete(project.slug);
  });

  managed.set(project.slug, { process: child, port: processPort });
  await waitForTcp("127.0.0.1", processPort, 20000);
  return new URL(`http://127.0.0.1:${processPort}`);
}

function defaultNodeCommand(projectPath) {
  const packagePath = path.join(projectPath, "package.json");
  if (!existsSync(packagePath)) return "";
  const pkg = JSON.parse(readFileSync(packagePath, "utf8"));
  const scripts = pkg.scripts || {};
  const scriptName = scripts.start ? "start" : scripts.dev ? "dev" : scripts.preview ? "preview" : "";
  if (!scriptName) return "";
  const runner = packageRunner(projectPath, pkg);
  if (runner === "pnpm" || runner === "yarn") return `corepack enable && ${runner} run ${scriptName}`;
  return `npm run ${scriptName}`;
}

function packageRunner(projectPath, pkg) {
  const declared = typeof pkg.packageManager === "string" ? pkg.packageManager.split("@")[0] : "";
  if (declared === "pnpm" || declared === "yarn") return declared;
  if (existsSync(path.join(projectPath, "pnpm-lock.yaml"))) return "pnpm";
  if (existsSync(path.join(projectPath, "yarn.lock"))) return "yarn";
  return "npm";
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
    if (!isPhp && !isNode) continue;
    const type = isPhp ? "php" : "node";
    projects.push({
      name: entry.name,
      slug,
      type,
      host: nodeHosts.get(slug) || `${slug}${hostSuffix}`,
      path: projectPath,
    });
    seen.add(slug);
  }
  return projects;
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

function isEnabled(slug) {
  const state = readState();
  return state.projects?.[slug]?.enabled !== false;
}

function readState() {
  try {
    return JSON.parse(readFileSync(stateFile, "utf8"));
  } catch {
    return { projects: {} };
  }
}

function stopDisabledProcesses() {
  for (const [slug, item] of managed) {
    if (!isEnabled(slug)) {
      item.process.kill("SIGTERM");
      managed.delete(slug);
    }
  }
}

function disabled(res, title, host, status = 404) {
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(`<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title><style>body{margin:0;background:#0b1117;color:#eef5ff;font-family:system-ui;display:grid;place-items:center;min-height:100vh}.box{max-width:560px;padding:28px;border:1px solid #263547;border-radius:10px;background:#121a23}a{color:#76e4c5}</style></head><body><div class="box"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(host)} is managed from the Stexor Control Center.</p><p><a href="https://projects.localhost.com/">Open Control Center</a></p></div></body></html>`);
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

function stableIndex(value) {
  let hash = 0;
  for (const char of value) hash = (hash * 31 + char.charCodeAt(0)) % 500;
  return hash;
}

function availableProjectPort(slug) {
  const usedPorts = new Set([...managed.values()].map((item) => item.port));
  let candidate = 4300 + stableIndex(slug);
  while (usedPorts.has(candidate)) candidate += 1;
  return candidate;
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

function waitForTcp(host, targetPort, timeoutMs) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const probe = () => {
      const socket = connect({ host, port: targetPort });
      socket.once("connect", () => {
        socket.destroy();
        resolve();
      });
      socket.once("error", () => {
        socket.destroy();
        if (Date.now() - started >= timeoutMs) {
          reject(new Error(`Timed out waiting for Node project on ${host}:${targetPort}`));
          return;
        }
        setTimeout(probe, 500);
      });
    };
    probe();
  });
}
