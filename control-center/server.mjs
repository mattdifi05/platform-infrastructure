import { createServer } from "node:http";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync, appendFileSync } from "node:fs";
import path from "node:path";

const port = Number(process.env.CONTROL_CENTER_PORT || 8080);
const projectsRoot = process.env.PROJECTS_ROOT || "/var/www/projects";
const docsRoot = process.env.CONTROL_CENTER_DOCS_ROOT || "/var/www/infra-docs";
const stateFile = process.env.PROJECT_STATE_FILE || "/var/www/project-state/projects.json";
const auditFile = process.env.PROJECT_AUDIT_FILE || "/var/www/project-state/audit.jsonl";
const operationsFile = process.env.PROJECT_OPERATIONS_FILE || "/var/www/project-state/operations.jsonl";
const sessionKeysFile = process.env.CONTROL_CENTER_SESSION_KEYS_FILE || "";
const adminPasswordFile = process.env.CONTROL_CENTER_ADMIN_PASSWORD_FILE || "";
const adminPasswordSha256 = String(process.env.CONTROL_CENTER_ADMIN_PASSWORD_SHA256 || "").trim().toLowerCase();
const authRequired = parseBoolean(process.env.CONTROL_CENTER_AUTH_REQUIRED || "") || Boolean(adminPasswordSha256 || adminPasswordFile);
const environment = normalizeEnvironment(process.env.CONTROL_CENTER_ENV || "local");
const projectsHost = normalizeHost(process.env.PROJECTS_HOST || "projects.localhost.com");
const hostSuffix = normalizeHostSuffix(process.env.PROJECT_HOST_SUFFIX || ".localhost.com");
const nodeHosts = parsePairs(process.env.NODE_PROJECT_HOSTS || "");

const docs = {
  "Start Here": [
    ["README.md", "Overview and local usage"],
    ["RUNBOOK.md", "Operations runbook"],
    ["VPS-PREDEPLOY-CHECKLIST.md", "VPS pre-deploy checklist"],
  ],
  "Security And Readiness": [
    ["SECURITY.md", "Security model"],
    ["THREAT-MODEL.md", "Threat model"],
    ["ENTERPRISE-MATURITY.md", "Enterprise maturity matrix"],
    ["READINESS-REPORT.md", "Readiness report"],
    ["FINAL-READINESS-AUDIT.md", "Final audit notes"],
  ],
  "Cloud And Edge": [
    ["cloudflare/README.md", "Cloudflare setup"],
    ["cloudflare/LIVE-CHANGES.md", "Cloudflare live change log"],
  ],
};

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", `https://${req.headers.host || projectsHost}`);
    if (url.pathname === "/__health") {
      json(res, { ok: true, service: "control-center" });
      return;
    }

    if (url.pathname === "/login" && req.method === "POST") {
      await handleLogin(req, res);
      return;
    }

    if (url.pathname === "/logout") {
      clearSession(res);
      redirect(res, "/");
      return;
    }

    const session = authenticateRequest(req);
    if (authRequired && !session.ok) {
      if (url.pathname.startsWith("/control/") || req.method !== "GET") {
        json(res, { error: "admin_auth_required", message: session.message }, session.status);
        return;
      }
      html(res, renderLogin(session.message), session.status);
      return;
    }

    const state = readState();
    const projects = discoverProjects(state);
    const context = buildContext({ projects, state });

    if (url.pathname.startsWith("/control/")) {
      await handleApi(req, res, url, context);
      return;
    }

    if (req.method === "POST" && url.pathname === "/actions/toggle-project") {
      await handleToggleProject(req, res, projects);
      return;
    }

    if (url.pathname !== "/" && url.pathname !== "/index.html") {
      notFound(res);
      return;
    }

    html(res, renderControlCenter(context, url.searchParams));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    json(res, { error: "control_center_error", message: sanitizeMessage(message) }, 500);
  }
});

server.listen(port, "0.0.0.0", () => {
  console.log(`control-center listening on ${port}`);
});

async function handleLogin(req, res) {
  const payload = await readPayload(req);
  const password = String(payload.password || "");
  if (!authVerifierConfigured()) {
    json(res, { error: "admin_auth_not_configured", message: "Admin authentication is required but no password verifier is configured." }, 503);
    return;
  }
  if (!verifyAdminPassword(password)) {
    appendAudit({
      action: "admin.login.failed",
      target: "control-center",
      environment,
      risk: "medium",
      result: "failed",
      dryRun: false,
      summary: "Admin login rejected.",
    });
    if (wantsJson(req)) {
      json(res, { error: "admin_auth_failed", message: "Invalid admin password." }, 401);
      return;
    }
    html(res, renderLogin("Invalid admin password."), 401);
    return;
  }

  appendAudit({
    action: "admin.login.success",
    target: "control-center",
    environment,
    risk: "low",
    result: "success",
    dryRun: false,
    summary: "Admin session created.",
  });
  setSession(res);
  redirect(res, "/");
}

async function handleApi(req, res, url, context) {
  const method = (req.method || "GET").toUpperCase();
  const parts = url.pathname.split("/").filter(Boolean);
  const payload = await readPayload(req);

  try {
    if (method === "GET" && route(parts, "control", "overview")) return json(res, context.overview);
    if (method === "GET" && route(parts, "control", "projects")) return json(res, { projects: context.projects });
    if (method === "POST" && route(parts, "control", "projects")) return json(res, planProjectCreate(payload, context), 202);
    if (method === "GET" && parts.length === 3 && route(parts.slice(0, 2), "control", "projects")) return json(res, findById(context.projects, parts[2], "Project"));

    if (method === "GET" && route(parts, "control", "applications")) return json(res, { applications: context.applications });
    if (method === "POST" && route(parts, "control", "applications")) return json(res, planApplicationCreate(payload, context), 202);
    if (method === "POST" && parts.length === 4 && route(parts.slice(0, 2), "control", "applications")) {
      return json(res, planApplicationLifecycle(parts[2], parts[3], context), 202);
    }

    if (method === "GET" && route(parts, "control", "domains")) return json(res, { domains: context.domains, subdomains: context.subdomains });
    if (method === "POST" && route(parts, "control", "subdomains", "plan")) return json(res, planSubdomain(payload, context), 202);
    if (method === "POST" && route(parts, "control", "subdomains", "apply")) return json(res, applySubdomain(payload, context), 202);
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[3], parts[4]], "control", "subdomains", "remove", "plan")) {
      return json(res, planSubdomainRemoval(parts[2], context), 202);
    }
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[3], parts[4]], "control", "subdomains", "remove", "apply")) {
      return json(res, applySubdomainRemoval(parts[2], payload, context), 202);
    }
    if (method === "POST" && parts.length === 4 && route([parts[0], parts[1], parts[3]], "control", "subdomains", "verify")) {
      return json(res, verifySubdomain(parts[2], context), 202);
    }

    if (method === "GET" && route(parts, "control", "webspaces")) return json(res, { webspaces: context.webspaces });
    if (method === "POST" && route(parts, "control", "webspaces")) return json(res, planWebspaceCreate(payload, context), 202);
    if (method === "POST" && parts.length === 4 && route([parts[0], parts[1], parts[3]], "control", "webspaces", "quota")) {
      return json(res, planWebspaceQuota(parts[2], payload, context), 202);
    }

    if (method === "GET" && route(parts, "control", "resources", "summary")) return json(res, context.resources);
    if (method === "GET" && route(parts, "control", "security", "summary")) return json(res, context.security);
    if (method === "GET" && route(parts, "control", "backups", "summary")) return json(res, context.backups);
    if (method === "POST" && route(parts, "control", "backups", "run")) return json(res, planBackupRun(payload, context), 202);
    if (method === "POST" && route(parts, "control", "restore", "plan")) return json(res, planRestore(payload, context), 202);

    if (method === "GET" && route(parts, "control", "operations")) return json(res, { operations: context.operations });
    if (method === "GET" && parts.length === 3 && route(parts.slice(0, 2), "control", "operations")) return json(res, findById(context.operations, parts[2], "Operation"));
    if (method === "GET" && route(parts, "control", "audit")) return json(res, { audit: context.audit });
  } catch (error) {
    if (error instanceof ValidationError) return json(res, { error: "validation_failed", message: error.message }, 422);
    if (error instanceof RejectedOperationError) return json(res, { error: "operation_rejected", message: error.message }, 409);
    throw error;
  }

  notFound(res);
}

async function handleToggleProject(req, res, projects) {
  const payload = await readPayload(req);
  const slug = slugify(payload.slug || "");
  if (!projects.some((project) => project.slug === slug)) {
    json(res, { error: "not_found", message: "Project not found." }, 404);
    return;
  }
  const enabled = String(payload.enabled || "") === "1";
  const state = readState();
  state.projects[slug] = { enabled, updatedAt: new Date().toISOString() };
  writeState(state);
  appendAudit({
    action: enabled ? "project.enable" : "project.disable",
    target: slug,
    environment,
    risk: enabled ? "low" : "medium",
    result: "success",
    dryRun: false,
    summary: enabled ? "Project routing enabled locally." : "Project routing disabled locally.",
  });
  redirect(res, `/?section=projects#project-${encodeURIComponent(slug)}`);
}

function buildContext({ projects, state }) {
  const applications = projects.map((project) => ({
    id: project.slug,
    projectId: project.slug,
    name: project.name,
    runtime: project.runtime,
    kind: project.runtime === "node" ? "frontend" : "php",
    host: project.host,
    status: project.enabled ? "online" : "offline",
    healthcheck: `https://${project.host}/`,
  }));
  const subdomains = [
    ...projects.map((project) => ({
      id: slugify(project.host),
      projectId: project.slug,
      applicationId: project.slug,
      environment,
      hostname: project.host,
      baseDomain: hostSuffix.replace(/^\./, ""),
      type: project.runtime === "node" ? "frontend" : "custom",
      visibility: "public",
      protection: "none",
      tlsStatus: environment === "local" ? "local-certificate" : "requires-verify",
      dnsStatus: environment === "local" ? "local-resolver-or-hosts" : "requires-cloudflare-verify",
      healthStatus: project.enabled ? "routable" : "disabled",
      status: project.enabled ? "active" : "disabled",
      createdBy: "control-center-discovery",
      deletedAt: null,
    })),
    ...Object.values(state.subdomains || {}).filter((item) => item && !item.deletedAt),
  ];
  const webspaces = projects.map((project) => ({
    id: project.slug,
    projectId: project.slug,
    name: project.slug,
    environment: "local",
    basePath: `webspaces/${project.slug}`,
    quotaBytes: 0,
    usedBytes: 0,
    mounts: ["public", "private", "uploads", "backups", "config"],
    linkedApps: [project.slug],
    status: project.enabled ? "active" : "disabled",
  }));
  const audit = readAudit();
  const operations = readOperations();
  const activeProjects = projects.filter((project) => project.enabled).length;
  const onlineApps = applications.filter((app) => app.status === "online").length;
  const resources = {
    mode: environment,
    source: "local-control-plane",
    cpu: { status: "configured", summary: "Container metrics are available through Grafana/Prometheus." },
    memory: { status: "configured", summary: "Memory trend is delegated to Prometheus/cAdvisor." },
    disk: { status: "local-estimate", webspacesBytes: webspaces.reduce((sum, item) => sum + item.usedBytes, 0) },
    containersByProject: applications.map((app) => ({
      projectId: app.projectId,
      applicationId: app.id,
      runtime: app.runtime,
      status: app.status,
    })),
  };
  const security = {
    waf: "configured",
    rateLimit: "configured",
    cloudflareAccess: environment === "production" ? "requires-verify-remote" : "plan-only-local",
    adminProtection: process.env.CONTROL_CENTER_REQUIRE_ADMIN === "1" ? "required" : "local-only",
    securityHeaders: "configured",
    passkeyAdminAuth: "available-through-stexor-account-app",
    recentAuditEvents: audit.slice(0, 8),
  };
  const backups = {
    mode: environment,
    manualBackup: "plan-only-from-control-center",
    restoreDrill: "available-through-infra-ops",
    offsite: process.env.BACKUP_SCHEDULER_ENABLE_OFFSITE === "true" ? "configured" : "not-configured",
    rpoRto: "reported-by-production-go-no-go-evidence",
  };
  const domains = [{
    id: "local",
    environment: "local",
    baseDomain: hostSuffix.replace(/^\./, ""),
    dnsStatus: "local-hosts-or-resolver",
    tlsStatus: "local-certificate",
    cloudflareStatus: "not-used-in-local-mode",
  }];
  const overview = {
    title: "Stexor Control Center",
    environment,
    modeEvidence: environment === "production" ? "production evidence requires verifyRemote" : "local evidence only",
    projects: { total: projects.length, active: activeProjects, archived: 0 },
    applications: { total: applications.length, online: onlineApps, offline: applications.length - onlineApps },
    resources,
    subdomains: { total: subdomains.length, active: subdomains.filter((item) => item.status === "active").length },
    alerts: { open: 0, source: "Alertmanager summary link" },
    deployments: { latest: [] },
    backups,
  };
  return {
    overview,
    projects,
    applications,
    domains,
    subdomains,
    webspaces,
    resources,
    security,
    backups,
    operations,
    audit,
    docsAvailable: countAvailableDocs(),
    environment,
    advancedServices: advancedServices(),
  };
}

function discoverProjects(state) {
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
    const type = isPhp ? "PHP" : "Node";
    const host = type === "Node" && nodeHosts.has(slug) ? nodeHosts.get(slug) : `${slug}${hostSuffix}`;
    const enabled = state.projects?.[slug]?.enabled !== false;
    projects.push({
      id: slug,
      slug,
      name: humanName(entry.name),
      type,
      runtime: type.toLowerCase(),
      host,
      href: `https://${host}/`,
      enabled,
      status: enabled ? "active" : "disabled",
      summary: type === "PHP" ? "Apache/PHP local host" : "Node routed service",
    });
    seen.add(slug);
  }
  projects.sort((a, b) => {
    const typeOrder = { PHP: 0, Node: 1 };
    return (typeOrder[a.type] - typeOrder[b.type]) || a.name.localeCompare(b.name);
  });
  return projects;
}

function renderControlCenter(context, params) {
  const mode = params.get("mode") === "advanced" ? "advanced" : "simple";
  const nav = navigationForMode(mode);
  const requestedSection = params.get("section") || (mode === "advanced" ? "infrastructure" : "overview");
  const section = nav.some((item) => item.id === requestedSection) ? requestedSection : nav[0].id;
  const selectedProject = context.projects.some((project) => project.slug === params.get("project")) ? params.get("project") : "";
  const scoped = (items) => selectedProject ? items.filter((item) => (item.projectId || item.slug) === selectedProject) : items;
  const title = nav.find((item) => item.id === section)?.label || "Overview";

  let body = "";
  if (mode === "simple") {
    if (section === "overview") body = renderOverview(context);
    else if (section === "projects") body = renderProjects(scoped(context.projects));
    else if (section === "applications") body = renderApplications(scoped(context.applications));
    else if (section === "domains") body = renderDomains(context.domains, scoped(context.subdomains));
    else if (section === "webspaces") body = renderWebspaces(scoped(context.webspaces));
    else if (section === "resources") body = renderJsonPanel("Resources", context.resources);
    else if (section === "security") body = renderJsonPanel("Security", context.security);
    else if (section === "backups") body = renderJsonPanel("Backups", context.backups);
    else if (section === "logs") body = renderAudit(context.audit, "Logs / Alerts minimal");
    else body = renderSettings(context);
  } else {
    if (section === "audit") body = renderAudit(context.audit, "Audit Log");
    else if (section === "network") body = renderDomains(context.domains, scoped(context.subdomains));
    else if (section === "infrastructure") body = renderInfrastructure(context.advancedServices);
    else if (section === "backup-restore") body = renderJsonPanel("Backup & Restore Advanced", context.backups);
    else body = renderPlanOnlyPanel(title, advancedItems(section));
  }

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stexor Control Center</title>
${styleTag()}
</head>
<body>
<main class="control-shell">
  <aside class="sidebar">
    <div class="brand"><span class="brand-mark">SX</span><div><strong>Stexor</strong><small>Control Center</small></div></div>
    <nav aria-label="Control navigation">
      ${nav.map((item) => `<a class="${section === item.id ? "active" : ""}" href="/?mode=${mode}&section=${item.id}"><span>${escapeHtml(item.short)}</span>${escapeHtml(item.label)}</a>`).join("")}
    </nav>
    <div class="mode-card">
      <small>Mode</small>
      <div class="segmented">
        <a class="${mode === "simple" ? "selected" : ""}" href="/?mode=simple&section=overview">Simple</a>
        <a class="${mode === "advanced" ? "selected" : ""}" href="/?mode=advanced&section=infrastructure">Advanced</a>
      </div>
    </div>
  </aside>
  <section class="workspace">
    <header class="topbar">
      <div><p class="eyebrow">${escapeHtml(environment.toUpperCase())} MODE</p><h1>${escapeHtml(title)}</h1></div>
      <div class="top-actions">
        <span class="pill ${environment === "production" ? "danger" : "info"}">${escapeHtml(context.overview.modeEvidence)}</span>
        ${authRequired ? '<a class="button" href="/logout">Logout</a>' : ""}
        <form method="get" class="switcher">
          <input type="hidden" name="mode" value="${escapeHtml(mode)}">
          <input type="hidden" name="section" value="${escapeHtml(section)}">
          <select name="project" onchange="this.form.submit()" aria-label="Project switcher">
            <option value="">All projects</option>
            ${context.projects.map((project) => `<option value="${escapeHtml(project.slug)}" ${selectedProject === project.slug ? "selected" : ""}>${escapeHtml(project.name)}</option>`).join("")}
          </select>
        </form>
      </div>
    </header>
    ${body}
  </section>
</main>
</body>
</html>`;
}

function renderLogin(message) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stexor Control Center Sign In</title>
${styleTag()}
</head>
<body>
<main class="login-shell">
  <section class="login-panel">
    <span class="brand-mark">SX</span>
    <p class="eyebrow">${escapeHtml(environment.toUpperCase())} MODE</p>
    <h1>Admin Sign In</h1>
    <p class="login-copy">${escapeHtml(message || "Admin authentication required.")}</p>
    <form method="post" action="/login" class="login-form">
      <label for="password">Admin password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
      <button class="button open" type="submit">Sign in</button>
    </form>
  </section>
</main>
</body>
</html>`;
}

function renderOverview(context) {
  return `<section class="metric-grid">
    <div class="metric"><span>${context.overview.projects.active}</span><small>active projects</small></div>
    <div class="metric"><span>${context.overview.applications.online}</span><small>online apps</small></div>
    <div class="metric"><span>${context.overview.subdomains.active}</span><small>active subdomains</small></div>
    <div class="metric"><span>${context.overview.alerts.open}</span><small>open alerts</small></div>
  </section>
  <section class="grid two">
    <div class="panel"><div class="panel-head"><span>OPS</span><div><h2>Daily operations</h2><p>Safe local controls and dry-run production planning.</p></div></div>
      <div class="cards">
        <a class="card compact" href="/?section=projects"><strong>Projects</strong><span>Create/edit/archive/delete planning and routing state.</span></a>
        <a class="card compact" href="/?section=applications"><strong>Applications</strong><span>Node, PHP, static, API and worker inventory.</span></a>
        <a class="card compact" href="/?section=domains"><strong>Domains</strong><span>Local subdomain planning and production dry-runs.</span></a>
        <a class="card compact" href="/?section=backups"><strong>Backups</strong><span>Manual backup and restore drill planning.</span></a>
      </div>
    </div>
    <div class="panel"><div class="panel-head"><span>SEC</span><div><h2>Safety posture</h2><p>No live provider calls from this panel by default.</p></div></div>
      <ul class="status-list">
        <li><strong>Cloudflare</strong><span>plan-only until explicit apply and verifyRemote</span></li>
        <li><strong>Secrets</strong><span>never serialized to the client</span></li>
        <li><strong>Audit</strong><span>every Control Center action writes local audit</span></li>
        <li><strong>Production</strong><span>local evidence is never production evidence</span></li>
      </ul>
    </div>
  </section>`;
}

function renderProjects(projects) {
  return `<section class="panel"><div class="panel-head"><span>PRJ</span><div><h2>Projects</h2><p>Routing toggle is local and audited. Create/archive/delete are API planned.</p></div></div>
  <div class="cards project-cards">${projects.map(renderProjectCard).join("") || empty("No projects", "No mounted projects found.")}</div></section>`;
}

function renderProjectCard(project) {
  return `<div id="project-${escapeHtml(project.slug)}" class="card project-card ${project.enabled ? "" : "is-off"}">
    <div class="card-title"><strong>${escapeHtml(project.name)}</strong><em>${escapeHtml(project.type)}</em></div>
    <span class="host">${escapeHtml(project.host)}</span>
    <span>${escapeHtml(project.summary)}</span>
    <div class="project-actions">
      <span class="state ${project.enabled ? "on" : "off"}">${project.enabled ? "Active" : "Off"}</span>
      ${project.enabled ? `<a class="button open" href="${escapeHtml(project.href)}">Open</a>` : `<span class="button muted">Open</span>`}
      <form method="post" action="/actions/toggle-project">
        <input type="hidden" name="slug" value="${escapeHtml(project.slug)}">
        <input type="hidden" name="enabled" value="${project.enabled ? "0" : "1"}">
        <button class="button ${project.enabled ? "danger" : "enable"}" type="submit">${project.enabled ? "Disable" : "Enable"}</button>
      </form>
    </div>
  </div>`;
}

function renderApplications(applications) {
  return `<section class="panel"><div class="panel-head"><span>APP</span><div><h2>Applications</h2><p>Lifecycle commands are exposed as dry-run API plans.</p></div></div><div class="cards">${applications.map((app) => `<div class="card"><div class="card-title"><strong>${escapeHtml(app.name)}</strong><em>${escapeHtml(app.runtime)}</em></div><span>${escapeHtml(app.host)}</span><span class="state ${app.status === "online" ? "on" : "off"}">${escapeHtml(app.status)}</span></div>`).join("")}</div></section>`;
}

function renderDomains(domains, subdomains) {
  return `<section class="grid two"><div class="panel"><div class="panel-head"><span>DNS</span><div><h2>Domains</h2><p>Local DNS is simulated; production requires Cloudflare dry-run/apply/verify.</p></div></div><div class="cards">${domains.map((domain) => `<div class="card compact"><strong>${escapeHtml(domain.baseDomain)}</strong><span>${escapeHtml(domain.environment)} / ${escapeHtml(domain.tlsStatus)}</span></div>`).join("")}</div></div>
  <div class="panel"><div class="panel-head"><span>SUB</span><div><h2>Subdomains</h2><p>Wildcard local routing maps hostnames to apps by project slug.</p></div></div><div class="cards">${subdomains.map((item) => `<div class="card compact"><strong>${escapeHtml(item.hostname)}</strong><span>${escapeHtml(item.type)} / ${escapeHtml(item.visibility)} / ${escapeHtml(item.healthStatus)}</span></div>`).join("")}</div></div></section>`;
}

function renderWebspaces(webspaces) {
  return `<section class="panel"><div class="panel-head"><span>WEB</span><div><h2>Web Spaces</h2><p>Declarative folders only; secrets are excluded by policy.</p></div></div><div class="cards">${webspaces.map((space) => `<div class="card"><strong>${escapeHtml(space.name)}</strong><span>${escapeHtml(space.basePath)}</span><span>${bytesLabel(space.usedBytes)} used / quota ${bytesLabel(space.quotaBytes)}</span></div>`).join("")}</div></section>`;
}

function renderSettings(context) {
  return `<section class="grid two"><div class="panel"><div class="panel-head"><span>SET</span><div><h2>Settings</h2><p>Connections are status-only here; tokens stay in Docker secrets.</p></div></div><ul class="status-list">
    <li><strong>Environment</strong><span>${escapeHtml(context.environment)}</span></li>
    <li><strong>Base domain</strong><span>${escapeHtml(hostSuffix.replace(/^\./, ""))}</span></li>
    <li><strong>Cloudflare</strong><span>${escapeHtml(context.security.cloudflareAccess)}</span></li>
    <li><strong>GitHub</strong><span>governance dry-run through infra ops</span></li>
    <li><strong>SMTP alerts</strong><span>configured through secret-backed environment</span></li>
  </ul></div><div class="panel"><div class="panel-head"><span>DOC</span><div><h2>Documentation</h2><p>${context.docsAvailable} local docs</p></div></div>${renderDocs()}</div></section>`;
}

function renderDocs() {
  return Object.entries(docs).map(([group, items]) => `<h3>${escapeHtml(group)}</h3><div class="cards">${items.map(([docPath, description]) => {
    const exists = existsSync(safeDocPath(docPath));
    return `<a class="card compact ${exists ? "" : "disabled"}" href="#"><strong>${escapeHtml(path.basename(docPath))}</strong><span>${escapeHtml(description)}</span></a>`;
  }).join("")}</div>`).join("");
}

function renderInfrastructure(services) {
  return `<section class="panel"><div class="panel-head"><span>INF</span><div><h2>Infrastructure</h2><p>Enterprise service map. Mutations stay behind backend adapters and confirmation.</p></div></div><div class="cards">${services.map((service) => `<div class="card compact"><strong>${escapeHtml(service.name)}</strong><span>${escapeHtml(service.role)} / ${escapeHtml(service.status)}</span></div>`).join("")}</div></section>`;
}

function renderPlanOnlyPanel(title, items) {
  return `<section class="panel"><div class="panel-head"><span>ADV</span><div><h2>${escapeHtml(title)}</h2><p>Advanced control is dry-run/plan by default in this foundation.</p></div></div><div class="cards">${items.map((item) => `<div class="card compact"><strong>${escapeHtml(item)}</strong><span>planned adapter surface</span></div>`).join("")}</div></section>`;
}

function renderJsonPanel(title, data) {
  return `<section class="panel"><div class="panel-head"><span>SUM</span><div><h2>${escapeHtml(title)}</h2><p>Sanitized local summary.</p></div></div><pre class="json-block">${escapeHtml(JSON.stringify(data, null, 2))}</pre></section>`;
}

function renderAudit(audit, title) {
  return `<section class="panel"><div class="panel-head"><span>AUD</span><div><h2>${escapeHtml(title)}</h2><p>Control Center events are append-only JSON lines in local state.</p></div></div>${audit.length ? `<div class="cards">${audit.slice(0, 12).map((event) => `<div class="card compact"><strong>${escapeHtml(event.action || "event")}</strong><span>${escapeHtml(`${event.timestamp || ""} / ${event.result || "unknown"}`)}</span></div>`).join("")}</div>` : empty("No events", "No Control Center action has been audited yet.")}</section>`;
}

function planProjectCreate(payload, context) {
  const slug = slugify(payload.slug || payload.name || "");
  validateSlug(slug);
  appendAudit({ action: "project.create.plan", target: slug, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Project creation plan generated; no filesystem changes applied." });
  return operationPlan("project.create", context.environment, true, ["validate slug", "create project metadata", "create optional webspace", "link applications/domains/databases", "write audit event"], { projectId: slug });
}

function planApplicationCreate(payload, context) {
  const runtime = String(payload.runtime || "");
  if (!["node", "php", "static", "api", "worker"].includes(runtime)) throw new ValidationError("Unsupported application runtime.");
  appendAudit({ action: "application.create.plan", target: sanitizeIdentifier(payload.projectId || "unknown"), environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Application creation plan generated." });
  return operationPlan("application.create", context.environment, true, ["validate runtime", "link repository or webspace", "create healthcheck", "prepare route plan", "write audit event"], { runtime });
}

function planApplicationLifecycle(id, action, context) {
  if (!["start", "stop", "restart"].includes(action)) throw new ValidationError("Unsupported lifecycle action.");
  findById(context.applications, id, "Application");
  appendAudit({ action: `application.${action}.plan`, target: sanitizeIdentifier(id), environment: context.environment, risk: action === "stop" ? "medium" : "low", result: "planned", dryRun: true, summary: "Lifecycle action planned; no container command executed." });
  return operationPlan(`application.${action}`, context.environment, true, ["validate application", "check current health", "prepare Docker adapter command", "require confirmation for apply", "write audit event"], { applicationId: id });
}

function planSubdomain(payload, context) {
  const targetEnv = normalizeEnvironment(payload.environment || context.environment);
  const projectId = slugify(payload.projectId || "");
  validateSlug(projectId);
  findById(context.projects, projectId, "Project");
  const hostname = subdomainHostname(payload, targetEnv);
  validateHostname(hostname, targetEnv);
  const visibility = choice(payload.visibility || "public", ["public", "admin", "private"], "visibility");
  const protection = choice(payload.protection || "none", ["none", "passkey", "cloudflare-access"], "protection");
  appendAudit({ action: "subdomain.plan", target: hostname, environment: targetEnv, risk: targetEnv === "production" ? "high" : "low", result: "planned", dryRun: true, summary: "Subdomain plan generated without live provider calls." });
  const steps = targetEnv === "production"
    ? ["validate hostname", "prepare Cloudflare DNS record", "prepare Traefik route", "prepare TLS/proxy settings", "prepare Access/WAF policy", "verifyRemote after apply"]
    : ["validate hostname", "use local wildcard route", "link project/app", "mark TLS as local certificate", "write audit event"];
  return operationPlan("subdomain.plan", targetEnv, true, steps, { hostname, projectId, visibility, protection, productionEvidence: false });
}

function applySubdomain(payload, context) {
  const plan = planSubdomain(payload, context);
  if (plan.environment === "production") {
    if (payload.confirm !== "APPLY-PRODUCTION") throw new RejectedOperationError("Production apply requires confirm=APPLY-PRODUCTION and verified provider secrets.");
    throw new RejectedOperationError("Production apply is disabled in local Control Center foundation; use the backend Cloudflare adapter with verifyRemote.");
  }
  if (payload.confirm !== "APPLY-LOCAL") throw new RejectedOperationError("Local apply requires confirm=APPLY-LOCAL.");
  const state = readState();
  const id = slugify(plan.details.hostname);
  state.subdomains[id] = {
    id,
    projectId: plan.details.projectId,
    applicationId: payload.applicationId || plan.details.projectId,
    environment: "local",
    hostname: plan.details.hostname,
    visibility: plan.details.visibility,
    protection: plan.details.protection,
    status: "active",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  writeState(state);
  appendAudit({ action: "subdomain.apply.local", target: plan.details.hostname, environment: "local", risk: "medium", result: "success", dryRun: false, summary: "Local subdomain state recorded; routing uses existing wildcard Traefik rule." });
  return operationPlan("subdomain.apply.local", "local", false, ["record local subdomain state", "use existing wildcard Traefik route", "write audit event"], {
    subdomainId: id,
    hostname: plan.details.hostname,
    projectId: plan.details.projectId,
    visibility: plan.details.visibility,
    protection: plan.details.protection,
    productionEvidence: false,
  });
}

function planSubdomainRemoval(id, context) {
  const item = findById(context.subdomains, id, "Subdomain");
  appendAudit({ action: "subdomain.remove.plan", target: item.hostname, environment: item.environment, risk: "high", result: "planned", dryRun: true, summary: "Subdomain removal plan generated." });
  return operationPlan("subdomain.remove", item.environment, true, ["soft delete subdomain", "disable route", "remove Cloudflare DNS only after explicit confirmation", "write audit event"], { subdomainId: id, hostname: item.hostname });
}

function applySubdomainRemoval(id, payload, context) {
  const item = findById(context.subdomains, id, "Subdomain");
  if (payload.confirm !== "REMOVE-SUBDOMAIN") throw new RejectedOperationError("Subdomain removal requires confirm=REMOVE-SUBDOMAIN.");
  const state = readState();
  state.subdomains[item.id] = { ...item, status: "disabled", deletedAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
  writeState(state);
  appendAudit({ action: "subdomain.remove.apply", target: item.hostname, environment: item.environment, risk: "high", result: "success", dryRun: false, summary: "Subdomain soft deleted locally." });
  return operationPlan("subdomain.remove", item.environment, false, ["soft delete local subdomain state"], { subdomainId: id });
}

function verifySubdomain(id, context) {
  const item = findById(context.subdomains, id, "Subdomain");
  appendAudit({ action: "subdomain.verify.plan", target: item.hostname, environment: item.environment, risk: "low", result: "planned", dryRun: true, summary: "Verification plan generated; no external DNS request made." });
  return operationPlan("subdomain.verify", item.environment, true, ["check DNS status", "check TLS status", "check route status", "check app health status"], { hostname: item.hostname, productionEvidence: false });
}

function planWebspaceCreate(payload, context) {
  const projectId = slugify(payload.projectId || "");
  validateSlug(projectId);
  findById(context.projects, projectId, "Project");
  const name = slugify(payload.name || projectId);
  validateSlug(name);
  const basePath = validateWebspacePath(payload.basePath || `webspaces/${projectId}`);
  appendAudit({ action: "webspace.create.plan", target: `${projectId}/${name}`, environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Webspace creation plan generated." });
  return operationPlan("webspace.create", context.environment, true, ["validate project", "validate path traversal protection", "create public/private/uploads/backups/config folders", "apply quota", "write audit event"], { projectId, name, basePath });
}

function planWebspaceQuota(id, payload, context) {
  findById(context.webspaces, id, "Webspace");
  const quotaBytes = Number(payload.quotaBytes || 0);
  if (!Number.isFinite(quotaBytes) || quotaBytes < 0) throw new ValidationError("Quota must be zero or greater.");
  appendAudit({ action: "webspace.quota.plan", target: sanitizeIdentifier(id), environment: context.environment, risk: "low", result: "planned", dryRun: true, summary: "Quota update plan generated." });
  return operationPlan("webspace.quota", context.environment, true, ["validate quota", "prepare quota adapter update", "write audit event"], { webspaceId: id, quotaBytes });
}

function planBackupRun(payload, context) {
  const scope = sanitizeIdentifier(payload.scope || "all") || "all";
  appendAudit({ action: "backup.run.plan", target: scope, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Manual backup plan generated." });
  return operationPlan("backup.run", context.environment, true, ["select scope", "invoke backup adapter", "verify artifact", "write evidence"], { scope });
}

function planRestore(payload, context) {
  const scope = sanitizeIdentifier(payload.scope || "all") || "all";
  appendAudit({ action: "restore.plan", target: scope, environment: context.environment, risk: "high", result: "planned", dryRun: true, summary: "Restore plan generated; no data changed." });
  return operationPlan("restore.plan", context.environment, true, ["validate backup artifact", "create disposable restore target", "run restore drill", "generate evidence"], { scope });
}

function operationPlan(type, targetEnv, dryRun, steps, details = {}) {
  const now = new Date().toISOString();
  const operationId = rid();
  const cleanDetails = sanitizeOperationDetails(details);
  const operation = sanitizeEvent({
    id: operationId,
    operationId,
    type,
    status: dryRun ? "planned" : "accepted",
    projectId: cleanDetails.projectId || cleanDetails.project || cleanDetails.applicationId || cleanDetails.webspaceId || cleanDetails.subdomainId || "",
    environment: targetEnv,
    requestedBy: "local-admin",
    dryRun,
    startedAt: now,
    finishedAt: now,
    resultSummary: dryRun ? "Plan generated. No external provider or destructive action executed." : "Local operation accepted.",
    reportPath: null,
    errorCode: null,
    errorMessage: null,
    steps: steps.map((name) => ({
      id: rid(),
      operationId,
      name,
      status: dryRun ? "planned" : "accepted",
      startedAt: now,
      finishedAt: now,
      output: "sanitized",
    })),
    details: cleanDetails,
  });
  appendOperation(operation);
  return operation;
}

function readState() {
  try {
    const parsed = JSON.parse(readFileSync(stateFile, "utf8"));
    return {
      ...parsed,
      projects: typeof parsed.projects === "object" && parsed.projects ? parsed.projects : {},
      subdomains: typeof parsed.subdomains === "object" && parsed.subdomains ? parsed.subdomains : {},
    };
  } catch {
    return { projects: {}, subdomains: {} };
  }
}

function writeState(state) {
  mkdirSync(path.dirname(stateFile), { recursive: true });
  writeFileSync(stateFile, `${JSON.stringify(state, null, 2)}\n`);
}

function appendAudit(event) {
  mkdirSync(path.dirname(auditFile), { recursive: true });
  const record = sanitizeEvent({
    id: rid(),
    timestamp: new Date().toISOString(),
    actor: "local-admin",
    requestId: rid(),
    ...event,
  });
  appendFileSync(auditFile, `${JSON.stringify(record)}\n`);
}

function readAudit() {
  try {
    return readFileSync(auditFile, "utf8").split(/\r?\n/).filter(Boolean).reverse().slice(0, 100).map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

function appendOperation(operation) {
  mkdirSync(path.dirname(operationsFile), { recursive: true });
  appendFileSync(operationsFile, `${JSON.stringify(sanitizeEvent(operation))}\n`);
}

function readOperations() {
  try {
    return readFileSync(operationsFile, "utf8").split(/\r?\n/).filter(Boolean).reverse().slice(0, 100).map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

async function readPayload(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString("utf8");
  const type = String(req.headers["content-type"] || "").toLowerCase();
  if (type.includes("application/json")) {
    try {
      const parsed = JSON.parse(raw || "{}");
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch {
      throw new ValidationError("Invalid JSON payload.");
    }
  }
  const params = new URLSearchParams(raw);
  return Object.fromEntries(params.entries());
}

function authenticateRequest(req) {
  if (!authRequired) return { ok: true, status: 200, message: "" };
  if (!authVerifierConfigured()) {
    return { ok: false, status: 503, message: "Admin authentication is required but no password verifier is configured." };
  }
  const token = parseCookie(req.headers.cookie || "").sxcc_session || "";
  if (!verifySession(token)) {
    return { ok: false, status: 401, message: "Admin authentication required." };
  }
  return { ok: true, status: 200, message: "" };
}

function authVerifierConfigured() {
  return Boolean(adminPasswordSha256 || (adminPasswordFile && existsSync(adminPasswordFile)));
}

function verifyAdminPassword(password) {
  if (!password) return false;
  if (adminPasswordSha256) {
    return safeEqualHex(sha256(password), adminPasswordSha256);
  }
  if (adminPasswordFile && existsSync(adminPasswordFile)) {
    const expected = readFileSync(adminPasswordFile, "utf8").trim();
    return safeEqualText(password, expected);
  }
  return false;
}

function setSession(res) {
  const expiresAt = Date.now() + (8 * 60 * 60 * 1000);
  const nonce = rid();
  const body = `${expiresAt}.${nonce}`;
  const signature = signSessionBody(body);
  const token = `v1.${body}.${signature}`;
  res.setHeader("set-cookie", `sxcc_session=${token}; Path=/; Max-Age=28800; HttpOnly; Secure; SameSite=Lax`);
}

function clearSession(res) {
  res.setHeader("set-cookie", "sxcc_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax");
}

function verifySession(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 4 || parts[0] !== "v1") return false;
  const expiresAt = Number(parts[1]);
  if (!Number.isFinite(expiresAt) || expiresAt < Date.now()) return false;
  const body = `${parts[1]}.${parts[2]}`;
  return sessionKeys().some((key) => safeEqualHex(signSessionBody(body, key), parts[3]));
}

function signSessionBody(body, explicitKey = "") {
  const key = explicitKey || sessionKeys()[0] || "";
  if (!key) return "";
  return createHmac("sha256", key).update(body).digest("hex");
}

function sessionKeys() {
  const raw = sessionKeysFile && existsSync(sessionKeysFile) ? readFileSync(sessionKeysFile, "utf8") : "";
  return raw.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
}

function parseCookie(header) {
  const out = {};
  for (const part of String(header || "").split(";")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    out[decodeURIComponent(part.slice(0, separator).trim())] = decodeURIComponent(part.slice(separator + 1).trim());
  }
  return out;
}

function wantsJson(req) {
  return String(req.headers.accept || "").includes("application/json") || String(req.headers["content-type"] || "").includes("application/json");
}

function sha256(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function safeEqualHex(left, right) {
  if (!/^[a-f0-9]{64}$/i.test(left) || !/^[a-f0-9]{64}$/i.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function safeEqualText(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  if (leftBuffer.length !== rightBuffer.length) return false;
  return timingSafeEqual(leftBuffer, rightBuffer);
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

function validateSlug(value) {
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value)) throw new ValidationError("Invalid slug.");
}

function validateHostname(hostname, targetEnv) {
  if (!hostname || hostname.length > 253 || hostname.includes("..")) throw new ValidationError("Invalid hostname.");
  if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/.test(hostname)) throw new ValidationError("Invalid hostname.");
  if (targetEnv === "production" && hostname.includes("localhost")) throw new ValidationError("Production hostname must use a real domain.");
  if (targetEnv === "local" && !hostname.endsWith(hostSuffix)) throw new ValidationError("Local hostname must use the configured local suffix.");
}

function validateWebspacePath(value) {
  const input = String(value || "");
  const normalized = input.replaceAll("\\", "/").replace(/^\/+|\/+$/g, "");
  if (!normalized || normalized.includes("..") || input.startsWith("/") || /^[A-Za-z]:/.test(input)) throw new ValidationError("Invalid webspace path.");
  if (!/^[a-zA-Z0-9._/-]+$/.test(normalized)) throw new ValidationError("Invalid webspace path.");
  return normalized;
}

function subdomainHostname(payload, targetEnv) {
  const explicit = normalizeHost(payload.hostname || "");
  if (explicit) return explicit;
  const label = slugify(payload.subdomain || "");
  validateSlug(label);
  const baseDomain = normalizeHost(payload.baseDomain || hostSuffix.replace(/^\./, ""));
  return `${label}.${baseDomain}`;
}

function findById(items, id, label) {
  const slug = slugify(id);
  const found = items.find((item) => item.id === id || item.id === slug || item.slug === slug || slugify(item.hostname || "") === slug);
  if (!found) throw new ValidationError(`${label} not found.`);
  return found;
}

function route(parts, ...expected) {
  return parts.length === expected.length && expected.every((part, index) => parts[index] === part);
}

function choice(value, allowed, label) {
  if (!allowed.includes(value)) throw new ValidationError(`Invalid ${label}.`);
  return value;
}

function parsePairs(value) {
  const pairs = new Map();
  for (const item of String(value).split(",")) {
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

function normalizeEnvironment(value) {
  const normalized = String(value || "").toLowerCase().trim();
  return ["local", "staging", "production"].includes(normalized) ? normalized : "local";
}

function parseBoolean(value) {
  return ["1", "true", "yes", "on"].includes(String(value || "").toLowerCase().trim());
}

function normalizeHost(value) {
  return String(value || "").toLowerCase().trim().replace(/:\d+$/, "");
}

function normalizeHostSuffix(value) {
  const normalized = normalizeHost(value);
  return normalized.startsWith(".") ? normalized : `.${normalized}`;
}

function slugify(value) {
  return String(value || "").trim().toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "");
}

function sanitizeIdentifier(value) {
  return slugify(value).slice(0, 80);
}

function sanitizeMessage(message) {
  return String(message || "").replace(/\b(token|secret|password|authorization|cookie)=([^\s]+)/gi, "$1=[redacted]");
}

function sanitizeEvent(event) {
  return sanitizeValue(event);
}

function sanitizeOperationDetails(details) {
  return sanitizeValue(details && typeof details === "object" ? details : {});
}

function sanitizeValue(value, keyName = "") {
  if (/(secret|token|password|authorization|cookie)/i.test(keyName)) return "[redacted]";
  if (typeof value === "string") return sanitizeMessage(value);
  if (Array.isArray(value)) return value.map((item) => sanitizeValue(item));
  if (value && typeof value === "object") {
    const clean = {};
    for (const [key, childValue] of Object.entries(value)) clean[key] = sanitizeValue(childValue, key);
    return clean;
  }
  return value;
}

function safeIsDirectory(value) {
  try {
    return statSync(value).isDirectory();
  } catch {
    return false;
  }
}

function safeDocPath(docPath) {
  const normalized = String(docPath || "").replaceAll("\\", "/");
  if (normalized.includes("..")) return path.join(docsRoot, "__invalid__");
  return path.join(docsRoot, normalized);
}

function countAvailableDocs() {
  return Object.values(docs).flat().filter(([docPath]) => existsSync(safeDocPath(docPath))).length;
}

function humanName(value) {
  return String(value).replace(/[-_]+/g, " ").replace(/\b\w/g, (match) => match.toUpperCase());
}

function bytesLabel(bytes) {
  if (!bytes) return "unlimited";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = Number(bytes);
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${Math.round(value * 10) / 10} ${units[index]}`;
}

function rid() {
  return randomBytes(8).toString("hex");
}

function empty(title, message) {
  return `<div class="empty"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(message)}</p></div>`;
}

function advancedServices() {
  return [
    ["Traefik", "reverse proxy"], ["WAF", "ModSecurity CRS"], ["MariaDB", "local PHP database"], ["PostgreSQL", "platform database"],
    ["Redis", "cache/session support"], ["NATS", "messaging"], ["Keycloak", "identity provider"], ["MinIO", "object storage"],
    ["Prometheus", "metrics"], ["Loki", "logs"], ["Alertmanager", "alert routing"], ["Grafana", "observability UI"],
    ["backup scheduler", "scheduled backup orchestration"], ["workers", "jobs and notifications"], ["node-exporter", "host metrics"], ["cAdvisor", "container metrics"],
  ].map(([name, role]) => ({ name, role, status: name === "backup scheduler" ? "planned adapter" : "configured" }));
}

function navigationForMode(mode) {
  if (mode === "advanced") {
    return [
      ["infrastructure", "Infrastructure", "INF"], ["network", "Network", "NET"], ["databases", "Databases", "DB"], ["storage", "Storage", "S3"],
      ["deployments", "Deployments", "DEP"], ["cloudflare", "Cloudflare", "CF"], ["monitoring", "Monitoring", "MON"], ["backup-restore", "Backup & Restore", "BKP"],
      ["go-no-go", "Production Go/No-Go", "GO"], ["identity", "Identity & Access", "IAM"], ["secrets", "Secrets", "SEC"], ["audit", "Audit Log", "AUD"],
    ].map(([id, label, short]) => ({ id, label, short }));
  }
  return [
    ["overview", "Overview", "OVR"], ["projects", "Projects", "PRJ"], ["applications", "Applications", "APP"], ["domains", "Domains & Subdomains", "DNS"],
    ["webspaces", "Web Spaces", "WEB"], ["resources", "Resources", "RES"], ["security", "Security", "SEC"], ["backups", "Backups", "BKP"],
    ["logs", "Logs / Alerts", "LOG"], ["settings", "Settings", "SET"],
  ].map(([id, label, short]) => ({ id, label, short }));
}

function advancedItems(section) {
  const map = {
    databases: ["MariaDB", "PostgreSQL", "backup DB", "restore DB", "users and permissions"],
    storage: ["MinIO buckets", "quota", "access key policy", "lifecycle", "bucket restore"],
    deployments: ["deploy history", "image digest", "SBOM", "provenance", "rollback target"],
    cloudflare: ["DNS records", "Access policies", "WAF rules", "Cache rules", "Remote verification"],
    monitoring: ["Prometheus", "cAdvisor", "node-exporter", "latency", "error rate"],
    "go-no-go": ["production-go-no-go", "evidence bundle", "live blockers", "JSON/Markdown reports"],
    identity: ["users", "teams", "roles", "passkeys", "sessions", "login audit"],
    secrets: ["Docker secrets", "KMS metadata", "rotation", "usage map", "no plaintext values"],
  };
  return map[section] || ["dry-run adapter", "apply confirmation", "verify evidence"];
}

function json(res, payload, status = 200) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(`${JSON.stringify(payload, null, 2)}\n`);
}

function html(res, content, status = 200) {
  res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  res.end(content);
}

function redirect(res, location) {
  res.writeHead(303, { location, "cache-control": "no-store" });
  res.end();
}

function notFound(res) {
  json(res, { error: "not_found", message: "Control endpoint not found." }, 404);
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

function styleTag() {
  return `<style>
:root{color-scheme:dark;--bg:#0b1117;--panel:#121a23;--panel-2:#172231;--text:#eef5ff;--muted:#9eb0c5;--line:#263547;--accent:#76e4c5;--accent-2:#8fb7ff;--danger:#ff8b8b;--warn:#f6d66f;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text)}a{color:inherit;text-decoration:none}button,input,select{font:inherit}.control-shell{display:grid;grid-template-columns:280px minmax(0,1fr);min-height:100vh}.sidebar{position:sticky;top:0;height:100vh;padding:18px;border-right:1px solid var(--line);background:#090f15;overflow:auto}.brand{display:flex;gap:12px;align-items:center;padding-bottom:18px;border-bottom:1px solid var(--line)}.brand-mark{display:grid;place-items:center;width:42px;height:42px;border:1px solid var(--accent);border-radius:8px;color:var(--accent);font-weight:900}.brand strong,.brand small{display:block}.brand small{color:var(--muted)}nav{display:grid;gap:8px;margin-top:18px}nav a{display:flex;align-items:center;gap:10px;min-height:40px;padding:8px 10px;border:1px solid transparent;border-radius:8px;color:var(--muted);font-weight:800}nav a span{display:inline-grid;place-items:center;min-width:38px;min-height:26px;border:1px solid var(--line);border-radius:7px;color:var(--accent-2);font-size:11px}nav a.active,nav a:hover{color:var(--text);background:var(--panel);border-color:var(--line)}.mode-card{margin-top:18px;padding:12px;border:1px solid var(--line);border-radius:8px;background:var(--panel)}.mode-card small{color:var(--muted)}.segmented{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:8px}.segmented a{display:grid;place-items:center;min-height:34px;border:1px solid var(--line);border-radius:8px;color:var(--muted);font-weight:850}.segmented a.selected{color:var(--accent);border-color:var(--accent)}.workspace{width:min(1240px,calc(100% - 32px));margin:0 auto;padding:28px 0 48px}.topbar{display:flex;justify-content:space-between;align-items:end;gap:18px;padding-bottom:22px;border-bottom:1px solid var(--line)}.eyebrow{margin:0 0 8px;color:var(--accent);font-size:13px;font-weight:850;letter-spacing:0}h1{margin:0;font-size:48px;line-height:1;letter-spacing:0}h2{margin:0;font-size:22px}h3{margin:18px 0 10px;color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:0}.top-actions{display:flex;align-items:center;justify-content:end;gap:10px;flex-wrap:wrap}.switcher select{min-height:38px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--text);padding:0 10px}.pill,.state{display:inline-flex;align-items:center;min-height:30px;padding:0 10px;border:1px solid var(--line);border-radius:999px;font-size:12px;font-weight:850;color:var(--muted)}.pill.info,.state.on{color:var(--accent);border-color:color-mix(in srgb,var(--accent) 55%,var(--line))}.pill.danger,.state.off{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 55%,var(--line))}.metric-grid{display:grid;grid-template-columns:repeat(4,minmax(140px,1fr));gap:12px;margin-top:22px}.metric{min-height:96px;padding:16px;background:var(--panel);border:1px solid var(--line);border-radius:8px}.metric span{display:block;font-size:34px;font-weight:900;color:var(--accent-2)}.metric small{color:var(--muted)}.grid{display:grid;gap:16px;margin-top:22px}.grid.two{grid-template-columns:minmax(0,1.15fr) minmax(320px,.85fr)}.panel{margin-top:22px;padding:18px;background:var(--panel);border:1px solid var(--line);border-radius:8px}.grid .panel{margin-top:0}.panel-head{display:flex;gap:12px;align-items:center;margin-bottom:16px}.panel-head>span{display:inline-grid;place-items:center;width:42px;height:42px;border:1px solid var(--accent);border-radius:8px;color:var(--accent);font-size:12px;font-weight:900}.panel-head p{margin:4px 0 0;color:var(--muted);font-size:13px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px}.card{min-height:96px;padding:14px;background:var(--panel-2);border:1px solid var(--line);border-radius:8px;transition:transform .18s ease,border-color .18s ease,background .18s ease}a.card:hover,.project-card:hover{transform:translateY(-2px);border-color:var(--accent);background:#1a2838}.card strong{display:block;font-size:15px}.card span{display:block;margin-top:8px;color:var(--muted);font-size:13px;line-height:1.45}.card.compact{min-height:78px}.project-cards{margin-top:16px}.project-card{min-height:164px;display:flex;flex-direction:column;gap:4px}.project-card.is-off{opacity:.76}.card-title{display:flex;align-items:start;justify-content:space-between;gap:10px}.card-title em{padding:4px 8px;border:1px solid var(--line);border-radius:999px;color:var(--accent);font-size:11px;font-style:normal;font-weight:850}.card .host{color:var(--accent-2);font-weight:850;overflow-wrap:anywhere}.project-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:auto;padding-top:12px}.button{display:inline-flex;align-items:center;justify-content:center;min-height:34px;padding:0 12px;border:1px solid var(--line);border-radius:8px;background:#101820;color:var(--text);font-size:13px;font-weight:850;cursor:pointer}.button.open,.button.enable{border-color:color-mix(in srgb,var(--accent) 60%,var(--line));color:var(--accent)}.button.danger{border-color:color-mix(in srgb,var(--danger) 60%,var(--line));color:var(--danger)}.button.muted{color:var(--muted);cursor:not-allowed;opacity:.55}.status-list{display:grid;gap:10px;padding:0;margin:0;list-style:none}.status-list li{display:flex;justify-content:space-between;gap:16px;padding:12px;background:var(--panel-2);border:1px solid var(--line);border-radius:8px}.status-list span{color:var(--muted);text-align:right}.json-block,pre{overflow:auto;white-space:pre-wrap;margin:0;color:#dce8f7;line-height:1.55;font-size:14px}.empty{padding:18px;background:#101820;border:1px dashed var(--line);border-radius:8px;color:var(--muted)}.disabled{opacity:.45;pointer-events:none}.login-shell{display:grid;place-items:center;min-height:100vh;padding:24px}.login-panel{width:min(460px,100%);padding:24px;border:1px solid var(--line);border-radius:8px;background:var(--panel)}.login-panel h1{font-size:38px}.login-copy{color:var(--muted);line-height:1.55}.login-form{display:grid;gap:12px;margin-top:20px}.login-form label{color:var(--muted);font-size:13px;font-weight:850}.login-form input{min-height:42px;padding:0 12px;border:1px solid var(--line);border-radius:8px;background:#090f15;color:var(--text)}@media(max-width:980px){.control-shell{display:block}.sidebar{position:static;height:auto}.workspace{width:min(100% - 24px,1240px)}.topbar,.grid.two{display:block}.metric-grid{grid-template-columns:repeat(2,1fr)}h1{font-size:36px}.top-actions{justify-content:start;margin-top:14px}}
</style>`;
}

class ValidationError extends Error {}
class RejectedOperationError extends Error {}
