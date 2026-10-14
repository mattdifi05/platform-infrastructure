import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { parseCloudflareDnsZones } from './cloudflare-dns.mjs';
import { visibilityDigest, visibilityHostnames } from '../hosting/visibility.mjs';

const ID32 = /^[a-f0-9]{32}$/;
const CF_ID = /^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/i;
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const API = 'https://api.cloudflare.com/client/v4';
const STATE_SCHEMA = 1;
const tunnelApplyLocks = new Map();

function readProtectedFile(file, { secret = false } = {}) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(fd);
    const ownerOkay = stat.uid === 0 || (secret && stat.uid === process.getuid());
    if (!stat.isFile() || !ownerOkay || (stat.mode & (secret ? 0o077 : 0o022)) || stat.size > 256 * 1024) throw Error();
    return fs.readFileSync(fd, 'utf8').trim();
  } catch {
    throw Error('Cloudflare visibility protected configuration unavailable');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function exactKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !keys.includes(key))) {
    throw Error(`Invalid ${label}`);
  }
}

export function parseCloudflareVisibilityConfig(text, zones) {
  let config;
  try { config = JSON.parse(text); } catch { throw Error('Invalid Cloudflare visibility configuration'); }
  exactKeys(config, ['accountId', 'tunnelId', 'projects'], 'Cloudflare visibility configuration');
  if (!ID32.test(config.accountId) || !CF_ID.test(config.tunnelId) || !Array.isArray(config.projects) || config.projects.length > 500) {
    throw Error('Invalid Cloudflare visibility configuration');
  }
  const projects = config.projects.map(project => {
    exactKeys(project, ['id', 'hostname', 'baseDomain', 'ownerEmail', 'originService', 'cloneOriginService', 'relatedHostnames'], 'Cloudflare project admission');
    const id = String(project.id || '').toLowerCase();
    const hostname = String(project.hostname || '').toLowerCase();
    const baseDomain = String(project.baseDomain || '').toLowerCase();
    const ownerEmail = String(project.ownerEmail || '').trim().toLowerCase();
    const originService = String(project.originService || '');
    const cloneOriginService = String(project.cloneOriginService || '');
    if (!SLUG.test(id) || !EMAIL.test(ownerEmail) || !HOSTNAME.test(hostname) || !HOSTNAME.test(baseDomain)
      || !(hostname === baseDomain || hostname.endsWith(`.${baseDomain}`))
      || !isLoopbackOrigin(originService) || !isLoopbackOrigin(cloneOriginService)) throw Error('Invalid Cloudflare project admission');
    const zone = zones.filter(candidate => hostname === candidate.name || hostname.endsWith(`.${candidate.name}`))
      .sort((a, b) => b.name.length - a.name.length)[0];
    if (!zone || !(baseDomain === zone.name || baseDomain.endsWith(`.${zone.name}`))) throw Error('Project hostname is outside verified Cloudflare zones');
    const relatedHostnames = project.relatedHostnames || [];
    if (!Array.isArray(relatedHostnames) || relatedHostnames.length > 20 || relatedHostnames.some(host => typeof host !== 'string' || !HOSTNAME.test(host) || !host.endsWith(`.${baseDomain}`) || host === hostname) || new Set(relatedHostnames).size !== relatedHostnames.length) throw Error('Invalid related hostname admission');
    return { id, hostname, baseDomain, ownerEmail, originService, cloneOriginService, zone, relatedHostnames };
  });
  if (new Set(projects.map(p => p.id)).size !== projects.length || new Set(projects.map(p => p.hostname)).size !== projects.length) {
    throw Error('Duplicate Cloudflare project admission');
  }
  const expandedProjects = projects.flatMap(project => [project, ...project.relatedHostnames.map(hostname => ({ ...project, id: `host-${visibilityDigest({ id: project.id, hostname }).slice(0, 20)}`, hostname, relatedHostnames: [], aliasOf: project.id }))]);
  const admissions = expandedProjects.flatMap(project => {
    const cloneId = `local-${project.id}`;
    const cloneHostname = visibilityHostnames(project, [project.zone]).privateHostname;
    if (!SLUG.test(cloneId)) throw Error('Derived clone project identifier is too long');
    return [{ id: project.id, hostname: project.hostname }, { id: cloneId, hostname: cloneHostname }];
  });
  if (new Set(admissions.map(project => project.id)).size !== admissions.length
    || new Set(admissions.map(project => project.hostname)).size !== admissions.length) throw Error('Source and derived clone admissions conflict');
  return { accountId: config.accountId, tunnelId: config.tunnelId, projects: expandedProjects };
}

const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function isLoopbackOrigin(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.port !== ''
      && Number(url.port) >= 1 && Number(url.port) <= 65535 && !url.username && !url.password
      && (url.pathname === '/' || url.pathname === '') && !url.search && !url.hash;
  } catch { return false; }
}

function parseManagedState(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schemaVersion !== STATE_SCHEMA
    || !value.routes || typeof value.routes !== 'object' || Array.isArray(value.routes)) throw Error('Cloudflare visibility state is invalid');
  const routes = {};
  for (const [hostname, route] of Object.entries(value.routes)) {
    if (!HOSTNAME.test(hostname) || !route || typeof route !== 'object' || Array.isArray(route)
      || !SLUG.test(route.projectId) || route.hostname !== hostname
      || (route.accessAppId != null && !CF_ID.test(route.accessAppId))
      || (route.accessPolicyId != null && !CF_ID.test(route.accessPolicyId))
      || (route.dnsRecordId != null && !ID32.test(route.dnsRecordId))
      || (route.routeDigest != null && !/^[a-f0-9]{64}$/.test(route.routeDigest))
      || (route.routeKind != null && !['origin', 'offline-block'].includes(route.routeKind))
      || !['public', 'private', 'offline'].includes(route.mode)) throw Error('Cloudflare visibility state is invalid');
    routes[hostname] = { ...route };
  }
  return { schemaVersion: STATE_SCHEMA, routes };
}

function readStateFile(file) {
  try {
    const info = fs.lstatSync(file);
    if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077)) throw Error();
    return parseManagedState(JSON.parse(fs.readFileSync(file, 'utf8')));
  } catch (error) {
    if (error.code === 'ENOENT') return { schemaVersion: STATE_SCHEMA, routes: {} };
    throw Error('Cloudflare visibility state is unavailable');
  }
}

function writeStateFile(file, state) {
  const validated = parseManagedState(state);
  const directory = path.dirname(file);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  let fd;
  try {
    fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(fd, `${JSON.stringify(validated)}\n`, 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temporary, file);
    fs.chmodSync(file, 0o600);
  } catch {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temporary); } catch {}
    throw Error('Cloudflare visibility state could not be saved');
  }
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
}

function ownerTag(projectId) { return `control-center:visibility:v1:${projectId}`; }
function accessName(projectId) { return `control-center-visibility-v1-${projectId}`; }
function routeFingerprint(rule) { return visibilityDigest(canonical(rule)); }
function dnsFingerprint(record) {
  return visibilityDigest(canonical({ id: record.id, type: record.type, name: record.name, content: record.content, proxied: record.proxied, tags: record.tags || [], comment: record.comment || '' }));
}
function wildcardMatchesHost(hostname, ingress) {
  return ingress.some(rule => typeof rule.hostname === 'string' && rule.hostname.startsWith('*.')
    && hostname.endsWith(rule.hostname.slice(1)) && hostname !== rule.hostname.slice(2));
}
function accessPolicy(project) {
  return {
    name: `${accessName(project.id)}-owner`,
    decision: 'allow',
    include: [{ email: { email: project.ownerEmail } }],
    exclude: [],
    require: [],
    precedence: 1,
  };
}
function safePolicy(policy, project) {
  return policy?.name === `${accessName(project.id)}-owner`
    && policy.decision === 'allow'
    && Array.isArray(policy.include)
    && policy.include.length === 1
    && policy.include[0] && Object.keys(policy.include[0]).length === 1
    && policy.include[0].email && Object.keys(policy.include[0].email).length === 1
    && typeof policy.include[0].email.email === 'string'
    && policy.include[0].email.email.toLowerCase() === project.ownerEmail
    && (!policy.exclude || policy.exclude.length === 0)
    && (!policy.require || policy.require.length === 0);
}

function normalizeProject(input, config) {
  const id = String(input?.id || input?.slug || '').toLowerCase();
  const source = config.projects.find(project => project.id === id);
  const sourceId = id.startsWith('local-') ? id.slice('local-'.length) : '';
  const origin = source || config.projects.find(project => project.id === sourceId);
  if (!origin) {
    throw Error('Project is not in the host-only Cloudflare visibility admission');
  }
  const clone = !source;
  const derived = clone ? visibilityHostnames(origin, [origin.zone]) : null;
  const hostname = clone ? derived.privateHostname : origin.hostname;
  const projectId = clone ? `local-${origin.id}` : origin.id;
  const baseDomain = origin.baseDomain;
  const originService = clone ? origin.cloneOriginService : origin.originService;
  if (projectId !== id || input.hostname && String(input.hostname).toLowerCase() !== hostname
    || input.baseDomain && String(input.baseDomain).toLowerCase() !== baseDomain
    || input.originService && String(input.originService) !== originService) {
    throw Error('Project does not match its host-only visibility admission');
  }
  return { id: projectId, sourceId: origin.id, hostname, baseDomain, ownerEmail: origin.ownerEmail, originService, zone: origin.zone, isClone: clone };
}

function makeFileStateStore(file) {
  return { load: () => readStateFile(file), save: state => writeStateFile(file, state) };
}

function loadConfiguration(env) {
  const configPath = env.CONTROL_CENTER_CLOUDFLARE_VISIBILITY_CONFIG_FILE;
  const zonesPath = env.CONTROL_CENTER_CLOUDFLARE_DNS_CONFIG_FILE;
  const tokenPath = env.CONTROL_CENTER_CLOUDFLARE_VISIBILITY_TOKEN_FILE;
  if (!configPath || !zonesPath || !tokenPath) throw Error('Cloudflare visibility integration is not configured');
  const zones = parseCloudflareDnsZones(readProtectedFile(zonesPath));
  const config = parseCloudflareVisibilityConfig(readProtectedFile(configPath), zones);
  const token = readProtectedFile(tokenPath, { secret: true });
  if (!/^[A-Za-z0-9_-]{20,256}$/.test(token)) throw Error('Cloudflare visibility protected configuration unavailable');
  return { config, token };
}

export function createCloudflareVisibilityProvider({ env = process.env, fetchImpl = fetch, stateStore, now = () => new Date(), configuration } = {}) {
  const store = stateStore || makeFileStateStore(env.CONTROL_CENTER_CLOUDFLARE_VISIBILITY_STATE_FILE || '/var/www/project-state/cloudflare-visibility.json');
  const { config, token } = configuration
    ? { config: parseCloudflareVisibilityConfig(JSON.stringify(configuration.config), configuration.zones), token: configuration.token }
    : loadConfiguration(env);
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{20,256}$/.test(token)) throw Error('Cloudflare visibility protected configuration unavailable');
    const request = async (route, method = 'GET', body) => {
      let response, value;
      try {
        response = await fetchImpl(`${API}${route}`, {
          method, redirect: 'error', signal: AbortSignal.timeout(10000),
          headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
          ...(body ? { body: JSON.stringify(body) } : {}),
        });
        value = await response.json();
      } catch { throw Error('Cloudflare visibility provider unavailable'); }
      if (!response.ok || value?.success !== true) throw Error('Cloudflare visibility provider rejected the operation');
      return value;
    };

    async function list(pathname, maxPages = 20) {
      const records = [];
      for (let page = 1; page <= maxPages; page += 1) {
        const result = await request(`${pathname}${pathname.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
        if (!Array.isArray(result.result)) throw Error('Cloudflare visibility inventory is invalid');
        records.push(...result.result);
        const pages = Number(result.result_info?.total_pages ?? 1);
        if (pages === 0 && page === 1 && records.length === 0
          && Number(result.result_info?.total_count ?? 0) === 0) return records;
        if (!Number.isSafeInteger(pages) || pages < 1 || pages > maxPages) throw Error('Cloudflare visibility inventory exceeds its bound');
        if (page >= pages) return records;
      }
      throw Error('Cloudflare visibility inventory is incomplete');
    }

    async function readResources(project) {
      const state = parseManagedState(await store.load());
      const managed = state.routes[project.hostname] || null;
      const apps = await list(`/accounts/${config.accountId}/access/apps`);
      const tunnelResponse = await request(`/accounts/${config.accountId}/cfd_tunnel/${config.tunnelId}/configurations`);
      const tunnel = tunnelResponse.result;
      if (!Array.isArray(tunnel?.config?.ingress) || tunnel.config.ingress.length < 1) throw Error('Cloudflare Tunnel ingress configuration is invalid');
      if (tunnel.config.originRequest?.access) throw Error('Tunnel-wide origin Access gate is outside project ownership');
      const ingress = tunnel.config.ingress;
      const matchingRoutes = ingress.map((rule, index) => ({ rule, index })).filter(({ rule }) => rule.hostname === project.hostname);
      if (matchingRoutes.length > 1) throw Error('Multiple Cloudflare Tunnel routes match the project hostname');
      const route = matchingRoutes[0] || null;
      const dnsRecords = await list(`/zones/${project.zone.id}/dns_records?name=${encodeURIComponent(project.hostname)}`);
      const matchingDns = dnsRecords.filter(record => record.name === project.hostname
        && ['A', 'AAAA', 'CNAME'].includes(record.type));
      if (matchingDns.length > 1) throw Error('Multiple DNS records match the project hostname');
      const dns = matchingDns[0] || null;
      const exactApps = apps.filter(app => String(app.domain || '').toLowerCase() === project.hostname);
      if (exactApps.length > 1) throw Error('Multiple Cloudflare Access applications match the project hostname');
      const app = exactApps[0] || null;
      let policies = [];
      if (app) {
        if (!CF_ID.test(app.id) || app.name !== accessName(project.id) || app.type !== 'self_hosted') throw Error('Cloudflare Access application is not owned by this project');
        if (!managed?.accessAppId || managed.accessAppId !== app.id) throw Error('Cloudflare Access application is not registered in managed project state');
        policies = await list(`/accounts/${config.accountId}/access/apps/${app.id}/policies`);
        if (policies.length !== 1 || !safePolicy(policies[0], project) || !CF_ID.test(policies[0].id)) throw Error('Cloudflare Access policy is not the exact project-owner policy');
        if (managed.accessPolicyId !== policies[0].id) throw Error('Cloudflare Access policy ownership changed');
      } else if (managed?.accessAppId) {
        throw Error('Managed Cloudflare Access application is missing');
      }
      let adoptableRoute = false;
      if (route) {
        if (route.rule.originRequest?.access) throw Error('Origin Access gate is outside managed project ownership');
        if (Object.keys(route.rule).some(key => !['hostname', 'service', 'originRequest'].includes(key))) throw Error('Cloudflare Tunnel route differs from the admitted project service');
        if (managed?.routeDigest) {
          if (managed.routeDigest !== routeFingerprint(route.rule)) throw Error('Managed Cloudflare Tunnel route ownership changed');
          if (managed.routeKind === 'offline-block') {
            if (route.rule.service !== 'http_status:404') throw Error('Managed Cloudflare offline blocker changed');
          } else if (route.rule.service !== project.originService) throw Error('Managed Cloudflare Tunnel route differs from the admitted project service');
        } else if (!project.isClone && route.rule.service === project.originService && !route.rule.originRequest?.access) adoptableRoute = true;
        else throw Error('Cloudflare Tunnel route is not provably managed');
      } else if (managed?.routeDigest) {
        throw Error('Managed Cloudflare Tunnel route is missing');
      }
      let adoptableDns = false;
      if (dns) {
        const expectedTunnelRecord = dns.type === 'CNAME' && dns.name === project.hostname
          && dns.content === `${config.tunnelId}.cfargotunnel.com` && dns.proxied === true;
        if (!expectedTunnelRecord || !ID32.test(dns.id)) throw Error('Cloudflare DNS record differs from the admitted tunnel route');
        if (managed?.dnsRecordId) {
          if (dns.id !== managed.dnsRecordId || dns.comment !== ownerTag(project.id)) throw Error('Managed DNS record ownership changed');
          if (managed.dnsRecordDigest && managed.dnsRecordDigest !== dnsFingerprint(dns)) throw Error('Managed DNS ownership changed');
        } else if (!project.isClone && (!dns.tags?.length) && !dns.comment) adoptableDns = true;
        else throw Error('Cloudflare DNS record is not provably managed');
      } else if (managed?.dnsRecordId) {
        throw Error('Managed Cloudflare DNS record is missing');
      }
      const fallback = ingress.at(-1);
      if (!fallback || fallback.service !== 'http_status:404' || fallback.hostname !== undefined) throw Error('Cloudflare Tunnel must end with the standard 404 fallback');
      const access = app ? { id: app.id, policyId: policies[0].id, name: app.name, domain: app.domain } : null;
      return { config, project, state, managed, apps, tunnel, ingress, route, dns, access, policies, adoptableRoute, adoptableDns };
    }

    function currentMode(resources) {
      if (!resources.route || resources.managed?.routeKind === 'offline-block') return 'offline';
      return resources.access ? 'private' : 'public';
    }

    async function planVisibility(input, mode) {
      if (!['public', 'private', 'offline'].includes(mode)) throw Error('Visibility mode is invalid');
      const project = normalizeProject(input, config);
      const resources = await readResources(project);
      if (project.isClone && mode === 'public' && !resources.managed) throw Error('Clone must first be initialized with private visibility');
      const observed = {
        projectId: project.id,
        hostname: project.hostname,
        mode: currentMode(resources),
        route: resources.route ? routeFingerprint(resources.route.rule) : null,
        dns: resources.dns ? dnsFingerprint(resources.dns) : null,
        accessAppId: resources.access?.id || null,
        accessPolicyId: resources.access?.policyId || null,
        managed: resources.managed,
        adoptableRoute: resources.adoptableRoute,
        adoptableDns: resources.adoptableDns,
        tunnelVersion: resources.tunnel.version ?? null,
        tunnelConfig: visibilityDigest(canonical(resources.tunnel.config)),
      };
      const revision = visibilityDigest(canonical(observed));
      const actions = mode === 'private'
        ? ['ensure exact owner-only Cloudflare Access application before route', 'ensure ownership-marked CNAME to the admitted tunnel', 'ensure exact host route to the admitted project router']
        : mode === 'public'
          ? ['ensure ownership-marked CNAME to the admitted tunnel', 'ensure exact host route to the admitted project router', 'remove only this project’s exact Access application after route readback']
          : ['remove only this project’s exact host route', 'remove only this project’s ownership-marked CNAME', 'retain the exact Cloudflare Access application and policy'];
      if (resources.adoptableRoute || resources.adoptableDns) actions.unshift('adopt only the exact registered source host route and matching tunnel DNS record after revision confirmation');
      if (mode === 'offline' && wildcardMatchesHost(project.hostname, resources.ingress)) actions.unshift('replace the exact forwarding route with an exact 404 blocker so a broader Tunnel wildcard cannot expose the project');
      return {
        schemaVersion: 1,
        action: 'project.visibility',
        projectId: project.id,
        hostname: project.hostname,
        requestedMode: mode,
        currentMode: observed.mode,
        revision,
        confirmationRequired: `SET-VISIBILITY:${project.id}:${mode}:${revision}`,
        dryRun: true,
        providerTouched: false,
        actions,
        verifiedAt: now().toISOString(),
      };
    }

    async function saveRouteState(project, mutate) {
      const state = parseManagedState(await store.load());
      const current = state.routes[project.hostname] || { projectId: project.id, hostname: project.hostname, mode: 'offline' };
      if (current.projectId !== project.id) throw Error('Cloudflare visibility state ownership conflict');
      const next = mutate({ ...current });
      state.routes[project.hostname] = next;
      await store.save(state);
      return next;
    }

    async function applyVisibilityLocked(plan, { expectedRevision, confirm, gateOnly = false } = {}) {
      if (plan?.action === 'project.visibility-group') {
        const fresh = await planGroup({ id: plan.projectId }, plan.requestedMode);
        if (plan.revision !== fresh.revision || expectedRevision !== fresh.revision || confirm !== fresh.confirmationRequired) throw Error('Visibility plan changed or explicit confirmation is missing');
        if (plan.requestedMode === 'private') {
          for (const child of fresh.hostPlans) await applyVisibilityLocked(child, { expectedRevision: child.revision, confirm: child.confirmationRequired, gateOnly: true });
        }
        for (const child of fresh.hostPlans) {
          const current = await planVisibility({ id: child.projectId }, child.requestedMode);
          await applyVisibilityLocked(current, { expectedRevision: current.revision, confirm: current.confirmationRequired });
        }
        const status = await getGroup({ id: plan.projectId });
        if (!status.verified || status.effective !== plan.requestedMode) throw Error('Aggregate visibility state failed readback');
        return { ...status, providerTouched: true };
      }
      if (!plan || plan.action !== 'project.visibility' || plan.schemaVersion !== 1 || plan.dryRun !== true
        || !['public', 'private', 'offline'].includes(plan.requestedMode)) throw Error('Visibility plan is invalid');
      const project = normalizeProject({ id: plan.projectId, hostname: plan.hostname }, config);
      const fresh = await planVisibility(project, plan.requestedMode);
      if (expectedRevision !== fresh.revision || confirm !== fresh.confirmationRequired || plan.revision !== fresh.revision) {
        throw Error('Visibility plan changed or explicit confirmation is missing');
      }
      const resources = await readResources(project);
      const routeRule = { hostname: project.hostname, service: project.originService };
      const tunnelPath = `/accounts/${config.accountId}/cfd_tunnel/${config.tunnelId}/configurations`;
      const zonePath = `/zones/${project.zone.id}/dns_records`;
      const tunnelCname = `${config.tunnelId}.cfargotunnel.com`;
      let access = resources.access;
      let dns = resources.dns;
      let route = resources.route;

      const setIngress = async nextIngress => {
        const fallback = nextIngress.at(-1);
        if (fallback?.service !== 'http_status:404' || fallback.hostname !== undefined) throw Error('Cloudflare Tunnel fallback would be changed');
        const beforeWrite = await request(tunnelPath);
        if (!beforeWrite.result?.config
          || visibilityDigest(canonical(beforeWrite.result.config)) !== visibilityDigest(canonical(resources.tunnel.config))
          || (beforeWrite.result.version ?? null) !== (resources.tunnel.version ?? null)) {
          throw Error('Cloudflare Tunnel configuration changed before write');
        }
        await request(tunnelPath, 'PUT', { config: { ...resources.tunnel.config, ingress: nextIngress } });
        const readback = await request(tunnelPath);
        const actual = readback.result?.config?.ingress;
        if (!Array.isArray(actual) || visibilityDigest(canonical(actual)) !== visibilityDigest(canonical(nextIngress))) throw Error('Cloudflare Tunnel route readback differs');
        resources.tunnel = readback.result;
        resources.ingress = actual;
        resources.route = actual.map((rule, index) => ({ rule, index })).find(({ rule }) => rule.hostname === project.hostname) || null;
        route = resources.route;
      };
      const ensureRoute = async () => {
        if (route?.rule.service === 'http_status:404' && resources.managed?.routeKind === 'offline-block') {
          const ingress = resources.ingress.map((rule, index) => index === route.index ? routeRule : rule);
          await setIngress(ingress);
        } else if (!route) {
          const wildcardIndex = resources.ingress.slice(0, -1).findIndex(rule => typeof rule.hostname === 'string' && rule.hostname.startsWith('*'));
          const insertAt = wildcardIndex >= 0 ? wildcardIndex : resources.ingress.length - 1;
          const ingress = [...resources.ingress.slice(0, insertAt), routeRule, ...resources.ingress.slice(insertAt)];
          await setIngress(ingress);
        }
        if (!route || route.rule.hostname !== project.hostname || route.rule.service !== routeRule.service) throw Error('Cloudflare Tunnel route readback failed');
        const routeDigest = routeFingerprint(route.rule);
        const stateRecord = await saveRouteState(project, current => ({ ...current, routeDigest, routeKind: 'origin' }));
        return stateRecord;
      };
      const ensureDns = async () => {
        if (!dns) {
          const body = { type: 'CNAME', name: project.hostname, content: tunnelCname, proxied: true, ttl: 1, comment: ownerTag(project.id) };
          const created = await request(zonePath, 'POST', body);
          const result = created.result;
          if (!result || !ID32.test(result.id) || result.name !== project.hostname || result.content !== tunnelCname || result.proxied !== true || result.comment !== ownerTag(project.id)) throw Error('Created Cloudflare DNS record failed owner verification');
          dns = result;
        } else if (!(await store.load()).routes[project.hostname]?.dnsRecordId) {
          const patch = Object.fromEntries(['type', 'name', 'content', 'ttl', 'proxied', 'settings'].filter(key => dns[key] !== undefined).map(key => [key, dns[key]]));
          patch.comment = ownerTag(project.id);
          await request(`${zonePath}/${dns.id}`, 'PATCH', patch);
          const readback = await list(`${zonePath}?name=${encodeURIComponent(project.hostname)}`);
          const actual = readback.find(record => record.id === dns.id);
          if (!actual || actual.name !== project.hostname || actual.type !== 'CNAME' || actual.content !== tunnelCname || actual.proxied !== true
            || actual.comment !== ownerTag(project.id)) throw Error('Adopted Cloudflare DNS record readback differs');
          dns = actual;
        }
        await saveRouteState(project, current => ({ ...current, dnsRecordId: dns.id, dnsRecordDigest: dnsFingerprint(dns) }));
        return dns;
      };
      const ensureAccess = async () => {
        if (!access) {
          const body = {
            name: accessName(project.id), domain: project.hostname, type: 'self_hosted',
            app_launcher_visible: false, session_duration: '24h', policies: [accessPolicy(project)],
          };
          const created = await request(`/accounts/${config.accountId}/access/apps`, 'POST', body);
          const result = created.result;
          if (!result || !CF_ID.test(result.id) || result.name !== accessName(project.id) || result.domain !== project.hostname || result.type !== 'self_hosted') throw Error('Cloudflare Access creation failed exact ownership verification');
          const createdPolicies = Array.isArray(result.policies) ? result.policies : await list(`/accounts/${config.accountId}/access/apps/${result.id}/policies`);
          if (createdPolicies.length !== 1 || !safePolicy(createdPolicies[0], project) || !CF_ID.test(createdPolicies[0].id)) throw Error('Cloudflare Access policy failed owner-only verification');
          access = { id: result.id, policyId: createdPolicies[0].id, name: result.name, domain: result.domain };
          await saveRouteState(project, current => ({ ...current, accessAppId: access.id, accessPolicyId: access.policyId }));
        }
        const confirmedApps = await list(`/accounts/${config.accountId}/access/apps`);
        const confirmedApp = confirmedApps.filter(app => String(app.domain || '').toLowerCase() === project.hostname);
        const confirmedPolicies = await list(`/accounts/${config.accountId}/access/apps/${access.id}/policies`);
        if (confirmedApp.length !== 1 || confirmedApp[0].id !== access.id || confirmedApp[0].name !== accessName(project.id)
          || confirmedApp[0].type !== 'self_hosted' || confirmedPolicies.length !== 1
          || confirmedPolicies[0].id !== access.policyId || !safePolicy(confirmedPolicies[0], project)) {
          throw Error('Cloudflare Access owner protection failed independent readback');
        }
        return access;
      };

      if (plan.requestedMode === 'private') {
        await ensureAccess();
        if (gateOnly) return { providerTouched: true };
        await ensureDns();
        await ensureRoute();
      } else if (plan.requestedMode === 'public') {
        await ensureDns();
        await ensureRoute();
        if (access) {
          const managed = (await store.load()).routes[project.hostname];
          if (!managed || managed.projectId !== project.id || managed.accessAppId !== access.id || managed.accessPolicyId !== access.policyId) throw Error('Refusing to ungate an Access application without exact persisted ownership');
          await request(`/accounts/${config.accountId}/access/apps/${access.id}`, 'DELETE');
          await saveRouteState(project, current => { delete current.accessAppId; delete current.accessPolicyId; current.mode = 'public'; return current; });
          access = null;
        }
      } else {
        if (dns && !(await store.load()).routes[project.hostname]?.dnsRecordId) await ensureDns();
        if (route && !(await store.load()).routes[project.hostname]?.routeDigest) await ensureRoute();
        const needsWildcardBlock = wildcardMatchesHost(project.hostname, resources.ingress);
        if (needsWildcardBlock && route?.rule.service !== 'http_status:404') {
          const blockRule = { hostname: project.hostname, service: 'http_status:404' };
          const ingress = route
            ? resources.ingress.map((rule, index) => index === route.index ? blockRule : rule)
            : (() => {
                const wildcardIndex = resources.ingress.findIndex(rule => typeof rule.hostname === 'string' && rule.hostname.startsWith('*'));
                const insertAt = wildcardIndex >= 0 ? wildcardIndex : resources.ingress.length - 1;
                return [...resources.ingress.slice(0, insertAt), blockRule, ...resources.ingress.slice(insertAt)];
              })();
          await setIngress(ingress);
          await saveRouteState(project, current => ({ ...current, routeDigest: routeFingerprint(route.rule), routeKind: 'offline-block', mode: 'offline' }));
          route = resources.route;
        } else if (route && route.rule.service !== 'http_status:404') {
          const managed = (await store.load()).routes[project.hostname];
          if (!managed?.routeDigest || managed.routeDigest !== routeFingerprint(route.rule)) throw Error('Refusing to remove a Tunnel route without exact persisted ownership');
          const ingress = resources.ingress.filter((_, index) => index !== route.index);
          await setIngress(ingress);
          await saveRouteState(project, current => { delete current.routeDigest; delete current.routeKind; current.mode = 'offline'; return current; });
          route = null;
        } else if (route?.rule.service === 'http_status:404' && resources.managed?.routeKind === 'offline-block') {
          await saveRouteState(project, current => ({ ...current, mode: 'offline' }));
        }
        if (dns) {
          const managed = (await store.load()).routes[project.hostname];
          if (!managed?.dnsRecordId || managed.dnsRecordId !== dns.id || dns.comment !== ownerTag(project.id)) throw Error('Refusing to remove a DNS record without exact persisted ownership');
          await request(`${zonePath}/${dns.id}`, 'DELETE');
          await saveRouteState(project, current => { delete current.dnsRecordId; delete current.dnsRecordDigest; current.mode = 'offline'; return current; });
          dns = null;
        }
      }
      await saveRouteState(project, current => ({ ...current, mode: plan.requestedMode, updatedAt: now().toISOString() }));
      const status = await getVisibility(project);
      if (!status.verified || status.effective !== plan.requestedMode) throw Error('Cloudflare visibility apply completed but effective state failed readback');
      return { ...status, providerTouched: true };
    }

    async function applyVisibility(plan, options = {}) {
      const admittedMembers = members({ id: plan?.projectId, hostname: plan?.hostname });
      if (admittedMembers.length > 1 && plan?.action !== 'project.visibility-group') throw Error('Related hostnames require the complete aggregate visibility plan');
      const lockKey = `${config.accountId}:${config.tunnelId}`;
      const previous = tunnelApplyLocks.get(lockKey) || Promise.resolve();
      let release;
      const current = new Promise(resolve => { release = resolve; });
      const queued = previous.then(() => current);
      tunnelApplyLocks.set(lockKey, queued);
      await previous;
      try {
        return await applyVisibilityLocked(plan, options);
      } finally {
        release();
        if (tunnelApplyLocks.get(lockKey) === queued) tunnelApplyLocks.delete(lockKey);
      }
    }

    async function edgeOwnerGate(project) {
      try {
        const response = await fetchImpl(`https://${project.hostname}/`, {
          method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(3000),
          headers: { Accept: 'text/html', 'Cache-Control': 'no-cache' },
        });
        const challenge = new URL(response.headers.get('location') || '', `https://${project.hostname}`);
        return response.status === 302 && challenge.protocol === 'https:'
          && challenge.hostname.endsWith('.cloudflareaccess.com')
          && challenge.pathname.startsWith('/cdn-cgi/access/login/');
      } catch { return false; }
    }

    async function getVisibility(input) {
      const project = normalizeProject(input, config);
      const resources = await readResources(project);
      const managed = resources.managed;
      const effective = currentMode(resources);
      const accessMatchesMode = effective === 'private' ? Boolean(resources.access) : effective === 'public' ? !resources.access : true;
      const adoptablePublic = !managed && !project.isClone && effective === 'public' && resources.adoptableRoute && resources.adoptableDns && !resources.access;
      const apiVerified = adoptablePublic || Boolean(managed && managed.mode === effective && accessMatchesMode
        && (effective === 'offline' ? (!resources.route || managed.routeKind === 'offline-block') && !resources.dns : resources.route && resources.dns)
      );
      const edgeVerified = effective === 'private' ? await edgeOwnerGate(project) : null;
      const verified = apiVerified && (effective !== 'private' || edgeVerified);
      return {
        projectId: project.id,
        hostname: project.hostname,
        desired: managed?.mode || (adoptablePublic ? 'public' : 'unmanaged'),
        managed: Boolean(managed),
        adoptable: Boolean(adoptablePublic),
        effective,
        verified,
        edgeVerified,
        updatedAt: managed?.updatedAt || null,
        access: resources.access ? 'owner-only' : 'not-applied',
        accessApplicationId: resources.access?.id || null,
        accessPolicyId: resources.access?.policyId || null,
        verifiedAt: now().toISOString(),
      };
    }

  // Admission metadata has no credentials or owner email; source and derived clone
  // inputs remain bound to the protected configuration by normalizeProject.
  const getProject = id => {
    const project = normalizeProject({ id }, config);
    return { id: project.id, sourceId: project.sourceId, hostname: project.hostname,
      baseDomain: project.baseDomain, originService: project.originService, isClone: project.isClone };
  };
  const getPrivate = sourceId => {
    const source = config.projects.find(project => project.id === String(sourceId).toLowerCase());
    if (!source) throw Error('Source project is not in the host-only Cloudflare visibility admission');
    return getProject(`local-${source.id}`);
  };
  const listProjects = () => config.projects.filter(project => !project.aliasOf).flatMap(project => [getProject(project.id), getPrivate(project.id)]);
  const members = input => {
    const admitted = normalizeProject(input, config);
    const source = config.projects.find(project => project.id === admitted.sourceId);
    if (source?.aliasOf) throw Error('Related hostname is only managed through its admitted project');
    return [admitted, ...config.projects.filter(project => project.aliasOf === source.id).map(project => normalizeProject({ id: admitted.isClone ? `local-${project.id}` : project.id }, config))];
  };
  async function planGroup(input, mode) {
    const group = members(input);
    if (group.length === 1) return planVisibility(input, mode);
    const hostPlans = [];
    for (const project of group) hostPlans.push(await planVisibility(project, mode));
    const revision = visibilityDigest(hostPlans.map(plan => ({ projectId: plan.projectId, revision: plan.revision })));
    return { ...hostPlans[0], action: 'project.visibility-group', revision,
      confirmationRequired: `SET-VISIBILITY:${group[0].id}:${mode}:${revision}`,
      hostnames: group.map(project => project.hostname), hostPlans,
      actions: hostPlans.flatMap(plan => plan.actions.map(action => `${plan.hostname}: ${action}`)) };
  }
  async function getGroup(input) {
    const group = members(input);
    if (group.length === 1) return getVisibility(input);
    const hosts = [];
    for (const project of group) hosts.push(await getVisibility(project));
    return { ...hosts[0], effective: hosts.every(host => host.effective === hosts[0].effective) ? hosts[0].effective : 'mixed',
      verified: hosts.every(host => host.verified && host.effective === hosts[0].effective), hosts, hostnames: hosts.map(host => host.hostname) };
  }
  return { planVisibility: planGroup, applyVisibility, getVisibility: getGroup, getProject, getPrivate, listProjects };
}

export function createCloudflareVisibilityProviderFromEnv(options = {}) {
  if (!options.env?.CONTROL_CENTER_CLOUDFLARE_VISIBILITY_CONFIG_FILE
    && !process.env.CONTROL_CENTER_CLOUDFLARE_VISIBILITY_CONFIG_FILE) return null;
  return createCloudflareVisibilityProvider(options);
}
