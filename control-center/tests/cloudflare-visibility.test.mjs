import test from 'node:test';
import assert from 'node:assert/strict';
import { createCloudflareVisibilityProvider, parseCloudflareVisibilityConfig } from '../providers/cloudflare-access.mjs';
import { visibilityHostnames } from '../hosting/visibility.mjs';

const accountId = '1'.repeat(32);
const zoneId = '2'.repeat(32);
const tunnelId = 'aaa1c1a2-9447-4597-b2de-0612b1c8391d';
const project = { id: 'alpha', hostname: 'example.com', baseDomain: 'example.com', ownerEmail: 'owner@example.net', originService: 'http://127.0.0.1:8080', cloneOriginService: 'http://127.0.0.1:18181' };
const zones = [{ name: 'example.com', id: zoneId }];
const config = { accountId, tunnelId, projects: [project] };
const ownerTag = 'control-center:visibility:v1:alpha';
const accessName = 'control-center-visibility-v1-alpha';
const policyName = `${accessName}-owner`;
const appId = 'a'.repeat(32);
const policyId = 'b'.repeat(32);

function memoryState(initial = { schemaVersion: 1, routes: {} }) {
  let value = structuredClone(initial);
  return { load: async () => structuredClone(value), save: async next => { value = structuredClone(next); } };
}

function remoteFixture({ ingress, apps = [], dnsRecords = [] } = {}) {
  let tunnel = structuredClone({ config: { ingress: ingress || [{ service: 'http_status:404' }] }, version: 7 });
  let applications = structuredClone(apps);
  let records = structuredClone(dnsRecords);
  const calls = [];
  const fetchImpl = async (url, options) => {
    const parsed = new URL(url);
    if (parsed.hostname !== 'api.cloudflare.com') {
      assert.equal(options.headers.Authorization, undefined, 'API credentials must never be sent to the application');
      return { status: 302, headers: { get: () => `https://owner.cloudflareaccess.com/cdn-cgi/access/login/${parsed.hostname}` } };
    }
    const pathname = parsed.pathname;
    const method = options.method;
    const body = options.body ? JSON.parse(options.body) : undefined;
    if (pathname.includes('/dns_records') && body) assert.equal('tags' in body, false, 'free-plan DNS writes cannot require paid record tags');
    calls.push({ method, pathname, body });
    let result;
    if (pathname.endsWith('/access/apps') && method === 'GET') result = applications;
    else if (pathname.includes('/access/apps/') && pathname.endsWith('/policies') && method === 'GET') {
      const id = pathname.split('/').at(-2);
      result = applications.find(app => app.id === id)?.policies || [];
    } else if (pathname.endsWith('/access/apps') && method === 'POST') {
      const nextAppId = applications.some(app => app.id === appId) ? (applications.length + 1).toString(16).padStart(32, '0') : appId;
      const app = { ...body, id: nextAppId, policies: body.policies.map(policy => ({ ...policy, id: policyId })) };
      applications.push(app); result = app;
    } else if (pathname.includes('/access/apps/') && method === 'DELETE') {
      const id = pathname.split('/').at(-1);
      applications = applications.filter(app => app.id !== id); result = { id };
    } else if (pathname.endsWith('/configurations') && method === 'GET') result = tunnel;
    else if (pathname.endsWith('/configurations') && method === 'PUT') {
      tunnel = { config: body.config, version: tunnel.version + 1 }; result = tunnel;
    } else if (pathname.endsWith('/dns_records') && method === 'GET') {
      result = records.filter(record => record.name === parsed.searchParams.get('name'));
    } else if (pathname.endsWith('/dns_records') && method === 'POST') {
      const record = { ...body, id: records.some(record => record.id === 'c'.repeat(32)) ? (records.length + 1).toString(16).padStart(32, '0') : 'c'.repeat(32) };
      records.push(record); result = record;
    } else if (pathname.includes('/dns_records/') && method === 'PATCH') {
      const id = pathname.split('/').at(-1);
      const record = { ...records.find(item => item.id === id), ...body };
      records = records.map(item => item.id === id ? record : item); result = record;
    } else if (pathname.includes('/dns_records/') && method === 'DELETE') {
      const id = pathname.split('/').at(-1);
      records = records.filter(record => record.id !== id); result = { id };
    } else throw Error(`Unexpected provider request: ${method} ${pathname}`);
    return { ok: true, json: async () => ({ success: true, result: structuredClone(result), result_info: { total_pages: 1 } }) };
  };
  return { fetchImpl, calls, setIngress: next => { tunnel.config.ingress = structuredClone(next); tunnel.version += 1; }, get applications() { return structuredClone(applications); }, get records() { return structuredClone(records); }, get tunnel() { return structuredClone(tunnel); } };
}

function provider(remote, state = memoryState()) {
  return createCloudflareVisibilityProvider({
    configuration: { config, zones, token: 'synthetic-token-value-0123456789' },
    stateStore: state,
    fetchImpl: remote.fetchImpl,
    now: () => new Date('2026-10-14T12:00:00.000Z'),
  });
}

function confirmed(plan) { return { expectedRevision: plan.revision, confirm: plan.confirmationRequired }; }

test('empty Cloudflare inventories accept zero pages while inconsistent nonempty pagination fails closed', async () => {
  const remote = remoteFixture();
  const emptyPages = { fetchImpl: async (...args) => {
    const response = await remote.fetchImpl(...args);
    const value = await response.json();
    if (Array.isArray(value.result) && value.result.length === 0) value.result_info = { total_pages: 0, total_count: 0 };
    return { ...response, json: async () => value };
  } };
  const plan = await provider(emptyPages).planVisibility({ id: 'alpha' }, 'private');
  assert.equal(plan.currentMode, 'offline');
  assert.ok(remote.calls.every(call => call.method === 'GET'));
  const invalidPages = { fetchImpl: async () => ({ ok: true, json: async () => ({ success: true, result: [{}], result_info: { total_pages: 0, total_count: 1 } }) }) };
  await assert.rejects(provider(invalidPages).planVisibility({ id: 'alpha' }, 'private'), /inventory exceeds/);
});

test('project admission uses a registered zone and derives private host without guessing a public suffix', () => {
  assert.deepEqual(visibilityHostnames({ id: 'alpha', hostname: 'example.com', baseDomain: 'example.com' }, zones), {
    slug: 'alpha', hostname: 'example.com', baseDomain: 'example.com', privateHostname: 'local.example.com', zone: zones[0],
  });
  assert.equal(visibilityHostnames({ id: 'stream', hostname: 'stream.stexor.com', baseDomain: 'stexor.com' }, [{ name: 'stexor.com', id: zoneId }]).privateHostname, 'local-stream.stexor.com');
  assert.throws(() => visibilityHostnames({ id: 'bad', hostname: 'example.co.uk', baseDomain: 'co.uk' }, zones), /verified Cloudflare zones/);
  assert.throws(() => parseCloudflareVisibilityConfig(JSON.stringify({ ...config, projects: [{ ...project, originService: 'http://evil.example:8080' }] }), zones), /admission/);
  assert.throws(() => parseCloudflareVisibilityConfig(JSON.stringify({ ...config, projects: [{ ...project, hostname: 'outside.test', baseDomain: 'outside.test' }] }), zones), /verified Cloudflare zones/);
});

test('private mode creates an exact owner-only Access app before adding its DNS and tunnel route', async () => {
  const remote = remoteFixture({ ingress: [{ hostname: '*.example.com', service: 'http://legacy-router:8080' }, { service: 'http_status:404' }] });
  const visibility = provider(remote);
  const plan = await visibility.planVisibility({ id: 'alpha', hostname: project.hostname }, 'private');
  assert.equal(plan.dryRun, true);
  assert.equal(plan.providerTouched, false);
  assert.ok(remote.calls.every(call => call.method === 'GET'));
  await assert.rejects(visibility.applyVisibility(plan, { ...confirmed(plan), confirm: 'APPLY' }), /confirmation/);
  const applied = await visibility.applyVisibility(plan, confirmed(plan));
  assert.equal(applied.effective, 'private');
  assert.equal(applied.verified, true);
  assert.equal(applied.accessApplicationId, appId);
  assert.equal(applied.accessPolicyId, policyId);
  assert.deepEqual(remote.applications[0].policies[0].include, [{ email: { email: project.ownerEmail } }]);
  assert.deepEqual(remote.applications[0].policies[0].exclude, []);
  assert.equal(remote.applications[0].domain, project.hostname);
  assert.equal(remote.records[0].comment, ownerTag);
  const accessCreate = remote.calls.findIndex(call => call.method === 'POST' && call.pathname.endsWith('/access/apps'));
  const dnsCreate = remote.calls.findIndex(call => call.method === 'POST' && call.pathname.endsWith('/dns_records'));
  const tunnelWrite = remote.calls.findIndex(call => call.method === 'PUT' && call.pathname.endsWith('/configurations'));
  assert.ok(accessCreate >= 0 && accessCreate < dnsCreate && dnsCreate < tunnelWrite);
  assert.equal(remote.tunnel.config.ingress[0].hostname, project.hostname, 'exact host route precedes the wildcard route');
  assert.equal(remote.tunnel.config.ingress.at(-1).service, 'http_status:404');
  assert.doesNotMatch(JSON.stringify(applied), /synthetic-token-value|owner@example.net/);
});

test('API policy readback alone cannot verify private publication before the edge denies anonymous access', async () => {
  const remote = remoteFixture();
  const edgeNotReady = { fetchImpl: (url, options) => new URL(url).hostname === 'api.cloudflare.com'
    ? remote.fetchImpl(url, options) : Promise.resolve({ status: 200, headers: { get: () => null } }) };
  const visibility = provider(edgeNotReady);
  const plan = await visibility.planVisibility({ id: 'alpha' }, 'private');
  await assert.rejects(visibility.applyVisibility(plan, confirmed(plan)), /readback/);
  const status = await visibility.getVisibility({ id: 'alpha' });
  assert.equal(status.effective, 'private');
  assert.equal(status.edgeVerified, false);
  assert.equal(status.verified, false);
  assert.equal(remote.applications.length, 1);
});

test('registered source can adopt only its exact existing tunnel route and CNAME after reviewed confirmation', async () => {
  const existingDns = { id: 'e'.repeat(32), type: 'CNAME', name: project.hostname, content: `${tunnelId}.cfargotunnel.com`, proxied: true, ttl: 1 };
  const remote = remoteFixture({ ingress: [{ hostname: project.hostname, service: project.originService }, { service: 'http_status:404' }], dnsRecords: [existingDns] });
  const visibility = provider(remote);
  const plan = await visibility.planVisibility({ id: project.id, hostname: project.hostname }, 'private');
  assert.equal(plan.currentMode, 'public');
  assert.ok(plan.actions[0].includes('adopt only the exact registered source host route'));
  assert.match(plan.confirmationRequired, /^SET-VISIBILITY:alpha:private:/);
  const applied = await visibility.applyVisibility(plan, confirmed(plan));
  assert.equal(applied.effective, 'private');
  assert.equal(remote.tunnel.config.ingress[0].hostname, project.hostname);
  assert.equal(remote.records[0].id, existingDns.id);
  assert.equal(remote.records[0].comment, ownerTag);
  assert.equal(remote.calls.some(call => call.method === 'POST' && call.pathname.endsWith('/dns_records')), false);
  assert.equal(remote.calls.some(call => call.method === 'PATCH' && call.pathname.endsWith(`/dns_records/${existingDns.id}`)), true);
});

test('apex visibility preserves unrelated mail and verification records at the same hostname', async () => {
  const mail = { id: '1'.repeat(32), type: 'MX', name: project.hostname, content: 'mail.example.net', priority: 0 };
  const verification = { id: '2'.repeat(32), type: 'TXT', name: project.hostname, content: 'synthetic-domain-verification' };
  const route = { id: 'e'.repeat(32), type: 'CNAME', name: project.hostname, content: `${tunnelId}.cfargotunnel.com`, proxied: true, ttl: 1 };
  const remote = remoteFixture({ ingress: [{ hostname: project.hostname, service: project.originService }, { service: 'http_status:404' }], dnsRecords: [mail, verification, route] });
  const visibility = provider(remote);
  const plan = await visibility.planVisibility({ id: project.id }, 'private');
  assert.equal((await visibility.applyVisibility(plan, confirmed(plan))).verified, true);
  const offline = await visibility.planVisibility({ id: project.id }, 'offline');
  await visibility.applyVisibility(offline, confirmed(offline));
  assert.deepEqual(remote.records, [mail, verification]);
});

test('clone admission is deterministic and uses its separately registered loopback origin', async () => {
  const remote = remoteFixture();
  const visibility = provider(remote);
  const clone = { id: 'local-alpha', hostname: 'local.example.com', baseDomain: 'example.com' };
  const plan = await visibility.planVisibility(clone, 'private');
  const applied = await visibility.applyVisibility(plan, confirmed(plan));
  assert.equal(applied.projectId, clone.id);
  assert.equal(applied.hostname, clone.hostname);
  assert.equal(remote.applications[0].domain, clone.hostname);
  assert.equal(remote.records[0].name, clone.hostname);
  assert.equal(remote.tunnel.config.ingress[0].service, project.cloneOriginService);
  assert.equal(remote.tunnel.config.ingress[0].hostname, clone.hostname);
  assert.equal(remote.records[0].comment, 'control-center:visibility:v1:local-alpha');
});

test('offline removes only the recorded project route and ownership-marked DNS while retaining Access protection', async () => {
  const remote = remoteFixture();
  const visibility = provider(remote);
  const privatePlan = await visibility.planVisibility({ id: 'alpha' }, 'private');
  await visibility.applyVisibility(privatePlan, confirmed(privatePlan));
  const beforeApps = remote.applications;
  const offlinePlan = await visibility.planVisibility({ id: 'alpha' }, 'offline');
  const result = await visibility.applyVisibility(offlinePlan, confirmed(offlinePlan));
  assert.equal(result.effective, 'offline');
  assert.equal(result.verified, true);
  assert.deepEqual(remote.applications, beforeApps);
  assert.equal(remote.records.length, 0);
  assert.deepEqual(remote.tunnel.config.ingress, [{ service: 'http_status:404' }]);
  assert.equal(remote.calls.some(call => call.method === 'DELETE' && call.pathname.includes('/access/apps/')), false);
});

test('public mode ungates only its owned Access application after route readback', async () => {
  const unrelated = { id: 'd'.repeat(32), domain: 'unrelated.example.com', name: 'unrelated-owner-app', type: 'self_hosted', policies: [] };
  const remote = remoteFixture({ apps: [unrelated] });
  const visibility = provider(remote);
  const privatePlan = await visibility.planVisibility({ id: 'alpha' }, 'private');
  await visibility.applyVisibility(privatePlan, confirmed(privatePlan));
  const publicPlan = await visibility.planVisibility({ id: 'alpha' }, 'public');
  const before = remote.calls.length;
  const result = await visibility.applyVisibility(publicPlan, confirmed(publicPlan));
  assert.equal(result.effective, 'public');
  assert.equal(result.verified, true);
  assert.deepEqual(remote.applications, [unrelated]);
  const mutations = remote.calls.slice(before).filter(call => call.method !== 'GET');
  assert.equal(mutations.at(-1).method, 'DELETE');
  assert.match(mutations.at(-1).pathname, new RegExp(`/access/apps/${appId}$`));
});

test('stale plan, unowned route and unowned Access app fail without provider writes', async () => {
  const staleRemote = remoteFixture();
  const stale = provider(staleRemote);
  const plan = await stale.planVisibility({ id: 'alpha' }, 'private');
  staleRemote.setIngress([{ hostname: 'other.example.com', service: 'http://other-router:8080' }, { service: 'http_status:404' }]);
  const writesBefore = staleRemote.calls.filter(call => call.method !== 'GET').length;
  await assert.rejects(stale.applyVisibility(plan, confirmed(plan)), /changed|confirmation/);
  assert.equal(staleRemote.calls.filter(call => call.method !== 'GET').length, writesBefore);

  const routeRemote = remoteFixture({ ingress: [{ hostname: project.hostname, service: 'http://127.0.0.1:9999' }, { service: 'http_status:404' }] });
  const routeProvider = provider(routeRemote);
  await assert.rejects(routeProvider.planVisibility({ id: 'alpha' }, 'private'), /admitted project service|not provably managed/);
  assert.ok(routeRemote.calls.every(call => call.method === 'GET'));

  const appRemote = remoteFixture({ apps: [{ id: appId, domain: project.hostname, name: accessName, type: 'self_hosted', policies: [{ id: policyId, name: policyName, decision: 'allow', include: [{ everyone: {} }] }] }] });
  const appProvider = provider(appRemote);
  await assert.rejects(appProvider.planVisibility({ id: 'alpha' }, 'private'), /registered in managed project state/);
  assert.ok(appRemote.calls.every(call => call.method === 'GET'));
});


test('adoptable source status is verified by exact provider readback before adoption', async () => {
  const remote = remoteFixture({ ingress: [{ hostname: project.hostname, service: project.originService }, { service: 'http_status:404' }], dnsRecords: [{ id: 'e'.repeat(32), type: 'CNAME', name: project.hostname, content: `${tunnelId}.cfargotunnel.com`, proxied: true }] });
  const status = await provider(remote).getVisibility({ id: 'alpha' });
  assert.equal(status.verified, true);
  assert.equal(status.adoptable, true);
  assert.equal(status.managed, false);
  assert.equal(status.effective, 'public');
  assert.ok(remote.calls.every(call => call.method === 'GET'));
});

test('offline clone installs exact 404 before wildcard and can resume private', async () => {
  const remote = remoteFixture({ ingress: [{ hostname: '*.example.com', service: 'http://legacy:8080' }, { service: 'http_status:404' }] });
  const visibility = provider(remote);
  const clone = { id: 'local-alpha' };
  const first = await visibility.planVisibility(clone, 'private');
  await visibility.applyVisibility(first, confirmed(first));
  const plan = await visibility.planVisibility(clone, 'offline');
  const result = await visibility.applyVisibility(plan, confirmed(plan));
  assert.equal(result.verified, true);
  assert.equal(result.effective, 'offline');
  assert.deepEqual(remote.tunnel.config.ingress[0], { hostname: 'local.example.com', service: 'http_status:404' });
  assert.equal(remote.records.length, 0);
  assert.equal(remote.applications.length, 1);
  const resume = await visibility.planVisibility(clone, 'private');
  assert.equal((await visibility.applyVisibility(resume, confirmed(resume))).verified, true);
  assert.equal(remote.tunnel.config.ingress[0].service, project.cloneOriginService);
});

test('clone cannot initialize public and foreign origin Access gate cannot be adopted', async () => {
  const remote = remoteFixture();
  await assert.rejects(provider(remote).planVisibility({ id: 'local-alpha' }, 'public'), /first be initialized/);
  assert.ok(remote.calls.every(call => call.method === 'GET'));
  const gated = remoteFixture({ ingress: [{ hostname: project.hostname, service: project.originService, originRequest: { access: { required: true, audTag: ['foreign'] } } }, { service: 'http_status:404' }] });
  await assert.rejects(provider(gated).planVisibility({ id: 'alpha' }, 'public'), /outside managed project ownership/);
  assert.ok(gated.calls.every(call => call.method === 'GET'));
});


test('admission metadata exposes exact source and derived clone without credentials', () => {
  const visibility = provider(remoteFixture());
  assert.deepEqual(visibility.listProjects().map(item => item.id), ['alpha', 'local-alpha']);
  assert.equal(visibility.getProject('alpha').hostname, 'example.com');
  assert.equal(visibility.getProject('local-alpha').hostname, 'local.example.com');
  assert.deepEqual(visibility.getPrivate('alpha'), visibility.getProject('local-alpha'));
  assert.throws(() => visibility.getPrivate('local-alpha'), /Source project/);
  assert.equal(visibility.getProject('local-alpha').originService, project.cloneOriginService);
  assert.doesNotMatch(JSON.stringify(visibility.listProjects()), /owner@example.net|token/);
  assert.throws(() => visibility.getProject('arbitrary'), /host-only/);
  assert.throws(() => parseCloudflareVisibilityConfig(JSON.stringify({ ...config, tunnelId: '-'.repeat(36) }), zones), /configuration/);
});


test('private readback rejects sibling bypass policy and broadened owner inclusion', async () => {
  const exactPolicy = { id: policyId, name: policyName, decision: 'allow', include: [{ email: { email: project.ownerEmail } }], exclude: [], require: [] };
  const state = () => memoryState({ schemaVersion: 1, routes: { [project.hostname]: { projectId: 'alpha', hostname: project.hostname, mode: 'offline', accessAppId: appId, accessPolicyId: policyId } } });
  for (const policies of [
    [exactPolicy, { id: 'f'.repeat(32), decision: 'bypass', include: [{ everyone: {} }] }],
    [{ ...exactPolicy, include: [{ email: { email: project.ownerEmail }, everyone: {} }] }],
    [{ ...exactPolicy, include: [{ email: { email: 'another@example.net' } }] }],
  ]) {
    const remote = remoteFixture({ apps: [{ id: appId, name: accessName, type: 'self_hosted', domain: project.hostname, policies }] });
    await assert.rejects(provider(remote, state()).getVisibility({ id: 'alpha' }), /exact project-owner policy/);
    assert.ok(remote.calls.every(call => call.method === 'GET'));
  }
});


test('protected admission rejects a clone hostname or identifier colliding with another source', () => {
  for (const sibling of [
    { ...project, id: 'beta', hostname: 'local.example.com' },
    { ...project, id: 'local-alpha', hostname: 'beta.example.com' },
  ]) {
    assert.throws(() => parseCloudflareVisibilityConfig(JSON.stringify({ ...config, projects: [project, sibling] }), zones), /admissions conflict/);
  }
});


test('related hostnames gate every host before any DNS or route mutation and aggregate all modes', async () => {
  const remote = remoteFixture();
  const visibility = createCloudflareVisibilityProvider({ configuration: { config: { ...config, projects: [{ ...project, relatedHostnames: ['api.example.com'] }] }, zones, token: 'synthetic-token-value-0123456789' }, stateStore: memoryState(), fetchImpl: remote.fetchImpl });
  const plan = await visibility.planVisibility({ id: 'alpha' }, 'private');
  assert.equal(plan.action, 'project.visibility-group');
  assert.deepEqual(plan.hostnames, ['example.com', 'api.example.com']);
  await assert.rejects(visibility.applyVisibility(plan.hostPlans[0], confirmed(plan.hostPlans[0])), /complete aggregate/);
  await assert.rejects(visibility.applyVisibility(plan.hostPlans[1], confirmed(plan.hostPlans[1])), /only managed through/);
  const applied = await visibility.applyVisibility(plan, confirmed(plan));
  assert.equal(applied.verified, true);
  assert.equal(applied.hosts.length, 2);
  assert.equal(applied.hosts.every(host => host.access === 'owner-only'), true);
  const creates = remote.calls.map((call,index) => ({...call,index})).filter(call => call.method === 'POST' && call.pathname.endsWith('/access/apps'));
  const firstRoutingMutation = remote.calls.findIndex(call => call.method !== 'GET' && !call.pathname.includes('/access/apps'));
  assert.equal(creates.length, 2);
  assert.ok(creates.every(call => call.index < firstRoutingMutation));
  await assert.rejects(visibility.planVisibility({ id: plan.hostPlans[1].projectId }, 'public'), /only managed through/);
  const publicPlan = await visibility.planVisibility({ id: 'alpha' }, 'public');
  assert.equal((await visibility.applyVisibility(publicPlan, confirmed(publicPlan))).verified, true);
  assert.equal(remote.applications.length, 0);
  const offlinePlan = await visibility.planVisibility({ id: 'alpha' }, 'offline');
  const offline = await visibility.applyVisibility(offlinePlan, confirmed(offlinePlan));
  assert.equal(offline.effective, 'offline');
  assert.equal(offline.verified, true);
  assert.equal(remote.records.length, 0);
  const clonePlan = await visibility.planVisibility({ id: 'local-alpha' }, 'private');
  assert.deepEqual(clonePlan.hostnames, ['local.example.com', 'local-api.example.com']);
  const clone = await visibility.applyVisibility(clonePlan, confirmed(clonePlan));
  assert.equal(clone.verified, true);
  assert.equal(clone.hosts.every(host => host.effective === 'private'), true);
});


test('external tunnel drift during Access/DNS provisioning aborts before tunnel PUT', async () => {
  const remote = remoteFixture();
  const fetchImpl = async (url, options) => {
    const result = await remote.fetchImpl(url, options);
    if (options.method === 'POST' && new URL(url).pathname.endsWith('/dns_records')) {
      remote.setIngress([{ hostname: 'sibling.example.com', service: 'http://sibling:8080' }, { service: 'http_status:404' }]);
    }
    return result;
  };
  const visibility = createCloudflareVisibilityProvider({ configuration: { config, zones, token: 'synthetic-token-value-0123456789' }, stateStore: memoryState(), fetchImpl });
  const plan = await visibility.planVisibility({ id: 'alpha' }, 'private');
  await assert.rejects(visibility.applyVisibility(plan, confirmed(plan)), /configuration changed before write/);
  assert.equal(remote.calls.some(call => call.method === 'PUT' && call.pathname.endsWith('/configurations')), false);
  assert.equal(remote.tunnel.config.ingress[0].hostname, 'sibling.example.com');
  assert.equal(remote.applications.length, 1, 'owner protection remains after safe failure');
});
