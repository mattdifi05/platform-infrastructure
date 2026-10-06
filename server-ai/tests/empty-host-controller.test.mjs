import test from 'node:test';
import assert from 'node:assert/strict';
import { attestContainer, validateRegistry, createControllerServer } from '../scripts/server-ai-controller.mjs';
import { buildRegistry } from '../scripts/enroll-empty-host.mjs';
import http from 'node:http';

// Synthetic fixtures only: enrollment never accepts these as live host evidence.
const machineId = 'a'.repeat(64);
const policy = { searxngConfigDir: '/etc/platform-infrastructure/server-ai/searxng', searxngSettingsFile: '/etc/platform-infrastructure/server-ai/settings.yml', observerTokenFile: '/etc/platform-infrastructure/server-ai/observer-token' };
function fixture(service) {
  const search = service === 'searxng';
  const name = search ? 'gf-searxng' : 'gf-server-ai-observer';
  const mounts = search ? [['/etc/searxng', policy.searxngConfigDir], ['/run/secrets/searxng-settings.yml', policy.searxngSettingsFile]] : [['/run/platform-docker-observer', '/run/platform-docker-observer'], ['/run/secrets/server_ai_observer_token', policy.observerTokenFile]];
  return { Id: (search ? 'b' : 'c').repeat(64), Name: '/' + name, Image: 'sha256:' + 'd'.repeat(64),
    Config: { User: search ? '977:977' : '1000:1000', Labels: { 'com.docker.compose.project': 'platform_server_ai', 'com.docker.compose.service': service, 'com.docker.compose.config-hash': 'e'.repeat(64), 'io.platform.server-ai.machine-id': machineId } },
    HostConfig: { ReadonlyRootfs: true, Privileged: false, RestartPolicy: { Name: 'unless-stopped' }, Memory: (search ? 768 : 128) * 1024 ** 2, MemorySwap: (search ? 768 : 128) * 1024 ** 2, MemoryReservation: 0, NanoCpus: search ? 1e9 : 5e8, PidsLimit: search ? 128 : 64, CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges:true'], Tmpfs: search ? { '/tmp': 'size=64m,mode=1777', '/var/cache/searxng': 'size=64m,uid=977,gid=977,mode=0700' } : { '/tmp': 'size=16m,uid=1000,gid=1000,mode=0700' }, GroupAdd: search ? [] : ['999'] },
    NetworkSettings: { Networks: Object.fromEntries((search ? ['platform_server_ai_egress', 'platform_server_ai_search'] : ['platform_server_ai_observer']).map(n => [n, {}])), Ports: { '8080/tcp': null } },
    Mounts: mounts.map(([Destination, Source]) => ({ Destination, Source, Type: 'bind', RW: false })), State: { Running: true, Health: { Status: 'healthy' } } };
}
function enrollment() { const containers = ['searxng', 'server-ai-observer'].map(fixture); return { containers, registry: buildRegistry({ machineId, policy, containers }) }; }
test('empty-host enrollment binds real supplied identities and exactly two services', () => {
  const { registry, containers } = enrollment();
  assert.equal(registry.version, 2); assert.equal(registry.services.length, 2);
  assert.equal(registry.services[0].imageId, containers[0].Image);
  assert.equal(validateRegistry(registry), registry);
  assert.equal(attestContainer(containers[0], registry.services[0], machineId).compatible, true);
});
test('enrollment rejects changed host, writable or unexpected source mounts and extra privileges', () => {
  for (const mutate of [c => c.Config.Labels['io.platform.server-ai.machine-id'] = 'f'.repeat(64), c => c.Mounts[0].RW = true, c => c.Mounts[0].Source = '/tmp/unreviewed', c => c.HostConfig.Privileged = true, c => c.HostConfig.Memory = 1, c => c.NetworkSettings.Ports['8080/tcp'] = [{ HostPort: '8080' }]]) {
    const containers = ['searxng', 'server-ai-observer'].map(fixture); mutate(containers[0]);
    assert.throws(() => buildRegistry({ machineId, policy, containers }), /Enrollment rejected/);
  }
});
test('v2 rejects absent observer, project-reader declarations, duplicate services and path traversal', () => {
  for (const mutate of [r => r.services.pop(), r => r.services.push({ ...r.services[0], name: 'gf-server-ai-project-source-reader', service: 'server-ai-project-source-reader' }), r => r.services[1] = r.services[0], r => r.services[0].mountSources['/etc/searxng'] = '/etc/../tmp']) {
    const { registry } = enrollment(); mutate(registry); assert.throws(() => validateRegistry(registry));
  }
});
test('legacy v1 four-service contract and policy remain accepted', () => {
  const base = { imageId: 'sha256:' + 'd'.repeat(64), configHash: 'e'.repeat(64) };
  const registry = { version: 1, machineId, services: ['searxng', 'server-ai-observer', 'server-ai-project-source-reader', 'server-ai-project-query-reader'].map(service => ({ ...base, service, name: 'gf-' + service, ...(service === 'server-ai-project-source-reader' ? { platformSourcePath: '/var/lib/platform-infrastructure/server-ai-home/repo' } : {}) })) };
  assert.equal(validateRegistry(registry), registry);
  const search = fixture('searxng'); search.Mounts[1].Source = '/home/platform_infrastructure/server-ai-provision-20260906/candidates/os-security-20260927/settings.yml';
  assert.equal(attestContainer(search, registry.services[0], machineId).compatible, true);
  const observer = fixture('server-ai-observer'); observer.HostConfig.Tmpfs = {};
  assert.equal(attestContainer(observer, registry.services[1], machineId).compatible, true);
  assert.throws(() => validateRegistry({ ...registry, services: registry.services.slice(0, 2) }));
});
test('status inspects only enrolled VPS containers without requiring reader images', async () => {
  const { registry, containers } = enrollment(); const inspected = [];
  const controller = createControllerServer({ registry, hostMachineId: machineId, docker: { async inspectContainer(name) { inspected.push(name); return containers.find(c => c.Name === '/' + name); } } });
  await new Promise(resolve => controller.server.listen(0, '127.0.0.1', resolve));
  try {
    const body = await new Promise((resolve, reject) => http.get({ host: '127.0.0.1', port: controller.server.address().port, path: '/status' }, res => { let data = ''; res.on('data', p => data += p); res.on('end', () => resolve(JSON.parse(data))); }).on('error', reject));
    assert.deepEqual(inspected, ['gf-searxng', 'gf-server-ai-observer']);
    assert.equal(body.compatible, true); assert.equal(body.coreHealthy, true); assert.equal(body.projectReadersHealthy, false);
  } finally { await controller.stop(); }
});

test('lifecycle enable does not mutate the strict enrolled registry', async () => {
  const { registry, containers } = enrollment(); const before = JSON.stringify(registry);
  const controller = createControllerServer({ registry, hostMachineId: machineId, docker: { async inspectContainer(name) { return containers.find(c => c.Name === '/' + name); } } });
  await new Promise(resolve => controller.server.listen(0, '127.0.0.1', resolve));
  try {
    const body = await new Promise((resolve, reject) => {
      const request = http.request({ host: '127.0.0.1', port: controller.server.address().port, path: '/enable', method: 'POST', headers: { 'content-type': 'application/json' } }, res => { let data = ''; res.on('data', p => data += p); res.on('end', () => resolve({ status: res.statusCode, data: JSON.parse(data) })); });
      request.on('error', reject); request.end(JSON.stringify({ machineId }));
    });
    assert.equal(body.status, 200); assert.equal(body.data.coreHealthy, true);
    assert.equal(JSON.stringify(registry), before); assert.equal(validateRegistry(registry), registry);
  } finally { await controller.stop(); }
});
