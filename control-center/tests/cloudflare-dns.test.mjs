import test from 'node:test';
import assert from 'node:assert/strict';
import { executeCloudflareDnsChange, listCloudflareDns, parseCloudflareDnsZones, readCloudflareDnsStatus } from '../providers/cloudflare-dns.mjs';
const zones = ['matthewdifilippo.com', 'scriptastudents.com', 'stexor.com'].map((name, i) => ({ name, id: String(i + 1).repeat(32) }));

test('DNS integration is absent unless explicitly mounted; exact three-zone scope only', async () => {
  assert.equal(await readCloudflareDnsStatus({}), null);
  assert.deepEqual(parseCloudflareDnsZones(JSON.stringify({ zones })), zones);
  assert.throws(() => parseCloudflareDnsZones(JSON.stringify({ zones: [...zones.slice(0, 2), { name: 'fireport.example', id: '4'.repeat(32) }] })));
  assert.throws(() => parseCloudflareDnsZones(JSON.stringify({ zones: zones.map(z => ({ ...z, id: '../accounts' })) })));
  assert.throws(() => parseCloudflareDnsZones(JSON.stringify({ zones: zones.map(z => ({ ...z, id: zones[0].id })) })));
});

test('only bounded DNS GETs occur; status omits credentials, content and provider comments', async () => {
  const calls = [];
  const status = await listCloudflareDns(zones, 'synthetic-secret', async (url, options) => {
    calls.push({ url, options });
    const zone = zones.find(z => url.includes(z.id));
    return { ok: true, json: async () => ({ success: true, result: [{ id: 'a'.repeat(32), name: zone.name, type: 'TXT', content: 'private-value', comment: 'private-comment', ttl: 1 }], result_info: { total_pages: 1 } }) };
  });
  assert.equal(status.status, 'verified-dns-read');
  assert.equal(calls.length, 3);
  for (const { url, options } of calls) {
    assert.match(url, /^https:\/\/api\.cloudflare\.com\/client\/v4\/zones\/[a-f0-9]{32}\/dns_records\?/);
    assert.equal(options.method, 'GET'); assert.equal(options.redirect, 'error');
  }
  assert.doesNotMatch(JSON.stringify(status), /synthetic-secret|private-value|private-comment/);
  assert.ok(status.capabilities.includes('dns-records:list'));
  assert.equal(status.writePermissionVerified, false);
  assert.equal(status.mutationsEnabled, true);
});

test('upstream secrets, redirects/errors, excessive pages and wrong-zone records fail closed', async () => {
  await assert.rejects(listCloudflareDns(zones, 'synthetic-secret', async () => { throw Error('synthetic-secret'); }), { message: 'Cloudflare DNS request unavailable' });
  for (const body of [
    { success: false, errors: [{ message: 'synthetic-secret' }] },
    { success: true, result: [], result_info: { total_pages: 21 } },
    { success: true, result: [{ id: 'a'.repeat(32), name: 'outside.example' }] },
  ]) await assert.rejects(listCloudflareDns(zones, 'synthetic-secret', async () => ({ ok: true, json: async () => body })), error => !error.message.includes('synthetic-secret'));
  assert.equal((await readCloudflareDnsStatus({ CLOUDFLARE_DNS_API_TOKEN_FILE: '/nonexistent' })).status, 'unavailable');
});

function provider(initial = []) {
  let records = structuredClone(initial);
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, method: options.method });
    const id = new URL(url).pathname.split('/')[6];
    let result;
    if (options.method === 'GET') result = id ? records.find(r => r.id === id) : records;
    if (options.method === 'POST') { result = { ...JSON.parse(options.body), id: 'a'.repeat(32) }; records.push(result); }
    if (options.method === 'PATCH') { result = { ...records.find(r => r.id === id), ...JSON.parse(options.body) }; records = records.map(r => r.id === id ? result : r); }
    if (options.method === 'DELETE') { records = records.filter(r => r.id !== id); result = { id }; }
    return { ok: true, json: async () => ({ success: true, result, result_info: { total_pages: 1 } }) };
  };
  return { calls, fetchImpl };
}
const input = { zoneId: zones[0].id, action: 'create', record: { type: 'TXT', name: zones[0].name, content: 'public-dns-value', proxied: false, ttl: 300 } };
const options = remote => ({ zones, token: 'synthetic-secret', fetchImpl: remote.fetchImpl });

test('create is plan-only until exact confirmation, then native write/readback succeeds', async () => {
  const remote = provider();
  const plan = await executeCloudflareDnsChange(input, options(remote));
  assert.equal(plan.dryRun, true);
  assert.ok(remote.calls.every(c => c.method === 'GET'));
  await assert.rejects(executeCloudflareDnsChange({ ...input, apply: true }, options(remote)), /confirmation/);
  const result = await executeCloudflareDnsChange({ ...input, apply: true, expectedRevision: plan.revision, confirm: plan.confirmationRequired }, options(remote));
  assert.equal(result.verified, true);
  assert.equal(remote.calls.filter(c => c.method === 'POST').length, 1);
});

test('update/delete expose original to owner review and reject stale record before any write', async () => {
  const before = { ...input.record, id: 'b'.repeat(32), comment: 'retain-metadata', tags: ['owner:platform'] };
  for (const action of ['update', 'delete']) {
    const request = { ...input, action, recordId: before.id, ...(action === 'update' ? { record: { ...input.record, content: 'new-public-value' } } : {}) };
    const remote = provider([before]);
    const plan = await executeCloudflareDnsChange(request, options(remote));
    assert.deepEqual(plan.before, before);
    const changed = provider([{ ...before, content: 'concurrent-change' }]);
    await assert.rejects(executeCloudflareDnsChange({ ...request, apply: true, expectedRevision: plan.revision, confirm: plan.confirmationRequired }, options(changed)), /stale/);
    assert.ok(changed.calls.every(c => c.method === 'GET'));
    const result = await executeCloudflareDnsChange({ ...request, apply: true, expectedRevision: plan.revision, confirm: plan.confirmationRequired }, options(remote));
    assert.equal(result.verified, true);
  }
});

test('unscoped IDs, NAS, DNS type/field errors and duplicate SPF cannot mutate', async () => {
  for (const bad of [
    { ...input, zoneId: 'f'.repeat(32) },
    { ...input, action: 'delete', recordId: '../accounts' },
    { ...input, record: { ...input.record, name: 'nas.' + zones[0].name } },
    { ...input, record: { ...input.record, name: 'elsewhere.example' } },
    { ...input, record: { ...input.record, proxied: true } },
    { ...input, record: { ...input.record, type: 'NS' } },
    { ...input, record: { ...input.record, type: 'MX' } },
  ]) {
    const remote = provider();
    await assert.rejects(executeCloudflareDnsChange(bad, options(remote)));
    assert.ok(remote.calls.every(c => c.method === 'GET'));
  }
  const remote = provider([{ ...input.record, id: 'a'.repeat(32), content: 'v=spf1 -all' }]);
  await assert.rejects(executeCloudflareDnsChange({ ...input, record: { ...input.record, content: 'v=spf1 include:example.com -all' } }, options(remote)), /conflict/);
});
