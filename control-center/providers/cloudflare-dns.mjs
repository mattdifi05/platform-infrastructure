import fs from 'node:fs';

const DOMAINS = ['matthewdifilippo.com', 'scriptastudents.com', 'stexor.com'];
const ID = /^[a-f0-9]{32}$/;

function protectedText(file, { secret = false } = {}) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const info = fs.fstatSync(fd);
    const validOwner = info.uid === 0 || (secret && info.uid === process.getuid());
    if (!info.isFile() || !validOwner || (info.mode & (secret ? 0o077 : 0o022)) || info.size > 4096) throw Error();
    return fs.readFileSync(fd, 'utf8').trim();
  } catch {
    throw Error('Cloudflare DNS protected configuration unavailable');
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

export function parseCloudflareDnsZones(text) {
  const value = JSON.parse(text);
  if (!Array.isArray(value.zones) || value.zones.length !== DOMAINS.length) throw Error('Invalid Cloudflare DNS zone scope');
  const zones = value.zones.map(({ name, id }) => ({ name, id }));
  if (JSON.stringify(zones.map(z => z.name).sort()) !== JSON.stringify(DOMAINS)
    || zones.some(z => !ID.test(z.id)) || new Set(zones.map(z => z.id)).size !== zones.length) throw Error('Invalid Cloudflare DNS zone scope');
  return zones;
}

// Only this fixed DNS-list endpoint is reachable; no account, Access, tunnel or write API.
export async function listCloudflareDns(zones, token, fetchImpl = fetch) {
  zones = parseCloudflareDnsZones(JSON.stringify({ zones }));
  const result = [];
  for (const zone of zones) {
    const records = [];
    for (let page = 1; page <= 20; page += 1) {
      let response, body;
      try {
        response = await fetchImpl(`https://api.cloudflare.com/client/v4/zones/${zone.id}/dns_records?per_page=100&page=${page}`, {
          method: 'GET', redirect: 'error', signal: AbortSignal.timeout(10000),
          headers: { Authorization: `Bearer ${token}` },
        });
        body = await response.json();
      } catch { throw Error('Cloudflare DNS request unavailable'); }
      if (!response.ok || body.success !== true || !Array.isArray(body.result)) throw Error('Cloudflare DNS verification failed');
      for (const record of body.result) {
        if (!ID.test(record.id) || typeof record.name !== 'string' || !(record.name === zone.name || record.name.endsWith(`.${zone.name}`))) throw Error('Cloudflare DNS record outside enrolled zone');
        // Record values and provider comments are intentionally omitted from status responses.
        records.push({ id: record.id, name: record.name, type: String(record.type), proxied: record.proxied === true, ttl: Number(record.ttl) });
      }
      const pages = Number(body.result_info?.total_pages ?? 1);
      if (!Number.isSafeInteger(pages) || pages < 1 || pages > 20) throw Error('Cloudflare DNS pagination exceeds bounded inventory');
      if (page >= pages) break;
    }
    result.push({ id: zone.id, name: zone.name, records, recordCount: records.length });
  }
  return { configured: true, status: 'verified-dns-read', verifiedAt: new Date().toISOString(), capabilities: ['dns-records:list', 'dns-records:plan', 'dns-records:create', 'dns-records:update', 'dns-records:delete'], writePermissionVerified: false, mutationsEnabled: true, zones: result };
}

export async function readCloudflareDnsStatus(env = process.env) {
  if (!env.CONTROL_CENTER_CLOUDFLARE_DNS_CONFIG_FILE && !env.CLOUDFLARE_DNS_API_TOKEN_FILE) return null;
  try {
    const zones = parseCloudflareDnsZones(protectedText(env.CONTROL_CENTER_CLOUDFLARE_DNS_CONFIG_FILE));
    const token = protectedText(env.CLOUDFLARE_DNS_API_TOKEN_FILE, { secret: true });
    if (!/^[A-Za-z0-9_-]{20,256}$/.test(token)) throw Error();
    return await listCloudflareDns(zones, token);
  } catch {
    return { configured: true, status: 'unavailable', capabilities: [], mutationsEnabled: false, zones: [], error: 'Cloudflare DNS configuration or remote verification unavailable' };
  }
}

// Mutations require a reviewed current-record digest and explicit confirmation.
// PATCH preserves fields omitted from the deliberately small editable field set.
export async function cloudflareDnsChange(payload, { env = process.env, fetchImpl = fetch } = {}) {
  const zones = parseCloudflareDnsZones(protectedText(env.CONTROL_CENTER_CLOUDFLARE_DNS_CONFIG_FILE));
  const token = protectedText(env.CLOUDFLARE_DNS_API_TOKEN_FILE, { secret: true });
  if (!/^[A-Za-z0-9_-]{20,256}$/.test(token)) throw Error('Cloudflare DNS protected configuration unavailable');
  return executeCloudflareDnsChange(payload, { zones, token, fetchImpl });
}

export async function executeCloudflareDnsChange(payload, { zones, token, fetchImpl = fetch }) {
  const { createHash } = await import('node:crypto');
  const { isIP } = await import('node:net');
  const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
  zones = parseCloudflareDnsZones(JSON.stringify({ zones }));
  const zone = zones.find(z => z.id === payload.zoneId);
  if (!zone || !['create', 'update', 'delete'].includes(payload.action)) throw Error('Invalid DNS operation scope');
  const base = `https://api.cloudflare.com/client/v4/zones/${zone.id}/dns_records`;
  const request = async (suffix, method = 'GET', body) => {
    let response, value;
    try {
      response = await fetchImpl(base + suffix, { method, redirect: 'error', signal: AbortSignal.timeout(10000), headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
      value = await response.json();
    } catch { throw Error('Cloudflare DNS request unavailable; verify current DNS before retrying'); }
    if (!response.ok || value.success !== true) throw Error('Cloudflare DNS operation failed; verify current DNS before retrying');
    return value;
  };
  const inZone = name => typeof name === 'string' && name.length <= 253 && /^[a-z0-9_.*-]+(?:\.[a-z0-9_-]+)*$/.test(name) && (name === zone.name || name.endsWith(`.${zone.name}`));
  const snapshot = record => Object.fromEntries(['id', 'type', 'name', 'content', 'ttl', 'proxied', 'priority', 'comment', 'tags', 'settings', 'modified_on'].filter(k => record[k] !== undefined).map(k => [k, record[k]]));
  let before = null, desired = null;
  if (payload.action !== 'create') {
    if (!ID.test(payload.recordId)) throw Error('Invalid DNS record identifier');
    before = (await request(`/${payload.recordId}`)).result;
    if (!before || before.id !== payload.recordId || !inZone(before.name)) throw Error('DNS record outside enrolled zone');
    before = snapshot(before);
  }
  if (payload.action !== 'delete') {
    const r = payload.record;
    if (!r || typeof r !== 'object' || Array.isArray(r) || Object.keys(r).some(k => !['type', 'name', 'content', 'ttl', 'proxied', 'priority'].includes(k))) throw Error('Invalid DNS fields');
    if (!['A', 'AAAA', 'CNAME', 'TXT', 'MX'].includes(r.type) || !inZone(r.name) || typeof r.content !== 'string' || !r.content.length || r.content.length > 4096 || /[\r\n\0]/.test(r.content)) throw Error('Invalid DNS record');
    if (!Number.isInteger(r.ttl) || !(r.ttl === 1 || r.ttl >= 60 && r.ttl <= 86400) || typeof r.proxied !== 'boolean') throw Error('Explicit DNS TTL and proxy flag required');
    if (r.proxied && (!['A', 'AAAA', 'CNAME'].includes(r.type) || /(^|\.)(autodiscover|_domainkey)(\.|$)/.test(r.name))) throw Error('Mail and TXT records must be DNS-only');
    if (r.type === 'A' && isIP(r.content) !== 4 || r.type === 'AAAA' && isIP(r.content) !== 6) throw Error('Invalid DNS IP address');
    if (['CNAME', 'MX'].includes(r.type) && !/^(?=.{1,253}\.?$)[a-z0-9_-]+(?:\.[a-z0-9_-]+)+\.?$/i.test(r.content)) throw Error('Invalid DNS target');
    if (r.type === 'MX' && (!Number.isInteger(r.priority) || r.priority < 0 || r.priority > 65535)) throw Error('MX priority required');
    if (r.type !== 'MX' && r.priority !== undefined) throw Error('Unexpected DNS priority');
    if (before && before.type !== r.type) throw Error('DNS record type changes require a separate reviewed replacement');
    desired = { ...r };
    const found = await request(`?name=${encodeURIComponent(r.name)}&per_page=100`);
    if (!Array.isArray(found.result) || Number(found.result_info?.total_pages ?? 1) !== 1) throw Error('DNS conflict inventory incomplete');
    const others = found.result.filter(x => x.id !== payload.recordId);
    if (others.some(x => x.type === 'NS' || x.type === 'CNAME' || r.type === 'CNAME' || (x.type === r.type && x.content === r.content) || (r.type === 'TXT' && /^v=spf1\s/i.test(r.content) && x.type === 'TXT' && /^v=spf1\s/i.test(x.content)))) throw Error('DNS record conflict; review existing records');
  }
  const name = desired?.name || before.name;
  if (/(^|\.)nas(?:[.-]|$)/i.test(name) || before && /(^|\.)nas(?:[.-]|$)/i.test(before.name)) throw Error('NAS DNS records excluded');
  if (before && !['A', 'AAAA', 'CNAME', 'TXT', 'MX'].includes(before.type)) throw Error('DNS record type outside editable scope');
  const revision = digest({ action: payload.action, zoneId: zone.id, before, desired });
  const confirmation = `${payload.action.toUpperCase()}-DNS:${name}:${revision}`;
  const plan = { action: payload.action, zone: zone.name, zoneId: zone.id, recordId: before?.id || null, before, desired, revision, confirmationRequired: confirmation, dryRun: true, providerTouched: false };
  if (payload.apply !== true) return plan;
  if (payload.expectedRevision !== revision || payload.confirm !== confirmation) throw Error('DNS review is stale or explicit confirmation missing');
  const response = await request(before ? `/${before.id}` : '', payload.action === 'create' ? 'POST' : payload.action === 'update' ? 'PATCH' : 'DELETE', desired || undefined);
  const id = before?.id || response.result?.id;
  if (!ID.test(id)) throw Error('DNS mutation result unavailable; verify current DNS before retrying');
  const check = await request(`?name=${encodeURIComponent(name)}&per_page=100`);
  if (!Array.isArray(check.result) || Number(check.result_info?.total_pages ?? 1) !== 1) throw Error('DNS mutation verification incomplete; do not retry blindly');
  const actual = check.result.find(r => r.id === id);
  if (payload.action === 'delete' ? Boolean(actual) : !actual || Object.entries(desired).some(([k, v]) => actual[k] !== v)) throw Error('DNS mutation verification differs; review remote state');
  return { ...plan, dryRun: false, providerTouched: true, verified: true, recordId: id };
}
