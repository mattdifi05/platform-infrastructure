import { RuntimeUpdatesError, validRuntimeUpdatesId } from './client.mjs';

async function boundedJson(req) {
  if (Number(req.headers?.['content-length']) > 64 * 1024) throw new RuntimeUpdatesError(413, 'request_too_large');
  let size = 0; const chunks = [];
  for await (const chunk of req) { size += Buffer.byteLength(chunk); if (size > 64 * 1024) throw new RuntimeUpdatesError(413, 'request_too_large'); chunks.push(Buffer.from(chunk)); }
  try { return size ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}; }
  catch { throw new RuntimeUpdatesError(400, 'invalid_request'); }
}
function payload(value, required) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== required.length || Object.keys(value).some(key => !required.includes(key))) throw new RuntimeUpdatesError(400, 'invalid_request');
  return value;
}
const defaultJson = (res, value, status = 200) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(value)); };

// Server authorization and CSRF validation must run before this dispatcher.
export async function handleRuntimeUpdatesApi(req, res, url, { readJson = boundedJson, json = defaultJson, client } = {}) {
  const pathname = url.pathname.replace(/^\/control\/v1\//, '/control/');
  if (pathname !== '/control/runtime-updates' && !pathname.startsWith('/control/runtime-updates/')) return false;
  const method = String(req.method || 'GET').toUpperCase();
  try {
    const segments = pathname.split('/').slice(3);
    if (!client) throw new RuntimeUpdatesError();
    res.setHeader('cache-control', 'no-store');
    let value, status = 200;
    if (method === 'GET' && segments.length === 0) value = await client.catalog();
    else if (method === 'GET' && segments.length === 1 && segments[0] === 'system') value = await client.hostCatalog();
    else if (method === 'POST' && segments[0] === 'system' && (segments.length === 2 || segments.length === 3 && segments[1] === 'reboot')) {
      const action = segments.at(-1), reboot = segments.length === 3;
      if (!['check', 'plan', 'apply'].includes(action) || reboot && action === 'check') throw new RuntimeUpdatesError(404, 'not_found');
      const body = payload(await readJson(req), action === 'check' ? [] : action === 'plan' ? ['revision'] : ['revision', 'planId', 'confirmation', 'idempotencyKey']);
      const operation = reboot ? action === 'plan' ? 'hostRebootPlan' : 'hostRebootApply' : action === 'check' ? 'hostCheck' : action === 'plan' ? 'hostPlan' : 'hostApply';
      value = await client[operation](body); status = action === 'plan' ? 200 : 202;
    }
    else if (method === 'POST' && segments.length === 1 && segments[0] === 'check') {
      payload(await readJson(req), []); value = await client.check(); status = 202;
    } else if (method === 'GET' && segments.length === 2 && segments[0] === 'operations') {
      if (!validRuntimeUpdatesId(segments[1])) throw new RuntimeUpdatesError(400, 'invalid_request');
      value = await client.operation(segments[1]);
    } else if (method === 'POST' && segments.length === 2 && ['plan', 'apply'].includes(segments[1])) {
      const id = segments[0]; if (!validRuntimeUpdatesId(id)) throw new RuntimeUpdatesError(400, 'invalid_request');
      const body = payload(await readJson(req), segments[1] === 'plan' ? ['revision'] : ['revision', 'planId', 'confirmation', 'idempotencyKey']);
      value = await client[segments[1]](id, body); status = segments[1] === 'apply' ? 202 : 200;
    } else throw new RuntimeUpdatesError(404, 'not_found');
    json(res, value, status);
  } catch (error) {
    const safe = error instanceof RuntimeUpdatesError ? error : new RuntimeUpdatesError();
    json(res, { error: { code: safe.code, message: safe.message, status: safe.status } }, safe.status);
  }
  return true;
}
