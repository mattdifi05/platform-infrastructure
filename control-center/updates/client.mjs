import http from 'node:http';
import { openSync, closeSync, fstatSync, readFileSync, lstatSync, constants } from 'node:fs';
import { createHmac, randomBytes } from 'node:crypto';
import path from 'node:path';

const actions = new Set(['catalog', 'check', 'plan', 'apply', 'operation']);
const fields = {
  catalog: [], check: [], plan: ['componentId', 'revision'],
  apply: ['componentId', 'revision', 'planId', 'confirmation', 'idempotencyKey'], operation: ['operationId'],
};
const token = value => typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(value);
export const validRuntimeUpdatesId = value => typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$/.test(value);
const messages = {
  400: 'Richiesta aggiornamento non valida.', 401: 'Autenticazione del servizio aggiornamenti non disponibile.',
  403: 'Operazione aggiornamento non consentita.', 404: 'Componente o operazione non disponibile.',
  409: 'Lo stato è cambiato. Aggiorna il catalogo e verifica un nuovo piano.',
  410: 'Il piano è scaduto. Verifica un nuovo piano.', 412: 'La revisione è cambiata. Verifica un nuovo piano.',
  413: 'Richiesta aggiornamento troppo grande.', 422: 'Piano o richiesta aggiornamento non applicabile.',
  429: 'Servizio occupato. Riprova tra poco.', 503: 'Servizio aggiornamenti non disponibile.',
  504: 'Il servizio aggiornamenti non ha risposto in tempo.',
};
const codes = new Set(['invalid_request', 'invalid_component', 'not_found', 'stale_revision', 'stale_plan', 'plan_expired', 'revision_changed', 'confirmation_required', 'idempotency_conflict', 'operation_conflict', 'updates_unavailable', 'updates_timeout', 'invalid_response', 'response_too_large', 'request_too_large', 'forbidden', 'unsupported']);
export class RuntimeUpdatesError extends Error {
  constructor(status = 503, code = 'updates_unavailable') {
    super(messages[status] || 'Operazione aggiornamento non riuscita.');
    this.name = 'RuntimeUpdatesError'; this.status = status; this.code = codes.has(code) ? code : 'updates_unavailable';
  }
}
const invalid = () => { throw new RuntimeUpdatesError(400, 'invalid_request'); };
export function validateRuntimeUpdatesRequest(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || !actions.has(body.action)) invalid();
  const required = fields[body.action];
  if (Object.keys(body).length !== required.length + 1 || Object.keys(body).some(key => key !== 'action' && !required.includes(key))) invalid();
  for (const key of required) {
    if (key === 'confirmation' ? body[key] !== 'UPDATE' : key === 'componentId' || key === 'operationId' || key === 'planId' ? !validRuntimeUpdatesId(body[key]) : !token(body[key])) invalid();
  }
  return Object.freeze({ ...body });
}
export function unavailableRuntimeUpdatesCatalog() {
  return { schema: 'runtime-updates/v1', revision: null, checkedAt: null, available: false, canCheck: false, canApply: false, components: [], operations: [] };
}

// Return only the documented metadata; native errors, logs and unknown fields
// must never become an accidental secret/file transport through the portal.
const text = (value, max = 256) => typeof value === 'string' && value.length <= max && !/[\u0000-\u001f]/u.test(value) ? value : null;
const timestamp = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) ? value : null;
const digest = value => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value) ? value : null;
const strings = value => Array.isArray(value) && value.length <= 100 && value.every(item => text(item, 512) !== null) ? [...value] : [];
function accepted(value) {
  if (!validRuntimeUpdatesId(value?.operationId) || !['queued', 'running', 'completed', 'failed', 'rolled_back', 'rolled-back', 'rollback_failed', 'interrupted', 'succeeded'].includes(value.status)) throw new RuntimeUpdatesError(503, 'invalid_response');
  return { operationId: value.operationId, status: value.status };
}
function operation(value) {
  if (!validRuntimeUpdatesId(value?.id) || !text(value.status, 64) || !text(value.stage, 80)
      || !Number.isSafeInteger(value.completedSteps) || !Number.isSafeInteger(value.totalSteps)
      || value.completedSteps < 0 || value.totalSteps < value.completedSteps) throw new RuntimeUpdatesError(503, 'invalid_response');
  const result = { id: value.id, status: value.status, stage: value.stage, completedSteps: value.completedSteps, totalSteps: value.totalSteps };
  for (const key of ['componentId', 'targetVersion']) if (text(value[key], 128)) result[key] = value[key];
  for (const key of ['createdAt', 'startedAt', 'finishedAt']) if (timestamp(value[key])) result[key] = value[key];
  result.recoveryRequired = value.recoveryRequired === true;
  if (value.error) result.error = 'Operazione non riuscita. Controlla lo stato e verifica un nuovo piano.';
  return result;
}
function sanitizeResult(body, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new RuntimeUpdatesError(503, 'invalid_response');
  if (body.action === 'check' || body.action === 'apply') return accepted(value);
  if (body.action === 'operation') {
    const result = operation(value);
    if (result.id !== body.operationId) throw new RuntimeUpdatesError(503, 'invalid_response');
    return result;
  }
  if (body.action === 'plan') {
    if (!validRuntimeUpdatesId(value.planId) || !token(value.revision) || value.revision !== body.revision
        || value.componentId !== body.componentId || !timestamp(value.expiresAt) || !text(value.targetVersion, 128)
        || !digest(value.targetDigest) || !Array.isArray(value.affectedServices) || !Array.isArray(value.steps) || !Array.isArray(value.risks)
        || value.confirmationRequired !== 'UPDATE') throw new RuntimeUpdatesError(503, 'invalid_response');
    return { planId: value.planId, revision: value.revision, expiresAt: value.expiresAt, componentId: value.componentId,
      targetVersion: value.targetVersion, targetDigest: value.targetDigest, affectedServices: strings(value.affectedServices),
      steps: strings(value.steps), risks: strings(value.risks), confirmationRequired: 'UPDATE' };
  }
  if (value.schema !== 'runtime-updates/v1' || typeof value.available !== 'boolean' || !Array.isArray(value.components) || !Array.isArray(value.operations)
      || value.components.length > 200 || value.operations.length > 100 || value.available && !token(value.revision)) throw new RuntimeUpdatesError(503, 'invalid_response');
  const seen = new Set();
  const release = value => {
    let sourceUrl = null;
    try { const url = new URL(value?.sourceUrl); if (url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash) sourceUrl = url.href; } catch {}
    return { version: text(value?.version, 128), imageDigest: digest(value?.imageDigest), sourceUrl };
  };
  const components = value.components.map(item => {
    if (!validRuntimeUpdatesId(item?.id) || seen.has(item.id) || !text(item.label) || !text(item.category, 64) || !text(item.status, 64)) throw new RuntimeUpdatesError(503, 'invalid_response');
    seen.add(item.id);
    return { id: item.id, label: item.label, category: item.category,
      current: { version: text(item.current?.version, 128), imageDigest: digest(item.current?.imageDigest), verifiedAt: timestamp(item.current?.verifiedAt) },
      latestStable: release(item.latestStable), candidateRelease: release(item.candidateRelease),
      status: item.status, canUpdate: value.available === true && value.canApply !== false && item.installed === true && item.canUpdate === true,
      blockedReason: text(item.blockedReason, 512) || (value.canApply === false ? 'Una manutenzione interrotta richiede verifica amministrativa.' : null), services: strings(item.services), installed: item.installed === true };
  });
  return { schema: value.schema, revision: token(value.revision) ? value.revision : null, checkedAt: timestamp(value.checkedAt),
    available: value.available, canCheck: value.available && value.canCheck === true, canApply: value.available && value.canApply !== false, components, operations: value.operations.map(operation) };
}

export function createRuntimeUpdatesClient({ env = process.env, timeoutMs = 30_000, maxResponseBytes = 128 * 1024 } = {}) {
  const socketPath = env.CONTROL_CENTER_UPDATES_SOCKET || '/run/platform-updates/updates.sock';
  const keyFile = env.CONTROL_CENTER_UPDATES_KEY_FILE || '/run/secrets/control_center_updates_bridge_token';
  async function call(input) {
    const body = validateRuntimeUpdatesRequest(input);
    try {
      if (!path.isAbsolute(socketPath) || !path.isAbsolute(keyFile) || !lstatSync(socketPath).isSocket()) throw new RuntimeUpdatesError();
      let key; const fd = openSync(keyFile, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const stat = fstatSync(fd);
        if (!stat.isFile() || stat.size < 32 || stat.size > 4096) throw new RuntimeUpdatesError();
        key = readFileSync(fd);
      } finally { closeSync(fd); }
      const raw = Buffer.from(JSON.stringify({ body, timestamp: Date.now(), nonce: randomBytes(16).toString('hex') }));
      const signature = createHmac('sha256', key).update(raw).digest('hex');
      return await new Promise((resolve, reject) => {
        let settled = false, timer;
        const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolve(value); };
        const req = http.request({ socketPath, path: '/v1/updates', method: 'POST', headers: { 'content-type': 'application/json', 'content-length': raw.length, 'x-platform-signature': signature } }, res => {
          const chunks = []; let size = 0;
          res.on('data', chunk => { size += chunk.length; if (size > maxResponseBytes) { finish(new RuntimeUpdatesError(503, 'response_too_large')); req.destroy(); } else chunks.push(chunk); });
          res.on('error', () => finish(new RuntimeUpdatesError()));
          res.on('aborted', () => finish(new RuntimeUpdatesError()));
          res.on('end', () => {
            if (settled) return;
            try {
              const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
              if (![200, 202].includes(res.statusCode) || value.error) {
                const status = Number.isInteger(value.error?.status) && value.error.status >= 400 && value.error.status <= 599 ? value.error.status : res.statusCode >= 400 ? res.statusCode : 503;
                finish(new RuntimeUpdatesError(status, value.error?.code));
              } else finish(null, sanitizeResult(body, value));
            } catch (error) { finish(error instanceof RuntimeUpdatesError ? error : new RuntimeUpdatesError(503, 'invalid_response')); }
          });
        });
        timer = setTimeout(() => { finish(new RuntimeUpdatesError(504, 'updates_timeout')); req.destroy(); }, timeoutMs);
        req.on('error', () => finish(new RuntimeUpdatesError()));
        req.end(raw);
      });
    } catch (error) { throw error instanceof RuntimeUpdatesError ? error : new RuntimeUpdatesError(); }
  }
  return Object.freeze({ call,
    async catalog() { try { return await call({ action: 'catalog' }); } catch { return unavailableRuntimeUpdatesCatalog(); } },
    check: () => call({ action: 'check' }),
    plan: (componentId, payload) => call({ ...payload, action: 'plan', componentId }),
    apply: (componentId, payload) => call({ ...payload, action: 'apply', componentId }),
    operation: operationId => call({ action: 'operation', operationId }),
  });
}
