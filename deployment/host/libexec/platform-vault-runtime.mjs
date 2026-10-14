#!/usr/bin/env node
// Bounded runtime secret delivery. No shell or browser-selected paths/commands.
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { loadStore, withStoreLock, decryptVersion } from '../../../control-center/vault/store.mjs';
import { readValues, prepare, writePrepared, rollbackPrepared, disposePrepared, consumerMatches } from './vault-materialize.mjs';

const exec = promisify(execFile);
const CONFIG = '/etc/platform-infrastructure/vault';
const STATE = '/var/lib/platform-vault';
const SOCKET = '/run/platform-vault/runtime.sock';
const STORE = {
  storePath: '/srv/platform-infrastructure/first-install/projects-portal/state/secret-vault.json',
  lockPath: '/srv/platform-infrastructure/first-install/projects-portal/state/secret-vault.json.lock',
  keyFile: '/srv/platform-infrastructure/first-install/secrets/control_center_vault_keys.txt',
  ownerUid: 1000, ownerGid: 1000,
};
const ID = /^[A-Za-z0-9_-]{1,128}$/;
const terminal = new Set(['verified', 'rolled-back', 'failed', 'requires-reconciliation']);
const allowed = new Set(['action','bindingId','itemId','versionId','expectedVaultRevision','expectedBindingRevision','planId','confirmation','operationId']);
const identifier = value => typeof value === 'string' && ID.test(value);
export function validateRequest(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(k => !allowed.has(k))) throw Error('invalid-request');
  if (!['catalog','adopt','plan','apply','rollback','status'].includes(body.action)) throw Error('invalid-action');
  for (const value of Object.values(body)) if (typeof value !== 'string' || !value || value.length > 256 || /[\x00-\x1f]/.test(value)) throw Error('invalid-field');
  for (const key of ['bindingId','itemId','versionId','planId','operationId']) if (body[key] !== undefined && !identifier(body[key])) throw Error('invalid-identifier');
  if (!['catalog','status'].includes(body.action) && !body.bindingId) throw Error('invalid-binding-request');
  if (body.action === 'adopt' && body.confirmation !== 'ADOPT:' + body.bindingId) throw Error('adoption-confirmation-invalid');
  if (body.action === 'plan' && ['itemId','versionId','expectedVaultRevision','expectedBindingRevision'].some(key => !body[key])) throw Error('invalid-plan-request');
  if (body.action === 'apply' && (!body.planId || body.confirmation !== 'APPLY:' + body.planId)) throw Error('plan-confirmation-invalid');
  if (body.action === 'status' && !body.operationId && !body.bindingId) throw Error('invalid-status-request');
  return body;
}
export function validateEnvelope(raw, signature, token, now = Date.now()) {
  if (!Buffer.isBuffer(raw) || raw.length < 1 || raw.length > 8192 || !Buffer.isBuffer(token) || token.length < 32) throw Error('invalid-envelope');
  const expected = createHmac('sha256', token).update(raw).digest('hex');
  if (typeof signature !== 'string' || !/^[a-f0-9]{64}$/.test(signature) || !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) throw Error('unauthorized');
  let envelope; try { envelope = JSON.parse(raw); } catch { throw Error('invalid-envelope'); }
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)
      || Object.keys(envelope).sort().join(',') !== 'body,nonce,timestamp'
      || typeof envelope.nonce !== 'string' || !/^[a-f0-9]{32}$/.test(envelope.nonce)
      || !Number.isSafeInteger(envelope.timestamp) || Math.abs(now - envelope.timestamp) > 60000) throw Error('expired-request');
  validateRequest(envelope.body);
  return envelope;
}
async function protectedFile(filename, privateOnly = true) {
  const info = await fs.lstat(filename);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.uid !== 0 || info.mode & (privateOnly ? 0o077 : 0o022)) throw Error('unsafe-runtime-metadata');
  return filename;
}
async function json(filename, fallback) {
  try { await protectedFile(filename); return JSON.parse(await fs.readFile(filename, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT' && fallback !== undefined) return fallback; throw error; }
}
async function save(filename, value) {
  const temporary = filename + '.tmp-' + randomBytes(12).toString('hex');
  const handle = await fs.open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(JSON.stringify(value) + '\n'); await handle.sync(); } finally { await handle.close(); }
  await fs.rename(temporary, filename);
  const directory = await fs.open(path.dirname(filename), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await directory.sync(); } finally { await directory.close(); }
}
const canonicalPath = value => typeof value === 'string' && path.isAbsolute(value) && path.normalize(value) === value && !/[\x00-\x1f]/.test(value) && !value.endsWith('/');
const field = value => typeof value === 'string' && /^[A-Za-z_][A-Za-z0-9_-]{0,127}$/.test(value) && !['__proto__','prototype','constructor'].includes(value);
export function validatePolicy(policy) {
  if (policy?.schema !== 'platform.vault-bindings/v1' || !identifier(policy.revision) || !Array.isArray(policy.bindings) || policy.bindings.length > 100) throw Error('invalid-binding-policy');
  const ids = new Set(); const items = new Set(); const destinations = new Map();
  for (const binding of policy.bindings) {
    if (!binding || !identifier(binding.id) || !identifier(binding.itemId) || ids.has(binding.id) || items.has(binding.itemId)
        || !Array.isArray(binding.targets) || !binding.targets.length || binding.targets.length > 16
        || !Array.isArray(binding.consumers) || !binding.consumers.length || binding.consumers.length > 16) throw Error('invalid-binding');
    ids.add(binding.id); items.add(binding.itemId);
    for (const target of binding.targets) {
      if (!target || !canonicalPath(target.path) || !target.path.startsWith('/srv/platform-infrastructure/')
          || /(?:private[-_]?key|master|keyring|authority|admission|apns|signing|control_center_vault_keys|manifest-key|(?:jwt|session)[_-]secret|\.pem$|\.p8$|\.bak$)/i.test(target.path + ':' + (target.key || ''))
          || !['raw-file','env-key','json-key'].includes(target.format) || !['in-place','atomic'].includes(target.writeMode)
          || target.format !== 'raw-file' && !field(target.key)
          || target.ownerUid !== undefined && (!Number.isInteger(target.ownerUid) || target.ownerUid < 0)
          || target.ownerGid !== undefined && (!Number.isInteger(target.ownerGid) || target.ownerGid < 0)
          || target.mode !== undefined && (!Number.isInteger(target.mode) || target.mode < 0 || target.mode > 0o7777 || target.mode & 0o022)) throw Error('protected-secret-target');
      const prior = destinations.get(target.path) || [];
      if (prior.some(other => other.format === 'raw-file' || target.format === 'raw-file' || other.key === target.key || other.format !== target.format)) throw Error('duplicate-secret-target');
      prior.push(target); destinations.set(target.path, prior);
      if (target.ancestorMetadata !== undefined && !Array.isArray(target.ancestorMetadata)) throw Error('invalid-ancestor-policy');
      const ancestors = new Set();
      for (const ancestor of target.ancestorMetadata || []) {
        if (!ancestor || !canonicalPath(ancestor.path) || !(ancestor.path === '/srv/platform-infrastructure' || ancestor.path.startsWith('/srv/platform-infrastructure/'))
            || !target.path.startsWith(ancestor.path + '/') || ancestors.has(ancestor.path)
            || !Number.isInteger(ancestor.uid) || ancestor.uid < 0 || !Number.isInteger(ancestor.gid) || ancestor.gid < 0
            || !Number.isInteger(ancestor.mode) || ancestor.mode < 0 || ancestor.mode > 0o7777 || ancestor.mode & 0o002) throw Error('invalid-ancestor-policy');
        ancestors.add(ancestor.path);
      }
    }
    const consumers = new Set();
    for (const consumer of binding.consumers) {
      const containerEnv = consumer?.format === 'container-env';
      if (!consumer || typeof consumer.containerId !== 'string' || !/^[a-f0-9]{64}$/.test(consumer.containerId)
          || typeof consumer.containerName !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(consumer.containerName)
          || (!containerEnv && (!canonicalPath(consumer.path) || !/^(?:\/run\/secrets\/|\/var\/www\/projects\/)[A-Za-z0-9_./-]+$/.test(consumer.path)))
          || !['raw-file','env-key','json-key','container-env'].includes(consumer.format) || consumer.format !== 'raw-file' && !field(consumer.key)
          || consumers.has(consumer.containerId + ':' + (consumer.path || '') + ':' + (consumer.key || ''))) throw Error('invalid-consumer');
      if (containerEnv && (binding.rotation !== 'coupled-service' || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(consumer.key)
          || !binding.targets.some(target => target.format === 'env-key' && target.key === consumer.key && target.path.endsWith('.env')
            && (consumer.path === undefined || consumer.path === target.path)))) throw Error('invalid-container-environment-policy');
      if (consumer.restart !== undefined && typeof consumer.restart !== 'boolean' || consumer.restart === false && binding.rotation !== 'coupled-service') throw Error('invalid-restart-policy');
      consumers.add(consumer.containerId + ':' + (consumer.path || '') + ':' + (consumer.key || ''));
      const health = consumer.health;
      if (!health || !['docker-health','http'].includes(health.kind)) throw Error('invalid-health-policy');
      if (health.kind === 'http' && (!/^[A-Za-z0-9.-]+$/.test(health.host || '') || !/^\/[A-Za-z0-9/_.-]*$/.test(health.path || '/')
          || health.port !== 80 || !Number.isInteger(health.expectedStatus) || health.expectedStatus < 100 || health.expectedStatus > 599)) throw Error('invalid-health-policy');
    }
    if (!['provider-update','coupled-service','configuration'].includes(binding.rotation)) throw Error('invalid-rotation-policy');
    if (binding.provider && !['openai','groq'].includes(binding.provider.kind)) throw Error('unsupported-provider-verifier');
  }
  return policy;
}
async function policy() { return validatePolicy(await json(CONFIG + '/bindings.json')); }
async function runtimeState() { return json(STATE + '/bindings.json', { bindings: {} }); }
function bindingPublic(binding, record = {}, store) {
  const item = store.items[binding.itemId];
  return {
    bindingId: binding.id, itemId: binding.itemId, label: binding.label,
    project: binding.project, environment: binding.environment, rotation: binding.rotation,
    consumers: binding.consumers.map(c => ({ name: c.containerName })),
    adopted: !!record.appliedVersionId, appliedVersionId: record.appliedVersionId || '',
    previousVersionId: record.previousVersionId || '', bindingRevision: record.revision || 'unadopted',
    deliveryVerified: record.deliveryVerified === true, runtimeHealthy: record.runtimeHealthy === true,
    providerVerified: record.providerVerified === true, verifiedAt: record.verifiedAt || null,
    lastOperation: record.lastOperation || null,
    versions: Object.values(item?.versions || {}).map(v => ({ versionId: v.id || v.versionId, createdAt: v.createdAt })),
  };
}
async function container(consumer) {
  const result = await exec('docker', ['inspect', consumer.containerId], { timeout: 10000, maxBuffer: 1024 * 1024 });
  const [row] = JSON.parse(result.stdout);
  if (row?.Id !== consumer.containerId || row.Name !== '/' + consumer.containerName || !row.State.Running || row.State.Paused || row.State.Restarting || row.State.OOMKilled) throw Error('consumer-unavailable');
  if (row.State.Health && row.State.Health.Status !== 'healthy') throw Error('consumer-unhealthy');
  return row;
}
async function verify(binding, value) {
  const values = await readValues(binding);
  if (values.some(entry => entry.value !== value)) throw Error('runtime-file-mismatch');
  for (const consumer of binding.consumers) {
    const row = await container(consumer);
    const source = consumer.format === 'container-env'
      ? binding.rotation === 'coupled-service' && binding.targets.find(t => t.format === 'env-key' && t.key === consumer.key && t.path.endsWith('.env'))
      : binding.targets.find(t => row.Mounts.some(m => !m.RW && (m.Source === t.path && m.Destination === consumer.path || t.path.startsWith(m.Source + '/') && consumer.path === m.Destination + t.path.slice(m.Source.length))));
    if (!source || !(await consumerMatches(consumer, value))) throw Error('consumer-delivery-mismatch');
    if (!row.State.Health && consumer.health?.kind !== 'http') throw Error('consumer-health-unavailable');
    if (consumer.health?.kind === 'http') {
      const headers = 'Host: ' + consumer.health.host + '\r\nX-Forwarded-Proto: https\r\n';
      if (!/^[A-Za-z0-9.-]+$/.test(consumer.health.host || '') || !/^\/[A-Za-z0-9/_.-]*$/.test(consumer.health.path || '/') || consumer.health.port !== 80 || !Number.isInteger(consumer.health.expectedStatus)) throw Error('invalid-health-policy');
      const code = `$ctx=stream_context_create(['http'=>['ignore_errors'=>true,'timeout'=>10,'follow_location'=>0,'header'=>${JSON.stringify(headers)}]]);@file_get_contents(${JSON.stringify('http://127.0.0.1' + (consumer.health.path || '/'))},false,$ctx);exit(isset($http_response_header[0])&&preg_match('/^HTTP\\/\\S+ ${consumer.health.expectedStatus}(?: |$)/',$http_response_header[0])?0:1);`;
      const { stdout } = await exec('docker', ['exec', consumer.containerId, 'php', '-r', code], { timeout: 15000, maxBuffer: 1024 });
      if (stdout) throw Error('unexpected-health-output');
    }
  }
  return { deliveryVerified: true, runtimeHealthy: true };
}
async function providerProbe(binding, value) {
  if (!binding.provider) return false;
  const endpoint = binding.provider.kind === 'openai' ? 'https://api.openai.com/v1/models' : 'https://api.groq.com/openai/v1/models';
  try {
    const response = await fetch(endpoint, { headers: { Authorization: 'Bearer ' + value.trim() }, signal: AbortSignal.timeout(10000), redirect: 'error' });
    await response.body?.cancel();
    return response.ok;
  } catch { return false; }
}
async function restart(binding) {
  for (const containerId of new Set(binding.consumers.filter(c => c.restart !== false).map(c => c.containerId))) await exec('docker', ['restart', '--time', '30', containerId], { timeout: 90000, maxBuffer: 4096 });
  for (let attempt = 0; attempt < 45; attempt++) {
    try { for (const c of binding.consumers) await container(c); return; }
    catch { await new Promise(resolve => setTimeout(resolve, 1000)); }
  }
  throw Error('consumer-start-failed');
}
const operationFile = id => STATE + '/operations/' + id + '.json';
const planFile = id => STATE + '/plans/' + id + '.json';
const id = prefix => prefix + '-' + randomBytes(16).toString('hex');
async function busy() {
  for (const name of (await fs.readdir(STATE + '/operations')).filter(n => /^op-[a-f0-9]{32}\.json$/.test(n))) {
    const op = await json(STATE + '/operations/' + name);
    if (!terminal.has(op.phase)) return true;
    if (op.phase === 'requires-reconciliation') throw Error('runtime-reconciliation-required');
  }
  return false;
}
export async function validatePlan(plan, binding, p, state, store) {
  if (!plan || !binding || plan.bindingId !== binding.id || plan.itemId !== binding.itemId || !identifier(plan.versionId)
      || !Number.isFinite(Date.parse(plan.expiresAt)) || plan.policyRevision !== p.revision || plan.expectedVaultRevision !== store.revision || plan.expectedBindingRevision !== (state.bindings[binding.id]?.revision || 'unadopted')
      || plan.previousVersionId !== state.bindings[binding.id]?.appliedVersionId || Date.parse(plan.expiresAt) < Date.now()) throw Error('plan-expired-or-state-changed');
  if (!store.items[binding.itemId]?.versions?.[plan.versionId]) throw Error('vault-version-unavailable');
}
export async function handle(body) {
  validateRequest(body);
  const p = await policy(); const state = await runtimeState(); const store = await loadStore(STORE);
  if (body.action === 'catalog') return { available: true, policyRevision: p.revision, vaultRevision: store.revision, bindings: p.bindings.map(b => bindingPublic(b, state.bindings[b.id], store)) };
  if (body.action === 'status') {
    const operation = body.operationId ? await json(operationFile(body.operationId)) : null;
    const binding = p.bindings.find(b => b.id === (body.bindingId || operation?.bindingId));
    return { operation, binding: binding ? bindingPublic(binding, state.bindings[binding.id], store) : null, vaultRevision: store.revision };
  }
  const binding = p.bindings.find(b => b.id === body.bindingId);
  if (!binding || body.itemId && body.itemId !== binding.itemId) throw Error('binding-not-authorized');
  if (await busy()) throw Error('runtime-operation-in-progress');
  const record = state.bindings[binding.id];
  if (body.action === 'adopt') {
    if (body.confirmation !== 'ADOPT:' + binding.id) throw Error('adoption-confirmation-invalid');
    if (record?.appliedVersionId) return bindingPublic(binding, record, store);
    const values = await readValues(binding); const value = values[0]?.value;
    if (!value || values.some(v => v.value !== value)) throw Error('adoption-source-mismatch');
    const evidence = await verify(binding, value);
    const created = await withStoreLock(STORE, async tx => tx.upsertVersion({ itemId: binding.itemId, value, expectedRevision: body.expectedVaultRevision || store.revision, metadata: { label: binding.label, itemKey: binding.id.replace(/-/g, '_'), projectId: binding.project, environment: binding.environment, kind: 'runtime', source: 'native-runtime', linkedApps: binding.project === 'platform' ? binding.consumers.map(c => c.containerName) : [binding.project] } }));
    const versionId = created.versionId || created.version?.id || created.item?.currentVersionId;
    if (!versionId) throw Error('vault-version-save-failed');
    state.bindings[binding.id] = { ...evidence, revision: id('binding'), appliedVersionId: versionId, previousVersionId: '', providerVerified: await providerProbe(binding, value), verifiedAt: new Date().toISOString() };
    await save(STATE + '/bindings.json', state);
    return bindingPublic(binding, state.bindings[binding.id], await loadStore(STORE));
  }
  if (!record?.appliedVersionId) throw Error('binding-not-adopted');
  if (body.action === 'plan' || body.action === 'rollback') {
    const versionId = body.action === 'rollback' ? record.previousVersionId : body.versionId;
    if (!versionId) throw Error('previous-version-unavailable');
    if (body.expectedVaultRevision && body.expectedVaultRevision !== store.revision || body.expectedBindingRevision && body.expectedBindingRevision !== record.revision) throw Error('runtime-revision-conflict');
    const value = await decryptVersion(STORE, { itemId: binding.itemId, versionId });
    const current = await decryptVersion(STORE, { itemId: binding.itemId, versionId: record.appliedVersionId });
    if (binding.rotation === 'coupled-service' && value !== current) throw Error('coordinated-service-rotation-required');
    await verify(binding, current);
    const planId = id('plan');
    const plan = { planId, bindingId: binding.id, itemId: binding.itemId, versionId, kind: body.action === 'rollback' ? 'rollback' : 'apply', policyRevision: p.revision, expectedVaultRevision: store.revision, expectedBindingRevision: record.revision, previousVersionId: record.appliedVersionId, status: 'validated', expiresAt: new Date(Date.now() + 300000).toISOString(), consumers: binding.consumers.map(c => ({ name: c.containerName })), rollbackAvailable: true, requiresRestart: true, providerVerification: binding.provider ? 'available' : 'unavailable', confirmation: 'APPLY:' + planId };
    await save(planFile(planId), plan); return plan;
  }
  const plan = await json(planFile(body.planId));
  if (plan.bindingId !== binding.id || body.confirmation !== plan.confirmation || plan.operationId
      || body.expectedVaultRevision && body.expectedVaultRevision !== plan.expectedVaultRevision
      || body.expectedBindingRevision && body.expectedBindingRevision !== plan.expectedBindingRevision) throw Error('plan-confirmation-invalid');
  await validatePlan(plan, binding, p, state, store);
  const operationId = id('op');
  const operation = { operationId, bindingId: binding.id, itemId: binding.itemId, versionId: plan.versionId, previousVersionId: plan.previousVersionId, planId: plan.planId, phase: 'queued', createdAt: new Date().toISOString(), deliveryVerified: false, runtimeHealthy: false, providerVerified: false };
  await save(operationFile(operationId), operation); await save(planFile(plan.planId), { ...plan, operationId });
  const child = spawn('/usr/bin/flock', ['--exclusive', '--nonblock', '/var/lib/platform-vps-backup/operation.lock', process.execPath, fileURLToPath(import.meta.url), '--job', operationId], { stdio: 'ignore' });
  child.on('error', () => { void settleChild(operationId, 'worker-start-failed').catch(() => {}); });
  child.on('exit', () => { void settleChild(operationId, 'worker-exited-before-completion').catch(() => {}); });
  return { operationId, phase: 'queued', bindingId: binding.id };
}
export function operationAfterExit(operation, error = 'interrupted-operation') {
  if (terminal.has(operation.phase)) return operation;
  return { ...operation, phase: operation.phase === 'queued' ? 'failed' : 'requires-reconciliation', error,
    deliveryVerified: false, runtimeHealthy: false, providerVerified: false, completedAt: new Date().toISOString() };
}
async function settleChild(operationId, reason) {
  const operation = await json(operationFile(operationId));
  const settled = operationAfterExit(operation, reason);
  if (settled !== operation) await save(operationFile(operationId), settled);
}
export async function runJob(operationId, overrides = {}) {
  const deps = {
    readOperation: ident => json(operationFile(ident)), readPlan: ident => json(planFile(ident)), readPolicy: policy,
    readState: runtimeState, saveState: state => save(STATE + '/bindings.json', state),
    saveOperation: (ident, operation) => save(operationFile(ident), operation),
    withStoreLock, decryptVersion, verify, providerProbe, prepare, writePrepared, rollbackPrepared, restart, disposePrepared,
    ...overrides,
  };
  const operation = await deps.readOperation(operationId);
  if (operation.phase !== 'queued') throw Error('operation-not-queued');
  let prepared, changed = false;
  try {
    const p = await deps.readPolicy(), binding = p.bindings.find(b => b.id === operation.bindingId);
    const plan = await deps.readPlan(operation.planId);
    await deps.withStoreLock(STORE, async tx => {
      const store = await tx.load(), state = await deps.readState();
      const priorRecord = structuredClone(state.bindings[binding?.id]);
      try {
        await validatePlan(plan, binding, p, state, store);
        if (operation.itemId !== binding.itemId || operation.versionId !== plan.versionId || operation.previousVersionId !== plan.previousVersionId) throw Error('invalid-operation-plan');
        const value = await deps.decryptVersion(STORE, { itemId: binding.itemId, versionId: operation.versionId });
        const previous = await deps.decryptVersion(STORE, { itemId: binding.itemId, versionId: operation.previousVersionId });
        await deps.verify(binding, previous);
        if (binding.provider && !(await deps.providerProbe(binding, value))) throw Error('provider-credential-not-verified');
        prepared = await deps.prepare(binding, value);
        operation.phase = 'applying'; await deps.saveOperation(operationId, operation);
        changed = true; await deps.writePrepared(prepared); await deps.restart(binding);
        operation.phase = 'verifying'; await deps.saveOperation(operationId, operation);
        const evidence = await deps.verify(binding, value);
        const providerVerified = await deps.providerProbe(binding, value);
        if (binding.provider && !providerVerified) throw Error('provider-credential-not-verified');
        state.bindings[binding.id] = { ...priorRecord, ...evidence, revision: id('binding'), previousVersionId: operation.previousVersionId,
          appliedVersionId: operation.versionId, providerVerified, verifiedAt: new Date().toISOString(), lastOperation: operationId };
        await deps.saveState(state);
        Object.assign(operation, evidence, { phase: plan.kind === 'rollback' ? 'rolled-back' : 'verified', providerVerified,
          appliedVersionId: operation.versionId, completedAt: new Date().toISOString() });
        await deps.saveOperation(operationId, operation);
      } catch {
        operation.error = 'delivery-failed'; operation.phase = changed ? 'rolling-back' : 'failed';
        operation.deliveryVerified = false; operation.runtimeHealthy = false; operation.providerVerified = false;
        try { await deps.saveOperation(operationId, operation); } catch { /* Attempt rollback even if a progress receipt cannot be written. */ }
        if (changed) {
          try {
            await deps.rollbackPrepared(prepared); await deps.restart(binding);
            const previous = await deps.decryptVersion(STORE, { itemId: binding.itemId, versionId: operation.previousVersionId });
            const evidence = await deps.verify(binding, previous);
            const restoredState = await deps.readState();
            const providerVerified = await deps.providerProbe(binding, previous);
            restoredState.bindings[binding.id] = { ...priorRecord, ...evidence, providerVerified, revision: id('binding'),
              appliedVersionId: operation.previousVersionId, verifiedAt: new Date().toISOString(), lastOperation: operationId };
            await deps.saveState(restoredState);
            Object.assign(operation, evidence, { phase: 'rolled-back', appliedVersionId: operation.previousVersionId,
              providerVerified, completedAt: new Date().toISOString() });
          } catch {
            operation.phase = 'requires-reconciliation'; operation.deliveryVerified = false; operation.runtimeHealthy = false;
            operation.providerVerified = false;
          }
          await deps.saveOperation(operationId, operation);
        }
      }
    });
  } catch {
    operation.phase = changed ? 'requires-reconciliation' : 'failed'; operation.error = 'delivery-failed';
    operation.deliveryVerified = false; operation.runtimeHealthy = false; operation.providerVerified = false;
    try { await deps.saveOperation(operationId, operation); } catch { /* Child exit settlement retains the last durable phase. */ }
  } finally { if (prepared) deps.disposePrepared(prepared); }
  return operation;
}
async function serve() {
  const token = await fs.readFile(await protectedFile(CONFIG + '/bridge-token', false));
  if (token.length < 32) throw Error('invalid-bridge-token');
  // Requests are serialized; operations continue in one bounded flock child.
  let queue = Promise.resolve();
  const server = http.createServer((request, response) => {
    response.setHeader('content-type', 'application/json'); response.setHeader('cache-control', 'no-store');
    let chunks = []; let size = 0;
    request.on('data', data => { size += data.length; if (size > 8192) request.destroy(); else chunks.push(data); });
    request.on('end', () => { queue = queue.then(async () => {
      try {
        if (request.method !== 'POST' || request.url !== '/v1/runtime') throw Error('invalid-route');
        const raw = Buffer.concat(chunks);
        const signature = String(request.headers['x-platform-signature'] || '');
        const envelope = validateEnvelope(raw, signature, token);
        const nonces = await json(STATE + '/nonces.json', {});
        if (nonces[envelope.nonce]) throw Error('replayed-request');
        for (const [key, timestamp] of Object.entries(nonces)) if (Date.now() - timestamp > 120000) delete nonces[key];
        if (Object.keys(nonces).length >= 1000) throw Error('request-limit');
        nonces[envelope.nonce] = Date.now(); await save(STATE + '/nonces.json', nonces);
        const result = await handle(envelope.body); response.end(JSON.stringify(result));
      } catch (error) {
        const safe = /^(?:invalid-|unsafe-|protected-|unsupported-|duplicate-|binding-|runtime-|plan-|previous-|vault-|coordinated-|consumer-|adoption-|maintenance-|provider-|replayed-|expired-|unauthorized|request-limit)/.test(error.message) ? error.message : 'vault-runtime-unavailable';
        response.statusCode = 409; response.end(JSON.stringify({ error: safe }));
      }
    }).catch(() => { if (!response.writableEnded) { response.statusCode = 503; response.end('{"error":"vault-runtime-unavailable"}'); } }); });
  });
  await policy();
  for (const name of (await fs.readdir(STATE + '/operations')).filter(n => /^op-[a-f0-9]{32}\.json$/.test(n))) {
    const op = await json(STATE + '/operations/' + name);
    if (!terminal.has(op.phase)) await save(STATE + '/operations/' + name, { ...op, phase: 'requires-reconciliation', error: 'interrupted-operation' });
  }
  try {
    const info = await fs.lstat(SOCKET);
    if (!info.isSocket() || info.isSymbolicLink() || info.uid !== 0) throw Error('unsafe-runtime-socket');
    await fs.unlink(SOCKET);
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(SOCKET, resolve); });
  await fs.chown('/run/platform-vault', 0, 1000); await fs.chmod('/run/platform-vault', 0o750);
  await fs.chown(SOCKET, 0, 1000); await fs.chmod(SOCKET, 0o660);
}
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  if (process.getuid() !== 0) throw Error('root-required');
  process.umask(0o077);
  if (process.argv[2] === '--job' && ID.test(process.argv[3] || '')) await runJob(process.argv[3]);
  else await serve();
}
