import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { renderRuntimeUpdates } from '../updates/ui.mjs';
const source = readFileSync(new URL('../styles/runtime-updates.js', import.meta.url), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));
class Node {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = {}; this.attributes = {}; this.value = ''; this.disabled = false; this.hidden = false; this.textContent = ''; this.open = false; }
  append(...nodes) { for (const node of nodes) { if (node.parent) node.remove(); node.parent = this; this.children.push(node); } }
  insertBefore(node, next) { if (node.parent) node.remove(); const index = next ? this.children.indexOf(next) : this.children.length; node.parent = this; this.children.splice(index < 0 ? this.children.length : index, 0, node); }
  remove() { if (this.parent) { const index = this.parent.children.indexOf(this); if (index >= 0) this.parent.children.splice(index, 1); this.parent = null; } }
  replaceChildren(...nodes) { this.children = nodes; }
  addEventListener(type, callback) { this.listeners[type] = callback; }
  setAttribute(key, value) { this.attributes[key] = value; }
  removeAttribute(key) { delete this.attributes[key]; }
  get options() { return this.children; }
  get parentElement() { return this.parent; }
  showModal() { this.open = true; }
  close() { this.open = false; }
}
function fixture(request, host = false, options = {}) {
  const nodes = new Map(), calls = [], timers = new Map(), animations = []; let timer = 0, scan;
  const create = tag => { const node = new Node(tag); node.getBoundingClientRect = () => ({ top: node.parent ? node.parent.children.indexOf(node) * 48 : 0 }); node.animate = frames => { animations.push({ node, frames }); return { finished: Promise.resolve(), cancel() {} }; }; return node; };
  const root = new Node(); root.isConnected = true;
  root.querySelector = selector => { if (['[data-updates-search]', '[data-updates-category]'].includes(selector)) throw Error('Search control was removed'); if (!nodes.has(selector)) nodes.set(selector, new Node()); return nodes.get(selector); };
  root.querySelector('[data-updates-progress]').querySelector = () => root.querySelector('progress');
  root.querySelector('[data-host-updates-progress]').querySelector = () => root.querySelector('progress');
  const track = new Node('span'), fill = new Node('span'); fill.style = {}; track.querySelector = () => fill; track.append(root.querySelector('progress'), fill);
  nodes.set('[data-progress-fill]', fill); nodes.set('[data-progress-track]', track);
  const document = { readyState: 'complete', hidden: false, body: {}, createElement: create, querySelectorAll: selector => root.isConnected && selector === (host ? '[data-host-updates]' : '[data-runtime-updates]') ? [root] : [], addEventListener() {} };
  const context = { document, Headers, Date, Set, WeakSet, Number, Array, String, Error, encodeURIComponent, crypto: { randomUUID: () => 'fixture-uuid' }, clearTimeout: id => timers.delete(id), setTimeout: (callback, delay) => { timers.set(++timer, { callback, delay }); return timer; } };
  context.window = { addEventListener() {}, matchMedia: () => ({ matches: !options.motion }), MutationObserver: class {} , controlCenterRuntimeUpdates: { authenticate: async () => calls.push('authenticate'), request: async (path, payload) => { calls.push({ path, payload }); return request(path, payload); } } };
  context.MutationObserver = class { constructor(callback) { scan = callback; } observe() {} };
  vm.runInNewContext(source, context);
  return { root, nodes, calls, timers, document, animations, scan: () => scan(), node: selector => root.querySelector(selector), context };
}
const component = { id: 'php', label: 'PHP', category: 'Runtime', installed: true, current: { version: '8.5.11' }, latestStable: { version: '8.5.12', imageDigest: 'sha256:fixture' }, candidateRelease: { version: '8.5.12', imageDigest: 'sha256:fixture' }, status: 'update-available', canUpdate: true, services: ['php-apache'] };
const catalog = { available: true, revision: 'revision', components: [component], operations: [] };
test('settings markup has accessible update controls and uses existing vendored icons', () => {
  const html = renderRuntimeUpdates();
  const css = readFileSync(new URL('../styles/runtime-updates.css', import.meta.url), 'utf8');
  assert.match(css, /\.cc-settings > \.ops-project-detail-panel\{border-radius:var\(--cc-radius-2xl,16px\)\}/);
  assert.match(html, /data-runtime-updates/); assert.match(html, /<dialog/); assert.match(html, /aria-live="polite"/); assert.match(html, /data-fa-version="7.3.1"/); assert.doesNotMatch(html, /Installa componente|data-updates-search|data-updates-category|Tutte le categorie|type="search"|https:\/\//);
  assert.ok(html.indexOf('data-host-updates aria-labelledby') < html.indexOf('data-runtime-updates aria-labelledby'), 'OS is a separate panel above runtime updates');
});
test('settings update surfaces inherit the shared panel inset instead of introducing a different edge', () => {
  const css = readFileSync(new URL('../styles/runtime-updates.css', import.meta.url), 'utf8');
  const shared = readFileSync(new URL('../styles/control-center.css', import.meta.url), 'utf8');
  assert.match(shared, /\.ops-project-detail-panel \{[^}]*padding: 15px;/s);
  const overrides = css.match(/\.cc-settings > \.cc-updates,\.cc-settings > \.cc-host-updates\{([^}]*)\}/);
  assert.ok(overrides); assert.doesNotMatch(overrides[1], /padding|border|background|box-shadow/);
});
test('check remains queued until operation readback and polls pending operations at two seconds', async () => {
  const h = fixture(path => path.endsWith('/check') ? { operationId: 'check1', status: 'queued' } : catalog);
  await tick(); assert.equal(h.node('[data-updates-check]').disabled, false);
  await h.node('[data-updates-check]').listeners.click();
  assert.equal(h.node('[data-updates-check]').disabled, true);
  assert.match(h.node('[data-updates-status]').textContent, /attesa/);
  assert.equal([...h.timers.values()][0].delay, 2000);
  assert.equal(h.node('progress').attributes.value, undefined);
  assert.equal(h.calls.filter(call => call.path?.endsWith('/check')).length, 1);
});
test('late catalog response cannot render after navigation disconnects the panel', async () => {
  let resolve; const promise = new Promise(yes => { resolve = yes; }); const h = fixture(() => promise);
  h.root.isConnected = false; h.scan(); resolve(catalog); await tick();
  assert.equal(h.node('[data-updates-list]').children.length, 0); assert.equal(h.timers.size, 0);
});
test('metadata checks finish their real step progress instead of leaving an indeterminate bar', async () => {
  const h = fixture(path => path.endsWith('/check') ? { operationId: 'check1', status: 'queued' }
    : path.includes('/operations/') ? { id: 'check1', status: 'succeeded', stage: 'Verifica completata', completedSteps: 19, totalSteps: 19 } : catalog);
  await tick(); await h.node('[data-updates-check]').listeners.click();
  await [...h.timers.values()][0].callback(); await tick();
  assert.equal(h.node('progress').max, 19); assert.equal(h.node('progress').value, 19);
  assert.match(h.node('[data-updates-stage]').textContent, /Verifica completata/);
  assert.doesNotMatch(h.node('[data-updates-stage]').textContent, /19 servizi/);
});
test('closing a plan before passkey returns prevents the plan request and apply', async () => {
  const h = fixture(() => catalog); await tick();
  let finish; h.context.window.controlCenterRuntimeUpdates.authenticate = () => new Promise(resolve => { finish = resolve; });
  const button = h.node('[data-updates-list]').children[0].children.find(node => node.tagName === 'button');
  button.listeners.click(); h.node('[data-updates-close]').listeners.click(); finish(); await tick();
  assert.equal(h.calls.some(call => call.path?.endsWith('/plan')), false); assert.equal(h.node('[data-updates-apply]').disabled, true);
});
test('unavailable, missing and unsupported components cannot start an update', async () => {
  const h = fixture(() => ({ ...catalog, components: ['unavailable', 'not-installed', 'unsupported'].map(status => ({ ...component, id: status, status, blockedReason: 'Migrazione richiesta' })) }));
  await tick();
  assert.equal(h.node('[data-updates-list]').children.length, 3);
  for (const row of h.node('[data-updates-list]').children) assert.equal(row.children.find(node => node.tagName === 'button').disabled, true);
});
test('a current component with no candidate never renders a null version or a migration claim', async () => {
  const h = fixture(() => ({ ...catalog, components: [{ ...component, status: 'current', canUpdate: false, candidateRelease: { version: null, imageDigest: null }, latestStable: { version: '8.5.12' }, current: { version: '8.5.12' } }] }));
  await tick();
  const row = h.node('[data-updates-list]').children[0];
  assert.equal(row.children.some(node => node.textContent.includes('Aggiornamento compatibile:') || node.textContent.includes('migrazione')), false);
  assert.equal(row.children.find(node => node.tagName === 'button').disabled, true);
});
test('compatible candidate is separate from a newer major and apply requires a fresh reviewed plan', async () => {
  const plan = { planId: 'p1', revision: 'revision', expiresAt: new Date(Date.now() + 60000).toISOString(), targetVersion: '8.5.12', targetDigest: 'sha256:fixture', affectedServices: ['php-apache'], steps: ['Scarica', 'Verifica'], risks: ['Riavvio breve'], confirmationRequired: 'UPDATE' };
  const h = fixture(path => path.endsWith('/plan') ? plan : path.endsWith('/apply') ? { operationId: 'apply1', status: 'queued' } : { ...catalog, components: [{ ...component, latestStable: { version: '9.0.1' } }] });
  await tick(); const row = h.node('[data-updates-list]').children[0];
  assert.ok(row.children[4].children[1].textContent.includes('Aggiornamento compatibile: 8.5.12'));
  row.children.find(node => node.tagName === 'button').listeners.click(); await tick();
  assert.equal(h.node('[data-updates-apply]').disabled, true);
  h.node('[data-updates-confirm]').value = 'UPDATE'; h.node('[data-updates-confirm]').listeners.input();
  assert.equal(h.node('[data-updates-apply]').disabled, false);
  await h.node('[data-updates-apply]').listeners.click();
  assert.equal(h.calls.filter(call => call === 'authenticate').length, 2);
  const call = h.calls.find(call => call.path?.endsWith('/apply'));
  assert.equal(call.payload.planId, 'p1'); assert.equal(call.payload.confirmation, 'UPDATE');
  assert.equal(h.node('[data-updates-dialog]').open, false);
  assert.equal(h.node('[data-updates-check]').disabled, true);
});
test('one runtime family displays all known mixed versions and reviews a single target for every service', async () => {
  const services = ['app-one', 'app-two', 'app-three', 'app-four', 'app-five', 'app-six'];
  const family = { ...component, id: 'node', label: 'Node.js', current: { version: null, versions: ['24.22.0', '26.10.0'] }, needsAlignment: true, services, latestStable: { version: '26.12.1', imageDigest: 'sha256:fixture' }, candidateRelease: { version: '26.12.1', imageDigest: 'sha256:fixture' } };
  const plan = { planId: 'family-plan', revision: 'revision', expiresAt: new Date(Date.now() + 60000).toISOString(), targetVersion: '26.12.1', targetDigest: 'sha256:fixture', affectedServices: services, steps: ['Prepara tutti i servizi', 'Verifica e uniforma'], risks: [], confirmationRequired: 'UPDATE' };
  const h = fixture(path => path.endsWith('/plan') ? plan : { ...catalog, components: [family] }); await tick();
  const rows = h.node('[data-updates-list]').children; assert.equal(rows.length, 1);
  const current = rows[0].children[1].children[1].textContent;
  assert.equal(current, 'Da uniformare: 24.22.0 / 26.10.0'); assert.doesNotMatch(current, /Non verificata/);
  assert.match(h.node('[data-updates-summary]').textContent, /^1 componente · 1 aggiornamento disponibile/);
  const button = rows[0].children.find(node => node.tagName === 'button'); assert.equal(button.textContent, 'Aggiorna'); assert.equal(button.disabled, false);
  button.listeners.click(); await tick();
  const details = h.node('[data-updates-plan-details]').children.map(node => node.textContent).join('\n');
  assert.match(details, /→ 26\.12\.1/); assert.match(details, /Versione unica per tutti i servizi elencati/);
  for (const service of services) assert.ok(details.includes(service));
  assert.equal(h.calls.filter(call => call.path?.endsWith('/plan')).length, 1);
  assert.equal(h.calls.some(call => call.path?.endsWith('/apply')), false);
});
async function poll(h) { const timer = [...h.timers.values()][0]; assert.ok(timer); await timer.callback(); await tick(); }
test('updatable components sort first and idle catalog refresh does not flash busy or disable actions', async () => {
  let resolve; let count = 0;
  const h = fixture(() => ++count === 1 ? { ...catalog, components: [{ ...component, id: 'current', status: 'current', canUpdate: false }, component] } : new Promise(yes => { resolve = yes; })); await tick();
  assert.equal(h.node('[data-updates-list]').children[0].children[0].children[0].textContent, 'PHP');
  const loading = [...h.timers.values()][0].callback();
  assert.equal(h.node('[data-updates-check]').disabled, false); assert.equal(h.node('[data-updates-all]').disabled, false);
  assert.equal(h.node('[data-updates-progress]').hidden, true); assert.equal(h.root.attributes['aria-busy'], 'false');
  resolve(catalog); await loading;
});
test('pending operation polls only its status and confirms all services before displaying a full bar', async () => {
  let operation = { id: 'op', status: 'running', stage: 'verifica', totalServices: 2, completedServices: 2, currentService: 'php-app', serviceResults: [{ service: 'php-app', status: 'verifying', stage: 'Controllo HTTP' }, { service: 'other-app', status: 'verified' }] };
  const h = fixture(path => path.includes('/operations/') ? operation : { ...catalog, operations: [operation] }); await tick();
  assert.equal(h.calls.length, 1); await poll(h);
  assert.equal(h.calls.filter(call => call.path === '/control/runtime-updates').length, 1, 'pending must not perform another expensive catalog request');
  assert.equal(h.node('progress').value, ''); assert.equal(h.node('progress').attributes.value, undefined);
  assert.equal(h.node('[data-updates-services]').children.length, 2); assert.match(h.node('[data-updates-stage]').textContent, /php-app/);
  operation = { ...operation, status: 'succeeded', serviceResults: operation.serviceResults.map(service => ({ ...service, status: 'verified' })) };
  await poll(h);
  assert.equal(h.calls.filter(call => call.path === '/control/runtime-updates').length, 2, 'terminal status refreshes catalog once');
  assert.equal(h.node('progress').value, 2); assert.equal(h.node('progress').max, 2);
});
test('self update reconnects after a dropped poll and preserves operation without another catalog request', async () => {
  let attempts = 0;
  const operation = { id: 'self', status: 'running', stage: 'Riavvio Control Center', totalServices: 1, completedServices: 0, currentService: 'control-center' };
  const h = fixture(path => { if (path.includes('/operations/')) { if (++attempts === 1) throw Error('Failed to fetch'); return { ...operation, status: 'succeeded', completedServices: 1 }; } return { ...catalog, operations: attempts > 1 ? [] : [operation] }; }); await tick();
  await poll(h); assert.match(h.node('[data-updates-status]').textContent, /Riconnessione automatica/); assert.equal([...h.timers.values()][0].delay, 2000);
  assert.equal(h.calls.filter(call => call.path === '/control/runtime-updates').length, 1);
  await poll(h); assert.match(h.node('[data-updates-status]').textContent, /completata/); assert.equal(h.node('[data-updates-check]').disabled, false);
});
test('batch review enumerates targets, submits one all operation and retains service failure evidence', async () => {
  const plan = { kind: 'batch', componentId: 'all', planId: 'all-plan', revision: 'revision', expiresAt: new Date(Date.now() + 60000).toISOString(), targetVersion: '2 componenti', targetDigest: 'sha256:aggregate', components: [{ id: 'php', label: 'PHP', targetVersion: '8.5.12', targetDigest: 'sha256:fixture', affectedServices: ['php-app'] }, { id: 'node', label: 'Node.js', targetVersion: '26.12.1', targetDigest: 'sha256:fixture', affectedServices: ['node-app'] }], affectedServices: ['php-app', 'node-app'], steps: ['Prepara tutti', 'Verifica tutti'], risks: ['Riavvio servizi'], confirmationRequired: 'UPDATE' };
  const operation = { id: 'batch1', status: 'failed', stage: 'Rollback completato dopo errore', totalServices: 2, completedServices: 1, error: 'Verifica non riuscita', serviceResults: [{ componentId: 'php', service: 'php-app', status: 'rolled-back' }, { componentId: 'node', service: 'node-app', status: 'failed' }] };
  const h = fixture(path => path.endsWith('/all/plan') ? plan : path.endsWith('/all/apply') ? { operationId: 'batch1', status: 'queued' } : path.includes('/operations/') ? operation : catalog); await tick();
  h.node('[data-updates-all]').listeners.click(); await tick();
  const details = h.node('[data-updates-plan-details]').children;
  assert.ok(details.find(node => node.tagName === 'ul').children.some(node => node.textContent.includes('Node.js → 26.12.1')));
  assert.equal(h.node('[data-updates-apply]').disabled, true);
  h.node('[data-updates-confirm]').value = 'UPDATE'; h.node('[data-updates-confirm]').listeners.input(); await h.node('[data-updates-apply]').listeners.click();
  assert.equal(h.calls.filter(call => call.path?.endsWith('/all/apply')).length, 1); assert.equal(h.calls.filter(call => call === 'authenticate').length, 2);
  await poll(h); assert.equal(h.node('progress').value, 1); assert.equal(h.node('[data-updates-services]').children[1].attributes['data-service-status'], 'failed'); assert.equal(h.node('[data-updates-all]').disabled, false);
});
test('batch success stays active through preparation and verifies each service before completion', async () => {
  let stage = 0;
  const services = ['php-app', 'node-app'];
  const operations = [
    { id: 'all-op', status: 'preparing', stage: 'Preparazione immagini', totalServices: 0, completedServices: 0, serviceResults: [] },
    { id: 'all-op', status: 'updating', stage: 'Aggiornamento servizi', currentComponent: 'node', currentService: 'node-app', totalServices: 2, completedServices: 1, serviceResults: services.map((service, index) => ({ service, status: index ? 'updating' : 'verified' })) },
    { id: 'all-op', status: 'succeeded', stage: 'Verifica finale completata', totalServices: 2, completedServices: 2, serviceResults: services.map(service => ({ service, status: 'verified' })) },
  ];
  const h = fixture(path => path.includes('/operations/') ? operations[++stage] : { ...catalog, operations: stage === 0 ? [operations[0]] : [] }); await tick();
  assert.equal(h.node('progress').attributes.value, undefined); assert.equal(h.node('[data-updates-all]').disabled, true);
  await poll(h); assert.equal(h.node('progress').value, 1); assert.match(h.node('[data-updates-stage]').textContent, /node-app/);
  await poll(h); assert.equal(h.node('progress').value, 2); assert.equal(h.node('[data-updates-all]').disabled, false);
  assert.ok(h.node('[data-updates-services]').children.every(row => row.attributes['data-service-status'] === 'verified'));
  assert.equal(h.calls.filter(call => call.path === '/control/runtime-updates').length, 2);
});
const hostCatalog = { schema: 'host-updates/v1', available: true, revision: 'host-revision', os: { id: 'ubuntu', name: 'Ubuntu', version: '24.04' }, checkedAt: new Date().toISOString(), updateCount: 1, keptBackCount: 1, rebootRequired: true, canCheck: true, canApply: true, operations: [] };
test('OS catalog loads independently once and never applies upgrades or reboots on mount', async () => {
  const h = fixture(() => hostCatalog, true); await tick();
  assert.equal(h.calls.length, 1); assert.equal(h.calls[0].path, '/control/runtime-updates/system'); assert.equal(h.timers.size, 0);
  assert.equal(h.node('[data-host-updates-os]').textContent, 'Ubuntu 24.04');
  assert.match(h.node('[data-host-updates-summary]').textContent, /Riavvio richiesto/);
  assert.equal(h.node('[data-host-updates-reboot]').hidden, false);
  assert.doesNotMatch(renderRuntimeUpdates(), /data-host-updates-packages/);
  assert.equal(h.node('[data-host-updates-upgrade]').disabled, false);
});
test('OS cleanup-only plans show removal counts and keep typed confirmation without listing packages', async () => {
  const plan = { kind: 'host-upgrade', planId: 'cleanup-plan', revision: 'host-revision', expiresAt: new Date(Date.now() + 60000).toISOString(), packageCount: 0, autoremoveCount: 2, steps: ['Autoremove verificato'], risks: [], confirmationRequired: 'UPDATE' };
  const h = fixture(path => path.endsWith('/plan') ? plan : { ...hostCatalog, updateCount: 0, autoremoveCount: 2, rebootRequired: false }, true);
  await tick(); assert.equal(h.node('[data-host-updates-upgrade]').disabled, false);
  assert.match(h.node('[data-host-updates-summary]').textContent, /2 dipendenze da rimuovere/);
  h.node('[data-host-updates-upgrade]').listeners.click(); await tick();
  assert.match(h.node('[data-host-updates-plan-details]').children[0].textContent, /0 pacchetti da aggiornare.*2 dipendenze/);
  assert.equal(h.node('[data-host-updates-apply]').disabled, true);
  assert.ok(!h.calls.some(call => call.path?.endsWith('/apply')));
});
test('OS upgrade and reboot require distinct reviewed confirmation and recover connection after server maintenance', async () => {
  for (const rebooting of [false, true]) {
    let polls = 0;
    const kind = rebooting ? 'host-reboot' : 'host-upgrade', expected = rebooting ? 'REBOOT' : 'UPDATE';
    const plan = { kind, planId: 'host-plan', revision: 'host-revision', expiresAt: new Date(Date.now() + 60000).toISOString(), packageCount: hostCatalog.updateCount, steps: ['Prepara', 'Verifica'], risks: ['Indisponibilità temporanea'], confirmationRequired: expected };
    const h = fixture(path => path.endsWith('/plan') ? plan : path.endsWith('/apply') ? { operationId: 'host-op', status: 'queued' } : path.includes('/operations/') ? (++polls === 1 ? Promise.reject(Error('connection reset')) : { id: 'host-op', status: 'succeeded', stage: 'Server verificato', totalSteps: 2, completedSteps: 2 }) : hostCatalog, true);
    await tick(); h.node(rebooting ? '[data-host-updates-reboot]' : '[data-host-updates-upgrade]').listeners.click(); await tick();
    assert.match(h.node('[data-host-updates-confirm-prompt]').textContent, new RegExp(expected));
    assert.ok(!h.node('[data-host-updates-plan-details]').children.some(node => node.textContent.includes('openssl')), 'package names never appear in OS review');
    h.node('[data-host-updates-confirm]').value = rebooting ? 'UPDATE' : 'REBOOT'; h.node('[data-host-updates-confirm]').listeners.input(); assert.equal(h.node('[data-host-updates-apply]').disabled, true);
    h.node('[data-host-updates-confirm]').value = expected; h.node('[data-host-updates-confirm]').listeners.input(); await h.node('[data-host-updates-apply]').listeners.click();
    const call = h.calls.find(call => call.path?.endsWith('/apply'));
    assert.equal(call.payload.confirmation, expected); assert.equal(call.payload.revision, 'host-revision');
    assert.equal(call.path, '/control/runtime-updates/system/' + (rebooting ? 'reboot/' : '') + 'apply');
    await poll(h); assert.match(h.node('[data-host-updates-status]').textContent, /Riconnessione automatica/); assert.equal(h.calls.filter(call => call.path === '/control/runtime-updates/system').length, 1);
    await poll(h); assert.equal(h.node('progress').value, 2); assert.equal(h.node('[data-host-updates-reboot]').disabled, false);
    assert.equal(h.calls.filter(call => call === 'authenticate').length, 2); assert.equal(h.calls.filter(call => call.path === '/control/runtime-updates/system').length, 2);
  }
});
test('unavailable OS catalog offers a read retry and never touches the runtime catalog', async () => {
  let count = 0;
  const h = fixture(() => ++count === 1 ? { ...hostCatalog, available: false, updateCount: 0 } : hostCatalog, true); await tick();
  assert.equal(h.node('[data-host-updates-upgrade]').disabled, true); assert.equal(h.node('[data-host-updates-check]').disabled, false);
  await h.node('[data-host-updates-check]').listeners.click(); await tick();
  assert.ok(h.calls.every(call => call.path === '/control/runtime-updates/system' && call.payload === undefined));
  assert.equal(h.node('[data-host-updates-upgrade]').disabled, false);
});
test('reboot control stays hidden when the server does not require a reboot', async () => {
  const h = fixture(() => ({ ...hostCatalog, rebootRequired: false }), true); await tick();
  assert.equal(h.node('[data-host-updates-reboot]').hidden, true); assert.equal(h.node('[data-host-updates-reboot]').disabled, true);
  await h.node('[data-host-updates-reboot]').listeners.click();
  assert.equal(h.calls.length, 1); assert.equal(h.node('[data-host-updates-dialog]').open, false);
});
test('keyed rows preserve disclosure state and identity through reorder; unchanged idle refresh does not animate', async () => {
  let aligned = false;
  const node = { ...component, id: 'node', label: 'Node.js' };
  const h = fixture(() => ({ ...catalog, components: [{ ...component, status: aligned ? 'current' : 'update-available', canUpdate: !aligned }, { ...node, status: aligned ? 'update-available' : 'current', canUpdate: aligned }] }), false, { motion: true }); await tick();
  const list = h.node('[data-updates-list]'), phpRow = list.children[0], nodeRow = list.children[1];
  phpRow.children[4].open = true;
  const before = h.animations.length;
  aligned = true; await poll(h);
  assert.equal(list.children[0], nodeRow); assert.equal(list.children[1], phpRow); assert.equal(phpRow.children[4].open, true);
  assert.ok(h.animations.slice(before).some(animation => animation.frames.some(frame => /translateY\((?:48|-48)px\)/.test(frame.transform || ''))), 'reorder animates actual old-to-new geometry');
  const after = h.animations.length; await poll(h);
  assert.equal(h.animations.length, after); assert.equal(list.children[0], nodeRow); assert.equal(list.children[1], phpRow);
  assert.equal(h.node('[data-updates-status]').hidden, true);
  assert.ok(!phpRow.children[0].children.some(child => child.textContent === 'Runtime'), 'category labels are absent');
});
test('service rows update in place and successful results collapse while failure evidence stays open', async () => {
  let phase = 'running';
  const operation = () => ({ id: 'services-op', status: phase, stage: 'Verifica', totalServices: 1, completedServices: phase === 'succeeded' ? 1 : 0, serviceResults: [{ componentId: 'php', service: 'php-app', status: phase === 'running' ? 'verifying' : phase === 'succeeded' ? 'verified' : 'failed', stage: 'Verifica HTTP' }] });
  const h = fixture(path => path.includes('/operations/') ? operation() : { ...catalog, operations: phase === 'running' ? [operation()] : [] }); await tick();
  const row = h.node('[data-updates-services]').children[0]; assert.equal(h.node('[data-updates-results]').open, true);
  await poll(h); assert.equal(h.node('[data-updates-services]').children[0], row);
  phase = 'succeeded'; await poll(h); assert.equal(h.node('[data-updates-services]').children[0], row); assert.equal(h.node('[data-updates-results]').open, false);
  const failed = fixture(path => path.includes('/operations/') ? { ...operation(), status: 'failed' } : { ...catalog, operations: [{ ...operation(), status: 'running' }] }); await tick(); await poll(failed);
  assert.equal(failed.node('[data-updates-results]').open, true);
});
test('reduced motion preserves keyed updates without calling the animation API', async () => {
  let phase = false;
  const h = fixture(() => ({ ...catalog, components: [{ ...component, status: phase ? 'current' : 'update-available' }] })); await tick();
  const row = h.node('[data-updates-list]').children[0]; phase = true; await poll(h);
  assert.equal(h.node('[data-updates-list]').children[0], row); assert.equal(h.animations.length, 0);
});
test('decorative progress targets interpolate while native values stay exact and unknown totals remain indeterminate', async () => {
  let completed = 1, total = 4;
  const operation = () => ({ id: 'bar', status: 'running', stage: 'Verifica', completedServices: completed, totalServices: total });
  const h = fixture(path => path.includes('/operations/') ? operation() : { ...catalog, operations: [operation()] }); await tick();
  assert.equal(h.node('progress').value, 1); assert.equal(h.node('[data-progress-fill]').style.transform, 'scaleX(0.25)');
  completed = 2; await poll(h); assert.equal(h.node('progress').value, 2); assert.equal(h.node('[data-progress-fill]').style.transform, 'scaleX(0.5)');
  completed = 4; await poll(h); assert.equal(h.node('[data-progress-track]').attributes['data-progress-state'], 'indeterminate', 'full visual target requires terminal success');
  total = 0; completed = 0; await poll(h); assert.equal(h.node('[data-progress-fill]').style.transform, '');
  const css = readFileSync(new URL('../styles/runtime-updates.css', import.meta.url), 'utf8');
  assert.match(css, /transition:transform 400ms/); assert.match(css, /prefers-reduced-motion:reduce\)\{\.cc-progress-fill\{transition:none/);
});
