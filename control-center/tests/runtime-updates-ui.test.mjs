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
function fixture(request, options = {}) {
  const nodes = new Map(), calls = [], timers = new Map(), animations = []; let timer = 0, scan;
  const create = tag => { const node = new Node(tag); node.getBoundingClientRect = () => ({ top: node.parent ? node.parent.children.indexOf(node) * 48 : 0 }); node.animate = frames => { animations.push({ node, frames }); return { finished: Promise.resolve(), cancel() {} }; }; return node; };
  const root = new Node(); root.isConnected = true;
  root.querySelector = selector => { if (['[data-updates-search]', '[data-updates-category]'].includes(selector)) throw Error('Search control was removed'); if (!nodes.has(selector)) nodes.set(selector, new Node()); return nodes.get(selector); };
  root.querySelector('[data-platform-updates-progress]').querySelector = () => root.querySelector('progress');
  const track = new Node('span'), fill = new Node('span'); fill.style = {}; track.querySelector = () => fill; track.append(root.querySelector('progress'), fill);
  nodes.set('[data-progress-fill]', fill); nodes.set('[data-progress-track]', track);
  const document = { readyState: 'complete', hidden: false, body: {}, createElement: create, querySelectorAll: selector => root.isConnected && selector === '[data-platform-updates]' ? [root] : [], addEventListener() {} };
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
  assert.match(html, /data-platform-updates/); assert.match(html, /<dialog/); assert.match(html, /aria-live="polite"/); assert.match(html, /data-fa-version="7.3.1"/); assert.doesNotMatch(html, /Installa componente|data-updates-search|data-updates-category|Tutte le categorie|type="search"|https:\/\//);
  assert.doesNotMatch(html, /data-host-updates|data-runtime-updates|data-updates-all/);
});
test('redesigned surface uses the existing canvas and compact list geometry', () => {
  const css = readFileSync(new URL('../styles/runtime-updates.css', import.meta.url), 'utf8');
  assert.match(css, /\.cc-settings > \.cc-updates\{padding:0;border:0;background:transparent;box-shadow:none/);
  assert.match(css, /min-height:58px/); assert.match(css, /min-height:47px/);
});
async function poll(h) { const timer = [...h.timers.values()][0]; assert.ok(timer); await timer.callback(); await tick(); }
const systemCatalog = { available: true, canCheck: true, canApply: true, revision: 'system-revision', checkedAt: new Date().toISOString(), updateCount: 1, operations: [] };
function platformFixture(request) { return fixture(request); }
test('unified markup has one primary entry and discloses individual actions separately', () => {
  const html = renderRuntimeUpdates();
  assert.match(html, /data-platform-updates[^>]*aria-labelledby/);
  assert.match(html, /data-platform-updates-installed><summary><span>Servizi installati/);
  assert.doesNotMatch(html, /Rivedi aggiornamento|Scrivi UPDATE|data-host-updates|data-runtime-updates/);
  assert.match(html, /data-platform-updates-results/);
});
test('one check submits both scopes and retains an accepted operation when the other scope fails', async () => {
  const h = platformFixture(path => {
    if (path === '/control/runtime-updates/system/check') return { operationId: 'host-check', status: 'queued' };
    if (path.endsWith('/check')) throw Error('Verifica servizi non disponibile');
    if (path.includes('/operations/')) return { id: 'host-check', status: 'running', stage: 'Controllo pacchetti', completedSteps: 1, totalSteps: 3 };
    return path.endsWith('/system') ? systemCatalog : catalog;
  });
  await tick(); await h.node('[data-platform-updates-check]').listeners.click();
  assert.equal(h.calls.filter(call => call.path?.endsWith('/check')).length, 2);
  assert.equal(h.node('[data-platform-updates-check]').disabled, true);
  assert.match(h.node('[data-platform-updates-status]').textContent, /Verifica servizi non disponibile/);
  await poll(h);
  assert.ok(h.calls.some(call => call.path === '/control/runtime-updates/operations/host-check'));
  assert.match(h.node('[data-platform-updates-results]').children[0].children[2].textContent, /Controllo pacchetti/);
});
test('one authentication refreshes catalogs, validates plans and applies immediately with partial evidence', async () => {
  const expiresAt = new Date(Date.now() + 60000).toISOString();
  const hostPlan = { planId: 'host-plan', revision: 'system-revision', kind: 'host-upgrade', confirmationRequired: 'UPDATE_AND_REBOOT', rebootAfter: true, coordinatedReboot: true, expiresAt, packageCount: 1, packages: [{ name: 'curl', currentVersion: '1', targetVersion: '2' }], steps: ['Verifica pacchetti'], risks: ['Riavvio servizi'] };
  const servicesPlan = { planId: 'services-plan', revision: 'revision', kind: 'batch', confirmationRequired: 'UPDATE', expiresAt, targetVersion: '1 componente', targetDigest: 'sha256:aggregate', components: [{ label: 'PHP', targetVersion: '8.5.12', affectedServices: ['php-app'] }], steps: [], risks: [] };
  const h = platformFixture(path => {
    if (path === '/control/runtime-updates/system/plan') return hostPlan;
    if (path.endsWith('/all/plan')) return servicesPlan;
    if (path === '/control/runtime-updates/system/apply') return { operationId: 'accepted-host', status: 'queued' };
    if (path.endsWith('/all/apply')) throw Error('Servizi rifiutati');
    if (path.includes('/operations/')) return { id: 'accepted-host', status: 'running', stage: 'Aggiornamento pacchetti', totalSteps: 3, completedSteps: 1 };
    return path.endsWith('/system') ? systemCatalog : catalog;
  });
  await tick(); await h.node('[data-platform-updates-upgrade]').listeners.click();
  assert.equal(h.calls.filter(call => call.path === '/control/runtime-updates/system').length, 2);
  assert.equal(h.calls.filter(call => call.path === '/control/runtime-updates').length, 2);
  assert.equal(h.calls.filter(call => call === 'authenticate').length, 1);
  assert.equal(h.calls.find(call => call.path === '/control/runtime-updates/system/plan').payload.rebootAfter, true);
  assert.equal(h.calls.find(call => call.path === '/control/runtime-updates/system/plan').payload.coordinatedReboot, true);
  assert.equal(h.calls.find(call => call.path === '/control/runtime-updates/system/apply').payload.confirmation, 'UPDATE_AND_REBOOT');
  assert.equal(h.node('[data-platform-updates-dialog]').open, false);
  assert.match(h.node('[data-platform-updates-status]').textContent, /Servizi rifiutati/);
  await poll(h);
  assert.ok(h.calls.some(call => call.path === '/control/runtime-updates/operations/accepted-host'));
  assert.equal(h.calls.filter(call => call.path?.endsWith('/apply')).length, 2);
  assert.ok(h.node('progress').value !== h.node('progress').max, 'partial work cannot show full completion');
});

test('unified list mixes package and runtime versions, preserves null dependency versions and discloses installed versions', async () => {
  const h = platformFixture(path => path.endsWith('/system') ? { ...systemCatalog, rebootRequired: true, packages: [{ name: 'libcurl', currentVersion: null, targetVersion: '2' }] } : catalog);
  await tick();
  const rows = h.node('[data-platform-updates-list]').children;
  assert.equal(rows.length, 2); assert.equal(rows[0].children[1].textContent, 'libcurl'); assert.equal(rows[0].children[2].textContent, 'Nuova dipendenza'); assert.equal(rows[1].children[1].textContent, 'PHP');
  assert.equal(h.node('[data-platform-updates-installed-list]').children[0].children[2].textContent, '8.5.11');
  assert.equal(h.node('[data-platform-updates-reboot]').hidden, false);
});
test('invalid fresh combined plans never submit any update', async () => {
  const h = platformFixture(path => path.endsWith('/plan') ? { kind: 'batch', planId: 'invalid', revision: 'revision', confirmationRequired: 'UPDATE', expiresAt: new Date(Date.now() + 60000).toISOString(), components: [] } : path.endsWith('/system') ? systemCatalog : catalog);
  await tick(); await h.node('[data-platform-updates-upgrade]').listeners.click();
  assert.equal(h.calls.filter(call => call === 'authenticate').length, 1);
  assert.equal(h.calls.some(call => call.path?.endsWith('/apply')), false);
  assert.match(h.node('[data-platform-updates-status]').textContent, /Piano di aggiornamento non valido/);
  assert.equal(h.node('[data-platform-updates-dialog]').open, false);
});
test('navigation disconnect ignores late catalogs and cancels polling', async () => {
  let resolve; const h = platformFixture(() => new Promise(done => { resolve = done; }));
  h.root.isConnected = false; h.scan(); resolve(catalog); await tick();
  assert.equal(h.node('[data-platform-updates-list]').children.length, 0); assert.equal(h.timers.size, 0);
});
test('interrupted recovery blocks both global controls without polling a terminal job', async () => {
  const operation = { id: 'interrupted', status: 'interrupted', recoveryRequired: true, stage: 'Verifica amministrativa', completedSteps: 1, totalSteps: 2 };
  const h = platformFixture(path => path.endsWith('/system') ? systemCatalog : { ...catalog, canCheck: false, canApply: false, operations: [operation] }); await tick();
  assert.match(h.node('[data-platform-updates-status]').textContent, /Verifica amministrativa richiesta/);
  assert.equal(h.node('[data-platform-updates-check]').disabled, true); assert.equal(h.node('[data-platform-updates-upgrade]').disabled, true);
  assert.equal(h.calls.some(call => call.path?.includes('/operations/')), false);
});
test('operation reconnect preserves accepted IDs and full progress waits for both terminal successes', async () => {
  let reconnect = true, finished = false;
  const operation = id => ({ id, status: finished ? 'succeeded' : 'running', stage: 'Verifica finale', completedSteps: 2, totalSteps: 2 });
  const h = platformFixture(path => { if (path.includes('/operations/')) { if (reconnect) throw Error('Failed to fetch'); return operation(path.split('/').pop()); } return path.endsWith('/system') ? { ...systemCatalog, operations: [operation('host')] } : { ...catalog, operations: [operation('services')] }; });
  await tick(); await poll(h); assert.match(h.node('[data-platform-updates-status]').textContent, /Riconnessione automatica/);
  assert.equal(h.calls.filter(call => call.path === '/control/runtime-updates/system').length, 1);
  assert.notEqual(h.node('progress').value, 2); reconnect = false; finished = true; await poll(h);
  assert.equal(h.node('progress').value, 2); assert.equal(h.node('progress').max, 2);
});
test('reboot retains a distinct reviewed REBOOT confirmation and never starts on mount', async () => {
  const plan = { planId: 'reboot-plan', revision: 'system-revision', kind: 'host-reboot', confirmationRequired: 'REBOOT', expiresAt: new Date(Date.now() + 60000).toISOString() };
  const h = platformFixture(path => path.endsWith('/reboot/plan') ? plan : path.endsWith('/reboot/apply') ? { operationId: 'reboot', status: 'queued' } : path.endsWith('/system') ? { ...systemCatalog, rebootRequired: true, canReboot: true } : catalog);
  await tick(); assert.equal(h.calls.some(call => call.path?.includes('/reboot/')), false);
  await h.node('[data-platform-updates-reboot]').listeners.click();
  h.node('[data-platform-updates-confirm]').value = 'UPDATE'; h.node('[data-platform-updates-confirm]').listeners.input(); assert.equal(h.node('[data-platform-updates-apply]').disabled, true);
  h.node('[data-platform-updates-confirm]').value = 'REBOOT'; h.node('[data-platform-updates-confirm]').listeners.input(); await h.node('[data-platform-updates-apply]').listeners.click();
  assert.equal(h.calls.find(call => call.path?.endsWith('/reboot/apply')).payload.confirmation, 'REBOOT');
  assert.equal(h.node('[data-platform-updates-dialog]').open, false);
});
test('installed versions disclosure animates only when motion is allowed', async () => {
  for (const motion of [false, true]) {
    const h = fixture(path => path.endsWith('/system') ? systemCatalog : catalog, { motion }); await tick();
    const disclosure = h.node('[data-platform-updates-installed]'); h.node('[data-platform-updates-installed-list]').animate = frames => { h.animations.push(frames); return { finished: Promise.resolve(), cancel() {} }; }; disclosure.open = true; const before = h.animations.length; disclosure.listeners.toggle.call(disclosure);
    assert.equal(h.animations.length > before, motion);
  }
  const css = readFileSync(new URL('../styles/runtime-updates.css', import.meta.url), 'utf8');
  assert.match(css, /transition:transform 400ms/); assert.match(css, /prefers-reduced-motion:reduce\)\{\.cc-progress-fill\{transition:none/);
});
test('compatible candidates stay distinct from newer majors and mixed installed versions stay readable', async () => {
  const h = platformFixture(path => path.endsWith('/system') ? { ...systemCatalog, updateCount: 0 } : { ...catalog, components: [{ ...component, latestStable: { version: '9.0.0' }, needsAlignment: true, current: { versions: ['8.5.10', '8.5.11'] } }, { ...component, id: 'unsupported', status: 'unsupported', canUpdate: false }] }); await tick();
  const rows = h.node('[data-platform-updates-list]').children; assert.equal(rows.length, 1);
  assert.equal(rows[0].children[2].textContent, 'Da uniformare: 8.5.10 / 8.5.11'); assert.equal(rows[0].children[4].textContent, '8.5.12');
});

test('active progress is flat with individual services and one package operation row', async () => {
  const operation = { id: 'services', status: 'running', stage: 'Verifica', serviceResults: [{ service: 'app-one', status: 'verified', stage: 'HTTP verificato' }, { service: 'app-two', status: 'updating', stage: 'Avvio' }] };
  const h = platformFixture(path => path.endsWith('/system') ? { ...systemCatalog, operations: [{ id: 'host', status: 'running', stage: 'APT' }] } : { ...catalog, operations: [operation] }); await tick();
  const rows = h.node('[data-platform-updates-results]').children;
  assert.equal(rows.length, 3); assert.deepEqual(rows.map(row => row.children[0].textContent), ['Pacchetti del server', 'app-one', 'app-two']);
});

test('initial skeleton reserves real row, toolbar count and disclosure geometry with no spinner', async () => {
  const html = renderRuntimeUpdates();
  assert.equal((html.match(/cc-platform-version-row cc-update-skeleton/g) || []).length, 3);
  assert.match(html, /data-loading="true" aria-busy="true"/);
  assert.match(html, /cc-update-count cc-skeleton-block/); assert.match(html, /cc-update-installed-count cc-skeleton-block/);
  assert.doesNotMatch(html, /spinner|Caricamento aggiornamenti/);
  const h = platformFixture(path => path.endsWith('/system') ? systemCatalog : catalog); await tick();
  assert.equal(h.root.attributes['data-loading'], 'false'); assert.equal(h.node('[data-platform-updates-summary]').textContent, '2 disponibili');
  assert.equal(h.node('[data-platform-updates-installed-count]').textContent, '1');
});
test('idle polling preserves row identity, disclosure and focus without replaying entry animations', async () => {
  const h = fixture(path => path.endsWith('/system') ? systemCatalog : catalog, { motion: true }); await tick();
  const list = h.node('[data-platform-updates-list]'), installed = h.node('[data-platform-updates-installed-list]'), row = list.children[0], installedRow = installed.children[0];
  const disclosure = h.node('[data-platform-updates-installed]'); disclosure.open = true; row.focused = true;
  const animations = h.animations.length; await poll(h);
  assert.equal(list.children[0], row); assert.equal(installed.children[0], installedRow); assert.equal(row.focused, true); assert.equal(disclosure.open, true); assert.equal(h.animations.length, animations);
});
test('service progress updates its existing row while retaining the individual service name', async () => {
  let stage = 'Avvio';
  const value = () => ({ id: 'op', status: 'running', stage, serviceResults: [{ service: 'app', status: 'updating', stage }] });
  const h = platformFixture(path => path.includes('/operations/') ? value() : path.endsWith('/system') ? systemCatalog : { ...catalog, operations: [value()] }); await tick();
  const row = h.node('[data-platform-updates-results]').children[0]; stage = 'Verifica HTTP'; await poll(h);
  assert.equal(h.node('[data-platform-updates-results]').children[0], row); assert.equal(row.children[0].textContent, 'app'); assert.equal(row.children[2].textContent, 'Verifica HTTP');
});
test('installed services use equal responsive columns while candidate updates remain a flat list', () => {
  const css = readFileSync(new URL('../styles/runtime-updates.css', import.meta.url), 'utf8');
  assert.match(css, /\[data-platform-updates-installed-list\]\{grid-template-columns:repeat\(3,minmax\(0,1fr\)\)\}/);
  assert.match(css, /@container cc-updates \(max-width:860px\)\{\[data-platform-updates-installed-list\]\{grid-template-columns:repeat\(2,minmax\(0,1fr\)\)\}\}/);
  assert.match(css, /@container cc-updates \(max-width:540px\)\{\[data-platform-updates-installed-list\]\{grid-template-columns:minmax\(0,1fr\)\}\}/);
  assert.doesNotMatch(css, /\[data-platform-updates-list\]\{grid-template-columns:repeat/);
});

test('host-only update requests required reboot without coordination and reconnects without another passkey', async () => {
  let accepted = false, offline = true, completed = false;
  const plan = { planId: 'host-auto', revision: 'system-revision', kind: 'host-upgrade', confirmationRequired: 'UPDATE_AND_REBOOT', rebootAfter: true, expiresAt: new Date(Date.now() + 60000).toISOString() };
  const operation = () => ({ id: 'host-auto', status: completed ? 'succeeded' : 'running', stage: completed ? 'Riavvio verificato' : 'Riavvio automatico' });
  const h = platformFixture(path => {
    if (path.endsWith('/system/plan')) return plan;
    if (path.endsWith('/system/apply')) { accepted = true; return { operationId: 'host-auto', status: 'queued' }; }
    if (path.includes('/operations/')) { if (offline) throw Error('Offline'); return operation(); }
    return path.endsWith('/system') ? { ...systemCatalog, operations: accepted ? [operation()] : [] } : { ...catalog, components: [] };
  });
  await tick(); await h.node('[data-platform-updates-upgrade]').listeners.click();
  const request = h.calls.find(call => call.path?.endsWith('/system/plan'));
  assert.equal(request.payload.rebootAfter, true); assert.equal(request.payload.coordinatedReboot, undefined);
  assert.match(h.node('[data-platform-updates-results]').children[0].children[2].textContent, /Riavvio automatico se necessario/);
  await poll(h); assert.match(h.node('[data-platform-updates-status]').textContent, /Riconnessione automatica/);
  assert.equal(h.node('[data-platform-updates-upgrade]').disabled, true);
  offline = false; completed = true; await poll(h);
  assert.equal(h.node('progress').value, 1);
  assert.equal(h.calls.filter(call => call === 'authenticate').length, 1);
  assert.equal(h.calls.filter(call => call.path?.endsWith('/apply')).length, 1);
  assert.equal(h.node('[data-platform-updates-dialog]').open, false);
});

test('update all rejects a host plan that omits coordinated reboot consent', async () => {
  const expiresAt = new Date(Date.now() + 60000).toISOString();
  const h = platformFixture(path => path.endsWith('/system/plan') ? { planId: 'host', revision: 'system-revision', kind: 'host-upgrade', confirmationRequired: 'UPDATE_AND_REBOOT', rebootAfter: true, expiresAt } : path.endsWith('/all/plan') ? { planId: 'services', revision: 'revision', kind: 'batch', confirmationRequired: 'UPDATE', expiresAt, components: [component], targetVersion: '2', targetDigest: 'sha256:test' } : path.endsWith('/system') ? systemCatalog : catalog);
  await tick(); await h.node('[data-platform-updates-upgrade]').listeners.click();
  assert.equal(h.calls.some(call => call.path?.endsWith('/apply')), false);
  assert.match(h.node('[data-platform-updates-status]').textContent, /Piano di aggiornamento non valido/);
});
