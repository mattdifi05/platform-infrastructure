import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { renderRuntimeUpdates } from '../updates/ui.mjs';
const source = readFileSync(new URL('../styles/runtime-updates.js', import.meta.url), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));
class Node {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = {}; this.attributes = {}; this.value = ''; this.disabled = false; this.hidden = false; this.textContent = ''; this.open = false; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  addEventListener(type, callback) { this.listeners[type] = callback; }
  setAttribute(key, value) { this.attributes[key] = value; }
  removeAttribute(key) { delete this.attributes[key]; }
  get options() { return this.children; }
  showModal() { this.open = true; }
  close() { this.open = false; }
}
function fixture(request) {
  const nodes = new Map(), calls = [], timers = new Map(); let timer = 0, scan;
  const root = new Node(); root.isConnected = true;
  root.querySelector = selector => { if (!nodes.has(selector)) nodes.set(selector, new Node()); return nodes.get(selector); };
  root.querySelector('[data-updates-category]').value = 'all';
  root.querySelector('[data-updates-progress]').querySelector = () => root.querySelector('progress');
  const document = { readyState: 'complete', hidden: false, body: {}, createElement: tag => new Node(tag), querySelectorAll: () => root.isConnected ? [root] : [], addEventListener() {} };
  const context = { document, Headers, Date, Set, WeakSet, Number, Array, String, Error, encodeURIComponent, crypto: { randomUUID: () => 'fixture-uuid' }, clearTimeout: id => timers.delete(id), setTimeout: (callback, delay) => { timers.set(++timer, { callback, delay }); return timer; } };
  context.window = { addEventListener() {}, MutationObserver: class {} , controlCenterRuntimeUpdates: { authenticate: async () => calls.push('authenticate'), request: async (path, payload) => { calls.push({ path, payload }); return request(path, payload); } } };
  context.MutationObserver = class { constructor(callback) { scan = callback; } observe() {} };
  vm.runInNewContext(source, context);
  return { root, nodes, calls, timers, document, scan: () => scan(), node: selector => root.querySelector(selector), context };
}
const component = { id: 'php', label: 'PHP', category: 'Runtime', installed: true, current: { version: '8.5.11' }, latestStable: { version: '8.5.12', imageDigest: 'sha256:fixture' }, candidateRelease: { version: '8.5.12', imageDigest: 'sha256:fixture' }, status: 'update-available', canUpdate: true, services: ['php-apache'] };
const catalog = { available: true, revision: 'revision', components: [component], operations: [] };
test('settings markup has accessible update controls and uses existing vendored icons', () => {
  const html = renderRuntimeUpdates();
  assert.match(html, /data-runtime-updates/); assert.match(html, /<dialog/); assert.match(html, /aria-live="polite"/); assert.match(html, /data-fa-version="7.3.1"/); assert.doesNotMatch(html, /Installa componente|https:\/\//);
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
test('closing a plan before passkey returns prevents the plan request and apply', async () => {
  const h = fixture(() => catalog); await tick();
  let finish; h.context.window.controlCenterRuntimeUpdates.authenticate = () => new Promise(resolve => { finish = resolve; });
  const button = h.node('[data-updates-list]').children[0].children.find(node => node.tagName === 'button');
  button.listeners.click(); h.node('[data-updates-close]').listeners.click(); finish(); await tick();
  assert.equal(h.calls.some(call => call.path?.endsWith('/plan')), false); assert.equal(h.node('[data-updates-apply]').disabled, true);
});
test('unavailable, missing and unsupported components cannot start an update', async () => {
  const h = fixture(() => ({ ...catalog, components: ['unavailable', 'not-installed', 'unsupported'].map(status => ({ ...component, status, blockedReason: 'Migrazione richiesta' })) }));
  await tick();
  assert.equal(h.node('[data-updates-list]').children.length, 3);
  for (const row of h.node('[data-updates-list]').children) assert.equal(row.children.find(node => node.tagName === 'button').disabled, true);
});
test('compatible candidate is separate from a newer major and apply requires a fresh reviewed plan', async () => {
  const plan = { planId: 'p1', revision: 'revision', expiresAt: new Date(Date.now() + 60000).toISOString(), targetVersion: '8.5.12', targetDigest: 'sha256:fixture', affectedServices: ['php-apache'], steps: ['Scarica', 'Verifica'], risks: ['Riavvio breve'], confirmationRequired: 'UPDATE' };
  const h = fixture(path => path.endsWith('/plan') ? plan : path.endsWith('/apply') ? { operationId: 'apply1', status: 'queued' } : { ...catalog, components: [{ ...component, latestStable: { version: '9.0.1' } }] });
  await tick(); const row = h.node('[data-updates-list]').children[0];
  assert.ok(row.children.some(node => node.textContent.includes('Aggiornamento compatibile: 8.5.12')));
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
