import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { renderServerEvents } from '../events/ui.mjs';
const source = readFileSync(new URL('../styles/server-events.js', import.meta.url), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));
class Node {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.attributes = {}; this.listeners = {}; this.hidden = false; this.disabled = false; this.parentNode = null; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children.forEach(node => { node.parentNode = null; }); this.children = []; }
  get textContent() { return this._text + this.children.map(node => node.textContent).join(' '); }
  append(...nodes) { for (const node of nodes) this.insertBefore(node, null); }
  insertBefore(node, before) { node.remove(); const index = before ? this.children.indexOf(before) : this.children.length; this.children.splice(index, 0, node); node.parentNode = this; }
  remove() { if (this.parentNode) { const nodes = this.parentNode.children; nodes.splice(nodes.indexOf(this), 1); this.parentNode = null; } }
  addEventListener(type, callback) { this.listeners[type] = callback; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name] ?? null; }
}
function fixture(request, hidden = false) {
  const root = new Node(), nodes = new Map(), calls = [], timers = new Map(), documentListeners = {}, windowListeners = {}; let timer = 0, scan;
  root.isConnected = true;
  const buttons = ['active', 'recent'].map(view => { const button = new Node('button'); button.setAttribute('data-events-view', view); return button; });
  root.querySelector = selector => { if (!nodes.has(selector)) nodes.set(selector, new Node()); return nodes.get(selector); };
  root.querySelectorAll = selector => selector === '[data-events-view]' ? buttons : [];
  const document = { readyState: 'complete', hidden, body: {}, createElement: tag => new Node(tag), querySelectorAll: selector => selector === '[data-server-events]' && root.isConnected ? [root] : [], addEventListener: (type, callback) => { documentListeners[type] = callback; } };
  const context = { document, Date, Set, WeakSet, Map, Number, String, Array, Object, Promise, clearTimeout: id => timers.delete(id), setTimeout: (callback, delay) => { const id = ++timer; timers.set(id, { callback: () => { timers.delete(id); return callback(); }, delay }); return id; } };
  context.window = { MutationObserver: true, addEventListener: (type, callback) => { windowListeners[type] = callback; }, controlCenterRuntimeUpdates: { request: async (path, payload) => { calls.push({ path, payload }); return request(path, payload); } } };
  context.MutationObserver = class { constructor(callback) { scan = callback; } observe() {} };
  vm.runInNewContext(source, context);
  return { root, calls, timers, document, buttons, node: name => root.querySelector('[data-events-' + name + ']'), scan: () => scan(), visibility: value => { document.hidden = value; documentListeners.visibilitychange(); }, dispose: () => windowListeners.pagehide() };
}
const event = { id: 'docker:db-health', severity: 'error', source: 'docker', service: 'database', message: 'Il servizio non risponde.', count: 3, firstSeen: '2026-10-26T12:00:00Z', lastSeen: '2026-10-26T12:10:00Z', active: true };
const feed = { schema: 'server-events/v1', available: true, partial: false, checkedAt: '2026-10-26T12:10:00Z', issues: [event], events: [event], sources: ['host', 'systemd', 'docker', 'updates'].map(id => ({ id, available: true })) };

test('markup is read-only, accessible, uses vendored icons and a full-width rounded panel', () => {
  const html = renderServerEvents();
  const css = readFileSync(new URL('../styles/server-events.css', import.meta.url), 'utf8');
  assert.match(html, /data-server-events/); assert.match(html, /aria-live="polite"/); assert.match(html, /aria-pressed="true"/); assert.match(html, /data-fa-version="7\.3\.1"/);
  assert.match(css, /width:100%;min-width:0;border-radius:var\(--cc-radius-2xl,16px\)/);
  assert.match(css, /prefers-reduced-motion:reduce/);
  assert.doesNotMatch(html, /Ripara|Risolvi|data-events-apply|data-events-export/);
  assert.doesNotMatch(source, /innerHTML|outerHTML|insertAdjacentHTML|authenticate\(/);
});

test('active issue counts deduplicate records and keep occurrence totals instead of summing duplicates', async () => {
  const h = fixture(() => ({ ...feed, issues: [event, { ...event, count: 5, lastSeen: '2026-10-26T12:11:00Z' }] }));
  await tick();
  assert.equal(h.node('errors').textContent, '1'); assert.equal(h.node('warnings').textContent, '0');
  assert.equal(h.node('list').children.length, 1);
  assert.match(h.node('list').textContent, /5 occorrenze/);
  assert.equal(h.root.getAttribute('data-feed-state'), 'complete');
});

test('recent view distinguishes historical entries without claiming they are resolved', async () => {
  const h = fixture(() => ({ ...feed, events: [{ ...event, id: 'recovered', active: false, severity: 'warning', message: 'Avviso registrato nel giornale del sistema.' }] }));
  await tick(); h.buttons[1].listeners.click();
  assert.equal(h.buttons[1].getAttribute('aria-pressed'), 'true');
  assert.match(h.node('list').textContent, /Storico/); assert.doesNotMatch(h.node('list').textContent, /Attivo/);
  assert.match(h.node('description').textContent, /non conferma.*presente o risolto/i);
  assert.doesNotMatch(h.node('list').textContent, /Rientrato|Risolto/);
  assert.equal(h.node('errors').textContent, '1', 'counters still describe active issues');
  h.buttons[0].listeners.click(); assert.match(h.node('list').textContent, /Attivo/);
});

test('only a complete feed can state there are no active problems', async () => {
  const complete = fixture(() => ({ ...feed, issues: [], events: [] }));
  await tick(); assert.match(complete.node('empty').textContent, /Nessun problema attivo/);
  const partial = fixture(() => ({ ...feed, partial: true, issues: [], events: [], sources: [{ id: 'docker', available: false, reason: 'secret raw diagnostic must not render' }] }));
  await tick(); assert.match(partial.node('status').textContent, /parziale/); assert.match(partial.node('empty').textContent, /non è confermato/);
  assert.doesNotMatch(partial.node('status').textContent, /Nessun errore/); assert.doesNotMatch(partial.node('sources').textContent, /secret/);
  assert.equal(partial.root.getAttribute('data-feed-state'), 'partial');
});

test('unavailable sources and malformed records never produce an all-clear', async () => {
  for (const value of [{ ...feed, available: false, issues: [], events: [] }, { ...feed, sources: [{ id: 'host', available: false }], issues: [], events: [] }, { ...feed, issues: [{ ...event, severity: 'unknown' }], events: [] }, { ...feed, sources: [], issues: [], events: [] }, { ...feed, sources: [null], issues: [], events: [] }]) {
    const h = fixture(() => value); await tick();
    assert.notEqual(h.root.getAttribute('data-feed-state'), 'complete');
    assert.doesNotMatch(h.node('empty').textContent, /Nessun problema attivo/);
  }
});

test('journal warnings remain visible as a supported source', async () => {
  const h = fixture(() => ({ ...feed, issues: [{ ...event, id: 'journal-warning', severity: 'warning', source: 'journal' }], sources: [{ id: 'journal', available: true }] }));
  await tick(); assert.equal(h.node('warnings').textContent, '1');
  assert.equal(h.root.getAttribute('data-feed-state'), 'complete');
  assert.match(h.node('list').textContent, /Registro di sistema/);
});

test('transport failure retains cached issues with an explicit stale-data state', async () => {
  let failed = false;
  const h = fixture(() => { if (failed) throw Error('credential-bearing network diagnostic'); return feed; });
  await tick(); const row = h.node('list').children[0]; failed = true;
  await h.node('refresh').listeners.click(); await tick();
  assert.equal(h.node('list').children[0], row);
  assert.equal(h.root.getAttribute('data-feed-state'), 'unavailable');
  assert.match(h.node('status').textContent, /ultimi dati ricevuti/); assert.doesNotMatch(h.node('status').textContent, /credential/);
});

test('untrusted messages are literal bounded text and unrelated fields never render', async () => {
  const attack = '<img src=x onerror=alert(1)>';
  const h = fixture(() => ({ ...feed, issues: [{ ...event, message: attack + 'x'.repeat(2000), raw: 'private credential', stack: 'secret stack' }] }));
  await tick(); const row = h.node('list').children[0], message = row.children[2];
  assert.equal(message.children.length, 0); assert.equal(message.textContent.length, 1600); assert.ok(message.textContent.startsWith(attack));
  assert.doesNotMatch(row.textContent, /private credential|secret stack/);
});

test('a quiet unchanged poll preserves keyed nodes and only reads at fifteen seconds while visible', async () => {
  const h = fixture(() => feed); await tick(); const row = h.node('list').children[0];
  assert.deepEqual([...h.timers.values()].map(timer => timer.delay), [15000]);
  await [...h.timers.values()][0].callback(); await tick();
  assert.equal(h.node('list').children[0], row);
  assert.ok(h.calls.every(call => call.path === '/control/server-events' && call.payload === undefined));
  h.visibility(true); assert.equal(h.timers.size, 0); const count = h.calls.length;
  await h.node('refresh').listeners.click(); await tick(); assert.equal(h.calls.length, count);
  h.visibility(false); await tick(); assert.equal(h.calls.length, count + 1);
  h.dispose(); assert.equal(h.timers.size, 0);
});

test('initially hidden pages do not request logs and navigation ignores late responses', async () => {
  const hidden = fixture(() => feed, true); await tick(); assert.equal(hidden.calls.length, 0);
  hidden.visibility(false); await tick(); assert.equal(hidden.calls.length, 1);
  let finish; const h = fixture(() => new Promise(resolve => { finish = resolve; }));
  h.root.isConnected = false; h.scan(); finish(feed); await tick();
  assert.equal(h.node('list').children.length, 0); assert.equal(h.timers.size, 0);
});
