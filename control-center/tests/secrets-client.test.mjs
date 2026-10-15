import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../styles/control-center.js', import.meta.url), 'utf8');
const editorSource = readFileSync(new URL('../styles/secrets.js', import.meta.url), 'utf8');
const section = (start, end) => {
  const begin = source.indexOf(start), finish = source.indexOf(end, begin);
  assert.ok(begin >= 0 && finish > begin, `Client section exists: ${start}`);
  return source.slice(begin, finish);
};
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const tick = () => new Promise(resolve => setImmediate(resolve));

function harness({ credential = async () => ({ toJSON: () => ({ id: 'fixture-assertion' }) }), reveal, management } = {}) {
  const calls = [], timers = new Map(), boxes = [], events = [], navigation = [];
  let timerId = 0;
  const document = { hidden: false, querySelectorAll: () => boxes, dispatchEvent: event => events.push(event) };
  const context = {
    document, Headers, URLSearchParams, URL, WeakMap, WeakSet, Error,
    window: { PublicKeyCredential: true, location: { href: 'http://fixture/?section=secrets' }, setTimeout: (callback, delay) => { const id = ++timerId; timers.set(id, { callback, delay }); return id; }, clearTimeout: id => timers.delete(id) },
    navigator: { credentials: { get: options => { calls.push({ kind: 'credential', options }); return credential(); } } },
    fetch: async (url, request) => {
      calls.push({ kind: 'fetch', url, request });
      if (url.endsWith('/options')) return { ok: true, json: async () => ({ options: { challenge: 'YQ', allowCredentials: [] } }) };
      if (url.endsWith('/verify')) return { ok: true, json: async () => ({ ok: true }) };
      return reveal ? reveal(url, request) : { ok: true, json: async () => ({ value: 'public-fixture-value', ttlMs: 90000 }) };
    },
    base64UrlToBuffer: value => value,
    serializePasskeyAssertion: value => value.toJSON(),
    addMutationHeaders: headers => headers.set('X-CSRF-Token', 'public-fixture-csrf'),
    showError: message => { throw new Error(message); },
    hostingRequest: async (url, payload) => { calls.push({ kind: 'management', url, payload }); return management?.(url, payload); },
    FormData: class { constructor(form) { this.form = form; } entries() { return Object.entries(this.form.payload); } },
    clearCache: () => calls.push({ kind: 'clearCache' }),
    navigate: async (...args) => navigation.push(args), currentPageScrollTop: () => 42,
    CustomEvent: class { constructor(type, options) { this.type = type; this.detail = options.detail; } },
  };
  vm.createContext(context);
  vm.runInContext('var passkeyActionInFlight = false; var formSubmissions = new WeakSet();\n' + section('  async function passkeyJsonRequest(', '  async function runPasskeyNavigation(') + section('  var vaultRevealStates =', '  async function copyVaultSecret(') + section('  async function submitVaultManagement(', '  async function submitVaultRuntime('), context);
  function row(id = 'fixture-item') {
    const input = { value: '', dataset: {}, tagName: 'TEXTAREA' }, copy = { disabled: true }, revealed = { hidden: true }, status = { textContent: '', hidden: true }, label = { textContent: 'Mostra' };
    const attrs = { 'data-vault-id': id, 'data-vault-confirm': `REVEAL-VAULT-SECRET:${id}`, 'aria-label': `Mostra valore ${id}` };
    const box = { isConnected: true, querySelector: selector => ({ '[data-vault-reveal-value]': input, '[data-vault-copy-action]': copy, '[data-secret-revealed]': revealed, '[data-secret-reveal-status]': status, '[data-vault-reveal-action]': button })[selector] };
    const button = { isConnected: true, disabled: false, closest: () => box, querySelector: () => label, getAttribute: key => attrs[key], setAttribute: (key, value) => { attrs[key] = value; }, hasAttribute: key => key in attrs, removeAttribute: key => { delete attrs[key]; } };
    boxes.push(box);
    return { input, copy, revealed, status, label, box, button, attrs };
  }
  return { context, calls, timers, document, row, events, navigation };
}

test('Mostra completes an explicit passkey assertion before fetching a value, then erases it within 30 seconds', async () => {
  const h = harness(), row = h.row();
  await h.context.revealVaultSecret(row.button);
  assert.deepEqual(h.calls.map(call => call.url || call.kind), ['/auth/passkey/login/options', 'credential', '/auth/passkey/login/verify', '/control/vault/secrets/fixture-item/reveal']);
  const request = h.calls.at(-1).request;
  assert.equal(request.method, 'POST');
  assert.equal(request.headers.get('X-CSRF-Token'), 'public-fixture-csrf');
  assert.equal(request.body.get('confirm'), 'REVEAL-VAULT-SECRET:fixture-item');
  assert.equal(row.input.value, 'public-fixture-value');
  assert.equal(row.copy.disabled, false);
  assert.equal(row.label.textContent, 'Nascondi');
  const timer = [...h.timers.values()][0];
  assert.equal(timer.delay, 30000, 'Server TTL cannot extend the client exposure window');
  timer.callback();
  assert.equal(row.input.value, '');
  assert.equal(row.revealed.hidden, true);
  assert.equal(row.copy.disabled, true);
  assert.equal(row.label.textContent, 'Mostra');
});

test('cancelled or aborted passkey prompts never fetch or reveal a value', async () => {
  for (const name of ['NotAllowedError', 'AbortError']) {
    const h = harness({ credential: async () => { throw Object.assign(new Error('fixture cancellation'), { name }); } }), row = h.row();
    await h.context.revealVaultSecret(row.button);
    assert.deepEqual(h.calls.filter(call => call.kind === 'fetch').map(call => call.url), ['/auth/passkey/login/options']);
    assert.equal(row.input.value, '');
    assert.match(row.status.textContent, /Autenticazione annullata/);
    assert.equal(row.button.disabled, false);
  }
});

test('concurrent Mostra clicks share one credential challenge, including different rows', async () => {
  const credential = deferred(), h = harness({ credential: () => credential.promise });
  const first = h.row('first'), second = h.row('second');
  const pending = h.context.revealVaultSecret(first.button);
  await tick();
  await h.context.revealVaultSecret(first.button);
  await h.context.revealVaultSecret(second.button);
  assert.equal(h.calls.filter(call => call.kind === 'credential').length, 1);
  credential.resolve({ toJSON: () => ({ id: 'fixture-assertion' }) });
  await pending;
  assert.equal(h.calls.filter(call => call.url?.endsWith('/reveal')).length, 1);
  assert.equal(second.input.value, '');
});

test('hiding or leaving the page during authentication prevents the reveal request', async () => {
  for (const invalidate of ['hide', 'hidden', 'disconnected']) {
    const credential = deferred(), h = harness({ credential: () => credential.promise }), row = h.row();
    const pending = h.context.revealVaultSecret(row.button);
    await tick();
    if (invalidate === 'hide') h.context.clearVaultReveals();
    if (invalidate === 'hidden') h.document.hidden = true;
    if (invalidate === 'disconnected') row.box.isConnected = false;
    credential.resolve({ toJSON: () => ({ id: 'fixture-assertion' }) });
    await pending;
    assert.equal(h.calls.some(call => call.url?.endsWith('/reveal')), false, invalidate);
    assert.equal(row.input.value, '', invalidate);
  }
});

test('late reveal responses cannot restore a value after hide, navigation or document hiding', async () => {
  for (const invalidate of ['hide', 'hidden', 'disconnected']) {
    const response = deferred(), h = harness({ reveal: () => response.promise }), row = h.row();
    const pending = h.context.revealVaultSecret(row.button);
    await tick();
    assert.ok(h.calls.some(call => call.url?.endsWith('/reveal')));
    if (invalidate === 'hide') h.context.clearVaultReveals();
    if (invalidate === 'hidden') h.document.hidden = true;
    if (invalidate === 'disconnected') row.box.isConnected = false;
    response.resolve({ ok: true, json: async () => ({ value: 'public-late-fixture-value' }) });
    await pending;
    assert.equal(row.input.value, '', invalidate);
    assert.equal(row.copy.disabled, true, invalidate);
    assert.equal(row.revealed.hidden, true, invalidate);
    assert.equal(h.timers.size, 0, invalidate);
  }
  assert.match(source, /async function navigate\([^]*?clearVaultReveals\(\)/);
  assert.match(source, /visibilitychange[^\n]*document\.hidden[^\n]*clearVaultReveals/);
  assert.match(source, /addEventListener\("pagehide", clearVaultReveals\)/);
});

test('pending Vault management prevents concurrent submissions and ignores callbacks after navigation', async () => {
  const response = deferred(), h = harness({ management: () => response.promise });
  const controls = [{ disabled: false, isConnected: true }, { disabled: true, isConnected: true }];
  const root = { dataset: {}, isConnected: true, querySelectorAll: () => controls }, field = { value: 'public-new-version' }, submit = { disabled: false, isConnected: true };
  const status = { textContent: '', removeAttribute: () => {} }, attrs = {};
  const form = { isConnected: true, elements: { action: { value: 'version' } }, payload: { action: 'version', itemId: 'fixture-item', newValue: field.value }, closest: () => root, querySelector: selector => selector === '[data-secret-form-status]' ? status : submit, querySelectorAll: () => [field], getAttribute: () => '/actions/vault-command', setAttribute: (key, value) => { attrs[key] = value; }, removeAttribute: key => { delete attrs[key]; } };
  const pending = h.context.submitVaultManagement(form);
  assert.equal(root.dataset.managementBusy, 'true');
  assert.equal(submit.disabled, true);
  assert.equal(attrs['aria-busy'], 'true');
  assert.equal(controls[0].disabled, true);
  assert.match(status.textContent, /Salvataggio in corso/);
  await h.context.submitVaultManagement(form);
  await h.context.submitVaultManagement({ ...form });
  assert.equal(h.calls.filter(call => call.kind === 'management').length, 1);
  form.isConnected = false; root.isConnected = false;
  response.resolve({}); await pending;
  assert.equal(field.value, 'public-new-version');
  assert.equal(h.navigation.length, 0);
  assert.equal(h.events.length, 0);
  assert.equal(root.dataset.managementBusy, undefined);
  assert.equal(attrs['aria-busy'], undefined);
  assert.equal(controls[0].disabled, false);
  assert.equal(controls[1].disabled, true, 'Previously disabled controls remain disabled');
});

test('the editor cannot switch or close while a management request is pending', () => {
  const listeners = {}, root = { dataset: { managementBusy: 'true', editorOpen: 'true' }, querySelector: () => { throw new Error('Pending editor must not be modified'); } };
  const context = { document: { readyState: 'loading', addEventListener: (name, callback) => { listeners[name] = callback; }, querySelector: () => root }, WeakMap, WeakSet };
  vm.runInNewContext(editorSource, context);
  for (const attribute of ['data-secret-create', 'data-secret-edit', 'data-secret-delete', 'data-secret-close']) {
    const button = { hasAttribute: value => value === attribute };
    listeners.click({ target: { closest: selector => selector === 'button' ? button : root } });
  }
  let prevented = false;
  listeners.keydown({ key: 'Escape', preventDefault: () => { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(root.dataset.editorOpen, 'true');
});
