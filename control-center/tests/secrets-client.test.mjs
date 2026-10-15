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

function motionFixture({ reduced = false } = {}) {
  const animations = [], listeners = {}, focus = [];
  const createAnimation = (frames, options) => {
    const finished = deferred();
    const animation = { frames, options, finished: finished.promise, finish: finished.resolve, cancelled: false, cancel() { this.cancelled = true; finished.reject(new Error('Animation replaced')); } };
    animations.push(animation); return animation;
  };
  const fields = { create: { value: '' }, edit: { value: '' }, delete: { value: '' } }, statuses = {};
  const forms = Object.fromEntries(Object.keys(fields).map(mode => {
    statuses[mode] = { textContent: '', removeAttribute() {} };
    return [mode, { hidden: true, resets: 0, elements: { itemId: {}, id: {}, confirm: {} }, reset() { this.resets++; fields[mode].value = ''; }, querySelector(selector) { return selector === '[data-secret-form-status]' ? statuses[mode] : { focus: () => focus.push(mode) }; } }];
  }));
  const editor = { hidden: true, animate: createAnimation, contains: () => false, querySelector: selector => forms[selector.match(/data-secret-(\w+)-form/)[1]] };
  const root = { isConnected: true, dataset: {}, querySelector: selector => selector === '[data-secret-editor]' ? editor : { textContent: '' }, querySelectorAll: selector => selector === '[data-secret-editor] form' ? Object.values(forms) : [] };
  const context = { document: { readyState: 'loading', addEventListener: (name, callback) => { listeners[name] = callback; }, querySelector: () => root }, window: { matchMedia: () => ({ matches: reduced }), getComputedStyle: () => ({ opacity: '.7', transform: 'matrix(1,0,0,1,4,0)' }) } };
  vm.createContext(context);
  vm.runInContext(editorSource.replace(/\}\)\(\);\s*$/, 'globalThis.secretMotion = { animate, filter, open, close };})();'), context);
  const trigger = { isConnected: true, closest: () => null, focus: () => focus.push('trigger') };
  return { context, motion: context.secretMotion, animations, root, editor, forms, fields, trigger, focus, createAnimation };
}

test('rapid editor open-close-open cancels superseded motion without hiding or clearing the new draft', async () => {
  const h = motionFixture();
  h.motion.open(h.root, 'create', h.trigger);
  h.motion.close(h.root);
  h.motion.open(h.root, 'edit', h.trigger);
  h.fields.edit.value = 'public-in-progress-draft';
  await tick();
  assert.equal(h.animations.length, 3);
  assert.equal(h.animations[0].cancelled, true, 'Opening animation is tracked and cancelled on close');
  assert.equal(h.animations[1].cancelled, true, 'Stale close is cancelled by the new editor');
  assert.equal(h.editor.hidden, false);
  assert.equal(h.forms.edit.hidden, false);
  assert.equal(h.fields.edit.value, 'public-in-progress-draft');
  assert.equal(h.root.dataset.editorOpen, 'true');
  assert.equal(h.focus.at(-1), 'edit', 'Stale closing callback cannot steal focus');
  assert.equal(h.animations[2].frames[0].opacity, '.7', 'Interrupted motion continues from its visible state');
});

test('editor close restores focus only after completion and ignores a detached page', async () => {
  for (const detached of [false, true]) {
    const h = motionFixture();
    h.motion.open(h.root, 'create', h.trigger);
    h.motion.close(h.root);
    assert.equal(h.editor.hidden, false);
    if (detached) h.root.isConnected = false;
    h.animations.at(-1).finish(); await tick();
    assert.equal(h.editor.hidden, !detached);
    assert.equal(h.focus.includes('trigger'), !detached);
  }
});

test('finishing a closing animation cannot steal focus from a newly selected control', async () => {
  const h = motionFixture();
  h.motion.open(h.root, 'create', h.trigger);
  h.motion.close(h.root);
  h.context.document.activeElement = { id: 'another-navigation-control' };
  h.animations.at(-1).finish(); await tick();
  assert.equal(h.editor.hidden, true);
  assert.equal(h.focus.includes('trigger'), false);
});

test('reduced motion keeps editor controls immediate with no animation or deferred focus', () => {
  const h = motionFixture({ reduced: true });
  h.motion.open(h.root, 'create', h.trigger);
  assert.equal(h.editor.hidden, false);
  h.motion.close(h.root);
  assert.equal(h.animations.length, 0);
  assert.equal(h.editor.hidden, true);
  assert.equal(h.focus.at(-1), 'trigger');
});

test('search motion follows real visibility and repositions retained rows without a second list fade', () => {
  const h = motionFixture();
  const rows = ['alpha', 'beta'].map(name => ({ dataset: { secretSearch: name, secretLinked: 'false' }, hidden: false, animate: h.createAnimation, getBoundingClientRect() { return { top: rows.indexOf(this) === 0 ? 0 : rows[0].hidden ? 0 : 100 }; } }));
  const search = { value: 'beta' }, empty = {}, count = {};
  const root = { querySelector: selector => ({ '[data-secret-search]': search, '[data-secret-filter][aria-pressed="true"]': { dataset: { secretFilter: 'all' } }, '[data-secret-empty]': empty, '[data-secret-visible-count]': count })[selector], querySelectorAll: () => rows };
  h.motion.filter(root);
  assert.equal(rows[0].hidden, true);
  assert.equal(rows[1].hidden, false);
  assert.equal(count.textContent, '1 di 2 elementi');
  assert.equal(h.animations.length, 1);
  assert.equal(h.animations[0].frames[0].transform, 'translateY(100px)');
  search.value = '';
  h.motion.filter(root);
  assert.equal(rows.every(row => !row.hidden), true);
  assert.equal(h.animations[0].cancelled, true, 'Rapid search replaces the retained-row movement');
  assert.equal(h.animations.length, 3, 'Only the entering and repositioned rows animate');
});

test('cached route transitions replace only their own motion, respect reduced motion and focus the heading', async () => {
  const h = motionFixture();
  let reduced = false, focused;
  const heading = { tagName: 'H1', focus: options => { focused = options; } }, page = { animate: h.createAnimation };
  const context = { document: { querySelector: selector => selector === '.ops-page h1' ? heading : page }, window: { matchMedia: () => ({ matches: reduced }) } };
  vm.createContext(context);
  vm.runInContext(section('  function restoreNavigationFocus()', '  function setText('), context);
  context.restoreNavigationFocus();
  assert.equal(heading.tabIndex, -1);
  assert.equal(focused.preventScroll, true);
  context.animatePortalPage(); context.animatePortalPage();
  assert.equal(h.animations[0].cancelled, true);
  assert.equal(h.animations[1].id, 'cc-route-enter');
  reduced = true; context.animatePortalPage();
  assert.equal(h.animations[1].cancelled, true);
  assert.equal(h.animations.length, 2);
  await tick();
  assert.match(source, /fitSingleLineText\(\);\s*animatePortalPage\(\)/, 'Initial render uses the same entrance as cached navigation');
});

test('Applications local filtering preserves groups and replaces row movement without fetching', () => {
  for (const reduced of [false, true]) {
    const h = motionFixture(), search = { value: 'beta' }, empty = {};
    const rows = ['alpha', 'beta'].map(name => ({ dataset: { applicationSearch: name }, hidden: false, animate: h.createAnimation, getBoundingClientRect() { return { top: rows.indexOf(this) === 0 ? 0 : rows[0].hidden ? 0 : 80 }; } }));
    const groups = rows.map(row => ({ hidden: false, querySelector: () => row.hidden ? null : row }));
    const root = { querySelector: selector => selector === '[data-application-search-input]' ? search : empty, querySelectorAll: selector => selector === '[data-application-row]' ? rows : groups };
    const context = { document: {}, window: { matchMedia: () => ({ matches: reduced }) } };
    vm.createContext(context);
    vm.runInContext(section('  var portalMotions =', '  function setText(') + section('  function filterApplications(', '  function startFileManagers('), context);
    context.filterApplications(root);
    assert.equal(groups[0].hidden, true);
    assert.equal(groups[1].hidden, false);
    assert.equal(empty.hidden, true);
    search.value = ''; context.filterApplications(root);
    assert.ok(rows.every(row => !row.hidden));
    assert.ok(groups.every(group => !group.hidden));
    assert.equal(h.animations.length, reduced ? 0 : 3);
    if (!reduced) assert.equal(h.animations[0].cancelled, true);
  }
});

test('reduced-motion sidebar moves the existing pill immediately without a transition frame', () => {
  const pill = { style: {} }, nav = { dataset: {}, isConnected: true, querySelector: () => pill };
  let cancelled = 0;
  const context = { opsNavPillFrame: 7, usableOpsNavPillTarget: () => true, opsNavPixel: value => value + 'px', window: { matchMedia: () => ({ matches: true }), cancelAnimationFrame: () => { cancelled++; }, requestAnimationFrame: () => 1 } };
  vm.createContext(context);
  vm.runInContext(section('  function opsNavPillRectToTarget(', '  function positionOpsNavPill('), context);
  assert.equal(context.applyOpsNavPill(nav, { left: 4, top: 20, width: 200, height: 44 }, {}), true);
  assert.equal(cancelled, 1);
  assert.equal(nav.dataset.navPillInstant, 'true');
  assert.equal(pill.style.transform, 'translate3d(4px, 20px, 0)');
  assert.equal(pill.style.width, '200px');
});
