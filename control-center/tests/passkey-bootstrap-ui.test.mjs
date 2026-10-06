import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
const source = fs.readFileSync(new URL('../server.mjs', import.meta.url), 'utf8');
const begin = source.indexOf('const APP_PASSKEY_REGISTRATION_SCRIPT =');
const end = source.indexOf('\nconst APP_PASSKEY_LOGIN_SCRIPT', begin);
const script = new Function(source.slice(begin, end) + ';return APP_PASSKEY_REGISTRATION_SCRIPT;')();
const renderBegin = source.indexOf('function renderAppPasskeyFirstConfiguration(state)');
const renderEnd = source.indexOf('\nfunction renderAppPasskeyLogin(', renderBegin);
const render = env => new Function('process', 'controlCenterStylesheetLinks', 'APP_PASSKEY_REGISTRATION_SCRIPT', source.slice(renderBegin, renderEnd) + ';return renderAppPasskeyFirstConfiguration({});')({ env }, () => '', script);

test('bootstrap field exists only for configured FILE gate, with no credential or path in HTML', () => {
  assert.doesNotMatch(render({}), /<input id="app-passkey-bootstrap-token"/);
  const html = render({ CONTROL_CENTER_FIRST_CONFIGURATION_TOKEN_FILE: '/protected/fixture-token.json' });
  assert.match(html, /id="app-passkey-bootstrap-token" type="password" autocomplete="off"/);
  assert.doesNotMatch(html, /\/protected\/fixture-token\.json|localStorage|sessionStorage/);
});

test('both registration POSTs carry transient token only in JSON and input clears after success or rejection', async () => {
  for (const fail of [false, true]) {
    let click;
    const input = { value: 'synthetic-bootstrap-fixture', reportValidity: () => true };
    const button = { addEventListener: (_name, callback) => { click = callback; } };
    const status = {};
    const calls = [];
    const options = { challenge: 'YQ', user: { id: 'Yg' }, excludeCredentials: [] };
    const context = {
      document: { getElementById: id => id === 'app-passkey-register' ? button : id === 'app-passkey-status' ? status : input },
      window: { PublicKeyCredential: true, location: { assign: () => {} } },
      navigator: { credentials: { create: async () => ({ toJSON: () => ({ id: 'synthetic-credential' }) }) } },
      fetch: async (url, request) => {
        calls.push({ url, request });
        return { ok: !fail, json: async () => fail ? { message: 'Rejected' } : url.endsWith('/options') ? { options } : { ok: true, redirect: '/' } };
      },
      Uint8Array, String, JSON, Error, atob, btoa,
    };
    vm.runInNewContext(script, context);
    await click();
    assert.equal(calls.length, fail ? 1 : 2);
    for (const { url, request } of calls) {
      assert.match(url, /^\/auth\/passkey\/register\/(options|verify)$/);
      assert.equal(request.method, 'POST');
      assert.equal(JSON.parse(request.body).bootstrapToken, 'synthetic-bootstrap-fixture');
      assert.doesNotMatch(JSON.stringify(request.headers), /synthetic-bootstrap/);
    }
    assert.equal(input.value, '');
    assert.doesNotMatch(status.textContent, /synthetic-bootstrap/);
  }
});
