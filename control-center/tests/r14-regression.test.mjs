import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('passkey form action is accepted by the submit handler', () => {
  const script = readFileSync(new URL('../styles/control-center.js', import.meta.url), 'utf8');
  const allowed = script.match(/var allowedActions = new Set\((\[[^\]]+\])\);/);
  assert.ok(allowed, 'submitPasskeyForm allowlist missing');
  assert.ok(JSON.parse(allowed[1]).includes('/actions/project-remove-from-list'));
  assert.match(script, /if \(!action \|\| !allowedActions\.has\(action\.pathname\)\) return false/);
});
