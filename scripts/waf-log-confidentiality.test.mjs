import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const compose = fs.readFileSync(path.join(root, "compose.waf.yaml"), "utf8");
const promtail = fs.readFileSync(path.join(root, "promtail", "config.yml"), "utf8");

test("FG-021 WAF inspects bodies but audit output excludes all header/body parts", () => {
  assert.match(compose, /MODSEC_REQ_BODY_ACCESS: "On"/);
  assert.match(compose, /MODSEC_AUDIT_LOG_PARTS: "AKZ"/);
  assert.doesNotMatch(compose, /MODSEC_AUDIT_LOG_PARTS:\s*\$\{/);
  for (const name of [
    "waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf",
    "waf/REQUEST-900-VPS-RULES-BEFORE-CRS.conf",
  ]) {
    const rules = fs.readFileSync(path.join(root, name), "utf8");
    assert.match(rules, /sanitiseRequestHeader:Authorization/);
    assert.match(rules, /sanitiseRequestHeader:Cookie/);
    assert.match(rules, /sanitiseResponseHeader:Set-Cookie/);
  }
});

test("FG-021 Promtail fixture drops body/header events and redacts credential fields", () => {
  const dropSource = promtail.match(/- drop:\n\s+expression: '([^']+)'\n\s+drop_counter_reason: sensitive_http_material/)?.[1];
  const replaceMatch = promtail.match(/- replace:\n\s+expression: '([^']+)'\n\s+replace: '([^']+)'/);
  assert.ok(dropSource, "missing fail-closed sensitive HTTP material drop stage");
  assert.ok(replaceMatch, "missing credential replacement stage");
  const drop = compilePromtailExpression(dropSource);
  const replace = compilePromtailExpression(replaceMatch[1], true);
  const fixtures = [
    '{"transaction":{"request":{"body":"username=user&BODY_TOKEN=secret"}}}',
    'ModSecurity Authorization: Bearer AUTH_TOKEN',
    'ModSecurity Cookie: session=COOKIE_TOKEN',
    'ModSecurity Set-Cookie: session=SET_COOKIE_TOKEN; Secure',
    '{"event":"login","password":"JSON_TOKEN"}',
    '{"transaction":{"id":"safe-id","rules":[942100]}}',
  ];
  const shipped = fixtures
    .filter((line) => !drop.test(line))
    .map((line) => line.replace(replace, replaceMatch[2]));
  const lokiFixture = shipped.join("\n");
  for (const token of ["BODY_TOKEN", "AUTH_TOKEN", "COOKIE_TOKEN", "SET_COOKIE_TOKEN", "JSON_TOKEN"]) {
    assert.doesNotMatch(lokiFixture, new RegExp(token));
  }
  assert.match(lokiFixture, /safe-id/);
  assert.match(lokiFixture, /\[REDACTED\]/);
});

function compilePromtailExpression(source, global = false) {
  const caseInsensitive = source.startsWith("(?i)");
  return new RegExp(caseInsensitive ? source.slice(4) : source, `${caseInsensitive ? "i" : ""}${global ? "g" : ""}`);
}
