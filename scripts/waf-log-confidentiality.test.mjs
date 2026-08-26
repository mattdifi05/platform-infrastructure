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
  // Primary compensating control: audit log structurally excludes request
  // header (B) and response header (F) sections, so Authorization, Cookie
  // and Set-Cookie values cannot reach persistent audit output regardless
  // of whether sanitise actions are active.
  assert.match(compose, /MODSEC_AUDIT_LOG_PARTS: "AKZ"/);
  assert.doesNotMatch(compose, /MODSEC_AUDIT_LOG_PARTS:\s*"[^"]*[BF]/);
  assert.doesNotMatch(compose, /MODSEC_AUDIT_LOG_PARTS:\s*\$\{/);
});

test("FG-021 sanitise actions disabled but preserved as comments for CRS upgrade", () => {
  for (const name of [
    "waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf",
    "waf/REQUEST-900-VPS-RULES-BEFORE-CRS.conf",
  ]) {
    const rules = fs.readFileSync(path.join(root, name), "utf8");
    for (const action of ["sanitiseRequestHeader:Authorization", "sanitiseRequestHeader:Cookie", "sanitiseResponseHeader:Set-Cookie"]) {
      const lines = rules.split("\n");
      const activeLines = lines.filter((l) => !l.trim().startsWith("#") && l.includes(action));
      assert.equal(activeLines.length, 0, `${name}: ${action} must not appear on an active directive`);
      const commentLines = lines.filter((l) => l.trim().startsWith("#") && l.includes(action));
      assert.ok(commentLines.length > 0 || rules.includes(action), `${name}: ${action} must survive as a comment or string for future re-enablement`);
    }
  }
});

test("FG-021 no active sanitise actions in any engine-bound WAF config", () => {
  for (const name of [
    "waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf",
    "waf/REQUEST-900-VPS-RULES-BEFORE-CRS.conf",
    "waf/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf",
  ]) {
    const rules = fs.readFileSync(path.join(root, name), "utf8");
    const lines = rules.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line.startsWith("#") || line === "") continue;
      assert.doesNotMatch(line, /sanitiseRequestHeader|sanitiseResponseHeader/, `${name}:${i + 1}: unsupported ModSecurity action must be commented out`);
    }
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
