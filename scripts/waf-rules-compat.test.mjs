import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

// Blocker 3 regression gate for the platform WAF rule files.
//
// Root cause (FG-021, fd55ba5): SecAction directives using
// sanitiseRequestHeader / sanitiseResponseHeader abort engine startup on the
// pinned CRS image (owasp/modsecurity-crs:4.26.0) with
// "SanitiseRequestHeader is not yet supported". The greenfield cohort mounts
// waf/REQUEST-900-VPS-RULES-BEFORE-CRS.conf into gf-waf, so any unsupported
// action there is a start blocker.
//
// Scope note: compose.vps-waf.yaml and compose.local-private.yaml bind exactly
// {REQUEST-900-VPS-RULES-BEFORE-CRS.conf, RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf}
// into the WAF container. The legacy brownfield-only
// waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf (used solely by
// compose.waf.yaml) still carries active sanitise* actions and is NOT gated
// here because it is outside this fix's scope; it will hit the same startup
// failure on restart with the pinned image until the FG-021 block receives
// the same treatment.
const UNSUPPORTED_ACTION_PATTERN = /\bsanitise(?:Request|Response)Header\b/;
const UNSUPPORTED_ACTION_NAMES = ["sanitiseRequestHeader", "sanitiseResponseHeader"];
const DIRECTIVE_PATTERN = /^(SecAction|SecRule)\b/;
const ID_PATTERN = /\bid\s*:\s*(\d+)\b/;
const ENGINE_BOUND_COMPOSE_FILES = ["compose.vps-waf.yaml", "compose.local-private.yaml"];
const GREENFIELD_BLOCKER_RULE_FILE = "REQUEST-900-VPS-RULES-BEFORE-CRS.conf";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const wafDir = path.join(root, "waf");

function listWafConfFiles() {
  return fs
    .readdirSync(wafDir)
    .filter((name) => name.endsWith(".conf"))
    .sort();
}

// Joins backslash continuations and skips blank/comment lines so each entry
// is one logical directive with its starting physical line number.
function logicalLines(source) {
  const parsed = [];
  let current = null;
  for (const [index, physical] of source.split("\n").entries()) {
    const lineNumber = index + 1;
    const trimmed = physical.trim();
    if (current === null) {
      if (trimmed.length === 0 || trimmed.startsWith("#")) continue;
      current = { text: trimmed, startLine: lineNumber };
    } else {
      current.text += ` ${trimmed}`;
    }
    if (trimmed.endsWith("\\")) {
      current.text = current.text.slice(0, -1).trimEnd();
      continue;
    }
    parsed.push(current);
    current = null;
  }
  assert.equal(current, null, "unterminated backslash continuation at end of file");
  return parsed;
}

function countUnescapedDoubleQuotes(text) {
  let count = 0;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (character === "\\") {
      index += 1;
      continue;
    }
    if (character === '"') count += 1;
  }
  return count;
}

function parseWafFileSet() {
  return listWafConfFiles().map((name) => {
    const source = fs.readFileSync(path.join(wafDir, name), "utf8");
    const directives = [];
    let previousOpensChain = false;
    for (const logical of logicalLines(source)) {
      const match = logical.text.match(DIRECTIVE_PATTERN);
      if (!match) continue;
      directives.push({
        file: name,
        startLine: logical.startLine,
        kind: match[1],
        id: logical.text.match(ID_PATTERN)?.[1] ?? null,
        text: logical.text,
        chainFollower: previousOpensChain,
      });
      previousOpensChain = /,\s*chain\s*"?$/.test(logical.text.trim());
    }
    return { name, source, directives };
  });
}

function readEngineBoundWafFileNames(confNames) {
  const bound = new Set();
  for (const composeName of ENGINE_BOUND_COMPOSE_FILES) {
    const compose = fs.readFileSync(path.join(root, composeName), "utf8");
    for (const match of compose.matchAll(/^\s*-\s*\.\/waf\/([^\s:]+\.conf):/gm)) {
      bound.add(match[1]);
    }
  }
  assert.ok(bound.size > 0, "no ./waf/*.conf bind mounts found; overlay layout changed");
  for (const name of bound) {
    assert.ok(confNames.includes(name), `compose binds ${name} but it is absent from waf/`);
  }
  assert.ok(
    bound.has(GREENFIELD_BLOCKER_RULE_FILE),
    `${GREENFIELD_BLOCKER_RULE_FILE} must stay bound into the WAF container`,
  );
  return [...bound].sort();
}

test("every WAF directive line parses structurally with balanced double quotes", () => {
  for (const { name, source } of parseWafFileSet()) {
    for (const logical of logicalLines(source)) {
      const count = countUnescapedDoubleQuotes(logical.text);
      assert.equal(
        count % 2,
        0,
        `${name}:${logical.startLine} has unbalanced double quotes (${count}); the CRS engine would fail to parse this directive`,
      );
    }
  }
});

test("all SecAction/SecRule ids are present and unique across the WAF file set", () => {
  const seen = new Map();
  for (const { name, directives } of parseWafFileSet()) {
    for (const directive of directives) {
      if (directive.chainFollower) {
        // Chain members inherit the starter's id by design; only starters need one.
        continue;
      }
      assert.ok(
        directive.id !== null,
        `${directive.kind} at ${name}:${directive.startLine} is missing a numeric id`,
      );
      const prior = seen.get(directive.id);
      assert.ok(
        prior === undefined,
        `duplicate rule id ${directive.id}: ${prior} vs ${name}:${directive.startLine}`,
      );
      seen.set(directive.id, `${name}:${directive.startLine}`);
    }
  }
  assert.ok(seen.size > 0, "expected at least one id-bearing WAF directive");
});

test("engine-bound WAF rules use none of the CRS-unsupported sanitise actions", () => {
  const confNames = listWafConfFiles();
  const boundNames = readEngineBoundWafFileNames(confNames);
  for (const { name, directives } of parseWafFileSet()) {
    if (!boundNames.includes(name)) continue;
    for (const directive of directives) {
      assert.doesNotMatch(
        directive.text,
        UNSUPPORTED_ACTION_PATTERN,
        `${directive.kind} at ${name}:${directive.startLine} uses an action unsupported by owasp/modsecurity-crs:4.26.0 ` +
          `(FG-021); comment it out like the preserved block in ${GREENFIELD_BLOCKER_RULE_FILE}, ` +
          `or upgrade the CRS image first. Unsupported actions: ${UNSUPPORTED_ACTION_NAMES.join(", ")}`,
      );
    }
  }
});

test("FG-021 sanitise hardening survives as commented guidance for future re-enablement", () => {
  const vpsSource = fs.readFileSync(path.join(wafDir, GREENFIELD_BLOCKER_RULE_FILE), "utf8");
  const commentedOut = vpsSource.split("\n").filter((line) => line.trim().startsWith("#"));
  for (const [id, marker] of [
    ["1000105", "sanitiseRequestHeader:Authorization"],
    ["1000105", "sanitiseRequestHeader:Cookie"],
    ["1000106", "sanitiseResponseHeader:Set-Cookie"],
  ]) {
    assert.ok(
      commentedOut.some((line) => line.includes(`id:${id}`) && line.includes(marker)),
      `the disabled FG-021 SecAction id:${id} (${marker}) was removed instead of kept commented; ` +
        "restore it so the rule can be re-enabled when the CRS image supports sanitise* actions",
    );
  }
});
