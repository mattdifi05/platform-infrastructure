import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const configureScript = path.join(repositoryRoot, "scripts", "keycloak-backchannel-configure.sh");
const readinessScript = path.join(repositoryRoot, "scripts", "keycloak-passkey-readiness.sh");

function validateOrigin(origin, extraEnv = {}) {
  const env = { ...process.env };
  for (const key of [
    "CONTROL_CENTER_PUBLIC_ORIGIN",
    "KEYCLOAK_BACKCHANNEL_APPLY",
    "KEYCLOAK_BACKCHANNEL_CONFIRM",
    "KEYCLOAK_BACKCHANNEL_VALIDATE_ONLY",
    "KEYCLOAK_CONTAINER",
    "KEYCLOAK_REALM",
    "CONTROL_CENTER_OIDC_CLIENT_ID",
  ]) delete env[key];
  return spawnSync("sh", [configureScript], {
    cwd: repositoryRoot,
    env: {
      ...env,
      CONTROL_CENTER_PUBLIC_ORIGIN: origin,
      KEYCLOAK_BACKCHANNEL_APPLY: "false",
      KEYCLOAK_BACKCHANNEL_VALIDATE_ONLY: "true",
      ...extraEnv,
    },
    encoding: "utf8",
  });
}

test("Keycloak back-channel helper derives an exact HTTPS endpoint without Docker", () => {
  const result = validateOrigin("https://portal.example.test/");
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /expected_backchannel=https:\/\/portal\.example\.test\/auth\/backchannel-logout/);
  assert.match(result.stdout, /status=validated-only/);
});

test("Keycloak back-channel helper rejects non-origin and non-HTTPS inputs", () => {
  for (const origin of [
    "",
    "http://portal.example.test",
    "https://user:password@portal.example.test",
    "https://portal.example.test/path",
    "https://portal.example.test?query=1",
    "https://portal.example.test#fragment",
    " https://portal.example.test",
    "https://portal.example.test\n",
  ]) {
    const result = validateOrigin(origin);
    assert.equal(result.status, 2, `${origin}: ${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /origin-only HTTPS URL/);
  }
});

test("Keycloak back-channel apply requires the exact confirmation before Docker", () => {
  const result = validateOrigin("https://portal.example.test", {
    KEYCLOAK_BACKCHANNEL_APPLY: "true",
    KEYCLOAK_BACKCHANNEL_VALIDATE_ONLY: "false",
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /KEYCLOAK_BACKCHANNEL_CONFIRM=CONFIGURE-OIDC-BACKCHANNEL-LOGOUT/);
});

test("Keycloak helpers encode all three update and exact-readiness attributes", () => {
  const configure = readFileSync(configureScript, "utf8");
  const readiness = readFileSync(readinessScript, "utf8");
  for (const attribute of [
    "backchannel.logout.url",
    "backchannel.logout.session.required",
    "backchannel.logout.revoke.offline.tokens",
  ]) {
    assert.match(configure, new RegExp(attribute.replaceAll(".", "\\.")));
    assert.match(readiness, new RegExp(attribute.replaceAll(".", "\\.")));
  }
  assert.match(configure, /kcadm\.sh update/);
  assert.match(configure, /exact_contract \"\$client_json\"/);
  assert.match(readiness, /PLATFORM_VERIFY_BACKCHANNEL_URL/);
  for (const helper of [configure, readiness]) {
    assert.match(helper, /umask 077/);
    assert.match(helper, /config_dir=\$\(mktemp -d \/tmp\/platform-[^\n]+\.XXXXXX\)/);
    assert.match(helper, /config=\$config_dir\/kcadm\.config/);
    assert.match(helper, /rm -rf -- "\$config_dir"/);
  }
});
