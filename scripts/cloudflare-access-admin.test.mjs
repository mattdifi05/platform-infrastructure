import assert from "node:assert/strict";
import test from "node:test";

import {
  assertAppMatches,
  assertExactPolicyCollection,
  assertPolicyMatches,
  findExactApplication,
  listApplications,
  normalizeManifest,
} from "./cloudflare-access-admin.mjs";

const expectedApp = {
  name: "Platform Admin",
  domain: "admin.example.test",
  type: "self_hosted",
  session_duration: "8h",
  allowed_idps: ["idp-1"],
  auto_redirect_to_identity: true,
  enable_binding_cookie: true,
  http_only_cookie_attribute: true,
  same_site_cookie_attribute: "strict",
};

const expectedPolicy = {
  name: "Platform Admin allow",
  decision: "allow",
  precedence: 1,
  session_duration: "8h",
  include: [{ email: { email: "admin@example.test" } }],
  require: [{ login_method: { id: "idp-1" } }],
  exclude: [],
};

test("FG-040 requires exact application identity, session and IdP set", () => {
  assert.doesNotThrow(() => assertAppMatches(structuredClone(expectedApp), expectedApp));
  for (const mutate of [
    (remote) => { remote.name = "Sibling Admin"; },
    (remote) => { remote.session_duration = "24h"; },
    (remote) => { remote.allowed_idps.push("idp-wide"); },
  ]) {
    const remote = structuredClone(expectedApp);
    mutate(remote);
    assert.throws(() => assertAppMatches(remote, expectedApp), /name|session|identity provider|IdP/i);
  }
  assert.throws(
    () => findExactApplication([{ ...expectedApp, id: "one" }, { ...expectedApp, id: "two" }], expectedApp),
    /duplicate/,
  );
  assert.throws(
    () => findExactApplication([{ ...expectedApp, domain: "sibling.example.test" }], expectedApp),
    /reused by a sibling/,
  );
});

test("FG-040 rejects widened, unknown and duplicate policy selectors", () => {
  assert.doesNotThrow(() => assertPolicyMatches(structuredClone(expectedPolicy), expectedPolicy));
  const probes = [
    (remote) => remote.include.push({ email_domain: { domain: "example.test" } }),
    (remote) => remote.include.push({ everyone: {} }),
    (remote) => remote.include.push(structuredClone(remote.include[0])),
    (remote) => remote.require.push({ login_method: { id: "idp-wide" } }),
    (remote) => remote.exclude.push({ email: { email: "auditor@example.test" } }),
  ];
  for (const mutate of probes) {
    const remote = structuredClone(expectedPolicy);
    mutate(remote);
    assert.throws(() => assertPolicyMatches(remote, expectedPolicy), /selector|include|require|exclude|duplicate|exact/i);
  }
});

test("FG-040 rejects sibling policies and duplicate manifest identities", () => {
  for (const decision of ["allow", "bypass"]) {
    assert.throws(
      () => assertExactPolicyCollection([structuredClone(expectedPolicy), { name: `sibling-${decision}`, decision }], expectedPolicy),
      /extra sibling/,
    );
  }
  assert.throws(
    () => assertExactPolicyCollection([structuredClone(expectedPolicy), { ...structuredClone(expectedPolicy), id: "duplicate" }], expectedPolicy),
    /exactly one/,
  );
  const raw = {
    accountId: "placeholder",
    teamName: "platform",
    adminSessionDuration: "8h",
    mfaEnforcedByIdentityProvider: true,
    allowedIdentityProviderIds: ["idp-1"],
    allowedEmails: ["Admin@example.test", "admin@example.test"],
    allowedEmailDomains: [],
    applications: [{ name: "Platform Admin", domain: "admin.example.test" }],
  };
  assert.throws(() => normalizeManifest(raw, { apply: false, verifyRemote: false }), /duplicated/);
});

test("FG-040 paginates Cloudflare collections before reconciliation", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(String(url));
    const page = Number(new URL(url).searchParams.get("page") || "1");
    const result = Array.from({ length: page === 1 ? 50 : 1 }, (_, index) => ({
      id: `app-${page}-${index}`,
      domain: `admin-${page}-${index}.example.test`,
    }));
    return {
      ok: true,
      status: 200,
      json: async () => ({
        success: true,
        result,
        result_info: { page, total_pages: 2, per_page: 50, count: result.length, total_count: 51 },
      }),
    };
  };
  try {
    const applications = await listApplications("account", "synthetic-token");
    assert.equal(applications.length, 51);
    assert.equal(applications[0].id, "app-1-0");
    assert.equal(applications.at(-1).id, "app-2-0");
    assert.equal(calls.length, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("FG-040 rejects a successful collection response without result_info", async () => {
  await assert.rejects(
    () => withCloudflareCollectionResponse({
      success: true,
      result: [{ id: "app-1", domain: "admin.example.test" }],
    }),
    /result_info|pagination/i,
  );
});

test("FG-040 rejects incoherent pagination metadata even when the item is valid", async () => {
  await assert.rejects(
    () => withCloudflareCollectionResponse({
      success: true,
      result: [{ id: "app-1", domain: "admin.example.test" }],
      result_info: { page: 999, total_pages: 1, per_page: 0, count: 999, total_count: 999 },
    }),
    /result_info|pagination/i,
  );
});

test("FG-040 rejects a non-exact page progression", async () => {
  const originalFetch = globalThis.fetch;
  let call = 0;
  globalThis.fetch = async () => {
    call += 1;
    const result = Array.from({ length: call === 1 ? 50 : 1 }, (_, index) => ({ id: `app-${call}-${index}` }));
    return {
      ok: true,
      status: 200,
      json: async () => ({
        success: true,
        result,
        result_info: { page: call === 1 ? 1 : 3, total_pages: 2, per_page: 50, count: result.length, total_count: 51 },
      }),
    };
  };
  try {
    await assert.rejects(() => listApplications("account", "synthetic-token"), /page|progression|pagination/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

async function withCloudflareCollectionResponse(payload) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => structuredClone(payload),
  });
  try {
    return await listApplications("account", "synthetic-token");
  } finally {
    globalThis.fetch = originalFetch;
  }
}
