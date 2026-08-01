import fs from "node:fs";

const manifestPath = requiredEnvironment("FG051_MOCK_MANIFEST");
const receiptPath = requiredEnvironment("FG051_MOCK_RECEIPT");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const syntheticToken = "offline-synthetic-token";
const remoteApps = manifest.applications.map((app, index) => ({
  id: `synthetic-app-${index}`,
  name: app.name,
  domain: app.domain,
  type: "self_hosted",
  auto_redirect_to_identity: true,
  enable_binding_cookie: true,
  http_only_cookie_attribute: true,
  same_site_cookie_attribute: "strict",
}));
const appsById = new Map(remoteApps.map((app, index) => [app.id, manifest.applications[index]]));
let fetchCalls = 0;
let unexpectedRequests = 0;

globalThis.fetch = async (input, options = {}) => {
  fetchCalls += 1;
  const url = new URL(String(input));
  const method = String(options.method ?? "GET").toUpperCase();
  const authorization = options.headers?.Authorization;

  try {
    if (url.origin !== "https://api.cloudflare.com") throw new Error("unexpected origin");
    if (!url.pathname.startsWith("/client/v4/accounts/")) throw new Error("unexpected API path");
    if (method !== "GET") throw new Error("unexpected method");
    if (authorization !== `Bearer ${syntheticToken}`) throw new Error("unexpected synthetic authorization");

    if (url.pathname.endsWith("/access/apps") && url.searchParams.get("per_page") === "1000") {
      return response(remoteApps);
    }

    const policyMatch = url.pathname.match(/\/access\/apps\/([^/]+)\/policies$/);
    if (policyMatch && url.searchParams.get("per_page") === "1000") {
      const app = appsById.get(policyMatch[1]);
      if (!app) throw new Error("unknown synthetic application id");
      return response([{
        id: `synthetic-policy-${policyMatch[1]}`,
        name: app.policyName ?? `${app.name} admin allow`,
        decision: "allow",
        precedence: 1,
        include: manifest.allowedEmails.map((email) => ({ email: { email } })),
        require: [{ login_method: { id: manifest.allowedIdentityProviderIds[0] } }],
        exclude: [],
      }]);
    }

    throw new Error("unexpected request shape");
  } catch (error) {
    unexpectedRequests += 1;
    throw error;
  }
};

process.on("exit", () => {
  fs.writeFileSync(receiptPath, `${JSON.stringify({
    fetchCalls,
    unexpectedRequests,
    manifestApplications: manifest.applications.length,
    network: "blocked-by-fetch-override",
  }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  process.stdout.write(`[MOCK] offline_fetch_calls=${fetchCalls} unexpected_requests=${unexpectedRequests} network=blocked\n`);
  if (unexpectedRequests > 0) process.exitCode = 1;
});

function response(result) {
  return {
    ok: true,
    status: 200,
    async json() {
      return { success: true, result, errors: [], messages: [] };
    },
  };
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} is required`);
  return value;
}
