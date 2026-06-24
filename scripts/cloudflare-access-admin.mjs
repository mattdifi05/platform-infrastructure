#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const API_BASE = "https://api.cloudflare.com/client/v4";
const DEFAULT_MANIFEST = "cloudflare/access-admin.example.json";

function parseArgs(args) {
  const out = { manifest: DEFAULT_MANIFEST, apply: false, verifyRemote: false };
  for (let i = 0; i < args.length; i += 1) {
    const value = args[i];
    if (value === "--manifest") {
      out.manifest = args[++i];
    } else if (value === "--account-id") {
      out.accountId = args[++i];
    } else if (value === "--apply") {
      out.apply = true;
    } else if (value === "--verifyRemote") {
      out.verifyRemote = true;
    } else if (value === "--help" || value === "-h") {
      out.help = true;
    } else {
      throw new Error(`Unknown argument: ${value}`);
    }
  }
  return out;
}

function usage() {
  process.stdout.write(`Usage: node scripts/cloudflare-access-admin.mjs [--manifest ${DEFAULT_MANIFEST}] [--apply|--verifyRemote] [--account-id ID]\n\n`);
  process.stdout.write("Dry-run by default. The apply path is additive-only: it creates missing Access applications and missing named allow policies, and refuses to weaken or rewrite existing resources.\n");
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(path.resolve(file), "utf8").replace(/^\uFEFF/, ""));
}

function reportTimestamp() {
  return new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
}

function ensureReportDir() {
  const directory = path.join(process.cwd(), "reports", "cloudflare-access");
  fs.mkdirSync(directory, { recursive: true });
  return directory;
}

function manifestSummary(manifest) {
  return {
    accountId: manifest.accountId,
    teamName: manifest.teamName,
    adminSessionDuration: manifest.adminSessionDuration,
    mfaEnforcedByIdentityProvider: true,
    allowedIdentityProviderCount: manifest.allowedIdentityProviderIds.length,
    allowedEmailCount: manifest.allowedEmails.length,
    allowedEmailDomainCount: manifest.allowedEmailDomains.length,
    applications: manifest.applications.map((app) => ({
      name: app.name,
      domain: app.domain,
      policyName: app.policyName,
      sessionDuration: app.sessionDuration,
    })),
  };
}

function writeEvidenceReport({ mode, status, manifest, applications, issues = [] }) {
  const generatedAt = new Date().toISOString();
  const payload = {
    generatedAt,
    mode,
    status,
    manifest: manifestSummary(manifest),
    applications,
    issues,
  };
  const directory = ensureReportDir();
  const baseName = `cloudflare-access-admin-${reportTimestamp()}`;
  const jsonPath = path.join(directory, `${baseName}.json`);
  const markdownPath = path.join(directory, `${baseName}.md`);
  fs.writeFileSync(jsonPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  fs.writeFileSync(markdownPath, [
    "# Stexor Cloudflare Access Admin Evidence",
    "",
    `Status: ${status}`,
    `Mode: ${mode}`,
    `Generated at: ${generatedAt}`,
    `Team: ${manifest.teamName}`,
    "",
    "| Application | Domain | Result |",
    "| --- | --- | --- |",
    ...applications.map((app) => `| ${app.name} | ${app.domain} | ${app.result}${app.issue ? `: ${app.issue}` : ""} |`),
    "",
    "## Issues",
    "",
    ...(issues.length ? issues.map((issue) => `- ${issue}`) : ["- none"]),
  ].join("\n") + "\n", "utf8");
  process.stdout.write(`Cloudflare Access evidence written to ${jsonPath} and ${markdownPath}\n`);
}

function isPlaceholder(value) {
  return !value
    || /^0{32}$/.test(value)
    || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(value)
    || /(^|\.)example\.com$/i.test(value)
    || /^admin@example\.com$/i.test(value);
}

function cleanArray(value) {
  return Array.isArray(value) ? value.map((item) => String(item).trim()).filter(Boolean) : [];
}

function normalizeManifest(raw, argv) {
  const accountId = argv.accountId || process.env.CLOUDFLARE_ACCOUNT_ID || raw.accountId;
  const allowedIdentityProviderIds = cleanArray(raw.allowedIdentityProviderIds);
  const allowedEmails = cleanArray(raw.allowedEmails);
  const allowedEmailDomains = cleanArray(raw.allowedEmailDomains);
  const applications = Array.isArray(raw.applications) ? raw.applications : [];

  if (!raw.teamName) throw new Error("Cloudflare Access manifest must define teamName.");
  if (!raw.adminSessionDuration) throw new Error("Cloudflare Access manifest must define adminSessionDuration.");
  if (raw.mfaEnforcedByIdentityProvider !== true) {
    throw new Error("Cloudflare Access manifest must set mfaEnforcedByIdentityProvider: true.");
  }
  if (allowedIdentityProviderIds.length !== 1) {
    throw new Error("Cloudflare Access admin manifest must define exactly one allowedIdentityProviderId so the allow policy can require that MFA-capable login method unambiguously.");
  }
  if (allowedEmails.length === 0 && allowedEmailDomains.length === 0) {
    throw new Error("Cloudflare Access manifest must allow at least one admin email or email domain.");
  }
  if (applications.length === 0) throw new Error("Cloudflare Access manifest must define at least one admin application.");

  const normalizedApps = applications.map((app) => {
    if (!app.name || !app.domain) throw new Error(`Every Access application needs name and domain: ${JSON.stringify(app)}`);
    return {
      name: String(app.name),
      domain: String(app.domain).toLowerCase(),
      policyName: app.policyName ? String(app.policyName) : `${app.name} admin allow`,
      sessionDuration: app.sessionDuration ? String(app.sessionDuration) : String(raw.adminSessionDuration),
    };
  });

  if (argv.apply || argv.verifyRemote) {
    if (isPlaceholder(accountId)) throw new Error("Set a real Cloudflare account id with --account-id or CLOUDFLARE_ACCOUNT_ID before live operations.");
    if (allowedIdentityProviderIds.some(isPlaceholder)) throw new Error("Replace the placeholder Cloudflare Access identity provider id before live operations.");
    if (allowedEmails.some(isPlaceholder) && allowedEmailDomains.length === 0) throw new Error("Replace placeholder admin emails before live operations.");
    const placeholderApp = normalizedApps.find((app) => isPlaceholder(app.domain) || /localhost/i.test(app.domain));
    if (placeholderApp) throw new Error(`Replace placeholder/local Access application domain before live operations: ${placeholderApp.domain}`);
  }

  return {
    accountId,
    teamName: String(raw.teamName),
    adminSessionDuration: String(raw.adminSessionDuration),
    allowedIdentityProviderIds,
    allowedEmails,
    allowedEmailDomains,
    applications: normalizedApps,
  };
}

function applicationPayload(app, manifest) {
  return {
    name: app.name,
    domain: app.domain,
    type: "self_hosted",
    session_duration: app.sessionDuration,
    allowed_idps: manifest.allowedIdentityProviderIds,
    auto_redirect_to_identity: true,
    enable_binding_cookie: true,
    http_only_cookie_attribute: true,
    same_site_cookie_attribute: "strict",
  };
}

function policyPayload(app, manifest) {
  return {
    name: app.policyName,
    decision: "allow",
    precedence: 1,
    session_duration: app.sessionDuration,
    include: [
      ...manifest.allowedEmails.map((email) => ({ email: { email } })),
      ...manifest.allowedEmailDomains.map((domain) => ({ email_domain: { domain } })),
    ],
    require: [{ login_method: { id: manifest.allowedIdentityProviderIds[0] } }],
    exclude: [],
  };
}

async function cloudflareRequest({ method, requestPath, token, body }) {
  const response = await fetch(`${API_BASE}${requestPath}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await response.json().catch(() => ({}));
  if (!response.ok || json.success === false) {
    const errors = (json.errors || []).map((error) => `${error.code ?? "unknown"}: ${error.message}`).join("; ");
    throw new Error(`Cloudflare ${method} ${requestPath} failed (${response.status})${errors ? `: ${errors}` : ""}`);
  }
  return json;
}

async function listApplications(accountId, token) {
  const result = await cloudflareRequest({ method: "GET", requestPath: `/accounts/${accountId}/access/apps?per_page=1000`, token });
  return result.result || [];
}

async function listPolicies(accountId, appId, token) {
  const result = await cloudflareRequest({ method: "GET", requestPath: `/accounts/${accountId}/access/apps/${appId}/policies?per_page=1000`, token });
  return result.result || [];
}

function selectorKeys(selectors = []) {
  const keys = [];
  for (const selector of selectors) {
    if (selector.email?.email) keys.push(`email:${String(selector.email.email).toLowerCase()}`);
    if (selector.email_domain?.domain) keys.push(`email_domain:${String(selector.email_domain.domain).toLowerCase()}`);
    if (selector.login_method?.id) keys.push(`login_method:${String(selector.login_method.id)}`);
  }
  return new Set(keys);
}

function requireSelectorSet(remoteSelectors, expectedSelectors, label) {
  const remote = selectorKeys(remoteSelectors);
  for (const key of selectorKeys(expectedSelectors)) {
    if (!remote.has(key)) throw new Error(`${label} is missing selector ${key}.`);
  }
}

function assertAppMatches(remote, expected) {
  if (remote.type !== expected.type) throw new Error(`${expected.name} exists but is not self_hosted.`);
  if (String(remote.domain).toLowerCase() !== expected.domain) throw new Error(`${expected.name} exists with a different domain.`);
  if (remote.auto_redirect_to_identity !== true) throw new Error(`${expected.name} must auto-redirect to the configured identity provider.`);
  if (remote.enable_binding_cookie !== true) throw new Error(`${expected.name} must enable binding cookies.`);
  if (remote.http_only_cookie_attribute !== true) throw new Error(`${expected.name} must use HTTP-only cookies.`);
  if (String(remote.same_site_cookie_attribute || "").toLowerCase() !== "strict") throw new Error(`${expected.name} must use SameSite=strict cookies.`);
}

function assertPolicyMatches(remote, expected) {
  if (remote.decision !== "allow") throw new Error(`${expected.name} policy must be an allow policy.`);
  if (Number(remote.precedence) !== 1) throw new Error(`${expected.name} policy must have precedence 1.`);
  requireSelectorSet(remote.include, expected.include, `${expected.name} include policy`);
  requireSelectorSet(remote.require, expected.require, `${expected.name} require policy`);
}

function dryRun(manifest) {
  process.stdout.write(`==> Cloudflare Access admin plan for account ${manifest.accountId || "<set during apply>"}\n`);
  process.stdout.write(`Team: ${manifest.teamName}\n`);
  process.stdout.write(`Admin session duration: ${manifest.adminSessionDuration}\n`);
  process.stdout.write("MFA source: required identity provider configuration\n");
  process.stdout.write(`Allowed identity provider: ${manifest.allowedIdentityProviderIds[0]}\n`);
  process.stdout.write(`Allowed admin emails: ${manifest.allowedEmails.length}\n`);
  process.stdout.write(`Allowed admin email domains: ${manifest.allowedEmailDomains.length}\n`);
  for (const app of manifest.applications) {
    process.stdout.write(`Would protect ${app.domain} as ${app.name} with policy ${app.policyName}.\n`);
  }
  return manifest.applications.map((app) => ({
    name: app.name,
    domain: app.domain,
    result: "planned",
  }));
}

async function apply(manifest) {
  const token = process.env.CLOUDFLARE_API_TOKEN;
  if (!token) throw new Error("Set CLOUDFLARE_API_TOKEN before --apply or --verifyRemote.");

  const apps = await listApplications(manifest.accountId, token);
  const results = [];
  for (const app of manifest.applications) {
    const expectedApp = applicationPayload(app, manifest);
    let remote = apps.find((item) => String(item.domain).toLowerCase() === app.domain);
    let appResult = "matched";
    let policyResult = "matched";
    if (!remote) {
      const created = await cloudflareRequest({
        method: "POST",
        requestPath: `/accounts/${manifest.accountId}/access/apps`,
        token,
        body: expectedApp,
      });
      remote = created.result;
      apps.push(remote);
      process.stdout.write(`Created Access application ${app.name} (${app.domain}).\n`);
      appResult = "created";
    } else {
      assertAppMatches(remote, expectedApp);
      process.stdout.write(`Access application already exists and matches hardened settings: ${app.domain}.\n`);
    }

    const expectedPolicy = policyPayload(app, manifest);
    const policies = await listPolicies(manifest.accountId, remote.id, token);
    const policy = policies.find((item) => item.name === expectedPolicy.name);
    if (!policy) {
      await cloudflareRequest({
        method: "POST",
        requestPath: `/accounts/${manifest.accountId}/access/apps/${remote.id}/policies`,
        token,
        body: expectedPolicy,
      });
      process.stdout.write(`Created Access allow policy ${expectedPolicy.name}.\n`);
      policyResult = "created";
    } else {
      assertPolicyMatches(policy, expectedPolicy);
      process.stdout.write(`Access policy already exists and matches required selectors: ${expectedPolicy.name}.\n`);
    }
    results.push({
      name: app.name,
      domain: app.domain,
      result: `application:${appResult};policy:${policyResult}`,
    });
  }
  return results;
}

async function verifyRemote(manifest) {
  const token = process.env.CLOUDFLARE_API_TOKEN;
  if (!token) throw new Error("Set CLOUDFLARE_API_TOKEN before --verifyRemote.");

  const apps = await listApplications(manifest.accountId, token);
  const results = [];
  const issues = [];
  for (const app of manifest.applications) {
    try {
      const expectedApp = applicationPayload(app, manifest);
      const remote = apps.find((item) => String(item.domain).toLowerCase() === app.domain);
      if (!remote) throw new Error(`Missing Cloudflare Access application: ${app.domain}`);
      assertAppMatches(remote, expectedApp);
      const policies = await listPolicies(manifest.accountId, remote.id, token);
      const expectedPolicy = policyPayload(app, manifest);
      const policy = policies.find((item) => item.name === expectedPolicy.name);
      if (!policy) throw new Error(`Missing Cloudflare Access policy: ${expectedPolicy.name}`);
      assertPolicyMatches(policy, expectedPolicy);
      results.push({
        name: app.name,
        domain: app.domain,
        result: "verified",
        applicationId: remote.id ?? null,
        policyId: policy.id ?? null,
      });
    } catch (error) {
      const issue = String(error?.message ?? error);
      issues.push(issue);
      results.push({
        name: app.name,
        domain: app.domain,
        result: "failed",
        issue,
      });
    }
  }
  if (issues.length) {
    const error = new Error(`Cloudflare Access remote verification failed for ${issues.length} application(s).`);
    error.applications = results;
    error.issues = issues;
    throw error;
  }
  process.stdout.write("Cloudflare Access admin applications match the manifest.\n");
  return results;
}

async function main() {
  const argv = parseArgs(process.argv.slice(2));
  if (argv.help) {
    usage();
    return;
  }
  let mode = argv.verifyRemote ? "verifyRemote" : argv.apply ? "apply" : "plan";
  let applications = [];
  let manifest = null;
  try {
    manifest = normalizeManifest(readJson(argv.manifest), argv);
    if (argv.apply && argv.verifyRemote) throw new Error("Use either --apply or --verifyRemote, not both.");
    let status = "warning";
    if (argv.apply) {
      applications = await apply(manifest);
      status = "passed";
    } else if (argv.verifyRemote) {
      applications = await verifyRemote(manifest);
      status = "passed";
    } else {
      applications = dryRun(manifest);
    }
    writeEvidenceReport({ mode, status, manifest, applications });
  } catch (error) {
    if (manifest) {
      writeEvidenceReport({
        mode,
        status: "failed",
        manifest,
        applications: error.applications ?? applications,
        issues: error.issues ?? [String(error?.message ?? error)],
      });
    }
    throw error;
  }
}

main().catch((error) => {
  process.stderr.write(`${error.message ?? error}\n`);
  process.exitCode = 1;
});
