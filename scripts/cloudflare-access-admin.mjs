#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertExactAdminApplications,
  buildAdminAccessEvidence,
  loadAdminAccessInventory,
  reconcileAdminRouteInventory,
} from "./admin-access-inventory.mjs";

const API_BASE = "https://api.cloudflare.com/client/v4";
const DEFAULT_MANIFEST = "cloudflare/access-admin.example.json";
const DEFAULT_INVENTORY = "governance/admin-access-surfaces.json";
const ADMIN_ROUTES = "traefik/dynamic/admin-routes.yml";

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
    domainSuffix: manifest.domainSuffix,
    adminSurfaceInventory: manifest.inventoryContract.inventory,
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

function writeEvidenceReport({ mode, status, manifest, applications, routeReconciliation, issues = [] }) {
  const generatedAt = new Date().toISOString();
  const adminSurfaceCoverage = buildAdminAccessEvidence({
    inventoryContract: manifest.inventoryContract,
    routeReconciliation,
    applications,
    mode,
  });
  const payload = {
    generatedAt,
    mode,
    status,
    manifest: manifestSummary(manifest),
    applications,
    adminSurfaceCoverage,
    issues,
  };
  const directory = ensureReportDir();
  const baseName = `cloudflare-access-admin-${reportTimestamp()}`;
  const jsonPath = path.join(directory, `${baseName}.json`);
  const markdownPath = path.join(directory, `${baseName}.md`);
  fs.writeFileSync(jsonPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  fs.writeFileSync(markdownPath, [
    "# Platform Cloudflare Access Admin Evidence",
    "",
    `Status: ${status}`,
    `Mode: ${mode}`,
    `Generated at: ${generatedAt}`,
    `Team: ${manifest.teamName}`,
    `Admin inventory: ${adminSurfaceCoverage.inventory.id}@${adminSurfaceCoverage.inventory.version} (${adminSurfaceCoverage.inventory.sha256})`,
    `Complete inventory coverage: ${adminSurfaceCoverage.complete ? "yes" : "no"}`,
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

function uniqueValues(values, label, lowerCase) {
  const normalized = values.map((value) => lowerCase ? value.toLowerCase() : value);
  requireUnique(normalized, label);
  return normalized;
}

function requireUnique(values, label) {
  const seen = new Set();
  for (const value of values) {
    if (seen.has(value)) throw new Error(`${label} is duplicated: ${value}.`);
    seen.add(value);
  }
}

export function normalizeManifest(raw, argv, inventoryRecord) {
  const accountId = argv.accountId || process.env.CLOUDFLARE_ACCOUNT_ID || raw.accountId;
  const allowedIdentityProviderIds = uniqueValues(cleanArray(raw.allowedIdentityProviderIds), "identity provider", false);
  const allowedEmails = uniqueValues(cleanArray(raw.allowedEmails), "allowed email", true);
  const allowedEmailDomains = uniqueValues(cleanArray(raw.allowedEmailDomains), "allowed email domain", true);
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

  const inventoryContract = assertExactAdminApplications(applications, inventoryRecord, {
    domainSuffix: raw.domainSuffix,
    binding: raw.adminSurfaceInventory,
  });

  const normalizedApps = applications.map((app) => {
    if (!app.name || !app.domain) throw new Error(`Every Access application needs name and domain: ${JSON.stringify(app)}`);
    return {
      name: String(app.name),
      domain: String(app.domain).toLowerCase(),
      policyName: app.policyName ? String(app.policyName) : `${app.name} admin allow`,
      sessionDuration: app.sessionDuration ? String(app.sessionDuration) : String(raw.adminSessionDuration),
    };
  });
  requireUnique(normalizedApps.map((app) => app.name), "Access application name");
  requireUnique(normalizedApps.map((app) => app.domain), "Access application domain");
  requireUnique(normalizedApps.map((app) => app.policyName), "Access policy name");

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
    domainSuffix: String(raw.domainSuffix).toLowerCase(),
    inventoryContract,
    allowedIdentityProviderIds,
    allowedEmails,
    allowedEmailDomains,
    applications: normalizedApps,
  };
}

export function applicationPayload(app, manifest) {
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

export function policyPayload(app, manifest) {
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

export async function listApplications(accountId, token) {
  return listPaginated(`/accounts/${accountId}/access/apps`, token, "Access applications");
}

export async function listPolicies(accountId, appId, token) {
  return listPaginated(`/accounts/${accountId}/access/apps/${appId}/policies`, token, "Access policies");
}

async function listPaginated(requestPath, token, label) {
  const items = [];
  const ids = new Set();
  const perPage = 50;
  let collectionShape = null;
  for (let page = 1; page <= 1000; page += 1) {
    const separator = requestPath.includes("?") ? "&" : "?";
    const response = await cloudflareRequest({ method: "GET", requestPath: `${requestPath}${separator}per_page=${perPage}&page=${page}`, token });
    if (!Array.isArray(response.result)) throw new Error(`${label} response is not an array.`);
    const pageInfo = exactPaginationInfo(response.result_info, {
      label,
      requestedPage: page,
      requestedPerPage: perPage,
      resultCount: response.result.length,
    });
    if (collectionShape
        && (pageInfo.perPage !== collectionShape.perPage
          || pageInfo.totalCount !== collectionShape.totalCount
          || pageInfo.totalPages !== collectionShape.totalPages)) {
      throw new Error(`${label} pagination totals changed between pages.`);
    }
    collectionShape ??= pageInfo;
    for (const item of response.result) {
      const id = String(item?.id ?? "");
      if (id && ids.has(id)) throw new Error(`${label} pagination returned duplicate id ${id}.`);
      if (id) ids.add(id);
      items.push(item);
    }
    if (pageInfo.totalPages === 0 || page === pageInfo.totalPages) {
      if (items.length !== pageInfo.totalCount) throw new Error(`${label} pagination did not return the declared total count.`);
      return items;
    }
  }
  throw new Error(`${label} pagination exceeded the safety limit.`);
}

function exactPaginationInfo(value, { label, requestedPage, requestedPerPage, resultCount }) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} pagination result_info is required.`);
  }
  const integer = (key) => {
    const number = value[key];
    if (typeof number !== "number" || !Number.isSafeInteger(number)) {
      throw new Error(`${label} pagination result_info.${key} must be an exact integer.`);
    }
    return number;
  };
  const page = integer("page");
  const perPage = integer("per_page");
  const count = integer("count");
  const totalCount = integer("total_count");
  const totalPages = integer("total_pages");
  if (page !== requestedPage || perPage !== requestedPerPage || count !== resultCount) {
    throw new Error(`${label} pagination page, per_page, or count does not match the exact request and result.`);
  }
  if (page < 1 || perPage < 1 || count < 0 || count > perPage || totalCount < 0 || totalPages < 0) {
    throw new Error(`${label} pagination result_info contains an invalid range.`);
  }
  const expectedTotalPages = totalCount === 0 ? 0 : Math.ceil(totalCount / perPage);
  if (totalPages !== expectedTotalPages || page > Math.max(1, totalPages)) {
    throw new Error(`${label} pagination total_pages is inconsistent with total_count and per_page.`);
  }
  const offset = (page - 1) * perPage;
  const expectedCount = Math.max(0, Math.min(perPage, totalCount - offset));
  if (count !== expectedCount) throw new Error(`${label} pagination count is inconsistent with the exact page progression.`);
  return { page, perPage, count, totalCount, totalPages };
}

function selectorKeys(selectors, label) {
  if (!Array.isArray(selectors)) throw new Error(`${label} selectors must be an array.`);
  const keys = selectors.map((selector, index) => selectorKey(selector, `${label}[${index}]`));
  if (new Set(keys).size !== keys.length) throw new Error(`${label} contains a duplicate selector.`);
  return keys.sort();
}

function selectorKey(selector, label) {
  if (!selector || typeof selector !== "object" || Array.isArray(selector)) throw new Error(`${label} must be an exact selector object.`);
  const types = Object.keys(selector);
  if (types.length !== 1) throw new Error(`${label} must contain exactly one supported selector type.`);
  const type = types[0];
  const fields = { email: "email", email_domain: "domain", login_method: "id" };
  const field = fields[type];
  if (!field) throw new Error(`${label} uses unknown selector type ${type}.`);
  const value = selector[type];
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== 1 || typeof value[field] !== "string" || !value[field].trim()) {
    throw new Error(`${label} must contain only ${type}.${field}.`);
  }
  const normalized = type === "login_method" ? value[field].trim() : value[field].trim().toLowerCase();
  return `${type}:${normalized}`;
}

function requireExactSelectorSet(remoteSelectors, expectedSelectors, label) {
  const remote = selectorKeys(remoteSelectors, `${label} remote`);
  const expected = selectorKeys(expectedSelectors, `${label} expected`);
  if (JSON.stringify(remote) !== JSON.stringify(expected)) throw new Error(`${label} selectors do not exactly match the manifest.`);
}

export function assertAppMatches(remote, expected) {
  if (remote.name !== expected.name) throw new Error(`${expected.name} exists with a different name.`);
  if (remote.type !== expected.type) throw new Error(`${expected.name} exists but is not self_hosted.`);
  if (String(remote.domain).toLowerCase() !== expected.domain) throw new Error(`${expected.name} exists with a different domain.`);
  if (String(remote.session_duration) !== expected.session_duration) throw new Error(`${expected.name} exists with a different session duration.`);
  const remoteIdps = uniqueValues(cleanArray(remote.allowed_idps), `${expected.name} remote identity provider`, false).sort();
  const expectedIdps = uniqueValues(cleanArray(expected.allowed_idps), `${expected.name} expected identity provider`, false).sort();
  if (JSON.stringify(remoteIdps) !== JSON.stringify(expectedIdps)) throw new Error(`${expected.name} identity provider set does not exactly match.`);
  if (remote.auto_redirect_to_identity !== true) throw new Error(`${expected.name} must auto-redirect to the configured identity provider.`);
  if (remote.enable_binding_cookie !== true) throw new Error(`${expected.name} must enable binding cookies.`);
  if (remote.http_only_cookie_attribute !== true) throw new Error(`${expected.name} must use HTTP-only cookies.`);
  if (String(remote.same_site_cookie_attribute || "").toLowerCase() !== "strict") throw new Error(`${expected.name} must use SameSite=strict cookies.`);
}

export function findExactApplication(applications, expected) {
  if (!Array.isArray(applications)) throw new Error(`${expected.name} application collection is invalid.`);
  const domainMatches = applications.filter((item) => String(item?.domain ?? "").toLowerCase() === expected.domain);
  if (domainMatches.length > 1) throw new Error(`${expected.name} domain is claimed by duplicate Access applications.`);
  const siblingName = applications.find((item) => item?.name === expected.name && String(item?.domain ?? "").toLowerCase() !== expected.domain);
  if (siblingName) throw new Error(`${expected.name} is reused by a sibling Access application.`);
  return domainMatches[0] ?? null;
}

export function assertPolicyMatches(remote, expected) {
  if (remote.name !== expected.name) throw new Error(`${expected.name} policy name does not exactly match.`);
  if (remote.decision !== "allow") throw new Error(`${expected.name} policy must be an allow policy.`);
  if (Number(remote.precedence) !== 1) throw new Error(`${expected.name} policy must have precedence 1.`);
  if (String(remote.session_duration) !== expected.session_duration) throw new Error(`${expected.name} policy session duration does not exactly match.`);
  requireExactSelectorSet(remote.include, expected.include, `${expected.name} include policy`);
  requireExactSelectorSet(remote.require, expected.require, `${expected.name} require policy`);
  requireExactSelectorSet(remote.exclude, expected.exclude, `${expected.name} exclude policy`);
}

export function assertExactPolicyCollection(policies, expected) {
  if (!Array.isArray(policies)) throw new Error(`${expected.name} policy collection is invalid.`);
  const matches = policies.filter((policy) => policy?.name === expected.name);
  if (matches.length !== 1) throw new Error(`${expected.name} requires exactly one named policy; found ${matches.length}.`);
  if (policies.length !== 1) {
    const siblings = policies.filter((policy) => policy !== matches[0]).map((policy) => `${policy?.name ?? "unnamed"}:${policy?.decision ?? "unknown"}`);
    throw new Error(`${expected.name} has extra sibling policies: ${siblings.join(", ")}.`);
  }
  assertPolicyMatches(matches[0], expected);
  return matches[0];
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
    let remote = findExactApplication(apps, expectedApp);
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
      assertAppMatches(remote, expectedApp);
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
      if (policies.length !== 0) throw new Error(`${expectedPolicy.name} cannot be created beside existing sibling policies.`);
      const created = await cloudflareRequest({
        method: "POST",
        requestPath: `/accounts/${manifest.accountId}/access/apps/${remote.id}/policies`,
        token,
        body: expectedPolicy,
      });
      assertPolicyMatches(created.result, expectedPolicy);
      process.stdout.write(`Created Access allow policy ${expectedPolicy.name}.\n`);
      policyResult = "created";
    } else {
      assertExactPolicyCollection(policies, expectedPolicy);
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
      const remote = findExactApplication(apps, expectedApp);
      if (!remote) throw new Error(`Missing Cloudflare Access application: ${app.domain}`);
      assertAppMatches(remote, expectedApp);
      const policies = await listPolicies(manifest.accountId, remote.id, token);
      const expectedPolicy = policyPayload(app, manifest);
      const policy = assertExactPolicyCollection(policies, expectedPolicy);
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
  let routeReconciliation = null;
  try {
    const inventoryRecord = loadAdminAccessInventory(path.join(process.cwd(), DEFAULT_INVENTORY));
    routeReconciliation = reconcileAdminRouteInventory(
      inventoryRecord,
      fs.readFileSync(path.join(process.cwd(), ADMIN_ROUTES), "utf8"),
    );
    manifest = normalizeManifest(readJson(argv.manifest), argv, inventoryRecord);
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
    writeEvidenceReport({ mode, status, manifest, applications, routeReconciliation });
  } catch (error) {
    if (manifest) {
      writeEvidenceReport({
        mode,
        status: "failed",
        manifest,
        applications: error.applications ?? applications,
        routeReconciliation,
        issues: error.issues ?? [String(error?.message ?? error)],
      });
    }
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.message ?? error}\n`);
    process.exitCode = 1;
  });
}
