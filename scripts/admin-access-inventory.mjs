import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const INVENTORY_SCHEMA_VERSION = 1;

function cleanString(value, label) {
  const clean = String(value ?? "").trim();
  if (!clean) throw new Error(`${label} must be a non-empty string.`);
  return clean;
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function sha256Canonical(value) {
  return crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function duplicates(values) {
  const seen = new Set();
  const repeated = new Set();
  for (const value of values) {
    if (seen.has(value)) repeated.add(value);
    seen.add(value);
  }
  return [...repeated].sort();
}

function sortedUniqueStrings(values) {
  return [...new Set(values.map((value) => String(value).trim().toLowerCase()).filter(Boolean))].sort();
}

function exactSortedArray(actual, expected) {
  return Array.isArray(actual)
    && actual.length === expected.length
    && actual.every((value, index) => value === expected[index]);
}

function validateDomainSuffix(value, label) {
  const suffix = cleanString(value, label).toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(suffix) || suffix.includes("..")) {
    throw new Error(`${label} must be a plain DNS suffix without a protocol, path, or wildcard.`);
  }
  return suffix;
}

export function validateAdminAccessInventory(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("Admin access inventory must be a JSON object.");
  if (raw.schemaVersion !== INVENTORY_SCHEMA_VERSION) throw new Error(`Admin access inventory schemaVersion must be ${INVENTORY_SCHEMA_VERSION}.`);
  const inventoryId = cleanString(raw.inventoryId, "Admin access inventory inventoryId");
  const version = cleanString(raw.version, "Admin access inventory version");
  const routeDomainSuffix = validateDomainSuffix(raw.routeDomainSuffix, "Admin access inventory routeDomainSuffix");
  if (!Array.isArray(raw.applications) || raw.applications.length === 0) throw new Error("Admin access inventory applications must be non-empty.");
  if (!Array.isArray(raw.routes) || raw.routes.length === 0) throw new Error("Admin access inventory routes must be non-empty.");

  const applications = raw.applications.map((entry, index) => {
    const id = cleanString(entry?.id, `Admin access inventory applications[${index}].id`);
    const name = cleanString(entry?.name, `Admin access inventory applications[${index}].name`);
    const subdomain = cleanString(entry?.subdomain, `Admin access inventory applications[${index}].subdomain`).toLowerCase();
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(subdomain)) throw new Error(`Invalid admin application subdomain: ${subdomain}`);
    return { id, name, subdomain };
  });
  const duplicateApplicationIds = duplicates(applications.map((entry) => entry.id.toLowerCase()));
  const duplicateApplicationNames = duplicates(applications.map((entry) => entry.name.toLowerCase()));
  const duplicateApplicationSubdomains = duplicates(applications.map((entry) => entry.subdomain));
  if (duplicateApplicationIds.length || duplicateApplicationNames.length || duplicateApplicationSubdomains.length) {
    throw new Error(`Authoritative admin application inventory contains duplicates: ids=${duplicateApplicationIds.join(",") || "none"} names=${duplicateApplicationNames.join(",") || "none"} subdomains=${duplicateApplicationSubdomains.join(",") || "none"}`);
  }
  if (!applications.some((entry) => entry.id === "phppgadmin")) throw new Error("Authoritative admin application inventory must include phpPgAdmin.");

  const applicationById = new Map(applications.map((entry) => [entry.id, entry]));
  const routes = raw.routes.map((entry, index) => {
    const route = {
      id: cleanString(entry?.id, `Admin access inventory routes[${index}].id`),
      sourceFile: cleanString(entry?.sourceFile, `Admin access inventory routes[${index}].sourceFile`),
      router: cleanString(entry?.router, `Admin access inventory routes[${index}].router`),
      host: cleanString(entry?.host, `Admin access inventory routes[${index}].host`).toLowerCase(),
      pathPrefix: cleanString(entry?.pathPrefix, `Admin access inventory routes[${index}].pathPrefix`),
      service: cleanString(entry?.service, `Admin access inventory routes[${index}].service`),
      accessApplicationId: cleanString(entry?.accessApplicationId, `Admin access inventory routes[${index}].accessApplicationId`),
    };
    if (!route.pathPrefix.startsWith("/") || route.pathPrefix.includes("..")) throw new Error(`Invalid admin route pathPrefix: ${route.pathPrefix}`);
    const application = applicationById.get(route.accessApplicationId);
    if (!application) throw new Error(`Admin route ${route.id} references unknown Access application ${route.accessApplicationId}.`);
    if (route.host !== `${application.subdomain}.${routeDomainSuffix}`) {
      throw new Error(`Admin route ${route.id} host is not covered by Access application ${route.accessApplicationId}.`);
    }
    return route;
  });
  const duplicateRouteIds = duplicates(routes.map((entry) => entry.id.toLowerCase()));
  const duplicateRouterNames = duplicates(routes.map((entry) => entry.router.toLowerCase()));
  const duplicateRouteTuples = duplicates(routes.map(routeTuple));
  if (duplicateRouteIds.length || duplicateRouterNames.length || duplicateRouteTuples.length) {
    throw new Error(`Authoritative admin route inventory contains duplicates: ids=${duplicateRouteIds.join(",") || "none"} routers=${duplicateRouterNames.join(",") || "none"} tuples=${duplicateRouteTuples.join(",") || "none"}`);
  }
  if (!routes.some((entry) => entry.service === "enterprise-phppgadmin" && entry.pathPrefix === "/phppgadmin")) {
    throw new Error("Authoritative admin route inventory must include the phpPgAdmin surface.");
  }

  return {
    schemaVersion: INVENTORY_SCHEMA_VERSION,
    inventoryId,
    version,
    routeDomainSuffix,
    applications,
    routes,
  };
}

export function loadAdminAccessInventory(file) {
  const resolved = path.resolve(file);
  const raw = JSON.parse(fs.readFileSync(resolved, "utf8").replace(/^\uFEFF/, ""));
  const inventory = validateAdminAccessInventory(raw);
  return { inventory, sha256: sha256Canonical(raw), file: resolved };
}

function expectedApplications(inventory, domainSuffix) {
  const suffix = validateDomainSuffix(domainSuffix, "Cloudflare Access manifest domainSuffix");
  if (suffix !== inventory.routeDomainSuffix) {
    throw new Error("Cloudflare Access manifest domainSuffix must match the authoritative inventory routeDomainSuffix.");
  }
  return inventory.applications.map((entry) => ({
    id: entry.id,
    name: entry.name,
    domain: `${entry.subdomain}.${suffix}`,
  }));
}

export function assertExactAdminApplications(applications, inventoryRecord, options = {}) {
  const inventory = inventoryRecord?.inventory ?? inventoryRecord;
  const inventorySha256 = inventoryRecord?.sha256 ?? sha256Canonical(inventory);
  validateAdminAccessInventory(inventory);
  const expected = expectedApplications(inventory, options.domainSuffix);
  const binding = options.binding;
  if (!binding || typeof binding !== "object") throw new Error("Cloudflare Access manifest must bind the authoritative admin surface inventory.");
  if (binding.id !== inventory.inventoryId || binding.version !== inventory.version || binding.sha256 !== inventorySha256) {
    throw new Error("Cloudflare Access manifest admin surface inventory binding is stale or mismatched.");
  }
  if (!Array.isArray(applications)) throw new Error("Cloudflare Access manifest applications must be an array.");

  const actual = applications.map((entry, index) => ({
    name: cleanString(entry?.name, `Cloudflare Access applications[${index}].name`),
    domain: cleanString(entry?.domain, `Cloudflare Access applications[${index}].domain`).toLowerCase(),
  }));
  const duplicateNames = duplicates(actual.map((entry) => entry.name.toLowerCase()));
  const duplicateDomains = duplicates(actual.map((entry) => entry.domain));
  const expectedPairs = new Set(expected.map((entry) => `${entry.name}\u0000${entry.domain}`));
  const actualPairs = new Set(actual.map((entry) => `${entry.name}\u0000${entry.domain}`));
  const missing = expected.filter((entry) => !actualPairs.has(`${entry.name}\u0000${entry.domain}`));
  const unknown = actual.filter((entry) => !expectedPairs.has(`${entry.name}\u0000${entry.domain}`));
  if (duplicateNames.length || duplicateDomains.length || missing.length || unknown.length) {
    throw new Error(`Admin Access set mismatch: missing=${missing.map((entry) => entry.domain).sort().join(",") || "none"} duplicateNames=${duplicateNames.join(",") || "none"} duplicateDomains=${duplicateDomains.join(",") || "none"} unknown=${unknown.map((entry) => entry.domain).sort().join(",") || "none"}`);
  }

  return {
    inventory: { id: inventory.inventoryId, version: inventory.version, sha256: inventorySha256 },
    expectedApplications: expected,
    expectedDomains: expected.map((entry) => entry.domain).sort(),
    manifestDomains: actual.map((entry) => entry.domain).sort(),
    missingDomains: [],
    duplicateDomains: [],
    unknownDomains: [],
    expectedCount: expected.length,
    manifestCount: actual.length,
    manifestComplete: true,
  };
}

function routeTuple(route) {
  return [route.sourceFile, route.router, route.host, route.pathPrefix, route.service, route.accessApplicationId ?? ""].join("|");
}

function parsedRouteTuple(route) {
  return ["traefik/dynamic/admin-routes.yml", route.router, route.host, route.pathPrefix, route.service, route.accessApplicationId].join("|");
}

function parseDatabaseAdminRoutes(source, inventory) {
  const lines = String(source).replace(/\r\n?/g, "\n").split("\n");
  const routerStart = lines.findIndex((line) => /^  routers:\s*$/.test(line));
  if (routerStart < 0) throw new Error("Traefik admin routes file has no http.routers section.");
  const routerEndOffset = lines.slice(routerStart + 1).findIndex((line) => /^  [a-zA-Z][\w-]*:\s*$/.test(line));
  const routerEnd = routerEndOffset < 0 ? lines.length : routerStart + 1 + routerEndOffset;
  const blocks = [];
  let current = null;
  for (const line of lines.slice(routerStart + 1, routerEnd)) {
    if (/^    #/.test(line)) continue;
    if (/^    \S/.test(line)) {
      const header = line.match(/^    ([a-zA-Z0-9][a-zA-Z0-9_.-]*):\s*$/);
      if (!header) throw new Error("Traefik admin routes file contains an unsupported router declaration.");
      if (current) blocks.push(current);
      current = { router: header[1] };
      continue;
    }
    if (!current) continue;
    const rule = line.match(/^      rule:\s*Host\(`([^`]+)`\)(?:\s*&&\s*PathPrefix\(`([^`]+)`\))?\s*$/);
    if (rule) {
      current.host = rule[1].toLowerCase();
      current.pathPrefix = rule[2] || "";
    }
    const service = line.match(/^      service:\s*([^\s#]+)\s*$/);
    if (service) current.service = service[1];
  }
  if (current) blocks.push(current);
  const applicationById = new Map(inventory.applications.map((entry) => [entry.id, entry]));
  // This dedicated file is a closed inventory boundary. Filtering by canonical
  // service name would let a new router disappear behind an arbitrary alias.
  return blocks.map((entry) => {
    if (!entry.host || !entry.pathPrefix) throw new Error(`Database admin router ${entry.router} must use an exact Host and PathPrefix rule.`);
    const application = inventory.routes.find((route) => route.host === entry.host && route.pathPrefix === entry.pathPrefix)?.accessApplicationId;
    if (!application || !applicationById.has(application)) {
      return { ...entry, accessApplicationId: "<unmapped>" };
    }
    return { ...entry, accessApplicationId: application };
  });
}

export function reconcileAdminRouteInventory(inventoryRecord, adminRoutesSource) {
  const inventory = inventoryRecord?.inventory ?? inventoryRecord;
  validateAdminAccessInventory(inventory);
  const actual = parseDatabaseAdminRoutes(adminRoutesSource, inventory);
  const expectedTuples = inventory.routes.map(routeTuple).sort();
  const actualTuples = actual.map(parsedRouteTuple).sort();
  const duplicateRoutes = duplicates(actualTuples);
  const actualSet = new Set(actualTuples);
  const expectedSet = new Set(expectedTuples);
  const missingRoutes = expectedTuples.filter((entry) => !actualSet.has(entry));
  const unknownRoutes = actualTuples.filter((entry) => !expectedSet.has(entry));
  if (duplicateRoutes.length || missingRoutes.length || unknownRoutes.length) {
    throw new Error(`Admin route inventory mismatch: missing=${missingRoutes.join(",") || "none"} duplicate=${duplicateRoutes.join(",") || "none"} unknown=${unknownRoutes.join(",") || "none"}`);
  }
  return {
    expectedRoutes: expectedTuples,
    discoveredRoutes: actualTuples,
    missingRoutes: [],
    duplicateRoutes: [],
    unknownRoutes: [],
    expectedCount: expectedTuples.length,
    discoveredCount: actualTuples.length,
    complete: true,
  };
}

export function buildAdminAccessEvidence({ inventoryContract, routeReconciliation, applications, mode }) {
  const applicationResults = Array.isArray(applications) ? applications : [];
  const verifiedDomainsRaw = applicationResults
    .filter((entry) => entry?.result === "access-shape-verified")
    .map((entry) => String(entry.domain ?? "").trim().toLowerCase())
    .filter(Boolean);
  const verifiedDomains = sortedUniqueStrings(verifiedDomainsRaw);
  const duplicateVerifiedDomains = duplicates(verifiedDomainsRaw);
  const expectedDomains = [...inventoryContract.expectedDomains];
  const verifiedSet = new Set(verifiedDomains);
  const expectedSet = new Set(expectedDomains);
  const missingVerifiedDomains = expectedDomains.filter((domain) => !verifiedSet.has(domain));
  const unknownVerifiedDomains = verifiedDomains.filter((domain) => !expectedSet.has(domain));
  const complete = mode === "verifyRemote"
    && inventoryContract.manifestComplete === true
    && routeReconciliation.complete === true
    && duplicateVerifiedDomains.length === 0
    && missingVerifiedDomains.length === 0
    && unknownVerifiedDomains.length === 0
    && verifiedDomains.length === expectedDomains.length;
  return {
    inventory: inventoryContract.inventory,
    expectedDomains,
    manifestDomains: [...inventoryContract.manifestDomains],
    verifiedDomains,
    missingDomains: missingVerifiedDomains,
    duplicateDomains: duplicateVerifiedDomains,
    unknownDomains: unknownVerifiedDomains,
    expectedCount: expectedDomains.length,
    manifestCount: inventoryContract.manifestCount,
    verifiedCount: verifiedDomains.length,
    manifestComplete: inventoryContract.manifestComplete === true,
    routeCoverage: routeReconciliation,
    complete,
  };
}

export function evaluateAdminAccessEvidence(payload, inventoryRecord) {
  try {
    const inventory = inventoryRecord?.inventory ?? inventoryRecord;
    const inventorySha256 = inventoryRecord?.sha256 ?? sha256Canonical(inventory);
    validateAdminAccessInventory(inventory);
    const coverage = payload?.adminSurfaceCoverage;
    if (!coverage || typeof coverage !== "object") return { ok: false, reason: "missing adminSurfaceCoverage" };
    if (coverage.inventory?.id !== inventory.inventoryId || coverage.inventory?.version !== inventory.version || coverage.inventory?.sha256 !== inventorySha256) {
      return { ok: false, reason: "inventory binding mismatch" };
    }
    const domainSuffix = payload?.manifest?.domainSuffix;
    const expected = expectedApplications(inventory, domainSuffix);
    const expectedDomains = expected.map((entry) => entry.domain).sort();
    const reportApps = Array.isArray(payload?.applications) ? payload.applications : [];
    const appDomains = reportApps.map((entry) => String(entry?.domain ?? "").trim().toLowerCase()).filter(Boolean);
    const verifiedDomains = reportApps.filter((entry) => entry?.result === "access-shape-verified").map((entry) => String(entry.domain ?? "").trim().toLowerCase()).filter(Boolean).sort();
    const duplicateReportDomains = duplicates(appDomains);
    const expectedPairs = expected.map((entry) => `${entry.name}\u0000${entry.domain}`).sort();
    const reportPairs = reportApps.map((entry) => `${String(entry?.name ?? "").trim()}\u0000${String(entry?.domain ?? "").trim().toLowerCase()}`).sort();
    const routeCoverage = coverage.routeCoverage;
    const expectedRouteTuples = inventory.routes.map(routeTuple).sort();
    const checks = [
      [payload?.mode === "verifyRemote", "mode is not verifyRemote"],
      [coverage.complete === true && coverage.manifestComplete === true, "coverage is not complete"],
      [coverage.expectedCount === expectedDomains.length && coverage.manifestCount === expectedDomains.length && coverage.verifiedCount === expectedDomains.length, "coverage counts mismatch"],
      [exactSortedArray(coverage.expectedDomains, expectedDomains), "expected domain set mismatch"],
      [exactSortedArray(coverage.manifestDomains, expectedDomains), "manifest domain set mismatch"],
      [exactSortedArray(coverage.verifiedDomains, expectedDomains), "verified domain set mismatch"],
      [Array.isArray(coverage.missingDomains) && coverage.missingDomains.length === 0, "reported missing domains"],
      [Array.isArray(coverage.duplicateDomains) && coverage.duplicateDomains.length === 0 && duplicateReportDomains.length === 0, "reported duplicate domains"],
      [Array.isArray(coverage.unknownDomains) && coverage.unknownDomains.length === 0, "reported unknown domains"],
      [exactSortedArray(verifiedDomains, expectedDomains), "application results are incomplete"],
      [exactSortedArray(reportPairs, expectedPairs), "application identity set mismatch"],
      [routeCoverage?.complete === true, "route coverage is not complete"],
      [exactSortedArray(routeCoverage?.expectedRoutes, expectedRouteTuples), "expected route set mismatch"],
      [exactSortedArray(routeCoverage?.discoveredRoutes, expectedRouteTuples), "discovered route set mismatch"],
      [routeCoverage?.expectedCount === expectedRouteTuples.length && routeCoverage?.discoveredCount === expectedRouteTuples.length, "route counts mismatch"],
      [Array.isArray(routeCoverage?.missingRoutes) && routeCoverage.missingRoutes.length === 0, "reported missing routes"],
      [Array.isArray(routeCoverage?.duplicateRoutes) && routeCoverage.duplicateRoutes.length === 0, "reported duplicate routes"],
      [Array.isArray(routeCoverage?.unknownRoutes) && routeCoverage.unknownRoutes.length === 0, "reported unknown routes"],
    ];
    const failure = checks.find(([passed]) => !passed);
    return failure ? { ok: false, reason: failure[1] } : { ok: true, reason: "exact inventory-bound Access evidence" };
  } catch (error) {
    return { ok: false, reason: String(error?.message ?? error) };
  }
}
