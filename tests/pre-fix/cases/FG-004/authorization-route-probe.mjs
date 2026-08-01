#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import process from "node:process";
import vm from "node:vm";

const VULNERABLE_REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const VULNERABLE_TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";

const operations = [
  {
    id: "CAN-016",
    name: "Vault reveal",
    path: "/control/vault/secrets/demo-item/reveal",
    routeNeedle: 'if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[2], parts[4]], "control", "vault", "secrets", "reveal"))',
  },
  {
    id: "CAN-017",
    name: "Vault create/overwrite",
    path: "/control/vault/secrets",
    routeNeedle: 'if (method === "POST" && route(parts, "control", "vault", "secrets"))',
  },
  {
    id: "CAN-018",
    name: "Vault import",
    path: "/control/vault/import-existing",
    routeNeedle: 'if (method === "POST" && route(parts, "control", "vault", "import-existing"))',
  },
  {
    id: "CAN-019",
    name: "Vault delete",
    path: "/control/vault/secrets/demo-item/delete",
    routeNeedle: 'if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[2], parts[4]], "control", "vault", "secrets", "delete"))',
  },
  {
    id: "CAN-020",
    name: "Database create",
    path: "/control/databases",
    routeNeedle: 'if (method === "POST" && route(parts, "control", "databases"))',
  },
  {
    id: "CAN-021",
    name: "Backup file delete",
    path: "/control/backups/files/delete",
    routeNeedle: 'if (method === "POST" && route(parts, "control", "backups", "files", "delete"))',
  },
  {
    id: "CAN-022",
    name: "Broad backup run",
    path: "/control/backups/run",
    routeNeedle: 'if (method === "POST" && route(parts, "control", "backups", "run"))',
  },
  {
    id: "CAN-023",
    name: "Database backup",
    path: "/control/databases/demo-db/backup",
    routeNeedle: 'if (method === "POST" && parts.length === 4 && route([parts[0], parts[1], parts[3]], "control", "databases", "backup"))',
  },
];

const negativeControls = [
  "/actions/vault-command",
  "/actions/database-command",
  "/actions/backup-command",
];

function usage(exitCode = 0) {
  const stream = exitCode === 0 ? process.stdout : process.stderr;
  stream.write(`Usage: node authorization-route-probe.mjs [options]\n\n`);
  stream.write(`Options:\n`);
  stream.write(`  --source-root PATH       Git checkout to inspect (required)\n`);
  stream.write(`  --revision REV           Commit/tag/tree-ish to inspect (default: vulnerable revision)\n`);
  stream.write(`  --expect vulnerable|fixed|either\n`);
  stream.write(`                           Required matrix result (default: vulnerable)\n`);
  stream.write(`  --help                   Show this help\n`);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const options = {
    sourceRoot: "",
    revision: VULNERABLE_REVISION,
    expect: "vulnerable",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--help") usage(0);
    if (!["--source-root", "--revision", "--expect"].includes(value)) {
      throw new Error(`Unknown argument: ${value}`);
    }
    const next = argv[index + 1];
    if (!next) throw new Error(`Missing value for ${value}`);
    index += 1;
    if (value === "--source-root") options.sourceRoot = next;
    if (value === "--revision") options.revision = next;
    if (value === "--expect") options.expect = next;
  }
  if (!["vulnerable", "fixed", "either"].includes(options.expect)) {
    throw new Error("--expect must be vulnerable, fixed, or either");
  }
  if (!options.sourceRoot) throw new Error("--source-root is required");
  return options;
}

function git(sourceRoot, ...args) {
  return execFileSync("git", ["-C", sourceRoot, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trimEnd();
}

function revisionFile(sourceRoot, revision, path) {
  return git(sourceRoot, "show", `${revision}:${path}`);
}

function extractBlock(source, marker) {
  const start = source.indexOf(marker);
  if (start < 0) throw new Error(`Source marker not found: ${marker}`);
  const opening = source.indexOf("{", start + marker.length);
  if (opening < 0) throw new Error(`Opening brace not found for: ${marker}`);

  let depth = 0;
  let quote = "";
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let index = opening; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1] || "";

    if (lineComment) {
      if (char === "\n") lineComment = false;
      continue;
    }
    if (blockComment) {
      if (char === "*" && next === "/") {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (quote) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === "\\") {
        escaped = true;
        continue;
      }
      if (char === quote) quote = "";
      continue;
    }
    if (char === "/" && next === "/") {
      lineComment = true;
      index += 1;
      continue;
    }
    if (char === "/" && next === "*") {
      blockComment = true;
      index += 1;
      continue;
    }
    if (["'", '"', "`"].includes(char)) {
      quote = char;
      continue;
    }
    if (char === "{") depth += 1;
    if (char === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(start, index + 1);
    }
  }
  throw new Error(`Unterminated source block: ${marker}`);
}

function compileAuthorization(authSource, serverSource) {
  const authorizeMethod = extractBlock(authSource, "authorize(req, url, session)");
  const sensitiveFunction = extractBlock(authSource, "function isSensitivePath(pathname)");
  const normalizeFunction = extractBlock(serverSource, "function normalizeControlApiParts(parts)");

  const context = vm.createContext({});
  vm.runInContext(`
    function denied(status, message, extra = {}) {
      return { ok: false, status, message, role: "", identity: null, ...extra };
    }
    ${sensitiveFunction}
    ${normalizeFunction}
    const authHarness = {
      config: { freshAuthSeconds: 300 },
      ${authorizeMethod}
    };
    globalThis.invokeAuthorization = (method, pathname, role, authTime) =>
      authHarness.authorize(
        { method },
        { pathname },
        { ok: true, status: 200, role, identity: { authTime } }
      );
    globalThis.normalizePath = (pathname) =>
      "/" + normalizeControlApiParts(pathname.split("/").filter(Boolean)).join("/");
  `, context, { timeout: 1000 });

  return {
    authorize(method, pathname, role, authTime) {
      context.input = { method, pathname, role, authTime };
      return vm.runInContext(
        "invokeAuthorization(input.method, input.pathname, input.role, input.authTime)",
        context,
        { timeout: 1000 },
      );
    },
    normalize(pathname) {
      context.inputPath = pathname;
      return vm.runInContext("normalizePath(inputPath)", context, { timeout: 1000 });
    },
  };
}

function versionedPath(pathname) {
  return pathname.replace(/^\/control(?=\/|$)/, "/control/v1");
}

function status(decision) {
  return decision?.ok ? 200 : decision?.status;
}

function actorMatrix(harness, pathname, now) {
  return {
    viewer: status(harness.authorize("POST", pathname, "viewer", new Date(now - 30_000).toISOString())),
    admin: status(harness.authorize("POST", pathname, "admin", new Date(now - 30_000).toISOString())),
    staleOwner: status(harness.authorize("POST", pathname, "owner", new Date(now - 600_000).toISOString())),
    freshOwner: status(harness.authorize("POST", pathname, "owner", new Date(now - 30_000).toISOString())),
  };
}

function isVulnerableRow(row) {
  return row.viewer === 403 && row.admin === 200 && row.staleOwner === 200 && row.freshOwner === 200;
}

function isFixedRow(row) {
  return row.viewer === 403 && row.admin === 403 && row.staleOwner === 428 && row.freshOwner === 200;
}

function assertSourceShape(authSource, serverSource) {
  const rawAuthorization = "const sensitive = isSensitivePath(url.pathname);";
  if (!authSource.includes(rawAuthorization)) {
    throw new Error(`Expected vulnerable authorization expression was not found: ${rawAuthorization}`);
  }
  const authorizeCall = serverSource.indexOf("controlAuth.authorize(req, url, session)");
  const apiNormalization = serverSource.indexOf("const parts = normalizeControlApiParts(url.pathname.split");
  if (authorizeCall < 0 || apiNormalization < 0 || authorizeCall >= apiNormalization) {
    throw new Error("Could not prove that raw-path authorization occurs before API normalization");
  }
  for (const operation of operations) {
    if (!serverSource.includes(operation.routeNeedle)) {
      throw new Error(`${operation.id} route branch not found in server source`);
    }
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const revision = git(options.sourceRoot, "rev-parse", `${options.revision}^{commit}`).trim();
  const tree = git(options.sourceRoot, "rev-parse", `${revision}^{tree}`).trim();
  const authSource = revisionFile(options.sourceRoot, revision, "control-center/auth/oidc.mjs");
  const serverSource = revisionFile(options.sourceRoot, revision, "control-center/server.mjs");
  assertSourceShape(authSource, serverSource);
  const harness = compileAuthorization(authSource, serverSource);
  const now = Date.now();

  console.log(`[+] revision: ${revision}`);
  console.log(`[+] tree:     ${tree}`);
  if (revision === VULNERABLE_REVISION && tree !== VULNERABLE_TREE) {
    throw new Error("Pinned vulnerable commit resolved to an unexpected tree");
  }
  console.log("[+] raw-path authorization is before /control/v1 normalization");
  console.log("ID       alias       viewer admin stale-owner fresh-owner normalized");

  const rows = [];
  for (const operation of operations) {
    const aliases = [operation.path, versionedPath(operation.path)];
    for (const pathname of aliases) {
      const matrix = actorMatrix(harness, pathname, now);
      const normalized = harness.normalize(pathname);
      const normalizedOk = normalized === operation.path;
      rows.push({ id: operation.id, pathname, ...matrix, normalizedOk });
      const alias = pathname.startsWith("/control/v1/") ? "v1" : "legacy-api";
      console.log(
        `${operation.id.padEnd(8)} ${alias.padEnd(11)} ${String(matrix.viewer).padEnd(6)} ` +
        `${String(matrix.admin).padEnd(5)} ${String(matrix.staleOwner).padEnd(11)} ` +
        `${String(matrix.freshOwner).padEnd(11)} ${normalizedOk ? "yes" : "NO"}`,
      );
    }
  }

  console.log("[+] legacy sensitive negative controls");
  for (const pathname of negativeControls) {
    const matrix = actorMatrix(harness, pathname, now);
    console.log(`    ${pathname}: admin=${matrix.admin} stale-owner=${matrix.staleOwner} fresh-owner=${matrix.freshOwner}`);
    if (matrix.admin !== 403 || matrix.staleOwner !== 428 || matrix.freshOwner !== 200) {
      throw new Error(`Legacy negative control failed for ${pathname}`);
    }
  }

  const aliasesNormalize = rows.every((row) => row.normalizedOk);
  const vulnerable = aliasesNormalize && rows.every(isVulnerableRow);
  const fixed = aliasesNormalize && rows.every(isFixedRow);
  const observed = vulnerable ? "vulnerable" : fixed ? "fixed" : "partial-or-unrecognized";
  const label = observed === "vulnerable" ? "VULNERABLE" : observed === "fixed" ? "FIXED" : "INDETERMINATE";
  console.log(`[${label}] observed matrix: ${observed}`);

  if (options.expect !== "either" && observed !== options.expect) {
    throw new Error(`Expected ${options.expect}, observed ${observed}`);
  }
  if (options.expect === "either" && observed === "partial-or-unrecognized") {
    throw new Error("Observed neither the vulnerable nor the fixed role/freshness matrix");
  }
  console.log(`[+] expectation matched: ${options.expect}`);
}

try {
  main();
} catch (error) {
  console.error(`[-] ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
