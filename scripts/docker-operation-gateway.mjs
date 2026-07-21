#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_TOKEN_FILE = "/run/secrets/docker_gateway_token";
const DEFAULT_JOBS_DIR = "/var/www/project-state/backup-jobs";
const MAX_BODY_BYTES = 16 * 1024;
const MAX_CLOCK_SKEW_MS = 60_000;
const REPLAY_TTL_MS = 5 * 60_000;

const OPERATIONS = new Map([
  ["backup-platform-catalog", { args: ["backup-platform-catalog"] }],
  ["prune-manifest-backups-plan", { args: ["prune-manifest-backups"] }],
  ["prune-manifest-backups-apply", { args: ["prune-manifest-backups", "--confirmPruneManifestBackups"] }],
  ["full-restore-drill", { args: ["full-restore-drill"] }],
  ["offsite-backup-restic", { args: ["offsite-backup-restic"] }],
  ["execute-backup-job", { jobFile: true, args: ["execute-backup-job"] }],
]);

export function operationNames() {
  return [...OPERATIONS.keys()];
}

export function normalizeOperationRequest(value, { now = Date.now(), jobsDir = DEFAULT_JOBS_DIR } = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw requestError(400, "request must be an object");
  assertExactKeys(value, ["issuedAt", "operation", "parameters", "requestId", "version"], "request");
  if (value.version !== 1) throw requestError(400, "unsupported request version");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value.requestId ?? ""))) {
    throw requestError(400, "requestId must be a UUID v4");
  }
  const issuedAtMs = Date.parse(String(value.issuedAt ?? ""));
  if (!Number.isFinite(issuedAtMs) || Math.abs(now - issuedAtMs) > MAX_CLOCK_SKEW_MS) {
    throw requestError(401, "request timestamp is outside the accepted window");
  }
  const operation = String(value.operation ?? "");
  const contract = OPERATIONS.get(operation);
  if (!contract) throw requestError(403, "operation is not authorized");
  const parameters = value.parameters;
  if (!parameters || typeof parameters !== "object" || Array.isArray(parameters)) throw requestError(400, "parameters must be an object");
  if (contract.jobFile) {
    assertExactKeys(parameters, ["jobFileName"], "parameters");
    const jobFileName = String(parameters.jobFileName ?? "");
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$/.test(jobFileName) || jobFileName.includes("..")) {
      throw requestError(400, "jobFileName is invalid");
    }
    return {
      requestId: value.requestId,
      operation,
      args: [...contract.args, "--jobFile", path.join(path.resolve(jobsDir), "running", jobFileName)],
    };
  }
  assertExactKeys(parameters, [], "parameters");
  return { requestId: value.requestId, operation, args: [...contract.args] };
}

export function authorizeBearer(header, expectedToken) {
  const match = /^Bearer ([^\s]+)$/.exec(String(header ?? ""));
  const actual = Buffer.from(match?.[1] ?? "");
  const expected = Buffer.from(String(expectedToken ?? ""));
  return expected.length >= 32 && actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

export function validateJobFilePath(filePath, jobsDir = DEFAULT_JOBS_DIR) {
  const runningDir = path.join(path.resolve(jobsDir), "running");
  const parent = fs.realpathSync.native(path.dirname(filePath));
  const expectedParent = fs.realpathSync.native(runningDir);
  const stat = fs.lstatSync(filePath, { throwIfNoEntry: false });
  if (parent !== expectedParent || !stat?.isFile() || stat.isSymbolicLink()) {
    throw requestError(400, "job file is not a regular file in the running queue");
  }
  return filePath;
}

export function createDockerOperationGateway({
  token,
  jobsDir = DEFAULT_JOBS_DIR,
  now = () => Date.now(),
  runOperation = defaultRunOperation,
} = {}) {
  if (String(token ?? "").length < 32) throw new Error("Docker operation gateway token must contain at least 32 characters.");
  const replay = new Map();
  let busy = false;
  return http.createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/healthz") return json(res, 200, { status: "ok" });
    if (req.method !== "POST" || req.url !== "/v1/operations") return json(res, 404, { error: "not found" });
    if (!authorizeBearer(req.headers.authorization, token)) return json(res, 401, { error: "unauthorized" });
    if (String(req.headers["content-type"] ?? "").split(";", 1)[0].trim().toLowerCase() !== "application/json") {
      return json(res, 415, { error: "application/json required" });
    }
    try {
      const body = await readJsonBody(req);
      const operation = normalizeOperationRequest(body, { now: now(), jobsDir });
      purgeReplay(replay, now());
      if (replay.has(operation.requestId)) throw requestError(409, "request replay rejected");
      replay.set(operation.requestId, now());
      if (busy) throw requestError(409, "another platform operation is running");
      busy = true;
      try {
        const result = await runOperation(operation);
        if (result?.status !== 0) return json(res, 500, { status: "failed", operation: operation.operation });
        return json(res, 200, { status: "completed", operation: operation.operation });
      } finally {
        busy = false;
      }
    } catch (error) {
      return json(res, Number(error?.statusCode) || 400, { error: String(error?.message ?? "invalid request") });
    }
  });
}

function defaultRunOperation(operation) {
  const infraRoot = path.resolve(process.env.PLATFORM_INFRA_ROOT || path.join(scriptDir, ".."));
  const env = gatewayChildEnvironment();
  if (operation.operation === "execute-backup-job") {
    validateJobFilePath(operation.args.at(-1), process.env.BACKUP_SCHEDULER_JOBS_DIR || DEFAULT_JOBS_DIR);
  }
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(infraRoot, "scripts", "infra-ops.mjs"), ...operation.args], {
      cwd: infraRoot,
      env,
      stdio: ["ignore", "inherit", "inherit"],
    });
    child.once("error", reject);
    child.once("exit", (status, signal) => resolve({ status: Number.isInteger(status) ? status : 1, signal }));
  });
}

function gatewayChildEnvironment() {
  const env = { ...process.env, PLATFORM_DOCKER_GATEWAY_CHILD: "1", DOCKER_HOST: "unix:///var/run/docker.sock" };
  const mappings = [
    ["PLATFORM_INFRA_HOST_ROOT", env.PLATFORM_INFRA_CONTAINER_ROOT || env.PLATFORM_INFRA_ROOT || "/infra"],
    ["PROJECT_SOURCE_HOST_ROOT", env.PROJECT_SOURCE_ROOT || "/project"],
  ];
  for (const [name, destination] of mappings) {
    if (env[name]) continue;
    const source = detectOwnMountSource(destination);
    if (source) env[name] = source;
  }
  return env;
}

function detectOwnMountSource(destination) {
  const containerId = String(process.env.HOSTNAME || "").trim();
  if (!containerId) return "";
  const format = `{{range .Mounts}}{{if eq .Destination ${JSON.stringify(destination)}}}{{.Source}}{{end}}{{end}}`;
  const result = spawnSync("docker", ["inspect", containerId, "--format", format], { encoding: "utf8", timeout: 5000 });
  return result.status === 0 ? String(result.stdout || "").trim() : "";
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) throw requestError(400, `${label} contains unsupported fields`);
}

function requestError(statusCode, message) {
  return Object.assign(new Error(message), { statusCode });
}

function purgeReplay(replay, now) {
  for (const [requestId, timestamp] of replay) if (now - timestamp > REPLAY_TTL_MS) replay.delete(requestId);
}

async function readJsonBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw requestError(413, "request body is too large");
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw requestError(400, "request body is not valid JSON");
  }
}

function json(res, statusCode, value) {
  const body = Buffer.from(`${JSON.stringify(value)}\n`);
  res.writeHead(statusCode, { "Content-Type": "application/json", "Content-Length": body.length, "Cache-Control": "no-store" });
  res.end(body);
}

function readToken(filePath) {
  const token = fs.readFileSync(filePath, "utf8").trim();
  if (token.length < 32) throw new Error("Docker operation gateway token is missing or too short.");
  return token;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const host = process.env.DOCKER_GATEWAY_HOST || "0.0.0.0";
  const port = Number(process.env.DOCKER_GATEWAY_PORT || 8787);
  const server = createDockerOperationGateway({
    token: readToken(process.env.DOCKER_GATEWAY_TOKEN_FILE || DEFAULT_TOKEN_FILE),
    jobsDir: process.env.BACKUP_SCHEDULER_JOBS_DIR || DEFAULT_JOBS_DIR,
  });
  server.listen(port, host, () => process.stdout.write(`typed Docker operation gateway listening on ${host}:${port}\n`));
}
