import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import http from "node:http";

const MAX_JSON_BYTES = 256 * 1024;
const MAX_LOG_BYTES = 32 * 1024;
const REQUEST_TIMEOUT_MS = 3000;
const ID_RE = /^[a-f0-9]{64}$/i;
const SINCE = { "15m": 15 * 60, "1h": 60 * 60, "24h": 24 * 60 * 60 };

export function redactText(value) {
  return redactSensitive(value);
}

function redactSensitive(text) {
  return String(text ?? "")
    .replace(/-----BEGIN [A-Z0-9 ]+-----[\s\S]*(?:-----END [A-Z0-9 ]+-----|$)/g, "[REDACTED PEM]")
    .replace(/\bhttps?:\/\/[^\s/@]+@/gi, (match) => match.slice(0, match.indexOf("://") + 3) + "[REDACTED]@")
    .replace(/\b(authorization|password|passwd|token|secret|client[_-]?secret|api[_-]?key|cookie)\s*[:=]\s*(?:Bearer\s+)?(?:"[^"]*"|'[^']*'|[^,;\r\n]+)/gi, "$1: [REDACTED]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[REDACTED JWT]");
}

function tokenDigest(value) { return createHash("sha256").update(String(value || "")).digest(); }
function isAuthorized(header, token) {
  const supplied = /^Bearer\s+(.+)$/i.exec(String(header || ""))?.[1] || "";
  return timingSafeEqual(tokenDigest(supplied), tokenDigest(token));
}
function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { "cache-control": "no-store", "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(body) });
  res.end(body);
}
function apiError(res, status, code, message) { sendJson(res, status, { error: code, message }); }
function dockerError() { const error = new Error("Docker observer unavailable."); error.expose = true; return error; }
function parseJson(buffer) { try { return JSON.parse(Buffer.from(buffer || "").toString("utf8")); } catch { throw dockerError(); } }
function string(value, max = 256) { return redactSensitive(String(value || "")).slice(0, max); }
function shortName(value) { return string(value).replace(/^\/+/, ""); }

function boundedDockerRequest({ socketPath, path, signal, maxBytes = MAX_JSON_BYTES, allowTruncation = false, timeoutMs = REQUEST_TIMEOUT_MS }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => { if (!settled) { settled = true; error ? reject(error) : resolve(value); } };
    const request = http.request({ socketPath, method: "GET", path, maxHeaderSize: 16 * 1024, headers: { accept: "application/json" }, timeout: timeoutMs }, (response) => {
      const chunks = []; let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > maxBytes) {
          if (!allowTruncation) { request.destroy(); finish(dockerError()); return; }
          const remaining = Math.max(0, maxBytes - (size - chunk.length));
          if (remaining) chunks.push(chunk.subarray(0, remaining));
          response.destroy(); finish(null, { statusCode: response.statusCode || 502, body: Buffer.concat(chunks), truncated: true }); return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => finish(null, { statusCode: response.statusCode || 502, body: Buffer.concat(chunks) }));
      response.on("error", () => finish(dockerError()));
    });
    request.on("timeout", () => { request.destroy(); finish(dockerError()); });
    request.on("error", () => finish(dockerError()));
    if (signal) signal.addEventListener("abort", () => { request.destroy(); finish(Object.assign(new Error("Request cancelled."), { name: "AbortError" })); }, { once: true });
    request.end();
  });
}

function normalizedContainer(row) {
  return { id: string(row.Id || row.ID, 64), name: shortName((row.Names || [])[0]), image: string(row.Image), state: string(row.State, 64), status: string(row.Status, 160) };
}
function healthLog(entries) {
  return (Array.isArray(entries) ? entries.slice(-3) : []).map((entry) => ({ start: string(entry.Start, 64), end: string(entry.End, 64), exitCode: Number(entry.ExitCode) || 0, output: redactSensitive(String(entry.Output || "")).slice(0, 2048) }));
}
function inspectView(value) {
  const state = value.State || {};
  const host = value.HostConfig || {};
  return {
    id: string(value.Id, 64), name: shortName(value.Name), image: string(value.Config?.Image || value.Image),
    state: { status: string(state.Status, 64), running: state.Running === true, paused: state.Paused === true, restarting: state.Restarting === true, exitCode: Number(state.ExitCode) || 0, restartCount: Number(value.RestartCount) || 0, startedAt: string(state.StartedAt, 64), finishedAt: string(state.FinishedAt, 64), health: state.Health ? { status: string(state.Health.Status, 32), failingStreak: Number(state.Health.FailingStreak) || 0, log: healthLog(state.Health.Log) } : null },
    limits: { memoryBytes: Number(host.Memory) || 0, nanoCpus: Number(host.NanoCpus) || 0, pidsLimit: typeof host.PidsLimit === "number" ? host.PidsLimit : null },
    mounts: (Array.isArray(value.Mounts) ? value.Mounts : []).slice(0, 32).map((mount) => ({ type: string(mount.Type, 32), destination: string(mount.Destination, 512) })),
  };
}
function statsView(value) {
  const cpu = value.cpu_stats || {}; const previous = value.precpu_stats || {};
  const cpuDelta = Number(cpu.cpu_usage?.total_usage || 0) - Number(previous.cpu_usage?.total_usage || 0);
  const systemDelta = Number(cpu.system_cpu_usage || 0) - Number(previous.system_cpu_usage || 0);
  const cpus = Number(cpu.online_cpus || cpu.cpu_usage?.percpu_usage?.length || 1);
  const networks = Object.values(value.networks || {}).reduce((total, network) => ({ rxBytes: total.rxBytes + Number(network.rx_bytes || 0), txBytes: total.txBytes + Number(network.tx_bytes || 0) }), { rxBytes: 0, txBytes: 0 });
  return { readAt: string(value.read, 64), cpuPercent: systemDelta > 0 ? Math.max(0, (cpuDelta / systemDelta) * cpus * 100) : 0, memoryUsageBytes: Number(value.memory_stats?.usage || 0), memoryLimitBytes: Number(value.memory_stats?.limit || 0), memoryPercent: Number(value.memory_stats?.limit || 0) ? (Number(value.memory_stats?.usage || 0) / Number(value.memory_stats.limit)) * 100 : 0, network: networks };
}
function multiplexLogs(buffer) {
  const chunks = []; let offset = 0; let frames = 0;
  const looksMultiplexed = buffer.length >= 4 && buffer[0] <= 2 && buffer[1] === 0 && buffer[2] === 0 && buffer[3] === 0;
  while (offset + 8 <= buffer.length && frames < 400) {
    const length = buffer.readUInt32BE(offset + 4);
    if (length > MAX_LOG_BYTES || offset + 8 + length > buffer.length) break;
    const type = buffer[offset];
    if (type > 2) break;
    chunks.push(buffer.subarray(offset + 8, offset + 8 + length)); offset += 8 + length; frames += 1;
  }
  // A capped body may end inside its first multiplexed frame. Do not expose
  // frame bytes as text in that case; completed frames are the only safe text.
  const raw = frames || looksMultiplexed ? Buffer.concat(chunks) : buffer;
  return redactSensitive(raw.toString("utf8").replace(/\u0000/g, "")).slice(0, MAX_LOG_BYTES);
}

export function createObserverServer(options = {}) {
  const tokenFile = options.tokenFile || process.env.SERVER_AI_OBSERVER_TOKEN_FILE;
  if (!tokenFile) throw new Error("SERVER_AI_OBSERVER_TOKEN_FILE is required.");
  const token = readFileSync(tokenFile, "utf8").trim();
  if (!token) throw new Error("SERVER_AI_OBSERVER_TOKEN_FILE is empty.");
  const dockerRequest = options.dockerRequest || ((request) => boundedDockerRequest({ socketPath: options.socketPath || process.env.SERVER_AI_DOCKER_SOCKET_PATH || "/var/run/docker.sock", ...request }));
  const requestedConcurrency = Number(options.maxConcurrent);
  const maxConcurrent = Number.isInteger(requestedConcurrency) && requestedConcurrency >= 1 && requestedConcurrency <= 4
    ? requestedConcurrency
    : 4;
  let inFlight = 0;
  async function docker(path, signal, maxBytes, allowTruncation = false) {
    const result = await dockerRequest({ method: "GET", path, signal, maxBytes, allowTruncation });
    if (!result || result.statusCode < 200 || result.statusCode >= 300) throw dockerError();
    const body = Buffer.from(result.body || ""); body.truncated = result.truncated === true; return body;
  }
  async function list(signal) { return parseJson(await docker("/containers/json?all=1&limit=100", signal)).slice(0, 100).map(normalizedContainer).filter((item) => ID_RE.test(item.id)); }
  async function known(id, signal) { const rows = await list(signal); if (!rows.some((row) => row.id.toLowerCase() === id.toLowerCase())) { const error = new Error("Container not found."); error.status = 404; throw error; } }
  const server = http.createServer({ maxHeaderSize: 16 * 1024 }, async (req, res) => {
    if (inFlight >= maxConcurrent) return apiError(res, 503, "observer_busy", "Observer busy.");
    inFlight += 1;
    const abort = new AbortController();
    const close = () => abort.abort();
    req.once("aborted", close);
    req.once("close", () => { if (!req.complete) close(); });
    res.once("close", () => { if (!res.writableEnded) close(); });
    try {
      if (req.method !== "GET") return apiError(res, 405, "method_not_allowed", "Only GET is supported.");
      if (req.headers["content-length"] && Number(req.headers["content-length"]) > 0 || req.headers["transfer-encoding"]) return apiError(res, 413, "body_not_allowed", "Request bodies are not supported.");
      const url = new URL(req.url || "/", "http://observer.invalid");
      if (url.pathname === "/healthz") return sendJson(res, 200, { ok: true, service: "server-ai-observer" });
      if (!isAuthorized(req.headers.authorization, token)) return apiError(res, 401, "unauthorized", "Authentication required.");
      if (url.pathname === "/containers" && !url.search) return sendJson(res, 200, { containers: await list(abort.signal) });
      const match = /^\/containers\/([a-f0-9]{64})\/(status|health|stats|logs)$/i.exec(url.pathname);
      if (!match) return apiError(res, 404, "not_found", "Route not found.");
      const [, id, resource] = match;
      await known(id, abort.signal);
      if (resource === "stats") return sendJson(res, 200, { stats: statsView(parseJson(await docker(`/containers/${id}/stats?stream=false&one-shot=true`, abort.signal))) });
      if (resource === "logs") {
        const since = url.searchParams.get("since") || "15m";
        if (!SINCE[since] || Array.from(url.searchParams.keys()).some((key) => key !== "since")) return apiError(res, 400, "invalid_since", "since must be 15m, 1h, or 24h.");
        const unixSince = Math.floor(Date.now() / 1000) - SINCE[since];
        const body = await docker(`/containers/${id}/logs?stdout=true&stderr=true&tail=200&timestamps=true&since=${unixSince}`, abort.signal, MAX_LOG_BYTES, true);
        return sendJson(res, 200, { logs: multiplexLogs(body), truncated: body.truncated === true, since });
      }
      const detail = inspectView(parseJson(await docker(`/containers/${id}/json`, abort.signal)));
      return sendJson(res, 200, resource === "health" ? { health: detail.state.health, state: detail.state.status } : { container: detail });
    } catch (error) {
      if (error?.name === "AbortError") return;
      return apiError(res, error?.status || 502, error?.status === 404 ? "not_found" : "observer_unavailable", error?.status === 404 ? "Container not found." : "Docker observer unavailable.");
    } finally { inFlight -= 1; }
  });
  server.maxHeadersCount = 64;
  server.headersTimeout = REQUEST_TIMEOUT_MS;
  server.requestTimeout = REQUEST_TIMEOUT_MS;
  server.keepAliveTimeout = 1000;
  return server;
}

if (import.meta.main) {
  const server = createObserverServer();
  server.listen(Number(process.env.SERVER_AI_OBSERVER_PORT || 8090), process.env.SERVER_AI_OBSERVER_HOST || "0.0.0.0");
}
