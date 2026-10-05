import { readFileSync } from "node:fs";
import { redactText } from "./web.mjs";

const SOURCE_BASE = "http://project-source-reader:8110";
const QUERY_BASE = "http://project-query-reader:8111";
const PROJECT = /^[a-z0-9][a-z0-9-]{0,63}$/;
const HASH = /^[a-f0-9]{64}$/i;
const SAFE_ERRORS = new Set(["PROJECT_UNAVAILABLE", "NOT_FOUND", "DENIED_PATH", "INPUT_LIMIT", "STALE_SOURCE", "QUERY_REJECTED", "TIMEOUT", "RESULT_LIMIT", "DB_UNAVAILABLE", "GIT_UNAVAILABLE"]);
const MAX_CONTENT_BYTES = 32 * 1024;
export class ProjectReaderError extends Error { constructor(code = "PROJECT_UNAVAILABLE") { super("Risorsa progetto non disponibile."); this.code = SAFE_ERRORS.has(code) ? code : "PROJECT_UNAVAILABLE"; } }
function fixed(base, pathname) { const url = new URL(pathname, base); if (url.href !== `${base}${pathname}`) throw new ProjectReaderError(); return url; }
function token(file, readFile) { const value = readFile(file, "utf8").trim(); if (value.length < 32 || value.length > 512 || /\s/.test(value)) throw new ProjectReaderError(); return value; }
function checkProject(projectId) { if (!PROJECT.test(projectId || "")) throw new ProjectReaderError(); }
function clipUtf8(value, maxBytes) { let text = String(value || ""); while (Buffer.byteLength(text) > maxBytes) text = text.slice(0, -1); return text; }
async function boundedJson(response, maxBytes = 64 * 1024) {
  if (!response.ok) { await response.body?.cancel?.(); throw new ProjectReaderError(); }
  if (!String(response.headers.get("content-type") || "").includes("application/json") || !response.body) throw new ProjectReaderError();
  const reader = response.body.getReader(); const chunks = []; let bytes = 0;
  try {
    for (;;) { const { done, value } = await reader.read(); if (done) break; bytes += value.byteLength; if (bytes > maxBytes) throw new ProjectReaderError("RESULT_LIMIT"); chunks.push(Buffer.from(value)); }
  } finally { await reader.cancel().catch(() => {}); }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw new ProjectReaderError(); }
}
function source(item, projectId) { if (!item || typeof item !== "object" || Array.isArray(item) || typeof item.sourceId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(item.sourceId) || !["file", "git", "database"].includes(item.kind) || typeof item.sha256 !== "string" || !HASH.test(item.sha256)) throw new ProjectReaderError(); const path = typeof item.path === "string" && item.path.length <= 512 && !item.path.startsWith("/") && !item.path.includes("..") ? item.path : ""; const startLine = Number.isInteger(item.startLine) && item.startLine > 0 && item.startLine <= 1_000_000 ? item.startLine : null; const endLine = Number.isInteger(item.endLine) && startLine && item.endLine >= startLine && item.endLine <= 1_000_000 ? item.endLine : null; return { id: item.sourceId, type: "project", projectId, kind: item.kind, title: String(item.title || path || item.kind).slice(0, 300), path, startLine, endLine, sha256: item.sha256.toLowerCase() }; }
function databaseSource(item, projectId, databaseId, dialect, operation) { return { ...source(item, projectId), databaseId, dialect, operation }; }
function schemaItem(item, projectId, databaseId, dialect) { const content = typeof item.content === "string" ? clipUtf8(redactText(item.content, MAX_CONTENT_BYTES * 2), MAX_CONTENT_BYTES) : ""; let parsed; try { parsed = JSON.parse(content); } catch { throw new ProjectReaderError(); } if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || parsed.schemaVersion !== 1 || parsed.databaseId !== databaseId || parsed.dialect !== dialect || typeof parsed.truncated !== "boolean" || !["tables", "columns", "indexes", "relationships", "stats"].every(key => Array.isArray(parsed[key]))) throw new ProjectReaderError(); return { ...databaseSource(item, projectId, databaseId, dialect, "schema"), content, truncated: parsed.truncated }; }

export function createProjectReaders({ tokenFile = "/run/secrets/server_ai_project_readers_token", sourceUrl = SOURCE_BASE, queryUrl = QUERY_BASE, fetchImpl = fetch, readFile = readFileSync } = {}) {
  if (tokenFile !== "/run/secrets/server_ai_project_readers_token") throw new TypeError("Token reader progetto non consentito.");
  if (sourceUrl !== SOURCE_BASE || queryUrl !== QUERY_BASE) throw new TypeError("Endpoint reader progetto non consentito.");
  async function call(base, pathname, body, signal, { collection = "items", limit = 32, requiresProjectId = true } = {}) {
    if (requiresProjectId) checkProject(body.projectId);
    const response = await fetchImpl(fixed(base, pathname), { method: "POST", signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(8000)]) : AbortSignal.timeout(8000), redirect: "error", headers: { authorization: `Bearer ${token(tokenFile, readFile)}`, "content-type": "application/json", accept: "application/json" }, body: JSON.stringify(body) });
    const value = await boundedJson(response);
    if (!value || value.available !== true || (requiresProjectId && value.projectId !== body.projectId) || !Array.isArray(value[collection]) || value[collection].length > limit) throw new ProjectReaderError(value?.code);
    return value;
  }
  return Object.freeze({
    async projectsCatalog({ cursor, limit = 64, signal } = {}) {
      if (cursor !== undefined && (typeof cursor !== "string" || !/^[A-Za-z0-9_-]{1,1024}$/.test(cursor))) throw new ProjectReaderError("INPUT_LIMIT");
      if (!Number.isInteger(limit) || limit < 1 || limit > 64) throw new ProjectReaderError("INPUT_LIMIT");
      const result = await call(sourceUrl, "/v1/projects/catalog", { ...(cursor ? { cursor } : {}), limit }, signal, { collection: "projects", limit, requiresProjectId: false });
      if (Object.keys(result).some(key => !["available", "projects", "nextCursor"].includes(key))) throw new ProjectReaderError();
      if (result.nextCursor !== null && (typeof result.nextCursor !== "string" || !/^[A-Za-z0-9_-]{1,1024}$/.test(result.nextCursor))) throw new ProjectReaderError();
      const ids = new Set();
      const projects = result.projects.flatMap(item => {
        if (!item || typeof item !== "object" || Array.isArray(item) || Object.keys(item).some(key => !["id", "filesAvailable"].includes(key)) || !PROJECT.test(item.id || "") || item.filesAvailable !== true || ids.has(item.id)) throw new ProjectReaderError();
        ids.add(item.id); return [{ id: item.id, filesAvailable: true }];
      });
      return { projects, nextCursor: result.nextCursor || null };
    },
    async filesIndex({ projectId, cursor, limit = 50, signal } = {}) {
      if (cursor !== undefined && (typeof cursor !== "string" || !/^[A-Za-z0-9_-]{1,1024}$/.test(cursor))) throw new ProjectReaderError("INPUT_LIMIT");
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new ProjectReaderError("INPUT_LIMIT");
      const result = await call(sourceUrl, "/v1/files/index", { projectId, ...(cursor ? { cursor } : {}), limit }, signal, { collection: "entries", limit });
      if (result.nextCursor !== null && (typeof result.nextCursor !== "string" || !/^[A-Za-z0-9_-]{1,1024}$/.test(result.nextCursor))) throw new ProjectReaderError();
      return { entries: result.entries.map(item => { const citation = source({ ...item, kind: "file", title: item.path }, projectId); if (!citation.path || !Number.isSafeInteger(item.size) || item.size < 0 || item.size > 2 * 1024 * 1024 || !Number.isFinite(item.mtimeMs)) throw new ProjectReaderError(); return { ...citation, size: item.size, mtimeMs: item.mtimeMs, language: typeof item.language === "string" ? item.language.slice(0, 48) : "" }; }), nextCursor: result.nextCursor || null };
    },
    async filesSearch({ projectId, query, maxResults = 8, signal } = {}) { if (typeof query !== "string" || !query.trim() || query.length > 400 || !Number.isInteger(maxResults) || maxResults < 1 || maxResults > 16) throw new ProjectReaderError("INPUT_LIMIT"); const result = await call(sourceUrl, "/v1/files/search", { projectId, query: query.trim(), maxResults }, signal); return { items: result.items.map(item => source(item, projectId)) }; },
    async readFile({ projectId, path, startLine, endLine, expectedSha256, signal } = {}) {
      if (typeof path !== "string" || !path || path.length > 512 || path.startsWith("/") || path.includes("..") || !Number.isInteger(startLine) || !Number.isInteger(endLine) || startLine < 1 || endLine < startLine || endLine - startLine > 5000 || (expectedSha256 !== undefined && !HASH.test(expectedSha256))) throw new ProjectReaderError("INPUT_LIMIT");
      const result = await call(sourceUrl, "/v1/files/read", { projectId, path, startLine, endLine, ...(expectedSha256 ? { expectedSha256 } : {}) }, signal);
      return { items: result.items.map(item => ({ ...source(item, projectId), content: typeof item.content === "string" ? clipUtf8(redactText(item.content, MAX_CONTENT_BYTES * 2), MAX_CONTENT_BYTES) : "" })) };
    },
    async gitStatus({ projectId, signal } = {}) { const result = await call(sourceUrl, "/v1/git/status", { projectId }, signal); return { items: result.items.map(item => ({ ...source(item, projectId), content: typeof item.content === "string" ? clipUtf8(redactText(item.content, MAX_CONTENT_BYTES * 2), MAX_CONTENT_BYTES) : "" })) }; },
    async gitLog({ projectId, limit = 20, signal } = {}) { if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new ProjectReaderError("INPUT_LIMIT"); const result = await call(sourceUrl, "/v1/git/log", { projectId, limit }, signal); return { items: result.items.map(item => ({ ...source(item, projectId), content: typeof item.content === "string" ? clipUtf8(redactText(item.content, MAX_CONTENT_BYTES * 2), MAX_CONTENT_BYTES) : "" })) }; },
    async gitBranch({ projectId, signal } = {}) { const result = await call(sourceUrl, "/v1/git/branch", { projectId }, signal); return { items: result.items.map(item => ({ ...source(item, projectId), content: typeof item.content === "string" ? clipUtf8(redactText(item.content, MAX_CONTENT_BYTES * 2), MAX_CONTENT_BYTES) : "" })) }; },
    async gitFileHistory({ projectId, path, limit = 20, signal } = {}) { if (typeof path !== "string" || !path || path.length > 512 || path.startsWith("/") || path.includes("..") || !Number.isInteger(limit) || limit < 1 || limit > 100) throw new ProjectReaderError("INPUT_LIMIT"); const result = await call(sourceUrl, "/v1/git/file-history", { projectId, path, limit }, signal); return { items: result.items.map(item => ({ ...source(item, projectId), content: typeof item.content === "string" ? clipUtf8(redactText(item.content, MAX_CONTENT_BYTES * 2), MAX_CONTENT_BYTES) : "" })) }; },
    async gitDiff({ projectId, path, signal } = {}) { if (typeof path !== "string" || !path || path.length > 512 || path.startsWith("/") || path.includes("..")) throw new ProjectReaderError("INPUT_LIMIT"); const result = await call(sourceUrl, "/v1/git/diff", { projectId, path }, signal); return { items: result.items.map(item => ({ ...source(item, projectId), content: typeof item.content === "string" ? clipUtf8(redactText(item.content, MAX_CONTENT_BYTES * 2), MAX_CONTENT_BYTES) : "" })) }; },
    async gitBlame({ projectId, path, startLine, endLine, signal } = {}) { if (typeof path !== "string" || !path || path.length > 512 || path.startsWith("/") || path.includes("..") || !Number.isInteger(startLine) || !Number.isInteger(endLine) || startLine < 1 || endLine < startLine || endLine - startLine > 500) throw new ProjectReaderError("INPUT_LIMIT"); const result = await call(sourceUrl, "/v1/git/blame", { projectId, path, startLine, endLine }, signal); return { items: result.items.map(item => ({ ...source(item, projectId), content: typeof item.content === "string" ? clipUtf8(redactText(item.content, MAX_CONTENT_BYTES * 2), MAX_CONTENT_BYTES) : "" })) }; },
    async dbSchema({ projectId, databaseId, dialect, signal } = {}) { if (!/^[a-z0-9][a-z0-9-]{0,95}$/.test(databaseId || "") || !["postgresql", "mariadb"].includes(dialect)) throw new ProjectReaderError("INPUT_LIMIT"); const result = await call(queryUrl, "/v1/db/schema", { projectId, databaseId, dialect }, signal); return { items: result.items.map(item => schemaItem(item, projectId, databaseId, dialect)) }; },
    async dbExplain({ projectId, databaseId, dialect, sql, params = [], signal } = {}) { if (!/^[a-z0-9][a-z0-9-]{0,95}$/.test(databaseId || "") || !["postgresql", "mariadb"].includes(dialect) || typeof sql !== "string" || !sql.trim() || sql.length > 4000 || !Array.isArray(params) || params.length > 32) throw new ProjectReaderError("INPUT_LIMIT"); const result = await call(queryUrl, "/v1/db/explain", { projectId, databaseId, dialect, sql, params }, signal); return { items: result.items.map(item => ({ ...databaseSource(item, projectId, databaseId, dialect, "explain"), content: typeof item.content === "string" ? clipUtf8(redactText(item.content, MAX_CONTENT_BYTES * 2), MAX_CONTENT_BYTES) : "" })) }; },
    async dbQuery({ projectId, databaseId, dialect, sql, params = [], signal } = {}) { if (!/^[a-z0-9][a-z0-9-]{0,95}$/.test(databaseId || "") || !["postgresql", "mariadb"].includes(dialect) || typeof sql !== "string" || !sql.trim() || sql.length > 4000 || !Array.isArray(params) || params.length > 32) throw new ProjectReaderError("INPUT_LIMIT"); const result = await call(queryUrl, "/v1/db/query", { projectId, databaseId, dialect, sql, params }, signal); return { items: result.items.map(item => ({ ...databaseSource(item, projectId, databaseId, dialect, "query"), content: typeof item.content === "string" ? clipUtf8(redactText(item.content, MAX_CONTENT_BYTES * 2), MAX_CONTENT_BYTES) : "" })) }; },
  });
}
