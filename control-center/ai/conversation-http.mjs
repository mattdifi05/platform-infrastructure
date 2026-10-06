import { EventEmitter } from "node:events";
import { resolveServerAiMode } from "./mode-router.mjs";
import { normalizeAnalysisSummary } from "./analysis-summary.mjs";
import { decodeConversationCursor, isBriefAffirmation, MAX_ATTACHMENT_BYTES_PER_FILE } from "./conversations.mjs";
import { redactText } from "./web.mjs";
import { ATTACHMENT_CAPABILITIES, readAndNormalizeAttachment } from "./attachments.mjs";
import { createChatArtifactTools } from "./artifact-tools.mjs";
import { shouldReloadHistoricalAttachmentContext } from "./quick-reply.mjs";

const MODES = new Set(["auto"]);
const TERMINAL = new Set(["completed", "aborted", "failed"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class ConversationHttpError extends Error {
  constructor(message, status = 400, code = "INVALID_REQUEST") {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function requireFound(value) {
  if (!value) throw new ConversationHttpError("Conversazione non trovata.", 404, "CONVERSATION_NOT_FOUND");
  return value;
}

function needsRetrieval(message, priorConversation, continuationAnchor = null) {
  const turns = Number(priorConversation?.turnCount || 0);
  // “Sì” is not a search query. The immediate pair already supplies short-turn
  // continuity; only a conversation that already qualifies for semantic memory
  // may reuse its server-derived topic as the retrieval query.
  if (isBriefAffirmation(message)) return turns >= 6 && typeof continuationAnchor?.query === "string" && Boolean(continuationAnchor.query.trim());
  return turns >= 6 || /\b(?:avevamo|prima|precedente|ricordi|risolto|quella|quel)\b/i.test(String(message || ""));
}

export function isExplicitPublicWebRequest(message) {
  const text = String(message || "");
  // A generic “cerca” is commonly a project-file instruction. Enter the
  // isolated public-web boundary only for an unambiguous external request.
  if (/\bnon\s+(?:cercare|cerca|fare\s+(?:una\s+)?ricerca|consultare)\s+(?:online|sul\s+web|in\s+rete)\b/i.test(text)) return false;
  if (/\b(?:contiene|contenga|stringa|testo|frase|literal(?:e)?|file)\b[^.!?]{0,96}[“”"'']?cerca\s+(?:online|sul\s+web|in\s+rete)\b/i.test(text)) return false;
  return /\b(?:cerca|ricerca)\s+(?:online|sul\s+web|in\s+rete)\b|\bweb\s*(?:search|ricerca)\b|\bleggi\s+(?:l['’])?(?:url|pagina|sito)\s+(?:pubblic[oa]|online)\b/i.test(text);
}

function generationKey({ ownerId, machineId, conversationId }) {
  return `${ownerId}\u0000${machineId}\u0000${conversationId}`;
}

function detachedTransport() {
  const req = new EventEmitter();
  req.aborted = false;
  req.resume = () => {};
  const res = new EventEmitter();
  res.statusCode = 202;
  res.destroyed = false;
  res.writableEnded = false;
  res.setHeader = () => {};
  res.flushHeaders = () => {};
  res.write = () => true;
  res.end = () => { res.writableEnded = true; };
  return { req, res };
}

async function withAttachmentWork(res, work) {
  // IncomingMessage.signal is not a client-disconnect signal in Node 26: it
  // can abort when a request body finishes normally. Attachment parsing has
  // its own request-integrity checks, so long-running attachment work follows
  // only a response close that happens before the response has ended.
  const controller = new AbortController();
  const onResponseClose = () => {
    if (!res?.writableEnded) controller.abort();
  };
  if (res?.destroyed && !res?.writableEnded) controller.abort();
  res?.once?.("close", onResponseClose);
  try { return await work(controller.signal); }
  finally { res?.removeListener?.("close", onResponseClose); }
}

function strictPayload(payload, keys) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)
    || Object.keys(payload).some(key => key !== "_csrf" && !keys.includes(key))) {
    throw new ConversationHttpError("Parametri della richiesta non validi.");
  }
  return payload;
}

export function createConversationHttp({ store, manager, readPayload, json, isReady = () => true, retrieval = null, getRetrieval = null, getProjectReaders = null, projectRegistry = null, refreshProjectCatalog = null, readAttachment = readAndNormalizeAttachment, attachmentCapabilities = ATTACHMENT_CAPABILITIES, attachmentStorage = null, artifactStorage = null, scanStore = null, startScan = null, stopScan = null, resumeScan = null, authorizeContinuation = null }) {
  const backgroundGenerations = new Map();
  const continuationSchedulers = new Map();
  const terminalScanStatuses = new Set(["completed", "failed", "aborted"]);
  const hasPendingContinuation = async ({ ownerId, machineId, conversationId, role = null } = {}) => {
    // This is the only public signal for a server-owned follow-up that may
    // still be created.  Keep the durable marker itself private: the browser
    // receives a boolean after the same current-RBAC check used by recovery.
    if (!role || !["owner", "admin", "viewer"].includes(role)
      || typeof authorizeContinuation !== "function"
      || typeof scanStore?.listContinuations !== "function") return false;
    const scope = { ownerId, machineId, conversationId };
    let markers;
    try { markers = await scanStore.listContinuations(scope); } catch { return false; }
    const marker = (Array.isArray(markers) ? markers : []).find(item => item?.role === role
      && ["pending", "running"].includes(item?.state)
      && typeof item.requestId === "string" && typeof item.userMessageId === "string");
    if (!marker) return false;
    try {
      return await authorizeContinuation({ ...scope, role, requestId: marker.requestId, userMessageId: marker.userMessageId }) === true;
    } catch { return false; }
  };
  const processAttachmentContinuations = async ({ ownerId, machineId, conversationId, role = null } = {}) => {
    // Startup reconciliation must have an authoritative current-RBAC
    // resolver. Persisted scan role is provenance, never a grant.
    if (!role || !["owner", "admin", "viewer"].includes(role) || typeof authorizeContinuation !== "function" || typeof scanStore?.listContinuations !== "function" || typeof store.beginAttachmentContinuation !== "function") return 0;
    const scope = { ownerId, machineId, conversationId };
    let scans;
    try { scans = await scanStore.listContinuations(scope); } catch { return 0; }
    const grouped = new Map();
    for (const scan of Array.isArray(scans) ? scans : []) {
      // listContinuations is a private projection (marker fields at the top
      // level), unlike the public scan DTO which intentionally omits them.
      const marker = scan;
      if (!marker || marker.role !== role || typeof marker.requestId !== "string" || typeof marker.userMessageId !== "string") continue;
      const key = `${marker.requestId}\u0000${marker.userMessageId}`;
      const group = grouped.get(key) || { ...marker, scans: [] };
      group.scans.push(scan);
      grouped.set(key, group);
    }
    let started = 0;
    for (const group of grouped.values()) {
      if (["completed", "failed", "cancelled"].includes(group.state)) continue;
      if (!group.scans.length || group.scans.some(scan => !terminalScanStatuses.has(scan.status))) continue;
      if (typeof authorizeContinuation === "function") {
        let authorized = false;
        try { authorized = await authorizeContinuation({ ...scope, role, requestId: group.requestId, userMessageId: group.userMessageId }); } catch { authorized = false; }
        if (authorized !== true) continue;
      }
      // One deterministic timer coalesces multiple scan completions and gives
      // the service time to persist every scan requested by the same turn.
      const key = `${ownerId}\u0000${machineId}\u0000${conversationId}\u0000${group.requestId}`;
      if (continuationSchedulers.has(key)) continue;
      if (typeof store.getAttachmentContinuation === "function") {
        let existing = null;
        try { existing = await store.getAttachmentContinuation({ ...scope, requestId: group.requestId }); } catch { continue; }
        if (existing?.generationStatus === "completed") {
          if (typeof scanStore.setContinuationState === "function") await scanStore.setContinuationState({ ...scope, requestId: group.requestId, state: "completed" }).catch(() => {});
          continue;
        }
        if (["pending", "streaming"].includes(existing?.generationStatus)) continue;
      } else if (typeof store.hasAttachmentContinuation === "function" && await store.hasAttachmentContinuation({ ...scope, requestId: group.requestId })) continue;
      started += 1;
      const task = (async () => {
        try {
          const transport = detachedTransport();
          const accepted = await handleConversation({ __serverAiContinuation: true, __serverAiPayload: { message: null, requestedMode: "auto", continuation: { ...group, scanIds: group.scans.map(scan => scan.scanId) } } }, transport.res, new URL("http://server-ai.invalid/"), { operationId: "ai.conversations.send", method: "POST", parameters: { machineId, conversationId } }, { subject: ownerId, role });
          if (accepted?.generationStatus === "pending" && typeof scanStore?.setContinuationState === "function") await scanStore.setContinuationState({ ...scope, requestId: group.requestId, state: "running" });
        } catch {
          // A disabled machine, a concurrent foreground turn, or a transient
          // store error leaves the terminal scans and marker durable. The next
          // authenticated conversation read retries the coordinator.
        } finally { continuationSchedulers.delete(key); }
      })();
      continuationSchedulers.set(key, task);
    }
    return started;
  };
  let handleConversation;
  const uploadOperations = new Map();
  const serializeUpload = async (scope, uploadId, work) => {
    const key = `${scope.ownerId}\u0000${scope.machineId}\u0000${scope.conversationId}\u0000${uploadId}`;
    const previous = uploadOperations.get(key) || Promise.resolve();
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    const tail = previous.catch(() => {}).then(() => gate);
    uploadOperations.set(key, tail);
    await previous.catch(() => {});
    try { return await work(); }
    finally {
      release();
      if (uploadOperations.get(key) === tail) uploadOperations.delete(key);
    }
  };
  handleConversation = async function handleConversation(req, res, url, operation, identity) {
    if (!operation.operationId.startsWith("ai.conversations.")) return false;
    const { machineId, conversationId, messageId, sourceId, attachmentId, uploadId, artifactId, scanId } = operation.parameters;
    if (!manager.list().some(machine => machine.id === machineId)) {
      throw new ConversationHttpError("Macchina non trovata.", 404, "AI_MACHINE_NOT_FOUND");
    }
    if (!identity?.subject || !["owner", "admin", "viewer"].includes(identity.role)) {
      throw new ConversationHttpError("Accesso alla chat non consentito.", 403, "FORBIDDEN");
    }
    if (conversationId && !UUID.test(conversationId)) requireFound(null);
    if (!store || !isReady()) throw new ConversationHttpError("Archivio conversazioni non disponibile.", 503, "CONVERSATIONS_UNAVAILABLE");
    // Project discovery is optional for the core local chat. A failed reader
    // never grants project access (the registry resolves no project), but it
    // must not take down a general or isolated public-web conversation.
    if (typeof refreshProjectCatalog === "function") {
      try { await refreshProjectCatalog({ machineId }); } catch {}
    }
    const scope = { ownerId: identity.subject, machineId, ...(conversationId ? { conversationId } : {}) };
    const machineRetrieval = typeof getRetrieval === "function" ? getRetrieval(machineId) : retrieval;
    const requireProjectAccess = (projectId) => {
      if (projectId === null || projectId === undefined) return;
      if (!projectRegistry || typeof projectRegistry.resolve !== "function") requireFound(null);
      try { projectRegistry.resolve({ projectId, subject: identity.subject, role: identity.role, machineId }); }
      catch { requireFound(null); }
    };
    const requireConversationProjects = async (id, legacyProjectId = null) => {
      let projectIds = legacyProjectId == null ? [] : [legacyProjectId];
      if (typeof store.getProjectIds === "function") {
        try { projectIds = await store.getProjectIds({ ...scope, conversationId: id }); }
        catch { requireFound(null); }
      }
      if (!Array.isArray(projectIds) || projectIds.length > 64) requireFound(null);
      for (const projectId of new Set(projectIds)) requireProjectAccess(projectId);
    };
    const authorizedProjectIds = () => {
      if (!projectRegistry || typeof projectRegistry.list !== "function") return [];
      try {
        const projects = projectRegistry.list({ subject: identity.subject, role: identity.role, machineId });
        return Array.isArray(projects) && projects.length <= 64 ? projects.map(project => project?.id).filter(projectId => typeof projectId === "string") : [];
      } catch { return []; }
    };
    const scanCall = async (action, options = {}) => {
      const scoped = { ...scope, ...options };
      if (typeof manager?.attachmentScan === "function") return manager.attachmentScan(machineId, action, scoped);
      if (action === "list" && typeof scanStore?.list === "function") return scanStore.list(scoped);
      if (action === "start" && typeof startScan === "function") return startScan(scoped);
      if (action === "stop" && typeof stopScan === "function") return stopScan(scoped);
      if (action === "resume" && typeof resumeScan === "function") return resumeScan(scoped);
      if (action === "start" && typeof scanStore?.createOrResume === "function") return scanStore.createOrResume(scoped);
      if (action === "resume" && typeof scanStore?.resume === "function") return scanStore.resume(scoped);
      if (action === "stop" && typeof scanStore?.abort === "function") return scanStore.abort(scoped);
      throw new ConversationHttpError("Scansione allegato non disponibile.", 503, "ATTACHMENT_SCANS_UNAVAILABLE");
    };
    const listScans = async () => {
      try { const scans = await scanCall("list"); return Array.isArray(scans) ? scans : []; }
      catch (error) { if (error?.code === "ATTACHMENT_SCANS_UNAVAILABLE") return []; throw error; }
    };
    const isAttachmentUpload = operation.operationId === "ai.conversations.attachments.create";
    const isUploadChunk = operation.operationId === "ai.conversations.uploads.chunk";
    if (req?.__serverAiQueueInternal === true) throw new ConversationHttpError("Accodamento chat non disponibile.", 409, "CHAT_QUEUE_DISABLED");
    const internalAttachmentContinuation = req?.__serverAiContinuation === true;
    const payload = internalAttachmentContinuation ? req.__serverAiPayload : (["POST", "PATCH", "DELETE"].includes(operation.method) && !isAttachmentUpload && !isUploadChunk ? await readPayload(req) : {});
    const requireAttachmentUploadReady = async () => {
      const status = await manager.status(machineId);
      if (!status || !["active", "degraded"].includes(status.state)) throw new ConversationHttpError("Server AI non è pronto per gli allegati.", 503, "AI_NOT_READY");
    };
    const requireUploadId = () => {
      if (!UUID.test(uploadId || "")) throw new ConversationHttpError("Caricamento allegato non valido.", 400, "UPLOAD_INVALID");
      return uploadId;
    };
    const validateUploadMetadata = () => {
      strictPayload(payload, ["filename", "byteSize"]);
      const filename = typeof payload.filename === "string" ? payload.filename.trim() : "";
      const byteSize = Number(payload.byteSize);
      if (!filename || Array.from(filename).length > 180 || /[\\/\0\x01-\x1f\x7f]/.test(filename)
        || !Number.isSafeInteger(byteSize) || byteSize < 1 || byteSize > MAX_ATTACHMENT_BYTES_PER_FILE) {
        throw new ConversationHttpError("File allegato non valido.", 400, "UPLOAD_INVALID");
      }
      return { filename, byteSize };
    };
    const uploadFailure = (error, fallback = "Caricamento allegato non disponibile.") => {
      if (error instanceof ConversationHttpError) throw error;
      throw new ConversationHttpError(
        typeof error?.message === "string" && error.message.length <= 240 ? error.message : fallback,
        Number.isInteger(error?.status) && error.status >= 400 && error.status <= 599 ? error.status : 400,
        typeof error?.code === "string" && /^[A-Z][A-Z0-9_]{1,63}$/.test(error.code) ? error.code : "UPLOAD_INVALID",
      );
    };
    switch (operation.operationId) {
      case "ai.conversations.list": {
        const cursor = url.searchParams.has("cursor") ? url.searchParams.get("cursor") : null;
        if (url.searchParams.has("before")) throw new ConversationHttpError("Parametro cursore non valido.");
        const rawLimit = url.searchParams.has("limit") ? url.searchParams.get("limit") : null;
        if (cursor !== null) {
          try { decodeConversationCursor(cursor); } catch { throw new ConversationHttpError("Cursore conversazioni non valido."); }
        }
        let limit = 100;
        if (rawLimit !== null) {
          if (!/^[1-9]\d{0,2}$/.test(rawLimit) || Number(rawLimit) > 100) {
            throw new ConversationHttpError("Limite conversazioni non valido.");
          }
          limit = Number(rawLimit);
        }
        const page = typeof store.listPage === "function"
          ? await store.listPage({ ...scope, limit, ...(cursor === null ? {} : { cursor }) })
          : { conversations: await store.list({ ...scope, limit }), nextCursor: null };
        const conversations = [];
        for (const conversation of page.conversations) {
          try { await requireConversationProjects(conversation.id, conversation?.projectId); conversations.push(conversation); } catch {}
        }
        return json(res, { conversations, nextCursor: page.nextCursor || null });
      }
      case "ai.conversations.create": {
        // Project choice is server-side tool context, never a browser-provided
        // conversation parameter.  A persisted legacy projectId remains only
        // a provenance hint for that old conversation.
        strictPayload(payload, []);
        const conversation = await store.create({ ...scope, projectId: null });
        return json(res, { conversation }, 201);
      }
      case "ai.conversations.read": {
        const before = url.searchParams.get("before") || undefined;
        if (before && (!/^[1-9]\d{0,18}$/.test(before) || BigInt(before) > 9223372036854775807n)) {
          throw new ConversationHttpError("Cursore conversazione non valido.");
        }
        const detail = requireFound(await store.get({ ...scope, before, limit: 100 }));
        await requireConversationProjects(conversationId, detail.conversation?.projectId);
        const continuationPending = await hasPendingContinuation({ ownerId: identity.subject, machineId, conversationId, role: identity.role });
        void processAttachmentContinuations({ ownerId: identity.subject, machineId, conversationId, role: identity.role });
        // The duplicate guard is persisted in assistant tool metadata for
        // restart recovery, but it is an implementation detail.  Do not let
        // a conversation read turn that marker into a client-visible ID.
        const messages = Array.isArray(detail.messages) ? detail.messages.map(message => {
          if (!message?.toolMetadata || typeof message.toolMetadata !== "object" || !Object.hasOwn(message.toolMetadata, "autoContinuation") && !Object.hasOwn(message.toolMetadata, "clientRequest")) return message;
          const { autoContinuation: _private, clientRequest: _request, ...toolMetadata } = message.toolMetadata;
          return { ...message, toolMetadata };
        }) : detail.messages;
        return json(res, { ...detail, messages, scans: await listScans(), continuationPending });
      }
      case "ai.conversations.scans.list": {
        await requireConversationProjects(conversationId);
        requireFound(await store.get(scope));
        return json(res, { scans: await listScans() });
      }
      case "ai.conversations.scans.create": {
        strictPayload(payload, ["attachmentId"]);
        if (!UUID.test(String(payload.attachmentId || "")) || typeof store.getAttachmentMetadata !== "function") throw new ConversationHttpError("Allegato non valido.");
        await requireConversationProjects(conversationId);
        requireFound(await store.get(scope));
        const metadata = requireFound(await store.getAttachmentMetadata({ ...scope, attachmentId: payload.attachmentId }));
        const context = typeof store.getAttachmentContext === "function"
          ? await store.getAttachmentContext({ ...scope, currentAttachmentIds: [payload.attachmentId] }) : [];
        const attachment = Array.isArray(context) && context[0] ? context[0] : metadata;
        const scan = await scanCall("start", { attachmentId: attachment.id, attachment, attachments: [attachment] });
        return json(res, { scan: requireFound(scan) }, 202);
      }
      case "ai.conversations.scans.stop": {
        strictPayload(payload, []);
        if (!UUID.test(String(scanId || ""))) requireFound(null);
        await requireConversationProjects(conversationId);
        requireFound(await store.get(scope));
        const scan = await scanCall("stop", { scanId });
        return json(res, { scan: requireFound(scan) });
      }
      case "ai.conversations.scans.resume": {
        strictPayload(payload, []);
        if (!UUID.test(String(scanId || ""))) requireFound(null);
        await requireConversationProjects(conversationId);
        requireFound(await store.get(scope));
        let options = { scanId };
        if (!manager?.attachmentScan && typeof scanStore?.resume === "function" && typeof scanStore?.get === "function") {
          const existing = await scanStore.get({ ...scope, scanId });
          if (existing?.attachmentId && typeof store.getAttachmentContext === "function") {
            const context = await store.getAttachmentContext({ ...scope, currentAttachmentIds: [existing.attachmentId] });
            if (context?.[0]) options = { ...options, attachmentId: existing.attachmentId, attachment: context[0] };
          }
        }
        const scan = await scanCall("resume", options);
        return json(res, { scan: requireFound(scan) });
      }
      case "ai.conversations.source.read": {
        if (!UUID.test(messageId || "") || !/^[A-Za-z0-9_-]{1,128}$/.test(sourceId || "")) requireFound(null);
        if (typeof store.getMessage !== "function") throw new ConversationHttpError("Archivio conversazioni non disponibile.", 503, "CONVERSATIONS_UNAVAILABLE");
        await requireConversationProjects(conversationId);
        const detail = requireFound(await store.getMessage({ ...scope, messageId }));
        await requireConversationProjects(conversationId, detail.conversation?.projectId);
        const message = detail.message;
        const citation = Array.isArray(message?.sources) ? message.sources.find(item => item?.type === "project" && item.id === sourceId) : null;
        if (!citation || !["file", "database"].includes(citation.kind)) requireFound(null);
        if (!projectRegistry || !getProjectReaders) requireFound(null);
        projectRegistry.resolve({ projectId: citation.projectId, subject: identity.subject, role: identity.role, machineId });
        const reader = getProjectReaders(machineId);
        if (citation.kind === "file" && (!citation.path || !citation.startLine || !citation.endLine || !reader?.readFile)) throw new ConversationHttpError("Fonte progetto non disponibile.", 503, "PROJECT_UNAVAILABLE");
        if (citation.kind === "database" && (!/^[a-z0-9][a-z0-9-]{0,95}$/.test(citation.databaseId || "") || !["postgresql", "mariadb"].includes(citation.dialect) || citation.operation !== "schema" || !reader?.dbSchema)) requireFound(null);
        try {
          const result = citation.kind === "database"
            ? await reader.dbSchema({ projectId: citation.projectId, databaseId: citation.databaseId, dialect: citation.dialect })
            : await reader.readFile({ projectId: citation.projectId, path: citation.path, startLine: citation.startLine, endLine: citation.endLine, expectedSha256: citation.sha256 });
          const current = result.items.find(item => item.id === citation.id && item.sha256 === citation.sha256 && typeof item.content === "string");
          if (!current) requireFound(null);
          return json(res, { source: { id: citation.id, type: "project", projectId: citation.projectId, kind: citation.kind, title: citation.title, path: citation.path, startLine: citation.startLine, endLine: citation.endLine, sha256: citation.sha256, ...(citation.kind === "database" ? { databaseId: citation.databaseId, dialect: citation.dialect, operation: citation.operation } : {}) }, content: current.content });
        } catch (error) {
          if (error?.code === "STALE_SOURCE" || error?.code === "NOT_FOUND" || error?.code === "DENIED_PATH") requireFound(null);
          throw new ConversationHttpError("Fonte progetto non disponibile.", 503, "PROJECT_UNAVAILABLE");
        }
      }
      case "ai.conversations.attachments.list": {
        if (typeof store.listPendingAttachments !== "function") throw new ConversationHttpError("Allegati non disponibili.", 503, "ATTACHMENTS_UNAVAILABLE");
        await requireConversationProjects(conversationId);
        requireFound(await store.get(scope));
        return json(res, { attachments: await store.listPendingAttachments(scope), supported: attachmentCapabilities });
      }
      case "ai.conversations.attachments.create": {
        if (typeof store.createAttachment !== "function" || typeof readAttachment !== "function") throw new ConversationHttpError("Allegati non disponibili.", 503, "ATTACHMENTS_UNAVAILABLE");
        await requireConversationProjects(conversationId);
        requireFound(await store.get(scope));
        let attachment;
        try { attachment = await withAttachmentWork(res, signal => readAttachment(req, { signal })); }
        catch (error) { throw new ConversationHttpError(error?.message || "Allegato non valido.", Number.isInteger(error?.status) ? error.status : 400, error?.code || "ATTACHMENT_INVALID"); }
        const stored = requireFound(await store.createAttachment({ ...scope, attachment }));
        return json(res, { attachment: stored }, 201);
      }
      case "ai.conversations.uploads.create": {
        if (!attachmentStorage || typeof attachmentStorage.beginUpload !== "function") throw new ConversationHttpError("Caricamento allegati non disponibile.", 503, "UPLOADS_UNAVAILABLE");
        await requireConversationProjects(conversationId);
        requireFound(await store.get(scope));
        await requireAttachmentUploadReady();
        let upload;
        try { upload = await attachmentStorage.beginUpload(scope, validateUploadMetadata()); }
        catch (error) { uploadFailure(error); }
        if (!upload || !UUID.test(upload.id || "") || !Number.isSafeInteger(upload.offset) || upload.offset !== 0 || !Number.isSafeInteger(upload.chunkBytes) || upload.chunkBytes < 1) {
          throw new ConversationHttpError("Caricamento allegati non disponibile.", 503, "UPLOADS_UNAVAILABLE");
        }
        return json(res, { upload: { id: upload.id, offset: upload.offset, chunkBytes: upload.chunkBytes, byteSize: upload.byteSize } }, 201);
      }
      case "ai.conversations.uploads.chunk": {
        if (!attachmentStorage || typeof attachmentStorage.appendUpload !== "function") throw new ConversationHttpError("Caricamento allegati non disponibile.", 503, "UPLOADS_UNAVAILABLE");
        await requireConversationProjects(conversationId);
        requireFound(await store.get(scope));
        const id = requireUploadId();
        const upload = await serializeUpload(scope, id, async () => {
          await requireAttachmentUploadReady();
          try { return await withAttachmentWork(res, signal => attachmentStorage.appendUpload(scope, id, req, { signal })); }
          catch (error) { uploadFailure(error); }
        });
        if (!upload || !UUID.test(upload.id || "") || !Number.isSafeInteger(upload.offset) || !Number.isSafeInteger(upload.byteSize)) throw new ConversationHttpError("Caricamento allegati non disponibile.", 503, "UPLOADS_UNAVAILABLE");
        return json(res, { upload: { id: upload.id, offset: upload.offset, byteSize: upload.byteSize } });
      }
      case "ai.conversations.uploads.complete": {
        strictPayload(payload, []);
        if (!attachmentStorage || typeof attachmentStorage.completeUpload !== "function" || typeof attachmentStorage.acknowledgeUpload !== "function" || typeof store.getAttachmentMetadata !== "function") throw new ConversationHttpError("Caricamento allegati non disponibile.", 503, "UPLOADS_UNAVAILABLE");
        await requireConversationProjects(conversationId);
        requireFound(await store.get(scope));
        const id = requireUploadId();
        const attachment = await serializeUpload(scope, id, async () => {
          const existing = await store.getAttachmentMetadata({ ...scope, attachmentId: id });
          if (existing) {
            // A client can miss the first 201 after the database commit. The
            // manifest may already be gone, so never require the engine to
            // normalise this upload again. A best-effort ack clears an older
            // completed-but-unacknowledged manifest without risking its object.
            try { await attachmentStorage.acknowledgeUpload(scope, id); } catch {}
            return existing;
          }
          await requireAttachmentUploadReady();
          let normalized;
          try { normalized = await withAttachmentWork(res, signal => attachmentStorage.completeUpload(scope, id, { signal })); }
          catch (error) { uploadFailure(error, "Allegato non valido."); }
          let created;
          try { created = requireFound(await store.createAttachment({ ...scope, attachment: normalized, attachmentId: id })); }
          catch (error) {
            // The object remains in the storage manifest. A retry can complete
            // idempotently or be explicitly aborted by its scoped owner.
            throw error;
          }
          try { await attachmentStorage.acknowledgeUpload(scope, id); }
          catch { throw new ConversationHttpError("Allegato salvato ma conferma del caricamento non disponibile. Riprova.", 503, "UPLOAD_ACK_PENDING"); }
          return created;
        });
        return json(res, { attachment }, 201);
      }
      case "ai.conversations.uploads.delete": {
        strictPayload(payload, []);
        if (!attachmentStorage || typeof attachmentStorage.abortUpload !== "function" || typeof store.getAttachmentMetadata !== "function") throw new ConversationHttpError("Caricamento allegati non disponibile.", 503, "UPLOADS_UNAVAILABLE");
        await requireConversationProjects(conversationId);
        requireFound(await store.get(scope));
        const id = requireUploadId();
        await serializeUpload(scope, id, async () => {
          // Deletion is also the recovery path for a browser reload while the
          // machine is disabled. Once the attachment is durable, only ack a
          // stale upload manifest: aborting it could delete the referenced
          // disk object.
          const existing = await store.getAttachmentMetadata({ ...scope, attachmentId: id });
          if (existing) { try { await attachmentStorage.acknowledgeUpload(scope, id); } catch {} return; }
          try { await attachmentStorage.abortUpload(scope, id); }
          catch (error) { uploadFailure(error); }
        });
        return json(res, { deleted: true });
      }
      case "ai.conversations.attachments.read": {
        if (typeof store.readAttachment !== "function" || !UUID.test(attachmentId || "")) requireFound(null);
        await requireConversationProjects(conversationId);
        const attachment = requireFound(await store.readAttachment({ ...scope, attachmentId }));
        const inlineImage = attachment.kind === "image" && attachment.mediaType === "image/jpeg";
        res.setHeader?.("Content-Type", inlineImage ? "image/jpeg" : attachment.kind === "archive" ? "application/zip" : "text/plain; charset=utf-8");
        const data = Buffer.isBuffer(attachment.data) ? attachment.data : attachment.data == null ? null : Buffer.from(attachment.data);
        res.setHeader?.("Content-Length", String(data ? data.length : attachment.byteSize));
        const filename = String(attachment.name || "allegato");
        const asciiFilename = filename.normalize("NFKD").replace(/[^\x20-\x7e]/g, "_").replace(/["\\\r\n]/g, "_").slice(0, 180) || "allegato";
        const encodedFilename = encodeURIComponent(filename).replace(/[!'()*]/g, character => `%${character.codePointAt(0).toString(16).toUpperCase()}`);
        res.setHeader?.("Content-Disposition", `${inlineImage ? "inline" : "attachment"}; filename="${asciiFilename}"; filename*=UTF-8''${encodedFilename}`);
        res.setHeader?.("Cache-Control", "private, no-store");
        res.setHeader?.("X-Content-Type-Options", "nosniff");
        if (attachment.stream && typeof attachment.stream.pipe === "function") {
          const closeDownload = () => attachment.stream.destroy();
          res.once?.("close", closeDownload);
          attachment.stream.once?.("close", () => res.removeListener?.("close", closeDownload));
          attachment.stream.once?.("error", () => { if (!res.writableEnded) res.destroy?.(); });
          attachment.stream.pipe(res);
        } else res.end(data || Buffer.alloc(0));
        return true;
      }
      case "ai.conversations.attachments.delete": {
        strictPayload(payload, []);
        if (typeof store.deletePendingAttachment !== "function" || !UUID.test(attachmentId || "")) requireFound(null);
        await requireConversationProjects(conversationId);
        requireFound(await store.deletePendingAttachment({ ...scope, attachmentId }));
        return json(res, { deleted: true });
      }
      case "ai.conversations.artifacts.list": {
        if (typeof store.listArtifacts !== "function") throw new ConversationHttpError("Artefatti non disponibili.", 503, "ARTIFACTS_UNAVAILABLE");
        await requireConversationProjects(conversationId);
        requireFound(await store.get(scope));
        return json(res, { artifacts: await store.listArtifacts(scope) });
      }
      case "ai.conversations.artifacts.read": {
        if (typeof store.readArtifact !== "function" || !UUID.test(artifactId || "")) requireFound(null);
        await requireConversationProjects(conversationId);
        const artifact = requireFound(await store.readArtifact({ ...scope, artifactId }));
        const type = typeof artifact.mediaType === "string" && /^[a-z]+\/[a-z0-9.+-]+$/i.test(artifact.mediaType) ? artifact.mediaType : "application/octet-stream";
        res.setHeader?.("Content-Type", type);
        res.setHeader?.("Content-Length", String(artifact.byteSize ?? artifact.size));
        const filename = String(artifact.name || "artifact");
        const asciiFilename = filename.normalize("NFKD").replace(/[^\x20-\x7e]/g, "_").replace(/["\\\r\n]/g, "_").slice(0, 180) || "artifact";
        const encodedFilename = encodeURIComponent(filename).replace(/[!'()*]/g, character => `%${character.codePointAt(0).toString(16).toUpperCase()}`);
        res.setHeader?.("Content-Disposition", `attachment; filename="${asciiFilename}"; filename*=UTF-8''${encodedFilename}`);
        res.setHeader?.("Cache-Control", "private, no-store");
        res.setHeader?.("X-Content-Type-Options", "nosniff");
        res.setHeader?.("Content-Security-Policy", "sandbox");
        if (artifact.stream && typeof artifact.stream.pipe === "function") {
          const closeDownload = () => artifact.stream.destroy();
          res.once?.("close", closeDownload);
          artifact.stream.once?.("close", () => res.removeListener?.("close", closeDownload));
          artifact.stream.once?.("error", () => { if (!res.writableEnded) res.destroy?.(); });
          artifact.stream.pipe(res);
        } else res.end(Buffer.isBuffer(artifact.data) ? artifact.data : Buffer.from(artifact.data || ""));
        return true;
      }
      case "ai.conversations.artifacts.delete": {
        strictPayload(payload, []);
        if (typeof store.deleteArtifact !== "function" || !UUID.test(artifactId || "")) requireFound(null);
        await requireConversationProjects(conversationId);
        requireFound(await store.deleteArtifact({ ...scope, artifactId }));
        return json(res, { deleted: true });
      }
      case "ai.conversations.rename": {
        strictPayload(payload, ["title"]);
        if (typeof payload.title !== "string" || !payload.title.trim() || payload.title.length > 160) {
          throw new ConversationHttpError("Il titolo deve contenere da 1 a 160 caratteri.");
        }
        await requireConversationProjects(conversationId);
        return json(res, { conversation: requireFound(await store.rename({ ...scope, title: payload.title.trim() })) });
      }
      case "ai.conversations.delete": {
        strictPayload(payload, []);
        const detail = requireFound(await store.get(scope));
        // An owner may still remove a revoked private chat. This does not
        // disclose transcript content or call a project reader.
        if (detail.messages.some(message => ["pending", "streaming"].includes(message.generationStatus))) {
          throw new ConversationHttpError("Interrompi la generazione prima di eliminare questa chat.", 409, "CONVERSATION_BUSY");
        }
        if (typeof manager.attachmentScan === "function") await scanCall("deleteConversation");
        requireFound(await store.delete(scope));
        if (machineRetrieval && typeof machineRetrieval.markConversationDeleted === "function") await machineRetrieval.markConversationDeleted({ ...scope, projectId: detail.conversation?.projectId || null });
        return json(res, { deleted: true });
      }
      case "ai.conversations.queue.delete": {
        strictPayload(payload, []);
        if (!UUID.test(String(operation.parameters?.queueId || "")) || typeof store.cancelQueued !== "function") requireFound(null);
        await requireConversationProjects(conversationId);
        const cancelled = requireFound(await store.cancelQueued({ ...scope, queueId: operation.parameters.queueId }));
        return json(res, { queueItem: cancelled });
      }
      case "ai.conversations.cancel": {
        strictPayload(payload, []);
        // Cancellation is scoped by the same durable conversation ownership as
        // a read. It never accepts a browser-supplied assistant or operation ID.
        requireFound(await store.get(scope));
        const key = generationKey({ ownerId: identity.subject, machineId, conversationId });
        const local = backgroundGenerations.get(key);
        local?.abort(new ConversationHttpError("La generazione è stata interrotta.", 499, "AI_ABORTED"));
        const stopped = await manager.cancelChat?.(machineId, key);
        return json(res, { conversationId, status: local || stopped ? "stopping" : "stopped" }, local || stopped ? 202 : 200);
      }
      case "ai.conversations.send": {
        if (!internalAttachmentContinuation) strictPayload(payload, ["message", "requestedMode", "attachmentIds", "delivery", "requestId"]);
        if (!internalAttachmentContinuation && !UUID.test(String(payload.requestId || ""))) throw new ConversationHttpError("Identificativo richiesta non valido.", 400, "REQUEST_ID_INVALID");
        let attachmentIds = payload.attachmentIds === undefined ? [] : payload.attachmentIds;
        if (!Array.isArray(attachmentIds) || attachmentIds.length > 5 || attachmentIds.some(id => !UUID.test(id || "")) || new Set(attachmentIds).size !== attachmentIds.length) {
          throw new ConversationHttpError("Allegati non validi.");
        }
        let sendMessage = typeof payload.message === "string" && payload.message.trim() ? payload.message.trim() : attachmentIds.length ? "Analizza gli allegati." : "";
        if (internalAttachmentContinuation) {
          const continuation = payload.continuation;
          if (!continuation || !UUID.test(String(continuation.userMessageId || "")) || !UUID.test(String(continuation.requestId || "")) || !UUID.test(String(continuation.scanIds?.[0] || ""))) throw new ConversationHttpError("Continuazione scansione non valida.", 400, "SCAN_CONTINUATION_INVALID");
          const original = requireFound(await store.getMessage?.({ ...scope, messageId: continuation.userMessageId }));
          if (original.message?.role !== "user" || typeof original.message.content !== "string" || !original.message.content.trim()) throw new ConversationHttpError("Turno originale non disponibile.", 409, "SCAN_CONTINUATION_ORIGINAL_MISSING");
          sendMessage = original.message.content;
          attachmentIds = Array.isArray(original.message.attachments) ? original.message.attachments.map(item => item?.id).filter(id => UUID.test(String(id || ""))) : [];
          if (attachmentIds.length > 5 || new Set(attachmentIds).size !== attachmentIds.length) throw new ConversationHttpError("Allegati originali non validi.", 409, "ATTACHMENTS_UNAVAILABLE");
        }
        if (!sendMessage || Buffer.byteLength(sendMessage) > 16 * 1024
          || !internalAttachmentContinuation && payload.requestedMode !== undefined && !MODES.has(payload.requestedMode)) {
          throw new ConversationHttpError("Messaggio o modalità non validi.");
        }
        // The canonical quick replies continue the latest assistant answer.
        // Do not silently reattach the most recent historical file and steer
        // the model away from that answer; a newly attached file remains an
        // explicit request and keeps the normal attachment path.
        const assistantContinuation = !shouldReloadHistoricalAttachmentContext(sendMessage, attachmentIds, internalAttachmentContinuation);
        if (payload.delivery !== undefined) throw new ConversationHttpError("Accodamento e risposta immediata non sono disponibili.", 409, "CHAT_QUEUE_DISABLED");
        const previous = requireFound(await store.buildContext({ ...scope, currentMessage: sendMessage }));
        await requireConversationProjects(conversationId, previous.projectId);
        const status = await manager.status(machineId);
        if (!["active", "degraded"].includes(status.state)) {
          throw new ConversationHttpError("Server AI non è pronto per nuove richieste.", 503, "AI_NOT_READY");
        }
        const history = Array.isArray(previous) ? previous : previous.messages || previous.context;
        const publicWebScope = isExplicitPublicWebRequest(sendMessage);
        if (publicWebScope && attachmentIds.length) throw new ConversationHttpError("La ricerca sul web non può usare allegati privati.", 400, "ATTACHMENTS_PRIVATE");
        const publicWebMessage = publicWebScope ? redactText(sendMessage, 16 * 1024) : null;
        // Public-web requests are an isolated boundary: neither conversation
        // history nor an affirmative anchor may be sent to external tools.
        const continuationAnchor = !publicWebScope && isBriefAffirmation(sendMessage)
          ? previous.continuationAnchor || null : null;
        const safeHistory = publicWebScope ? [{ role: "user", content: publicWebMessage || "Ricerca online." }] : history;
        const routed = resolveServerAiMode({
          requestedMode: "auto",
          message: publicWebMessage || sendMessage,
          projectId: publicWebScope ? null : previous.projectId || null,
          priorConversation: previous.priorConversation || {
            turnCount: Math.floor((history?.length || 0) / 2),
            hasSummary: Boolean(previous.summary),
          },
        });
        // AUTO keeps completed-scan synthesis and an already deep proposal in DEEP.
        const resolution = internalAttachmentContinuation || !publicWebScope && continuationAnchor?.resolvedMode === "deep" && routed.requestedMode === "auto"
          ? Object.freeze({ ...routed, resolvedMode: "deep", signals: Object.freeze([...routed.signals, internalAttachmentContinuation ? "attachment_continuation" : "affirmative_continuation"]) })
          : routed;
        // The durable pending assistant is the duplicate guard. It is created
        // before the browser receives 202 and survives navigation/reload.
        let turn;
        try { turn = requireFound(await (internalAttachmentContinuation
          ? store.beginAttachmentContinuation?.({ ...scope, userMessageId: payload.continuation.userMessageId, requestId: payload.continuation.requestId, requestedMode: resolution.requestedMode, resolvedMode: resolution.resolvedMode, scanId: payload.continuation.scanIds[0] })
          : store.beginTurn({ ...scope, message: sendMessage, attachmentIds, requestId: payload.requestId, ...resolution }))); }
        catch (error) {
          if (error?.code === "GENERATION_ACTIVE") return json(res, { error: "GENERATION_ACTIVE", message: "La conversazione è già in generazione.", conversationId, generationStatus: "active" }, 409);
          throw error;
        }
        if (turn.blocked) throw new ConversationHttpError("La conversazione è già in generazione.", 409, "GENERATION_ACTIVE");
        if (turn.idempotent) {
          const existing = { conversationId, assistantId: turn.assistant.id, generationStatus: turn.assistant.generationStatus, requestedMode: turn.assistant.requestedMode, resolvedMode: turn.assistant.resolvedMode, idempotent: true };
          return internalAttachmentContinuation ? existing : json(res, existing, 202);
        }
        const key = generationKey({ ownerId: identity.subject, machineId, conversationId });
        const backgroundAbort = new AbortController();
        // Publish cancellation before any attachment/provider await. Stop must
        // also cover the interval between durable admission and registration.
        backgroundGenerations.set(key, backgroundAbort);
        // The store rechecks that these IDs are bound user attachments after
        // beginTurn. Never accept browser bytes or pending attachment IDs in
        // the model request; public-web turns remain completely isolated.
        let trustedAttachments = [];
        try {
          trustedAttachments = !publicWebScope && !assistantContinuation && typeof store.getAttachmentContext === "function"
            ? await store.getAttachmentContext({ ...scope, currentAttachmentIds: attachmentIds }) : [];
          // IDs were atomically bound in beginTurn. A missing entry here is a
          // storage race or a failed scoped read, never an invitation to start
          // a model turn without the file the user supplied.
          if (attachmentIds.length && trustedAttachments.length !== attachmentIds.length) {
            throw new ConversationHttpError("Uno o più allegati non sono più disponibili.", 409, "ATTACHMENT_UNAVAILABLE");
          }
        } catch (error) {
          // No 202 has been written yet. Turn the durable duplicate guard into
          // a terminal failure so a transient storage failure cannot strand a
          // pending assistant or leave a browser-visible phantom generation.
          if (backgroundGenerations.get(key) === backgroundAbort) backgroundGenerations.delete(key);
          try { await store.finishTurn({ ...scope, turnId: turn.turnId, content: "", generationStatus: "failed", resolvedMode: resolution.resolvedMode }); } catch {}
          if (error instanceof ConversationHttpError) throw error;
          throw new ConversationHttpError("Allegati non disponibili.", 503, "ATTACHMENTS_UNAVAILABLE");
        }
        let registered = true;
        try {
          if (typeof manager.registerChat === "function") registered = await manager.registerChat(machineId, key, backgroundAbort);
        } catch {
          registered = false;
        }
        if (!registered) {
          if (backgroundGenerations.get(key) === backgroundAbort) backgroundGenerations.delete(key);
          requireFound(await store.finishTurn({ ...scope, turnId: turn.turnId, content: "", generationStatus: "failed", resolvedMode: resolution.resolvedMode }));
          throw new ConversationHttpError("La generazione non può essere registrata su questa macchina.", 503, "AI_NOT_READY");
        }
        const modeMetadata = { requestedMode: "auto", resolvedMode: resolution.resolvedMode };
        let terminal = false;
        let lastAnalysisSummary = "";
        const currentAnalysisSummary = (value) => {
          if (resolution.resolvedMode !== "deep") return "";
          if (value && Object.hasOwn(value, "analysisSummary")) {
            if (value.analysisSummary === "") lastAnalysisSummary = "";
            else {
              const candidate = normalizeAnalysisSummary(value.analysisSummary, { truncate: true });
              if (candidate) lastAnalysisSummary = candidate;
            }
          }
          return lastAnalysisSummary;
        };
        const finish = async (type, value = {}) => {
          if (terminal) return;
          const analysisSummary = currentAnalysisSummary(value);
          if (type === "started") {
            requireFound(await store.updateMessage({ ...scope, messageId: turn.assistant.id, generationStatus: "streaming", content: "", sources: [], toolMetadata: { ...modeMetadata, state: value.state || "preparing", tools: [], summarySteps: [], ...(analysisSummary ? { analysisSummary } : {}) } }));
            return;
          }
          if (type === "progress") {
            requireFound(await store.updateMessage({
              ...scope, messageId: turn.assistant.id, generationStatus: "streaming",
              content: typeof value.content === "string" ? value.content : "",
              sources: Array.isArray(value.sources) ? value.sources : [],
              toolMetadata: {
                ...modeMetadata,
                state: typeof value.state === "string" ? value.state : "responding",
                tools: Array.isArray(value.tools) ? value.tools : [],
                summarySteps: Array.isArray(value.summarySteps) ? value.summarySteps : [],
                ...(analysisSummary ? { analysisSummary } : {}),
              },
            }));
            return;
          }
          if (!TERMINAL.has(type)) return;
          const completed = requireFound(await store.finishTurn({
            ...scope, turnId: turn.turnId, content: typeof value.content === "string" ? value.content : "",
            generationStatus: type, resolvedMode: resolution.resolvedMode,
            sources: Array.isArray(value.sources) ? value.sources : [],
            toolMetadata: {
              ...modeMetadata,
              tools: Array.isArray(value.toolMetadata) ? value.toolMetadata : Array.isArray(value.tools) ? value.tools : [],
              summarySteps: Array.isArray(value.summarySteps) ? value.summarySteps : [],
              ...(analysisSummary ? { analysisSummary } : {}),
            },
          }));
          if (machineRetrieval && typeof machineRetrieval.enqueueConversationMessage === "function") {
            if (turn.user) machineRetrieval.enqueueConversationMessage({ ...scope, subject: identity.subject, role: identity.role, projectId: previous.projectId || null, messageId: turn.user.id, content: sendMessage });
            if (completed.generationStatus === "completed" && completed.content.trim()) machineRetrieval.enqueueConversationMessage({ ...scope, subject: identity.subject, role: identity.role, projectId: previous.projectId || null, messageId: completed.id, content: completed.content });
          }
          if (machineRetrieval && typeof machineRetrieval.enqueueBackfill === "function") void machineRetrieval.enqueueBackfill({ ...scope, subject: identity.subject, role: identity.role, projectId: previous.projectId || null });
          if (previous.projectId && machineRetrieval && typeof machineRetrieval.enqueueProjectIndex === "function") {
            machineRetrieval.enqueueProjectIndex({ ownerId: identity.subject, subject: identity.subject, role: identity.role, machineId, projectId: previous.projectId });
          }
          terminal = true;
          if (backgroundGenerations.get(key) === backgroundAbort) backgroundGenerations.delete(key);
          await manager.unregisterChat?.(machineId, key, backgroundAbort);
          const restartAbort = completed.generationStatus === "aborted" && backgroundAbort.signal.reason?.code === "AI_SHUTDOWN";
          if (internalAttachmentContinuation && !restartAbort && typeof scanStore?.setContinuationState === "function") {
            await scanStore.setContinuationState({ ...scope, requestId: payload.continuation.requestId, state: completed.generationStatus === "completed" ? "completed" : "failed" }).catch(() => {});
          }
          if (!internalAttachmentContinuation && turn.user && type === "aborted" && backgroundAbort.signal.reason?.code === "AI_ABORTED" && typeof scanStore?.setContinuationState === "function") {
            await scanStore.setContinuationState({ ...scope, requestId: turn.user.id, state: "cancelled" }).catch(() => {});
          }
          if (!internalAttachmentContinuation) void processAttachmentContinuations({ ownerId: identity.subject, machineId, conversationId, role: identity.role });
        };
        void (async () => {
          try {
            let retrievalContext = null; let retrievalSources = [];
            if (!publicWebScope && machineRetrieval && typeof machineRetrieval.retrieve === "function" && needsRetrieval(sendMessage, previous.priorConversation, continuationAnchor)) {
              const selected = await machineRetrieval.retrieve({ ownerId: identity.subject, subject: identity.subject, role: identity.role, machineId, projectId: null, authorizedProjectIds: authorizedProjectIds(), query: continuationAnchor?.query || sendMessage, signal: backgroundAbort.signal });
              if (backgroundAbort.signal.aborted) throw backgroundAbort.signal.reason;
              retrievalContext = typeof selected?.context === "string" ? selected.context : null;
              retrievalSources = Array.isArray(selected?.citations) ? selected.citations : [];
            }
            if (backgroundAbort.signal.aborted) throw backgroundAbort.signal.reason;
            // Access may change while private retrieval is running. No source is
            // handed to the model until this server-side recheck succeeds.
            await requireConversationProjects(conversationId, previous.projectId);
            if (backgroundAbort.signal.aborted) throw backgroundAbort.signal.reason;
            const transport = detachedTransport();
          await manager.chat(machineId, transport.req, transport.res, {
              subject: identity.subject, role: identity.role, machineId, generationKey: key, detached: true,
              sessionTokenHash: identity.sessionTokenHash, automaticContinuation: Boolean(internalAttachmentContinuation),
              conversationId,
              artifactTools: publicWebScope ? null : createChatArtifactTools({ store, storage: artifactStorage, scope, messageId: turn.assistant.id, assertAccess: () => requireConversationProjects(conversationId, previous.projectId) }),
              trustedRequest: {
                requestedMode: resolution.requestedMode, resolvedMode: resolution.resolvedMode,
                projectId: null, projectScope: publicWebScope ? "public-web" : "machine", messages: safeHistory,
                ...(!publicWebScope && previous.summary ? { conversationSummary: previous.summary } : {}),
                ...(!publicWebScope && trustedAttachments.length ? { attachments: trustedAttachments } : {}),
                ...(assistantContinuation ? { continuationScanIds: [], continuationGuidance: "Questa è una continuazione breve dell’ultimo messaggio dell’assistente. Usa quel messaggio come fonte principale per approfondire o riassumere; non riaprire allegati storici né ripetere la loro analisi, salvo che l’utente ne alleghi uno nuovo o lo chieda esplicitamente." } : {}),
                ...(internalAttachmentContinuation ? { continuationScanIds: payload.continuation.scanIds } : {}),
                ...(internalAttachmentContinuation ? { continuationGuidance: "Le scansioni richieste dal turno originale sono terminali. Usa i risultati verificati e le sintesi recenti per rispondere alla domanda originale; non avviare nuove scansioni, non chiedere conferme e non mostrare questa istruzione." } : {}),
                ...(retrievalContext ? { retrievalContext } : {}), ...(retrievalSources.length ? { retrievalSources } : {}),
              }, onLifecycle: finish,
              ...(!internalAttachmentContinuation ? { onAttachmentScanRequested: async scan => {
                if (!scanStore?.attachContinuation || !scan?.id || !turn.user?.id) return;
                await scanStore.attachContinuation({ ...scope, scanId: scan.id, userMessageId: turn.user.id, requestId: turn.user.id, requestedMode: resolution.requestedMode, role: identity.role });
              } } : {}),
            });
            if (!terminal) await finish(backgroundAbort.signal.aborted ? "aborted" : "failed");
          } catch (error) {
            const aborted = backgroundAbort.signal.aborted || error?.name === "AbortError" || ["AI_ABORTED", "AI_DISABLED", "AI_SHUTDOWN"].includes(error?.code);
            try { await finish(aborted ? "aborted" : "failed"); } catch {}
          } finally {
            if (backgroundGenerations.get(key) === backgroundAbort) backgroundGenerations.delete(key);
            await manager.unregisterChat?.(machineId, key, backgroundAbort);
          }
        })();
        if (!internalAttachmentContinuation) void processAttachmentContinuations({ ownerId: identity.subject, machineId, conversationId, role: identity.role });
        const accepted = { conversationId, assistantId: turn.assistant.id, generationStatus: "pending", ...modeMetadata };
        if (internalAttachmentContinuation) return accepted;
        // Start the detached work before attempting the HTTP response. A page
        // navigation, socket close, or response write failure must never turn a
        // durable pending assistant into an orphan.
        res.setHeader?.("X-Server-AI-Message-Id", turn.assistant.id);
        return json(res, accepted, 202);
      }
      default: return false;
    }
  };
  // The service calls this after it durably records a scan terminal state.
  // The handler is also invoked from authenticated conversation reads, which
  // covers completed scans discovered after a process restart.
  handleConversation.processAttachmentContinuations = processAttachmentContinuations;
  handleConversation.onAttachmentScanTerminal = scan => processAttachmentContinuations({ ownerId: scan?.ownerId, machineId: scan?.machineId, conversationId: scan?.conversationId, role: scan?.role || null });
  return handleConversation;
}
