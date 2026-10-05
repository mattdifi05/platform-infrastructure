import { extname } from "node:path";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CONTENT_BYTES = 16 * 1024;
const TYPES = { ".md": "text/markdown", ".csv": "text/csv", ".json": "application/json", ".html": "text/html", ".svg": "image/svg+xml", ".xml": "application/xml" };
function fail(message, code = "ARTIFACT_INVALID", status = 400) { throw Object.assign(new Error(message), { code, status }); }
function shape(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some(key => !keys.includes(key))) fail("Parametri del file non validi.");
}
function content(value) {
  if (typeof value !== "string" || !value.length || Buffer.byteLength(value) > CONTENT_BYTES || value.includes("\0")) fail("Il contenuto generato deve essere testo, massimo 16 KiB per operazione.");
  return value;
}
function filename(value, nested = false) {
  if (typeof value !== "string" || !value.trim() || Buffer.byteLength(value) > 160 || /[\\\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/.test(value)
    || value.startsWith("/") || /^[a-z]:/i.test(value) || (!nested && value.includes("/")) || value.split("/").some(part => !part || part === "." || part === "..")) fail("Nome del file non valido.");
  return value.normalize("NFC");
}

// This capability is constructed only inside the authenticated conversation
// handler. The model supplies content and opaque IDs, never a disk path, URL,
// owner, machine, conversation or assistant message ID.
export function createChatArtifactTools({ store, storage, scope, messageId, assertAccess = async () => {} }) {
  if (!storage || typeof store?.createArtifact !== "function") return null;
  const owned = Object.freeze({ ownerId: scope.ownerId, machineId: scope.machineId, conversationId: scope.conversationId });
  const check = async signal => {
    signal?.throwIfAborted();
    await assertAccess();
    if (!await store.get(owned)) fail("Conversazione non disponibile.", "CONVERSATION_NOT_FOUND", 404);
    signal?.throwIfAborted();
  };
  const persist = async (result, signal) => {
    try { await check(signal); }
    catch (error) {
      // No database write has started, so this freshly-created object is known
      // to be unreferenced and can be removed deterministically.
      try { await storage.remove(owned, result.id); } catch {}
      throw error;
    }
    // createArtifact owns cleanup when it can prove that its database write did
    // not commit. A caller cannot safely remove here: COMMIT may have succeeded
    // even when the database connection reports an uncertain result.
    const artifact = await store.createArtifact({ ...owned, messageId, artifact: result });
    if (!artifact) fail("Conversazione non disponibile.", "CONVERSATION_NOT_FOUND", 404);
    return { available: true, artifact };
  };
  return Object.freeze({
    async catalog({ signal } = {}) {
      await check(signal);
      const result = []; let bytes = 0;
      for (const file of (await store.listArtifacts(owned)).slice(-32)) {
        const item = { id: file.id, name: file.name, kind: file.kind, size: file.size };
        const length = Buffer.byteLength(JSON.stringify(item));
        if (bytes + length > 8192) break;
        result.push(item); bytes += length;
      }
      return result;
    },
    async createFile(args, { signal } = {}) {
      shape(args, ["name", "content"]);
      const name = filename(args.name); const source = content(args.content);
      await check(signal);
      return persist(await storage.createFile(owned, { name, source, mediaType: TYPES[extname(name).toLowerCase()] || "text/plain", signal }), signal);
    },
    async createZip(args, { signal } = {}) {
      shape(args, ["name", "files"]);
      const name = filename(args.name);
      if (!name.toLowerCase().endsWith(".zip") || !Array.isArray(args.files) || args.files.length < 1 || args.files.length > 32) fail("Specifica un archivio ZIP con da 1 a 32 file.");
      let textBytes = 0; const names = new Set(); const sourceRefs = new Set();
      const files = args.files.map(file => {
        shape(file, ["name", "content", "attachmentId", "artifactId"]);
        const cleanName = filename(file.name, true);
        if (names.has(cleanName)) fail("Nomi duplicati nell'archivio.");
        names.add(cleanName);
        const choices = ["content", "attachmentId", "artifactId"].filter(key => Object.hasOwn(file, key));
        if (choices.length !== 1) fail("Ogni file richiede un contenuto o un solo riferimento.");
        if (choices[0] === "content") textBytes += Buffer.byteLength(content(file.content));
        else if (!UUID.test(file[choices[0]])) fail("Riferimento del file non valido.");
        if (textBytes > CONTENT_BYTES) fail("Contenuto generato troppo grande per una singola operazione.");
        return { ...file, name: cleanName };
      });
      await check(signal);
      // Open source streams lazily: a rejected later entry never leaves an
      // earlier stream running, and 512 MiB inputs are never buffered in RAM.
      const entries = [];
      for (const file of files) {
        if (Object.hasOwn(file, "content")) { entries.push({ name: file.name, kind: "text", source: file.content }); continue; }
        const isAttachment = Object.hasOwn(file, "attachmentId");
        const available = isAttachment
          ? await store.getAttachmentMetadata({ ...owned, attachmentId: file.attachmentId })
          : (await store.listArtifacts(owned)).find(item => item.id === file.artifactId);
        if (!available) fail("File sorgente non disponibile in questa conversazione.", "ARTIFACT_SOURCE_NOT_FOUND", 404);
        if (isAttachment) sourceRefs.add(file.attachmentId);
        entries.push({ name: file.name, kind: available.kind === "image" ? "image" : "text", mediaType: available.mediaType, source: (async function* () {
          await check(signal);
          const opened = isAttachment ? await store.readAttachment({ ...owned, attachmentId: file.attachmentId }) : await store.readArtifact({ ...owned, artifactId: file.artifactId });
          if (!opened) fail("File sorgente non disponibile.", "ARTIFACT_SOURCE_NOT_FOUND", 404);
          const abort = () => opened.stream?.destroy(signal.reason);
          signal?.addEventListener("abort", abort, { once: true });
          try {
            signal?.throwIfAborted();
            if (opened.stream) { for await (const bytes of opened.stream) { signal?.throwIfAborted(); yield bytes; } }
            else if (opened.data != null) yield Buffer.from(opened.data);
            else fail("Contenuto sorgente non disponibile.", "ARTIFACT_SOURCE_NOT_FOUND", 404);
          } finally { signal?.removeEventListener("abort", abort); opened.stream?.destroy(); }
        })() });
      }
      if (sourceRefs.size > 5) fail("Massimo 5 allegati sorgente per archivio.");
      return persist(await storage.createZip(owned, { name, entries, sourceRefs: [...sourceRefs], signal }), signal);
    },
  });
}
