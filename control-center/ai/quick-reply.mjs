export function assistantContinuationKind(message) {
  const normalized = String(message || "").trim().toLocaleLowerCase("it-IT").replace(/[.!?…]+$/u, "").replace(/\s+/g, " ");
  return normalized === "riassumi" ? "summary" : normalized === "approfondisci" ? "expand" : null;
}

export function isCanonicalAssistantContinuation(message) {
  return assistantContinuationKind(message) !== null;
}

export function shouldReloadHistoricalAttachmentContext(message, attachmentIds = [], internalAttachmentContinuation = false) {
  if (internalAttachmentContinuation || (Array.isArray(attachmentIds) && attachmentIds.length > 0)) return true;
  return !isCanonicalAssistantContinuation(message);
}
