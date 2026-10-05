export type RequestedMode = "auto" | "fast" | "deep";
export type ResolvedMode = "fast" | "deep";
export interface ModeRouterInput { requestedMode?: unknown; message?: unknown; attachments?: unknown[]; priorConversation?: unknown; projectId?: unknown; }
export interface ModeRouterResult { requestedMode: RequestedMode; resolvedMode: ResolvedMode; signals: readonly string[]; }
const REQUESTED_MODES = new Set<RequestedMode>(["auto", "fast", "deep"]);

const DEEP_INTENTS = Object.freeze([
  "analizza", "analisi", "diagnostica", "diagnosi", "perché", "perche", "causa radice",
  "root cause", "troubleshoot", "indaga", "confronta", "correla", "approfondisci",
  "investiga", "why", "investigate", "compare",
]);
const WEB_INTENTS = Object.freeze(["cerca", "ricerca", "web", "documentazione", "release", "fonte", "latest", "ufficiale"]);
const SERVER_INTENTS = Object.freeze(["server", "docker", "container", "log", "cpu", "ram", "gpu", "rete", "network"]);
const FETCH_INTENTS = Object.freeze(["apri", "leggi la pagina", "leggi le pagine", "verifica la fonte", "webfetch", "fetch", "open the page", "read the page"]);
const STACK_MARKERS = Object.freeze(["at ", "typeerror", "exception", "traceback", "stack trace", "error:", "errno", "caused by"]);
const PROJECT_ANALYSIS_INTENTS = Object.freeze(["architettura", "architecture", "login", "autenticazione", "permessi", "ruolo", "admin", "tabelle", "tabella", "schema", "migration", "migrazion", "record orfani", "indici", "codice morto", "dead code"]);

export function normalizeRequestedMode(value: unknown): RequestedMode {
  const mode = String(value || "auto").trim().toLowerCase();
  return REQUESTED_MODES.has(mode as RequestedMode) ? mode as RequestedMode : "auto";
}

/**
 * Resolve AUTO without an LLM. The result is deliberately structured so that
 * future routing signals can be added without turning this into one opaque
 * regular expression.
 */
export function resolveServerAiMode({
  requestedMode = "auto",
  message = "",
  attachments = [],
  priorConversation = null,
  projectId = null,
}: ModeRouterInput = {}): Readonly<ModeRouterResult> {
  const requested = normalizeRequestedMode(requestedMode);
  if (requested !== "auto") {
    return Object.freeze({ requestedMode: requested, resolvedMode: requested, signals: Object.freeze(["explicit_override"]) });
  }

  const text = String(message || "").trim();
  const normalized = text.toLocaleLowerCase("it-IT");
  const signals: string[] = [];
  let depth = 0;
  const add = (name: string, weight: number): void => { signals.push(name); depth += weight; };

  const lineCount = text ? text.split(/\r?\n/).length : 0;
  const referenceCount = countReferences(text);
  const attachmentCount = Array.isArray(attachments) ? attachments.filter(Boolean).length : 0;
  const codeBlock = text.includes("```") || /(?:^|\n)\s*(?:const|let|function|class|interface|type|import|export)\s+\w/m.test(text);
  const stackHits = countOccurrences(normalized, STACK_MARKERS);
  const deepIntent = includesAny(normalized, DEEP_INTENTS);
  const webIntent = includesAny(normalized, WEB_INTENTS);
  const serverIntent = includesAny(normalized, SERVER_INTENTS);
  const fetchIntent = includesAny(normalized, FETCH_INTENTS);

  if (text.length >= 1800 || lineCount >= 45) add("long_input", 2);
  else if (text.length >= 700 || lineCount >= 18) add("medium_input", 1);
  if (codeBlock) add("code", lineCount >= 28 ? 2 : 1);
  if (stackHits >= 3) add("stack_trace", 2);
  if (deepIntent) add("analysis_intent", 2);
  if (typeof projectId === "string" && /^[a-z0-9][a-z0-9-]{0,63}$/.test(projectId) && includesAny(normalized, PROJECT_ANALYSIS_INTENTS)) add("project_analysis", 2);
  if (attachmentCount > 0) add("attachments", attachmentCount > 1 ? 2 : 1);
  if (referenceCount >= 3) add("multiple_references", 2);
  else if (referenceCount >= 2) add("multiple_references", 1);

  if (webIntent) {
    signals.push("web_request");
    if (referenceCount >= 2 || deepIntent || codeBlock || serverIntent) depth += 1;
  }
  if (serverIntent) signals.push("server_request");
  if (webIntent && fetchIntent) add("multi_step_web_verification", 2);

  const prior = normalizePriorConversation(priorConversation);
  if (prior.turnCount >= 10 || prior.hasUnresolvedQuestion || prior.hasSummary && (deepIntent || referenceCount >= 2)) {
    add("conversation_context", 1);
  }

  return Object.freeze({
    requestedMode: "auto",
    resolvedMode: depth >= 2 ? "deep" : "fast",
    signals: Object.freeze(signals),
  });
}

function normalizePriorConversation(value: unknown): { turnCount: number; hasSummary: boolean; hasUnresolvedQuestion: boolean } {
  if (!value || typeof value !== "object") return { turnCount: 0, hasSummary: false, hasUnresolvedQuestion: false };
  const prior = value as { turnCount?: unknown; hasSummary?: unknown; hasUnresolvedQuestion?: unknown };
  return {
    turnCount: typeof prior.turnCount === "number" && Number.isSafeInteger(prior.turnCount) && prior.turnCount > 0 ? prior.turnCount : 0,
    hasSummary: prior.hasSummary === true,
    hasUnresolvedQuestion: prior.hasUnresolvedQuestion === true,
  };
}

function includesAny(text: string, values: readonly string[]): boolean {
  return values.some((value) => text.includes(value));
}

function countOccurrences(text: string, values: readonly string[]): number {
  return values.reduce((count, value) => count + (text.split(value).length - 1), 0);
}

function countReferences(text: string): number {
  const urls = text.match(/https?:\/\/[^\s)\]}>,]+/gi) || [];
  const citations = text.match(/(?:\[[^\]]+\]|\b(?:fonte|source|riferimento)\s*\d+)/gi) || [];
  return Math.min(12, urls.length + citations.length);
}
