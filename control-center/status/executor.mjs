export class StatusExecutorError extends Error {}

export async function executeStatusChecks({
  runId,
  checks,
  delayMs = 0,
  timeoutMs = 30_000,
  onEvent = () => {},
  now = () => Date.now(),
}) {
  const catalog = validateCatalog(checks);
  const events = [];
  const results = [];
  let sequence = 0;
  const emit = (type, details = {}) => {
    const event = { schemaVersion: 1, runId, sequence: sequence += 1, type, timestamp: new Date(now()).toISOString(), ...details };
    events.push(event);
    onEvent(event);
  };

  emit("run-started", { total: catalog.length });
  for (const item of catalog) {
    if (delayMs > 0) await pause(delayMs);
    emit("check-started", { checkId: item.id, category: item.category, executionMode: item.executionMode });
    const started = now();
    let result;
    try {
      result = await withTimeout(Promise.resolve().then(() => item.run()), item.timeoutMs ?? timeoutMs, item.id);
      result = { ...result, id: result?.id || item.id, category: result?.category || item.category };
    } catch (error) {
      result = {
        id: item.id,
        title: item.title || item.id,
        category: item.category,
        source: "Executor Stato",
        required: item.required !== false,
        status: error?.code === "STATUS_TIMEOUT" ? "failed" : "failed",
        detail: error?.code === "STATUS_TIMEOUT" ? `Timeout executor dopo ${item.timeoutMs ?? timeoutMs} ms.` : "Il controllo ha generato un errore redatto.",
        nextAction: "Controlla il report executor e correggi il controllo prima di rilanciarlo.",
        errorCode: error?.code || "STATUS_EXECUTOR_ERROR",
      };
    }
    result.executionMode = item.executionMode;
    result.durationMs = Math.max(0, now() - started);
    results.push(result);
    emit("check-completed", { checkId: item.id, category: item.category, executionMode: item.executionMode, status: result.status, durationMs: result.durationMs });
  }
  emit("run-completed", { total: results.length });
  return { checks: results, events };
}

export function validateCatalog(checks) {
  if (!Array.isArray(checks)) throw new StatusExecutorError("Status catalog must be an array.");
  const seen = new Set();
  return checks.map((item) => {
    const id = String(item?.id || "").trim();
    const category = String(item?.category || "operational-evidence").trim();
    const executionMode = String(item?.executionMode || "evidence-validation").trim();
    if (!id || seen.has(id) || typeof item?.run !== "function") throw new StatusExecutorError(`Invalid or duplicate status executor: ${id || "missing"}.`);
    if (!["probe", "evidence-validation", "external-required"].includes(executionMode)) throw new StatusExecutorError(`Invalid execution mode for ${id}.`);
    seen.add(id);
    return { ...item, id, category, executionMode };
  });
}

function withTimeout(promise, timeoutMs, id) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) return promise;
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const error = new StatusExecutorError(`Status executor timed out: ${id}.`);
      error.code = "STATUS_TIMEOUT";
      reject(error);
    }, timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function pause(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
