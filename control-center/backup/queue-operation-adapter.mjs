const QUEUE_OPERATIONS = Object.freeze(new Map([
  ["backup.run", Object.freeze({ control: true, jobOperations: Object.freeze(["backup"]) })],
  ["database.backup", Object.freeze({ control: true, jobOperations: Object.freeze(["backup"]) })],
  ["legacy.backup", Object.freeze({ control: false, jobOperations: Object.freeze(["backup", "restore-drill"]) })],
]));

export class BackupQueueOperationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "BackupQueueOperationError";
    this.code = code;
    this.status = 403;
  }
}

// This boundary consumes the immutable operation object produced by
// auth/route-capabilities.mjs. It intentionally does not accept a URL and does
// not contain an alias/path matcher; authorization and dispatch must share the
// same resolved registry object before invoking queue admission.
export function requireCanonicalBackupQueueOperation(operation, jobOperation) {
  if (!operation || typeof operation !== "object" || Array.isArray(operation) || !Object.isFrozen(operation)) {
    throw denied("operation_not_canonical", "Backup queue admission requires an immutable resolved operation.");
  }
  if (operation.classified !== true || operation.method !== "POST" || operation.capability !== "owner:fresh") {
    throw denied("operation_not_privileged", "Backup queue admission requires a classified fresh-owner POST operation.");
  }
  const policy = QUEUE_OPERATIONS.get(operation.operationId);
  if (!policy || operation.control !== policy.control) {
    throw denied("operation_not_admitted", "Resolved operation is not a privileged backup queue producer.");
  }
  const normalizedJobOperation = String(jobOperation || "");
  if (!policy.jobOperations.includes(normalizedJobOperation)) {
    throw denied("job_operation_mismatch", "Resolved route cannot create this backup job operation.");
  }
  if (typeof operation.canonicalPath !== "string" || !operation.canonicalPath.startsWith("/")) {
    throw denied("operation_not_canonical", "Resolved operation is missing its canonical registry path.");
  }
  return Object.freeze({
    operationId: operation.operationId,
    capability: operation.capability,
    control: operation.control,
    jobOperation: normalizedJobOperation,
  });
}

export function listBackupQueueOperationIds() {
  return Object.freeze([...QUEUE_OPERATIONS.keys()]);
}

function denied(code, message) {
  return new BackupQueueOperationError(code, message);
}
