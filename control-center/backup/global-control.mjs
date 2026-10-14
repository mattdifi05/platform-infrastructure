// Only the root-published catalog supplies the effective capture state. Local
// queue admission is a request, never evidence that the switch changed.
export function normalizeBackupControl(catalog) {
  const input = catalog?.backupControl;
  if (input === undefined) return { available: false, enabled: catalog?.enabled === true, revision: "", updatedAt: "", requestId: "" };
  if (!input || typeof input !== "object" || Array.isArray(input)
    || typeof input.available !== "boolean" || typeof input.enabled !== "boolean"
    || (input.available && !/^[a-f0-9]{64}$/.test(input.revision || ""))
    || (input.updatedAt && !Number.isFinite(Date.parse(input.updatedAt)))
    || (input.requestId && !/^[a-z0-9][a-z0-9-]{15,127}$/.test(input.requestId))) {
    throw Error("Root backup control readback unavailable");
  }
  return { available: input.available, enabled: input.enabled,
    revision: typeof input.revision === "string" ? input.revision : "",
    updatedAt: input.updatedAt || "", requestId: input.requestId || "" };
}

export function withBackupControl(catalog) {
  if (!catalog) return null;
  const backupControl = normalizeBackupControl(catalog);
  const enrollmentEnabled = typeof catalog.enrollmentEnabled === "boolean" ? catalog.enrollmentEnabled : catalog.enabled === true;
  return { ...catalog, backupControl, enrollmentEnabled, enabled: enrollmentEnabled && backupControl.enabled };
}
