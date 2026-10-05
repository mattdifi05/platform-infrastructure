import path from "node:path";
import { createFileStateStore } from "../state/file-store.mjs";

const PROJECT_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const MACHINE_ID = /^[a-f0-9]{64}$/;
const ROLES = new Set(["owner", "admin", "viewer"]);
const MACHINE_WIDE_ROLES = new Set(["owner", "admin"]);
const SUBJECT_BYTES = 256;
const DEFAULT_PROJECTS = Object.freeze({
  // Registration is explicit, but an operator must add an assignment before a
  // person can see either project. This avoids a role-wide viewer grant.
  fiplatform: Object.freeze({ enabled: true, readOnly: true, assignments: [] }),
  workcalendar: Object.freeze({ enabled: true, readOnly: true, assignments: [] }),
});

export class ProjectRegistryError extends Error {
  constructor(message, status = 404, code = "PROJECT_NOT_AVAILABLE") {
    super(message);
    this.name = "ProjectRegistryError";
    this.status = status;
    this.code = code;
  }
}

function validateProjectId(value) {
  if (typeof value !== "string" || !PROJECT_ID.test(value)) throw new ProjectRegistryError("Progetto non disponibile.");
  return value;
}
function validateMachineId(value) {
  if (typeof value !== "string" || !MACHINE_ID.test(value)) throw new Error("Invalid AI project registry machine.");
  return value;
}
function validateSubject(value) {
  if (typeof value !== "string" || !value.trim() || Buffer.byteLength(value) > SUBJECT_BYTES || /[\u0000-\u001f]/.test(value)) throw new Error("Invalid AI project registry subject.");
  return value;
}
function normalizeRoles(roles) {
  if (!Array.isArray(roles) || roles.length < 1 || roles.length > 3) throw new Error("Invalid project registry roles.");
  const unique = [...new Set(roles)];
  if (unique.length !== roles.length || unique.some(role => !ROLES.has(role))) throw new Error("Invalid project registry roles.");
  return unique;
}
function validateAssignment(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some(key => !["subject", "machineId", "roles"].includes(key))) throw new Error("Invalid AI project assignment.");
  validateSubject(value.subject); validateMachineId(value.machineId); normalizeRoles(value.roles);
}
function validateRegistry(value) {
  if (!value || value.version !== 1 || !value.projects || Array.isArray(value.projects) || typeof value.projects !== "object") throw new Error("Invalid AI project registry.");
  const entries = Object.entries(value.projects);
  if (entries.length > 64) throw new Error("Invalid AI project registry.");
  for (const [id, record] of entries) {
    validateProjectId(id);
    if (!record || typeof record !== "object" || Array.isArray(record) || typeof record.enabled !== "boolean" || record.readOnly !== true || !Array.isArray(record.assignments) || record.assignments.length > 256 || Object.keys(record).some(key => !["enabled", "readOnly", "assignments"].includes(key))) throw new Error("Invalid AI project registry.");
    const keys = new Set();
    for (const assignment of record.assignments) {
      validateAssignment(assignment);
      const key = `${assignment.subject}\u0000${assignment.machineId}`;
      if (keys.has(key)) throw new Error("Duplicate AI project assignment.");
      keys.add(key);
    }
  }
}
function defaultRegistry() { return { version: 1, projects: structuredClone(DEFAULT_PROJECTS) }; }
function discoveredByCanonicalId(projects) {
  const result = new Map();
  for (const candidate of Array.isArray(projects) ? projects : []) {
    if (!candidate || typeof candidate !== "object") continue;
    const id = typeof candidate.id === "string" ? candidate.id : candidate.slug;
    if (!PROJECT_ID.test(id) || candidate.slug !== id || candidate.id !== id || result.has(id)) continue;
    if (candidate.filesAvailable !== true || candidate.filesystemExists !== true) continue;
    result.set(id, candidate);
  }
  return result;
}
function publicText(value, max = 160) {
  if (typeof value !== "string" || !value.trim() || value.length > max || /[\u0000-\u001f/\\]|\.\./.test(value)) return null;
  return value;
}
function publicProject(id, discovered) {
  const aliases = [...new Set((Array.isArray(discovered.aliases) ? discovered.aliases : []).map(value => publicText(value)).filter(Boolean))].slice(0, 16);
  const applications = (Array.isArray(discovered.applications) ? discovered.applications : []).slice(0, 16).flatMap(application => {
    if (!application || typeof application !== "object" || Array.isArray(application)) return [];
    const applicationId = publicText(application.id, 96);
    const name = publicText(application.name || applicationId);
    const runtime = ["php", "node", "static"].includes(application.runtime) ? application.runtime : "unknown";
    return applicationId && name ? [{ id: applicationId, label: name, runtime }] : [];
  });
  return Object.freeze({
    id, label: publicText(discovered.name) || id,
    runtime: ["php", "node", "static"].includes(discovered.runtime) ? discovered.runtime : "unknown",
    ...(aliases.length ? { aliases } : {}),
    ...(applications.length ? { applications } : {}),
    readOnly: true, source: "server-ai-project-registry",
  });
}

/** Server-owned canonical allowlist. It deliberately stores neither roots nor DB aliases. */
export function createProjectRegistry({ stateFile = "/var/www/project-state/projects.json", getProjects = () => [] } = {}) {
  if (typeof stateFile !== "string" || !path.isAbsolute(stateFile)) throw new TypeError("Project registry requires an absolute state file.");
  if (typeof getProjects !== "function") throw new TypeError("Project registry requires project discovery.");
  const store = createFileStateStore({ datasets: { projectRegistry: { path: path.join(path.dirname(stateFile), "server-ai-project-registry.json"), defaultValue: defaultRegistry(), validate: validateRegistry } } });
  function entries() { return store.read("projectRegistry", { strict: true }).value.projects; }
  function visible({ subject, role, machineId }) {
    if (!ROLES.has(role) || typeof subject !== "string" || !subject.trim() || !MACHINE_ID.test(machineId || "")) throw new ProjectRegistryError("Progetto non disponibile.", 403, "PROJECT_FORBIDDEN");
    const discovered = discoveredByCanonicalId(getProjects({ machineId }));
    const configured = entries();
    // A machine owner or administrator is allowed to inspect every canonical
    // project discovered on that machine.  A persisted disabled record remains
    // an explicit revocation even for that broader role.  Viewers deliberately
    // retain the narrower, per-subject assignment rule below.
    const ids = MACHINE_WIDE_ROLES.has(role)
      ? [...discovered.keys()].filter(id => configured[id]?.enabled !== false)
      : Object.entries(configured)
        .filter(([, entry]) => entry.enabled === true && entry.readOnly === true && entry.assignments.some(assignment => assignment.subject === subject && assignment.machineId === machineId && assignment.roles.includes(role)))
        .map(([id]) => id);
    return ids
      .flatMap(id => discovered.has(id) ? [publicProject(id, discovered.get(id))] : [])
      .sort((left, right) => left.label.localeCompare(right.label, "it"));
  }
  return Object.freeze({
    list(scope = {}) { return visible(scope); },
    resolve({ projectId, ...scope } = {}) {
      const id = validateProjectId(projectId);
      const project = visible(scope).find(entry => entry.id === id);
      if (!project) throw new ProjectRegistryError("Progetto non disponibile.");
      return project;
    },
    // Release/setup code may add explicitly reviewed assignments. It is an
    // additive merge: a restart or a later seed cannot erase another subject.
    applySeed({ projects } = {}) {
      if (!projects || typeof projects !== "object" || Array.isArray(projects)) throw new ProjectRegistryError("Seed progetti non valido.", 400, "PROJECT_SEED_INVALID");
      store.update("projectRegistry", current => {
        const next = structuredClone(current);
        for (const [id, incoming] of Object.entries(projects)) {
          validateProjectId(id);
          if (!incoming || typeof incoming !== "object" || Array.isArray(incoming) || typeof incoming.enabled !== "boolean" || incoming.readOnly !== true || !Array.isArray(incoming.assignments)) throw new ProjectRegistryError("Seed progetti non valido.", 400, "PROJECT_SEED_INVALID");
          for (const assignment of incoming.assignments) validateAssignment(assignment);
          const existing = next.projects[id] || { enabled: true, readOnly: true, assignments: [] };
          const merged = new Map(existing.assignments.map(assignment => [`${assignment.subject}\u0000${assignment.machineId}`, assignment]));
          for (const assignment of incoming.assignments) {
            const key = `${assignment.subject}\u0000${assignment.machineId}`;
            const previous = merged.get(key);
            merged.set(key, previous ? { ...previous, roles: [...new Set([...previous.roles, ...assignment.roles])].sort() } : structuredClone(assignment));
          }
          next.projects[id] = { enabled: incoming.enabled, readOnly: true, assignments: [...merged.values()] };
        }
        validateRegistry(next);
        return next;
      });
      return this.snapshot();
    },
    snapshot() { return structuredClone(entries()); },
  });
}
