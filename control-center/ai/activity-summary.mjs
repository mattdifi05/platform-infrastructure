const PROJECT_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const DATABASE_ID = /^[a-z0-9][a-z0-9-]{0,95}$/;
const CONTAINER_ID = /^[a-f0-9]{64}$/;
const SAFE_PATH_COMPONENT = /^[^\u0000-\u001f\\/:]{1,160}$/;
const DENIED_PATH_COMPONENTS = new Set([
  ".git", ".hg", ".svn", ".env", ".pnpm-store", "node_modules", "vendor",
  "secrets", "credentials", "uploads", "backups", "backup",
]);
const DENIED_FILE = /^(?:\.env(?:\..*)?|\.npmrc|\.pypirc|auth\.json|id_(?:rsa|ed25519)|.*\.(?:pem|key|p12|pfx|jks|keystore|sqlite|db|dump|bak))$/i;
const SENSITIVE_PATH_COMPONENT = /(?:^|[-_.])(?:secret|credential|password|passwd|token|private[-_]?key)s?(?:$|[-_.])/i;
const COMPLETED_OUTCOMES = new Set(["success", "unavailable"]);

const TOOLS = Object.freeze({
  getServerOverview: ["Panoramica server", "server"],
  getCpuUsage: ["Uso CPU", "server"],
  getMemoryUsage: ["Uso memoria", "server"],
  getDiskUsage: ["Uso disco", "server"],
  getLoadAverage: ["Carico sistema", "server"],
  getSystemUptime: ["Uptime sistema", "server"],
  getGpuStatus: ["Stato GPU", "server"],
  listMachineProjects: ["Catalogo progetti", "projects"],
  getDockerContainers: ["Container Docker", "containers"],
  getProjectContainers: ["Container progetto", "projectContainers"],
  getProjectOverview: ["Panoramica progetto", "projectOverview"],
  searchProjectKnowledge: ["Conoscenza progetto", "projectKnowledge"],
  searchProjectFiles: ["Ricerca nei file", "projectSources"],
  readProjectFile: ["Lettura file", "projectFile"],
  readChatAttachment: ["Lettura allegato", "attachment"],
  listChatArchive: ["Contenuto dello ZIP", "archive"],
  readChatArchiveEntry: ["Lettura file nello ZIP", "archiveEntry"],
  analyzeChatAttachment: ["Analisi completa del file", "scan"],
  createChatFile: ["Creazione file", "artifact"],
  createChatZip: ["Creazione archivio ZIP", "artifact"],
  getProjectFileTree: ["Albero file", "projectSources"],
  listProjectFiles: ["Elenco file", "projectSources"],
  getProjectGitStatus: ["Stato Git", "projectGit"],
  getProjectGitLog: ["Cronologia Git", "projectGit"],
  getProjectGitBranch: ["Branch Git", "projectGit"],
  getProjectGitFileHistory: ["Cronologia file Git", "projectFile"],
  getProjectGitDiff: ["Diff Git", "projectFile"],
  getProjectGitBlame: ["Blame Git", "projectFile"],
  getProjectDatabaseSchema: ["Schema database", "databaseSchema"],
  getProjectDatabaseStats: ["Statistiche database", "database"],
  explainProjectDatabase: ["Piano query", "database"],
  queryProjectDatabase: ["Query in sola lettura", "databaseQuery"],
  getContainerStatus: ["Stato container", "container"],
  getContainerStats: ["Metriche container", "container"],
  getContainerHealth: ["Salute container", "container"],
  getContainerLogs: ["Log container", "container"],
  getNetworkOverview: ["Rete server", "server"],
  getListeningServices: ["Servizi esposti", "server"],
  getRecentSystemErrors: ["Errori recenti", "server"],
  getApplicationHealth: ["Salute applicazioni", "applications"],
  getBackupStatus: ["Stato backup", "server"],
  webSearch: ["Ricerca web", "webSearch"],
  webFetch: ["Lettura fonte web", "web"],
});

export const SUPPORTED_ACTIVITY_TOOLS = Object.freeze(Object.keys(TOOLS));

function ownObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function count(value, key) {
  const rows = ownObject(value)[key];
  return Array.isArray(rows) ? Math.min(rows.length, 10_000) : 0;
}

function safeProjectId(args, result, fallback) {
  for (const value of [ownObject(args).projectId, ownObject(result).projectId, fallback]) {
    if (typeof value === "string" && PROJECT_ID.test(value)) return value;
  }
  return null;
}

function safePath(value) {
  if (typeof value !== "string" || !value || value.length > 512 || value.startsWith("/") || value.includes("//")) return null;
  const parts = value.split("/");
  if (parts.some(part => part === "." || part === ".." || !SAFE_PATH_COMPONENT.test(part)
    || DENIED_PATH_COMPONENTS.has(part.toLowerCase()) || SENSITIVE_PATH_COMPONENT.test(part))) return null;
  if (DENIED_FILE.test(parts.at(-1))) return null;
  return value;
}

function targetFor(kind, args, result, projectId) {
  if (["attachment", "archive", "archiveEntry", "scan", "artifact"].includes(kind)) {
    const name = ownObject(result).filename || ownObject(ownObject(result).artifact).name || ownObject(ownObject(result).scan).filename;
    if (kind === "archiveEntry") {
      const path = safePath(ownObject(ownObject(result).entry).path || ownObject(result).path);
      if (path) return `ZIP · ${path}`.slice(0, 240);
    }
    return typeof name === "string" && name.length <= 180 && !/[\x00-\x1f\x7f/\\]/.test(name) ? `Allegato · ${name}` : "Allegati della chat";
  }
  const project = safeProjectId(args, result, projectId);
  if (kind === "web" || kind === "webSearch") return "Web pubblico";
  if (kind === "server" || kind === "containers" || kind === "applications") return "Server locale";
  if (kind === "container") {
    const id = ownObject(args).containerId;
    return typeof id === "string" && CONTAINER_ID.test(id) ? `Container ${id.slice(0, 12)}` : "Container autorizzato";
  }
  if (kind === "projects") return "Catalogo macchina";
  if (kind === "database" || kind === "databaseQuery" || kind === "databaseSchema") {
    const database = ownObject(args).databaseId;
    const base = project ? `Progetto ${project}` : "Progetto autorizzato";
    return typeof database === "string" && DATABASE_ID.test(database) ? `${base} · DB ${database}` : base;
  }
  const base = project ? `Progetto ${project}` : "Progetto autorizzato";
  if (kind === "projectFile") {
    const path = safePath(ownObject(args).path);
    return path ? `${base} · ${path}`.slice(0, 240) : base;
  }
  return base;
}

function plural(value, one, many) {
  return `${value} ${value === 1 ? one : many}`;
}

function schemaCounts(result) {
  let tables = 0;
  let columns = 0;
  for (const item of Array.isArray(ownObject(result).items) ? result.items.slice(0, 32) : []) {
    const schema = ownObject(item).schema;
    tables += count(schema, "tables");
    columns += count(schema, "columns");
  }
  return { tables: Math.min(tables, 10_000), columns: Math.min(columns, 100_000) };
}

function databaseRowCount(result) {
  let rows = 0;
  let recognized = false;
  for (const item of Array.isArray(ownObject(result).items) ? result.items.slice(0, 32) : []) {
    const content = ownObject(item).content;
    if (typeof content !== "string" || content.length > 64 * 1024) continue;
    try {
      const parsed = JSON.parse(content);
      if (!Array.isArray(parsed?.rows)) continue;
      recognized = true;
      rows += Math.min(parsed.rows.length, 10_000 - rows);
      if (rows >= 10_000) break;
    } catch {}
  }
  return recognized ? rows : null;
}

function completedSummary(kind, result) {
  switch (kind) {
    case "archive": return `${plural(count(result, "entries"), "voce elencata", "voci elencate")}${result?.nextCursor ? " (elenco parziale)" : ""}.`;
    case "archiveEntry": return result?.hasMore ? "Estratto del file nello ZIP letto." : "File nello ZIP letto.";
    case "scan": {
      const scan = ownObject(result?.scan || result);
      if (scan.status === "completed" && Number.isSafeInteger(scan.processedBytes) && scan.processedBytes === scan.totalBytes) return "Analisi di tutti i blocchi completata.";
      if (scan.status === "running" || scan.status === "queued") return "Analisi a blocchi avviata in background.";
      return "Stato dell’analisi acquisito.";
    }
    case "artifact": return "File creato e disponibile per il download.";
    case "attachment": if (Number.isSafeInteger(result?.startByte) && Number.isSafeInteger(result?.endByte)) return `Byte ${result.startByte}–${result.endByte} letti${result.hasMore ? " (estratto parziale)" : ""}.`; return Number.isInteger(result?.startLine) && Number.isInteger(result?.endLine) ? `Righe ${result.startLine}–${result.endLine} lette${result.truncated ? " (estratto parziale)" : ""}.` : "Allegato letto.";
    case "projects": return `${plural(count(result, "projects"), "progetto rilevato", "progetti rilevati")}.`;
    case "containers": return `${plural(count(result, "containers"), "container rilevato", "container rilevati")}.`;
    case "applications": return `${plural(count(result, "applications"), "applicazione verificata", "applicazioni verificate")}.`;
    case "projectContainers": return `${plural(count(result, "containers"), "container verificato", "container verificati")}.`;
    case "projectOverview": {
      return `${count(result, "applications")} applicazioni, ${count(result, "containers")} container e ${count(result, "databases")} database rilevati.`;
    }
    case "projectKnowledge": return `${plural(count(result, "sources"), "riferimento verificato", "riferimenti verificati")}.`;
    case "projectSources": return `${plural(count(result, "items"), "riferimento verificato", "riferimenti verificati")}.`;
    case "projectFile": return `${plural(count(result, "items"), "fonte letta", "fonti lette")}.`;
    case "projectGit": return `${plural(count(result, "items"), "fonte Git letta", "fonti Git lette")}.`;
    case "databaseSchema": {
      const value = schemaCounts(result);
      return `${value.tables} tabelle e ${value.columns} colonne descritte.`;
    }
    case "databaseQuery": {
      const rows = databaseRowCount(result);
      return rows !== null
        ? `${plural(rows, "riga restituita", "righe restituite")}.`
        : "Risultato in sola lettura acquisito.";
    }
    case "database": return "Metadati database acquisiti.";
    case "webSearch": return `${plural(count(result, "results"), "risultato pubblico trovato", "risultati pubblici trovati")}.`;
    case "web": return "Fonte pubblica acquisita.";
    case "container": return "Dati del container acquisiti.";
    case "server": return "Dati del server acquisiti.";
    default: return "Dati verificati acquisiti.";
  }
}

function resultCount(kind, result) {
  const key = {
    projects: "projects", containers: "containers", applications: "applications",
    projectContainers: "containers", projectKnowledge: "sources", projectSources: "items", projectFile: "items",
    projectGit: "items", webSearch: "results",
  }[kind];
  if (key) return count(result, key);
  if (kind === "databaseQuery") return databaseRowCount(result);
  if (kind === "databaseSchema") return schemaCounts(result).tables;
  return null;
}

export function describeToolActivity({ name, args, result, projectId = null, outcome } = {}) {
  const metadata = typeof name === "string" && Object.hasOwn(TOOLS, name) ? TOOLS[name] : null;
  if (!metadata) return null;
  const [label, kind] = metadata;
  const target = targetFor(kind, args, result, projectId);
  if (outcome === undefined) return Object.freeze({ name, label, target, summary: "Consultazione in corso." });
  if (!COMPLETED_OUTCOMES.has(outcome)) return null;
  const effectiveOutcome = ownObject(result).available === false ? "unavailable" : outcome;
  const summary = effectiveOutcome === "unavailable" ? `${label} non disponibile.` : completedSummary(kind, result);
  const cardinality = effectiveOutcome === "success" ? resultCount(kind, result) : null;
  return Object.freeze({ name, label, target, summary, outcome: effectiveOutcome,
    ...(cardinality === null ? {} : { resultCount: cardinality }) });
}
