import { createFileStateStore } from "./file-store.mjs";

const stateRoot = "/var/www/project-state";

export function createControlStateStore(env = process.env, options = {}) {
  return createFileStateStore({
    ...options,
    datasets: controlStateDatasets(env),
  });
}

export function controlStateDatasets(env = process.env) {
  return {
    projects: json(env.PROJECT_STATE_FILE, "projects.json", { projects: {}, subdomains: {} }),
    audit: jsonl(env.PROJECT_AUDIT_FILE, "audit.jsonl"),
    operations: jsonl(env.PROJECT_OPERATIONS_FILE, "operations.jsonl"),
    applications: json(env.PROJECT_APPLICATIONS_FILE, "applications.json"),
    domains: json(env.PROJECT_DOMAINS_FILE, "domains.json"),
    webspaces: json(env.PROJECT_WEBSPACES_FILE, "webspaces.json"),
    storageBuckets: json(env.PROJECT_STORAGE_BUCKETS_FILE, "storage-buckets.json"),
    sensitiveMaterials: json(env.PROJECT_SENSITIVE_MATERIALS_FILE, "sensitive-materials.json"),
    workerJobs: json(env.PROJECT_WORKER_JOBS_FILE, "worker-jobs.json", { workers: {}, queues: {}, jobs: {}, schedules: {} }),
    identityAccess: json(env.PROJECT_IDENTITY_ACCESS_FILE, "identity-access.json", { users: {}, teams: {}, roles: {}, sessions: {}, accessReviews: {} }),
    deployments: jsonl(env.PROJECT_DEPLOYMENTS_FILE, "deployments.jsonl"),
    backupRecords: jsonl(env.PROJECT_BACKUP_RECORDS_FILE, "backups.jsonl"),
    resourceLimits: json(env.PROJECT_RESOURCE_LIMITS_FILE, "resource-limits.json"),
    securityPolicies: json(env.PROJECT_SECURITY_POLICIES_FILE, "security-policies.json"),
    alerts: json(env.PROJECT_ALERTS_FILE, "alerts.json"),
    notificationChannels: json(env.PROJECT_NOTIFICATION_CHANNELS_FILE, "notification-channels.json"),
    providerConnections: json(env.PROJECT_PROVIDER_CONNECTIONS_FILE, "provider-connections.json"),
    settings: json(env.PROJECT_SETTINGS_FILE, "settings.json"),
    statusRuns: jsonl(env.PROJECT_STATUS_RUNS_FILE, "status-runs.jsonl"),
    statusRunEvents: jsonl(env.PROJECT_STATUS_RUN_EVENTS_FILE, "status-run-events.jsonl"),
  };
}

export function validateStateRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("State record must be an object.");
}

function json(configuredPath, fileName, defaultValue = {}) {
  return { path: configuredPath || `${stateRoot}/${fileName}`, defaultValue, validate: validateStateRecord };
}

function jsonl(configuredPath, fileName) {
  return { path: configuredPath || `${stateRoot}/${fileName}`, kind: "jsonl", defaultValue: [], validate: validateStateRecord };
}
