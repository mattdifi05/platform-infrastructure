import { redactText } from './web.mjs';

const MACHINE = /^[a-f0-9]{64}$/;
const PROJECT = /^[a-z0-9][a-z0-9-]{0,63}$/;
const CURSOR = /^[A-Za-z0-9_-]{1,1024}$/;
const MAX_PROJECTS = 64;
const RUNTIMES = new Set(['php', 'node', 'static']);
const validProjectId = value => typeof value === 'string' && PROJECT.test(value);

function label(value, fallback) {
  if (typeof value !== 'string') return fallback;
  return redactText(value.replace(/[\u0000-\u001f\u007f]/g, ' '), 160).trim() || fallback;
}

function metadataRoot(row) {
  // Metadata may label an attested root, but can never introduce a root or
  // select a path. In particular, manifest slugs need not equal root names.
  if (!row || row.filesAvailable !== true || row.filesystemExists !== true
    || typeof row.relativePath !== 'string'
    || !PROJECT.test(row.relativePath)) return null;
  return row.relativePath;
}

function mergeMetadata(projects, discovered) {
  const canonicalIds = new Set(projects.map(row => row.id));
  const metadata = new Map();
  for (const row of Array.isArray(discovered) ? discovered.slice(0, 512) : []) {
    const root = metadataRoot(row);
    if (!root || !canonicalIds.has(root) || root === 'platform') continue;
    if (!metadata.has(root)) metadata.set(root, []);
    metadata.get(root).push(row);
  }
  return projects.map(({ id }) => {
    const rows = metadata.get(id) || [];
    const aliases = new Set();
    const applicationIds = new Set([id]);
    const applications = [];
    for (const row of rows) {
      for (const candidate of [row.id, row.slug, ...(Array.isArray(row.aliases) ? row.aliases.slice(0, 32) : [])]) {
        if (!validProjectId(candidate) || (canonicalIds.has(candidate) && candidate !== id)) continue;
        if (candidate !== id) aliases.add(candidate);
      }
      const appId = validProjectId(row.id) ? row.id : row.slug;
      if (!validProjectId(appId) || (canonicalIds.has(appId) && appId !== id)) continue;
      applicationIds.add(appId);
      if (!applications.some(app => app.id === appId)) applications.push({
        id: appId, name: label(row.name, appId), runtime: RUNTIMES.has(row.runtime) ? row.runtime : 'unknown',
      });
    }
    if (id === 'platform') {
      aliases.add('control-center'); aliases.add('platform-infrastructure');
      applicationIds.add('control-center');
    }
    const exact = rows.find(row => row.id === id || row.slug === id);
    const runtimes = new Set(rows.map(row => row.runtime).filter(value => RUNTIMES.has(value)));
    return {
      id, slug: id,
      name: id === 'platform' ? 'Piattaforma e Control Center' : label(exact?.name, id),
      runtime: runtimes.size === 1 ? [...runtimes][0] : 'unknown',
      filesAvailable: true, filesystemExists: true, relativePath: id,
      aliases: [...aliases].sort(), applicationIds: [...applicationIds].sort(),
      applications: applications.slice(0, 32), source: 'server-ai-machine-catalog',
    };
  }).sort((left, right) => left.id.localeCompare(right.id));
}

/** Machine-local reader attestation supplies IDs; Control Center supplies labels. */
export function createMachineProjectCatalog({
  machineId, local = false, reader, getDiscoveredProjects = () => [],
  getHiddenProjectIds = () => [],
  ttlMs = 15_000, now = Date.now,
} = {}) {
  if (!MACHINE.test(machineId || '') || typeof getDiscoveredProjects !== 'function'
    || typeof getHiddenProjectIds !== 'function'
    || typeof now !== 'function' || !Number.isInteger(ttlMs) || ttlMs < 0 || ttlMs > 60_000) {
    throw new TypeError('Invalid machine project catalog configuration.');
  }
  let projects = [];
  let refreshedAt = null;
  let pending = null;
  let available = false;
  let lastError = null;
  const configured = local === true && typeof reader?.projectsCatalog === 'function';

  function snapshot(scope = {}) {
    if (scope.machineId !== undefined && scope.machineId !== machineId) return [];
    return structuredClone(projects);
  }
  async function refresh({ signal, force = false } = {}) {
    signal?.throwIfAborted();
    if (!configured) return [];
    if (!force && refreshedAt !== null && now() - refreshedAt < ttlMs) return snapshot();
    if (pending) {
      await pending;
      signal?.throwIfAborted();
      return snapshot();
    }
    pending = (async () => {
      try {
        const rows = [];
        const seenIds = new Set();
        const seenCursors = new Set();
        let cursor;
        for (let page = 0; page < MAX_PROJECTS; page += 1) {
          signal?.throwIfAborted();
          const result = await reader.projectsCatalog({ ...(cursor ? { cursor } : {}), limit: MAX_PROJECTS, signal });
          if (!result || !Array.isArray(result.projects) || result.projects.length > MAX_PROJECTS
            || result.available === false) throw new Error('Invalid reader project catalog.');
          for (const item of result.projects) {
            if (!item || !validProjectId(item.id) || item.filesAvailable !== true
              || seenIds.has(item.id) || rows.length >= MAX_PROJECTS) throw new Error('Invalid reader project catalog.');
            seenIds.add(item.id); rows.push({ id: item.id });
          }
          const next = result.nextCursor;
          if (next === null || next === undefined) break;
          if (typeof next !== 'string' || !CURSOR.test(next) || seenCursors.has(next) || !result.projects.length
            || rows.length >= MAX_PROJECTS || page === MAX_PROJECTS - 1) throw new Error('Invalid reader project catalog.');
          seenCursors.add(next); cursor = next;
        }
        signal?.throwIfAborted();
        const discovered = await getDiscoveredProjects({ machineId });
        const hiddenIds = new Set(await getHiddenProjectIds({ machineId }));
        if ([...hiddenIds].some(id => !validProjectId(id))) throw new Error('Invalid hidden project IDs.');
        signal?.throwIfAborted();
        projects = mergeMetadata(rows.filter(row => !hiddenIds.has(row.id)), discovered);
        available = true; lastError = null; refreshedAt = now();
      } catch (error) {
        // Never publish a partial catalog or retain a previous root after a
        // failed refresh. No endpoint/path/error content enters the public view.
        projects = []; available = false; lastError = 'project_catalog_unavailable';
        refreshedAt = null;
        if (signal?.aborted) throw error;
      }
    })();
    try { await pending; return snapshot(); }
    finally { pending = null; }
  }
  function resolveApplicationProjectId(value, scope = {}) {
    if (scope.machineId !== undefined && scope.machineId !== machineId) return null;
    if (!validProjectId(value)) return null;
    const direct = projects.find(project => project.id === value);
    if (direct) return direct.id;
    const matches = projects.filter(project => project.applicationIds.includes(value) || project.aliases.includes(value));
    return matches.length === 1 ? matches[0].id : null;
  }
  return Object.freeze({
    refresh, snapshot, resolveApplicationProjectId,
    diagnostics: () => ({ machineId, configured, available, count: projects.length, refreshedAt, error: lastError }),
  });
}
