// Optional root-published VPS metadata adapter. Owner authentication remains in server.mjs.
import fs from 'node:fs';
import path from 'node:path';
import { backupDocumentDigest, normalizeBackupResources, parseBackupManifestDocument } from './contracts.mjs';

const SCRIPTA_PROJECT = 'scriptastudents';
const SCRIPTA_PERSISTENT = 'platform-state:scriptastudents-persistent';
const APPLICATION_RESOURCES = [
  { id: 'source:scriptastudents', externalId: 'scriptastudents', kind: 'source', projectId: SCRIPTA_PROJECT, name: 'scriptastudents', sourceDirectory: 'scriptastudents' },
  { id: 'database:scriptastudents-postgres-students-beta-app', externalId: 'scriptastudents-postgres-students-beta-app', kind: 'database', projectId: SCRIPTA_PROJECT, name: 'students_beta_app', engine: 'postgres' },
  { id: 'platform-state:scriptastudents-state', externalId: 'scriptastudents-state', kind: 'platform-state', projectId: SCRIPTA_PROJECT, name: 'scriptastudents-state' },
];
const WORKCALENDAR_PROJECT='workcalendar';
const WORKCALENDAR_PERSISTENT='platform-state:workcalendar-persistent';
const WORKCALENDAR_RESOURCES=[
  {id:'source:workcalendar',externalId:'workcalendar',kind:'source',projectId:WORKCALENDAR_PROJECT,name:'workcalendar',sourceDirectory:'workcalendar'},
  {id:'database:workcalendar-postgres-workcalendar-app',externalId:'workcalendar-postgres-workcalendar-app',kind:'database',projectId:WORKCALENDAR_PROJECT,name:'workcalendar_app',engine:'postgres'},
  {id:'platform-state:workcalendar-state',externalId:'workcalendar-state',kind:'platform-state',projectId:WORKCALENDAR_PROJECT,name:'workcalendar-state'},
];
const FINITE_APPS=new Map([[SCRIPTA_PROJECT,APPLICATION_RESOURCES],[WORKCALENDAR_PROJECT,WORKCALENDAR_RESOURCES]]);
const sorted = value => JSON.stringify([...value].sort((a, b) => a.id.localeCompare(b.id)));
const RESOURCE_MODES = new Map([...FINITE_APPS.values()].flatMap(resources => [[sorted(resources.slice(0,1)),'source'],[sorted(resources.slice(1,2)),'database'],[sorted(resources),'all']]));

function readApplications(value, restoreProfileDigest) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 2 || new Set(value.map(a=>a?.projectId)).size!==value.length) throw Error('Unexpected VPS application catalog');
  return value.map(application => {
    if (!application || typeof application !== 'object' || Array.isArray(application)
      || Object.keys(application).some(key => !['projectId', 'resources', 'enabled', 'productionRestoreEnabled'].includes(key))
      || !FINITE_APPS.has(application.projectId) || typeof application.enabled !== 'boolean'
      || typeof application.productionRestoreEnabled !== 'boolean') throw Error('Unexpected VPS application catalog');
    const resources = normalizeBackupResources(application.resources);
    if (sorted(resources) !== sorted(FINITE_APPS.get(application.projectId))) throw Error('Unexpected VPS application resource catalog');
    if ((application.enabled || application.productionRestoreEnabled) && !restoreProfileDigest) throw Error('Missing VPS application restore profile');
    return { id: application.projectId, projectId: application.projectId, resources, enabled: application.enabled,
      productionRestoreEnabled: application.productionRestoreEnabled, restoreProfileDigest, manifests: [] };
  });
}

function publicManifest(manifest, properties) {
  return { ...manifest, path: `manifests/${manifest.id}.json`, encrypted: true, ...properties,
    artifacts: manifest.artifacts.map(artifact => ({ ...artifact, name: path.basename(artifact.path),
      sizeLabel: `${artifact.sizeBytes} B`, modifiedAt: manifest.createdAt, mtimeMs: Date.parse(manifest.createdAt) })) };
}

export function readVpsBackupCatalog(root) {
  if (!root) return null;
  const file = path.join(root, 'catalog.json');
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o022) || stat.size > 1048576) throw Error('VPS backup catalog unavailable');
  const catalog = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (catalog.host !== 'platform-server-public' || catalog.schema !== 'platform.vps-backup-catalog/v1'
    || !Array.isArray(catalog.points) || catalog.points.length > 6) throw Error('Invalid VPS backup catalog');
  const resources = normalizeBackupResources(catalog.resources);
  const hasScripta = resources.some(resource => resource.id === SCRIPTA_PERSISTENT);
  const hasWorkcalendar=resources.some(resource=>resource.id===WORKCALENDAR_PERSISTENT);
  if (hasWorkcalendar && !hasScripta) throw Error('WorkCalendar requires existing Scripta admission');
  if (resources.length !== (hasScripta ? hasWorkcalendar ? 17 : 16 : 15)
    || resources.some(resource => resource.kind !== 'platform-state' || resource.projectId !== 'platform')) throw Error('Unexpected VPS backup resource catalog');
  const historicalResources=[resources.filter(r=>r.id!==WORKCALENDAR_PERSISTENT),resources.filter(r=>r.id!==WORKCALENDAR_PERSISTENT&&r.id!==SCRIPTA_PERSISTENT)];
  const restoreProfileDigest = /^[a-f0-9]{64}$/.test(catalog.restoreProfileDigest || '') ? catalog.restoreProfileDigest : '';
  const applications = readApplications(catalog.applications, restoreProfileDigest);
  const manifests = [];
  const ids = new Set();
  for (const point of catalog.points) {
    if (point.restoreCompatible !== undefined && typeof point.restoreCompatible !== 'boolean') throw Error('Invalid VPS restore compatibility');
    const manifest = parseBackupManifestDocument(point.manifest);
    if (point.offsiteVerified !== true || manifest.signature?.digest !== backupDocumentDigest(manifest)
      || !/^manifest-vps-[a-z0-9-]+$/.test(manifest.id) || ids.has(manifest.id)) throw Error('Unverified VPS recovery point');
    ids.add(manifest.id);
    if (manifest.scope.kind === 'application') {
      const application = applications.find(value => value.projectId === manifest.scope.id);
      const restoreMode = RESOURCE_MODES.get(sorted(manifest.resources));
      if (!application || !restoreMode || manifest.resources.some(resource=>resource.projectId!==application.projectId)) throw Error('Application recovery point differs from admitted resource catalog');
      application.manifests.push(publicManifest(manifest, { restoreCompatible: point.restoreCompatible !== false, coversScripta: application.projectId===SCRIPTA_PROJECT, coversWorkcalendar:application.projectId===WORKCALENDAR_PROJECT, restoreMode }));
      continue;
    }
    if (manifest.scope.kind !== 'platform') throw Error('Unverified VPS recovery point');
    const resourceCompatible = sorted(manifest.resources) === sorted(resources);
    if (!resourceCompatible && !historicalResources.some(previous=>sorted(manifest.resources)===sorted(previous))) throw Error('Recovery point resource set differs from enrolled catalog');
    const restoreCompatible = resourceCompatible && point.restoreCompatible !== false;
    manifests.push(publicManifest(manifest, { restoreCompatible, coversScripta: manifest.resources.some(resource => resource.id === SCRIPTA_PERSISTENT) }));
  }
  manifests.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  for (const application of applications) application.manifests.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  return { resources, manifests, applications, applicationManifests: applications.flatMap(application => application.manifests),
    productionRestoreEnabled: catalog.productionRestoreEnabled === true, restoreProfileDigest,
    restoreScope: 'runtime-data-and-bind-configs', enabled: catalog.enabled === true,
    queueActive: catalog.queueActive === true, scheduleActive: catalog.scheduleActive === true };
}
