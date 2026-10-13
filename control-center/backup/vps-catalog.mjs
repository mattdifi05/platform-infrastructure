// Optional root-published VPS metadata adapter. Owner authentication remains in server.mjs.
import fs from 'node:fs';
import { hostExtension } from '../host-extension.mjs';
import path from 'node:path';
import { backupDocumentDigest, normalizeBackupResources, parseBackupManifestDocument } from './contracts.mjs';

function publicManifest(manifest, properties) {
  return { ...manifest, path: `manifests/${manifest.id}.json`, encrypted: true, ...properties,
    artifacts: manifest.artifacts.map(artifact => ({ ...artifact, name: path.basename(artifact.path),
      sizeLabel: `${artifact.sizeBytes} B`, modifiedAt: manifest.createdAt, mtimeMs: Date.parse(manifest.createdAt) })) };
}

export function readVpsBackupCatalog(root) {
  if (!root) return null;
  if (hostExtension.readVpsBackupCatalog) return hostExtension.readVpsBackupCatalog(root);
  const file = path.join(root, 'catalog.json');
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o022) || stat.size > 1048576) throw Error('VPS backup catalog unavailable');
  const catalog = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (typeof catalog.host !== 'string' || !/^[a-z0-9][a-z0-9.-]{0,252}$/.test(catalog.host) || catalog.schema !== 'platform.vps-backup-catalog/v1'
    || !Array.isArray(catalog.points) || catalog.points.length > 6) throw Error('Invalid VPS backup catalog');
  const resources = normalizeBackupResources(catalog.resources);
  if (resources.some(resource => resource.kind !== 'platform-state' || resource.projectId !== 'platform')) throw Error('Unexpected platform backup resources');
  if (catalog.applications?.length) throw Error('Host application backup extension is required');
  const restoreProfileDigest = /^[a-f0-9]{64}$/.test(catalog.restoreProfileDigest || '') ? catalog.restoreProfileDigest : '';
  const applications = [];
  const sorted = value => JSON.stringify([...value].sort((a, b) => a.id.localeCompare(b.id)));
  const manifests = [];
  const ids = new Set();
  for (const point of catalog.points) {
    if (point.restoreCompatible !== undefined && typeof point.restoreCompatible !== 'boolean') throw Error('Invalid VPS restore compatibility');
    const manifest = parseBackupManifestDocument(point.manifest);
    if (point.offsiteVerified !== true || manifest.signature?.digest !== backupDocumentDigest(manifest)
      || !/^manifest-vps-[a-z0-9-]+$/.test(manifest.id) || ids.has(manifest.id)) throw Error('Unverified VPS recovery point');
    ids.add(manifest.id);
    if (manifest.scope.kind !== 'platform') throw Error('Unverified VPS recovery point');
    const resourceCompatible = sorted(manifest.resources) === sorted(resources);
    if (!resourceCompatible) throw Error('Recovery point resource set differs from enrolled catalog');
    const restoreCompatible = resourceCompatible && point.restoreCompatible !== false;
    manifests.push(publicManifest(manifest, { restoreCompatible }));
  }
  manifests.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  for (const application of applications) application.manifests.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  return { resources, manifests, applications, applicationManifests: applications.flatMap(application => application.manifests),
    productionRestoreEnabled: catalog.productionRestoreEnabled === true, restoreProfileDigest,
    restoreScope: 'runtime-data-and-bind-configs', enabled: catalog.enabled === true,
    queueActive: catalog.queueActive === true, scheduleActive: catalog.scheduleActive === true };
}
