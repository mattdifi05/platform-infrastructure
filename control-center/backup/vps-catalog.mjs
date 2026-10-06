// Optional VPS-only metadata adapter. Owner authentication remains in server.mjs.
import fs from 'node:fs';
import path from 'node:path';
import { backupDocumentDigest, normalizeBackupResources, parseBackupManifestDocument } from './contracts.mjs';
export function readVpsBackupCatalog(root) {
 if(!root) return null;
 const file=path.join(root,'catalog.json');const st=fs.lstatSync(file);
 if(!st.isFile()||st.isSymbolicLink()||st.uid!==0||(st.mode&0o022)||st.size>1048576)throw Error('VPS backup catalog unavailable');
 const x=JSON.parse(fs.readFileSync(file,'utf8'));
 if(x.host!=='platform-server-public'||x.schema!=='platform.vps-backup-catalog/v1'||!Array.isArray(x.points)||x.points.length>6)throw Error('Invalid VPS backup catalog');
 const resources=normalizeBackupResources(x.resources);
 const scriptaResource='platform-state:scriptastudents-persistent';
 const hasScripta=resources.some(r=>r.id===scriptaResource);
 if(resources.length!==(hasScripta?16:15)||resources.some(r=>r.kind!=='platform-state'||r.projectId!=='platform'))throw Error('Unexpected VPS backup resource catalog');
 const sorted=value=>JSON.stringify([...value].sort((a,b)=>a.id.localeCompare(b.id)));
 const precedingResources=resources.filter(r=>r.id!==scriptaResource);
 const manifests=x.points.map(p=>{
  const m=parseBackupManifestDocument(p.manifest);
  if(!p.offsiteVerified||m.signature?.digest!==backupDocumentDigest(m)||m.scope.kind!=='platform'||!/^manifest-vps-[a-z0-9-]+$/.test(m.id))throw Error('Unverified VPS recovery point');
  const restoreCompatible=sorted(m.resources)===sorted(resources);
  if(!restoreCompatible&&!(hasScripta&&m.resources.length===15&&sorted(m.resources)===sorted(precedingResources)))throw Error('Recovery point resource set differs from enrolled catalog');
  return {...m,path:`manifests/${m.id}.json`,encrypted:true,restoreCompatible,coversScripta:m.resources.some(r=>r.id===scriptaResource),artifacts:m.artifacts.map(a=>({...a,name:path.basename(a.path),sizeLabel:`${a.sizeBytes} B`,modifiedAt:m.createdAt,mtimeMs:Date.parse(m.createdAt)}))};
 }).sort((a,b)=>b.createdAt.localeCompare(a.createdAt));
 return {resources,manifests,productionRestoreEnabled:x.productionRestoreEnabled===true,restoreProfileDigest:/^[a-f0-9]{64}$/.test(x.restoreProfileDigest||'')?x.restoreProfileDigest:'',restoreScope:'runtime-data-and-bind-configs',enabled:x.enabled===true,queueActive:x.queueActive===true,scheduleActive:x.scheduleActive===true};
}
