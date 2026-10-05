import {canonicalJson} from './docker-action-contract.mjs';
export const NATIVE_SCHEMA='platform.local-private-backup-admission/v2';
export const OPERATOR_SOCKET='/run/platform/backup-operator/operator.sock';
export const OPERATOR_HOST_SOCKET='/run/platform-backup-operator/operator.sock';
export const NATIVE_ACTIONS=Object.freeze(['backup.offsite.sync','restore.offsite.proof']);
const SHA=/^[a-f0-9]{64}$/; const IMAGE=/^sha256:[a-f0-9]{64}$/;
export function exact(value,keys,label){if(!value||typeof value!=='object'||Array.isArray(value)||canonicalJson(Object.keys(value).sort())!==canonicalJson([...keys].sort()))throw Error(`${label} exact fields rejected`);}
function digest(v,label){if(!SHA.test(v)||v==='0'.repeat(64))throw Error(`${label} SHA rejected`);}
export function validateNativeResources(resources){
 exact(resources,['backupResources','capabilityFiles','offsite','objectStore','operator'],'native resources');
 const o=resources.offsite;
 exact(o,['backend','host','port','tlsName','folder','receiptSchema','maxBytes','maxAgeSeconds','maxPoints','maxPartBytes','restoreSelection','activationEvidence'],'native offsite');
 const fixed={backend:'ftps-multipart-v2',host:'92.113.28.106',port:21,tlsName:'hstgr.io',folder:'/server-platform-backups',receiptSchema:'platform.ftps-recovery-point/v2',maxBytes:70000000000,maxAgeSeconds:1209600,maxPoints:6,maxPartBytes:1000000000,restoreSelection:'latest-complete-authenticated'};
 if(Object.entries(fixed).some(([k,v])=>o[k]!==v))throw Error('Native FTPS fixed boundary rejected');
 exact(o.activationEvidence,['manifestId','manifestDigest','receiptSha256','requiredLiveAnchor'],'activation evidence');
 if(!/^manifest-[a-z0-9][a-z0-9-]{15,127}$/.test(o.activationEvidence.manifestId)||o.activationEvidence.requiredLiveAnchor!==false)throw Error('Activation proof cannot become an indefinite retention anchor');
 digest(o.activationEvidence.manifestDigest,'activation manifest');digest(o.activationEvidence.receiptSha256,'activation receipt');
 const s=resources.objectStore;
 exact(s,['backend','container','volume','image','imageId','archiveFormat','rootMarker','restoreMode'],'object store');
 if(s.backend!=='rustfs'||s.container!=='gf-rustfs'||s.volume!=='platform_rustfs_data'||s.archiveFormat!=='rustfs-volume/v1'||s.rootMarker!=='.rustfs.sys'||s.restoreMode!=='isolated-only'||!/^rustfs\/rustfs@sha256:[a-f0-9]{64}$/.test(s.image)||!IMAGE.test(s.imageId))throw Error('Native RustFS boundary rejected');
 const w=resources.operator;
 exact(w,['protocol','socket','uid','helperSha256','restoreHelperSha256','rustfsHelperSha256','rustfsRestoreHelperSha256','workerSha256','peerContainer','peerImageId'],'operator');
 if(w.protocol!=='platform.backup-operator/v2'||w.socket!==OPERATOR_SOCKET||w.uid!==0||w.peerContainer!=='gf-docker-action-broker'||!IMAGE.test(w.peerImageId))throw Error('Native operator boundary rejected');
 for(const k of ['helperSha256','restoreHelperSha256','rustfsHelperSha256','rustfsRestoreHelperSha256','workerSha256'])digest(w[k],k);
 return resources;
}
