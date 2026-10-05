import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {verifyOffsiteManifest,backupSigningKeyMap} from '/opt/platform-infrastructure/scripts/local-private-docker-action-broker.mjs';
const root=process.argv[2],manifestFile=process.argv[3],keyFile='/run/signing-keys';
const {manifest}=verifyOffsiteManifest(manifestFile,keyFile);
if(manifest.operation!=='backup'||manifest.scope.kind!=='platform'||!manifest.coverage.complete||manifest.artifacts.length!==manifest.resources.length)throw Error('Incomplete platform manifest');
const keys=backupSigningKeyMap(fs.readFileSync(keyFile));
let bytes=0;const paths=[`manifests/${manifest.id}.json`];
for(const a of manifest.artifacts){
 if(!/^[A-Za-z0-9_.\/-]+$/.test(a.path)||a.path.split('/').some(x=>x==='..'||!x)||path.isAbsolute(a.path))throw Error('Unsafe artifact path');
 const file=path.join(root,a.path),st=fs.lstatSync(file);
 if(!st.isFile()||st.isSymbolicLink()||st.size!==a.sizeBytes)throw Error('Invalid artifact');
 const h=crypto.createHash('sha256');for await(const chunk of fs.createReadStream(file))h.update(chunk);
 if(h.digest('hex')!==a.sha256)throw Error('Artifact SHA mismatch');
 const sig=JSON.parse(fs.readFileSync(file+'.sig.json','utf8'));
 const value=crypto.createHmac('sha256',keys.get(a.signatureKeyId)).update(`platform-postgres-backup-v1\n${path.basename(file)}\n${a.sha256}\n`).digest('base64url');
 if(sig.algorithm!=='HMAC-SHA256'||sig.artifact!==path.basename(file)||sig.sha256!==a.sha256||sig.keyId!==a.signatureKeyId||sig.signature!==value||fs.readFileSync(file+'.sha256','utf8').trim().split(/\s+/)[0]!==a.sha256)throw Error('Artifact sidecar mismatch');
 paths.push(a.path,a.path+'.sha256',a.path+'.sig.json');bytes+=st.size;
}
console.log(JSON.stringify({manifestId:manifest.id,manifestDigest:manifest.signature.digest,artifactCount:manifest.artifacts.length,artifactBytes:bytes,paths,manifestSignatureVerified:true,artifactSignaturesVerified:true}));
