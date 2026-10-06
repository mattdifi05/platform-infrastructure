#!/usr/bin/env node
// Uses the product's existing manifest contract and HMAC signature domain.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {createBackupJobDocument,createBackupManifestDocument,parseBackupManifestDocument,backupDocumentDigest} from '../../control-center/backup/contracts.mjs';
const [action,input,keyFile,output]=process.argv.slice(2);
const key=fs.readFileSync(keyFile);
if(key.length!==64) throw Error('Dedicated native manifest key must contain 64 bytes');
const mac=(id,digest)=>crypto.createHmac('sha256',key).update(`platform-backup-manifest-v1\n${id}\n${digest}\n`).digest('base64url');
const x=JSON.parse(fs.readFileSync(input,'utf8'));
if(action==='sign') {
 const job=createBackupJobDocument({id:x.jobId,operation:'backup',scope:{kind:'platform',id:'platform'},resources:x.resources,requestedBy:'vps-native-operator',environment:'production',createdAt:x.createdAt});
 const manifest=createBackupManifestDocument({id:`manifest-${x.jobId}`,job,artifacts:x.artifacts,createdAt:x.createdAt});
 if(!manifest.coverage.complete)throw Error('Incomplete manifest');
 const digest=backupDocumentDigest(manifest);
 manifest.signature={algorithm:'HMAC-SHA256',keyId:'vps-genesis-1',digest,value:mac(manifest.id,digest)};
 fs.writeFileSync(output,JSON.stringify(manifest)+'\n',{mode:0o600,flag:'wx'});
} else if(action==='verify') {
 const m=parseBackupManifestDocument(x);const digest=backupDocumentDigest(m);
 if(m.signature?.digest!==digest || m.signature.value!==mac(m.id,digest))throw Error('Native manifest authentication failed');
 process.stdout.write(JSON.stringify({manifestId:m.id,manifestDigest:digest,artifactCount:m.artifacts.length,coverageComplete:m.coverage.complete})+'\n');
} else throw Error('Unsupported native manifest operation');
