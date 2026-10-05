import fs from 'node:fs';import path from 'node:path';
import {verifyOffsiteManifest} from '/opt/platform-infrastructure/scripts/local-private-docker-action-broker.mjs';
const root='/backups', records=[], invalid=[];
for(const name of fs.readdirSync(root+'/manifests')){if(!/^manifest-.*\.json$/.test(name))continue;try{const {manifest}=verifyOffsiteManifest(root+'/manifests/'+name,'/run/signing-keys');if(manifest.operation==='backup'&&manifest.scope.kind==='platform'&&manifest.coverage.complete)records.push({name,manifest});}catch{invalid.push(name);}}
records.sort((a,b)=>b.manifest.createdAt.localeCompare(a.manifest.createdAt));
console.log(JSON.stringify({records,invalid}));
