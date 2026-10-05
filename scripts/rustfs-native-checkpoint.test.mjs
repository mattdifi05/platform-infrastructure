import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalJson } from './docker-action-contract.mjs';
import { validateNativeRustfsCheckpoint,copyBoundRustfsArchive } from './rustfs-native-checkpoint.mjs';

const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function fixture(){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'rustfs-checkpoint-test-'));fs.mkdirSync(path.join(root,'archives'),{mode:0o700});
 const key=crypto.randomBytes(32),keyFile=path.join(root,'capability');fs.writeFileSync(keyFile,key,{mode:0o600});
 const image='rustfs/rustfs@sha256:'+'a'.repeat(64),imageId='sha256:'+'b'.repeat(64),cipher=Buffer.from('encrypted fixture bytes');
 const archiveName='rustfs-20260928T063000Z.tar.gz.gpg',archive=path.join(root,'archives',archiveName);fs.writeFileSync(archive,cipher,{mode:0o600});
 const proof={schema:'platform.rustfs-operator-backup/v1',backend:'rustfs',format:'rustfs-volume/v1',status:'passed',sourceContainer:'gf-rustfs',volume:'platform_rustfs_data',rootMarker:'.rustfs.sys',image,imageId,restoreBootVerified:true,s3SemanticRestoreVerified:true,decryptRoundtripVerified:true,signedBrokerCompatible:false,archive:'archives/'+archiveName,encryptedArchiveSha256:hash(cipher),plaintextArchiveSha256:hash('plain'),encryptedBytes:cipher.length};
 fs.writeFileSync(path.join(root,'archives',archiveName.replace('.tar.gz.gpg','.json')),JSON.stringify(proof),{mode:0o600});
 const admission={resources:{objectStore:{backend:'rustfs',container:'gf-rustfs',volume:'platform_rustfs_data',rootMarker:'.rustfs.sys',restoreMode:'isolated-only',archiveFormat:'rustfs-volume/v1',image,imageId},capabilityFiles:{'capability.backup.job.execute':{sha256:hash(key)}}}};
 const now=Date.parse('2026-09-28T07:00:00.000Z');
 const payload={schema:'platform.rustfs-checkpoint/v1',admissionSha256:hash(canonicalJson(admission)),createdAt:'2026-09-28T06:31:00.000000+00:00',backend:'rustfs',proof};
 function writeCheckpoint(){const mac=crypto.createHmac('sha256',key).update(Buffer.from('platform-rustfs-checkpoint-v1\0')).update(canonicalJson(payload)).digest('hex');fs.writeFileSync(path.join(root,'latest.native.json'),JSON.stringify({payload,hmacSha256:mac}),{mode:0o600});}
 writeCheckpoint();return {root,keyFile,admission,now,payload,archive,cipher,writeCheckpoint};
}
test('accepts admitted checkpoint, copies exact encrypted archive',t=>{
 const f=fixture();t.after(()=>fs.rmSync(f.root,{recursive:true,force:true}));
 const verified=validateNativeRustfsCheckpoint({checkpointRoot:f.root,admission:f.admission,capabilityFile:f.keyFile,now:f.now});
 const staged=path.join(f.root,'staged');assert.equal(copyBoundRustfsArchive({archive:verified.archive,stagingPath:staged,proof:verified.proof}),f.cipher.length);assert.deepEqual(fs.readFileSync(staged),f.cipher);
});
test('rejects stale checkpoint, false admission, tampered archive, and link',t=>{
 const f=fixture();t.after(()=>fs.rmSync(f.root,{recursive:true,force:true}));
 const validate=()=>validateNativeRustfsCheckpoint({checkpointRoot:f.root,admission:f.admission,capabilityFile:f.keyFile,now:f.now});
 f.payload.createdAt='2026-09-27T00:00:00.000000+00:00';f.writeCheckpoint();assert.throws(validate,/stale/);
 f.payload.createdAt='2026-09-28T06:31:00.000000+00:00';f.writeCheckpoint();f.admission.resources.objectStore.imageId='sha256:'+'c'.repeat(64);assert.throws(validate,/admission binding/);
 f.admission.resources.objectStore.imageId='sha256:'+'b'.repeat(64);const verified=validate();fs.writeFileSync(f.archive,'changed encrypted bytes');assert.throws(()=>copyBoundRustfsArchive({archive:verified.archive,stagingPath:path.join(f.root,'staged'),proof:verified.proof}),/archive SHA256 differs|archive metadata differs/);
 fs.rmSync(f.archive);fs.symlinkSync('/dev/null',f.archive);assert.throws(()=>copyBoundRustfsArchive({archive:f.archive,stagingPath:path.join(f.root,'staged2'),proof:verified.proof}));
});
