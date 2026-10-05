import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { canonicalJson } from './docker-action-contract.mjs';

const DOMAIN=Buffer.from('platform-rustfs-checkpoint-v1\0');
const SHA=/^[a-f0-9]{64}$/;
const ARCHIVE=/^archives\/rustfs-[0-9]{8}T[0-9]{6}Z\.tar\.gz\.gpg$/;
const MAX_CHECKPOINT_BYTES=1024*1024;
const MAX_ARCHIVE_BYTES=32*1024**3;

function fail(message){throw Error(`Native RustFS checkpoint rejected: ${message}`);}
function exact(value,keys){if(!value||typeof value!=='object'||Array.isArray(value)||canonicalJson(Object.keys(value).sort())!==canonicalJson([...keys].sort()))fail('unexpected fields');}
function digest(value){if(!SHA.test(value))fail('invalid SHA256');}
function protectedRead(file,limit){
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{
  const before=fs.fstatSync(fd);
  if(!before.isFile()||before.nlink!==1||before.size<1||before.size>limit||before.mode&0o022)fail('unprotected input');
  const bytes=Buffer.alloc(before.size);if(fs.readSync(fd,bytes,0,bytes.length,0)!==bytes.length)fail('short input');
  const after=fs.fstatSync(fd);
  for(const field of ['dev','ino','size','mtimeMs','ctimeMs'])if(!Object.is(before[field],after[field]))fail('input changed');
  return bytes;
 }finally{fs.closeSync(fd);}
}
function sha(bytes){return crypto.createHash('sha256').update(bytes).digest('hex');}
function parseTime(value){const time=Date.parse(value);if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value)||!Number.isFinite(time))fail('invalid timestamp');return time;}

export function validateNativeRustfsCheckpoint({checkpointRoot,admission,capabilityFile,now=Date.now()}){
 for(const directory of [checkpointRoot,path.join(checkpointRoot,'archives')]){const st=fs.lstatSync(directory);if(!st.isDirectory()||st.isSymbolicLink())fail('checkpoint directory is not a real directory');}
 const store=admission?.resources?.objectStore;
 if(store?.backend!=='rustfs'||store.container!=='gf-rustfs'||store.volume!=='platform_rustfs_data'||store.rootMarker!=='.rustfs.sys'||store.restoreMode!=='isolated-only')fail('admitted store differs');
 const expectedCapability=admission.resources.capabilityFiles?.['capability.backup.job.execute']?.sha256;
 digest(expectedCapability);
 const key=protectedRead(capabilityFile,4096);if(sha(key)!==expectedCapability)fail('capability differs');
 const checkpointBytes=protectedRead(path.join(checkpointRoot,'latest.native.json'),MAX_CHECKPOINT_BYTES);
 let document;try{document=JSON.parse(checkpointBytes.toString('utf8'));}catch{fail('malformed checkpoint');}
 exact(document,['payload','hmacSha256']);exact(document.payload,['schema','admissionSha256','createdAt','backend','proof']);
 digest(document.hmacSha256);
 const expectedMac=crypto.createHmac('sha256',key).update(DOMAIN).update(canonicalJson(document.payload)).digest();
 if(!crypto.timingSafeEqual(Buffer.from(document.hmacSha256,'hex'),expectedMac))fail('HMAC differs');
 const payload=document.payload, proof=payload.proof;
 if(payload.schema!=='platform.rustfs-checkpoint/v1'||payload.backend!=='rustfs'||payload.admissionSha256!==sha(Buffer.from(canonicalJson(admission))))fail('admission binding differs');
 const created=parseTime(payload.createdAt);
 if(created>now+30000||now-created>6*3600*1000)fail('checkpoint stale or future');
 if(!proof||proof.schema!=='platform.rustfs-operator-backup/v1'||proof.backend!=='rustfs'||proof.format!==store.archiveFormat||proof.status!=='passed'||proof.sourceContainer!==store.container||proof.volume!==store.volume||proof.rootMarker!==store.rootMarker||proof.image!==store.image||proof.imageId!==store.imageId||proof.restoreBootVerified!==true||proof.s3SemanticRestoreVerified!==true||proof.decryptRoundtripVerified!==true||proof.signedBrokerCompatible!==false||!ARCHIVE.test(proof.archive))fail('proof identity differs');
 digest(proof.encryptedArchiveSha256);digest(proof.plaintextArchiveSha256);
 if(!Number.isSafeInteger(proof.encryptedBytes)||proof.encryptedBytes<1||proof.encryptedBytes>MAX_ARCHIVE_BYTES)fail('archive size invalid');
 const proofFile=path.join(checkpointRoot,'archives',path.basename(proof.archive).replace(/\.tar\.gz\.gpg$/,'.json'));
 const proofBytes=protectedRead(proofFile,MAX_CHECKPOINT_BYTES);
 let diskProof;try{diskProof=JSON.parse(proofBytes.toString('utf8'));}catch{fail('malformed proof');}
 if(canonicalJson(diskProof)!==canonicalJson(proof))fail('proof file differs');
 return {proof,archive:path.join(checkpointRoot,proof.archive),checkpointSha256:sha(checkpointBytes)};
}

export function copyBoundRustfsArchive({archive,stagingPath,proof}){
 const source=fs.openSync(archive,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 let target;
 try{
  const before=fs.fstatSync(source);
  if(!before.isFile()||before.nlink!==1||before.mode&0o022||before.size!==proof.encryptedBytes)fail('archive metadata differs');
  target=fs.openSync(stagingPath,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL,0o600);
  const digestor=crypto.createHash('sha256'),buffer=Buffer.alloc(1024*1024);
  let offset=0;
  while(offset<before.size){const count=fs.readSync(source,buffer,0,Math.min(buffer.length,before.size-offset),offset);if(count<=0)fail('short archive read');let written=0;while(written<count){const size=fs.writeSync(target,buffer,written,count-written);if(size<=0)fail('short archive write');written+=size;}digestor.update(buffer.subarray(0,count));offset+=count;}
  fs.fsyncSync(target);
  const after=fs.fstatSync(source);
  for(const field of ['dev','ino','size','mtimeMs','ctimeMs'])if(!Object.is(before[field],after[field]))fail('archive changed during copy');
  if(digestor.digest('hex')!==proof.encryptedArchiveSha256)fail('archive SHA256 differs');
  return offset;
 }finally{if(target!==undefined)fs.closeSync(target);fs.closeSync(source);}
}
