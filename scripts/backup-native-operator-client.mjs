import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import {canonicalJson,sha256,RESULT_SCHEMA} from './docker-action-contract.mjs';
import {NATIVE_ACTIONS,OPERATOR_SOCKET} from './backup-native-v2-contract.mjs';
const REQUEST_DOMAIN='platform-backup-operator-request-v2\0';
const RESPONSE_DOMAIN='platform-backup-operator-response-v2\0';
function mac(payload,key,domain){return crypto.createHmac('sha256',key).update(domain+canonicalJson(payload)).digest('hex');}
export function signNativeRequest(payload,key){return {payload,hmacSha256:mac(payload,key,REQUEST_DOMAIN)};}
export function verifyNativeResponse(doc,request,key){
 if(!doc||canonicalJson(Object.keys(doc).sort())!==canonicalJson(['hmacSha256','payload'])||!/^[a-f0-9]{64}$/.test(doc.hmacSha256)||!crypto.timingSafeEqual(Buffer.from(doc.hmacSha256,'hex'),Buffer.from(mac(doc.payload,key,RESPONSE_DOMAIN),'hex')))throw Error('Native operator response HMAC rejected');
 const p=doc.payload;
 if(p.schema!=='platform.backup-operator-result/v2'||p.requestSha256!==sha256(canonicalJson(request))||p.admissionSha256!==request.payload.admissionSha256||p.action!==request.payload.action)throw Error('Native operator response binding rejected');
 if(p.status!=='passed'){const error=Error('Native operator did not complete: '+String(p.errorCode||'FAILED'));error.preserveOperation=p.status==='running';throw error;}
 const r=p.result,selection=p.selection;
 if(!selection||canonicalJson(Object.keys(selection).sort())!==canonicalJson(['action','bundle','manifestDigest','manifestId','receiptSha256','schema'])||selection.schema!=='platform.backup-operator-selection/v2'||selection.action!==request.payload.action||selection.bundle!=='backup-'+selection.manifestId+'.tar.gpg'||canonicalJson(r?.selection)!==canonicalJson(selection)||r.manifestId!==selection.manifestId||r.manifestDigest!==selection.manifestDigest||!/^[a-f0-9]{64}$/.test(r.receiptSha256))throw Error('Native immutable selection binding rejected');
 if(request.payload.action==='restore.offsite.proof'&&(selection.receiptSha256!==r.receiptSha256||r.rustfsRestoreVerified!==true))throw Error('Native selected RustFS restore proof rejected');
 if(request.payload.action==='backup.offsite.sync'&&selection.receiptSha256!==null)throw Error('Native sync selector cannot predeclare receipt');
 if(!r||r.backend!=='ftps-multipart-v2'||r.productionModified!==false||!/^manifest-[a-z0-9][a-z0-9-]{15,127}$/.test(r.manifestId)||!/^[a-f0-9]{64}$/.test(r.manifestDigest)||!Number.isSafeInteger(r.artifactCount)||r.artifactCount<1||r.actualDownloadVerified!==true||r.decryptVerified!==true||r.everyArtifactShaAndHmacVerified!==true)throw Error('Native recovery result rejected');
 return r;
}
export function nativeEnvelope({action,requestSha256,trusted,now=Date.now()}){
 if(!NATIVE_ACTIONS.includes(action)||!/^[a-f0-9]{64}$/.test(requestSha256)||trusted.receipt.resources.offsite.backend!=='ftps-multipart-v2')throw Error('Invalid native operation');
 return {schema:'platform.backup-operator-request/v2',action,requestId:requestSha256,admissionSha256:sha256(canonicalJson(trusted.document)),generation:trusted.receipt.generation,issuedAt:new Date(now).toISOString(),expiresAt:new Date(Math.min(now+60000,Date.parse(trusted.receipt.expiresAt))).toISOString(),parameters:{}};
}
export async function runNativeOperator({action,requestSha256,trusted,stateDir,signal,transport}){
 const capability=fs.readFileSync(trusted.capabilityFiles[action]);
 const folder=path.join(stateDir,'native-operator');fs.mkdirSync(folder,{recursive:true,mode:0o700});
 const file=path.join(folder,requestSha256+'.json');let request;
 if(fs.existsSync(file)){
  const st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o077)||st.size>16384)throw Error('Unsafe native request journal');
  request=JSON.parse(fs.readFileSync(file));
  if(request.payload.requestId!==requestSha256||request.payload.action!==action||request.payload.admissionSha256!==sha256(canonicalJson(trusted.document))||canonicalJson(signNativeRequest(request.payload,capability))!==canonicalJson(request))throw Error('Native request journal binding differs');
 }else{
  request=signNativeRequest(nativeEnvelope({action,requestSha256,trusted}),capability);const fd=fs.openSync(file,'wx',0o600);try{fs.writeFileSync(fd,canonicalJson(request)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}const dirfd=fs.openSync(folder,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);try{fs.fsyncSync(dirfd);}finally{fs.closeSync(dirfd);}
 }
 const bytes=Buffer.from(canonicalJson(request)+'\n');
 const exchange=transport||((frame)=>exchangeNativeSocket(frame,{signal}));
 let result;try{result=verifyNativeResponse(await exchange(bytes),request,capability);}catch(error){if(error.preserveOperation===undefined)error.preserveOperation=true;throw error;}
 const output={...result,schema:action==='backup.offsite.sync'?'platform.offsite-backup-receipt/v2':'platform.offsite-restore-proof/v2',status:'completed'};
 return {schema:RESULT_SCHEMA,action,job:null,status:'completed',phases:[{phaseId:action==='backup.offsite.sync'?'offsite.sync':'offsite.restore',status:'completed',outputSchema:output.schema,outputSha256:sha256(canonicalJson(output)),output}]};
}

export function exchangeNativeSocket(frame,{signal,deadlineMs=4*3600000+60000,connect=()=>net.createConnection(OPERATOR_SOCKET)}={}){
 return new Promise((resolve,reject)=>{
  if(signal?.aborted){const e=Error('Native operation already aborted');e.preserveOperation=true;reject(e);return;}
  const socket=connect();let data=Buffer.alloc(0),settled=false;
  const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);signal?.removeEventListener('abort',aborted);socket.removeAllListeners();socket.destroy();if(error){error.preserveOperation=true;reject(error);}else resolve(value);};
  const aborted=()=>finish(Error('Native operation interrupted; reconciliation required'));
  const timer=setTimeout(()=>finish(Error('Native operator response deadline exceeded')),deadlineMs);
  signal?.addEventListener('abort',aborted,{once:true});
  socket.on('connect',()=>socket.write(frame));
  socket.on('data',chunk=>{data=Buffer.concat([data,chunk]);if(data.length>65536)finish(Error('Native response exceeds bound'));});
  socket.on('error',error=>finish(error));
  socket.on('close',()=>{if(!settled)finish(Error('Native operator closed before response'));});
  socket.on('end',()=>{try{const text=data.toString('utf8');if(!text.endsWith('\n'))throw Error('Native response frame incomplete');const doc=JSON.parse(text);if(text!==canonicalJson(doc)+'\n')throw Error('Native response frame is not canonical');finish(null,doc);}catch(error){finish(error);}});
 });
}
