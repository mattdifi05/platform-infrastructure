import { createHash } from 'node:crypto';
import fs from 'node:fs';

const approved = new WeakSet();
const HASH=/^[a-f0-9]{64}$/;
const IMAGE=/^sha256:[a-f0-9]{64}$/;
export const SCRIPTA_DATABASE_ID='scriptastudents-postgres-students-beta-app';
const EXACT={projectId:'scriptastudents',engine:'postgres',name:'students_beta_app',ownerRole:'scripta_app'};
const CREDENTIAL_FILES=new Set(['/run/secrets/scripta_control_center_db','/run/secrets/scripta_app_password']);
const CA_FILES=new Set(['/run/scripta-admin-tls/ca.crt','/run/tls/scripta-ca.crt']);
const MUTATIONS=new Set(['create','credential','rotate','delete','delete-now','delete-approve','delete-execute','grant','cleanup-principal','alter-owner']);

export class ExternalDatabasePolicyError extends Error {
  constructor(code='EXTERNAL_DATABASE_UNAVAILABLE') {super('Database esterno non disponibile o non autorizzato.');this.code=code;}
}
function requireValue(ok,code='EXTERNAL_DATABASE_INVALID'){if(!ok)throw new ExternalDatabasePolicyError(code);}
function exact(value,keys){requireValue(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join() === [...keys].sort().join());}
function canonical(value){
  if(Array.isArray(value))return value.map(canonical);
  if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])]));
  return value;
}
function freeze(value){if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;}
export function trustedExternalDatabaseDigest(value){return createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');}
export const EXTERNAL_DATABASE_FILE_ENV='CONTROL_CENTER_TRUSTED_EXTERNAL_DATABASE_FILE';
export const EXTERNAL_DATABASE_DIGEST_ENV='CONTROL_CENTER_TRUSTED_EXTERNAL_DATABASE_SHA256';

/** approvedDigest must come from an already verified root/operator admission,
 * never from a browser payload, live Docker labels, or a discovered DB name. */
export function validateTrustedExternalDatabase(raw,{approvedDigest,now=Date.now()}={}){
  requireValue(typeof approvedDigest==='string'&&HASH.test(approvedDigest)&&trustedExternalDatabaseDigest(raw)===approvedDigest,'EXTERNAL_DATABASE_ADMISSION_MISMATCH');
  exact(raw,['schema','management','id','projectId','engine','name','displayName','ownerRole','principalManaged','principalBindingStatus','attestation','connection','capabilities']);
  requireValue(raw.schema==='platform.control-center.trusted-database/v1'&&raw.management==='existing-external'&&raw.id===SCRIPTA_DATABASE_ID);
  for(const [key,value]of Object.entries(EXACT))requireValue(raw[key]===value);
  requireValue(raw.displayName==='Scripta Students'&&raw.principalManaged===false&&raw.principalBindingStatus==='legacy-unbound');
  exact(raw.attestation,['receiptSha256','host','containerName','containerId','image','reviewedAt']);
  const a=raw.attestation;
  requireValue(HASH.test(a.receiptSha256)&&a.host==='platform-server-public'&&a.containerName==='scripta-postgres'&&HASH.test(a.containerId)&&IMAGE.test(a.image));
  const time=Date.parse(a.reviewedAt);requireValue(typeof a.reviewedAt==='string'&&Number.isFinite(time)&&time<=now+30_000);
  exact(raw.connection,['host','port','tlsMode','caFile','username','credentialFile','defaultDatabase','tool','internalUrl']);
  const c=raw.connection;
  requireValue(c.host==='scripta-postgres'&&c.port===5432&&c.tlsMode==='verify-full'&&CA_FILES.has(c.caFile));
  requireValue(c.username==='scripta_app'&&CREDENTIAL_FILES.has(c.credentialFile)&&c.defaultDatabase==='students_beta_app');
  requireValue(c.tool==='phppgadmin'&&c.internalUrl==='http://phppgadmin:80');
  exact(raw.capabilities,['browse','backup','restore','rotateCredentials','dropDatabase','managePrincipals']);
  for(const value of Object.values(raw.capabilities))requireValue(typeof value==='boolean');
  requireValue(raw.capabilities.browse===true&&raw.capabilities.rotateCredentials===false&&raw.capabilities.dropDatabase===false&&raw.capabilities.managePrincipals===false);
  const result=freeze(structuredClone(raw));approved.add(result);return result;
}

/** Reads only non-secret metadata. The credential FILE is never opened here. */
export function readTrustedExternalDatabase(file,options={}){
  const before=fs.lstatSync(file);
  requireValue(before.isFile()&&!before.isSymbolicLink()&&before.uid===0&&!(before.mode&0o022)&&before.nlink===1&&before.size<=32_768,'EXTERNAL_DATABASE_CATALOG_UNSAFE');
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try {
    const actual=fs.fstatSync(fd);
    requireValue(actual.dev===before.dev&&actual.ino===before.ino&&actual.uid===0&&!(actual.mode&0o022)&&actual.size===before.size,'EXTERNAL_DATABASE_CATALOG_CHANGED');
    return validateTrustedExternalDatabase(JSON.parse(fs.readFileSync(fd,'utf8')),options);
  }finally{fs.closeSync(fd);}
}
export function isTrustedExternalDatabase(value){return approved.has(value);}
function trusted(value){requireValue(isTrustedExternalDatabase(value),'EXTERNAL_DATABASE_NOT_ADMITTED');return value;}

/** Use the existing database row renderer, but retain the admitted profile in a
 * server-side map keyed by ID. Serializing a record does not grant authority. */
export function externalDatabaseRecord(profile){
  const p=trusted(profile);
  return {id:p.id,projectId:p.projectId,engine:p.engine,name:p.name,displayName:p.displayName,ownerRole:p.ownerRole,
    principalManaged:false,principalBindingId:'',principalBindingStatus:'legacy-unbound',status:'active',connectionStatus:'configured',
    credentialRef:'scripta.control-center.db',credentialFile:p.connection.credentialFile,credentialStatus:'secret-file-set',
    linkedApps:['scriptastudents'],source:'operator-attested-existing',externalProfileId:p.id,capabilities:{...p.capabilities}};
}
export function externalDatabaseCapabilities(profile){return {...trusted(profile).capabilities};}
export function assertExternalDatabaseAction(profile,action){
  const p=trusted(profile);requireValue(!MUTATIONS.has(action),'EXTERNAL_PRINCIPAL_MUTATION_DENIED');
  requireValue(['browse','backup','restore'].includes(action)&&p.capabilities[action]===true,'EXTERNAL_DATABASE_ACTION_DENIED');return p;
}
export function externalDatabaseAdminTarget(profile){
  const p=assertExternalDatabaseAction(profile,'browse'),c=p.connection;
  return Object.freeze({host:c.host,port:c.port,tlsMode:c.tlsMode,caFile:c.caFile,defaultDatabase:c.defaultDatabase,
    serverId:`${c.host}:${c.port}:${c.tlsMode}`,internalUrl:c.internalUrl,username:c.username,credentialFile:c.credentialFile,
    allowPlatformCredentialFallback:false});
}
/** This result stays inside the authenticated login adapter. Never include it
 * in renderContext/JSON/logs. No fallback to a core/platform principal exists. */
export function externalDatabaseAdminCredentials(profile,readPasswordFile){
  const target=externalDatabaseAdminTarget(profile);requireValue(typeof readPasswordFile==='function');
  const password=readPasswordFile(target.credentialFile);
  requireValue(typeof password==='string'&&password.length>=16&&password.length<=512&&!/[\u0000\r\n]/.test(password),'EXTERNAL_DATABASE_CREDENTIAL_UNAVAILABLE');
  return [{user:target.username,password,source:'trusted-external-database-file'}];
}
