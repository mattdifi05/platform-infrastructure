import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {readVpsBackupCatalog} from '../../../control-center/backup/vps-catalog.mjs';
import {createBackupJobDocument,createBackupManifestDocument,backupDocumentDigest} from '../../../control-center/backup/contracts.mjs';
test('home path remains unchanged without explicit VPS catalog',()=>assert.equal(readVpsBackupCatalog(''),null));
test('VPS catalog requires protected owner and exact full resource set',(t)=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vps-catalog-unit-'));
 const resources=Array.from({length:15},(_,i)=>({id:`platform-state:unit-${i}`,externalId:`unit-${i}`,kind:'platform-state',projectId:'platform',name:`unit-${i}`}));
 const catalog={schema:'platform.vps-backup-catalog/v1',host:'platform-server-public',enabled:false,resources,points:[]};
 const file=path.join(root,'catalog.json');fs.writeFileSync(file,JSON.stringify(catalog),{mode:0o600});
 const original=fs.lstatSync;
 try {
  t.mock.method(fs,'lstatSync',(p)=>({...original(p),uid:0,mode:0o100640,isFile:()=>true,isSymbolicLink:()=>false}));
  assert.equal(readVpsBackupCatalog(root).resources.length,15);
  assert.equal(readVpsBackupCatalog(root).enabled,false);
  fs.writeFileSync(file,JSON.stringify({...catalog,resources:[...resources.slice(1),{...resources[0],kind:'application'}]}));
  assert.throws(()=>readVpsBackupCatalog(root),/resource/);
  t.mock.restoreAll();
  t.mock.method(fs,'lstatSync',(p)=>({...original(p),uid:1000,mode:0o100640,isFile:()=>true,isSymbolicLink:()=>false}));
  assert.throws(()=>readVpsBackupCatalog(root),/unavailable/);
 } finally {t.mock.restoreAll();fs.rmSync(root,{recursive:true,force:true});}
});
test('only exact current resources can enter the generic recovery catalog',(t)=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'vps-generic-catalog-'));
 const base=Array.from({length:15},(_,i)=>({id:`platform-state:unit-${i}`,externalId:`unit-${i}`,kind:'platform-state',projectId:'platform',name:`unit-${i}`}));
 const extra={id:'platform-state:unit-extra',externalId:'unit-extra',kind:'platform-state',projectId:'platform',name:'unit-extra'};
 function point(resources, suffix){
  const job=createBackupJobDocument({id:'vps-unit-job-'+suffix,operation:'backup',scope:{kind:'platform',id:'platform'},resources,requestedBy:'unit-owner',environment:'evidence'});
  const manifest=createBackupManifestDocument({id:'manifest-vps-unit-'+suffix,job,artifacts:resources.map((r,i)=>({id:'artifact-'+i,resourceId:r.id,path:'artifacts/unit-'+i+'.tar',sha256:'a'.repeat(64),sizeBytes:1,signatureKeyId:'unit-key'}))});
  manifest.signature={algorithm:'HMAC-SHA256',keyId:'unit-key',digest:backupDocumentDigest(manifest),value:'unitSignature'};
  return {manifest,offsiteVerified:true};
 }
 const current=[...base,extra],file=path.join(root,'catalog.json'),original=fs.lstatSync;
 function write(resources,points){fs.writeFileSync(file,JSON.stringify({schema:'platform.vps-backup-catalog/v1',host:'platform-server-public',resources,points}),{mode:0o600});}
 try{
  t.mock.method(fs,'lstatSync',p=>({...original(p),uid:0,mode:0o100640,isFile:()=>true,isSymbolicLink:()=>false}));
  write(current,[point(base,'old')]);
  assert.throws(()=>readVpsBackupCatalog(root),/resource set/);
  write(current,[point(current,'current')]);
  const read=readVpsBackupCatalog(root);assert.equal(read.resources.length,16);
  assert.equal(read.manifests[0].restoreCompatible,true);
  write(current,[point(base.slice(1),'incomplete')]);assert.throws(()=>readVpsBackupCatalog(root),/resource set/);
 }finally{t.mock.restoreAll();fs.rmSync(root,{recursive:true,force:true});}
});
