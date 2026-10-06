import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {readVpsBackupCatalog} from '../../../control-center/backup/vps-catalog.mjs';
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
  fs.writeFileSync(file,JSON.stringify({...catalog,resources:resources.slice(1)}));
  assert.throws(()=>readVpsBackupCatalog(root),/resource catalog/);
  t.mock.restoreAll();
  t.mock.method(fs,'lstatSync',(p)=>({...original(p),uid:1000,mode:0o100640,isFile:()=>true,isSymbolicLink:()=>false}));
  assert.throws(()=>readVpsBackupCatalog(root),/unavailable/);
 } finally {t.mock.restoreAll();fs.rmSync(root,{recursive:true,force:true});}
});
