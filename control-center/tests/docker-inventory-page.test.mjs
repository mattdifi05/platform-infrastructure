import test from 'node:test';
import assert from 'node:assert/strict';
import {dockerInventoryPage} from '../ai/tools.mjs';
const row=(i,state='running',status='Up 2 hours (healthy)')=>({id:i.toString(16).padStart(64,'0'),name:'service-'+String(i).padStart(3,'0'),image:'registry.example/image@sha256:'+'a'.repeat(64),state,status});
test('45-row inventory retains exact global health counts with a bounded first page and lossless pagination',()=>{
 const input={containers:[...Array.from({length:43},(_,i)=>row(i+1)),row(44,'exited','Exited (0)'),row(45,'created','Created')]};
 const p=dockerInventoryPage(input);assert.deepEqual(p.counts,{observed:45,running:43,notRunning:2,healthy:43,unhealthy:0,healthStarting:0,healthNotReported:0});assert.equal(p.inventoryComplete,true);assert.equal(p.containers.length,20);assert.equal(p.nextOffset,20);assert.ok(Buffer.byteLength(JSON.stringify(p))<10000);
 const all=[...p.containers,...dockerInventoryPage(input,{offset:20}).containers,...dockerInventoryPage(input,{offset:40}).containers];assert.equal(all.length,43);assert.equal(new Set(all.map(r=>r.id)).size,43);assert.equal(dockerInventoryPage(input,{offset:40}).nextOffset,null);
 assert.equal(dockerInventoryPage(input,{includeStopped:true,offset:40}).containers.length,5);
});
test('unknown, starting and unhealthy states are not counted as healthy; observer limit is explicit',()=>{
 const p=dockerInventoryPage({containers:[row(1,'running','Up 2h'),row(2,'running','Up (unhealthy)'),row(3,'running','Up (health: starting)')]});assert.equal(p.counts.healthy,0);assert.equal(p.counts.unhealthy,1);assert.equal(p.counts.healthStarting,1);assert.equal(p.counts.healthNotReported,1);
 assert.equal(dockerInventoryPage({containers:Array.from({length:100},(_,i)=>row(i+1))}).inventoryComplete,false);
});
test('malformed data and abusive pagination are rejected while unavailable remains unavailable',()=>{
 for(const args of [{offset:-1},{offset:100},{limit:0},{limit:21},{includeStopped:'true'}])assert.throws(()=>dockerInventoryPage({containers:[row(1)]},args));
 assert.throws(()=>dockerInventoryPage({containers:[row(1),row(1)]}));assert.throws(()=>dockerInventoryPage({containers:[{...row(1),id:'bad'}]}));
 assert.deepEqual(dockerInventoryPage({available:false,message:'offline'}),{available:false,message:'offline'});
});
