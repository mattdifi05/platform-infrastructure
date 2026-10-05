import { readFileSync, statSync } from 'node:fs';
import { redactText } from './web.mjs';

export function readGpuSnapshot(file, now=Date.now()) {
  const unavailable={available:false,stale:false,source:'host-nvidia-smi',message:'GPU non disponibile: la chat può usare la CPU.'};
  if(!file)return {...unavailable,message:'Telemetria GPU non configurata.'};
  try{
    const stat=statSync(file);
    if(!stat.isFile()||stat.size>8192) return unavailable;
    const value=JSON.parse(readFileSync(file,'utf8'));
    const observed=Date.parse(value.observedAt);
    const stale=!Number.isFinite(observed)||now-observed>45000||observed-now>5000;
    if(stale)return {...unavailable,stale:true,message:'Telemetria GPU non aggiornata.'};
    if(value.available!==true)return {...unavailable,observedAt:value.observedAt};
    const number=(key,max)=>Number.isFinite(value[key])&&value[key]>=0&&value[key]<=max?value[key]:null;
    return {available:true,stale:false,source:'host-nvidia-smi',observedAt:value.observedAt,name:redactText(value.name,120),driverVersion:redactText(value.driverVersion,40),memoryTotalMiB:number('memoryTotalMiB',1048576),memoryUsedMiB:number('memoryUsedMiB',1048576),memoryFreeMiB:number('memoryFreeMiB',1048576),utilizationPercent:number('utilizationPercent',100),temperatureC:number('temperatureC',150)};
  }catch{return unavailable;}
}
