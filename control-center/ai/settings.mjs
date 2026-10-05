import path from 'node:path';
import { createFileStateStore } from '../state/file-store.mjs';

const ID=/^[a-f0-9]{64}$/;
export function createMachineAiSettings({stateFile='/var/www/project-state/projects.json'}={}) {
  const store=createFileStateStore({datasets:{machineAi:{path:path.join(path.dirname(stateFile),'server-ai-settings.json'),defaultValue:{version:1,machines:{}},validate(value){
    if(value?.version!==1||!value.machines||Array.isArray(value.machines)||typeof value.machines!=='object')throw new Error('Invalid machine AI settings.');
    for(const[id,record]of Object.entries(value.machines))if(!ID.test(id)||typeof record?.enabled!=='boolean')throw new Error('Invalid machine AI settings.');
  }}}});
  return {
    read(machineId){if(!ID.test(machineId))throw new Error('Invalid machine identity.');return store.read('machineAi',{strict:true}).value.machines[machineId]||{enabled:false};},
    setEnabled(machineId,enabled){
      if(!ID.test(machineId)||typeof enabled!=='boolean')throw new Error('Invalid machine AI setting.');
      store.update('machineAi',value=>({...value,machines:{...value.machines,[machineId]:{enabled,updatedAt:new Date().toISOString()}}}));
      return this.read(machineId);
    },
  };
}
