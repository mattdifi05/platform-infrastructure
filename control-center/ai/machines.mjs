import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import http from 'node:http';
import { createMachineAiSettings } from './settings.mjs';
import { SERVER_AI_MODEL, SERVER_AI_MODEL_LABEL, normalizeServerAiContext } from './model.mjs';

const ID=/^[a-f0-9]{64}$/;
export function readMachineRegistry({identityFile='/run/platform/host-machine-id',registryFile,label='Server locale'}={}) {
  let localId=null;
  try{const bytes=readFileSync(identityFile);if(!/^[a-f0-9]{32}\n?$/.test(bytes.toString('utf8')))throw new Error();localId=createHash('sha256').update(bytes).digest('hex');}catch{}
  if(!registryFile)return localId?[{id:localId,label,configured:false}]:[];
  if(statSync(registryFile).size>32768)throw new Error('Machine registry too large.');
  const document=JSON.parse(readFileSync(registryFile,'utf8'));
  if(document.version!==1||!Array.isArray(document.machines)||document.machines.length>32)throw new Error('Invalid machine registry.');
  const ids=new Set();
  const machines=document.machines.map(machine=>{
    if(!ID.test(machine.id)||ids.has(machine.id)||typeof machine.label!=='string'||machine.label.length>120)throw new Error('Invalid machine identity.');
    ids.add(machine.id);
    normalizeServerAiContext(machine.contextLength);
    if(machine.local===true&&machine.id!==localId)throw new Error('Machine registry does not match host identity.');
    if(machine.configured===true&&(!/^\/[a-zA-Z0-9_./-]+\.sock$/.test(machine.controllerSocket||'')||machine.controllerSocket.includes('..')||machine.controllerSocket.length>256))throw new Error('Invalid machine controller.');
    const auxiliaryKeys=['auxEmbeddingUrl','auxRerankerUrl','auxTokenFile'];
    const auxiliaryDeclared=auxiliaryKeys.some(key=>machine[key]!==undefined);
    if(auxiliaryDeclared&&(!machine.local||machine.configured!==true||machine.auxEmbeddingUrl!=='http://server-ai-embedding:8000'||machine.auxRerankerUrl!=='http://server-ai-reranker:8000'||machine.auxTokenFile!=='/run/secrets/server_ai_aux_token'))throw new Error('Invalid auxiliary AI registry binding.');
    const projectReaderKeys=['projectSourceReaderUrl','projectQueryReaderUrl','projectReadersTokenFile'];
    const projectReadersDeclared=projectReaderKeys.some(key=>machine[key]!==undefined);
    if(projectReadersDeclared&&(!machine.local||machine.configured!==true||machine.projectSourceReaderUrl!=='http://project-source-reader:8110'||machine.projectQueryReaderUrl!=='http://project-query-reader:8111'||machine.projectReadersTokenFile!=='/run/secrets/server_ai_project_readers_token'))throw new Error('Invalid project reader registry binding.');
    return {...machine,configured:machine.configured===true,auxiliaryConfigured:false,projectReadersConfigured:projectReadersDeclared};
  });
  if(localId&&!ids.has(localId))machines.push({id:localId,label,configured:false});
  return machines;
}

export function controllerRequest(socketPath,method,action,machineId,{timeoutMs=70000}={}) {
  if(!['GET /status','POST /enable','POST /disable'].includes(`${method} ${action}`))throw new Error('Unsupported lifecycle operation.');
  return new Promise((resolve,reject)=>{
    const body=method==='POST'?JSON.stringify({machineId}):null;
    const req=http.request({socketPath,path:action,method,timeout:timeoutMs,maxHeaderSize:8192,headers:{accept:'application/json',...(body?{'content-type':'application/json','content-length':Buffer.byteLength(body)}:{})}},res=>{
      let bytes=0;const chunks=[];
      res.on('data',chunk=>{bytes+=chunk.length;if(bytes>16384){res.destroy();reject(new Error('Controller response exceeded limit.'));}else chunks.push(chunk);});
      res.on('end',()=>{try{const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(res.statusCode!==200||value.machineId!==machineId)throw new Error();resolve(value);}catch{reject(new Error('Machine controller rejected the operation.'));}});
      res.on('error',()=>reject(new Error('Machine controller unavailable.')));
    });
    req.once('timeout',()=>req.destroy(new Error('Machine controller timeout.')));req.once('error',()=>reject(new Error('Machine controller unavailable.')));req.end(body);
  });
}

export class MachineAiError extends Error {
  constructor(message,status=409){super(message);this.status=status;}
}

export function createMachineAiManager({machines,stateFile,audit=()=>{},pollMs=1000,activationTimeoutMs=5*60*1000}) {
  const registry=new Map(machines.map(machine=>[machine.id,{...machine,operation:null,cache:null,lastFailure:null}]));
  if(registry.size!==machines.length)throw new Error('Duplicate machine identity.');
  const settings=createMachineAiSettings({stateFile});
  const get=id=>{const machine=registry.get(id);if(!machine)throw new MachineAiError('Macchina non presente nel Control Center.',404);return machine;};
  const desired=machine=>{try{return settings.read(machine.id).enabled;}catch{throw new MachineAiError('Configurazione macchina non leggibile.',503);}};
  const controller=(machine,method,action)=>machine.controller?machine.controller(method,action,machine.id):controllerRequest(machine.controllerSocket,method,action,machine.id,{timeoutMs:method==='GET'?4000:70000});
  const gpuFor=machine=>machine.gpu?machine.gpu():{available:false,stale:false};
  const coreHealthy=runtime=>['server-ai-observer'].every(name=>runtime?.services?.some(service=>service.service===name&&service.running&&service.healthy));
  const runtimeCompatible=runtime=>runtime?.coreCompatible===true||runtime?.compatible===true;
  const runtimeLifecycleSafe=runtime=>runtime?.lifecycleSafe!==false;
  const runtimeCoreHealthy=runtime=>runtime?.coreHealthy===true||runtime?.allHealthy===true||coreHealthy(runtime);
  const auxiliarySummary=(machine,runtime)=>{
    if(!machine.auxiliaryConfigured)return { configured:false, available:false, services:[] };
    const services=(runtime?.services||[]).filter(service=>['server-ai-embedding','server-ai-reranker'].includes(service?.service)).map((service)=>{
      const device=['NPU','GPU','CPU'].includes(service.device)?service.device:null;
      const deviceVerified=device!==null&&service.deviceVerified===true;
      return { service:service.service, available:service.running===true&&service.healthy===true&&deviceVerified, device, deviceVerified };
    });
    return { configured:true, available:runtime?.auxiliaryHealthy===true&&services.length===2&&services.every(service=>service.available), services };
  };
  const projectReadersSummary=(machine,runtime)=>({ configured:machine.projectReadersConfigured===true, available:machine.projectReadersConfigured===true&&runtime?.projectReadersHealthy===true });
  async function enableRuntime(machine){
    try{return await controller(machine,'POST','/enable');}
    catch(error){const runtime=await controller(machine,'GET','/status');if(runtimeCompatible(runtime)&&runtimeLifecycleSafe(runtime)&&runtimeCoreHealthy(runtime))return runtime;throw error;}
  }
  const base=machine=>({machineId:machine.id,machineLabel:machine.label,configured:machine.configured===true,enabled:desired(machine),state:'unavailable',ready:false,generationAvailable:false,historyAvailable:false,online:false,models:[],loaded:[],gpu:gpuFor(machine),search:{online:false},missing:[],warnings:[],busy:false});
  async function prerequisites(machine){
    const gpu=gpuFor(machine);const missing=[];
    if(!machine.configured)missing.push('Runtime Server AI non configurato su questa macchina.');
    let runtime=null;
    if(machine.configured){try{
      runtime=await controller(machine,'GET','/status');
      if(!runtimeCompatible(runtime))missing.push(...(runtime.missing||['Configurazione dei container AI non valida.']));
      if(!runtimeLifecycleSafe(runtime))missing.push('Controllo del ciclo di vita AI non sicuro.');
    }catch{missing.push('Controllore Docker della macchina non disponibile.');}}
    return {gpu,runtime,missing};
  }
  async function status(id,{fresh=false}={}){
    const machine=get(id);const result=base(machine);
    if(machine.operation)return {...result,state:machine.operation.kind,busy:true,label:machine.operation.kind==='starting'?'Avvio di Server AI…':'Arresto di Server AI…'};
    if(!fresh&&machine.cache&&Date.now()-machine.cache.at<2000)return machine.cache.value;
    const {gpu,runtime,missing}=await prerequisites(machine);result.gpu=gpu;result.missing=missing;
    if(!result.enabled){
      if(runtime&&!runtime.allStopped&&!machine.lastFailure){beginDisable(machine);return {...result,state:'stopping',busy:true,label:'Arresto di Server AI…'};}
      if(runtime&&!runtime.allStopped)result.missing.push('Arresto dei servizi dedicati non confermato.');
      if(!runtime&&machine.configured)result.missing.push('Impossibile confermare il rilascio delle risorse.');
      result.state=missing.length?'unavailable':'disabled';result.resourcesReleased=runtime?.allStopped===true;result.label=missing.length?'Server AI non disponibile':'Server AI disattivato';
    }else if(!missing.length&&runtimeCoreHealthy(runtime)){
      const [ai,search]=await Promise.all([machine.service.status(),machine.web.health()]);
      Object.assign(result,ai,{search,gpu,enabled:true});
      result.historyAvailable=true;
      if (typeof machine.retrieval?.diagnostics === 'function') result.retrieval=machine.retrieval.diagnostics();
      const auxiliary=auxiliarySummary(machine,runtime);
      if(machine.auxiliaryConfigured)result.auxiliary=auxiliary;
      const projectReaders=projectReadersSummary(machine,runtime);
      if(machine.projectReadersConfigured)result.projectReaders=projectReaders;
      if(!ai.online)result.warnings.push('OpenAI API non raggiungibile durante l’ultimo controllo. La cronologia resta disponibile e puoi riprovare.');
      if(!ai.models?.some(model=>model.model===SERVER_AI_MODEL&&model.available))result.missing.push(`${SERVER_AI_MODEL_LABEL} non disponibile per questa chiave.`);
      result.generationAvailable=ai.ready===true&&ai.models?.some(model=>model.model===SERVER_AI_MODEL&&model.available)===true;
      result.ready=result.generationAvailable;
      if(!search.online)result.warnings.push('SearXNG non disponibile: la chat resta utilizzabile.');
      if(machine.projectReadersConfigured&&!projectReaders.available)result.warnings.push('Lettori progetto privati non disponibili: la chat resta utilizzabile.');
      if(ai.state==='starting'){result.state='starting';result.label=`Connessione a ${SERVER_AI_MODEL_LABEL}…`;}
      else {
        result.state=result.generationAvailable&&ai.online&&search.online&&(!machine.projectReadersConfigured||projectReaders.available)?'active':'degraded';
        result.label=result.state==='active'?'Server AI · GPT-6 Luna attivo':!ai.online?'Cronologia disponibile · connessione OpenAI da verificare':!result.generationAvailable?'Cronologia disponibile · generazione GPT-6 Luna non disponibile':'GPT-6 Luna attivo · alcune fonti private o la ricerca non sono disponibili';
      }
      result.webMessage=!search.online?'Ricerca web non disponibile':search.internet?.online===false?'Accesso Internet non raggiungibile dal controllo HTTPS':'Ricerca web disponibile';
    }else{
      if(runtime&&!runtime.allHealthy)result.missing.push('I servizi AI della macchina non sono tutti avviati e sani.');
      result.label='Server AI non disponibile';
    }
    if(machine.lastFailure){
      result.lastError=machine.lastFailure;
      if(result.state==='disabled')result.label=`Server AI disattivato. ${machine.lastFailure}`;
      else {result.missing.push(machine.lastFailure);if(result.enabled){result.state='error';result.label='Errore Server AI';result.ready=false;}}
    }
    machine.cache={at:Date.now(),value:result};return result;
  }
  function beginDisable(machine,previousOperation){
    if(machine.operation)return;
    machine.cache=null;machine.lastFailure=null;
    const operation={kind:'stopping',promise:null};machine.operation=operation;
    operation.promise=(async()=>{
      try{
        try { if(machine.service)await machine.service.deactivate(); } catch {}
        await previousOperation;
        const stopped=await controller(machine,'POST','/disable');
        if(!stopped.allStopped)throw new Error();
        audit({action:'disable',machineId:machine.id,result:'success'});
      }catch{machine.lastFailure='Arresto non confermato: il rilascio delle risorse deve essere verificato.';audit({action:'disable',machineId:machine.id,result:'failed'});}
      finally{machine.cache=null;if(machine.operation===operation)machine.operation=null;}
    })();
  }
  return {
    list(){return machines.map(({id,label})=>({id,label}));},
    retrieval(id){return get(id).retrieval||null;},
    projectReaders(id){return get(id).projectReaders||null;},
    projectCatalog(id){return get(id).projectCatalog||null;},
    status,
    async enable(id){
      const machine=get(id);if(machine.operation)throw new MachineAiError('Operazione macchina già in corso.');
      const operation={kind:'starting',promise:null};machine.operation=operation;
      try { const check=await prerequisites(machine);if(machine.operation!==operation||operation.cancelled)throw new MachineAiError('Attivazione annullata.');if(check.missing.length)throw new MachineAiError(check.missing.join(' '));settings.setEnabled(id,true); }
      catch(error){if(machine.operation===operation)machine.operation=null;throw error;}
      machine.cache=null;machine.lastFailure=null;
      operation.promise=(async()=>{
        try{
          await enableRuntime(machine);const deadline=Date.now()+activationTimeoutMs;
          let prewarmed=false;
          while(Date.now()<deadline){
            if(!desired(machine))return;
            const runtime=await controller(machine,'GET','/status');
            if(runtimeCoreHealthy(runtime)){
              if(!desired(machine)||operation.cancelled)return;
              if(!prewarmed){await machine.service.prewarm({signal:AbortSignal.timeout(Math.max(1,deadline-Date.now()))});prewarmed=true;}
              const ai=await machine.service.status();
              if(!desired(machine))return;
              if(ai.online&&ai.ready===true&&ai.models?.some(model=>model.model===SERVER_AI_MODEL&&model.available)){await (machine.service.recoverAttachmentScans?.(id) ?? machine.service.resumeAttachmentScans?.(id));audit({action:'enable',machineId:id,result:'success'});return;}
            }
            await new Promise(resolve=>setTimeout(resolve,pollMs));
          }
          throw new Error();
        }catch{if(desired(machine)){machine.lastFailure=`Avvio non completato: verifica l’accesso a ${SERVER_AI_MODEL_LABEL} e la salute dei servizi.`;audit({action:'enable',machineId:id,result:'failed'});}}
        finally{machine.cache=null;if(machine.operation===operation)machine.operation=null;}
      })();
      return {machineId:id,enabled:true,state:'starting'};
    },
    disable(id){const machine=get(id);settings.setEnabled(id,false);if(machine.operation?.kind!=='stopping'){const previous=machine.operation?.promise;if(machine.operation)machine.operation.cancelled=true;machine.operation=null;beginDisable(machine,previous);}return {machineId:id,enabled:false,state:'stopping'};},
    async reconcileDisabled(){
      // Rebuild enabled capability (including permanent model residency) and finish interrupted shutdowns.
      await Promise.allSettled([...registry.values()].filter(machine=>machine.configured).map(async machine=>{
        if(machine.operation)return;
        if(desired(machine)){
          const check=await prerequisites(machine);
          if(!check.missing.length&&runtimeCoreHealthy(check.runtime)){
            const ai=await machine.service.status();
            if(ai.online&&ai.ready===true&&ai.models?.some(model=>model.model===SERVER_AI_MODEL&&model.available)){await (machine.service.recoverAttachmentScans?.(machine.id) ?? machine.service.resumeAttachmentScans?.(machine.id));return;}
          }
          if(machine.operation||!desired(machine))return;
          const operation={kind:'starting',promise:null};machine.operation=operation;machine.cache=null;machine.lastFailure=null;
          operation.promise=(async()=>{
            try{
              const retry=await prerequisites(machine);if(retry.missing.length)throw new Error(retry.missing.join(' '));
              if(!runtimeCoreHealthy(retry.runtime))await enableRuntime(machine);
              if(!desired(machine)||operation.cancelled)return;
              await machine.service.prewarm({signal:AbortSignal.timeout(activationTimeoutMs)});
              const ai=await machine.service.status();
              if(!ai.online||!ai.ready||!ai.models?.some(model=>model.model===SERVER_AI_MODEL&&model.available))throw new Error('OpenAI provider unavailable.');
              await (machine.service.recoverAttachmentScans?.(machine.id) ?? machine.service.resumeAttachmentScans?.(machine.id));
              audit({action:'reconcile',machineId:machine.id,result:'success'});
            }catch{machine.lastFailure=`Ripristino automatico non completato: ${SERVER_AI_MODEL_LABEL} non è pronto.`;audit({action:'reconcile',machineId:machine.id,result:'failed'});}
            finally{machine.cache=null;if(machine.operation===operation)machine.operation=null;}
          })();
          await operation.promise;
          return;
        }
        const runtime=await controller(machine,'GET','/status');
        if(!desired(machine)&&!machine.operation&&!runtime.allStopped)beginDisable(machine);
      }));
    },
    async attachmentScan(id,action,options={}) {
      const machine=get(id);
      if(options.machineId!==id||!machine.service)throw new MachineAiError('Analisi allegati non disponibile su questa macchina.',503);
      if(['start','resume'].includes(action)) {
        if(!desired(machine)||machine.operation)throw new MachineAiError('Server AI non è attivo su questa macchina.',503);
        const current=await status(id);
        if(!['active','degraded'].includes(current.state)||!desired(machine)||machine.operation)throw new MachineAiError('Prerequisiti Server AI non disponibili su questa macchina.',503);
      }
      const scope={ownerId:options.ownerId,machineId:id,conversationId:options.conversationId};
      if(action==='list')return machine.service.getAttachmentScans?.(scope)||[];
      if(action==='stop')return machine.service.abortAttachmentScan?.({...scope,scanId:options.scanId})||null;
      if(action==='resume')return machine.service.resumeAttachmentScan?.({...scope,scanId:options.scanId})||null;
      if(action==='deleteConversation')return machine.service.abortConversationAttachmentScans?.(scope)||null;
      if(action==='start')return machine.service.handleAttachmentScanTool?.({attachments:options.attachments||[],args:{attachmentId:options.attachmentId,action:'start'},subject:scope.ownerId,machineId:id,conversationId:scope.conversationId})||null;
      throw new MachineAiError('Operazione analisi allegati non valida.',400);
    },
    async chat(id,req,res,identity){const machine=get(id);if(!desired(machine)||machine.operation||!machine.service)throw new MachineAiError('Server AI non è attivo su questa macchina.',503);const current=await status(id);if(!['active','degraded'].includes(current.state)||!desired(machine)||machine.operation)throw new MachineAiError('Prerequisiti Server AI non disponibili su questa macchina.',503);return machine.service.handleChat(req,res,identity);},
    async registerChat(id,generationKey,controller){const machine=get(id);if(!desired(machine)||machine.operation||!machine.service||typeof machine.service.registerBackgroundGeneration!=='function')return false;const current=await status(id);if(!['active','degraded'].includes(current.state)||!desired(machine)||machine.operation)return false;return machine.service.registerBackgroundGeneration(generationKey,controller);},
    async unregisterChat(id,generationKey,controller){const machine=get(id);return machine.service?.unregisterBackgroundGeneration?.(generationKey,controller)===true;},
    async cancelChat(id,generationKey){const machine=get(id);if(!machine.service||typeof machine.service.abortGeneration!=='function')return false;return machine.service.abortGeneration(generationKey);},
    async shutdown(){await Promise.allSettled([...registry.values()].map(machine=>machine.service?.abortAll?.('Control Center si sta arrestando.')));},
    async settled(id){await get(id).operation?.promise;},
  };
}
