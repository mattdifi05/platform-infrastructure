#!/usr/bin/env node
// One minimal official API request. Credentials are file-only and never logged.
import fs from 'node:fs/promises';
const path='/run/secrets/server_ai_openai_api_key';
try {
  if(process.env.OPENAI_API_KEY_FILE!==path)throw new Error('credential_reference_unavailable');
  const stat=await fs.stat(path);
  if(!stat.isFile()||stat.uid!==process.getuid()||(stat.mode&0o077)||stat.size<20||stat.size>8192)throw new Error('credential_metadata_rejected');
  const key=(await fs.readFile(path,'utf8')).trim();
  if(key.length<20||key.length>4096||/\s/.test(key))throw new Error('credential_format_rejected');
  const response=await fetch('https://api.openai.com/v1/responses',{method:'POST',headers:{authorization:`Bearer ${key}`,'content-type':'application/json'},body:JSON.stringify({model:'gpt-6-luna',instructions:'Rispondi esattamente READY.',input:'READY',reasoning:{effort:'none'},max_output_tokens:16,store:false}),signal:AbortSignal.timeout(30000)});
  const data=await response.json();
  const text=(data.output||[]).flatMap(item=>item.content||[]).filter(item=>item.type==='output_text').map(item=>item.text||'').join('').trim();
  const ready=response.ok&&text==='READY';
  const result={provider:'openai',model:'gpt-6-luna',httpStatus:response.status,ready};
  if(response.ok){result.inputTokens=data.usage?.input_tokens;result.outputTokens=data.usage?.output_tokens;}
  else if(/^[a-z_]{1,80}$/.test(data.error?.code||''))result.errorCode=data.error.code;
  console.log(JSON.stringify(result));
  if(!ready)process.exitCode=1;
}catch(error){console.log(JSON.stringify({provider:'openai',model:'gpt-6-luna',ready:false,error:['credential_reference_unavailable','credential_metadata_rejected','credential_format_rejected'].includes(error.message)?error.message:'request_failed'}));process.exitCode=1;}
