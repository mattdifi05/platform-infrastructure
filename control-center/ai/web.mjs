import http from 'node:http';
import https from 'node:https';
import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';

const IPV4_DENY = [[0,8],[0x0a000000,8],[0x64400000,10],[0x7f000000,8],[0xa9fe0000,16],[0xac100000,12],[0xc0000000,24],[0xc0000200,24],[0xc0586300,24],[0xc0a80000,16],[0xc6120000,15],[0xc6336400,24],[0xcb007100,24],[0xe0000000,4],[0xf0000000,4]];
const HTML_TYPES = new Set(['text/html','application/xhtml+xml']);
const TEXT_TYPES = new Set([...HTML_TYPES,'text/plain','application/json']);
const FORBIDDEN_HOSTS = /(?:^|\.)(?:localhost|local|internal|lan|home|test|invalid|example|onion|docker|host\.docker\.internal|platform-infrastructure\.com|tail3b7b30\.ts\.net)$/i;
export class WebToolError extends Error { constructor(code, message) { super(message); this.name='WebToolError'; this.code=code; } }
const fail = (code,message) => { throw new WebToolError(code,message); };

export function isPublicAddress(address) {
  if (isIP(address) === 4) {
    const n = address.split('.').reduce((a,b)=>(a*256+Number(b))>>>0,0);
    return !IPV4_DENY.some(([base,bits]) => (n >>> (32-bits)) === (base >>> (32-bits)));
  }
  if (isIP(address) !== 6 || address.includes('%') || address.includes('.')) return false;
  const lower=address.toLowerCase();
  // Only ordinary global unicast; deny transition, documentation and special allocations.
  if (!/^[23][0-9a-f]{3}:/.test(lower) || /^2002:/.test(lower) || /^3fff:/.test(lower)) return false;
  if (/^2001:/.test(lower)) {
    const second=parseInt(lower.split(':')[1]||'0',16);
    if (second < 0x200 || second === 0xdb8) return false;
  }
  return true;
}

export function validatePublicUrl(value) {
  if (typeof value!=='string' || value.length>2048 || /[\x00-\x20\x7f\\]/.test(value)) fail('invalid_url','URL non valido.');
  let url; try { url=new URL(value); } catch { fail('invalid_url','URL non valido.'); }
  if (!['http:','https:'].includes(url.protocol) || url.username || url.password || (url.port && !['80','443'].includes(url.port))) fail('blocked_url','Protocollo, credenziali o porta non consentiti.');
  if ([...url.searchParams.keys()].some(key=>/(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|signature|session[_-]?id)/i.test(key))) fail('blocked_url','Parametri riservati non consentiti nelle fonti web.');
  const host=url.hostname.replace(/^\[|\]$/g,'').replace(/\.$/,'').toLowerCase();
  if (!host || FORBIDDEN_HOSTS.test(host) || (!isIP(host) && (!host.includes('.') || !/^[a-z0-9.-]+$/.test(host)))) fail('blocked_url','Destinazione interna o non consentita.');
  if (isIP(host) && !isPublicAddress(host)) fail('blocked_url','Indirizzo non pubblico.');
  url.hostname=isIP(host)===6 ? `[${host}]` : host;
  url.hash='';
  return url;
}

const MARKDOWN_FIELD = String.raw`(?:database\s+host|host\s+database|database(?:\s+(?:name|nome))?|nome\s+database|database\s+user|db\s+user|utente(?:\s+(?:database|db))?|nome\s+utente|username|password(?:\s+(?:database|db))?|passwd|pwd|credenziale|secret|segreto|token|api[_ -]?key)`;
const MARKDOWN_DECORATION = String.raw`[\x60*_~"']{0,3}`;
const MARKDOWN_LABELED_VALUE = new RegExp(String.raw`^(\s*(?:[-+*]\s+)?${MARKDOWN_DECORATION}${MARKDOWN_FIELD}${MARKDOWN_DECORATION}\s*(?::|=>|=)\s*)(.*)$`, 'i');
const MARKDOWN_TABLE_VALUE = new RegExp(String.raw`^(\s*\|\s*${MARKDOWN_DECORATION}${MARKDOWN_FIELD}${MARKDOWN_DECORATION}\s*\|\s*)([^|]*)(.*)$`, 'i');
const INLINE_LABELED_VALUE = new RegExp(String.raw`(${MARKDOWN_DECORATION}${MARKDOWN_FIELD}${MARKDOWN_DECORATION}\s*(?::|=>|=)\s*)(?:\x60[^\x60\r\n]*\x60|"[^"\r\n]*"|'[^'\r\n]*'|[^,;|\s]+)`, 'gi');
const INLINE_BACKTICK_FIELD = new RegExp(String.raw`(\b${MARKDOWN_FIELD}\b\s+)\x60[^\x60\r\n]+\x60`, 'gi');
const CONNECTION_PAIR = /\b(?:server|server\s+instance|host|database|initial\s+catalog|user\s*id|uid|username|password|passwd|pwd)\s*=/gi;
const CONNECTION_PAIR_VALUE = /(\b(?:server|server\s+instance|host|database|initial\s+catalog|user\s*id|uid|username|password|passwd|pwd)\s*=\s*)(?:"[^"\r\n;]*"|'[^'\r\n;]*'|`[^`\r\n;]*`|[^;\s]+)/gi;
const DATABASE_COMMAND = /\b(?:mysql|mariadb)(?:\.exe)?\b|\b(?:Invoke-Sqlcmd|MySqlConnection|MySqlCommand|PSCredential)\b/i;
const LONG_CREDENTIAL_FLAG = /(\s--?(?:serverinstance|password|username|credential|database|passwd|server|host|user)(?:=|\s+))(?:(['"`])[^\r\n]*?\2|[^\s;|]+)/gi;
const MYSQL_SHORT_FLAG = /(\s-[puh])(?:(['"`])[^\r\n]*?\2|[^\s;|]+)/g;

function redactDocumentCredentials(value) {
  return value.split(/(\r?\n)/).map(line => {
    if (/^\r?\n$/.test(line)) return line;
    let result = line.replace(MARKDOWN_TABLE_VALUE, '$1[redatto]$3');
    const labeled = result.match(MARKDOWN_LABELED_VALUE);
    if (labeled) {
      const markdownBreak = /\s{2}$/.test(labeled[2]) ? '  ' : '';
      return `${labeled[1]}[redatto]${markdownBreak}`;
    }
    result = result.replace(INLINE_LABELED_VALUE, '$1[redatto]');
    result = result.replace(INLINE_BACKTICK_FIELD, '$1`[redatto]`');
    const pairs = result.match(CONNECTION_PAIR);
    CONNECTION_PAIR.lastIndex = 0;
    if (pairs?.length >= 2) result = result.replace(CONNECTION_PAIR_VALUE, '$1[redatto]');
    if (DATABASE_COMMAND.test(result)) {
      const mysqlWithCredentials = /\b(?:mysql|mariadb)(?:\.exe)?\b/i.test(result) && /(?:\s--?(?:password|passwd|username|user|host|database)(?:=|\s+)|\s-[puh](?:\s+|[^\s-]))/i.test(result);
      result = result.replace(LONG_CREDENTIAL_FLAG, '$1[redatto]');
      result = result.replace(MYSQL_SHORT_FLAG, '$1[redatto]');
      if (mysqlWithCredentials && !/\s(?:-e|--execute)(?:=|\s)|[<>|]/i.test(result)) result = result.replace(/(\s)([A-Za-z0-9_.-]+)(\s*)$/, '$1[redatto]$3');
    }
    return result;
  }).join('');
}

export function redactText(value, max=16000) {
  return redactDocumentCredentials(String(value ?? ''))
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,'[chiave privata rimossa]')
    .replace(/\b(?:bearer|basic)\s+[A-Za-z0-9+/_=.-]+/gi,'[credenziale rimossa]')
    .replace(/((?:["'`*_~]{0,3})(?:[a-z0-9_-]*(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|session[_-]?id|credential))(?:["'`*_~]{0,3})\s*(?:=>|[=:])\s*)(?:"[^"\n]*(?:"|$)|'[^'\n]*(?:'|$)|`[^`\n]*(?:`|$)|[^\s,;]+)/gi,'$1[redatto]')
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g,'[token rimosso]')
    .replace(/(https?:\/\/)[^/\s:@]+:[^/\s@]+@/gi,'$1[redatto]@').slice(0,max);
}

function decodeEntities(text) {
  return text.replace(/&(?:#(x[0-9a-f]{1,6}|[0-9]{1,7})|(amp|lt|gt|quot|apos|nbsp));/gi,(_,n,name)=>{
    if (n) { const cp=n[0].toLowerCase()==='x'?parseInt(n.slice(1),16):Number(n); return cp>0&&cp<=0x10ffff&&!(cp>=0xd800&&cp<=0xdfff)?String.fromCodePoint(cp):' '; }
    return {amp:'&',lt:'<',gt:'>',quot:'"',apos:"'",nbsp:' '}[name.toLowerCase()];
  });
}
export function extractWebText(body, type, maxChars=16000) {
  let title='',text=body;
  if (HTML_TYPES.has(type)) {
    title=decodeEntities((body.match(/<title\b[^>]*>([\s\S]*?)<\/title\s*>/i)?.[1]||'').replace(/<[^>]*>/g,' ')).trim().slice(0,240);
    text=body.replace(/<!--[\s\S]*?(?:-->|$)/g,' ')
      .replace(/<(script|style|noscript|svg|nav|header|footer|form|iframe)\b[^>]*>[\s\S]*?<\/\1\s*>/gi,' ')
      .replace(/<(script|style)\b[^>]*>[\s\S]*$/gi,' ')
      .replace(/<\/(?:p|div|h[1-6]|li|tr|section|article)>|<br\s*\/?\s*>/gi,'\n')
      .replace(/<[^>]*>/g,' ');
    text=decodeEntities(text);
  }
  text=text.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g,'').replace(/[ \t]+/g,' ').replace(/\n\s*\n\s*\n/g,'\n\n').trim();
  return {title,text:redactText(text,maxChars),truncated:text.length>maxChars};
}

// The validated IP is pinned to the socket lookup. Redirects get fresh DNS validation.
export async function fetchPublicPage(value, {signal,resolve=dnsLookup,request,blockedAddresses=[],timeoutMs=12000,maxBytes=1024*1024,maxChars=16000,maxRedirects=3}={}) {
  const deadline=AbortSignal.timeout(timeoutMs);
  const combined=signal?AbortSignal.any([signal,deadline]):deadline;
  let url=validatePublicUrl(value); const visited=new Set();
  for (let redirect=0;redirect<=maxRedirects;redirect++) {
    combined.throwIfAborted();
    if (visited.has(url.href)) fail('redirect_loop','Redirect circolare.'); visited.add(url.href);
    const host=url.hostname.replace(/^\[|\]$/g,'');
    const addresses=isIP(host)?[{address:host,family:isIP(host)}]:await Promise.race([
      resolve(host,{all:true,verbatim:true}),
      new Promise((_,reject)=>{if(combined.aborted)reject(combined.reason);else combined.addEventListener('abort',()=>reject(combined.reason),{once:true});}),
    ]);
    const canonical=address=>isIP(address)===6?new URL(`http://[${address}]`).hostname:address;
    const blocked=new Set(blockedAddresses.map(canonical));
    if (!Array.isArray(addresses) || !addresses.length || addresses.length>32 || addresses.some(row=>!row||typeof row.address!=='string'||!isPublicAddress(row.address)||blocked.has(canonical(row.address)))) fail('blocked_address','La destinazione DNS non è pubblica.');
    const selected=addresses.find(a=>a.family===4)||addresses[0];
    const reply=await pinnedRequest(url,selected,{signal:combined,maxBytes,request});
    if ([301,302,303,307,308].includes(reply.status)) {
      if (!reply.location || redirect===maxRedirects) fail('redirect_limit','Troppi redirect.');
      let next; try { next=new URL(reply.location,url).href; } catch { fail('invalid_redirect','Redirect non valido.'); }
      url=validatePublicUrl(next); continue;
    }
    if(reply.status<200||reply.status>=300) fail('http_error',`La fonte ha risposto HTTP ${reply.status}.`);
    const extracted=extractWebText(reply.body,reply.type,maxChars);
    return {url:url.href,domain:url.hostname,title:extracted.title||url.hostname,text:extracted.text,truncated:extracted.truncated,downloadBytes:reply.bytes,fetchedAt:new Date().toISOString(),untrusted:true};
  }
  fail('redirect_limit','Troppi redirect.');
}

function pinnedRequest(url,address,{signal,maxBytes,request}) {
  return new Promise((resolve,reject)=>{
    const makeRequest=request||(url.protocol==='https:'?https.request:http.request);
    const req=makeRequest(url,{
      method:'GET',agent:false,signal,maxHeaderSize:16384,
      lookup:(_host,opts,cb)=>opts?.all?cb(null,[address]):cb(null,address.address,address.family),
      servername:isIP(url.hostname)?undefined:url.hostname,
      rejectUnauthorized:true,
      headers:{'user-agent':'ServerAI/1.0 (controlled public-page reader)','accept':'text/html, text/plain, application/json','accept-encoding':'identity'},
    },res=>{
      const status=res.statusCode||0;
      if ([301,302,303,307,308].includes(status)) { const location=res.headers.location;res.destroy();resolve({status,location});return; }
      const type=String(res.headers['content-type']||'').split(';')[0].trim().toLowerCase();
      if (!TEXT_TYPES.has(type)) {res.destroy();reject(new WebToolError('content_type','Tipo di contenuto non consentito.'));return;}
      if (res.headers['content-encoding'] && res.headers['content-encoding']!=='identity') {res.destroy();reject(new WebToolError('content_encoding','Contenuto compresso non consentito.'));return;}
      if (Number(res.headers['content-length']||0)>maxBytes) {res.destroy();reject(new WebToolError('download_limit','Pagina troppo grande.'));return;}
      let bytes=0;const chunks=[];
      res.on('data',chunk=>{bytes+=chunk.length;if(bytes>maxBytes){res.destroy(new WebToolError('download_limit','Pagina troppo grande.'));return;}chunks.push(chunk);});
      res.on('end',()=>resolve({status,type,bytes,body:Buffer.concat(chunks).toString('utf8')}));
      res.on('error',reject);
    });
    req.on('socket',socket=>{
      socket.once('connect',()=>{const remote=socket.remoteAddress?.replace(/^::ffff:/,''); if(remote && remote!==address.address){req.destroy(new WebToolError('address_changed','La destinazione di rete è cambiata.'));}});
    });
    req.on('error',reject);req.end();
  });
}

async function limitedJson(response,maxBytes=256*1024) {
  if(!response.ok)fail('search_unavailable','Ricerca web non disponibile.');
  if(!String(response.headers.get('content-type')||'').includes('application/json'))fail('search_unavailable','Risposta del motore non valida.');
  const reader=response.body.getReader();let bytes=0;const chunks=[];
  try{for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>maxBytes)fail('search_limit','Risultato ricerca troppo grande.');chunks.push(Buffer.from(value));}return JSON.parse(Buffer.concat(chunks).toString('utf8'));}
  finally{await reader.cancel().catch(()=>{});}
}

export function createWebTools({searxngUrl='http://searxng:8080',fetchImpl=fetch,pageReader=fetchPublicPage,connectivityProbe=()=>fetchPublicPage('https://example.com/',{timeoutMs:2500,maxBytes:16000,maxChars:1})}={}) {
  const searchBase=new URL(searxngUrl);
  if(searchBase.protocol!=='http:'||!['searxng','gf-searxng'].includes(searchBase.hostname)||searchBase.port!=='8080'||searchBase.username||searchBase.password||searchBase.pathname!=='/'||searchBase.search||searchBase.hash) fail('invalid_search_service','SearXNG deve usare il servizio Docker privato configurato.');
  let connectivity=null,connectivityPending=null;
  async function internetHealth(){
    if(connectivity&&Date.now()-Date.parse(connectivity.checkedAt)<60000)return connectivity;
    if(!connectivityPending)connectivityPending=(async()=>{let online=false;try{await connectivityProbe();online=true;}catch{}connectivity={online,checkedAt:new Date().toISOString(),source:'controlled-public-HTTPS-probe'};return connectivity;})().finally(()=>{connectivityPending=null;});
    return connectivityPending;
  }
  return {
    async search(args,{mode='fast',signal,sources=new Map()}={}) {
      const allowed=['query','language','timeRange','maxResults'];
      if(!args||typeof args!=='object'||Array.isArray(args)||Object.keys(args).some(k=>!allowed.includes(k))||typeof args.query!=='string'||!args.query.trim()||args.query.length>400)fail('invalid_args','Query non valida (massimo 400 caratteri).');
      const max=mode==='deep'?10:5;
      if(args.maxResults!==undefined&&(!Number.isInteger(args.maxResults)||args.maxResults<1||args.maxResults>max))fail('invalid_args','Numero risultati non consentito.');
      if(args.language!==undefined&&!['it','en','all'].includes(args.language))fail('invalid_args','Lingua non consentita.');
      if(args.timeRange!==undefined&&!['day','week','month','year'].includes(args.timeRange))fail('invalid_args','Intervallo non consentito.');
      const url=new URL('/search',searchBase);
      url.search=new URLSearchParams({q:redactText(args.query,400).replace(/[!<>]/g,' ').trim(),format:'json',categories:'general',language:args.language||'all',safesearch:'1',...(args.timeRange?{time_range:args.timeRange}:{})}).toString();
      const combined=signal?AbortSignal.any([signal,AbortSignal.timeout(10000)]):AbortSignal.timeout(10000);
      let data;try{data=await limitedJson(await fetchImpl(url,{signal:combined,redirect:'error',headers:{accept:'application/json'}}));}catch(e){if(signal?.aborted)throw e;fail('search_unavailable','Ricerca web non disponibile.');}
      const results=[];
      for(const row of (Array.isArray(data.results)?data.results:[]).slice(0,50)) {
        if(!row||typeof row!=='object'||Array.isArray(row))continue;
        let link;try{link=validatePublicUrl(row.url);}catch{continue;}
        const source={id:`S${sources.size+1}`,title:redactText(row.title||link.hostname,240),url:link.href,domain:link.hostname,fetchedAt:new Date().toISOString()};
        const existing=[...sources.values()].find(s=>s.url===source.url);if(existing)source.id=existing.id;else {if(sources.size>=24)break;sources.set(source.id,source);}
        results.push({...source,snippet:redactText(row.content||'',1000),source:link.hostname});
        if(results.length>=(args.maxResults||max))break;
      }
      return {query:redactText(args.query,400),results,untrusted:true,truncated:Array.isArray(data.results)&&data.results.length>results.length};
    },
    async read(args,{signal,sources=new Map(),mode='fast'}={}) {
      if(!args||typeof args!=='object'||Array.isArray(args)||Object.keys(args).some(k=>k!=='url'))fail('invalid_args','Argomenti fonte non validi.');
      const result=await pageReader(args.url,{signal,maxChars:mode==='deep'?16000:8000});
      const existing=[...sources.values()].find(s=>s.url===result.url);
      const source={id:existing?.id||`S${sources.size+1}`,title:result.title,url:result.url,domain:result.domain,fetchedAt:result.fetchedAt};
      sources.set(source.id,source);
      return {...result,id:source.id};
    },
    async health() {
      const internetPromise=internetHealth();let online=false;
      try{const r=await fetchImpl(new URL('/healthz',searchBase),{signal:AbortSignal.timeout(2000),redirect:'error'});online=r.ok;await r.body?.cancel();}catch{}
      return {online,internet:await internetPromise};
    },
  };
}
