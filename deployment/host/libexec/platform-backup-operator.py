#!/usr/bin/python3
"""Closed native-v2 adapter: admitted peer, fixed helpers, durable immutable selection."""
import base64,datetime,fcntl,hashlib,hmac,json,os,pathlib,re,signal,socket,socketserver,stat,struct,subprocess,tempfile,time
R=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime');TRUST=R/'local-private-backup/trust';BROKER_STATE=R/'local-private-backup/broker-state'
WORK=pathlib.Path('/var/lib/platform-backup-operator');SOCKET=pathlib.Path('/run/platform-backup-operator/operator.sock');PUBLIC=pathlib.Path('/etc/platform-backup-operator/admission-public.pem')
LOCAL_PROOF=pathlib.Path('/var/lib/platform-local-dedup/latest-proof.json');OFFSITE_PROOF=pathlib.Path('/var/lib/platform-ftps-backup/latest-proof.json')
HELPERS={'helperSha256':'/usr/local/libexec/platform-ftps-backup.py','restoreHelperSha256':'/usr/local/libexec/platform-ftps-restore.py','rustfsHelperSha256':'/usr/local/libexec/platform-rustfs-recovery.py','rustfsRestoreHelperSha256':'/usr/local/libexec/platform-rustfs-restore.py','workerSha256':'/usr/local/libexec/platform-backup-operator.py'}
CAPABILITIES={'backup.offsite.sync':'docker_action_backup_offsite_sync','restore.offsite.proof':'docker_action_restore_offsite_proof'}
REQUEST_DOMAIN=b'platform-backup-operator-request-v2\0';RESPONSE_DOMAIN=b'platform-backup-operator-response-v2\0'
SHA=re.compile(r'[a-f0-9]{64}');MANIFEST=re.compile(r'manifest-[a-z0-9][a-z0-9-]{15,127}')
class UncertainOperation(RuntimeError):pass

def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def exact(v,keys):
 if not isinstance(v,dict) or set(v)!=set(keys):raise RuntimeError('Exact protocol fields rejected')
def epoch(value):
 if not isinstance(value,str):raise RuntimeError('Timestamp type rejected')
 parsed=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
 if parsed.tzinfo is None:raise RuntimeError('Timestamp lacks timezone')
 return parsed.timestamp()
def protected_directory(path,private=False):
 st=path.lstat()
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&(0o077 if private else 0o022):raise RuntimeError('Root directory rejected')
def root_path_parents(path):
 for parent in path.parents:
  if str(parent)=='/':break
  protected_directory(parent)
def read_regular(path,max_bytes=65536,root_only=False):
 path=pathlib.Path(path)
 if root_only:root_path_parents(path)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_mode&0o022 or (root_only and st.st_uid!=0) or not 0<st.st_size<=max_bytes:raise RuntimeError('Protected input rejected')
  data=b''
  while len(data)<st.st_size:
   block=os.read(fd,st.st_size-len(data))
   if not block:break
   data+=block
  after=os.fstat(fd)
  if st.st_size!=len(data) or any(getattr(st,k)!=getattr(after,k) for k in ['st_ino','st_size','st_mtime_ns','st_ctime_ns']):raise RuntimeError('Protected input changed')
  return data
 finally:os.close(fd)
def sync_directory(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def write_new(path,value):
 protected_directory(path.parent,True)
 fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(canonical(value));f.flush();os.fsync(f.fileno())
 sync_directory(path.parent)
def verify_signature(document,public_file,openssl='/usr/bin/openssl'):
 exact(document,['schema','payload','signature'])
 if document['schema']!='platform.local-private-backup-admission/v2':raise RuntimeError('Native worker requires admission v2')
 signature=document['signature'];exact(signature,['algorithm','keyId','value'])
 if signature['algorithm']!='Ed25519':raise RuntimeError('Admission signature algorithm rejected')
 try:value=base64.b64decode(signature['value'],validate=True)
 except Exception:raise RuntimeError('Admission signature encoding rejected')
 if len(value)!=64:raise RuntimeError('Admission signature length rejected')
 public=read_regular(public_file,4096,True)
 with tempfile.TemporaryDirectory(prefix='verify-admission-',dir=WORK) as temp:
  folder=pathlib.Path(temp);(folder/'public').write_bytes(public);(folder/'message').write_bytes(document['schema'].encode()+b'\0'+canonical(document['payload']));(folder/'signature').write_bytes(value)
  der=subprocess.run([openssl,'pkey','-pubin','-in',str(folder/'public'),'-outform','DER'],capture_output=True,timeout=5,check=True).stdout
  if signature['keyId']!='ed25519-'+sha(der)[:24]:raise RuntimeError('Public-key identity differs')
  result=subprocess.run([openssl,'pkeyutl','-verify','-pubin','-inkey',str(folder/'public'),'-rawin','-in',str(folder/'message'),'-sigfile',str(folder/'signature')],capture_output=True,timeout=5)
  if result.returncode:raise RuntimeError('Admission signature rejected')
def validate_object_store(store):
 exact(store,['backend','container','volume','image','imageId','archiveFormat','rootMarker','restoreMode'])
 fixed={'backend':'rustfs','container':'gf-rustfs','volume':'platform_rustfs_data','archiveFormat':'rustfs-volume/v1','rootMarker':'.rustfs.sys','restoreMode':'isolated-only'}
 if any(store.get(k)!=v for k,v in fixed.items()) or not isinstance(store['image'],str) or not re.fullmatch(r'rustfs/rustfs@sha256:[a-f0-9]{64}',store['image']) or not isinstance(store['imageId'],str) or not re.fullmatch(r'sha256:[a-f0-9]{64}',store['imageId']) or store['image'].endswith('0'*64) or store['imageId'].endswith('0'*64):raise RuntimeError('Signed RustFS store binding invalid')
 return store
def validate_admission(document,now):
 p=document['payload'];issued=epoch(p['issuedAt']);expires=epoch(p['expiresAt'])
 if type(p['generation']) is not int or p['generation']<1 or not issued-30<=now<=expires or not 0<expires-issued<=31*86400:raise RuntimeError('Admission expired or invalid')
 if not re.fullmatch(r'sha256:[a-f0-9]{64}',p['brokerImageId']):raise RuntimeError('Broker image identity invalid')
 o=p['resources']['offsite'];fixed={'backend':'ftps-multipart-v2','host':'92.113.28.106','port':21,'tlsName':'hstgr.io','folder':'/server-platform-backups','receiptSchema':'platform.ftps-recovery-point/v2','maxBytes':70000000000,'maxAgeSeconds':1209600,'maxPoints':6,'maxPartBytes':1000000000,'restoreSelection':'latest-complete-authenticated'}
 exact(o,[*fixed,'activationEvidence'])
 if any(type(o[k]) is not type(v) or o[k]!=v for k,v in fixed.items()):raise RuntimeError('Native destination or retention differs')
 anchor=o['activationEvidence'];exact(anchor,['manifestId','manifestDigest','receiptSha256','requiredLiveAnchor'])
 if not MANIFEST.fullmatch(anchor['manifestId']) or not SHA.fullmatch(anchor['manifestDigest']) or not SHA.fullmatch(anchor['receiptSha256']) or anchor['requiredLiveAnchor'] is not False:raise RuntimeError('Activation evidence invalid')
 validate_object_store(p['resources']['objectStore'])
 w=p['resources']['operator'];exact(w,['protocol','socket','uid','peerContainer','peerImageId',*HELPERS])
 if w['protocol']!='platform.backup-operator/v2' or w['socket']!='/run/platform/backup-operator/operator.sock' or type(w['uid']) is not int or w['uid']!=0 or w['peerContainer']!='gf-docker-action-broker' or w['peerImageId']!=p['brokerImageId'] or any(not SHA.fullmatch(w[k]) for k in HELPERS):raise RuntimeError('Native operator binding differs')
 return p

def validate_request(document,request,key,peer,active,now):
 exact(request,['payload','hmacSha256']);p=request['payload'];exact(p,['schema','action','requestId','admissionSha256','generation','issuedAt','expiresAt','parameters'])
 if p['schema']!='platform.backup-operator-request/v2' or p['action'] not in CAPABILITIES or p['parameters']!={} or not isinstance(p['requestId'],str) or not SHA.fullmatch(p['requestId']):raise RuntimeError('Native action or selector rejected')
 if not isinstance(request['hmacSha256'],str) or not hmac.compare_digest(hmac.new(key,REQUEST_DOMAIN+canonical(p),hashlib.sha256).hexdigest(),request['hmacSha256']):raise RuntimeError('Native request HMAC rejected')
 if type(p['generation']) is not int or p['generation']!=document['payload']['generation'] or p['admissionSha256']!=sha(canonical(document)):raise RuntimeError('Native admission binding differs')
 if peer['uid']!=1000 or peer['containerName']!='gf-docker-action-broker' or peer['imageId']!=document['payload']['brokerImageId']:raise RuntimeError('Native peer identity differs')
 exact(active,['action','admittedAt','request','requestId','requestSha256','schema','terminalFile'])
 if active['schema']!='platform.local-private-broker-active-operation/v2' or active['requestSha256']!=sha(canonical(active['request'])) or active['requestSha256']!=p['requestId'] or active['action']!=p['action'] or active['request'].get('action')!=p['action'] or active['request'].get('requestId')!=active['requestId'] or active['terminalFile']!='terminal/'+p['requestId']+'.json' or epoch(active['admittedAt'])>time.time()+30:raise RuntimeError('Native request is not the current accepted broker operation')
 issued=epoch(p['issuedAt']);expires=epoch(p['expiresAt'])
 if not issued-30<=now<=expires or not 0<expires-issued<=60:raise RuntimeError('Native request lifetime rejected')
 return p

def peer_identity(sock):
 pid,uid,gid=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
 record=json.loads(subprocess.check_output(['docker','inspect','gf-docker-action-broker'],text=True,timeout=5))[0]
 cgroup=pathlib.Path('/proc/'+str(pid)+'/cgroup').read_text()
 if not record['State']['Running'] or not re.search(r'(?:/|docker-)'+re.escape(record['Id'])+r'(?:\.scope|/|$)',cgroup,re.M):raise RuntimeError('Socket peer is not the exact broker container')
 return {'uid':uid,'containerName':record['Name'].lstrip('/'),'imageId':record['Image']}
def signed_response(request,key,status,result=None,error=None,selection=None):
 payload={'schema':'platform.backup-operator-result/v2','requestSha256':sha(canonical(request)),'admissionSha256':request['payload']['admissionSha256'],'action':request['payload']['action'],'status':status,'result':result,'errorCode':error,'selection':selection}
 return {'payload':payload,'hmacSha256':hmac.new(key,RESPONSE_DOMAIN+canonical(payload),hashlib.sha256).hexdigest()}
def stop_process_group(child):
 # The leader may already be dead while grandchildren still own this group.
 try:os.killpg(child.pid,signal.SIGTERM)
 except ProcessLookupError:pass
 try:child.wait(timeout=10)
 except subprocess.TimeoutExpired:pass
 # Always address survivors, including when wait() reaped the leader immediately.
 try:os.killpg(child.pid,signal.SIGKILL)
 except ProcessLookupError:pass
 try:child.wait(timeout=5)
 except subprocess.TimeoutExpired:raise UncertainOperation('Process group termination requires reconciliation')
def fixed_process(args,log,timeout):
 # Own process group: a lost client cannot change selection or restart the helper.
 fd=os.open(log,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as output:
  child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,start_new_session=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','HOME':'/root'})
  try:code=child.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
   stop_process_group(child)
   # Docker daemon children / remote writes may need operator reconciliation.
   raise UncertainOperation('Fixed helper deadline requires reconciliation')
  if code<0:
   stop_process_group(child)
   raise UncertainOperation('Signalled fixed helper requires reconciliation')
  if code:stop_process_group(child)
  output.flush();os.fsync(output.fileno())
 if code:raise RuntimeError('Fixed native helper failed')
def validate_selection(value,action):
 exact(value,['schema','action','manifestId','manifestDigest','bundle','receiptSha256'])
 if value['schema']!='platform.backup-operator-selection/v2' or value['action']!=action or not MANIFEST.fullmatch(value['manifestId']) or not SHA.fullmatch(value['manifestDigest']) or value['bundle']!='backup-'+value['manifestId']+'.tar.gpg':raise RuntimeError('Frozen selection invalid')
 if action=='restore.offsite.proof':
  if not isinstance(value['receiptSha256'],str) or not SHA.fullmatch(value['receiptSha256']):raise RuntimeError('Frozen receipt digest invalid')
 elif value['receiptSha256'] is not None:raise RuntimeError('Sync cannot supply remote receipt selector')
 return value

def select_operation(action,request_id):
 if action=='backup.offsite.sync':
  current=json.loads(read_regular(LOCAL_PROOF,root_only=True))
  if current.get('status')!='passed' or current.get('restoreVerified') is not True or current.get('manifestSignatureVerified') is not True:raise RuntimeError('Current local point is not actually verified')
  value={'manifestId':current['manifestId'],'manifestDigest':current['manifestDigest'],'bundle':'backup-'+current['manifestId']+'.tar.gpg','receiptSha256':None}
 else:
  log=WORK/(request_id+'.selection.log');fixed_process(['/usr/bin/python3',HELPERS['helperSha256'],'--native-select-latest'],log,180)
  value=json.loads(read_regular(log,16384,True));exact(value,['manifestId','manifestDigest','bundle','receiptSha256'])
 return validate_selection({'schema':'platform.backup-operator-selection/v2','action':action,**value},action)
def execute(action,request_id,selection,object_store):
 validate_object_store(object_store)
 validate_selection(selection,action);log=WORK/(request_id+'.log')
 if action=='backup.offsite.sync':args=['/usr/bin/python3',HELPERS['helperSha256'],'--expected-manifest-id',selection['manifestId'],'--expected-manifest-digest',selection['manifestDigest']]
 else:args=['/usr/bin/python3',HELPERS['restoreHelperSha256'],selection['bundle'],'--expected-receipt-sha256',selection['receiptSha256'],'--expected-rustfs-image',object_store['image'],'--expected-rustfs-image-id',object_store['imageId']]
 fixed_process(args,log,4*3600)
 if action=='backup.offsite.sync':
  result=json.loads(read_regular(OFFSITE_PROOF,root_only=True))
  remote=select_operation('restore.offsite.proof',request_id+'.completed')
  if remote['manifestId']!=selection['manifestId'] or remote['manifestDigest']!=selection['manifestDigest']:raise RuntimeError('Final authenticated remote selector differs')
  result['receiptSha256']=remote['receiptSha256']
 else:
  raw=json.loads(read_regular(log,65536,True))
  result={'manifestId':raw['manifestId'],'manifestDigest':raw['manifestDigest'],'artifactCount':raw['artifactCount'],'actualDownloadVerified':raw['actualRemoteDownloadVerified'],'decryptVerified':raw['decryptionVerified'],'everyArtifactShaAndHmacVerified':raw['everyArtifactShaAndHmacVerified'],'rustfsRestoreVerified':raw.get('rustfsRestoreVerified'),'receiptSha256':raw.get('receiptSha256'),'rustfsImage':raw.get('rustfsImage'),'rustfsImageId':raw.get('rustfsImageId')}
  if result['rustfsImage']!=object_store['image'] or result['rustfsImageId']!=object_store['imageId']:raise RuntimeError('Restored RustFS image differs from signed admission')
  if result['receiptSha256']!=selection['receiptSha256'] or result['rustfsRestoreVerified'] is not True:raise RuntimeError('Restore receipt or RustFS proof differs')
 if result['manifestId']!=selection['manifestId'] or result['manifestDigest']!=selection['manifestDigest']:raise RuntimeError('Helper switched selected recovery point')
 required=['actualDownloadVerified','decryptVerified','everyArtifactShaAndHmacVerified']
 if any(result.get(k) is not True for k in required) or type(result.get('artifactCount')) is not int or not 1<=result['artifactCount']<=25000:raise RuntimeError('Native helper did not prove recovery')
 return {'backend':'ftps-multipart-v2','productionModified':False,'manifestId':result['manifestId'],'manifestDigest':result['manifestDigest'],'artifactCount':result['artifactCount'],**{k:True for k in required},'rustfsRestoreVerified':result.get('rustfsRestoreVerified',False),'receiptSha256':result['receiptSha256'],'selection':selection,**({'rustfsImage':result['rustfsImage'],'rustfsImageId':result['rustfsImageId']} if action=='restore.offsite.proof' else {})}
def process(sock,request):
 protected_directory(WORK,True)
 doc=json.loads(read_regular(TRUST/'admission.json',2*1024*1024));verify_signature(doc,PUBLIC);p=validate_admission(doc,time.time())
 action=request.get('payload',{}).get('action')
 if action not in CAPABILITIES:raise RuntimeError('Unknown native capability')
 key=read_regular(TRUST/CAPABILITIES[action],4096)
 if sha(key)!=p['resources']['capabilityFiles']['capability.'+action]['sha256']:raise RuntimeError('Capability differs from signed admission')
 for name,helper in HELPERS.items():
  if sha(read_regular(pathlib.Path(helper),512*1024,True))!=p['resources']['operator'][name]:raise RuntimeError('Installed helper differs from admission')
 state=json.loads(read_regular(BROKER_STATE/'active-admission.json'))
 if state!={'generation':p['generation'],'admissionSha256':sha(canonical(doc))}:raise RuntimeError('Admission not committed by broker')
 active=json.loads(read_regular(BROKER_STATE/'active-operation.json'));peer=peer_identity(sock)
 request_id=request.get('payload',{}).get('requestId','')
 if not isinstance(request_id,str) or not SHA.fullmatch(request_id):raise RuntimeError('Invalid request identifier')
 record=WORK/(request_id+'.request.json');terminal=WORK/(request_id+'.response.json');selected=WORK/(request_id+'.selection.json')
 if record.exists():
  prior=json.loads(read_regular(record,root_only=True));validate_request(doc,request,key,peer,active,epoch(prior['payload']['issuedAt']))
  if canonical(prior)!=canonical(request):raise RuntimeError('Replay substitution rejected')
  selection=validate_selection(json.loads(read_regular(selected,root_only=True)),action) if selected.exists() else None
  if terminal.exists():
   response=json.loads(read_regular(terminal,root_only=True));payload=response['payload']
   expected=signed_response(request,key,payload['status'],payload['result'],payload['errorCode'],selection)
   if canonical(response)!=canonical(expected):raise RuntimeError('Terminal journal binding differs')
   return response
  return signed_response(request,key,'running',error='RECONCILIATION_REQUIRED',selection=selection)
 validate_request(doc,request,key,peer,active,time.time())
 if len(list(WORK.glob('*.request.json')))>=4096:raise RuntimeError('Native replay journal capacity reached')
 write_new(record,request);selection=None
 try:
  selection=select_operation(action,request_id);write_new(selected,selection)
  response=signed_response(request,key,'passed',execute(action,request_id,selection,p['resources']['objectStore']),selection=selection)
 except UncertainOperation:response=signed_response(request,key,'running',error='RECONCILIATION_REQUIRED',selection=selection)
 except Exception:response=signed_response(request,key,'failed',error='FIXED_OPERATION_FAILED',selection=selection)
 write_new(terminal,response);return response
class Handler(socketserver.StreamRequestHandler):
 def handle(self):
  self.request.settimeout(10);raw=self.rfile.readline(16385)
  if len(raw)>16384 or not raw.endswith(b'\n'):return
  try:
   request=json.loads(raw);assert raw==canonical(request)+b'\n';response=process(self.request,request);self.wfile.write(canonical(response)+b'\n')
  except Exception:
   try:self.wfile.write(b'{"error":"NATIVE_OPERATION_REJECTED"}\n')
   except OSError:pass

def main():
 if os.geteuid()!=0:raise RuntimeError('Root service required')
 os.umask(0o077);WORK.mkdir(mode=0o700,exist_ok=True);protected_directory(WORK,True);root_path_parents(WORK)
 fd=os.open(WORK/'service.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);SOCKET.parent.mkdir(mode=0o750,exist_ok=True);protected_directory(SOCKET.parent);os.chown(SOCKET.parent,0,1000)
  if SOCKET.exists() or SOCKET.is_symlink():
   if not stat.S_ISSOCK(SOCKET.lstat().st_mode) or SOCKET.lstat().st_uid!=0:raise RuntimeError('Unexpected operator socket object')
   SOCKET.unlink()
  with socketserver.UnixStreamServer(str(SOCKET),Handler) as server:
   os.chown(SOCKET,0,1000);os.chmod(SOCKET,0o660);server.serve_forever()
if __name__=='__main__':main()
