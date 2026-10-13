#!/usr/bin/python3
"""Root-native VPS capture, encrypted verification and separately gated FTPS sync.
Home authority and project source remain outside this fresh-host capture scope.
"""
import base64,datetime,signal,fcntl,hashlib,hmac,importlib.util,json,os,pathlib,re,shutil,sqlite3,stat,subprocess,sys,tarfile,tempfile,time,uuid
HERE=pathlib.Path(__file__).resolve().parent
CONFIG=pathlib.Path('/etc/platform-vps-backup')
WORK=pathlib.Path('/var/lib/platform-vps-backup')
REPO=pathlib.Path('/srv/platform-infrastructure/first-install')
KEY=CONFIG/'encryption-key'
SIGNING=CONFIG/'manifest-key'
PROFILE=CONFIG/'profile.json'
ALLOW_PROJECTS={'platform_infra_vps','platform_server_ai','scriptastudents_vps','workcalendar_vps'}
HOST='platform-server-public'
MAX_BYTES=70_000_000_000

BASE_CONTAINER_NAMES=frozenset('/'+name for name in (
 'enterprise-postgres','enterprise-redis','enterprise-control-center','enterprise-traefik','enterprise-waf','platform-waf-loopback-proxy',
 'mariadb','enterprise-nats','enterprise-keycloak','enterprise-project-router','gf-rustfs','gf-minio-gateway',
 'enterprise-platform-alert-dispatcher','enterprise-alertmanager','enterprise-prometheus','enterprise-grafana','enterprise-loki','enterprise-promtail',
 'gf-searxng','gf-server-ai-controller','gf-server-ai-observer'))
NODE_EXPORTER_BINDS={'/proc/stat':'/proc-host/stat','/proc/meminfo':'/proc-host/meminfo','/proc/1/mountinfo':'/proc-host/1/mountinfo','/var/lib/platform-host-metrics/rootfs':'/host'}

SCRIPTA_NAMES=frozenset('/'+name for name in ('node-scriptastudents','students-beta-redis','scriptastudents-ingress','scripta-postgres'))
SCRIPTA_ROOT='/srv/platform-infrastructure/scripta-students'

SCRIPTA_PROJECT='scriptastudents'
SCRIPTA_SOURCE='/srv/platform-infrastructure/src/scriptastudents'

def validate_scripta_management(management,rows=None):
 if not isinstance(management,dict) or set(management)!={'schema','projectId','sourceRoot','database','adminContainer'} or management.get('schema')!='scripta-management/v1' or management.get('projectId')!=SCRIPTA_PROJECT or management.get('sourceRoot')!=SCRIPTA_SOURCE:raise RuntimeError('Invalid finite Scripta management admission')
 expected={'id':'scriptastudents-postgres-students-beta-app','name':'students_beta_app','engine':'postgres','host':'scripta-postgres','port':5432,'role':'scripta_app'}
 if management.get('database')!=expected:raise RuntimeError('Scripta database admission differs')
 pin=management.get('adminContainer')
 if not isinstance(pin,dict) or set(pin)!={'name','id','image','mounts','labels'} or pin.get('name')!='/phppgadmin' or not re.fullmatch('[a-f0-9]{64}',pin.get('id','')) or not re.fullmatch('sha256:[a-f0-9]{64}',pin.get('image','')) or not isinstance(pin.get('mounts'),list) or not isinstance(pin.get('labels'),dict) or pin['labels'].get('com.docker.compose.project')!='scriptastudents_vps' or pin['labels'].get('com.docker.compose.service')!='phppgadmin':raise RuntimeError('Invalid scoped database admin pin')
 for mount in pin['mounts']:
  if mount.get('Type') not in ('bind','tmpfs') or mount.get('Type')=='bind' and (mount.get('RW') is not False or not isinstance(mount.get('Source'),str) or not mount['Source'].startswith(SCRIPTA_ROOT+'/') or '..' in pathlib.PurePosixPath(mount['Source']).parts):raise RuntimeError('Unreviewed database admin mount')
 if rows is not None:
  actual=next((r for r in rows if r['Name']=='/phppgadmin'),None)
  if not actual or {'name':actual['Name'],'id':actual['Id'],'image':actual['Image'],'mounts':actual['Mounts'],'labels':actual['Config'].get('Labels') or {}}!=pin:raise RuntimeError('Database admin identity differs from signed profile')
 return management

def scripta_resources(p):
 validate_scripta_management(p.get('scriptaManagement'))
 return [{'id':'source:scriptastudents','externalId':'scriptastudents','kind':'source','projectId':SCRIPTA_PROJECT,'name':'scriptastudents','sourceDirectory':'scriptastudents'},{'id':'database:scriptastudents-postgres-students-beta-app','externalId':'scriptastudents-postgres-students-beta-app','kind':'database','projectId':SCRIPTA_PROJECT,'name':'students_beta_app','engine':'postgres'},{'id':'platform-state:scriptastudents-state','externalId':'scriptastudents-state','kind':'platform-state','projectId':SCRIPTA_PROJECT,'name':'scriptastudents-state'}]

def scripta_mode(p,resources):
 expected=scripta_resources(p)
 for name,selected in [('all',expected),('source',expected[:1]),('database',expected[1:2])]:
  if canonical(sorted(resources,key=lambda r:r['id']))==canonical(sorted(selected,key=lambda r:r['id'])):return name
 raise RuntimeError('Application resource set is not an exact admitted mode')


WORKCALENDAR_NAMES=frozenset('/'+name for name in ('node-workcalendar','workcalendar-redis','workcalendar-ingress','workcalendar-postgres'))
WORKCALENDAR_ROOT='/srv/platform-infrastructure/workcalendar'
WORKCALENDAR_PROJECT='workcalendar'
WORKCALENDAR_SOURCE='/srv/platform-infrastructure/src/workcalendar'

def validate_workcalendar_management(management,rows=None):
 expected={'schema':'workcalendar-management/v1','projectId':WORKCALENDAR_PROJECT,'sourceRoot':WORKCALENDAR_SOURCE,'database':{'id':'workcalendar-postgres-workcalendar-app','name':'workcalendar_app','engine':'postgres','host':'workcalendar-postgres','port':5432,'role':'workcalendar_app'}}
 if management!=expected:raise RuntimeError('Invalid finite WorkCalendar management admission')
 return management

def workcalendar_resources(p):
 validate_workcalendar_management(p.get('workcalendarManagement'))
 return [{'id':'source:workcalendar','externalId':'workcalendar','kind':'source','projectId':WORKCALENDAR_PROJECT,'name':'workcalendar','sourceDirectory':'workcalendar'},{'id':'database:workcalendar-postgres-workcalendar-app','externalId':'workcalendar-postgres-workcalendar-app','kind':'database','projectId':WORKCALENDAR_PROJECT,'name':'workcalendar_app','engine':'postgres'},{'id':'platform-state:workcalendar-state','externalId':'workcalendar-state','kind':'platform-state','projectId':WORKCALENDAR_PROJECT,'name':'workcalendar-state'}]

def workcalendar_mode(p,resources):
 expected=workcalendar_resources(p)
 for name,selected in [('all',expected),('source',expected[:1]),('database',expected[1:2])]:
  if canonical(sorted(resources,key=lambda r:r['id']))==canonical(sorted(selected,key=lambda r:r['id'])):return name
 raise RuntimeError('WorkCalendar resources are not an exact admitted mode')

def validate_workcalendar_runtime(extension,rows):
 if not isinstance(extension,dict) or set(extension)!={'schema','project','containers','persistentRoots','postgresData','previousProfileSha256','reviewSha256','updatedAt'} or extension.get('schema')!='workcalendar-reviewed-runtime/v1' or extension.get('project')!='workcalendar_vps':raise RuntimeError('Invalid finite WorkCalendar runtime admission')
 expected=extension.get('containers')
 if not isinstance(expected,list) or len(expected)!=4 or {x.get('name') for x in expected}!=WORKCALENDAR_NAMES:raise RuntimeError('WorkCalendar membership is not the exact quartet')
 if any(not re.fullmatch('[a-f0-9]{64}',extension.get(k,'')) for k in ('previousProfileSha256','reviewSha256')):raise RuntimeError('Missing preceding WorkCalendar review identity')
 if extension.get('persistentRoots')!=[WORKCALENDAR_ROOT+'/data/legacy',WORKCALENDAR_ROOT+'/data/redis'] or extension.get('postgresData')!=WORKCALENDAR_ROOT+'/data/postgres':raise RuntimeError('WorkCalendar persistent boundary differs')
 by_name={r['Name']:r for r in rows}
 services={'/node-workcalendar':'backend','/workcalendar-redis':'redis','/workcalendar-ingress':'ingress','/workcalendar-postgres':'postgres'}
 for item in expected:
  actual=by_name.get(item['name']);labels=(actual['Config'].get('Labels') or {}) if actual else {}
  if not actual or {'name':actual['Name'],'id':actual['Id'],'image':actual['Image'],'mounts':actual['Mounts'],'labels':labels}!=item:raise RuntimeError('WorkCalendar identity differs from reviewed receipt')
  if labels.get('com.docker.compose.project')!='workcalendar_vps' or labels.get('com.docker.compose.service')!=services[item['name']]:raise RuntimeError('WorkCalendar compose identity differs')
  for mount in item['mounts']:
   if mount.get('Type') not in ('bind','tmpfs') or mount.get('Type')=='bind' and (not isinstance(mount.get('Source'),str) or not mount['Source'].startswith(WORKCALENDAR_ROOT+'/') or '..' in pathlib.PurePosixPath(mount['Source']).parts):raise RuntimeError('Foreign WorkCalendar mount')
 return extension

def reviewed_membership(rows,scripta=None,management=None,workcalendar=None,workcalendar_management=None):
 names={r['Name'] for r in rows};extra=frozenset()
 if scripta is not None:
  if not isinstance(scripta,dict) or scripta.get('schema')!='scripta-reviewed-runtime/v1' or scripta.get('project')!='scriptastudents_vps':raise RuntimeError('Invalid reviewed application extension')
  expected=scripta.get('containers')
  if not isinstance(expected,list) or len(expected)!=4 or {r.get('name') for r in expected}!=SCRIPTA_NAMES:raise RuntimeError('Application membership is not the exact reviewed set')
  if not re.fullmatch('[a-f0-9]{64}',scripta.get('previousProfileSha256','')):raise RuntimeError('Missing preceding profile identity')
  by_name={r['Name']:r for r in rows}
  for item in expected:
   actual=by_name.get(item['name']);labels=actual['Config'].get('Labels') or {} if actual else {}
   if not actual or {'name':actual['Name'],'id':actual['Id'],'image':actual['Image'],'mounts':actual['Mounts'],'labels':labels}!=item:raise RuntimeError('Application Docker identity differs from reviewed receipt')
   if labels.get('com.docker.compose.project')!='scriptastudents_vps':raise RuntimeError('Application project identity differs')
  if scripta.get('persistentRoots')!=[SCRIPTA_ROOT+'/data/legacy',SCRIPTA_ROOT+'/data/redis'] or scripta.get('postgresData')!=SCRIPTA_ROOT+'/data/postgres':raise RuntimeError('Application persistent boundary differs')
  extra=SCRIPTA_NAMES
 if management is not None:
  if scripta is None:raise RuntimeError('Application management requires existing runtime admission')
  validate_scripta_management(management,rows);extra=extra|{'/phppgadmin'}
 if workcalendar is not None:
  validate_workcalendar_runtime(workcalendar,rows);validate_workcalendar_management(workcalendar_management,rows);extra=extra|WORKCALENDAR_NAMES
 elif workcalendar_management is not None:raise RuntimeError('WorkCalendar management requires runtime admission')
 core=names-extra
 if len(names)!=len(rows) or core not in (BASE_CONTAINER_NAMES,BASE_CONTAINER_NAMES|{'/enterprise-node-exporter'}):raise RuntimeError('Runtime differs from reviewed core plus finite application membership')
 if '/enterprise-node-exporter' not in names:return
 node=next(r for r in rows if r['Name']=='/enterprise-node-exporter');labels=node['Config'].get('Labels') or {}
 if labels.get('com.docker.compose.project')!='platform_infra_vps' or labels.get('com.docker.compose.service')!='node-exporter':raise RuntimeError('Unexpected metrics service identity')
 mounts=node['Mounts'];binds=[m for m in mounts if m['Type']=='bind']
 if len(binds)!=4 or {m['Source']:m['Destination'] for m in binds}!=NODE_EXPORTER_BINDS or any(m.get('RW') is not False for m in binds) or any(m['Type'] not in ('bind','tmpfs') for m in mounts):raise RuntimeError('Metrics mounts differ from reviewed regenerable scope')

def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(p):
 h=hashlib.sha256()
 with pathlib.Path(p).open('rb') as f:
  for data in iter(lambda:f.read(1024*1024),b''):h.update(data)
 return h.hexdigest()
def private(p,directory=False):
 p=pathlib.Path(p);s=p.lstat()
 if p.is_symlink() or s.st_uid!=0 or s.st_mode&0o077 or (not stat.S_ISDIR(s.st_mode) if directory else not stat.S_ISREG(s.st_mode)):raise RuntimeError('Private backup input is not root protected')
 return p

def fsync_directory(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def durable_rename(source,destination):
 source=pathlib.Path(source);destination=pathlib.Path(destination)
 os.rename(source,destination);fsync_directory(destination.parent)
 if source.parent!=destination.parent:fsync_directory(source.parent)

def save(p,v):
 p=pathlib.Path(p);tmp=p.with_name('.'+p.name+'-'+uuid.uuid4().hex)
 fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(canonical(v)+b'\n');f.flush();os.fsync(f.fileno())
 os.replace(tmp,p);fsync_directory(p.parent)

def run(args,timeout=300,output=None):
 # Command output may contain secrets. Never include stdout/stderr in exceptions.
 r=subprocess.run(args,stdout=output or subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 if r.returncode:raise RuntimeError('Native command failed: '+pathlib.Path(args[0]).name+' exit '+str(r.returncode))
 return r.stdout

def settle_restore_journal(file=None):
 if file is None:
  for name in ('production-restore.json','application-restore.json','workcalendar-application-restore.json'):settle_restore_journal(WORK/name)
  return
 file=pathlib.Path(file) if file is not None else WORK/'production-restore.json'
 if not file.exists() and not file.is_symlink():return
 private(file);journal=json.loads(file.read_text())
 if journal.get('status') not in ('done','rolled-back') or journal.get('runtimeHealthVerified') is not True:raise RuntimeError('Incomplete production restore requires native reconciliation before backup or queue work')
 operation=journal.get('operation','')
 if not re.fullmatch('[a-z0-9][a-z0-9-]{15,127}',operation):raise RuntimeError('Invalid terminal restore journal')
 history=file.parent/'restore-journals';history.mkdir(mode=0o700,exist_ok=True);private(history,True)
 suffix='-application' if journal.get('scope')=={'kind':'application','id':SCRIPTA_PROJECT} else ''
 target=history/(operation+suffix+'.json')
 if target.exists() or target.is_symlink():raise RuntimeError('Terminal restore journal already archived; reconcile duplicate')
 durable_rename(file,target) # Keep original rollback paths and root replay ledger intact.

def capture_file_metadata(container,source):
 raw=run(['docker','exec',container,'stat','-Lc','%u:%g:%a:%f',source]).decode().strip().split(':')
 if len(raw)!=4 or not all(v.isdigit() for v in raw[:3]) or not re.fullmatch('[a-fA-F0-9]+',raw[3]) or not stat.S_ISREG(int(raw[3],16)):raise RuntimeError('Expected regular native database configuration file')
 mode=int(raw[2],8)
 if mode&~0o777:raise RuntimeError('Unexpected database configuration mode')
 return {'uid':int(raw[0]),'gid':int(raw[1]),'mode':mode}

def inspect(enrolled=None):
 active=run(['docker','ps','-q','--no-trunc']).decode().split()
 if enrolled is not None:
  ids=[v.get('id','') for v in enrolled]
  if not ids or len(ids)>64 or len(ids)!=len(set(ids)) or any(not re.fullmatch(r'[a-f0-9]{64}',v) for v in ids):raise RuntimeError('Invalid enrolled container identities')
  if set(active)-set(ids):raise RuntimeError('Unexpected running container blocks capture')
 else:ids=active
 if not ids:raise RuntimeError('No enrolled containers')
 rows=json.loads(run(['docker','inspect',*ids]))
 if len(rows)!=len(ids) or {r['Id'] for r in rows}!=set(ids):raise RuntimeError('Missing enrolled container')
 if any((r['Config'].get('Labels') or {}).get('com.docker.compose.project') not in ALLOW_PROJECTS for r in rows):raise RuntimeError('Unclassified container blocks capture')
 return sorted(rows,key=lambda r:r['Name'])


def pins(rows):return [{'name':r['Name'],'id':r['Id'],'image':r['Image'],'mounts':r['Mounts']} for r in rows]
def validate_admission_chain(p):
 generation=p.get('generation');previous=p.get('previousAdmissionSha256')
 if type(generation) is not int or not 1<=generation<=1024:raise RuntimeError('Invalid admission generation')
 seen=set()
 while generation>1:
  if not isinstance(previous,str)or not re.fullmatch('[a-f0-9]{64}',previous)or previous in seen or previous=='0'*64:raise RuntimeError('Invalid admission predecessor')
  seen.add(previous);directory=CONFIG/'admission-history'/previous
  private(directory,True);prior=private(directory/'profile.json');signature=private(directory/'profile.sig')
  if sha(prior)!=previous:raise RuntimeError('Admission predecessor bytes differ')
  run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(CONFIG/'authority-public.pem'),'-rawin','-in',str(prior),'-sigfile',str(signature)])
  old=json.loads(prior.read_text())
  if old.get('generation')!=generation-1 or old.get('hostname')!=p.get('hostname')or old.get('machineId')!=p.get('machineId'):raise RuntimeError('Admission ancestry identity differs')
  generation=old['generation'];previous=old.get('previousAdmissionSha256')
 if previous!='0'*64:raise RuntimeError('Admission genesis predecessor differs')

def profile():
 private(CONFIG,True);private(PROFILE);private(KEY);private(SIGNING)
 p=json.loads(PROFILE.read_text());rows=inspect(p.get('pins',[]));reviewed_membership(rows,p.get('scriptaRuntime'),p.get('scriptaManagement'),p.get('workcalendarRuntime'),p.get('workcalendarManagement'))
 if p.get('hostname')!=HOST or p.get('machineId')!=sha('/etc/machine-id') or p.get('pins')!=pins(rows):raise RuntimeError('Actual host/container identity differs from enrolled profile')
 validate_admission_chain(p)
 # Fresh authority signature uses OpenSSL Ed25519, as the native admission does.
 run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(CONFIG/'authority-public.pem'),'-rawin','-in',str(PROFILE),'-sigfile',str(CONFIG/'profile.sig')])
 return p,rows

def archive(source,destination,arcname):
 with tarfile.open(destination,'w:',dereference=False) as out:
  def checked(info):
   if not(info.isfile() or info.isdir() or info.issym() or info.islnk()):raise RuntimeError('Unsupported persistent filesystem object')
   return info
  out.add(source,arcname=arcname,filter=checked)

def restore_archive_verify(path):
 # Validate archived member boundaries and read every byte before admission.
 count=0
 with tarfile.open(path,'r:') as t:
  for m in t:
   count+=1;p=pathlib.PurePosixPath(m.name)
   if count>500000 or p.is_absolute() or '..' in p.parts or not(m.isfile() or m.isdir() or m.issym() or m.islnk()):raise RuntimeError('Unsafe persistent archive member')
   if m.isfile():
    with t.extractfile(m) as f:
     read=0
     for b in iter(lambda:f.read(1024*1024),b''):read+=len(b)
     if read!=m.size:raise RuntimeError('Truncated persistent archive')
 return count

def gpg(args):
 home=WORK/'gnupg';home.mkdir(mode=0o700,exist_ok=True)
 run(['gpg','--no-options','--homedir',str(home),'--batch','--yes','--pinentry-mode','loopback','--passphrase-file',str(KEY),*args],timeout=7200)

def artifact_record(path,identity):
 digest=sha(path);signature=base64.urlsafe_b64encode(hmac.new(SIGNING.read_bytes(),('platform-postgres-backup-v1\n'+path.name+'\n'+digest+'\n').encode(),hashlib.sha256).digest()).decode().rstrip('=')
 save(path.with_name(path.name+'.sig.json'),{'version':1,'algorithm':'HMAC-SHA256','keyId':'vps-genesis-1','artifact':path.name,'sha256':digest,'signature':signature,'signedAt':now()})
 path.with_name(path.name+'.sha256').write_text(digest+'  '+path.name+'\n')
 return {'id':'artifact-'+identity,'resourceId':'platform-state:'+identity,'path':'artifacts/'+path.name,'sha256':sha(path),'sizeBytes':path.stat().st_size,'signatureKeyId':'vps-genesis-1'}

def database_container(rows,volume):
 matches=[r['Name'].lstrip('/') for r in rows if any(m['Type']=='volume' and m.get('Name')==volume for m in r['Mounts'])]
 if len(matches)!=1:raise RuntimeError('Database volume must have one enrolled owner')
 return matches[0]

def wait_scripta_sql():
 # Drain every client of the dedicated database, including the admitted admin
 # and idle-in-transaction work, before fencing the matching Redis state.
 deadline=time.monotonic()+5;attempts=0
 while time.monotonic()<deadline:
  attempts+=1
  try:
   active=run(['docker','exec','scripta-postgres','psql','-U','postgres','-Atc',"SELECT count(*) FROM pg_stat_activity WHERE datname='students_beta_app' AND pid<>pg_backend_pid() AND backend_type='client backend' AND (state IS DISTINCT FROM 'idle' OR xact_start IS NOT NULL)"],timeout=min(1,deadline-time.monotonic())).decode('ascii').strip()
  except (subprocess.TimeoutExpired,OSError,UnicodeError):raise RuntimeError('Application SQL quiescence could not be verified') from None
  if not re.fullmatch('0|[1-9][0-9]*',active):raise RuntimeError('Application SQL quiescence returned an invalid count')
  if active=='0':return attempts
  time.sleep(min(.1,max(0,deadline-time.monotonic())))
 raise RuntimeError('Application SQL did not quiesce within the bounded pause')

def scripta_redis_durability(ident,operation):
 if not re.fullmatch('[a-f0-9]{64}',ident) or not re.fullmatch('vps-[0-9]{8}t[0-9]{6}z-[a-f0-9]{12}',operation):raise RuntimeError('Invalid application durability fence identity')
 # NX prevents touching a colliding key; DEL in the same tiny script leaves no
 # user-visible key, even on command failure. TTL bounds an interrupted SET.
 barrier='platform-backup-barrier:'+operation
 script="if redis.call('SET',KEYS[1],'1','NX','PX',10000) then return redis.call('DEL',KEYS[1]) else return 0 end"
 # redis-cli renders INFO raw even with --json; returning it through EVAL
 # preserves one JSON string and the same authenticated connection.
 info="return redis.call('INFO','persistence')"
 commands=('EVAL '+json.dumps(script)+' 1 '+barrier+'\nWAITAOF 1 0 2000\nEVAL '+json.dumps(info)+' 0\n').encode()
 # One redis-cli process is one authenticated connection: WAITAOF must observe
 # our own preceding write. Never pass a plaintext password through host argv.
 shell='set -eu; set +x; export REDISCLI_AUTH="$(cat /run/secrets/redis-password)"; test -n "$REDISCLI_AUTH"; exec redis-cli --json -2 --show-pushes no --tls --cacert /run/tls/ca.crt -h students-beta-redis --sni students-beta-redis -p 6379'
 try:
  reply=subprocess.run(['docker','exec','-i',ident,'sh','-c',shell],input=commands,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
 except (subprocess.TimeoutExpired,OSError):raise RuntimeError('Application Redis durability fence timed out or was unavailable') from None
 # Raw output can contain Redis errors or credentials. Never propagate it.
 if reply.returncode or len(reply.stdout)>65536:raise RuntimeError('Application Redis durability fence failed')
 try:
  lines=reply.stdout.decode('utf-8').splitlines()
  if len(lines)!=3:raise ValueError()
  deleted,ack,persistence=[json.loads(line) for line in lines]
  if type(deleted) is not int or deleted!=1 or not isinstance(ack,list) or len(ack)!=2 or any(type(x) is not int for x in ack) or ack!=[1,0] or not isinstance(persistence,str):raise ValueError()
  fields={}
  for line in persistence.splitlines():
   if not line or line.startswith('#'):continue
   key,separator,value=line.partition(':')
   if not separator or key in fields:raise ValueError()
   fields[key]=value
  if fields.get('aof_enabled')!='1':raise ValueError()
  receipt={}
  for key in ('aof_buffer_length','aof_pending_bio_fsync'):
   if key in fields:
    if fields[key]!='0':raise ValueError()
    receipt[key]=0
  if 'aof_last_write_status' in fields and fields['aof_last_write_status']!='ok':raise ValueError()
 except (UnicodeError,ValueError,TypeError):raise RuntimeError('Application Redis did not acknowledge a clean local AOF fence') from None
 return {'schema':'scripta-redis-durability/v1','operation':operation,'containerId':ident,'method':'WAITAOF','localAcknowledgements':ack[0],'replicaAcknowledgements':ack[1],'barrierDeleted':True,'persistence':receipt,'verifiedAt':now()}

def prepare_scripta_redis_pause(rows,paused,row,operation,runtime):
 writer=next((r for r in rows if r['Name']=='/node-scriptastudents'),None)
 if not writer or not writer['State'].get('Running') or writer['Id'] not in paused or row['Name']!='/students-beta-redis':raise RuntimeError('Application writer must be paused before its Redis durability fence')
 attempts=wait_scripta_sql()
 receipt=scripta_redis_durability(row['Id'],operation)
 receipt.update(writerContainerId=writer['Id'],sqlQuiescenceAttempts=attempts)
 save(runtime/'scripta-redis-durability.json',receipt)

def wait_workcalendar_sql():
 # Drain every client of the dedicated database, including the admitted admin
 # and idle-in-transaction work, before fencing the matching Redis state.
 deadline=time.monotonic()+5;attempts=0
 while time.monotonic()<deadline:
  attempts+=1
  try:
   active=run(['docker','exec','workcalendar-postgres','psql','-U','postgres','-Atc',"SELECT count(*) FROM pg_stat_activity WHERE datname='workcalendar_app' AND pid<>pg_backend_pid() AND backend_type='client backend' AND (state IS DISTINCT FROM 'idle' OR xact_start IS NOT NULL)"],timeout=min(1,deadline-time.monotonic())).decode('ascii').strip()
  except (subprocess.TimeoutExpired,OSError,UnicodeError):raise RuntimeError('Application SQL quiescence could not be verified') from None
  if not re.fullmatch('0|[1-9][0-9]*',active):raise RuntimeError('Application SQL quiescence returned an invalid count')
  if active=='0':return attempts
  time.sleep(min(.1,max(0,deadline-time.monotonic())))
 raise RuntimeError('Application SQL did not quiesce within the bounded pause')

def workcalendar_redis_durability(ident,operation):
 if not re.fullmatch('[a-f0-9]{64}',ident) or not re.fullmatch('vps-[0-9]{8}t[0-9]{6}z-[a-f0-9]{12}',operation):raise RuntimeError('Invalid application durability fence identity')
 # NX prevents touching a colliding key; DEL in the same tiny script leaves no
 # user-visible key, even on command failure. TTL bounds an interrupted SET.
 barrier='platform-backup-barrier:'+operation
 script="if redis.call('SET',KEYS[1],'1','NX','PX',10000) then return redis.call('DEL',KEYS[1]) else return 0 end"
 # redis-cli renders INFO raw even with --json; returning it through EVAL
 # preserves one JSON string and the same authenticated connection.
 info="return redis.call('INFO','persistence')"
 commands=('EVAL '+json.dumps(script)+' 1 '+barrier+'\nWAITAOF 1 0 2000\nEVAL '+json.dumps(info)+' 0\n').encode()
 # One redis-cli process is one authenticated connection: WAITAOF must observe
 # our own preceding write. Never pass a plaintext password through host argv.
 shell='set -eu; set +x; export REDISCLI_AUTH="$(cat /run/secrets/redis-password)"; test -n "$REDISCLI_AUTH"; exec redis-cli --json -2 --show-pushes no --tls --cacert /run/tls/ca.crt -h workcalendar-redis --sni workcalendar-redis -p 6379'
 try:
  reply=subprocess.run(['docker','exec','-i',ident,'sh','-c',shell],input=commands,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
 except (subprocess.TimeoutExpired,OSError):raise RuntimeError('Application Redis durability fence timed out or was unavailable') from None
 # Raw output can contain Redis errors or credentials. Never propagate it.
 if reply.returncode or len(reply.stdout)>65536:raise RuntimeError('Application Redis durability fence failed')
 try:
  lines=reply.stdout.decode('utf-8').splitlines()
  if len(lines)!=3:raise ValueError()
  deleted,ack,persistence=[json.loads(line) for line in lines]
  if type(deleted) is not int or deleted!=1 or not isinstance(ack,list) or len(ack)!=2 or any(type(x) is not int for x in ack) or ack!=[1,0] or not isinstance(persistence,str):raise ValueError()
  fields={}
  for line in persistence.splitlines():
   if not line or line.startswith('#'):continue
   key,separator,value=line.partition(':')
   if not separator or key in fields:raise ValueError()
   fields[key]=value
  if fields.get('aof_enabled')!='1':raise ValueError()
  receipt={}
  for key in ('aof_buffer_length','aof_pending_bio_fsync'):
   if key in fields:
    if fields[key]!='0':raise ValueError()
    receipt[key]=0
  if 'aof_last_write_status' in fields and fields['aof_last_write_status']!='ok':raise ValueError()
 except (UnicodeError,ValueError,TypeError):raise RuntimeError('Application Redis did not acknowledge a clean local AOF fence') from None
 return {'schema':'workcalendar-redis-durability/v1','operation':operation,'containerId':ident,'method':'WAITAOF','localAcknowledgements':ack[0],'replicaAcknowledgements':ack[1],'barrierDeleted':True,'persistence':receipt,'verifiedAt':now()}

def prepare_workcalendar_redis_pause(rows,paused,row,operation,runtime):
 writer=next((r for r in rows if r['Name']=='/node-workcalendar'),None)
 if not writer or not writer['State'].get('Running') or writer['Id'] not in paused or row['Name']!='/workcalendar-redis':raise RuntimeError('Application writer must be paused before its Redis durability fence')
 attempts=wait_workcalendar_sql()
 receipt=workcalendar_redis_durability(row['Id'],operation)
 receipt.update(writerContainerId=writer['Id'],sqlQuiescenceAttempts=attempts)
 save(runtime/'workcalendar-redis-durability.json',receipt)


def capture():
 settle_restore_journal()
 if (WORK/'paused.json').exists():raise RuntimeError('Prior pause journal must be reconciled before a new capture')
 p,rows=profile()
 pg=database_container(rows,'enterprise_postgres_data');maria=database_container(rows,'enterprise_mariadb_data')
 # Fail before exporting secrets or pausing writers when a running image was removed.
 for image in sorted({r['Image'] for r in rows}):run(['docker','image','inspect',image])
 if p.get('captureAuthorized') is not True:raise RuntimeError('Local capture is not authorized in enrolled profile')
 stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ').lower();job='vps-'+stamp+'-'+uuid.uuid4().hex[:12]
 tmp=pathlib.Path(tempfile.mkdtemp(prefix='capture-',dir=WORK));art=tmp/'artifacts';art.mkdir(mode=0o700)
 paused=[];records=[];resources=[]
 def add(file,identity):
  records.append(artifact_record(file,identity));resources.append({'id':'platform-state:'+identity,'externalId':identity,'kind':'platform-state','projectId':'platform','name':identity})
 volumes={m['Name']:m['Source'] for r in rows for m in r['Mounts'] if m['Type']=='volume'}
 if len(volumes)!=p['volumeCount']:raise RuntimeError('Persistent volume count changed')
 if shutil.disk_usage(WORK).free<20*1024**3:raise RuntimeError('Insufficient protected capture reserve')
 try:
  # Profile contains explicit bounded roots; never infer personal/home paths.
  for root in p['captureRoots']:
   if any(root==x or root.startswith(x+'/') for x in ('/proc','/sys','/dev','/run','/var/run','/var/lib/platform-host-metrics')):raise RuntimeError('Kernel/runtime metadata cannot be a persistent capture root')
   if not pathlib.Path(root).exists():raise RuntimeError('Required enrolled recovery root missing')
  runtime=tmp/'runtime';runtime.mkdir(mode=0o700)
  save(runtime/'containers.json',rows) # Encrypted only: includes runtime secret values.
  save(runtime/'profile.json',p)
  run(['docker','volume','inspect',*sorted(volumes)],output=(runtime/'volumes.json').open('wb'))
  run(['dpkg-query','-W','-f=${binary:Package}\t${Version}\n'],output=(runtime/'packages.tsv').open('wb'))
  # Logical exports supplement crash-consistent volume recovery.
  run(['docker','exec',pg,'pg_dumpall','-U','postgres'],timeout=900,output=(runtime/'postgres-all.sql').open('wb'))
  run(['docker','exec',maria,'sh','-c','MYSQL_PWD="$(cat /run/secrets/mariadb_root_password)" exec mariadb-dump -uroot --all-databases --single-transaction --routines --events --triggers'],timeout=900,output=(runtime/'mariadb-all.sql').open('wb'))
  for file,marker in [(runtime/'postgres-all.sql',b'PostgreSQL database cluster dump complete'),(runtime/'mariadb-all.sql',b'Dump completed')]:
   with file.open('rb') as stream:
    stream.seek(max(0,file.stat().st_size-8192));tail=stream.read()
   if marker not in tail:raise RuntimeError('Native online database export lacks completion trailer')
  recovery_spec=importlib.util.spec_from_file_location('vps_recovery',HERE/'production-restore.py');recovery=importlib.util.module_from_spec(recovery_spec);recovery_spec.loader.exec_module(recovery)
  save(runtime/'database-semantics.json',recovery.semantic_inventory(pg,maria))
  # Preserve live DB configuration/TLS as well as logical contents. Values stay encrypted.
  pgpaths={};file_metadata={'postgres':{},'mariadb':{}}
  for setting,name in [('hba_file','pg_hba.conf'),('ident_file','pg_ident.conf'),('config_file','postgresql.conf'),('data_directory','postgresql.auto.conf')]:
   source=run(['docker','exec',pg,'psql','-U','postgres','-Atc','SHOW '+setting]).decode().strip()
   if not source.startswith('/') or '\n' in source or '..' in pathlib.PurePosixPath(source).parts:raise RuntimeError('Unexpected live PostgreSQL config path')
   if setting=='data_directory':source+='/postgresql.auto.conf'
   pgpaths[name]=source;file_metadata['postgres'][name]=capture_file_metadata(pg,source)
   run(['docker','cp',pg+':'+source,str(runtime/name)])
  save(runtime/'postgres-live-config-paths.json',pgpaths)
  tls=run(['docker','exec',maria,'sh','-c',"MYSQL_PWD=\"$(cat /run/secrets/mariadb_root_password)\" exec mariadb -uroot -N -B -e \"SHOW VARIABLES WHERE Variable_name IN ('ssl_ca','ssl_cert','ssl_key')\""]).decode().splitlines()
  tls_paths={}
  for line in tls:
   variable,source=line.split('\t',1)
   if not source:continue
   if variable not in ('ssl_ca','ssl_cert','ssl_key') or not source.startswith(('/var/lib/mysql/','/etc/','/run/')) or '..' in pathlib.PurePosixPath(source).parts:raise RuntimeError('Unexpected live MariaDB TLS path')
   file_metadata['mariadb'][variable]=capture_file_metadata(maria,source)
   run(['docker','cp',maria+':'+source,str(runtime/('mariadb-'+variable))]);tls_paths[variable]=source
  save(runtime/'mariadb-live-tls-paths.json',tls_paths)
  save(runtime/'database-file-metadata.json',file_metadata)
  if p.get('pauseAuthorized') is not True:raise RuntimeError('Consistent filesystem capture requires explicit infrastructure pause authorization')
  pause_names={'gf-rustfs','enterprise-nats','enterprise-redis','enterprise-grafana','enterprise-prometheus','enterprise-loki','enterprise-alertmanager'}
  if p.get('scriptaRuntime'):pause_names.update({'node-scriptastudents','students-beta-redis'})
  if p.get('scriptaManagement'):pause_names.add('phppgadmin')
  if p.get('workcalendarRuntime'):pause_names.update({'node-workcalendar','workcalendar-redis'})
  # Journal lets ExecStopPost recover only containers paused by this operation.
  save(WORK/'paused.json',{'containers':[],'operation':job})
  try:
   def expired(*_):raise TimeoutError('Non-database writer snapshot exceeded 30 seconds')
   signal.signal(signal.SIGALRM,expired);signal.alarm(30)
   for r in rows:
    if r['Name'].lstrip('/') not in pause_names or not r['State'].get('Running'):continue
    if r['State'].get('Paused'):raise RuntimeError('Container already paused by another operation')
    if p.get('scriptaRuntime') and r['Name']=='/students-beta-redis':prepare_scripta_redis_pause(rows,paused,r,job,runtime)
    if p.get('workcalendarRuntime') and r['Name']=='/workcalendar-redis':prepare_workcalendar_redis_pause(rows,paused,r,job,runtime)
    paused.append(r['Id']);save(WORK/'paused.json',{'containers':paused,'operation':job})
    run(['docker','pause',r['Id']],timeout=30)
   run(['sync'])
   if p.get('scriptaRuntime'):
    app_pg='scripta-postgres'
    # App and admitted admin writers are paused. Drain all database clients
    # before comparing the dump with live count/ownership semantics.
    wait_scripta_sql()
    run(['docker','exec',app_pg,'pg_dumpall','-U','postgres'],timeout=25,output=(runtime/'scripta-postgres-all.sql').open('wb'))
    with (runtime/'scripta-postgres-all.sql').open('rb') as stream:
     stream.seek(max(0,(runtime/'scripta-postgres-all.sql').stat().st_size-8192))
     if b'PostgreSQL database cluster dump complete' not in stream.read():raise RuntimeError('Application PostgreSQL export lacks completion trailer')
    save(runtime/'scripta-database-semantics.json',recovery.postgres_semantic_inventory(app_pg))
    app_paths={};app_metadata={}
    for setting,name in [('hba_file','pg_hba.conf'),('ident_file','pg_ident.conf'),('config_file','postgresql.conf'),('data_directory','postgresql.auto.conf')]:
     source=run(['docker','exec',app_pg,'psql','-U','postgres','-Atc','SHOW '+setting]).decode().strip()
     if not source.startswith('/') or '\n' in source or '..' in pathlib.PurePosixPath(source).parts:raise RuntimeError('Unexpected application PostgreSQL config path')
     if setting=='data_directory':source+='/postgresql.auto.conf'
     app_paths[name]=source;app_metadata[name]=capture_file_metadata(app_pg,source)
     run(['docker','cp',app_pg+':'+source,str(runtime/('scripta-'+name))])
    save(runtime/'scripta-postgres-live-config-paths.json',app_paths);save(runtime/'scripta-postgres-file-metadata.json',app_metadata)
   if p.get('workcalendarRuntime'):
    app_pg='workcalendar-postgres'
    # App and admitted admin writers are paused. Drain all database clients
    # before comparing the dump with live count/ownership semantics.
    wait_workcalendar_sql()
    run(['docker','exec',app_pg,'pg_dumpall','-U','postgres'],timeout=25,output=(runtime/'workcalendar-postgres-all.sql').open('wb'))
    with (runtime/'workcalendar-postgres-all.sql').open('rb') as stream:
     stream.seek(max(0,(runtime/'workcalendar-postgres-all.sql').stat().st_size-8192))
     if b'PostgreSQL database cluster dump complete' not in stream.read():raise RuntimeError('Application PostgreSQL export lacks completion trailer')
    save(runtime/'workcalendar-database-semantics.json',recovery.postgres_semantic_inventory(app_pg))
    app_paths={};app_metadata={}
    for setting,name in [('hba_file','pg_hba.conf'),('ident_file','pg_ident.conf'),('config_file','postgresql.conf'),('data_directory','postgresql.auto.conf')]:
     source=run(['docker','exec',app_pg,'psql','-U','postgres','-Atc','SHOW '+setting]).decode().strip()
     if not source.startswith('/') or '\n' in source or '..' in pathlib.PurePosixPath(source).parts:raise RuntimeError('Unexpected application PostgreSQL config path')
     if setting=='data_directory':source+='/postgresql.auto.conf'
     app_paths[name]=source;app_metadata[name]=capture_file_metadata(app_pg,source)
     run(['docker','cp',app_pg+':'+source,str(runtime/('workcalendar-'+name))])
    save(runtime/'workcalendar-postgres-live-config-paths.json',app_paths);save(runtime/'workcalendar-postgres-file-metadata.json',app_metadata)
   for name,source in sorted(volumes.items()):
    if not re.fullmatch('[a-zA-Z0-9_-]+',name) or not source.startswith('/var/lib/docker/volumes/') or not source.endswith('/_data'):raise RuntimeError('Unexpected persistent volume boundary')
    target=art/(name+'.tar')
    if name in ('enterprise_postgres_data','enterprise_mariadb_data'):
     logical=runtime/('postgres-all.sql' if name=='enterprise_postgres_data' else 'mariadb-all.sql')
     with tarfile.open(target,'w:') as t:t.add(logical,arcname='logical/'+logical.name)
    else:archive(source,target,'data')
    add(target,'volume-'+name.replace('_','-'))
   if p.get('scriptaRuntime'):
    # The Redis/legacy bind snapshot is captured while its actual writers pause.
    target=art/'scriptastudents-persistent.tar'
    with tarfile.open(target,'w:',dereference=False) as t:
     def checked_app(info):
      if not(info.isfile() or info.isdir() or info.issym() or info.islnk()):raise RuntimeError('Unsupported application state object')
      return info
     for source in p['scriptaRuntime']['persistentRoots']:
      if pathlib.Path(source).is_symlink() or not pathlib.Path(source).is_dir():raise RuntimeError('Application state root is not a regular directory')
      t.add(source,arcname='host'+source,filter=checked_app)
    add(target,'scriptastudents-persistent')
   if p.get('workcalendarRuntime'):
    # The Redis/legacy bind snapshot is captured while its actual writers pause.
    target=art/'workcalendar-persistent.tar'
    with tarfile.open(target,'w:',dereference=False) as t:
     def checked_app(info):
      if not(info.isfile() or info.isdir() or info.issym() or info.islnk()):raise RuntimeError('Unsupported application state object')
      return info
     for source in p['workcalendarRuntime']['persistentRoots']:
      if pathlib.Path(source).is_symlink() or not pathlib.Path(source).is_dir():raise RuntimeError('Application state root is not a regular directory')
      t.add(source,arcname='host'+source,filter=checked_app)
    add(target,'workcalendar-persistent')
   signal.alarm(0)
   for ident in reversed(paused):run(['docker','unpause',ident],timeout=30)
   paused.clear();(WORK/'paused.json').unlink(missing_ok=True)
   # Native SQLite backup avoids relying on copying an active host database.
   db=pathlib.Path('/var/lib/platform-server-ai-admin/operations.sqlite')
   if db.exists():
    with sqlite3.connect(db.as_uri()+'?mode=ro',uri=True) as src,sqlite3.connect(runtime/'admin-operations.sqlite') as dst:
     src.backup(dst)
     if dst.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise RuntimeError('Admin SQLite snapshot failed')
   target=art/'host-config.tar'
   with tarfile.open(target,'w:',dereference=False) as t:
    def filter_host(info):
     if any('.platform-restore-' in part for part in pathlib.PurePosixPath(info.name).parts):return None
     if info.name.startswith('host/var/lib/platform-server-ai-admin/operations.sqlite'):return None
     if p.get('scriptaRuntime') and any(info.name=='host'+root or info.name.startswith('host'+root+'/') for root in [p['scriptaRuntime']['postgresData'],*p['scriptaRuntime']['persistentRoots']]):return None
     if p.get('workcalendarRuntime') and any(info.name=='host'+root or info.name.startswith('host'+root+'/') for root in [p['workcalendarRuntime']['postgresData'],*p['workcalendarRuntime']['persistentRoots']]):return None
     if not(info.isfile() or info.isdir() or info.issym() or info.islnk()):return None
     return info
    for source in p['captureRoots']:t.add(source,arcname='host/'+source.lstrip('/'),filter=filter_host)
    t.add(runtime,arcname='runtime')
   add(target,'host-config')
  finally:
   signal.alarm(0)
   failures=[]
   for ident in reversed(paused):
    try:run(['docker','unpause',ident],timeout=30)
    except Exception:failures.append(ident)
   if failures:save(WORK/'paused.json',{'containers':failures,'operation':job});raise RuntimeError('Some infrastructure containers still require unpause recovery')
   (WORK/'paused.json').unlink(missing_ok=True)
  # Include actual qualified image content, not merely mutable tag names.
  images=sorted({r['Image'] for r in rows})
  target=art/'images.tar';run(['docker','image','save','-o',str(target),*images],timeout=3600);add(target,'runtime-images')
  for item in records:restore_archive_verify(tmp/item['path'])
  seed={'jobId':job,'createdAt':now(),'resources':resources,'artifacts':records};save(tmp/'manifest-input.json',seed)
  manifest=tmp/'manifest.json'
  run(['node',str(HERE/'native-manifest.mjs'),'sign',str(tmp/'manifest-input.json'),str(SIGNING),str(manifest)])
  manifest_meta=json.loads(run(['node',str(HERE/'native-manifest.mjs'),'verify',str(manifest),str(SIGNING)]))
  plain=tmp/'complete.tar'
  with tarfile.open(plain,'w:') as t:
   t.add(manifest,arcname='manifest.json');t.add(art,arcname='artifacts')
  dest=WORK/'points'/('backup-'+manifest_meta['manifestId']+'.tar.gpg');dest.parent.mkdir(mode=0o700,exist_ok=True)
  gpg(['--symmetric','--cipher-algo','AES256','--compress-algo','none','--s2k-digest-algo','SHA512','--s2k-count','65011712','--output',str(dest),str(plain)])
  restored=tmp/'roundtrip.tar';gpg(['--decrypt','--output',str(restored),str(dest)])
  if sha(restored)!=sha(plain):raise RuntimeError('Encrypted archive restore differs')
  verify_bundle(restored)
  proof={'status':'passed','host':HOST,'createdAt':now(),**manifest_meta,'scope':{'kind':'platform','id':'platform'},'profileSha256':sha(PROFILE),'bundle':dest.name,'encryptedBytes':dest.stat().st_size,'encryptedSha256':sha(dest),'plaintextSha256':sha(plain),'imageCount':len(images),'containerCount':len(rows),'runningContainerCount':sum(bool(r['State'].get('Running')) for r in rows),'volumeCount':len(volumes),'artifactCount':len(records),'encryptedRoundtripVerified':True,'allArtifactHashesVerified':True,'semanticBootRestoreVerified':False,'offsiteVerified':False,'productionRestorePerformed':False,'databaseRecovery':'native-online-logical-dumps','dbRestartedOrPaused':False}
  (WORK/'manifests').mkdir(mode=0o700,exist_ok=True)
  save(WORK/'manifests'/(manifest_meta['manifestId']+'.json'),json.loads(manifest.read_text()))
  save(dest.with_suffix(dest.suffix+'.local.json'),proof);save(WORK/'latest-local.json',proof);save(WORK/'latest-full-local.json',proof)
  print(json.dumps(proof))
 finally:
  # Plaintext only ever exists in the protected root scratch directory.
  if tmp.parent==WORK and tmp.name.startswith('capture-'):shutil.rmtree(tmp)

def verify_bundle(bundle):
 with tarfile.open(bundle,'r:') as t:
  members=t.getmembers();names=[m.name.rstrip('/') for m in members]
  if len(names)!=len(set(names)) or any(pathlib.PurePosixPath(n).is_absolute() or '..' in pathlib.PurePosixPath(n).parts for n in names):raise RuntimeError('Unsafe outer recovery bundle')
  m=t.extractfile('manifest.json').read();manifest=json.loads(m)
  scratch=pathlib.Path(tempfile.mkdtemp(prefix='verify-',dir=WORK))
  try:
   file=scratch/'manifest.json';file.write_bytes(m)
   run(['node',str(HERE/'native-manifest.mjs'),'verify',str(file),str(SIGNING)])
   wanted={'manifest.json','artifacts'}|{a['path']+suffix for a in manifest['artifacts'] for suffix in ('','.sig.json','.sha256')}
   if set(names)!=wanted:raise RuntimeError('Unmanifested recovery artifact')
   for a in manifest['artifacts']:
    member=t.getmember(a['path'])
    if not member.isfile() or member.size!=a['sizeBytes']:raise RuntimeError('Artifact type or size differs')
    h=hashlib.sha256()
    with t.extractfile(member) as f:
     for data in iter(lambda:f.read(1024*1024),b''):h.update(data)
    if h.hexdigest()!=a['sha256']:raise RuntimeError('Artifact integrity differs')
    side=json.load(t.extractfile(a['path']+'.sig.json'));name=pathlib.PurePosixPath(a['path']).name
    expected=base64.urlsafe_b64encode(hmac.new(SIGNING.read_bytes(),('platform-postgres-backup-v1\n'+name+'\n'+a['sha256']+'\n').encode(),hashlib.sha256).digest()).decode().rstrip('=')
    if side.get('version')!=1 or side.get('algorithm')!='HMAC-SHA256' or side.get('keyId')!='vps-genesis-1' or side.get('artifact')!=name or side.get('sha256')!=a['sha256'] or not hmac.compare_digest(side.get('signature',''),expected):raise RuntimeError('Artifact HMAC differs')
    if t.extractfile(a['path']+'.sha256').read().decode().split()[0]!=a['sha256']:raise RuntimeError('Artifact checksum sidecar differs')
  finally:shutil.rmtree(scratch)

def enrolled_resources(p):
 names=sorted({m['Name'] for r in p['pins'] for m in r['mounts'] if m['Type']=='volume'})
 ids=['volume-'+n.replace('_','-') for n in names]+['host-config','runtime-images']
 if p.get('scriptaRuntime'):ids+=['scriptastudents-persistent']
 if p.get('workcalendarRuntime'):ids+=['workcalendar-persistent']
 return [{'id':'platform-state:'+i,'externalId':i,'kind':'platform-state','projectId':'platform','name':i} for i in ids]

def point_restore_compatible(point,manifest,p,current_digest):
 if not p.get('scriptaManagement') and not p.get('workcalendarManagement'):return True
 if point.get('containerCount')!=len(p['pins'])or point.get('profileSha256')!=current_digest:return False
 if manifest.get('scope',{}).get('kind')=='application':
  is_workcalendar=manifest.get('scope',{}).get('id')==WORKCALENDAR_PROJECT
  mode=(workcalendar_mode if is_workcalendar else scripta_mode)(p,manifest['resources'])
  if point.get('applicationMode',mode)!=mode:return False
  if mode!='source'and point.get('applicationStructureSchema')!=('workcalendar-database-structure/v2' if is_workcalendar else 'scripta-database-structure/v2'):return False
 return True

def publish_catalog(verified_points=None):
 p,_=profile();directory=WORK/'public';directory.mkdir(mode=0o750,exist_ok=True);os.chown(directory,0,1000);os.chmod(directory,0o750)
 current=directory/'catalog.json';retained=[]
 if verified_points is None and current.exists():
  retained=json.loads(current.read_text()).get('points',[])
  # A changed management admission cannot inherit an older UI capability.
  if p.get('scriptaManagement') or p.get('workcalendarManagement'):
   for point in retained:
    point['restoreCompatible']=point_restore_compatible(point,point['manifest'],p,sha(PROFILE))
 elif verified_points is not None:
  for point in verified_points:
   file=WORK/'manifests'/(point['manifestId']+'.json');manifest=json.loads(private(file).read_text())
   checked=json.loads(run(['node',str(HERE/'native-manifest.mjs'),'verify',str(file),str(SIGNING)]))
   if checked['manifestDigest']!=point['manifestDigest']:raise RuntimeError('Public catalog manifest differs from verified receipt')
   compatible=point_restore_compatible(point,manifest,p,sha(PROFILE))
   retained.append({'manifest':manifest,'offsiteVerified':True,'verifiedAt':point['verifiedAt'],'restoreCompatible':compatible,'profileSha256':point.get('profileSha256',''),'containerCount':point.get('containerCount'),**{k:point[k]for k in ('applicationMode','applicationStructureSchema')if k in point}})
 schedule_active=subprocess.run(['systemctl','is-active','--quiet','platform-vps-backup.timer']).returncode==0
 queue_active=subprocess.run(['systemctl','is-active','--quiet','platform-vps-backup-queue.timer']).returncode==0
 body={'productionRestoreEnabled':p.get('productionRestoreAuthorized') is True,'restoreProfileDigest':sha(PROFILE),'scheduleActive':schedule_active,'queueActive':queue_active,'schema':'platform.vps-backup-catalog/v1','host':HOST,'enabled':p.get('captureAuthorized') is True and p.get('offsiteAuthorized') is True,'resources':enrolled_resources(p),'points':retained,'updatedAt':now()}
 if p.get('scriptaManagement'):body['applications']=[{'projectId':SCRIPTA_PROJECT,'resources':scripta_resources(p),'enabled':body['enabled'] and queue_active,'productionRestoreEnabled':body['productionRestoreEnabled']}]
 if p.get('workcalendarManagement'):body.setdefault('applications',[]).append({'projectId':WORKCALENDAR_PROJECT,'resources':workcalendar_resources(p),'enabled':body['enabled'] and queue_active,'productionRestoreEnabled':body['productionRestoreEnabled']})
 save(current,body);os.chown(current,0,1000);os.chmod(current,0o640)
 # No artifact bytes or credentials are exposed through the panel metadata mount.

def recover_unpause():
 f=WORK/'paused.json'
 if not f.exists():return
 private(f);p=json.loads(f.read_text())
 for ident in p['containers']:
  if not re.fullmatch('[a-f0-9]{64}',ident):raise RuntimeError('Malformed recovery journal')
  r=json.loads(run(['docker','inspect',ident]))[0]
  if (r['Config'].get('Labels') or {}).get('com.docker.compose.project') not in ALLOW_PROJECTS:raise RuntimeError('Foreign recovery journal container')
  if r['State'].get('Paused'):run(['docker','unpause',ident],timeout=30)
 f.unlink()

def main():
 if os.geteuid()!=0 or len(sys.argv)!=2:raise RuntimeError('Root and explicit capture/recover-unpause operation required')
 def interrupted(*_):raise RuntimeError('Native capture interrupted; unpause cleanup required')
 signal.signal(signal.SIGTERM,interrupted)
 os.umask(0o077);private(WORK,True)
 with (WORK/'operation.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if sys.argv[1]=='capture':capture()
  elif sys.argv[1]=='recover-unpause':recover_unpause()
  elif sys.argv[1]=='publish-catalog':publish_catalog()
  else:raise RuntimeError('Unsupported VPS backup operation')
if __name__=='__main__':
 try:main()
 except Exception as e:print(json.dumps({'status':'failed','error':str(e)[:250]}));sys.exit(1)
