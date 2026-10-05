#!/usr/bin/env python3
"""Typed infrastructure operations. No shell, project path, SQL or secret API."""
import concurrent.futures,contextlib,datetime,hashlib,hmac,http.server,ipaddress,json,os,pathlib,re,secrets,socket,socketserver,sqlite3,ssl,subprocess,tempfile,threading,time,uuid

STATE=pathlib.Path('/var/lib/platform-server-ai-admin')
SOCKET='/run/platform-server-ai-admin/admin.sock'
TOKEN='/etc/platform-infrastructure/server-ai/infrastructure-token'
ZONE=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/generated/materialized-configs/dns/db.platform-infrastructure.com')
BACKUP=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/local-private-backup')
RUNTIME=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/state')
MACHINE=hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes()).hexdigest()
CORE_CONTAINERS=frozenset('gf-postgres gf-mariadb gf-redis gf-keycloak gf-nats gf-grafana gf-prometheus gf-loki gf-alertmanager gf-node-exporter gf-local-dns gf-traefik gf-waf gf-project-router gf-phpmyadmin gf-phppgadmin gf-rustfs gf-minio-gateway gf-platform-alert-dispatcher gf-promtail gf-searxng gf-server-ai-observer gf-server-ai-project-source-reader gf-server-ai-project-query-reader'.split())
HOSTING=frozenset('enterprise-worker-notifications enterprise-worker-jobs node-account node-ui php-matthewdifilippo php-anniversary php-workcalendar php-fiplatform php-stream students-beta-redis enterprise-web enterprise-backend node-scriptastudents officina-dibella-web carrozzeria-tasso-web scripta-local-doh'.split())
CONTAINERS=CORE_CONTAINERS|HOSTING
INVENTORY=pathlib.Path('/etc/platform-infrastructure/server-ai/infrastructure-inventory.json')
SERVICES=frozenset('chrony.service fail2ban.service cron.service systemd-resolved.service platform-docker-observer-proxy.service'.split())
JOBS={'dns':'platform-dns-probe.service','tls':'platform-db-tls-metrics.service','backup_metrics':'platform-backup-health-metrics.service','backup':'platform-backup-schedule.service','rustfs_recovery':'platform-rustfs-recovery.service','host_recovery':'platform-host-recovery.service','local_recovery':'platform-local-dedup.service'}
PACKAGES=frozenset('openssl ca-certificates curl wget openssh-client openssh-server chrony fail2ban ufw auditd apparmor rsync jq python3 python3-minimal sudo tar gzip coreutils dnsutils iproute2 iptables nftables logrotate'.split())
OPERATIONS=('service_start','service_restart','container_start','container_restart','container_resources','package_refresh','package_upgrade','dns_record_set','dns_record_remove','firewall_ban','firewall_unban','firewall_reapply','database_reload','maintenance_run','log_rotate')
TOPICS=('capabilities','os','packages','services','containers','network','firewall','dns','tls','storage','logs','resources','backups','databases','audit','operation')
PROTECTED_DNS=frozenset('ns portal admin auth login keycloak vpn'.split())
LOCK=threading.Lock()
EXECUTOR=concurrent.futures.ThreadPoolExecutor(max_workers=1)

class Rejected(Exception): pass
def exact(value,keys,required=None):
 if not isinstance(value,dict) or set(value)-set(keys) or set(keys if required is None else required)-set(value):raise Rejected('Invalid fields')
def clean(value):
 if isinstance(value,dict):return {str(k):clean(v) for k,v in list(value.items())[:100] if not re.search(r'password|secret|token|authorization|cookie|private.?key|credential|api.?key|access.?key|dsn',str(k),re.I)}
 if isinstance(value,list):return [clean(v) for v in value[:150]]
 if isinstance(value,str):
  value=re.sub(r'-----BEGIN[^-]*(?:PRIVATE KEY|CERTIFICATE)-----.*?-----END[^-]+-----','[redacted]',value,flags=re.S)
  value=re.sub(r'(?i)(?:bearer\s+|sk-[A-Za-z0-9_-]+)[A-Za-z0-9._-]*','[redacted]',value)
  value=re.sub(r'(?i)(password|secret|token|authorization|cookie|credential)[\s"\x27:=]+[^\s,;}]+',r'\1=[redacted]',value)
  value=re.sub(r'([a-z][a-z0-9+.-]*://)[^/@\s]+:[^/@\s]+@',r'\1[redacted]@',value)
  return value[:16000]
 return value
def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
@contextlib.contextmanager
def db():
 c=sqlite3.connect(STATE/'operations.sqlite',timeout=5);c.execute('pragma busy_timeout=5000')
 try:
  with c:yield c
 finally:c.close()
def initialize():
 STATE.mkdir(mode=0o700,exist_ok=True);os.chmod(STATE,0o700)
 with db() as c:
  c.execute('create table if not exists requests(id text primary key, at real not null)')
  c.execute('create table if not exists jobs(id text primary key, subject text not null, operation text not null, args text not null, status text not null, created real not null, result text)')
  c.execute('create table if not exists audit(id integer primary key, at real not null, subject text not null, action text not null, target text not null, outcome text not null, details text not null)')
def audit(subject,action,target,outcome,details=None):
 with db() as c:c.execute('insert into audit(at,subject,action,target,outcome,details) values(?,?,?,?,?,?)',(time.time(),subject,action,target,outcome,json.dumps(clean(details or {}))))
def command(argv,timeout=20,transaction=False):
 # Constant argv only, assembled from validated enums/numbers/addresses below.
 with tempfile.TemporaryFile() as output:
  try:
   p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,start_new_session=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','DEBIAN_FRONTEND':'noninteractive'})
   try:p.wait(timeout=None if transaction else timeout)
   except subprocess.TimeoutExpired:
    import signal
    os.killpg(p.pid,signal.SIGTERM)
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
    raise Rejected('Operation timed out; inspect its actual state before retrying')
   output.seek(0);raw=output.read(128*1024).decode('utf8','replace')
   if p.returncode:raise Rejected('Command failed: '+clean(raw)[-1600:])
   return raw
  except FileNotFoundError:raise Rejected('Required host utility is unavailable')
def docker(name):
 if name not in CONTAINERS:raise Rejected('Container is outside the infrastructure allowlist')
 value=json.loads(command(['docker','inspect',name]))[0]
 if value['Name']!='/'+name:raise Rejected('Container identity changed')
 info=INVENTORY.stat()
 if info.st_uid!=0 or info.st_mode&0o022 or INVENTORY.is_symlink():raise Rejected('Invalid reviewed inventory ownership')
 pins=json.loads(INVENTORY.read_bytes())
 actual={k:value[k] for k in ['Id','Image','Mounts']};actual['Labels']=value['Config'].get('Labels') or {}
 if pins.get(name)!=actual:raise Rejected('Runtime identity/mounts/labels changed; operator must review inventory again')
 return value
def parse_bytes(value):
 m=re.fullmatch(r'([0-9.]+)\s*(B|KiB|MiB|GiB|TiB|kB|MB|GB)',value)
 if not m:raise Rejected('Cannot verify live memory usage')
 factors={'B':1,'KiB':1024,'MiB':1024**2,'GiB':1024**3,'TiB':1024**4,'kB':1000,'MB':1000**2,'GB':1000**3}
 return float(m[1])*factors[m[2]]
def container_summary(c):
 h=c['HostConfig'];s=c['State']
 return {'name':c['Name'].lstrip('/'),'id':c['Id'],'imageId':c['Image'],'running':s['Running'],'health':s.get('Health',{}).get('Status'),'restarts':c['RestartCount'],'memoryBytes':h['Memory'],'nanoCpus':h['NanoCpus'],'pidsLimit':h.get('PidsLimit'),'readOnlyRoot':h['ReadonlyRootfs'],'publishedPorts':h.get('PortBindings') or {},'capabilitiesDropped':h.get('CapDrop') or []}
def service_status(name):
 return command(['systemctl','show',name,'--no-pager','--property=Id,LoadState,ActiveState,SubState,Result,UnitFileState,MemoryCurrent,CPUUsageNSec,InvocationID,ExecMainStatus,ExecMainStartTimestampMonotonic']).strip()
def capabilities():
 return {'source':'live-host-typed-infrastructure-bridge','machineId':MACHINE,'readTopics':list(TOPICS),'writeOperations':list(OPERATIONS),'containers':sorted(CONTAINERS),'services':sorted(SERVICES),'packages':sorted(PACKAGES),'maintenanceTargets':JOBS,'dnsZone':'platform-infrastructure.com','limits':{'writes':'owner + fresh active session + explicit trusted user turn','projectCodeAndData':'no source/data read/write API; reviewed hosting containers allow lifecycle and resource budgets only','database':'engine health/resources/lifecycle and PostgreSQL configuration reload only; no SQL or database content','firewall':'existing reviewed policy reapply and public-IP fail2ban sshd bans only','tls':'verified local certificate inspection and existing TLS metrics; no disabling TLS or exposing private keys','resources':'runtime limits persisted in bridge audit/desired limits; not an application compose/source edit','unsupported':'arbitrary shell/files/SQL, project edits, image/volume/database deletion, restore over live data, arbitrary network/routing changes, new package repositories, trust-key changes; require separate operator workflow'}}
def portal_tls_context():
    # Explicit dedicated trust store: never add ambient system roots here.
    ca=pathlib.Path('/etc/platform-infrastructure/tls/portal-new-root.pem')
    info=ca.lstat()
    if ca.is_symlink() or not ca.is_file() or info.st_uid!=0 or info.st_mode & 0o022:
        raise ValueError('Invalid dedicated Portal CA ownership or permissions')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(ca))
    context.verify_mode=ssl.CERT_REQUIRED
    context.check_hostname=True
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    return context

def read(topic,target,subject):
 if topic not in TOPICS:raise Rejected('Unknown read topic')
 if not isinstance(target,str) or len(target)>160 or any(c in target for c in '\r\n\0/\\'):raise Rejected('Invalid target')
 if topic=='capabilities':return capabilities()
 if topic=='os':return {'kernel':os.uname().release,'uptimeSeconds':float(pathlib.Path('/proc/uptime').read_text().split()[0]),'load':list(os.getloadavg()),'memory':{k:int(v.split()[0])*1024 for k,v in (line.split(':',1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines()) if k in ['MemTotal','MemAvailable','SwapTotal','SwapFree']},'release':{k:v.strip('"') for k,v in (line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line) if k in ['NAME','VERSION','VERSION_ID']}}
 if topic=='packages':
  if target and target not in PACKAGES:raise Rejected('Package outside managed upgrade allowlist')
  return {'installed':'\n'.join(line for line in command(['dpkg-query','-W','-f=${binary:Package}\t${Version}\n']).splitlines() if line.split('\t')[0].split(':')[0] in ([target] if target else PACKAGES)),'upgradePolicy':'installed packages only; signed configured distro repositories; no removal'}
 if topic=='services':
  if target and target not in SERVICES and target not in JOBS.values() and target!='platform-server-ai-egress.service':raise Rejected('Service outside reviewed infrastructure inventory')
  return {'services':{n:service_status(n) for n in ([target] if target else sorted(SERVICES))}}
 if topic in ['containers','databases']:
  names=[target] if target else (['gf-postgres','gf-mariadb','gf-redis'] if topic=='databases' else sorted(CONTAINERS));result=[]
  for name in names:
   try:result.append(container_summary(docker(name)))
   except Rejected as e:result.append({'name':name,'available':False,'reason':str(e)})
  return {'containers':result,'databaseContentsRead':False}
 if topic=='network':return {'addresses':json.loads(command(['ip','-j','address'])), 'routes':json.loads(command(['ip','-j','route'])),'listeners':command(['ss','-lntup'])}
 if topic=='firewall':return {'iptables':command(['iptables-save']),'fail2banSshd':command(['fail2ban-client','status','sshd'])}
 if topic=='dns':return {'zone':'platform-infrastructure.com','records':safe_zone().decode(),'resolver':pathlib.Path('/etc/resolv.conf').read_text()}
 if topic=='tls':
  host=target or 'portal.platform-infrastructure.com'
  if not re.fullmatch(r'[a-z0-9-]+\.platform-infrastructure\.com',host):raise Rejected('TLS target outside configured infrastructure zone')
  context=portal_tls_context()
  try:
   with socket.create_connection(('127.0.0.1',443),timeout=4) as raw:
    with context.wrap_socket(raw,server_hostname=host) as tls:return {'hostname':host,'verified':True,'protocol':tls.version(),'cipher':tls.cipher()[0],'certificate':tls.getpeercert()}
  except ssl.SSLCertVerificationError as error:return {'hostname':host,'verified':False,'error':'CERTIFICATE_VALIDATION_FAILED','verificationError':str(error),'trustStore':'dedicated Portal root'}
 if topic=='storage':return {'filesystems':command(['df','-PT','-B1']),'inodes':command(['df','-Pi']),'blockDevices':json.loads(command(['lsblk','-J','-o','NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS']))}
 if topic=='logs':
  if target not in SERVICES and target not in JOBS.values() and target not in ['platform-server-ai-egress.service','platform-server-ai-admin.service']:raise Rejected('Logs require one reviewed infrastructure unit')
  raw=command(['journalctl','--unit='+target,'--since=-30min','--lines=80','--no-pager','--output=short-iso'],timeout=5)
  return {'unit':target,'redactedJournal':'\n'.join('[sensitive log line redacted]' if re.search(r'password|secret|token|authorization|cookie|credential|private.?key|sk-',line,re.I) else clean(line) for line in raw.splitlines())}
 if topic=='resources':
  return {'cpuCounters':pathlib.Path('/proc/stat').read_text()[:12000],'diskCounters':pathlib.Path('/proc/diskstats').read_text()[:12000],'pressure':{n:(pathlib.Path('/proc/pressure')/n).read_text() for n in ['cpu','io','memory']},'inodes':command(['df','-Pi'])}
 if topic=='backups':
  result={}
  for name,p in [('rustfs',RUNTIME/'rustfs-recovery/latest.json'),('host',RUNTIME/'host-recovery/host-recovery-proof.json'),('ftps',RUNTIME/'host-recovery/ftps-proof.json'),('ftpsAttempt',RUNTIME/'host-recovery/ftps-last-attempt.json'),('ftpsRetention',RUNTIME/'host-recovery/ftps-retention-proof.json'),('localRecovery',RUNTIME/'host-recovery/local-dedup-proof.json')]:
   if p.is_file() and not p.is_symlink() and p.stat().st_size<128*1024:
    try:result[name]=project_proof(json.loads(p.read_bytes()))
    except (ValueError,OSError):result[name]={'available':False}
  return {'proofs':result,'schedule':command(['systemctl','list-timers','--all','--no-pager','platform-backup-schedule.timer']),'restoreOverLiveDataAllowed':False}
 if topic=='audit':
  with db() as c:rows=c.execute('select at,subject,action,target,outcome,details from audit order by id desc limit 30').fetchall()
  return {'events':[dict(zip(['at','subject','action','target','outcome','details'],r)) for r in rows]}
 if topic=='operation':
  try:uuid.UUID(target)
  except ValueError:raise Rejected('Invalid operation ID')
  with db() as c:row=c.execute('select id,subject,operation,status,created,result from jobs where id=? and subject=?',(target,subject)).fetchone()
  if not row:raise Rejected('Operation not available to this owner')
  result=dict(zip(['id','subject','operation','status','created','result'],row))
  if result['result']:result['result']=json.loads(result['result'])
  if result['status']=='submitted':
   saved=result['result'];observed=dict(line.split('=',1) for line in service_status(saved['service']).splitlines() if '=' in line)
   same=(observed.get('InvocationID')==saved.get('invocationId') and bool(saved.get('invocationId'))) or (observed.get('ExecMainStartTimestampMonotonic')==saved.get('startMonotonic') and saved.get('startMonotonic') not in [None,'','0'])
   result['externalService']=observed
   if same and observed.get('ActiveState') not in ['activating','deactivating','active']:
    result['status']='completed' if observed.get('Result')=='success' and observed.get('ExecMainStatus')=='0' else 'failed'
    result['completionMeaning']='This exact systemd invocation ended; backup or restore success additionally requires its saved proof.'
    with db() as c:c.execute('update jobs set status=?,result=? where id=?',(result['status'],json.dumps({**saved,'finalService':observed}),target))
   elif not same:result['correlation']='Invocation not yet observed or replaced; no success claim'
  return result
 raise Rejected('Unsupported topic')
def project_proof(value):
 # Proofs can include private paths and configuration; return status evidence only.
 if not isinstance(value,dict):return {'available':False}
 fields=('schema','status','backend','format','signedBrokerCompatible','restoreRoute','createdAt','completedAt','capturedAt','startedAt','finishedAt','timestamp','sha256','archiveSha256','encryptedSha256','treeSha256','bytes','archiveBytes','entryCount','entries','bucketCount','objectCount','versionCount','deleteMarkerCount','restoreVerified','verified','success','quiesceSeconds','retainedPoints','usedBytes','quotaBytes')
 result={k:v for k,v in value.items() if k in fields and isinstance(v,(str,int,float,bool,type(None)))}
 for k in ('restore','verification','inventory','checks','retention'):
  if isinstance(value.get(k),dict):result[k]=project_proof(value[k])
 return result
def replace_zone(data):
 fd,name=tempfile.mkstemp(prefix='.server-ai-zone-',dir=ZONE.parent)
 try:
  with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno());os.fchmod(out.fileno(),0o644)
  os.replace(name,ZONE)
 finally:
  try:os.unlink(name)
  except FileNotFoundError:pass
def safe_zone():
 if ZONE.resolve()!=ZONE or not ZONE.is_file() or ZONE.stat().st_size>65536:raise Rejected('DNS zone identity rejected')
 data=ZONE.read_bytes()
 if b'$ORIGIN platform-infrastructure.com.' not in data:raise Rejected('DNS zone boundary mismatch')
 return data
def validate_change(op,args):
 if op not in OPERATIONS:raise Rejected('Unsupported infrastructure operation; no shell/project/SQL fallback')
 exact(args,['target','memoryMiB','cpus','pids','address'],['target']);target=args['target']
 if not isinstance(target,str) or len(target)>160 or not target or any(c in target for c in '\r\n\0/\\'):raise Rejected('Invalid infrastructure target')
 allowed={'target'}
 if op=='container_resources':
  allowed|={'memoryMiB','cpus','pids'}
  if len(args)<2:raise Rejected('No resource limit supplied')
  total=int(next(x.split()[1] for x in pathlib.Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemTotal:')))//1024
  for k,low,high in [('memoryMiB',256,min(32768,total//2)),('cpus',0.25,min(8,os.cpu_count() or 1)),('pids',64,2048)]:
   if k in args and (isinstance(args[k],bool) or not isinstance(args[k],(int,float)) or not low<=args[k]<=high or k!='cpus' and not isinstance(args[k],int)):raise Rejected('Resource limit outside safe host bounds')
 if op=='dns_record_set':allowed.add('address')
 if set(args)-allowed:raise Rejected('Fields do not belong to this operation')
 if op.startswith('container_') and target not in CONTAINERS:raise Rejected('Container is outside the reviewed runtime inventory')
 if op.startswith('service_') and target not in SERVICES:raise Rejected('Service outside reviewed infrastructure allowlist')
 if op=='package_upgrade' and target not in PACKAGES:raise Rejected('Package outside managed installed-package allowlist')
 if op=='package_refresh' and target!='apt':raise Rejected('Only configured signed APT repositories are supported')
 if op.startswith('dns_record_'):
  label=target.removesuffix('.platform-infrastructure.com')
  if not re.fullmatch(r'[a-z][a-z0-9-]{0,50}',label) or label in PROTECTED_DNS:raise Rejected('DNS record is not an editable managed infrastructure alias')
  if target!=label+'.platform-infrastructure.com':raise Rejected('DNS target outside fixed zone')
  if op=='dns_record_set':
   try:ip=ipaddress.IPv4Address(args.get('address',''))
   except ValueError:raise Rejected('Invalid A record address')
   if not any(ip in ipaddress.IPv4Network(n) for n in ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']):raise Rejected('Managed DNS records require a private unicast address')
 if op in ['firewall_ban','firewall_unban']:
  try:ip=ipaddress.IPv4Address(target)
  except ValueError:raise Rejected('Invalid firewall address')
  if not ip.is_global or ip.is_multicast:raise Rejected('Management/private networks cannot be banned by this tool')
 if op=='firewall_reapply' and target!='server-ai-egress':raise Rejected('Only the reviewed egress policy may be reapplied')
 if op=='database_reload' and target!='gf-postgres':raise Rejected('Only PostgreSQL existing configuration reload is supported; no arbitrary SQL/config write')
 if op=='maintenance_run' and target not in JOBS:raise Rejected('Unknown reviewed maintenance job')
 if op=='log_rotate' and target!='system':raise Rejected('Only normal configured log rotation is supported')
 return args
def mutate(op,args):
 target=args['target']
 if (BACKUP/'broker-state/active-operation.json').exists() and not (op=='maintenance_run' and target in ['dns','tls','backup_metrics']):raise Rejected('A backup operation is active; defer infrastructure changes')
 if op.startswith('container_'):
  inspected=docker(target);before=container_summary(inspected)
  if op=='container_resources':
   argv=['docker','update']
   for key,flag in [('memoryMiB','--memory'),('cpus','--cpus'),('pids','--pids-limit')]:
    if key in args:argv += [flag,str(args[key])+('m' if key=='memoryMiB' else '')]
   if 'memoryMiB' in args:
    memory=args['memoryMiB']*1024*1024
    stats=json.loads(command(['docker','stats','--no-stream','--format','{{json .}}',target],timeout=15))
    usage=parse_bytes(stats['MemUsage'].split('/')[0].strip())
    if memory < usage*1.25+64*1024*1024:raise Rejected('Memory limit needs observed usage plus 25 percent and 64 MiB headroom')
    old=inspected['HostConfig'];swap=old.get('MemorySwap',0)
    # Keep unlimited/default semantics and existing positive swap headroom.
    next_swap=swap if swap<=0 else memory+max(0,swap-old.get('Memory',0))
    argv += ['--memory-swap',str(next_swap)]
   command(argv+[inspected['Id']])
   desired=STATE/'desired-resource-limits.json';values=json.loads(desired.read_text()) if desired.exists() else {};values[target]={k:v for k,v in args.items() if k!='target'};desired.write_bytes(encode(values));desired.chmod(0o600)
  else:command(['docker',op.split('_')[1],*(['--time','20'] if op.endswith('restart') else []),inspected['Id']],timeout=50)
  return {'completionMeaning':'Command ended; use observed health and logs to determine service health','before':before,'after':container_summary(docker(target)),'persistence':'runtime Docker settings; desired limits recorded for reviewed recovery, project compose files not changed'}
 if op.startswith('service_'):command(['systemctl',op.split('_')[1],target],timeout=60);return {'service':target,'observed':service_status(target)}
 if op=='package_refresh':return {'diagnostic':clean(command(['apt-get','-o','DPkg::Lock::Timeout=30','-o','Acquire::http::Timeout=30','-o','Acquire::https::Timeout=30','-o','Acquire::Retries=2','update'],transaction=True))}
 if op=='package_upgrade':
  before=command(['dpkg-query','-W','-f=${Status} ${Version}',target])
  if not before.startswith('install ok installed '):raise Rejected('Package must already be installed')
  out=command(['apt-get','-o','DPkg::Lock::Timeout=30','install','--only-upgrade','--no-remove','--assume-yes',target],transaction=True)
  return {'package':target,'before':before,'after':command(['dpkg-query','-W','-f=${Status} ${Version}',target]),'diagnostic':clean(out),'rebootRequired':pathlib.Path('/var/run/reboot-required').exists()}
 if op.startswith('dns_record_'):
  import shutil
  if not shutil.which('dig'):raise Rejected('DNS write requires the installed dig validator')
  dns_identity=docker('gf-local-dns')['Id']
  original=safe_zone();text=original.decode();label=target.split('.')[0];begin='; BEGIN SERVER-AI MANAGED\n';end='; END SERVER-AI MANAGED\n'
  records={}
  if begin in text:
   head,tail=text.split(begin,1);block,rest=tail.split(end,1);text=head+rest
   for line in block.splitlines():
    parts=line.split()
    if len(parts)!=4 or parts[1:3]!=['IN','A']:raise Rejected('Managed DNS block is invalid')
    records[parts[0]]=parts[3]
  # Never shadow an existing record outside the bridge-owned block.
  for line in text.splitlines():
   fields=line.split(';',1)[0].split()
   if fields and fields[0].rstrip('.') in [label,target]:raise Rejected('Existing DNS record requires the separate reviewed operator workflow')
  wildcard=re.search(r'^\*\s+(?:\d+\s+)?IN\s+A\s+(\d+\.\d+\.\d+\.\d+)\s*$',text,re.M|re.I)
  fallback=wildcard[1] if wildcard else ''
  if op=='dns_record_set':records[label]=args['address']
  elif label not in records:raise Rejected('Only a record created by this managed tool may be removed')
  else:del records[label]
  text=re.sub(r'(\d+)(\s*; serial)',lambda m:str(int(m[1])+1)+m[2],text,count=1)
  text+='\n'+begin+''.join(f'{k} IN A {v}\n' for k,v in sorted(records.items()))+end
  snapshot=STATE/('dns-before-'+str(uuid.uuid4())+'.zone');snapshot.write_bytes(original);snapshot.chmod(0o600)
  replace_zone(text.encode())
  try:
   command(['docker','restart','--time','15',dns_identity],timeout=35)
   expected=args.get('address',fallback)
   for attempt in range(8):
    answer=command(['dig','+short','+time=2','+tries=1','@192.168.1.202',target,'A'],timeout=4)
    if (expected and answer.splitlines()==[expected]) or (not expected and not answer.strip()):break
    time.sleep(0.5)
   else:raise Rejected('Changed DNS record did not resolve to its expected address')
  except Exception:
   replace_zone(original);command(['docker','restart','--time','15',dns_identity],timeout=35);raise
  return {'hostname':target,'address':records.get(label),'managedZoneSha256':hashlib.sha256(ZONE.read_bytes()).hexdigest(),'dnsContainer':container_summary(docker('gf-local-dns'))}
 if op in ['firewall_ban','firewall_unban']:return {'result':command(['fail2ban-client','set','sshd','banip' if op.endswith('_ban') else 'unbanip',target]),'observed':command(['fail2ban-client','status','sshd'])}
 if op=='firewall_reapply':command(['systemctl','reload','platform-server-ai-egress.service']);return {'observed':service_status('platform-server-ai-egress.service')}
 if op=='database_reload':identity=docker(target)['Id'];command(['docker','kill','--signal=HUP',identity]);return {'container':container_summary(docker(target)),'configurationSource':'existing mounted configuration; no SQL or project data modified'}
 if op=='maintenance_run':
  unit=JOBS[target]
  if 'ActiveState=activating' in service_status(unit) or 'ActiveState=active' in service_status(unit):raise Rejected('Maintenance job already active')
  if 'LoadState=loaded' not in service_status(unit):raise Rejected('Reviewed maintenance unit is unavailable')
  priorState=dict(line.split('=',1) for line in service_status(unit).splitlines() if '=' in line);prior=priorState.get('InvocationID')
  command(['systemctl','start','--no-block',unit])
  invocation='';startMonotonic=''
  for _ in range(20):
   state=dict(line.split('=',1) for line in service_status(unit).splitlines() if '=' in line);current=state.get('InvocationID','');started=state.get('ExecMainStartTimestampMonotonic','')
   if current and current!=prior or started not in ['', '0',priorState.get('ExecMainStartTimestampMonotonic')]:invocation=current;startMonotonic=started;break
   time.sleep(0.1)
  return {'invocationId':invocation,'startMonotonic':startMonotonic,'accepted':True,'service':unit,'observed':service_status(unit),'completion':'submitted; inspect unit Result and saved proof before claiming successful backup or restore'}
 if op=='log_rotate':return {'output':command(['logrotate','/etc/logrotate.conf'],timeout=90)}
 raise Rejected('Operation unavailable')
def run_job(job,subject,op,args):
 with db() as c:c.execute('update jobs set status=? where id=?',('running',job))
 try:
  with LOCK:result=clean(mutate(op,args))
  status='submitted' if result.get('accepted') else 'completed'
 except Exception as e:status='failed';result={'error':clean(str(e))}
 with db() as c:c.execute('update jobs set status=?,result=? where id=?',(status,json.dumps(result),job))
 audit(subject,op,args['target'],status,{'jobId':job,'result':result})
def handle(document):
 exact(document,['requestId','issuedAt','machineId','subject','role','mode','operation','arguments','mutationAuthorized','intentSha256'])
 try:uuid.UUID(document['requestId'])
 except (ValueError,TypeError):raise Rejected('Invalid request identity')
 if not isinstance(document['issuedAt'],(int,float)) or abs(time.time()-document['issuedAt'])>60:raise Rejected('Expired request')
 if document['machineId']!=MACHINE or document['role'] not in ['owner','admin']:raise Rejected('Machine or role denied')
 subject=document['subject']
 if not isinstance(subject,str) or not 1<=len(subject)<=256 or re.search(r'[\x00-\x1f]',subject):raise Rejected('Invalid owner identity')
 with db() as c:
  c.execute('delete from requests where at<?',(time.time()-86400,))
  try:c.execute('insert into requests values(?,?)',(document['requestId'],time.time()))
  except sqlite3.IntegrityError:raise Rejected('Request replay rejected')
 if document['mode']=='read':
  exact(document['arguments'],['target'],[]);result=read(document['operation'],document['arguments'].get('target',''),subject);audit(subject,'read.'+document['operation'],document['arguments'].get('target',''),'completed');return clean(result)
 if document['mode']!='change' or document['role']!='owner' or document['mutationAuthorized'] is not True or not re.fullmatch(r'[a-f0-9]{64}',str(document['intentSha256'])):raise Rejected('Explicit trusted owner turn required for changes')
 args=validate_change(document['operation'],document['arguments'])
 with db() as c:
  recent=c.execute('select id,status from jobs where subject=? and operation=? and args=? and created>? and status in (\'queued\',\'running\',\'submitted\',\'completed\') order by created desc limit 1',(subject,document['operation'],json.dumps(args,sort_keys=True),time.time()-120)).fetchone()
  if recent:return {'operationId':recent[0],'status':recent[1],'deduplicated':True}
  count=c.execute("select count(*) from jobs where status in ('queued','running')").fetchone()[0]
  if count>=4:raise Rejected('Infrastructure operation queue is full')
  job=str(uuid.uuid4());c.execute('insert into jobs values(?,?,?,?,?,?,?)',(job,subject,document['operation'],json.dumps(args,sort_keys=True),'queued',time.time(),None))
 audit(subject,document['operation'],args['target'],'accepted',{'jobId':job,'intentSha256':document['intentSha256']})
 EXECUTOR.submit(run_job,job,subject,document['operation'],args)
 return {'operationId':job,'status':'queued','message':'Operation accepted; inspect its final result before claiming success'}
class Handler(http.server.BaseHTTPRequestHandler):
 server_version='PlatformInfra/1';sys_version=''
 def log_message(self,*a):pass
 def do_POST(self):
  self.connection.settimeout(5)
  try:
   if self.path!='/v1/operation' or self.headers.get('Transfer-Encoding'):raise Rejected('Unsupported request path')
   n=int(self.headers.get('Content-Length','0'))
   if not 1<=n<=16384:raise Rejected('Invalid request size')
   body=self.rfile.read(n);signature=self.headers.get('X-Platform-Signature','')
   if len(body)!=n or not hmac.compare_digest(signature,hmac.new(self.server.key,body,hashlib.sha256).hexdigest()):raise Rejected('Authentication failed')
   doc=json.loads(body);result=handle(doc);status=200
  except Exception as e:
   status=403 if isinstance(e,Rejected) else 400;result={'error':clean(str(e))}
   try:audit('untrusted','request.denied','', 'denied',{'reason':clean(str(e))})
   except Exception:pass
  output=encode(clean(result))
  if len(output)>128*1024:output=encode({'truncated':True,'text':output[:64000].decode('utf8','replace')})
  self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(output)));self.end_headers();self.wfile.write(output)
class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):daemon_threads=True
def main():
 initialize()
 with db() as c:c.execute("update jobs set status='interrupted',result=? where status in ('queued','running')",(json.dumps({'error':'Host bridge restarted; inspect actual state before retry'}),))
 key=pathlib.Path(TOKEN).read_bytes()
 if len(key)!=32:raise RuntimeError('Invalid service capability')
 p=pathlib.Path(SOCKET);p.parent.mkdir(mode=0o750,exist_ok=True);os.chown(p.parent,0,1000)
 if p.exists():
  import stat
  if not stat.S_ISSOCK(p.lstat().st_mode):raise RuntimeError('Socket path is not a socket')
  p.unlink()
 with Server(SOCKET,Handler) as server:
  server.key=key;os.chown(SOCKET,0,1000);os.chmod(SOCKET,0o660);server.serve_forever()
if __name__=='__main__':main()
