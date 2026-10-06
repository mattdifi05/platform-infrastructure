#!/usr/bin/env python3
"""Typed infrastructure operations. No shell, project path, SQL or secret API."""
import concurrent.futures,contextlib,datetime,hashlib,hmac,http.server,ipaddress,json,os,pathlib,re,secrets,socket,socketserver,sqlite3,ssl,stat,shutil,subprocess,tempfile,threading,time,uuid

STATE=pathlib.Path('/var/lib/platform-server-ai-admin')
SOCKET='/run/platform-server-ai-admin/admin.sock'
TOKEN='/etc/platform-infrastructure/server-ai/infrastructure-token'
ZONE=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/generated/materialized-configs/dns/db.platform-infrastructure.com')
BACKUP=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/local-private-backup')
RUNTIME=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/state')
MACHINE=hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes()).hexdigest() if pathlib.Path('/etc/machine-id').exists() else None
CORE_CONTAINERS=frozenset('gf-postgres gf-mariadb gf-redis gf-keycloak gf-nats gf-grafana gf-prometheus gf-loki gf-alertmanager gf-node-exporter gf-local-dns gf-traefik gf-waf gf-project-router gf-phpmyadmin gf-phppgadmin gf-rustfs gf-minio-gateway gf-platform-alert-dispatcher gf-promtail gf-searxng gf-server-ai-observer gf-server-ai-project-source-reader gf-server-ai-project-query-reader'.split())
HOSTING=frozenset('enterprise-worker-notifications enterprise-worker-jobs node-account node-ui php-matthewdifilippo php-anniversary php-workcalendar php-fiplatform php-stream students-beta-redis enterprise-web enterprise-backend node-scriptastudents officina-dibella-web carrozzeria-tasso-web scripta-local-doh'.split())
CONTAINERS=CORE_CONTAINERS|HOSTING
INVENTORY=pathlib.Path('/etc/platform-infrastructure/server-ai/infrastructure-inventory.json')
SERVICES=frozenset('chrony.service fail2ban.service cron.service systemd-resolved.service platform-docker-observer-proxy.service'.split())
JOBS={'dns':'platform-dns-probe.service','tls':'platform-db-tls-metrics.service','backup_metrics':'platform-backup-health-metrics.service','backup':'platform-backup-schedule.service','rustfs_recovery':'platform-rustfs-recovery.service','host_recovery':'platform-host-recovery.service','local_recovery':'platform-local-dedup.service'}
PACKAGES=frozenset('openssl ca-certificates curl wget openssh-client openssh-server chrony fail2ban ufw auditd apparmor rsync jq python3 python3-minimal sudo tar gzip coreutils dnsutils iproute2 iptables nftables logrotate'.split())
OPERATIONS=('service_start','service_restart','service_stop','service_reload','service_enable','service_disable','config_patch','container_start','container_restart','container_resources','package_refresh','package_upgrade','package_install','dns_record_set','dns_record_remove','firewall_ban','firewall_unban','firewall_reapply','database_reload','maintenance_run','log_rotate')
TOPICS=('capabilities','os','packages','services','timers','identity','config','containers','network','firewall','dns','tls','storage','logs','resources','backups','databases','audit','operation')
PROTECTED_DNS=frozenset('ns portal admin auth login keycloak vpn'.split())
LOCK=threading.Lock()
EXECUTOR=concurrent.futures.ThreadPoolExecutor(max_workers=1)

class Rejected(Exception): pass
PORTABLE=False
HOST_CONFIG_PATH='/etc/platform-infrastructure/server-ai/admin-host.json'
VPS_CONTAINERS=(CORE_CONTAINERS-frozenset(['gf-server-ai-project-source-reader','gf-server-ai-project-query-reader']))|frozenset('gf-control-center gf-cadvisor gf-local-registry gf-minio gf-docker-action-broker gf-docker-action-activation-sidecar gf-backup-scheduler gf-server-ai-controller'.split())
VPS_CONTAINERS=VPS_CONTAINERS|frozenset('enterprise-traefik enterprise-postgres enterprise-redis enterprise-keycloak enterprise-nats enterprise-minio enterprise-control-center enterprise-project-router mariadb phpmyadmin phppgadmin enterprise-local-dns enterprise-prometheus enterprise-node-exporter enterprise-cadvisor enterprise-platform-alert-dispatcher enterprise-alertmanager enterprise-grafana enterprise-loki enterprise-promtail enterprise-local-registry enterprise-waf enterprise-docker-action-broker enterprise-docker-action-activation-sidecar enterprise-backup-scheduler enterprise-broker-auth-bootstrap'.split())
VPS_SERVICES=SERVICES|frozenset(['docker.service','ssh.service','auditd.service','apparmor.service','ufw.service'])
LOCKOUT_SERVICES=frozenset(['ssh.service','sshd.service','docker.service','containerd.service','dbus.service','systemd-logind.service','systemd-resolved.service','systemd-networkd.service','NetworkManager.service','networking.service','ufw.service','firewalld.service','cloudflared.service','platform-cloudflared-vps.service','platform-server-ai-admin.service','platform-docker-observer-proxy.service'])
HOME_JOBS=dict(JOBS)
def protected_json(filename,limit=262144):
 p=pathlib.Path(filename)
 if not p.is_absolute() or str(p)!=filename or '..' in p.parts:raise Rejected('Configuration path is not canonical')
 for parent in [p.parent,*p.parents]:
  info=parent.lstat()
  if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise Rejected('Configuration parent is not protected')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_nlink!=1 or not 0<info.st_size<=limit:raise Rejected('Configuration file is not protected')
  with os.fdopen(fd,'rb',closefd=False) as source:return json.load(source)
 finally:os.close(fd)
def bounded_runtime_path(value):
 if value is None:return None
 if not isinstance(value,str) or not re.fullmatch(r'/(?:var/lib/platform-infrastructure|srv/platform-infrastructure|home/platform_infrastructure/v1-fresh-runtime)/[A-Za-z0-9_./-]+',value) or '..' in value.split('/') or '.' in value.split('/') or '//' in value or value.endswith('/'):raise Rejected('Runtime path outside bounded infrastructure roots')
 p=pathlib.Path(value)
 if p.resolve()!=p or not p.is_dir():raise Rejected('Runtime directory is absent or redirected')
 for ancestor in [p,*p.parents]:
  info=ancestor.lstat()
  if info.st_uid!=0 or info.st_mode&0o022:raise Rejected('Runtime directory is not root protected')
 return p
def validate_host_config(value,machine_id):
 exact(value,['version','machineId','containers','services','jobs','inventoryFile','backupRoot','runtimeRoot'])
 if type(value['version']) is not int or value['version']!=1 or not re.fullmatch(r'[a-f0-9]{64}',str(machine_id)) or value['machineId']!=machine_id:raise Rejected('Host configuration identity mismatch')
 for key,allowed in [('containers',VPS_CONTAINERS),('services',VPS_SERVICES)]:
  rows=value[key]
  if not isinstance(rows,list) or any(not isinstance(row,str) for row in rows) or len(rows)!=len(set(rows)) or not set(rows)<=allowed:raise Rejected('Host configuration includes unreviewed '+key)
 if not isinstance(value['jobs'],dict) or any(k not in HOME_JOBS or not isinstance(v,str) or HOME_JOBS[k]!=v for k,v in value['jobs'].items()):raise Rejected('Host configuration includes unreviewed jobs')
 if value['inventoryFile']!='/etc/platform-infrastructure/server-ai/infrastructure-inventory.json':raise Rejected('Inventory path outside fixed infrastructure boundary')
 backup=bounded_runtime_path(value['backupRoot']);runtime=bounded_runtime_path(value['runtimeRoot'])
 if any(k in value['jobs'] for k in ['backup','rustfs_recovery','host_recovery','local_recovery']) and (backup is None or runtime is None):raise Rejected('Backup jobs require actual host backup state roots')
 return {**value,'backupRoot':backup,'runtimeRoot':runtime}
def configure_host(filename):
 global PORTABLE,CONTAINERS,SERVICES,JOBS,INVENTORY,BACKUP,RUNTIME,ZONE
 if filename!=HOST_CONFIG_PATH:raise Rejected('Host configuration path must be the fixed protected path')
 config=validate_host_config(protected_json(filename),MACHINE)
 pins=protected_json(config['inventoryFile'])
 if not isinstance(pins,dict) or set(pins)!=set(config['containers']):raise Rejected('Inventory differs from enrolled host containers')
 PORTABLE=True;CONTAINERS=frozenset(config['containers']);SERVICES=frozenset(config['services']);JOBS=config['jobs'];INVENTORY=pathlib.Path(config['inventoryFile']);BACKUP=config['backupRoot'];RUNTIME=config['runtimeRoot'];ZONE=None
def loaded_unit(name):
 try:return 'LoadState=loaded' in service_status(name)
 except Rejected:return False
def portable_catalog():
 services=sorted(n for n in SERVICES if loaded_unit(n));jobs={k:v for k,v in JOBS.items() if loaded_unit(v)}
 containers=[]
 if shutil.which('docker'):
  try:containers=sorted(CONTAINERS & set(command(['docker','ps','--all','--format','{{.Names}}']).splitlines()))
  except Rejected:pass
 topics=['capabilities','os','storage','resources','audit','operation','dns'];ops=[]
 if shutil.which('dpkg-query'):topics.append('packages')
 if shutil.which('apt-get') and shutil.which('apt-cache'):ops+=['package_refresh','package_upgrade','package_install']
 if shutil.which('systemctl'):topics+=['services','timers','logs','config']
 if shutil.which('getent'):topics.append('identity')
 if shutil.which('systemctl'):ops+=['service_start','service_restart','service_stop','service_reload','service_enable','service_disable']
 if all(shutil.which(x) for x in ['sshd','systemd-analyze']):ops.append('config_patch')
 if containers:topics+=['containers','databases'];ops+=['container_start','container_restart','container_resources']
 if set(containers)&{'gf-postgres','enterprise-postgres'}:ops.append('database_reload')
 if all(shutil.which(x) for x in ['ip','ss']):topics.append('network')
 if any(shutil.which(x) for x in ['iptables-save','ufw','nft']):topics.append('firewall')
 if pathlib.Path('/var/lib/platform-vps-backup/public/catalog.json').is_file():topics.append('backups')
 if pathlib.Path('/etc/platform-infrastructure/cloudflare-dns/zones.json').is_file():topics.append('tls')
 if shutil.which('fail2ban-client') and 'fail2ban.service' in services:
  try:command(['fail2ban-client','status','sshd']);ops+=['firewall_ban','firewall_unban']
  except Rejected:pass
 if jobs:ops.append('maintenance_run')
 if RUNTIME is not None and 'backup' in jobs and 'backups' not in topics:topics.append('backups')
 if shutil.which('logrotate') and pathlib.Path('/etc/logrotate.conf').is_file():ops.append('log_rotate')
 return topics,ops,containers,services,jobs
def exact(value,keys,required=None):
 if not isinstance(value,dict) or set(value)-set(keys) or set(keys if required is None else required)-set(value):raise Rejected('Invalid fields')
def clean(value):
 if isinstance(value,dict):return {str(k):(v if k in {'id','imageId','profileDigest','manifestDigest'} and isinstance(v,str) and re.fullmatch(r'(?:[a-f0-9]{64}|sha256:[a-f0-9]{64}|[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12})',v) else clean(v)) for k,v in list(value.items())[:100] if not re.search(r'password|secret|token|authorization|cookie|private.?key|credential|api.?key|access.?key|dsn',str(k),re.I)}
 if isinstance(value,list):return [clean(v) for v in value[:150]]
 if isinstance(value,str):
  value=re.sub(r'-----BEGIN[^-]*(?:PRIVATE KEY|CERTIFICATE)-----.*?-----END[^-]+-----','[redacted]',value,flags=re.S)
  value=re.sub(r'(?i)(?:bearer\s+|sk-[A-Za-z0-9_-]+)[A-Za-z0-9._-]*','[redacted]',value)
  value=re.sub(r'(?i)(password|secret|token|authorization|cookie|credential|[a-z0-9_]*private_?key|[a-z0-9_]*api_?key)[\s"\x27:=]+[^\s,;}]+',r'\1=[redacted]',value)
  value=re.sub(r'\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b','[redacted]',value)
  value=re.sub(r'(?<![A-Za-z0-9])[A-Za-z0-9+/=_-]{48,}(?![A-Za-z0-9])','[redacted]',value)
  value=re.sub(r'([?&][A-Za-z0-9_-]+=)[^&\s]+',r'\1[redacted]',value)
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
 pins=protected_json(str(INVENTORY)) if PORTABLE else json.loads(INVENTORY.read_bytes())
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
 return command(['systemctl','show',name,'--no-pager','--property=Id,LoadState,ActiveState,SubState,Result,UnitFileState,FragmentPath,CanReload,MemoryCurrent,CPUUsageNSec,InvocationID,ExecMainStatus,ExecMainStartTimestampMonotonic']).strip()
CLOUDFLARED_UNITS=(('cloudflared.service','/etc/systemd/system/cloudflared.service'),('platform-cloudflared-vps.service','/etc/systemd/system/platform-cloudflared-vps.service'))
def cloudflared_unit():
 for name,path in CLOUDFLARED_UNITS:
  status=service_status(name)
  values=dict(line.split('=',1) for line in status.splitlines() if '=' in line)
  if values.get('Id')==name and values.get('LoadState')=='loaded' and values.get('FragmentPath')==path:
   try:info=pathlib.Path(path).lstat()
   except OSError:continue
   if stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022:return name,path,status
 return None,None,None
def discovered_unit(name,kind='service'):
 if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,120}\.'+kind,name):raise Rejected('Invalid unit name')
 names={line.split()[0] for line in command(['systemctl','list-unit-files','--type='+kind,'--no-legend','--no-pager']).splitlines() if line.split()}
 if name not in names:raise Rejected('Unit is not installed on this host')
 return name
def writable_service(name,operation):
 discovered_unit(name)
 if re.match(r'^(?:php-|node-|gf-|enterprise-|project-|app-)',name):raise Rejected('Project and container units are outside infrastructure scope')
 if '@' in name or re.search(r'(?i)(backup|restore|recovery|snapshot|capture)',name):raise Rejected('Backup, restore and template units remain manual')
 values=dict(line.split('=',1) for line in command(['systemctl','show',name,'--no-pager','--property=Id,LoadState,FragmentPath,CanReload,UnitFileState']).splitlines() if '=' in line)
 if values.get('Id')!=name or values.get('LoadState')!='loaded':raise Rejected('Unit identity or load state changed')
 fragment=pathlib.Path(values.get('FragmentPath',''))
 if not fragment.is_absolute():raise Rejected('Unit fragment is not an installed file')
 resolved=fragment.resolve()
 if not any(str(resolved).startswith(prefix) for prefix in ['/usr/lib/systemd/system/','/lib/systemd/system/']):
  if not str(resolved).startswith('/etc/systemd/system/platform-') and str(resolved)!='/etc/systemd/system/cloudflared.service':raise Rejected('Only distro or reviewed platform infrastructure units may change')
 info=resolved.stat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise Rejected('Unit fragment is not root protected')
 if operation in ['service_stop','service_disable'] and name in LOCKOUT_SERVICES:raise Rejected('Stop or disable would lock out server administration')
 if operation=='service_reload' and values.get('CanReload')!='yes':raise Rejected('Unit does not support reload')
 if operation in ['service_enable','service_disable'] and values.get('UnitFileState') in ['static','masked','indirect','generated','transient']:raise Rejected('Unit cannot be enabled or disabled')
 return name
def metadata_file(filename):
 p=pathlib.Path(filename)
 try:
  s=p.lstat()
  if not stat.S_ISREG(s.st_mode) or s.st_size>65536:return {'available':False}
  return {'available':True,'ownerUid':s.st_uid,'mode':oct(stat.S_IMODE(s.st_mode)),'bytes':s.st_size}
 except OSError:return {'available':False}
def package_rows():
 rows=(line.split('\t') for line in command(['dpkg-query','-W','-f=${binary:Package}\t${Version}\t${db:Status-Status}\n']).splitlines())
 return sorted((row[:2] for row in rows if len(row)==3 and row[2]=='installed'),key=lambda row:row[0])
def official_apt_candidate(package,allow_vendor=False):
 if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]{0,100}(?::[a-z0-9-]+)?',package):raise Rejected('Invalid exact package name')
 if package in command(['apt-mark','showhold']).splitlines():raise Rejected('Held package cannot be changed')
 lines=command(['apt-cache','policy',package]).splitlines()
 candidate=next((line.split(':',1)[1].strip() for line in lines if line.strip().startswith('Candidate:')),None)
 if not candidate or candidate=='(none)':raise Rejected('No configured APT candidate')
 matching=False;official=False
 for line in lines:
  match=re.match(r'^\s*(?:\*\*\*\s+)?(\S+)\s+\d+\s*$',line)
  if match:matching=match[1]==candidate;continue
  if matching and re.search(r'\bhttps?://(?:archive|security)\.ubuntu\.com/ubuntu(?:\s|/)|\bhttps?://ports\.ubuntu\.com/ubuntu-ports(?:\s|/)',line):official=True
  if matching and allow_vendor and re.search(r'\bhttps://(?:download\.docker\.com/linux/ubuntu|pkg\.cloudflare\.com/cloudflared)\s',line):official=True
 if not official:raise Rejected('Candidate is not from an approved configured signed APT archive')
 return candidate
def checked_apt_plan(package,install):
 candidate=official_apt_candidate(package,allow_vendor=not install)
 argv=['apt-get','-s','--no-install-recommends','--no-remove','install']+([] if install else ['--only-upgrade'])+[package]
 simulated=command(argv,timeout=30)
 planned=re.findall(r'^Inst\s+([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?)\s',simulated,re.M)
 if not planned and install:raise Rejected('APT simulation did not plan an installation')
 installed={name.split(':')[0] for name,_ in package_rows()}
 for dependency in planned:official_apt_candidate(dependency,allow_vendor=not install and dependency.split(':')[0] in installed)
 if re.search(r'^(?:Remv|Purg)\s',simulated,re.M):raise Rejected('APT simulation would remove packages')
 return {'candidate':candidate,'plannedPackages':planned}
def selected_sshd():
 selected={'port','addressfamily','permitrootlogin','passwordauthentication','pubkeyauthentication','kbdinteractiveauthentication','authenticationmethods','allowusers','allowgroups','denyusers','denygroups','x11forwarding','permittty','maxauthtries','clientaliveinterval','clientalivecountmax','loglevel','logingracetime','allowtcpforwarding','gatewayports'}
 try:return {parts[0]:parts[1] for line in command(['sshd','-T'],timeout=8).splitlines() if len(parts:=line.split(None,1))==2 and parts[0] in selected}
 except Rejected:return {'available':False}
def selected_config(name):
 if name=='sshd':
  fields={'ClientAliveInterval','ClientAliveCountMax','MaxAuthTries','LogLevel','PasswordAuthentication','PermitRootLogin','PubkeyAuthentication'}
  sources={}
  for p in [pathlib.Path('/etc/ssh/sshd_config'),*sorted(pathlib.Path('/etc/ssh/sshd_config.d').glob('*.conf'))[:20]]:
   if p.is_symlink() or not p.is_file() or p.stat().st_size>65536:continue
   rows={}
   for line in p.read_text().splitlines():
    match=re.match(r'^\s*([A-Za-z]+)\s+([A-Za-z0-9_-]+)\s*$',line)
    if match and match[1] in fields:rows[match[1]]=match[2]
   sources[p.name]=rows
  return {'effective':selected_sshd(),'selectedSourceDirectives':sources}
 if name=='docker':
  try:
   value=protected_json('/etc/docker/daemon.json',limit=65536)
   return {k:v for k,v in value.items() if k in ['log-driver','live-restore','iptables','ip6tables','userland-proxy'] and isinstance(v,(str,bool))} if isinstance(value,dict) else {}
  except (OSError,Rejected):return {'available':False}
 if name=='ufw':
  try:
   lines=pathlib.Path('/etc/default/ufw').read_text().splitlines()
   keys={'IPV6','DEFAULT_INPUT_POLICY','DEFAULT_OUTPUT_POLICY','DEFAULT_FORWARD_POLICY'}
   return {m[1]:m[2] for line in lines if (m:=re.fullmatch(r'([A-Z_]+)="?(ACCEPT|DROP|REJECT|yes|no)"?',line.strip())) and m[1] in keys}
  except OSError:return {'available':False}
 if name in ['vps-backup-timer','vps-backup-queue-timer']:
  unit='platform-'+name.replace('vps-backup-queue-timer','vps-backup-queue').replace('vps-backup-timer','vps-backup')+'.timer'
  return command(['systemctl','show',unit,'--no-pager','--property=Id,LoadState,ActiveState,UnitFileState,TimersCalendar,NextElapseUSecRealtime,LastTriggerUSec,Unit'])
 if name=='cloudflared':
  unit,path,status=cloudflared_unit()
  return {'unit':unit,'status':status,'available':bool(unit)}
 return {'contentExposed':False}
def capabilities():
 topics,operations,containers,services,jobs=portable_catalog() if PORTABLE else (list(TOPICS),list(OPERATIONS),sorted(CONTAINERS),sorted(SERVICES),JOBS)
 packages=sorted(PACKAGES)
 if PORTABLE:
  packages=[]
 return {'source':'live-host-typed-infrastructure-bridge','machineId':MACHINE,'readTopics':topics,'writeOperations':operations,'containers':containers,'services':services,'packages':packages,'packageRead':'all installed packages, 50 per page or exact lookup' if PORTABLE else 'reviewed package allowlist','packageWrites':'legacy reviewed upgrades plus exact official Ubuntu APT candidates' if PORTABLE else 'reviewed installed package allowlist','serviceRead':'all installed unit status and bounded journals' if PORTABLE else 'reviewed unit inventory','serviceWriteScope':'installed root-protected distro and platform infrastructure units; backup/restore manual, stop/disable lockout protected' if PORTABLE else 'reviewed service inventory','maintenanceTargets':jobs,'dnsZone':None if PORTABLE else 'platform-infrastructure.com','limits':{'writes':'owner + fresh active session + explicit trusted user turn','projectCodeAndData':'no project container/source/data APIs' if PORTABLE else 'no source/data read/write API; reviewed hosting containers allow lifecycle and resource budgets only','database':'engine health/resources/lifecycle and PostgreSQL configuration reload only; no SQL or database content','firewall':'existing reviewed policy reapply and public-IP fail2ban sshd bans only','tls':'public certificate metadata for hostnames in configured zones' if PORTABLE else 'verified local certificate inspection and existing TLS metrics','resources':'runtime limits persisted in bridge audit/desired limits; not an application compose/source edit','unsupported':'arbitrary shell/files/SQL, project edits, image/volume/database deletion, restore over live data, arbitrary network/routing changes, new package repositories, trust-key changes; require separate operator workflow'}}
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
 if topic not in (portable_catalog()[0] if PORTABLE else TOPICS):raise Rejected('Read topic unavailable on this host')
 if not isinstance(target,str) or len(target)>160 or any(c in target for c in '\r\n\0/\\'):raise Rejected('Invalid target')
 if topic=='capabilities':return capabilities()
 if topic=='os':return {'kernel':os.uname().release,'uptimeSeconds':float(pathlib.Path('/proc/uptime').read_text().split()[0]),'load':list(os.getloadavg()),'memory':{k:int(v.split()[0])*1024 for k,v in (line.split(':',1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines()) if k in ['MemTotal','MemAvailable','SwapTotal','SwapFree']},'release':{k:v.strip('"') for k,v in (line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line) if k in ['NAME','VERSION','VERSION_ID']}}
 if topic=='packages':
  if PORTABLE:
   rows=package_rows()
   if target and not target.startswith('page:'):
    if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]{0,100}(?::[a-z0-9-]+)?',target):raise Rejected('Invalid package name')
    rows=[row for row in rows if row[0]==target or row[0].split(':')[0]==target]
    return {'installed':rows,'count':len(rows),'lookup':target}
   page=int(target[5:]) if re.fullmatch(r'page:[0-9]{1,4}',target) else 0
   if target and not re.fullmatch(r'page:[0-9]{1,4}',target):raise Rejected('Invalid package page')
   return {'installed':rows[page*50:(page+1)*50],'page':page,'pageSize':50,'total':len(rows)}
  if target and target not in PACKAGES:raise Rejected('Package outside managed upgrade allowlist')
  return {'installed':'\n'.join(line for line in command(['dpkg-query','-W','-f=${binary:Package}\t${Version}\n']).splitlines() if line.split('\t')[0].split(':')[0] in ([target] if target else PACKAGES)),'upgradePolicy':'installed packages only; signed configured distro repositories; no removal'}
 if topic=='services':
  if PORTABLE:
   if target and not target.startswith('page:'):return {'services':{target:service_status(discovered_unit(target))}}
   if target and not re.fullmatch(r'page:[0-9]{1,4}',target):raise Rejected('Invalid service page')
   page=int(target[5:]) if target else 0
   names=[line.split()[0] for line in command(['systemctl','list-unit-files','--type=service','--no-legend','--no-pager']).splitlines() if line.split()]
   return {'installedServiceCount':len(names),'installedServices':names[page*100:(page+1)*100],'page':page,'pageSize':100,'detail':'Use page:N or one exact installed .service target for status'}
  if target and target not in SERVICES and target not in JOBS.values() and (PORTABLE or target!='platform-server-ai-egress.service'):raise Rejected('Service outside reviewed infrastructure inventory')
  return {'services':{n:service_status(n) for n in ([target] if target else sorted(SERVICES))}}
 if topic=='timers':
  if target:return {'timer':target,'status':service_status(discovered_unit(target,'timer'))}
  return {'timers':command(['systemctl','list-timers','--all','--no-pager','--no-legend'])[:16000]}
 if topic=='identity':
  if target and not target.startswith('page:'):
   if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',target):raise Rejected('Invalid account name')
   passwd=command(['getent','passwd',target]).strip().split(':')
   return {'user':{'name':passwd[0],'uid':passwd[2],'gid':passwd[3],'home':passwd[5],'shell':passwd[6]},'sshd':selected_sshd()}
  if target and not re.fullmatch(r'page:[0-9]{1,4}',target):raise Rejected('Invalid identity page')
  page=int(target[5:]) if target else 0
  users=[]
  for line in command(['getent','passwd']).splitlines():
   p=line.split(':')
   if len(p)>=7:users.append({'name':p[0],'uid':p[2],'gid':p[3],'home':p[5],'shell':p[6]})
  groups=[]
  for line in command(['getent','group']).splitlines():
   p=line.split(':')
   if len(p)>=4:groups.append({'name':p[0],'gid':p[2],'members':p[3].split(',')[:30] if p[3] else []})
  return {'users':users[page*50:(page+1)*50],'groups':groups[page*50:(page+1)*50],'page':page,'pageSize':50,'userCount':len(users),'groupCount':len(groups),'sshd':selected_sshd(),'authorizedKeyMetadataOnly':True}
 if topic=='config':
  cloud_unit,cloud_path,_=cloudflared_unit()
  paths={'sshd':'/etc/ssh/sshd_config','docker':'/etc/docker/daemon.json','cloudflared':cloud_path or '/etc/systemd/system/platform-cloudflared-vps.service','ufw':'/etc/default/ufw','vps-backup-timer':'/etc/systemd/system/platform-vps-backup.timer','vps-backup-queue-timer':'/etc/systemd/system/platform-vps-backup-queue.timer','server-ai-admin':'/etc/platform-infrastructure/server-ai/admin-host.json'}
  if target and target not in paths:raise Rejected('Only reviewed configuration metadata is exposed')
  keys=[target] if target else list(paths)
  return {'files':{key:{**metadata_file(paths[key]),'selectedValues':selected_config(key)} for key in keys},'rawContentExposed':False}
 if topic in ['containers','databases']:
  names=[target] if target else ([n for n in (['gf-postgres','gf-mariadb','gf-redis','enterprise-postgres','enterprise-redis','mariadb'] if PORTABLE else ['gf-postgres','gf-mariadb','gf-redis']) if not PORTABLE or n in CONTAINERS] if topic=='databases' else sorted(CONTAINERS));result=[]
  for name in names:
   try:result.append(container_summary(docker(name)))
   except Rejected as e:result.append({'name':name,'available':False,'reason':str(e)})
  return {'containers':result,'databaseContentsRead':False}
 if topic=='network':return {'addresses':json.loads(command(['ip','-j','address'])), 'routes':json.loads(command(['ip','-j','route'])),'listeners':command(['ss','-lntup'])}
 if topic=='firewall':
  result={}
  if shutil.which('iptables-save'):result['iptables']=command(['iptables-save'])[:12000]
  if PORTABLE and shutil.which('ufw'):
   try:result['ufw']=command(['ufw','status','verbose'])[:12000]
   except Rejected as error:result['ufwError']=str(error)
  if PORTABLE and shutil.which('nft'):
   try:result['nft']=command(['nft','-j','list','ruleset'])[:12000]
   except Rejected as error:result['nftError']=str(error)
  if not PORTABLE or 'firewall_ban' in portable_catalog()[1]:result['fail2banSshd']=command(['fail2ban-client','status','sshd'])
  return result
 if topic=='dns':
  if PORTABLE:
   result={'resolver':pathlib.Path('/etc/resolv.conf').read_text()[:4000]}
   zones=pathlib.Path('/etc/platform-infrastructure/cloudflare-dns/zones.json')
   if zones.is_file():
    value=protected_json(str(zones))
    result['cloudflareZones']=[{'name':row.get('name'),'zoneId':row.get('id')} for row in value.get('zones',[])[:30] if isinstance(row,dict) and isinstance(row.get('name'),str)] if isinstance(value,dict) else []
   unit,path,status=cloudflared_unit()
   result['cloudflaredService']={'unit':unit,'status':status,'available':bool(unit)}
   result['cloudflaredRouteConfig']='Provider-managed; no local public route file enrolled'
   return result
  return {'zone':'platform-infrastructure.com','records':safe_zone().decode(),'resolver':pathlib.Path('/etc/resolv.conf').read_text()}
 if topic=='tls':
  if PORTABLE:
   zones=protected_json('/etc/platform-infrastructure/cloudflare-dns/zones.json')
   names=[row.get('name') for row in zones.get('zones',[]) if isinstance(row,dict) and isinstance(row.get('name'),str)]
   if not target or not re.fullmatch(r'[a-z0-9.-]{1,120}',target) or not any(target==name or target.endswith('.'+name) for name in names):raise Rejected('TLS target must be an exact hostname in a configured zone')
   addresses={row[4][0] for row in socket.getaddrinfo(target,443,type=socket.SOCK_STREAM)}
   if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):raise Rejected('TLS hostname does not resolve only to public addresses')
   context=ssl.create_default_context()
   with socket.create_connection((sorted(addresses)[0],443),timeout=5) as raw:
    with context.wrap_socket(raw,server_hostname=target) as tls:
     cert=tls.getpeercert()
     return {'hostname':target,'verified':True,'protocol':tls.version(),'notBefore':cert.get('notBefore'),'notAfter':cert.get('notAfter'),'subjectAltNames':[v for k,v in cert.get('subjectAltName',[]) if k=='DNS'][:50]}
  host=target or 'portal.platform-infrastructure.com'
  if not re.fullmatch(r'[a-z0-9-]+\.platform-infrastructure\.com',host):raise Rejected('TLS target outside configured infrastructure zone')
  context=portal_tls_context()
  try:
   with socket.create_connection(('127.0.0.1',443),timeout=4) as raw:
    with context.wrap_socket(raw,server_hostname=host) as tls:return {'hostname':host,'verified':True,'protocol':tls.version(),'cipher':tls.cipher()[0],'certificate':tls.getpeercert()}
  except ssl.SSLCertVerificationError as error:return {'hostname':host,'verified':False,'error':'CERTIFICATE_VALIDATION_FAILED','verificationError':str(error),'trustStore':'dedicated Portal root'}
 if topic=='storage':
  result={'filesystems':command(['df','-PT','-B1']),'inodes':command(['df','-Pi']),'blockDevices':json.loads(command(['lsblk','-J','-o','NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS']))}
  if PORTABLE and shutil.which('docker'):result['dockerVolumes']=command(['docker','volume','ls','--format','{{.Name}}']).splitlines()[:150]
  return result
 if topic=='logs':
  if PORTABLE:discovered_unit(target)
  elif target not in SERVICES and target not in JOBS.values() and target not in ['platform-server-ai-egress.service','platform-server-ai-admin.service']:raise Rejected('Logs require one reviewed infrastructure unit')
  raw=command(['journalctl','--unit='+target,'--since=-30min','--lines=80','--no-pager','--output=short-iso'],timeout=5)
  return {'unit':target,'redactedJournal':'\n'.join('[sensitive log line redacted]' if re.search(r'password|secret|token|authorization|cookie|credential|private.?key|api.?key|sk-',line,re.I) else clean(line) for line in raw.splitlines())}
 if topic=='resources':
  return {'cpuCounters':pathlib.Path('/proc/stat').read_text()[:12000],'diskCounters':pathlib.Path('/proc/diskstats').read_text()[:12000],'pressure':{n:(pathlib.Path('/proc/pressure')/n).read_text() for n in ['cpu','io','memory']},'inodes':command(['df','-Pi'])}
 if topic=='backups':
  if PORTABLE:
   catalog=pathlib.Path('/var/lib/platform-vps-backup/public/catalog.json')
   if catalog.is_symlink() or not catalog.is_file() or catalog.stat().st_size>65536:raise Rejected('Public backup catalog unavailable')
   value=json.loads(catalog.read_bytes())
   if not isinstance(value,dict) or value.get('schema')!='platform.vps-backup-catalog/v1':raise Rejected('Invalid public backup catalog')
   config=pathlib.Path('/etc/platform-vps-backup');profile=config/'profile.json';signature=config/'profile.sig';public=config/'authority-public.pem'
   if any(p.is_symlink() or not p.is_file() for p in [profile,signature,public]):raise Rejected('Signed backup profile unavailable')
   digest=hashlib.sha256(profile.read_bytes()).hexdigest()
   if digest!=value.get('restoreProfileDigest'):raise Rejected('Public catalog profile digest differs from signed profile')
   command(['openssl','pkeyutl','-verify','-pubin','-inkey',str(public),'-rawin','-in',str(profile),'-sigfile',str(signature)],timeout=8)
   points=[]
   for row in value.get('points',[])[:20]:
    if not isinstance(row,dict):continue
    manifest=row.get('manifest',{})
    points.append({'manifestId':manifest.get('id'),'manifestDigest':manifest.get('signature',{}).get('digest') if isinstance(manifest.get('signature'),dict) else None,'createdAt':manifest.get('createdAt'),'offsiteVerified':row.get('offsiteVerified'),'verifiedAt':row.get('verifiedAt')})
   return {'catalogMetadata':{'schema':value['schema'],'updatedAt':value.get('updatedAt'),'profileDigest':digest,'profileSignatureVerified':True,'scheduleActive':value.get('scheduleActive'),'queueActive':value.get('queueActive'),'points':points},'weeklyTimer':service_status('platform-vps-backup.timer'),'queueTimer':service_status('platform-vps-backup-queue.timer'),'artifactBytesExposed':False,'restoreOverLiveDataAllowed':False}
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
def replace_fixed_config(path,data):
 parent=path.parent
 info=parent.stat()
 if parent.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise Rejected('Configuration directory is not root protected')
 mode=0o644
 if path.exists() or path.is_symlink():
  existing=path.lstat()
  if not stat.S_ISREG(existing.st_mode) or existing.st_uid!=0 or existing.st_mode&0o022:raise Rejected('Existing configuration is not root protected')
  mode=stat.S_IMODE(existing.st_mode)
 fd,name=tempfile.mkstemp(prefix='.platform-server-ai-',dir=parent)
 try:
  with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fchmod(out.fileno(),mode);os.fsync(out.fileno())
  os.replace(name,path)
  sync_config_directory(parent)
 finally:
  try:os.unlink(name)
  except FileNotFoundError:pass
def sync_config_directory(parent):
 fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def patch_config(args):
 target=args['target']
 if target=='vps-backup-timer':
  path=pathlib.Path('/etc/systemd/system/platform-vps-backup.timer.d/90-platform-server-ai-schedule.conf')
  path.parent.mkdir(mode=0o755,exist_ok=True)
  calendar=args['onCalendar']
  command(['systemd-analyze','calendar',calendar],timeout=8)
  data=('[Timer]\nOnCalendar=\nOnCalendar='+calendar+'\n').encode()
  validate=lambda:command(['systemctl','daemon-reload'],timeout=15)
  readback=lambda:selected_config('vps-backup-timer')
 else:
  path=pathlib.Path('/etc/ssh/sshd_config.d/90-platform-server-ai-hardening.conf')
  path.parent.mkdir(mode=0o755,exist_ok=True)
  current={}
  if path.exists():
   if path.is_symlink() or path.stat().st_size>4096:raise Rejected('Existing SSH drop-in is not a bounded regular file')
   for line in path.read_text().splitlines():
    match=re.fullmatch(r'(ClientAliveInterval|ClientAliveCountMax|MaxAuthTries|LogLevel)\s+([A-Za-z0-9]+)',line.strip())
    if not match:raise Rejected('SSH drop-in contains unreviewed directives')
    current[match[1]]=match[2]
  mapping={'clientAliveInterval':'ClientAliveInterval','clientAliveCountMax':'ClientAliveCountMax','maxAuthTries':'MaxAuthTries','logLevel':'LogLevel'}
  current.update({directive:str(args[key]) for key,directive in mapping.items() if key in args})
  data=(''.join(f'{key} {current[key]}\n' for key in mapping.values() if key in current)).encode()
  def validate():
   command(['sshd','-t'],timeout=8)
   observed=selected_sshd()
   for key,directive in mapping.items():
    if key in args and observed.get(directive.lower())!=str(args[key]).lower():raise Rejected('SSH effective configuration differs from requested hardening')
   command(['systemctl','reload','ssh.service'],timeout=15)
  readback=selected_sshd
 if path.exists() or path.is_symlink():
  prior=path.lstat()
  if not stat.S_ISREG(prior.st_mode) or prior.st_uid!=0 or prior.st_mode&0o022 or prior.st_size>4096:raise Rejected('Existing configuration is not bounded and root protected')
 old=path.read_bytes() if path.exists() else None
 try:
  replace_fixed_config(path,data)
  validate()
  observed=readback()
  if target=='vps-backup-timer' and ('LoadState=loaded' not in observed or 'ActiveState=active' not in observed or 'OnCalendar='+calendar not in observed):raise Rejected('Backup timer schedule or active state did not match')
 except Exception:
  try:
   if old is None:
    if path.exists():path.unlink();sync_config_directory(path.parent)
   else:replace_fixed_config(path,old)
   if target=='vps-backup-timer':command(['systemctl','daemon-reload'],timeout=15)
   else:command(['sshd','-t'],timeout=8);command(['systemctl','reload','ssh.service'],timeout=15)
  except Exception as rollback_error:raise Rejected('Configuration failed and rollback could not be verified: '+clean(str(rollback_error)))
  raise
 return {'target':target,'selectedReadback':observed,'fileMetadata':metadata_file(str(path))}
def validate_change(op,args):
 if op not in (portable_catalog()[1] if PORTABLE else OPERATIONS):raise Rejected('Unsupported infrastructure operation; no shell/project/SQL fallback')
 exact(args,['target','memoryMiB','cpus','pids','address','onCalendar','clientAliveInterval','clientAliveCountMax','maxAuthTries','logLevel'],['target']);target=args['target']
 if not isinstance(target,str) or len(target)>160 or not target or any(c in target for c in '\r\n\0/\\'):raise Rejected('Invalid infrastructure target')
 allowed={'target'}
 if op=='config_patch':
  if not PORTABLE:raise Rejected('Typed configuration patch applies only to the enrolled VPS')
  if target=='vps-backup-timer':
   allowed.add('onCalendar')
   if not re.fullmatch(r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) \*-\*-\* (?:0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]:00 Europe/Rome',str(args.get('onCalendar',''))):raise Rejected('Backup calendar must be one weekly Rome time')
  elif target=='sshd-hardening':
   bounds={'clientAliveInterval':(30,3600),'clientAliveCountMax':(1,10),'maxAuthTries':(3,10)}
   allowed.update([*bounds,'logLevel'])
   if len(args)<2:raise Rejected('No SSH hardening field supplied')
   for key,(low,high) in bounds.items():
    if key in args and (type(args[key]) is not int or not low<=args[key]<=high):raise Rejected('SSH hardening value outside safe bounds')
   if 'logLevel' in args and args['logLevel'] not in ['INFO','VERBOSE']:raise Rejected('SSH log level outside reviewed values')
  else:raise Rejected('Configuration target is outside the reviewed allowlist')
 if op=='container_resources':
  allowed|={'memoryMiB','cpus','pids'}
  if len(args)<2:raise Rejected('No resource limit supplied')
  total=int(next(x.split()[1] for x in pathlib.Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemTotal:')))//1024
  for k,low,high in [('memoryMiB',256,min(32768,total//2)),('cpus',0.25,min(8,os.cpu_count() or 1)),('pids',64,2048)]:
   if k in args and (isinstance(args[k],bool) or not isinstance(args[k],(int,float)) or not low<=args[k]<=high or k!='cpus' and not isinstance(args[k],int)):raise Rejected('Resource limit outside safe host bounds')
 if op=='dns_record_set':allowed.add('address')
 if set(args)-allowed:raise Rejected('Fields do not belong to this operation')
 if op.startswith('container_') and target not in CONTAINERS:raise Rejected('Container is outside the reviewed runtime inventory')
 if op.startswith('service_'):
  if PORTABLE:
   writable_service(target,op)
  elif target not in SERVICES:raise Rejected('Service outside reviewed infrastructure allowlist')
 if op in ['package_upgrade','package_install']:
  if PORTABLE:
   installed={name.split(':')[0] for name,_ in package_rows()}
   if op=='package_upgrade' and target.split(':')[0] not in installed:raise Rejected('Upgrade requires an installed package')
   if op=='package_install' and target.split(':')[0] in installed:raise Rejected('Install requires an absent package; use upgrade')
   if op=='package_install' or target not in PACKAGES:checked_apt_plan(target,op=='package_install')
  elif target not in PACKAGES:raise Rejected('Package outside managed installed-package allowlist')
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
 if op=='database_reload' and target not in ({'gf-postgres','enterprise-postgres'}&CONTAINERS if PORTABLE else {'gf-postgres'}):raise Rejected('Only PostgreSQL existing configuration reload is supported; no arbitrary SQL/config write')
 if op=='maintenance_run' and target not in (portable_catalog()[4] if PORTABLE else JOBS):raise Rejected('Unknown reviewed maintenance job')
 if op=='log_rotate' and target!='system':raise Rejected('Only normal configured log rotation is supported')
 return args
def mutate(op,args):
 if PORTABLE:validate_change(op,args)
 target=args['target']
 if BACKUP is not None and (BACKUP/'broker-state/active-operation.json').exists() and not (op=='maintenance_run' and target in ['dns','tls','backup_metrics']):raise Rejected('A backup operation is active; defer infrastructure changes')
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
 if op.startswith('service_'):
  if PORTABLE:writable_service(target,op)
  command(['systemctl',op.split('_')[1],target],timeout=60)
  return {'service':target,'observed':service_status(target)}
 if op=='config_patch':return patch_config(args)
 if op=='package_refresh':return {'diagnostic':clean(command(['apt-get','-o','DPkg::Lock::Timeout=30','-o','Acquire::http::Timeout=30','-o','Acquire::https::Timeout=30','-o','Acquire::Retries=2','update'],transaction=True))}
 if op in ['package_upgrade','package_install']:
  before=next((version for name,version in package_rows() if name==target or name.split(':')[0]==target),None)
  if PORTABLE:
   if op=='package_upgrade' and before is None or op=='package_install' and before is not None:raise Rejected('Package installed state changed')
   plan=checked_apt_plan(target,op=='package_install') if op=='package_install' or target not in PACKAGES else {'legacyReviewedPackage':True}
   argv=['apt-get','-o','DPkg::Lock::Timeout=30','--no-install-recommends','--no-remove','--assume-yes','install']+([] if op=='package_install' else ['--only-upgrade'])+[target]
  else:
   if before is None:raise Rejected('Package must already be installed')
   plan={};argv=['apt-get','-o','DPkg::Lock::Timeout=30','install','--only-upgrade','--no-remove','--assume-yes',target]
  out=command(argv,transaction=True)
  after=next((version for name,version in package_rows() if name==target or name.split(':')[0]==target),None)
  return {'package':target,'before':before,'after':after,'plan':plan,'diagnostic':clean(out),'rebootRequired':pathlib.Path('/var/run/reboot-required').exists()}
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
 configured=os.environ.get('SERVER_AI_ADMIN_CONFIG')
 if configured:configure_host(configured)
 if MACHINE is None:raise RuntimeError('Host machine identity is unavailable')
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
