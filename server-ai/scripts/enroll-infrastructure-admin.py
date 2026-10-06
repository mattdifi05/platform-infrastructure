#!/usr/bin/env python3
"""Local root enrollment of existing VPS infrastructure. Does not read secrets."""
import importlib.util,json,os,pathlib,sys
repo=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('infra_admin',repo/'deployment/host/libexec/platform-server-ai-admin.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
def main():
 if os.geteuid()!=0 or len(sys.argv)!=1:raise RuntimeError('Run as root on the intended VPS, without arguments')
 directory=pathlib.Path('/etc/platform-infrastructure/server-ai')
 # Existing, root-owned protected directory; never create inside an unreviewed parent.
 for parent in [directory,*directory.parents]:
  info=parent.lstat()
  if not parent.is_dir() or parent.is_symlink() or info.st_uid!=0 or info.st_mode&0o022:raise RuntimeError('Enrollment directory is not protected')
 paths=[directory/n for n in ['admin-host.json','infrastructure-inventory.json','admin-host.env']]
 if any(p.exists() or p.is_symlink() for p in paths):raise RuntimeError('Existing enrollment preserved; review before replacement')
 if not a.MACHINE:raise RuntimeError('Host machine identity unavailable')
 names=set(a.command(['docker','ps','--all','--format','{{.Names}}']).splitlines())
 if names & (a.HOSTING|{'gf-server-ai-project-source-reader','gf-server-ai-project-query-reader','gf-php-apache','php-apache'}):raise RuntimeError('Project containers present; empty-host enrollment refused')
 containers=sorted(names & a.VPS_CONTAINERS)
 if not containers:raise RuntimeError('No reviewed infrastructure containers found')
 pins={}
 for name in containers:
  value=json.loads(a.command(['docker','inspect',name]))[0]
  if value.get('Name')!='/'+name:raise RuntimeError('Container identity mismatch')
  pins[name]={k:value[k] for k in ['Id','Image','Mounts']};pins[name]['Labels']=value['Config'].get('Labels') or {}
 config={'version':1,'machineId':a.MACHINE,'containers':containers,'services':sorted(n for n in a.VPS_SERVICES if a.loaded_unit(n)),'jobs':{},'inventoryFile':str(paths[1]),'backupRoot':None,'runtimeRoot':None}
 a.validate_host_config(config,a.MACHINE)
 # No backup/DNS jobs inferred from repository presence or home manifests.
 for p,body in [(paths[1],a.encode(pins)+b'\n'),(paths[0],a.encode(config)+b'\n'),(paths[2],b'SERVER_AI_ADMIN_CONFIG=/etc/platform-infrastructure/server-ai/admin-host.json\n')]:
  fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as out:out.write(body);out.flush();os.fsync(out.fileno())
 print('Enrolled '+str(len(containers))+' actual infrastructure containers; '+str(len(config['services']))+' loaded services; no maintenance jobs. No credentials read.')
if __name__=='__main__':
 try:main()
 except Exception as exc:print(str(exc),file=sys.stderr);sys.exit(1)
