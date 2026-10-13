#!/usr/bin/python3
"""Read-only real VPS capture inventory. This is not a backup or restore proof."""
import datetime, hashlib, json, os, subprocess
PROJECTS={'platform_infra_vps','platform_server_ai'}
def docker(*args):return subprocess.check_output(['docker',*args],timeout=30)
def main():
 if os.geteuid()!=0:raise RuntimeError('Host root is required')
 ids=docker('ps','-q').decode().split()
 if not ids or len(ids)>64:raise RuntimeError('Unexpected running container count')
 rows=json.loads(docker('inspect',*ids));containers=[];volumes={};binds={}
 for c in rows:
  labels=c['Config'].get('Labels') or {}
  if labels.get('com.docker.compose.project') not in PROJECTS:raise RuntimeError('Unclassified running container; review backup scope')
  mounts=[]
  for m in c['Mounts']:
   item={k:m[k] for k in ('Type','Source','Destination','RW')}
   mounts.append(item)
   if m['Type']=='volume':volumes[m['Name']]={'name':m['Name'],'path':m['Source'],'capture':'consistent-snapshot-required'}
   elif m['Type']=='bind':
    source=m['Source']
    ephemeral=source.startswith('/run/') or source in ('/var/run/docker.sock','/etc/localtime','/etc/timezone','/proc/stat','/proc/meminfo','/proc/1/mountinfo','/var/lib/platform-host-metrics/rootfs')
    binds[source]={'path':source,'capture':'recreate-runtime' if ephemeral else 'encrypted-host-capsule-required'}
   else:raise RuntimeError('Unclassified mount type')
  containers.append({'name':c['Name'].lstrip('/'),'containerId':c['Id'],'imageId':c['Image'],'imageReference':c['Config']['Image'],'project':labels['com.docker.compose.project'],'service':labels.get('com.docker.compose.service'),'mounts':mounts})
 print(json.dumps({'capturedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'host':'platform-server-public','machineId':hashlib.sha256(open('/etc/machine-id','rb').read()).hexdigest(),'purpose':'capture-planning-only','backupComplete':False,'containers':sorted(containers,key=lambda x:x['name']),'volumes':sorted(volumes.values(),key=lambda x:x['name']),'binds':sorted(binds.values(),key=lambda x:x['path'])},indent=2))
if __name__=='__main__':main()
