#!/usr/bin/python3
"""Delete only obsolete signed complete server backup artifacts after retained-set verification."""
import datetime,fcntl,hashlib,importlib.util,json,os,pathlib,re,sys
spec=importlib.util.spec_from_file_location('dedup','/usr/local/libexec/platform-local-dedup.py');d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
WORK=pathlib.Path('/var/lib/platform-backup-schedule');ROOT=d.DATA
apply='--apply' in sys.argv
inventory=json.loads(d.call(d.container(d.OPS,[(ROOT,'/backups',True),(d.SIGNING,'/run/signing-keys',True),('/usr/local/libexec/plan-local-retention.mjs','/plan.mjs',True)],['/plan.mjs'],'node')))
records=inventory['records']
if len(records)<2:raise RuntimeError('Fewer than two complete signed manifests')
keep=records[:2]
proofs=[d.verify(ROOT,r['name']) for r in keep]
latest=json.loads((d.WORK/'latest-proof.json').read_text())
if latest.get('manifestId')!=keep[0]['manifest']['id'] or latest.get('restoreVerified') is not True or latest.get('status')!='passed':raise RuntimeError('Latest retained point lacks actual local Restic restore proof')
# Keep any manifest ID named by the live signed admission, including immutable restore anchors.
admission=json.loads((d.BASE/'trust/admission.json').read_text());protected=set()
def walk(v):
 if isinstance(v,dict):
  for k,x in v.items():
   if k=='manifestId' and isinstance(x,str):protected.add(x)
   walk(x)
 elif isinstance(v,list):
  for x in v:walk(x)
walk(admission)
active=json.loads((d.BASE/'broker-state/active-admission.json').read_text())
anchor_file=WORK/'last-confirmed-admission-anchor.json'
if active['generation']==admission['payload']['generation']:
 anchor_record={'generation':active['generation'],'manifestIds':sorted(protected)}
 anchor_file.write_text(json.dumps(anchor_record));os.chmod(anchor_file,0o600)
elif active['generation']<admission['payload']['generation']:
 if not anchor_file.exists():raise RuntimeError('Pending authority transition lacks previous confirmed anchor')
 protected.update(json.loads(anchor_file.read_text())['manifestIds'])
else:raise RuntimeError('Admission document is behind the active generation')
admission_bytes=(d.BASE/'trust/admission.json').read_bytes()
active_bytes=(d.BASE/'broker-state/active-admission.json').read_bytes()
kept=[r for r in records if r in keep or r['manifest']['id'] in protected]
keptpaths=set()
for r in kept:
 for a in r['manifest']['artifacts']:
  keptpaths.update([a['path'],a['path']+'.sha256',a['path']+'.sig.json'])
expired=[r for r in records if r not in kept];candidates=set()
for r in expired:
 candidates.add('manifests/'+r['name'])
 for a in r['manifest']['artifacts']:
  for rel in [a['path'],a['path']+'.sha256',a['path']+'.sig.json']:
   if rel not in keptpaths:candidates.add(rel)
orphan_inventory=json.loads(d.call(d.container(d.OPS,[(ROOT,'/backups',True),(d.SIGNING,'/run/signing-keys',True),('/usr/local/libexec/plan-local-orphans.mjs','/plan.mjs',True)],['/plan.mjs'],'node')))
cutoff=datetime.datetime.fromisoformat(keep[1]['manifest']['createdAt'].replace('Z','+00:00')).strftime('%Y%m%d-%H%M%S')
orphan_paths=[]
for rel in orphan_inventory['verified']:
 timestamp=re.search(r'-(\d{8}-\d{6})\.',rel)
 if rel not in keptpaths and timestamp and timestamp.group(1)<cutoff:
  orphan_paths.append(rel);candidates.update([rel,rel+'.sha256',rel+'.sig.json'])
files=[]
for rel in sorted(candidates):
 p=ROOT/rel
 if pathlib.PurePosixPath(rel).is_absolute() or '..' in pathlib.PurePosixPath(rel).parts or not p.resolve().is_relative_to(ROOT.resolve()):raise RuntimeError('Unsafe retention candidate')
 if p.exists():
  if p.is_symlink() or not p.is_file():raise RuntimeError('Nonregular retention candidate')
  files.append({'path':rel,'bytes':p.stat().st_size,'inode':p.stat().st_ino})
plan={'schema':'platform.local-backup-retention/v1','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'keepLatest':2,'retainedManifestIds':[r['manifest']['id'] for r in kept],'protectedAdmissionManifestIds':sorted(protected),'expiredManifestIds':[r['manifest']['id'] for r in expired],'ignoredInvalidManifestCount':len(inventory['invalid']),'orphanSignedArtifactCount':len(orphan_paths),'ignoredInvalidSidecarCount':len(orphan_inventory['ignored']),'candidateFileCount':len(files),'candidateBytes':sum(f['bytes'] for f in files),'files':files,'applied':False}
WORK.mkdir(mode=0o700,exist_ok=True);dest=WORK/'local-retention-plan.json';dest.write_text(json.dumps(plan,indent=2)+'\n');os.chmod(dest,0o600)
if apply:
 if (d.BASE/'trust/admission.json').read_bytes()!=admission_bytes or (d.BASE/'broker-state/active-admission.json').read_bytes()!=active_bytes:raise RuntimeError('Authority changed during retention preflight')
 for f in files:
  p=ROOT/f['path'];st=p.lstat()
  if st.st_ino!=f['inode'] or st.st_size!=f['bytes']:raise RuntimeError('Retention candidate changed')
  p.unlink()
 plan['applied']=True;plan['deletedFiles']=len(files);dest=WORK/'local-retention-result.json';dest.write_text(json.dumps(plan,indent=2)+'\n');os.chmod(dest,0o600)
print(json.dumps({k:v for k,v in plan.items() if k!='files'}))

# Local encrypted repository is dedicated to this operator; two distinct full points plus two associated current capsules.
with (d.WORK/'copy.lock').open('a') as dedup_lock:
 fcntl.flock(dedup_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 def restic(args):
  return d.call(d.container(d.RESTIC,[(d.REPO,'/repository',False),(d.PASSWORD,'/run/password',True)],['--repo','/repository','--password-file','/run/password','--no-cache',*args],'restic'))
 snapshots=json.loads(restic(['snapshots','--json']));snapshots.sort(key=lambda x:x['time'],reverse=True)
 retain_ids=set();seen=set();capsules=0;unknown=[]
 for snapshot in snapshots:
  tags=snapshot.get('tags',[])
  if 'platform-local-dedup' in tags:
   manifest=next((t.removeprefix('manifest=') for t in tags if t.startswith('manifest=')),None)
   if manifest in [r['manifest']['id'] for r in keep] and manifest not in seen:
    retain_ids.add(snapshot['id']);seen.add(manifest)
  elif 'platform-host-recovery-capsule' in tags:
   capsules+=1
   if capsules<=2:retain_ids.add(snapshot['id'])
  else:unknown.append(snapshot['id']);retain_ids.add(snapshot['id'])
 if len(seen)!=2:raise RuntimeError('Local encrypted repository lacks both retained full points')
 if latest['snapshotId'] not in retain_ids or latest['capsuleSnapshotId'] not in retain_ids:raise RuntimeError('Current verified local restore snapshot would be removed')
 remove=[x['id'] for x in snapshots if x['id'] not in retain_ids]
 repo_plan={'retainedSnapshotIds':sorted(retain_ids),'removedSnapshotIds':remove,'unknownPreservedSnapshotIds':unknown,'applied':False}
 (WORK/'local-restic-retention-plan.json').write_text(json.dumps(repo_plan,indent=2)+'\n')
 if apply and remove:
  restic(['forget',*remove,'--prune']);restic(['check']);repo_plan['applied']=True
 (WORK/'local-restic-retention-result.json').write_text(json.dumps(repo_plan,indent=2)+'\n')
 print(json.dumps({'localRestic':repo_plan}))
# RustFS archives use the same cadence. Retain two verified immutable archives; legacy signed MinIO remains separate.
rustfs=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/state/rustfs-recovery');archives=sorted((rustfs/'archives').glob('rustfs-*.tar.gz.gpg'),reverse=True)
current=json.loads((rustfs/'latest.json').read_text())
if current.get('status')!='passed':raise RuntimeError('RustFS current restore proof is not valid')
rustfs_delete=archives[2:]
if any(str(p.relative_to(rustfs))==current.get('archive') for p in rustfs_delete):raise RuntimeError('Current RustFS archive cannot be deleted')
for p in rustfs_delete:
 if p.is_symlink() or not p.is_file():raise RuntimeError('Unsafe RustFS archive')
 if apply:
  p.unlink()
  sidecar=p.with_name(p.name.removesuffix('.tar.gz.gpg')+'.json')
  if sidecar.exists():
   if sidecar.is_symlink() or not sidecar.is_file():raise RuntimeError('Unsafe RustFS sidecar')
   sidecar.unlink()
print(json.dumps({'rustfsRetainedArchives':[p.name for p in archives[:2]],'rustfsExpiredArchives':[p.name for p in rustfs_delete],'applied':apply}))
