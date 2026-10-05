"""Closed membership derivation for the one historical G15 -> G16 overlay."""
import hashlib,json,re
from pathlib import Path

PARENT_ID='manifest-scheduled-platform-20260929-182357-1f9954'
PARENT_DIGEST='baf72a7c4ff5d2266b71afe4865ebffeb8be6c363dfc31c12f3a865389009b2c'
PARENT_RECEIPT='1868a512b5a47fe9cc4808622dfb4707d8fe988b0a1d523f801c12ad4c419030'
PARENT_MANIFEST_SHA='ae093766108a3bc177cbaca539b513755a8032e17c4b50d49fd1c09ba2511106'
FULL_BINDINGS_SHA='6fa2068e6d1d759c308ed0f1792936df600aba5166157cd10462ae0570fa5edf'
PRIVATE240_PLAN_SHA='c6f09fd00d7f8a7e1dc8794e214dfec1f0bf48f663fec2b0f26b8575b34d4c29'
PARENT_SELECTED_MEMBERS_SHA='fbd57667ad7f70423a8aeb9b43691f091592921f9bfdca2149eeed173cfc647b'
DURABLE_SUPPLEMENT_RECEIPT_SHA='d275da1dd5092345b155b9c8a1e832d0161b2c8f44f4bbb22cf356dbc58012cb'
DURABLE_INDEX_SHA='dc57f3390b82b1f91faa9d85df5c22b47bd9594fb2a22ff1c9361ac4c3d8bd23'
NATIVE_STATE_PROOF_SHA='a51b790bc55af4228c7e2bab0e18471779d5d18f9c8029bf875fa745b421de2f'
REDIS_PROVIDER_PROOF_SHA='e15f8f351531f36e9086376f9218865b6fec2880ff3d6002689b58b526be10e4'
REDIS_INNER_MANIFEST_SHA='7ed784f122cd938cf816d19214737496daab0f1d169416106d53a40b2286de53'
REDIS_SIGNED_LATEST_SHA='95a3c1b9db10d245b86400968e50786d9aac6ad789cdc8397faa519d803207ef'
RUSTFS_PROVIDER_PROOF_SHA='f06bf4e9045132d95960e8033b157d60019e4a023adf15ae39dc833227ee5f24'
RUSTFS_SIGNED_OUTER_PROOF_SHA='9625ce36be111eea06b66af110be63c3343efe1ebd1e4a14c4014e80a9eb2926'
RUSTFS_TREE_INDEX_SHA='051cf08614dd350643bbe123e30d18c85ea4259f8ff11406bb6e3356bc703b98'
BASE_ARCHIVE_SHA='77de6d262d269db484aa48fbe63ca064a151a9c5ecc081374bf9be4d3e034987'
HISTORICAL_TREES_SHA='6ed00c6e14abf23cb7d84ae9e4453206d5e33c8aaee7b37cb3485b20995ff8e3'
HISTORICAL_TREES_INDEX_SHA='3f032c289a77460aaaa7bfa9613a581e7d448cb6970b132343f0a19ae15ab7ce'
SQL_DUMP_IDS={'f59b6803635b9232032a9f078bba472a18fa9797ceb28346c6c3da5a29b6e44a':'database:postgres:control_center',
              '69dd358680066c3765a5ed05b83774da81c60d327ecd164e4de605be60df111a':'database:mariadb:phpmyadmin'}
SQL_RESOURCE_IDS={
 'postgres:stexor':'database:account-postgres-stexor',
 'postgres:keycloak':'database:platform-postgres-keycloak',
 'postgres:students_beta_app':'database:scriptastudents-postgres-students-beta-app',
 'mariadb:anniversary':'database:anniversary-mariadb-anniversary',
 'mariadb:fiplatform':'database:fiplatform-mariadb-fiplatform',
 'mariadb:u778675014_fip':'database:fiplatform-mariadb-u778675014-fip',
 'mariadb:stream':'database:stream-mariadb-stream',
 'mariadb:workcalendar':'database:workcalendar-mariadb-workcalendar',
}
STATE_RESOURCE_IDS={
 'state:projects', 'state:projects-meta', 'state:databases',
 'state:project-registry', 'state:project-registry-meta',
 'state:encrypted-secret-store',
}
SQL_COMPOSITES={
 'postgres:stexor':'persistent:postgres',
 'postgres:keycloak':'persistent:postgres',
 'postgres:students_beta_app':'persistent:postgres',
 'mariadb:anniversary':'persistent:mariadb',
 'mariadb:fiplatform':'persistent:mariadb',
 'mariadb:u778675014_fip':'persistent:mariadb',
 'mariadb:stream':'persistent:mariadb',
 'mariadb:workcalendar':'persistent:mariadb',
}
class Blocked(RuntimeError):pass
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def sha(v):return hashlib.sha256(canonical(v)).hexdigest()
def add(mapping,digest,ids):
 if not re.fullmatch('[a-f0-9]{64}',str(digest)):raise Blocked('MEMBERSHIP_ARTIFACT_SHA')
 values=mapping.setdefault(digest,set());values.update(ids)
def finalize(mapping):return {d:sorted(ids) for d,ids in sorted(mapping.items())}
def audit_active87(maps,binding,target_members=None):
 """Fail closed unless every fixed restore target has authenticated membership.

    The fixed manual restore scope is the 81 resources in the signed full
    bindings document plus the six selected Control Center state files. A
    target may have several authenticated component artifacts (the two SQL
    persistent volumes); every other target still needs its own authenticated
    source mapping. This check prevents the role-map counts from being mistaken
    for complete target coverage.
    """
 targets=set(binding)|STATE_RESOURCE_IDS
 if len(binding)!=81 or len(targets)!=87:raise Blocked('ACTIVE87_FIXED_TARGET_SET')
 seen=set()
 authenticated_pairs=set()
 for role in ('parent','base-completeness','source-overlay','parent-durable-supplement'):
  values=maps.get(role,{})
  if not isinstance(values,dict):raise Blocked('ACTIVE87_ROLE_MAP_SHAPE')
  for ids in values.values():
   if not isinstance(ids,list) or any(not isinstance(x,str) for x in ids):raise Blocked('ACTIVE87_ROLE_IDS_SHAPE')
   seen.update(ids)
  for digest,ids in values.items():
   authenticated_pairs.update((digest,rid) for rid in ids)
 if not isinstance(target_members,dict):raise Blocked('ACTIVE87_TARGET_MEMBER_MAP_REQUIRED')
 pair_roles={}
 for role,values in maps.items():
  for digest,ids in values.items():
   for rid in ids:pair_roles.setdefault((digest,rid),set()).add(role)
 for target,rows in target_members.items():
  if target not in targets or not isinstance(rows,list) or not rows:raise Blocked('ACTIVE87_TARGET_MEMBER_ROW')
  for row in rows:
   if (not isinstance(row,dict) or row.get('target')!=target or not re.fullmatch('[a-f0-9]{64}',str(row.get('artifactSha256',''))) or
       not re.fullmatch('[a-f0-9]{64}',str(row.get('memberSha256',''))) or not isinstance(row.get('resourceId'),str) or
       not isinstance(row.get('memberPath'),str)):
    raise Blocked('ACTIVE87_TARGET_MEMBER_ROW')
   pair=(row['artifactSha256'],row['resourceId'])
   if pair not in authenticated_pairs:
    raise Blocked('ACTIVE87_TARGET_MEMBER_NOT_IN_AUTHENTICATED_ROLE')
   expected_roles=pair_roles.get(pair,set())
   if not expected_roles or row.get('role') not in expected_roles:
    raise Blocked('ACTIVE87_TARGET_MEMBER_ROLE_MISMATCH')
 missing=sorted(targets-set(target_members))
 if missing:raise Blocked('ACTIVE87_AUTHENTICATED_ORIGIN_GAP:'+','.join(missing))
 return {'targetCount':len(targets),'mappedTargetCount':len(targets),'missing':[]}
def _member_target(target,artifact_sha,resource_id,member_path,member_sha,role):
 if not all(re.fullmatch('[a-f0-9]{64}',str(x)) for x in (artifact_sha,member_sha)):
  raise Blocked('TARGET_MEMBER_SHA')
 if not isinstance(member_path,str) or not member_path or member_path.startswith('/') or '..' in Path(member_path).parts:
  raise Blocked('TARGET_MEMBER_PATH')
 if role not in {'parent','base-completeness','source-overlay','parent-durable-supplement'}:raise Blocked('TARGET_MEMBER_ROLE')
 return {'target':target,'artifactSha256':artifact_sha,'resourceId':resource_id,
         'memberPath':member_path,'memberSha256':member_sha,'role':role}

def derive(parent_manifest,full_bindings,private_plan,base,overlay,source_resource_ids,capsule_index,
           selected_members=None,selected_members_sha=None,durable_payload=None,durable_receipt_sha=None,
           durable_index=None,durable_index_sha=None,native_state=None,native_state_sha=None,
           redis_provider=None,redis_provider_sha=None,redis_inner_manifest=None,redis_inner_manifest_sha=None,
           redis_latest=None,redis_latest_sha=None,rustfs_provider=None,rustfs_provider_sha=None,
           rustfs_outer_proof=None,rustfs_outer_proof_sha=None,rustfs_tree_index=None,rustfs_tree_index_sha=None):
 if (parent_manifest.get('id')!=PARENT_ID or parent_manifest.get('signature',{}).get('digest')!=PARENT_DIGEST or
     parent_manifest.get('scope')!={'kind':'platform','id':'platform'} or len(parent_manifest.get('artifacts',[]))!=69):raise Blocked('PINNED_PARENT_MANIFEST_SHAPE')
 resources=parent_manifest.get('resources');artifacts=parent_manifest.get('artifacts')
 if not isinstance(resources,list) or len(resources)!=69 or not isinstance(artifacts,list):raise Blocked('PARENT_MANIFEST_RESOURCE_SET')
 resource_ids={x.get('id') for x in resources if isinstance(x,dict)}
 if len(resource_ids)!=69 or None in resource_ids:raise Blocked('PARENT_RESOURCE_IDS')
 parent_map={}; parent_artifacts={}
 for row in artifacts:
  if not isinstance(row,dict) or not re.fullmatch('[a-f0-9]{64}',str(row.get('sha256',''))) or type(row.get('sizeBytes')) is not int or row.get('resourceId') not in resource_ids:raise Blocked('PARENT_ARTIFACT_ROW')
  add(parent_map,row['sha256'],[row['resourceId']])
  parent_artifacts[row['resourceId']]=row
 if {rid for ids in parent_map.values() for rid in ids}!=resource_ids:raise Blocked('PARENT_ARTIFACT_COVERAGE')
 if (full_bindings.get('manifestId')!=PARENT_ID or full_bindings.get('manifestDigest')!=PARENT_DIGEST or
     full_bindings.get('schema')!='platform.manual-full-server-bindings/v1' or not isinstance(full_bindings.get('resources'),dict)):raise Blocked('FULL_BINDINGS_PARENT')
 binding=full_bindings['resources'];source_ids={x for x in binding if x.startswith('source:')}
 cold_ids={x for x,v in binding.items() if x.startswith('cold-volume:') and isinstance(v,dict) and v.get('kind')=='cold-volume'}
 extra_ids={x for x,v in binding.items() if x.startswith('extra-tree:') and isinstance(v,dict) and v.get('kind')=='extra-mounted-tree'}
 if (len(binding)!=81 or len(source_ids)!=57 or len(cold_ids)!=6 or len(extra_ids)!=9 or
     set(source_resource_ids)!=source_ids or len(source_resource_ids)!=57 or 'source:stream' not in source_ids):raise Blocked('NATIVE_SOURCE_MEMBERSHIP_SET')
 if private_plan.get('schema')!='platform.full-private-clone-plan/v1':raise Blocked('PRIVATE_PLAN_SCHEMA')
 mounts=[x for x in private_plan.get('mounts',[]) if isinstance(x,dict) and x.get('provider')=='future-authenticated-extra-mounted-tree']
 if len(mounts)!=9:raise Blocked('EXTRA_TREE_PLAN_COUNT')
 mapped=set()
 for mount in mounts:
  matches=[rid for rid,row in binding.items() if rid.startswith('extra-tree:') and
           row.get('container')==mount.get('container') and row.get('destination')==mount.get('target') and row.get('target')==mount.get('source')]
  if len(matches)!=1:raise Blocked('EXTRA_TREE_FIXED_MAPPING')
  mapped.add(matches[0])
 if mapped!=extra_ids:raise Blocked('EXTRA_TREE_RESOURCE_COVERAGE')
 base_files=base.get('files');archive=[x for x in base_files if isinstance(x,dict) and x.get('name')=='full-runtime.tar.gz'] if isinstance(base_files,list) else []
 cold=[x for x in base_files if isinstance(x,dict) and x.get('name')=='cold-volumes.tar.gz'] if isinstance(base_files,list) else []
 if len(archive)!=1 or archive[0].get('sha256')!=BASE_ARCHIVE_SHA or archive[0].get('bytes')!=14_123_697_104 or len(cold)!=1:raise Blocked('BASE_RECOVERY_MEMBER_SET')
 base_map={};add(base_map,archive[0]['sha256'],source_ids);add(base_map,cold[0]['sha256'],cold_ids)
 target_members={}
 for rid in sorted(source_ids):
  target_members[rid]=[
   _member_target(rid,BASE_ARCHIVE_SHA,rid,'full-runtime.tar.gz:'+rid,BASE_ARCHIVE_SHA,'base-completeness'),
   _member_target(rid,overlay.get('metadataIndexSha256'),rid,'source-metadata-index:'+rid,overlay.get('metadataIndexSha256'),'source-overlay')]
 for rid in sorted(cold_ids):
  target_members[rid]=[_member_target(rid,cold[0]['sha256'],rid,'cold-volumes.tar.gz:'+rid,cold[0]['sha256'],'base-completeness')]
 # Parent database artifacts are authenticated by the signed parent manifest,
 # not duplicated into the completeness or source-overlay receipt roles.
 resource_to_db={v:k for k,v in SQL_RESOURCE_IDS.items()}
 index_files=capsule_index.get('files');
 if not isinstance(index_files,dict):raise Blocked('CAPSULE_FILE_INDEX_REQUIRED')
 record_root='host/var/lib/platform-host-recovery/recovery-records/'+PARENT_ID
 record_rows=[index_files.get(record_root+'/'+name) for name in ('current.tar','index.json','proof.json')]
 if any(not isinstance(row,dict) or type(row.get('bytes')) is not int or not re.fullmatch('[a-f0-9]{64}',str(row.get('sha256',''))) for row in record_rows):raise Blocked('HISTORICAL_RECORD_INDEX_BINDING')
 if overlay.get('metadataIndexSha256')!='951d2ffdd3eb56e44245bee03b7e2eafdd10d0b4758db4fc19dfd9434fe0150d':raise Blocked('OVERLAY_METADATA_INDEX')
 source_map={};add(source_map,overlay.get('metadataIndexSha256'),source_ids)
 add(source_map,HISTORICAL_TREES_SHA,extra_ids);add(source_map,HISTORICAL_TREES_INDEX_SHA,extra_ids)
 for dump_sha,database_id in SQL_DUMP_IDS.items():
  add(source_map,dump_sha,[database_id])
  persistent='persistent:postgres' if database_id.endswith(':control_center') else 'persistent:mariadb'
  add(source_map,dump_sha,[persistent])
 add(source_map,'e282ff9de94559703906bfd31a74a3759a6950a0900a97eba94e6c5baa612fe6',
     list(SQL_DUMP_IDS.values())+['persistent:postgres','persistent:mariadb'])
 add(source_map,overlay.get('capsuleSha256'),list(extra_ids|set(SQL_DUMP_IDS.values())))
 parent_db_ids={r.get('id') for r in resources if isinstance(r,dict) and r.get('kind')=='database'}
 if parent_db_ids!=set(SQL_RESOURCE_IDS.values()):raise Blocked('PARENT_DATABASE_SET')
 for row in artifacts:
  rid=row['resourceId']
  if rid.startswith('database:') and rid not in set(SQL_RESOURCE_IDS.values()):raise Blocked('PARENT_DATABASE_MAPPING')
 for rid in sorted(extra_ids):
  target_members[rid]=[
   _member_target(rid,HISTORICAL_TREES_INDEX_SHA,rid,'extra-mounted-trees/index.json:'+rid,HISTORICAL_TREES_INDEX_SHA,'source-overlay'),
   _member_target(rid,HISTORICAL_TREES_SHA,rid,'extra-mounted-trees/current.tar:'+rid,HISTORICAL_TREES_SHA,'source-overlay')]
 for row in artifacts:
  rid=row.get('resourceId')
  if isinstance(rid,str) and rid.startswith('database:'):
   persistent=SQL_COMPOSITES.get(resource_to_db.get(rid))
   if persistent:
    target_members.setdefault(persistent,[]).append(_member_target(persistent,row['sha256'],rid,row['path'],row['sha256'],'parent'))
 for digest,db_id in SQL_DUMP_IDS.items():
  persistent='persistent:postgres' if db_id.endswith(':control_center') else 'persistent:mariadb'
  filename='control_center.dump' if db_id.endswith(':control_center') else 'phpmyadmin.sql'
  target_members.setdefault(persistent,[]).append(_member_target(persistent,digest,db_id,'extra-databases/'+filename,digest,'source-overlay'))
 if len(target_members.get('persistent:postgres',[]))!=4 or len(target_members.get('persistent:mariadb',[]))!=6:
  raise Blocked('SQL_COMPOSITE_MEMBER_COVERAGE')
 durable_map={}
 if (not isinstance(selected_members,dict) or selected_members_sha!=PARENT_SELECTED_MEMBERS_SHA or
     selected_members.get('schema')!='platform.authenticated-parent-selected-members/v1' or
     selected_members.get('parentManifestId')!=PARENT_ID or selected_members.get('parentManifestSha256')!=PARENT_DIGEST or
     selected_members.get('artifactHmacRevalidated') is not True or selected_members.get('productionModified') is not False):
  raise Blocked('PARENT_SELECTED_MEMBERS_PROOF')
 selected_artifacts={x.get('artifact',{}).get('resourceId'):x for x in selected_members.get('selectedArtifacts',[]) if isinstance(x,dict)}
 def selected_member(resource_id,name):
  artifact=selected_artifacts.get(resource_id)
  if not isinstance(artifact,dict):raise Blocked('SELECTED_ARTIFACT_MISSING:'+resource_id)
  parent_row=parent_artifacts.get(resource_id); meta=artifact.get('artifact',{})
  if not isinstance(parent_row,dict) or any(meta.get(k)!=parent_row.get(k) for k in ('path','resourceId','sha256','sizeBytes')):
   raise Blocked('SELECTED_ARTIFACT_NOT_IN_PARENT:'+resource_id)
  matches=[m for m in artifact.get('members',[]) if isinstance(m,dict) and m.get('name')==name]
  if len(matches)!=1 or matches[0].get('type')!='0' or not re.fullmatch('[a-f0-9]{64}',str(matches[0].get('sha256',''))):
   raise Blocked('SELECTED_SUBMEMBER_MISSING:'+resource_id+':'+name)
  return parent_row,matches[0]
 # Bind six selected state files to exact member records of the two signed parent artifacts.
 state_specs={
  'state:projects':('platform-state:control-center-state','./projects.json'),
  'state:projects-meta':('platform-state:control-center-state','./projects.json.state-meta.json'),
  'state:databases':('platform-state:control-center-state','./databases.json'),
  'state:project-registry':('platform-state:control-center-state','./server-ai-project-registry.json'),
  'state:project-registry-meta':('platform-state:control-center-state','./server-ai-project-registry.json.state-meta.json'),
  'state:encrypted-secret-store':('platform-state:secret-manager-metadata','./infra-secret-manager-store.json'),
 }
 for target,(rid,member_name) in state_specs.items():
  art,member=selected_member(rid,member_name)
  add(parent_map,art['sha256'],[rid])
  target_members[target]=[_member_target(target,art['sha256'],rid,member_name,member['sha256'],'parent')]
 # Durable supplement: HMAC is checked by the caller before passing payload; index must be the signed member.
 if (not isinstance(durable_payload,dict) or durable_payload.get('kind')!='host-recovery-helper-delta' or
     durable_payload.get('status')!='passed' or durable_payload.get('parentManifestId')!=PARENT_ID or
     durable_payload.get('parentManifestDigest')!=PARENT_DIGEST or durable_payload.get('parentReceiptSha256')!=PARENT_RECEIPT or
     durable_payload.get('parentEncryptedSha256')!='f036f5a4a3f344f84425f6d7c2722a943d7d7087ee3b78b528c5dc1bc316d58d' or
     durable_payload.get('encryptedSha256')!='dbbdf35d04751465b6a3154dbea4f2a984213909aac01b61d6f0f3fa726599c6' or
     durable_receipt_sha!=DURABLE_SUPPLEMENT_RECEIPT_SHA or durable_index_sha!=DURABLE_INDEX_SHA or not isinstance(durable_index,dict) or
     durable_index.get('schema')!='platform.durable-volume-supplement/v2' or durable_index.get('productionModified') is not False or
     len(durable_index.get('files',[]))!=32):
  raise Blocked('DURABLE_SUPPLEMENT_BINDING')
 signed_index=[x for x in durable_payload.get('files',[]) if isinstance(x,dict) and x.get('name')=='durable-volumes/index.json']
 if len(signed_index)!=1 or signed_index[0]!={'name':'durable-volumes/index.json','bytes':4916,'sha256':DURABLE_INDEX_SHA}:
  raise Blocked('DURABLE_INDEX_NOT_SIGNED')
 durable_rows={x.get('name'):x for x in durable_index.get('files',[]) if isinstance(x,dict)}
 if len(durable_rows)!=len(durable_index.get('files',[])):raise Blocked('DURABLE_INDEX_DUPLICATE')
 durable_targets={'persistent:alertmanager':'alertmanager','persistent:attachments':'attachments',
                  'persistent:grafana':'grafana','persistent:students-data':'student-data'}
 for target,root in durable_targets.items():
  target_members[target]=[]
  rows=[x for n,x in durable_rows.items() if n==root or n.startswith(root+'/')]
  if not rows:raise Blocked('DURABLE_TARGET_EMPTY:'+target)
  for row in rows:
   member_path='durable-volumes/'+row['name']
   if row.get('type')=='file':
    files=[x for x in durable_payload['files'] if x.get('name')==member_path]
    if len(files)!=1 or (files[0].get('bytes'),files[0].get('sha256'))!=(row.get('bytes'),row.get('sha256')):
     raise Blocked('DURABLE_MEMBER_NOT_IN_HMAC:'+member_path)
    add(durable_map,durable_payload['encryptedSha256'],[target])
    target_members[target].append(_member_target(target,durable_payload['encryptedSha256'],target,member_path,row['sha256'],'parent-durable-supplement'))
   elif row.get('type')!='directory':raise Blocked('DURABLE_INDEX_MEMBER_TYPE')
 # Native state IDs are explicitly derived from the authenticated parent-state archives.
 cc,cc_redis=selected_member('platform-state:control-center-state','./redis-recovery/redis-recovery-current.tar.gz.gpg')
 _,redis_proof=selected_member('platform-state:control-center-state','./redis-recovery/saved-restore-proof.json')
 _,redis_latest_member=selected_member('platform-state:control-center-state','./redis-recovery/latest.json')
 if cc_redis.get('sha256')!='bf117634e237103cf7a5f487ed0ac146e1e7bc95b5b64caca381f09ca5387ff0' or redis_proof.get('sha256')!='5dc844061d0ae86a72f27c85d560b9b68501ea845cb3c276cd0c7299a54f151b':
  raise Blocked('REDIS_PARENT_SUBMEMBER_BINDING')
 if (redis_latest_member.get('sha256')!=REDIS_SIGNED_LATEST_SHA or
     redis_latest_sha!=REDIS_SIGNED_LATEST_SHA or not isinstance(redis_latest,dict) or
     redis_latest.get('encryptedSha256')!=cc_redis['sha256'] or redis_latest.get('encryptedBytes')!=cc_redis['size'] or
     redis_latest.get('status')!='passed' or redis_latest.get('decryptRoundtripVerified') is not True or
     redis_latest.get('allInstancesIsolatedRestoreVerified') is not True):
  raise Blocked('REDIS_SIGNED_LATEST_BINDING')
 if (not isinstance(redis_inner_manifest,dict) or redis_inner_manifest_sha!=REDIS_INNER_MANIFEST_SHA or
     redis_inner_manifest.get('schema')!='platform.redis-recovery/v1' or
     redis_inner_manifest.get('consistency')!='individual Redis instance RDB snapshots; no cross-database atomicity'):
  raise Blocked('REDIS_INNER_MANIFEST_BINDING')
 def redis_instances(doc,require_full_verification=True):
  rows=doc.get('instances')
  if not isinstance(rows,list) or len(rows)!=2:raise Blocked('REDIS_INSTANCE_SET')
  result={}
  for row in rows:
   container=row.get('container') if isinstance(row,dict) else None
   file_by_container={'gf-redis':'gf-redis.rdb','students-beta-redis':'students-beta-redis.rdb'}
   if (not isinstance(row,dict) or row.get('container') not in {'gf-redis','students-beta-redis'} or
       (require_full_verification and row.get('file')!=file_by_container.get(container)) or
       (not require_full_verification and 'file' in row and row.get('file')!=file_by_container.get(container)) or
       type(row.get('bytes')) is not int or row['bytes']<=0 or
       row.get('imageId')!='sha256:3811787313eba226a2ef38658c6ccb91cd5e110edc89c37767de373120a0e5a0' or
       not re.fullmatch('[a-f0-9]{64}',str(row.get('sha256','')))):
    raise Blocked('REDIS_INSTANCE_ROW')
   if require_full_verification and (row.get('rdbCheckPassed') is not True or row.get('isolatedBootPassed') is not True or
       row.get('network')!='none' or row.get('productionRestorePerformed') is not False):
    raise Blocked('REDIS_INSTANCE_VERIFICATION')
   if row['container'] in result:raise Blocked('REDIS_INSTANCE_DUPLICATE')
   result[row['container']]={'file':file_by_container[row['container']],'imageId':row['imageId'],
                             'bytes':row['bytes'],'sha256':row['sha256']}
  if set(result)!={'gf-redis','students-beta-redis'}:raise Blocked('REDIS_INSTANCE_SET')
  return result
 latest_rows=redis_instances(redis_latest);inner_rows=redis_instances(redis_inner_manifest)
 if latest_rows!=inner_rows:raise Blocked('REDIS_LATEST_INNER_MANIFEST_DIFFERS')
 expected_rdbs={'gf-redis':(477,'845e32ac574e3577cfd58db7ef65da9d58320855bf6c4cfcf6bbe4a3e67d7f17'),
                'students-beta-redis':(5484,'366298a001dccdb589c8bec03ab9842b62e46bf3bbf91b5a3720e1256a0fea29')}
 if any((latest_rows[k]['bytes'],latest_rows[k]['sha256'])!=v for k,v in expected_rdbs.items()):
  raise Blocked('REDIS_RDB_SIGNED_DIGESTS')
 if (not isinstance(redis_provider,dict) or redis_provider_sha!=REDIS_PROVIDER_PROOF_SHA or
     redis_provider.get('schema')!='platform.authenticated-redis-provider/v1' or redis_provider.get('status')!='passed' or
     redis_provider.get('parentManifestId')!=PARENT_ID or redis_provider.get('parentManifestDigest')!=PARENT_DIGEST or
     redis_provider.get('encryptedSha256')!=cc_redis['sha256'] or redis_provider.get('currentCiphertextDecrypted') is not True or
     redis_provider.get('stateProofSha256')!='d6e531ec27d34dab5d3bcf5fc25441ba0ad2e553d610d2a8bdd65a71cba5b139' or
     redis_provider.get('allRdbMemberHashesVerified') is not True or redis_provider.get('productionModified') is not False):
  raise Blocked('REDIS_PROVIDER_PROOF_BINDING')
 if redis_instances(redis_provider,False)!=latest_rows:raise Blocked('REDIS_PROVIDER_INSTANCE_DIFFERS')
 if (not isinstance(native_state,dict) or native_state_sha!=NATIVE_STATE_PROOF_SHA or
     native_state.get('schema')!='platform.private-native-state-semantics/v1' or
     native_state.get('parentManifestDigest')!=PARENT_DIGEST or native_state.get('productionModified') is not False or
     native_state.get('providerProofs',{}).get('redis')!=redis_provider_sha):
  raise Blocked('NATIVE_STATE_REDIS_PROOF_BINDING')
 target_members['persistent:redis']=[
  _member_target('persistent:redis',cc['sha256'],'platform-state:control-center-state',
   './redis-recovery/latest.json',redis_latest_member['sha256'],'parent'),
  _member_target('persistent:redis',cc['sha256'],'platform-state:control-center-state',
   './redis-recovery/redis-recovery-current.tar.gz.gpg',cc_redis['sha256'],'parent'),
  _member_target('persistent:redis',cc['sha256'],'platform-state:control-center-state',
   './redis-recovery/redis-recovery-current.tar.gz.gpg!/gf-redis.rdb',latest_rows['gf-redis']['sha256'],'parent'),
 ]
 target_members['persistent:students-redis']=[
  _member_target('persistent:students-redis',cc['sha256'],'platform-state:control-center-state',
   './redis-recovery/latest.json',redis_latest_member['sha256'],'parent'),
  _member_target('persistent:students-redis',cc['sha256'],'platform-state:control-center-state',
   './redis-recovery/redis-recovery-current.tar.gz.gpg',cc_redis['sha256'],'parent'),
  _member_target('persistent:students-redis',cc['sha256'],'platform-state:control-center-state',
   './redis-recovery/redis-recovery-current.tar.gz.gpg!/students-beta-redis.rdb',latest_rows['students-beta-redis']['sha256'],'parent')]
 parent_rustfs=parent_artifacts.get('platform-state:rustfs-data')
 if not isinstance(parent_rustfs,dict) or parent_rustfs.get('sha256')!='2c339f3d47c23eadcfe0de86cb1d4716618484d64c63cf030afd4e84c1f7c85e':
  raise Blocked('RUSTFS_PARENT_ARTIFACT_BINDING')
 if (not isinstance(rustfs_provider,dict) or rustfs_provider_sha!=RUSTFS_PROVIDER_PROOF_SHA or
     rustfs_provider.get('schema')!='platform.authenticated-rustfs-provider/v1' or rustfs_provider.get('status')!='passed' or
     rustfs_provider.get('parentManifestId')!=PARENT_ID or rustfs_provider.get('parentManifestDigest')!=PARENT_DIGEST or
     rustfs_provider.get('artifactSha256')!=parent_rustfs['sha256'] or rustfs_provider.get('currentParentFilesystemVerified') is not True or
     rustfs_provider.get('stagedData')!='/var/lib/platform-isolated-stack-20260930/recovered-inputs/rustfs-parent-tree/restored/data' or
     rustfs_provider.get('productionModified') is not False):raise Blocked('RUSTFS_PROVIDER_BINDING')
 if (not isinstance(rustfs_outer_proof,dict) or rustfs_outer_proof_sha!=RUSTFS_SIGNED_OUTER_PROOF_SHA or
     rustfs_outer_proof.get('schema')!='platform.rustfs-operator-backup/v1' or rustfs_outer_proof.get('status')!='passed' or
     rustfs_outer_proof.get('format')!='rustfs-volume/v1' or rustfs_outer_proof.get('sourceContainer')!='gf-rustfs' or
     rustfs_outer_proof.get('filesystem')!=rustfs_provider.get('filesystem') or
     rustfs_outer_proof.get('encryptedArchiveSha256')!=rustfs_provider.get('encryptedSha256') or
     rustfs_outer_proof.get('plaintextArchiveSha256')!=rustfs_provider.get('plaintextSha256') or
     rustfs_outer_proof.get('restoreBootVerified') is not True or rustfs_outer_proof.get('s3SemanticRestoreVerified') is not True or
     rustfs_outer_proof.get('productionModified') is True):raise Blocked('RUSTFS_SIGNED_OUTER_PROOF_BINDING')
 if (not isinstance(rustfs_tree_index,dict) or rustfs_tree_index_sha!=RUSTFS_TREE_INDEX_SHA or
     rustfs_tree_index.get('schema')!='platform.private-rustfs-extracted-tree-index/v1' or
     rustfs_tree_index.get('artifactSha256')!=parent_rustfs['sha256'] or
     rustfs_tree_index.get('artifactPath')!=parent_rustfs['path'] or
     rustfs_tree_index.get('root')!='/var/lib/platform-isolated-stack-20260930/recovered-inputs/rustfs-parent-tree/restored/data' or
     rustfs_tree_index.get('sourceResourceId')!='platform-state:rustfs-data' or
     rustfs_tree_index.get('signedOuterProofMemberName')!='proof.json' or
     rustfs_tree_index.get('signedOuterProofSha256')!=rustfs_outer_proof_sha or
     not isinstance(rustfs_tree_index.get('entries'),list) or len(rustfs_tree_index['entries'])!=27):
  raise Blocked('RUSTFS_TREE_INDEX_BINDING')
 entries=rustfs_tree_index['entries'];seen=set();regular_bytes=0
 for row in entries:
  if not isinstance(row,dict) or row.get('name') in seen or row.get('type') not in {'file','directory'}:
   raise Blocked('RUSTFS_TREE_INDEX_ROW')
  name=row['name'];parts=name.split('/') if name!='.' else []
  if (not name or name.startswith('/') or '\\' in name or '\x00' in name or '..' in parts or
      type(row.get('bytes')) is not int or row['bytes']<0 or type(row.get('uid')) is not int or
      type(row.get('gid')) is not int or type(row.get('mode')) is not int):raise Blocked('RUSTFS_TREE_INDEX_PATH_OR_METADATA')
  seen.add(name)
  if row['type']=='file':
   if not re.fullmatch('[a-f0-9]{64}',str(row.get('sha256',''))):raise Blocked('RUSTFS_TREE_FILE_SHA')
   regular_bytes+=row['bytes']
  elif row.get('sha256') is not None or row['bytes']!=0:raise Blocked('RUSTFS_TREE_DIRECTORY_ROW')
 if (len(seen)!=27 or regular_bytes!=7663 or
     rustfs_provider.get('filesystem')!={'bytes':7663,'entries':26,'sha256':'9ca23ca3d9f79e8128ae96f2b96c649857144740a0fbdf04d66b1aabd0e4db37'}):
  raise Blocked('RUSTFS_TREE_INDEX_SUMMARY')
 target_members['persistent:rustfs']=[
  _member_target('persistent:rustfs',parent_rustfs['sha256'],'platform-state:rustfs-data',parent_rustfs['path'],parent_rustfs['sha256'],'parent'),
  _member_target('persistent:rustfs',parent_rustfs['sha256'],'platform-state:rustfs-data','proof.json',rustfs_outer_proof_sha,'parent')]
 for row in entries:
  if row['type']=='file':
   target_members['persistent:rustfs'].append(_member_target('persistent:rustfs',parent_rustfs['sha256'],
     'platform-state:rustfs-data','restored/data/'+row['name'],row['sha256'],'parent'))
 final_maps={'parent':finalize(parent_map),'base-completeness':finalize(base_map),'source-overlay':finalize(source_map),
             'parent-durable-supplement':finalize(durable_map)}
 pair_roles={}
 for role,values in final_maps.items():
  for artifact_sha,ids in values.items():
   for rid in ids:pair_roles.setdefault((artifact_sha,rid),set()).add(role)
 for rows in target_members.values():
  for row in rows:
   if row.get('role') not in pair_roles.get((row['artifactSha256'],row['resourceId']),set()):
    raise Blocked('TARGET_MEMBER_ROLE_MISSING')
 return final_maps,resource_ids,source_ids,cold_ids,extra_ids,target_members
