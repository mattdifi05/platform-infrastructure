#!/usr/bin/python3
"""Verify the immutable G15 recovery record copied into a downloaded G16 capsule."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile

PARENT_ID='manifest-scheduled-platform-20260929-182357-1f9954'
PARENT_DIGEST='baf72a7c4ff5d2266b71afe4865ebffeb8be6c363dfc31c12f3a865389009b2c'
PARENT_RECEIPT='1868a512b5a47fe9cc4808622dfb4707d8fe988b0a1d523f801c12ad4c419030'
BASE_ARCHIVE='77de6d262d269db484aa48fbe63ca064a151a9c5ecc081374bf9be4d3e034987'
RECORD_PATH='/var/lib/platform-host-recovery/recovery-records/'+PARENT_ID
MAX_RECORD_BYTES=600_000_000
MAX_INNER_BYTES=1_000_000_000
ARTIFACTS={
 'oldExtraTreesArchiveSha256':'6ed00c6e14abf23cb7d84ae9e4453206d5e33c8aaee7b37cb3485b20995ff8e3',
 'oldExtraTreesIndexSha256':'3f032c289a77460aaaa7bfa9613a581e7d448cb6970b132343f0a19ae15ab7ce',
 'oldExtraTreesProofSha256':'c03827eb9e24a101218185cd2f4052f4130760ba659d251514d60d918b3e4a14',
 'extendedCapsuleSha256':'9fa5cf40056cb166cc2e3d5103c8bd0dc3548c4554b9e51f10976e887af23360',
 'extendedCapsuleProofSha256':'b166bae6283f3bd8a3271d8d556926b44828d08553c36ede5720dd726c06f194',
 'extendedCapsulePreparedProofSha256':'4909ca488290c5fdc8e8885b83aee2b1bdd3df0892be890fb9349ba914987869',
 'extendedCapsuleFileStagingProofSha256':'0176a8b4a6dee70deb82b3807326e3ab0602fdfaeed237874c221afd00cfcaf3',
 'extendedCapsulePlaintextSha256':'bc356f5e6e7ab1dbcf1581c445bff41b3f5051004931672f053f271ebccb43f0',
 'extraControlCenterDumpSha256':'f59b6803635b9232032a9f078bba472a18fa9797ceb28346c6c3da5a29b6e44a',
 'extraPhpmyadminDumpSha256':'69dd358680066c3765a5ed05b83774da81c60d327ecd164e4de605be60df111a',
 'extraDatabaseCaptureProofSha256':'b697f9765daf54ea183d5114d261c244f41bd52d5e562618d4842c76e1f62218',
 'extraDatabaseBundleSha256':'e282ff9de94559703906bfd31a74a3759a6950a0900a97eba94e6c5baa612fe6',
 'sourceMetadataCompressedSha256':'951d2ffdd3eb56e44245bee03b7e2eafdd10d0b4758db4fc19dfd9434fe0150d',
 'sourceMetadataPrescanProofSha256':'5ce7fc3cf7603262a2fa51e8f057e73de6b8bae247fe3deb56deaa7f1b710972',
 'sourceMetadataApplyProofSha256':'5da76d15fc06b71ef23ed339a1d86a61f02acc000f40b30c5b9151213ea18c4d',
 'expectedSourcesSha256':'7ca377a9e7e724c4aa475d2fda8f75402c4836113dd83af405c0d597732d3605',
 'expiredCacheDescriptorSha256':'31a788278a35f189770996f4c224e1c67f9a7bb3223447e90ac7ae85354665f2',
}
SQL_MEMBERS={
 'extra-databases/control_center.dump':(16_714_093,'f59b6803635b9232032a9f078bba472a18fa9797ceb28346c6c3da5a29b6e44a'),
 'extra-databases/phpmyadmin.sql':(20_335,'69dd358680066c3765a5ed05b83774da81c60d327ecd164e4de605be60df111a'),
}
SQL_CAPTURE_PROOF=('extra-databases/capture-proof.json',1_645,'b697f9765daf54ea183d5114d261c244f41bd52d5e562618d4842c76e1f62218')
SQL_CURRENT_MEMBER='host/var/lib/platform-host-recovery/extra-database-exports/current.tar'
SQL_LATEST_PROOF_MEMBER='host/var/lib/platform-host-recovery/extra-database-exports/latest-proof.json'
SQL_BUNDLE_BYTES=16_742_400
SQL_LATEST_PROOF_BYTES=461
SQL_LATEST_PROOF_SHA='a17d16c14aa2c68cea18d38a6f6d20bd1dee9b59c8c0e3838b1130edd3ceba22'
SQL_LATEST_PROOF_BUNDLE_SHA='46b014dc2479f0f668f6ed7eafee2194f913a6ac9f7218957150359c7b88b5a8'
SQL_ARCHIVED_PROOF_BYTES=1_646
SQL_ARCHIVED_PROOF_SHA='42c10bcfffca251e141be7729301bb822dd2aa4e9207b0c5302ea7efebcf75f1'
EXTENDED_REGULAR_FILES=4_895
EXTENDED_DIRECTORY_COUNT=504
EXTENDED_SYMLINK_COUNT=170
EXTENDED_ENTRY_COUNT=5_569
# Exact runtime member set observed in the SHA0176 index of the SHA9fa capsule.
# File bytes, owner/group/mode are also checked against that full pinned index.
HISTORICAL_RUNTIME_FILES=frozenset({
 'runtime/broker-config/redis-users.acl',
 'runtime/broker-config/redis-users.acl.sha256',
 'runtime/container-inspect.json',
 'runtime/ip-address.json',
 'runtime/ip-routes.json',
 'runtime/ip6tables.rules',
 'runtime/iptables.rules',
 'runtime/mariadb-users-grants.sql',
 'runtime/packages.tsv',
 'runtime/pg_hba.conf',
 'runtime/pg_ident.conf',
 'runtime/postgres-globals.sql',
 'runtime/postgres-live-config-paths.json',
 'runtime/postgresql.auto.conf',
 'runtime/postgresql.conf',
 'runtime/server-ai-admin-operations.sqlite',
 'runtime/server-ai-admin-state.json',
})
LINUX_LITERAL_BACKSLASH_MEMBERS={
 'host/etc/systemd/system/snap-canonical\\x2dlivepatch-414.mount',
 'host/etc/systemd/system/multi-user.target.wants/snap-canonical\\x2dlivepatch-414.mount',
 'host/etc/systemd/system/snapd.mounts.target.wants/snap-canonical\\x2dlivepatch-414.mount',
}
CONFIG_MEMBERS=(
 'host/etc/machine-id',
 'host/etc/platform-infrastructure/server-ai/controller-registry.json',
 'host/etc/platform-infrastructure/server-ai/db-anniversary-anniversary-ro.json',
 'host/etc/platform-infrastructure/server-ai/db-fiplatform-fiplatform-ro.json',
 'host/etc/platform-infrastructure/server-ai/db-fiplatform-u778675014-fip-ro.json',
 'host/etc/platform-infrastructure/server-ai/db-stexor-postgres-stexor-ro.json',
 'host/etc/platform-infrastructure/server-ai/db-stream-stream-ro.json',
 'host/etc/platform-infrastructure/server-ai/db-workcalendar-workcalendar-ro.json',
 'host/etc/platform-infrastructure/server-ai/infrastructure-inventory.json',
 'host/etc/platform-infrastructure/server-ai/infrastructure-token',
 'host/etc/platform-infrastructure/server-ai/project-readers-token',
 'host/home/platform_infrastructure/server-ai-provision-20260906/config/server-ai/search/settings.yml',
)
class Blocked(RuntimeError):pass
def digest(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def private_file(path,limit):
 p=Path(path);st=p.lstat()
 if p.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=__import__('os').geteuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600 or not 0<st.st_size<=limit:raise Blocked('RECORD_FILE_PROTECTION')
 return st
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
def _member_hash(tar,member,limit):
 if not member.isfile() or member.size<0 or member.size>limit:raise Blocked('NESTED_MEMBER_TYPE_OR_SIZE')
 source=tar.extractfile(member)
 if source is None:raise Blocked('NESTED_MEMBER_UNREADABLE')
 h=hashlib.sha256();count=0
 for b in iter(lambda:source.read(1024*1024),b''):
  count+=len(b)
  if count>member.size or count>limit:raise Blocked('NESTED_MEMBER_STREAM_LIMIT')
  h.update(b)
 if count!=member.size:raise Blocked('NESTED_MEMBER_SIZE_MISMATCH')
 return count,h.hexdigest()

def scan_indexed_capsule_tar(path,files,links,expected_counts=None):
 """Hash regular members and record indexed symlink names without following them."""
 seen={};seen_links=set();seen_dirs=set();total=0;entry_count=0
 try:
  with tarfile.open(path,'r|gz') as tar:
   for m in tar:
    entry_count+=1
    if entry_count>30_000:raise Blocked('INNER_CAPSULE_MEMBER_COUNT')
    name=m.name.removeprefix('./').rstrip('/') if m.isdir() else m.name.removeprefix('./')
    if not name or name.startswith('/') or '..' in Path(name).parts or ('\\' in name and name not in LINUX_LITERAL_BACKSLASH_MEMBERS) or '\x00' in name:raise Blocked('INNER_CAPSULE_PATH')
    if m.isfile():
     row=files.get(name);size,digest_value=_member_hash(tar,m,2_000_000_000);total+=size
     if total>2_000_000_000:raise Blocked('INNER_CAPSULE_TOTAL_SIZE')
     if (not isinstance(row,dict) or row.get('bytes')!=size or row.get('sha256')!=digest_value or
         (m.uid,m.gid,m.mode)!=(row.get('uid'),row.get('gid'),row.get('mode')) or name in seen or name in seen_links or name in seen_dirs):raise Blocked('INNER_CAPSULE_FILE_INDEX_DIFFERS')
     seen[name]={'bytes':size,'sha256':digest_value}
    elif m.issym():
     if name not in links or name in seen_links or name in seen or name in seen_dirs or '\x00' in m.linkname or len(m.linkname.encode('utf-8','surrogatepass'))>4096:raise Blocked('INNER_CAPSULE_UNINDEXED_LINK')
     seen_links.add(name)
    elif m.isdir():
     if name in seen_dirs or name in seen or name in seen_links:raise Blocked('INNER_CAPSULE_DUPLICATE')
     seen_dirs.add(name)
    else:raise Blocked('INNER_CAPSULE_LINK_OR_SPECIAL')
 except (OSError,tarfile.TarError):raise Blocked('INNER_CAPSULE_PARSE_FAILED') from None
 if set(seen)!=set(files) or seen_links!=set(links):raise Blocked('INNER_CAPSULE_INDEX_SET_DIFFERS')
 result={'regularFiles':len(seen),'directories':len(seen_dirs),'symlinks':len(seen_links),'symlinkNames':sorted(seen_links),'entries':entry_count,'regularBytes':total,'members':seen}
 if expected_counts is not None and any(result.get(k)!=v for k,v in expected_counts.items()):raise Blocked('INNER_CAPSULE_COUNTS_DIFFERS')
 return result

def validate_historical_index(idx):
 """Validate the index only after its full0176 byte digest was checked by caller."""
 files=idx.get('files')
 links=idx.get('linksNotMaterialized')
 if (idx.get('schema')!='platform.extended-capsule-file-staging/v1' or idx.get('noLinksFollowed') is not True or
     idx.get('regularFiles')!=EXTENDED_REGULAR_FILES or idx.get('entries')!=EXTENDED_ENTRY_COUNT or
     not isinstance(files,dict) or len(files)!=EXTENDED_REGULAR_FILES or
     not isinstance(links,list) or len(links)!=EXTENDED_SYMLINK_COUNT):raise Blocked('FILE_STAGING_INDEX_INVALID')
 expected_links=[];link_names=set()
 for link in links:
  if not isinstance(link,dict) or set(link)!={'name','type'} or link.get('type')!='symlink':raise Blocked('FILE_STAGING_LINK_DESCRIPTOR_INVALID')
  name=link['name']
  if not isinstance(name,str) or name.startswith('/') or '..' in Path(name).parts or ('\\' in name and name not in LINUX_LITERAL_BACKSLASH_MEMBERS) or not name.startswith('host/'):raise Blocked('FILE_STAGING_LINK_PATH_INVALID')
  if name in link_names or name in files:raise Blocked('FILE_STAGING_LINK_DUPLICATE')
  link_names.add(name);expected_links.append({'name':name,'type':'symlink'})
 for name,row in files.items():
  if (not isinstance(name,str) or name.startswith('/') or '..' in Path(name).parts or ('\\' in name and name not in LINUX_LITERAL_BACKSLASH_MEMBERS) or
      not (name.startswith('host/') or name in HISTORICAL_RUNTIME_FILES) or not isinstance(row,dict) or set(row)!={'sha256','bytes','uid','gid','mode'} or
      type(row.get('bytes')) is not int or row['bytes']<0 or not re.fullmatch('[a-f0-9]{64}',str(row.get('sha256',''))) or
      any(type(row.get(k)) is not int or row[k]<0 for k in ('uid','gid','mode'))):raise Blocked('FILE_STAGING_FILE_ROW_INVALID')
 if {name for name in files if name.startswith('runtime/')}!=HISTORICAL_RUNTIME_FILES:raise Blocked('HISTORICAL_RUNTIME_MEMBER_SET')
 if sum(name.startswith('host/') for name in files)!=4_878 or idx.get('regularBytes')!=sum(row['bytes'] for row in files.values()):raise Blocked('FILE_STAGING_INDEX_TOTALS')
 return files,link_names

def verify_stale_latest_proof(latest):
 # The pinned historical latest-proof names the previous manual capture. It
 # is preserved as history, never used to authenticate the included SQL tar.
 if not isinstance(latest,dict) or latest.get('bundleSha256')!=SQL_LATEST_PROOF_BUNDLE_SHA or latest.get('status')!='passed':raise Blocked('HISTORICAL_SQL_LATEST_PROOF_STALE_BINDING')
 return {'databaseLatestProofStaleForIncludedBundle':True,
         'databaseLatestProofUsedAsAttestation':False,
         'databaseLatestProofBundleSha256':latest['bundleSha256']}

def verify_embedded_capture_proof(embedded,capture):
 if not isinstance(embedded,dict) or embedded!=capture:raise Blocked('HISTORICAL_SQL_PROOF_SEMANTIC_DIFFERS')

def verify_inner_capsule(record_dir):
 d=Path(record_dir);cipher=d/'extended-capsule/host-recovery-current.tar.gz.gpg';outerproof=d/'extended-capsule/host-recovery-proof.json';prepared=d/'extended-capsule/prepared-proof.json';file_index=d/'extended-capsule/file-staging-proof.json';plain=d/'extended-capsule/capsule.tar.gz'
 for f in (cipher,outerproof,prepared,file_index,plain):private_file(f,MAX_INNER_BYTES)
 if digest(cipher)!=ARTIFACTS['extendedCapsuleSha256'] or digest(outerproof)!='b166bae6283f3bd8a3271d8d556926b44828d08553c36ede5720dd726c06f194' or digest(prepared)!=ARTIFACTS['extendedCapsulePreparedProofSha256'] or digest(file_index)!=ARTIFACTS['extendedCapsuleFileStagingProofSha256'] or digest(plain)!='bc356f5e6e7ab1dbcf1581c445bff41b3f5051004931672f053f271ebccb43f0':raise Blocked('HISTORICAL_CAPSULE_DIGEST')
 prep=json.loads(prepared.read_bytes());idx=json.loads(file_index.read_bytes());proof=json.loads(outerproof.read_bytes())
 if prep.get('schema')!='platform.extended-capsule-private-stage/v1' or prep.get('status')!='passed' or prep.get('encryptedSha256')!=ARTIFACTS['extendedCapsuleSha256'] or prep.get('plaintextArchiveSha256')!=digest(plain) or prep.get('fileStagingProofSha256')!=ARTIFACTS['extendedCapsuleFileStagingProofSha256'] or prep.get('offsiteVerified') is not False:raise Blocked('PREPARED_PROOF_BINDING')
 if proof.get('encryptedSha256')!=digest(cipher) or proof.get('plaintextArchiveSha256')!=digest(plain) or proof.get('status')!='passed':raise Blocked('CAPSULE_PROOF_BINDING')
 files,link_names=validate_historical_index(idx)
 required={SQL_CURRENT_MEMBER,SQL_LATEST_PROOF_MEMBER}|set(CONFIG_MEMBERS)
 if not required<=set(files):raise Blocked('HISTORICAL_SQL_OR_CONFIG_OMITTED')
 bundle_row=files[SQL_CURRENT_MEMBER];latest_row=files[SQL_LATEST_PROOF_MEMBER]
 if bundle_row.get('bytes')!=SQL_BUNDLE_BYTES or bundle_row.get('sha256')!=ARTIFACTS['extraDatabaseBundleSha256'] or latest_row.get('bytes')!=SQL_LATEST_PROOF_BYTES or latest_row.get('sha256')!=SQL_LATEST_PROOF_SHA:raise Blocked('HISTORICAL_SQL_CAPSULE_INDEX_BINDING')
 scanned=scan_indexed_capsule_tar(plain,files,link_names)
 seen=scanned['members']
 if (scanned['directories']!=EXTENDED_DIRECTORY_COUNT or scanned['regularFiles']!=EXTENDED_REGULAR_FILES or
     scanned['symlinks']!=EXTENDED_SYMLINK_COUNT or scanned['entries']!=EXTENDED_ENTRY_COUNT):raise Blocked('INNER_CAPSULE_INDEX_SET_DIFFERS')
 for name in CONFIG_MEMBERS:
  if name not in seen:raise Blocked('HISTORICAL_CONFIG_MEMBER_MISSING')
 if seen.get(SQL_CURRENT_MEMBER)!={'bytes':SQL_BUNDLE_BYTES,'sha256':ARTIFACTS['extraDatabaseBundleSha256']} or seen.get(SQL_LATEST_PROOF_MEMBER)!={'bytes':SQL_LATEST_PROOF_BYTES,'sha256':SQL_LATEST_PROOF_SHA}:raise Blocked('HISTORICAL_SQL_CAPSULE_MEMBERS')
 latest_member=None
 with tarfile.open(plain,'r|gz') as tar:
  for member in tar:
   if member.name.removeprefix('./')==SQL_LATEST_PROOF_MEMBER:
    if member.size>4_096:raise Blocked('HISTORICAL_SQL_LATEST_PROOF_BOUND')
    latest_member=json.load(tar.extractfile(member));break
 latest_identity=verify_stale_latest_proof(latest_member)
 sql_proof_path=d/'extended-capsule/extra-databases/capture-proof.json'
 private_file(sql_proof_path,1_000_000)
 if digest(sql_proof_path)!=SQL_CAPTURE_PROOF[2] or sql_proof_path.stat().st_size!=SQL_CAPTURE_PROOF[1]:raise Blocked('HISTORICAL_SQL_CAPTURE_PROOF_DIGEST')
 sqlproof=json.loads(sql_proof_path.read_bytes())
 if sqlproof.get('schema')!='platform.host-extra-database-exports/v1' or sqlproof.get('status')!='passed' or sqlproof.get('readOnly') is not True or sqlproof.get('productionDatabaseWrites') is not False or sqlproof.get('databaseCount')!=2 or sqlproof.get('combinedDumpBytes')!=16_734_428 or sqlproof.get('bundleFilename')!='current.tar':raise Blocked('HISTORICAL_SQL_CAPTURE_PROOF_INVALID')
 expected_db={'control_center':('postgres','control_center.dump',16_714_093,'f59b6803635b9232032a9f078bba472a18fa9797ceb28346c6c3da5a29b6e44a',19),'phpmyadmin':('mariadb','phpmyadmin.sql',20_335,'69dd358680066c3765a5ed05b83774da81c60d327ecd164e4de605be60df111a',19)}
 dbs=sqlproof.get('databases')
 if not isinstance(dbs,list) or len(dbs)!=2:raise Blocked('HISTORICAL_SQL_DATABASE_SET')
 for db in dbs:
  name=db.get('name'); expected=expected_db.get(name)
  if expected is None or db.get('engine')!=expected[0] or db.get('dump',{}).get('filename')!=expected[1] or db.get('dump',{}).get('bytes')!=expected[2] or db.get('dump',{}).get('sha256')!=expected[3] or db.get('tableCount')!=expected[4] or db.get('readOnlyCatalogStable') is not True:raise Blocked('HISTORICAL_SQL_DATABASE_PROOF')
 if {x.get('name') for x in dbs}!=set(expected_db):raise Blocked('HISTORICAL_SQL_DATABASE_NAMES')
 bundle=record_dir/'extended-capsule/extra-databases/current.tar'
 private_file(bundle,536_870_912)
 if digest(bundle)!=ARTIFACTS['extraDatabaseBundleSha256']:raise Blocked('HISTORICAL_SQL_BUNDLE_DIGEST')
 bundle_members={}
 try:
  with tarfile.open(bundle,'r|') as tar:
   for n,m in enumerate(tar,1):
    if n>16 or not m.isfile() or m.name in bundle_members:raise Blocked('HISTORICAL_SQL_BUNDLE_MEMBER_SET')
    size,sha=_member_hash(tar,m,536_870_912);bundle_members[m.name]={'bytes':size,'sha256':sha}
 except (OSError,tarfile.TarError):raise Blocked('HISTORICAL_SQL_BUNDLE_PARSE') from None
 if bundle_members!={'control_center.dump':{'bytes':16_714_093,'sha256':expected_db['control_center'][3]},'phpmyadmin.sql':{'bytes':20_335,'sha256':expected_db['phpmyadmin'][3]},'proof.json':{'bytes':SQL_ARCHIVED_PROOF_BYTES,'sha256':SQL_ARCHIVED_PROOF_SHA}}:raise Blocked('HISTORICAL_SQL_BUNDLE_CONTENTS')
 with tarfile.open(bundle,'r:') as tar:
  embedded=json.load(tar.extractfile('proof.json'))
 verify_embedded_capture_proof(embedded,sqlproof)
 if sqlproof.get('combinedDumpBytes')!=sum(v[2] for v in expected_db.values()):raise Blocked('HISTORICAL_SQL_BUNDLE_PROOF_BINDING')
 if bundle.stat().st_size!=SQL_BUNDLE_BYTES:raise Blocked('HISTORICAL_SQL_BUNDLE_SIZE')
 return {'cipherSha256':digest(cipher),'plaintextSha256':digest(plain),'fileStagingProofSha256':digest(file_index),'databaseCount':2,'databaseMembersVerified':True,'databaseCaptureProofSha256':digest(sql_proof_path),'databaseBundleSha256':digest(bundle),**latest_identity,'databaseAttestationSource':'exact-current.tar-embedded-proof-and-dump-hashes','configurationMembersVerified':len(CONFIG_MEMBERS),'innerFileCount':len(seen),'innerDirectoryCount':scanned['directories'],'innerSymlinkCount':scanned['symlinks'],'innerEntryCount':scanned['entries'],'runtimeMemberCount':len(HISTORICAL_RUNTIME_FILES),'runtimeMembersVerified':sorted(HISTORICAL_RUNTIME_FILES),'offsiteVerified':False}
def verify_record(record_dir, expected_parent=None):
 d=Path(record_dir);st=d.lstat()
 if d.is_symlink() or not stat.S_ISDIR(st.st_mode) or st.st_uid!=__import__('os').geteuid() or stat.S_IMODE(st.st_mode)!=0o700:raise Blocked('RECORD_DIR_PROTECTION')
 if sorted(p.name for p in d.iterdir())!=['current.tar','index.json','proof.json']:raise Blocked('RECORD_OUTER_MEMBER_SET')
 archive=d/'current.tar';index=d/'index.json';proof=d/'proof.json'
 ast=private_file(archive,MAX_RECORD_BYTES);ist=private_file(index,16*1024*1024);pst=private_file(proof,1_000_000)
 idx=json.loads(index.read_bytes());pr=json.loads(proof.read_bytes())
 if idx.get('schema')!='platform.historical-recovery-record-index/v1' or idx.get('status')!='historical-inputs-verified' or idx.get('historicalParent')!={'manifestId':PARENT_ID,'manifestDigest':PARENT_DIGEST,'receiptSha256':PARENT_RECEIPT,'sourceArchiveSha256':BASE_ARCHIVE} or idx.get('artifactSha256')!=ARTIFACTS or idx.get('productionModified') is not False or idx.get('offsiteVerified') is not False:raise Blocked('RECORD_INDEX_BINDING')
 if pr.get('schema')!='platform.historical-recovery-record-proof/v1' or pr.get('historicalParent')!=idx['historicalParent'] or pr.get('archiveBytes')!=ast.st_size or pr.get('archiveSha256')!=digest(archive) or pr.get('indexSha256')!=digest(index):raise Blocked('RECORD_PROOF_BINDING')
 expected={r['name']:r for r in idx.get('members',[])}
 expected_names={'historical-extra-trees/current.tar','historical-extra-trees/index.json','historical-extra-trees/proof.json','extended-capsule/host-recovery-current.tar.gz.gpg','extended-capsule/host-recovery-proof.json','extended-capsule/prepared-proof.json','extended-capsule/file-staging-proof.json','extended-capsule/capsule.tar.gz','extended-capsule/extra-databases/control_center.dump','extended-capsule/extra-databases/phpmyadmin.sql','extended-capsule/extra-databases/capture-proof.json','extended-capsule/extra-databases/current.tar','source-metadata/metadata-records.ndjson.gz','source-metadata/prescan-proof.json','source-metadata/expected-sources.json','source-metadata/expired-cache-descriptor.json','source-metadata/private-apply-proof.json'}
 if set(expected)!=expected_names or idx.get('memberCount')!=len(expected_names):raise Blocked('RECORD_INDEX_MEMBERS')
 if idx.get('artifactSha256')!=ARTIFACTS or set(idx.get('artifactBytes',{}))!=set(ARTIFACTS):raise Blocked('RECORD_ARTIFACT_SHA_SET')
 member_to_artifact={
  'historical-extra-trees/current.tar':'oldExtraTreesArchiveSha256','historical-extra-trees/index.json':'oldExtraTreesIndexSha256','historical-extra-trees/proof.json':'oldExtraTreesProofSha256',
  'extended-capsule/host-recovery-current.tar.gz.gpg':'extendedCapsuleSha256','extended-capsule/host-recovery-proof.json':'extendedCapsuleProofSha256','extended-capsule/prepared-proof.json':'extendedCapsulePreparedProofSha256','extended-capsule/file-staging-proof.json':'extendedCapsuleFileStagingProofSha256','extended-capsule/capsule.tar.gz':'extendedCapsulePlaintextSha256','extended-capsule/extra-databases/control_center.dump':'extraControlCenterDumpSha256','extended-capsule/extra-databases/phpmyadmin.sql':'extraPhpmyadminDumpSha256','extended-capsule/extra-databases/capture-proof.json':'extraDatabaseCaptureProofSha256','extended-capsule/extra-databases/current.tar':'extraDatabaseBundleSha256',
  'source-metadata/metadata-records.ndjson.gz':'sourceMetadataCompressedSha256','source-metadata/prescan-proof.json':'sourceMetadataPrescanProofSha256','source-metadata/private-apply-proof.json':'sourceMetadataApplyProofSha256','source-metadata/expected-sources.json':'expectedSourcesSha256','source-metadata/expired-cache-descriptor.json':'expiredCacheDescriptorSha256'}
 for row in idx.get('members',[]):
  key=member_to_artifact.get(row.get('name'))
  if key is not None and (idx['artifactBytes'].get(key)!=row.get('bytes') or idx['artifactSha256'].get(key)!=row.get('sha256')):raise Blocked('RECORD_ARTIFACT_MEMBER_BINDING')
 seen={};nested_root=None
 try:
  with tarfile.open(archive,'r|') as tar:
   with tempfile.TemporaryDirectory(prefix='historical-record-readback-',dir=d.parent) as nested_name:
    nested_root=Path(nested_name);os.chmod(nested_root,0o700)
    for n,m in enumerate(tar,1):
     if n>100:raise Blocked('RECORD_MEMBER_COUNT')
     if not m.isfile() or m.name in seen or m.name.startswith('/') or '..' in Path(m.name).parts:raise Blocked('RECORD_MEMBER_PATH_OR_TYPE')
     if m.size<0 or m.size>MAX_RECORD_BYTES:raise Blocked('RECORD_MEMBER_SIZE_BOUND')
     target=nested_root/m.name
     target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
     src=tar.extractfile(m)
     if src is None:raise Blocked('RECORD_MEMBER_UNREADABLE')
     fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
     h=hashlib.sha256();count=0
     with os.fdopen(fd,'wb') as out:
      for block in iter(lambda:src.read(1024*1024),b''):
       count+=len(block)
       if count>m.size or count>MAX_RECORD_BYTES:raise Blocked('RECORD_MEMBER_SIZE_BOUND')
       out.write(block);h.update(block)
      out.flush();os.fsync(out.fileno())
     if count!=m.size:raise Blocked('RECORD_EXTRACTED_MEMBER_SIZE')
     seen[m.name]={'name':m.name,'bytes':count,'sha256':h.hexdigest()}
    if seen!=expected:raise Blocked('RECORD_ARCHIVE_DIGESTS')
    nested=verify_inner_capsule(nested_root)
 except (OSError,tarfile.TarError):raise Blocked('RECORD_ARCHIVE_INVALID') from None
 if seen!=expected:raise Blocked('RECORD_ARCHIVE_DIGESTS')
 if expected_parent is not None and expected_parent!={'manifestId':PARENT_ID,'manifestDigest':PARENT_DIGEST,'receiptSha256':PARENT_RECEIPT}:raise Blocked('RECORD_EXPECTED_PARENT_DIFFERS')
 return {'status':'passed','schema':'platform.recovery-record-content/v1','source':'verified-local-record-content','remoteReadbackVerified':False,'decryptedAfterReadback':False,'recordPath':RECORD_PATH,'historicalParentManifestId':PARENT_ID,'historicalParentManifestDigest':PARENT_DIGEST,'historicalParentReceiptSha256':PARENT_RECEIPT,'historicalSourceArchiveSha256':BASE_ARCHIVE,'artifactSha256':ARTIFACTS,'artifactSetSha256':hashlib.sha256(json.dumps(ARTIFACTS,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'indexSha256':digest(index),'archiveMemberPath':RECORD_PATH+'/current.tar','indexMemberPath':RECORD_PATH+'/index.json','proofMemberPath':RECORD_PATH+'/proof.json','recordMemberSha256':digest(archive),'capsuleMemberSha256':digest(archive),'proofSha256':digest(proof),'memberCount':len(seen),'extendedCapsuleVerified':nested,'productionModified':False,'offsiteVerified':False}
