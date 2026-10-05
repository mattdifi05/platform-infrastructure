#!/usr/bin/python3
"""Package and independently extract the six private cold snapshots only."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from cold_volume_capture import ROOT, DEST, JOURNAL, FIXED, atomic, volume_tree
from source_adapter import _safe_link, _safe_relative


def main():
    if os.geteuid()!=0 or ROOT.is_symlink() or ROOT.stat().st_uid!=0 or ROOT.stat().st_mode&0o077:
        raise SystemExit('ROOT_PRIVATE_VOLUME_STAGING_REQUIRED')
    os.umask(0o077)
    state=json.loads(JOURNAL.read_text());subjects=[r[0] for r in FIXED]
    rows={r['subject']:r for r in state['snapshots']}
    if state.get('status')!='passed' or set(rows)!=set(subjects) or state.get('active'):
        raise SystemExit('SIX_VERIFIED_COLD_COPIES_REQUIRED')
    if DEST.is_symlink() or set(p.name for p in DEST.iterdir())!=set(subjects):
        raise SystemExit('EXACT_VOLUME_SNAPSHOT_SET_REQUIRED')
    total=sum(r['regularBytes'] for r in rows.values())
    if shutil.disk_usage(ROOT).free<3*total+2_000_000_000: raise SystemExit('VOLUME_PACKAGE_DISK_HEADROOM')
    out=ROOT/'cold-volume-snapshots.tar.gz'
    restored=ROOT/'isolated-volume-restored'
    if out.exists() or restored.exists(): raise SystemExit('NEW_VOLUME_PACKAGE_REQUIRED')
    for subject,row in rows.items():
        current=volume_tree(DEST/subject)
        if any(current[k]!=row[k] for k in current): raise RuntimeError('COLD_SNAPSHOT_DRIFT')
    fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
    subprocess.run(['tar','--numeric-owner','--acls','--xattrs','--format=pax','-czf',str(out),
                    '-C',str(DEST),*subjects],check=True,timeout=180,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    with out.open('rb') as stream: digest=hashlib.file_digest(stream,'sha256').hexdigest()
    count=0;regular_bytes=0;seen=set();root_subjects=set()
    with tarfile.open(out,'r:gz') as tf:
        for member in tf:
            parts=_safe_relative(member.name)
            if parts[0] not in rows or member.name in seen or not (member.isdir() or member.isfile() or member.issym()):
                raise RuntimeError('UNSAFE_OR_DUPLICATE_VOLUME_MEMBER')
            seen.add(member.name);count+=1
            if count>50000: raise RuntimeError('VOLUME_MEMBER_LIMIT')
            if len(parts)==1:
                if not member.isdir(): raise RuntimeError('VOLUME_ROOT_NOT_DIRECTORY')
                root_subjects.add(parts[0])
            if member.issym(): _safe_link(member.name,member.linkname)
            if member.isfile():
                if member.size<0: raise RuntimeError('VOLUME_NEGATIVE_FILE_SIZE')
                regular_bytes+=member.size
                if regular_bytes>total: raise RuntimeError('VOLUME_EXPANSION_LIMIT')
    if root_subjects!=set(subjects) or regular_bytes!=total:
        raise RuntimeError('VOLUME_ARCHIVE_COVERAGE_MISMATCH')
    for subject,row in rows.items():
        current=volume_tree(DEST/subject)
        if any(current[k]!=row[k] for k in current): raise RuntimeError('COLD_SNAPSHOT_DRIFT')
    scratch=Path(tempfile.mkdtemp(prefix='.isolated-volume-',dir=ROOT))
    try:
        subprocess.run(['tar','--numeric-owner','--same-permissions','--acls','--xattrs','--xattrs-include=*',
                        '-xzf',str(out),'-C',str(scratch)],check=True,timeout=180,
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for subject,row in rows.items():
            current=volume_tree(scratch/subject)
            if any(current[k]!=row[k] for k in current): raise RuntimeError('EXTRACTED_VOLUME_HASH_MISMATCH')
        os.replace(scratch,restored)
    except BaseException:
        shutil.rmtree(scratch);raise
    with out.open('rb') as stream:
        if hashlib.file_digest(stream,'sha256').hexdigest()!=digest: raise RuntimeError('VOLUME_ARCHIVE_DRIFT')
    proof={'schema':'platform.isolated-six-volume-restore/v1','status':'passed',
           'capturedAt':state['completedAt'],'verifiedAt':dt.datetime.now(dt.timezone.utc).isoformat(),
           'snapshotCount':6,'subjects':subjects,'regularBytes':total,'archiveBytes':out.stat().st_size,
           'archiveSha256':digest,'memberCount':count,'aclAndXattrPreserved':True,
           'sourceTreeHashes':{s:r['treeSha256'] for s,r in rows.items()},
           'isolatedRestoredRoot':str(restored),'sourceVolumesModified':False,
           'applicationStartupVerified':False,'fullyRecoverable':False,'offsitePublished':False}
    atomic(ROOT/'isolated-volume-restore-proof.json',proof)
    print(json.dumps(proof,sort_keys=True),flush=True)


if __name__=='__main__': main()
