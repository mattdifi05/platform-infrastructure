#!/usr/bin/python3
"""Closed root publisher for one verified, staged completeness attachment.

No capture, service restart, database writes, pruning or configurable endpoint.
The installed parent helper pins this file and the protocol module by SHA-256.
"""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import time
from completeness_producer import _locked, GPG, durable, private, source_index

FILES={'full-runtime.tar.gz','full-runtime-report.json','cold-volumes.tar.gz',
       'source-restore-proof.json','volume-restore-proof.json','image-load-proof.json',
       'coverage.json','RECOVERY.md','recovery/platform-ftps-backup.py',
       'recovery/platform-ftps-restore.py','recovery/completeness_producer.py',
       'recovery/platform-completeness-publisher.py'}
STAGING=Path('/var/lib/platform-ftps-backup')
EXPECTED_KEY=Path('/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase')


def hash_file(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()


def private_root(path):
    if path.resolve()!=path or path.is_symlink(): raise RuntimeError('UNSAFE_PUBLISHER_ROOT')
    for parent in [path,*path.parents]:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
            raise RuntimeError('UNPROTECTED_PUBLISHER_ANCESTOR')
    if path.stat().st_mode&0o077: raise RuntimeError('PRIVATE_PUBLISHER_ROOT_REQUIRED')


def verify_authority(b):
    path=Path('/usr/local/libexec/platform-backup-operator.py')
    info=path.lstat()
    if path.is_symlink() or info.st_uid!=0 or info.st_mode&0o022:
        raise RuntimeError('ROOT_OPERATOR_CODE_REQUIRED')
    spec=importlib.util.spec_from_file_location('publication_authority',path)
    operator=importlib.util.module_from_spec(spec);spec.loader.exec_module(operator)
    document=json.loads(operator.read_regular(operator.TRUST/'admission.json',2*1024*1024))
    operator.verify_signature(document,operator.PUBLIC)
    payload=operator.validate_admission(document,time.time())
    for name,helper in operator.HELPERS.items():
        if operator.sha(operator.read_regular(Path(helper),512*1024,True))!=payload['resources']['operator'][name]:
            raise RuntimeError('PUBLICATION_HELPER_ADMISSION_MISMATCH')
    active=json.loads(operator.read_regular(operator.BROKER_STATE/'active-admission.json'))
    if active!={'generation':payload['generation'],'admissionSha256':operator.sha(operator.canonical(document))}:
        raise RuntimeError('PUBLICATION_ADMISSION_NOT_COMMITTED')
    if 'backup.offsite.sync' not in payload['allowedActions'] or payload['resources']['operator']['helperSha256']!=hash_file(b.__file__):
        raise RuntimeError('PUBLICATION_ACTION_OR_CODE_NOT_BOUND')
    if b.KEY!=EXPECTED_KEY or b.WORK!=STAGING or b.FOLDER!='/server-platform-backups':
        raise RuntimeError('FIXED_PUBLICATION_BINDING_CHANGED')
    key_info=b.KEY.lstat()
    if (b.KEY.is_symlink() or not stat.S_ISREG(key_info.st_mode) or key_info.st_nlink!=1 or
        key_info.st_uid not in (0,1000) or key_info.st_mode&0o077 or not 16<=key_info.st_size<=4096):
        raise RuntimeError('PROTECTED_ENCRYPTION_KEY_REQUIRED')
    return active


def verify_staged(b,source,parent):
    if source.is_symlink() or source.resolve()!=source: raise RuntimeError('SOURCE_SYMLINK_OR_ALIAS')
    if source!=STAGING/'completeness-source'/parent['manifestId']:
        raise RuntimeError('FIXED_SOURCE_POINT_BINDING_REQUIRED')
    for ancestor in [source,source.parent]: private(ancestor,STAGING,True)
    found={p.relative_to(source).as_posix() for p in source.rglob('*') if not p.is_dir()}
    if found!=FILES: raise RuntimeError('EXACT_COMPLETENESS_FILES_REQUIRED')
    files,gaps=source_index(b,source,STAGING)
    hashes={f['name']:f['sha256'] for f in files};sizes={f['name']:f['bytes'] for f in files}
    for name in ('platform-ftps-backup.py','platform-ftps-restore.py',
                 'completeness_producer.py','platform-completeness-publisher.py'):
        if hashes['recovery/'+name]!=hash_file(Path('/usr/local/libexec')/name):
            raise RuntimeError('CURRENT_RECOVERY_CODE_NOT_ARCHIVED')
    report=json.loads((source/'full-runtime-report.json').read_text())
    sources=json.loads((source/'source-restore-proof.json').read_text())
    volumes=json.loads((source/'volume-restore-proof.json').read_text())
    images=json.loads((source/'image-load-proof.json').read_text())
    coverage=json.loads((source/'coverage.json').read_text())
    validate_proofs(report,sources,volumes,images,coverage,hashes,sizes,parent)
    return files,gaps


def validate_proofs(report,sources,volumes,images,coverage,hashes,sizes,parent):
    if (report.get('schema')!='platform.backup-completeness-candidate/v1' or
        report.get('sourceCaptureMode')!='full-current-source-snapshot' or report.get('sourceCount')!=57 or
        report.get('manifestId')!=parent['manifestId'] or report.get('manifestDigest')!=parent['manifestDigest'] or
        report.get('archiveSha256')!=hashes['full-runtime.tar.gz'] or report.get('supplementBytes')!=sizes['full-runtime.tar.gz']):
        raise RuntimeError('FULL_RUNTIME_POINT_PROOF_MISMATCH')
    if (sources.get('status')!='passed' or sources.get('sourceCount')!=57 or sources.get('streamIncluded') is not True or
        sources.get('sourceRestoreVerified') is not True or sources.get('productionModified') is not False or
        sources.get('archiveSha256')!=report['archiveSha256'] or sources.get('manifestId')!=parent['manifestId'] or
        sources.get('manifestDigest')!=parent['manifestDigest']):
        raise RuntimeError('SOURCE_RESTORE_PROOF_INCOMPLETE')
    if (volumes.get('status')!='passed' or volumes.get('snapshotCount')!=6 or
        volumes.get('archiveSha256')!=hashes['cold-volumes.tar.gz'] or volumes.get('archiveBytes')!=sizes['cold-volumes.tar.gz'] or
        volumes.get('aclAndXattrPreserved') is not True or volumes.get('sourceVolumesModified') is not False):
        raise RuntimeError('COLD_VOLUME_RESTORE_PROOF_INCOMPLETE')
    archived_images=[e for e in report.get('entries',[]) if e.get('kind')=='docker-image-archive']
    if (len(archived_images)!=1 or images.get('status')!='passed' or images.get('imageCount')!=34 or
        images.get('platform')!='linux/amd64' or images.get('archiveSha256')!=archived_images[0]['sha256'] or
        images.get('sourceArchiveSha256')!=report['archiveSha256'] or images.get('hostContainersPreserved') is not True or
        images.get('privateDaemonStopped') is not True or images.get('privateNetworkNamespaceConfirmed') is not True or
        images.get('productionDockerSocketUsedForWrites') is not False):
        raise RuntimeError('ISOLATED_NATIVE_IMAGE_PROOF_INCOMPLETE')
    expected_hashes={k:v for k,v in hashes.items() if k not in ('coverage.json','RECOVERY.md')}
    if (coverage.get('schema')!='platform.completeness-material-coverage/v1' or
        coverage.get('manifestId')!=parent['manifestId'] or coverage.get('manifestDigest')!=parent['manifestDigest'] or
        coverage.get('fullyRecoverable') is not False or coverage.get('fileSha256')!=expected_hashes or
        not coverage.get('knownGaps') or coverage.get('atomicSnapshot') is not False):
        raise RuntimeError('COVERAGE_CLAIMS_OR_BINDINGS_DIFFER')


def publish(b,bundle):
    if os.geteuid()!=0 or not b.NAME.fullmatch(bundle): raise RuntimeError('ROOT_EXACT_BUNDLE_REQUIRED')
    os.umask(0o077);private_root(STAGING)
    if b.FREEZE.exists(): raise RuntimeError('OFFSITE_PUBLICATION_FROZEN')
    lock=os.open(STAGING/'transfer.lock',os.O_RDWR|os.O_NOFOLLOW)
    info=os.fstat(lock)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077 or info.st_nlink!=1:
        raise RuntimeError('UNSAFE_GLOBAL_PUBLICATION_LOCK')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);connections=[]
    try:
        authority=verify_authority(b)
        f=b.connect();connections.append(f);b.verify_owner(f)
        listing=b.inventory(f)
        parent_receipt=b.get_json(f,bundle+'.receipt.json');parent=b.verify(parent_receipt)
        if parent.get('bundle')!=bundle: raise RuntimeError('EXACT_PARENT_REQUIRED')
        source=STAGING/'completeness-source'/parent['manifestId']
        verify_staged(b,source,parent)
        def guard():
            if b.FREEZE.exists(): raise RuntimeError('OFFSITE_PUBLICATION_FROZEN')
            if verify_authority(b)!=authority: raise RuntimeError('PUBLICATION_AUTHORITY_DRIFT')
        guard()
        result=_locked(b,f,STAGING,source,parent_receipt,parent,b.KEY,GPG(),b.PART_BYTES,lambda _:None,
                       work_override=STAGING,freeze_override=b.FREEZE,
                       completed_name='completeness-completed-'+parent['manifestId']+'.json',
                       precommit_guard=guard)
        if verify_authority(b)!=authority: raise RuntimeError('PUBLICATION_AUTHORITY_DRIFT_AFTER_COMMIT')
        completed=STAGING/('completeness-completed-'+parent['manifestId']+'.json')
        state=json.loads(completed.read_text());payload=state['payload']
        result.update(schema='platform.root-completeness-publication/v1',realFtpsVerified=True,
                      transport='certificate-verified explicit FTPS',admission=authority,
                      manifestId=parent['manifestId'],manifestDigest=parent['manifestDigest'],
                      encryptedBytes=payload['encryptedBytes'],encryptedSha256=payload['encryptedSha256'],
                      fullyRecoverable=False,productionDataModified=False)
        state['proof']=result;durable(completed,state)
        f=b.connect();connections.append(f);listing=b.inventory(f)
        if parent not in b.points(f,listing) or sum(listing.values())>b.CAP:
            raise RuntimeError('FINAL_PUBLICATION_INVENTORY_MISMATCH')
        result['managedRemoteBytes']=sum(listing.values());result['offsitePublished']=True
        durable(STAGING/'completeness-latest-proof.json',result)
        print(json.dumps(result,sort_keys=True),flush=True)
        return result
    finally:
        for f in connections:
            try: f.quit()
            except Exception: f.close()
        os.close(lock)
