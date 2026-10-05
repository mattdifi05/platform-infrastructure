"""Local g16 producer for the typed metadata sidecar; no import-time IO."""
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
import uuid

import source_metadata_overlay_v3 as overlay

G16_PART_BYTES = 250_000_000
G16_LEDGER_NAME = "source-overlay-g16-inflight.json"
G16_DONE_NAME = "source-overlay-g16-completed.json"
GPG_KEY_PATH = Path('/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase')
MOUNTED_CONFIG_CAPTURE = Path('/var/lib/platform-host-recovery/mounted-config-tree-records.json')
MOUNTED_CONFIG_MODULE_SHA256 = 'adc2406fba1cce0aa4086cc15cd50ac76411c8f4b144cbe33cb8284e1dcda99a'


def _hash(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def _load_mounted_config_module():
    producer_path=Path(__file__).absolute()
    # The producer is normally installed beside the sidecar in the versioned
    # native directory. Some pinned callers load this producer from libexec's
    # flat compatibility path; in that layout its sidecar remains under the
    # exact versioned install root, never beside the flat producer.
    candidates=(producer_path.with_name('mounted_config_sidecar_v5.py'),
                producer_path.parent/'platform-mounted-config-v5'/'native'/'mounted_config_sidecar_v5.py')
    module_path=next((candidate for candidate in candidates if candidate.exists()),None)
    if module_path is None:
        raise RuntimeError('mounted-config module is missing from pinned package layout')
    info=module_path.lstat()
    if (module_path.is_symlink() or module_path.resolve()!=module_path or not stat.S_ISREG(info.st_mode) or
        info.st_uid!=0 or info.st_mode&0o022 or info.st_nlink!=1 or _hash(module_path)!=MOUNTED_CONFIG_MODULE_SHA256):
        raise RuntimeError('mounted-config module pin or custody differs')
    spec=importlib.util.spec_from_file_location('mounted_config_sidecar_v5',module_path)
    if spec is None or spec.loader is None:raise RuntimeError('mounted-config module cannot be loaded')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def _read_mounted_config_capture(path=MOUNTED_CONFIG_CAPTURE):
    path=Path(path)
    if path!=MOUNTED_CONFIG_CAPTURE:raise RuntimeError('mounted-config capture path differs')
    st=path.lstat()
    if (path.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or
        stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1 or st.st_size<=0 or st.st_size>512*1024*1024 or
        path.resolve(strict=True)!=path):raise RuntimeError('mounted-config capture custody differs')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        before=os.fstat(fd);chunks=[];total=0
        while True:
            block=os.read(fd,1024*1024)
            if not block:break
            total+=len(block)
            if total>512*1024*1024:raise RuntimeError('mounted-config capture bound')
            chunks.append(block)
        after=os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
            raise RuntimeError('mounted-config capture changed while read')
        raw=b''.join(chunks)
    finally:os.close(fd)
    module=_load_mounted_config_module()
    try:document=json.loads(raw)
    except (json.JSONDecodeError,UnicodeDecodeError):raise RuntimeError('mounted-config capture JSON invalid') from None
    if module.canonical(document)+b'\n'!=raw:raise RuntimeError('mounted-config capture encoding differs')
    module.descriptor(raw,document)
    return raw,document

def _open_gpg_key(path):
    path=Path(path)
    if path!=GPG_KEY_PATH: raise RuntimeError('recovery key path differs from pinned path')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=1000 or before.st_gid!=1000 or
            stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 0<before.st_size<=65536):
            raise RuntimeError('recovery key metadata differs from pinned UID/GID/mode')
        current=path.lstat()
        if stat.S_ISLNK(current.st_mode) or (before.st_dev,before.st_ino,before.st_uid,before.st_gid,before.st_mode,before.st_nlink)!=(current.st_dev,current.st_ino,current.st_uid,current.st_gid,current.st_mode,current.st_nlink):
            raise RuntimeError('recovery key changed during open')
        if path.resolve(strict=True)!=path: raise RuntimeError('recovery key path is not canonical')
        for parent in (path.parent,*path.parent.parents):
            info=parent.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode): raise RuntimeError('recovery key ancestor alias')
        chunks=[];total=0
        while True:
            block=os.read(fd,4096)
            if not block: break
            total+=len(block)
            if total>65536: raise RuntimeError('recovery key size bound')
            chunks.append(block)
        after=os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
            raise RuntimeError('recovery key changed while reading')
        os.lseek(fd,0,os.SEEK_SET)
        return fd,b''.join(chunks)
    except BaseException:
        os.close(fd);raise


def _fsync_dir(path):
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
    try:os.fsync(fd)
    finally:os.close(fd)


def _private(path, root, directory=False):
    path=Path(path)
    st=path.lstat()
    expected_type = 0o040000 if directory else 0o100000
    if path.is_symlink() or st.st_uid!=0 or st.st_mode&0o077 or (st.st_mode&0o170000)!=expected_type or (not directory and st.st_nlink!=1):
        raise RuntimeError('g16 spool object is not root-private')
    cur=path.parent
    while cur!=root.parent:
        st=cur.lstat()
        if cur.is_symlink() or not cur.is_dir() or st.st_uid!=0 or st.st_mode&0o077:
            raise RuntimeError('g16 spool ancestry is not root-private')
        if cur==root:break
        cur=cur.parent
    if root not in path.parents and path!=root:raise RuntimeError('g16 spool outside fixed work root')


def _parent_base(b, f, parent, owned_names=()):
    listing=b.inventory(f)
    # Ignore only exact objects declared in our authenticated local ledger.
    clean={n:v for n,v in listing.items() if n not in set(owned_names)}
    points=b.points(f,clean)
    if parent not in points:raise RuntimeError('Exact parent recovery point not retained')
    b.verify_exact_parent_receipt(f,parent)
    attachments=b.point_supplements(f,clean,points)[parent['bundle']]
    b.validate_supplement_set(attachments)
    bases=[a for a in attachments if a['kind']=='runtime-completeness-material']
    overlays=[a for a in attachments if a['kind']=='source-metadata-overlay-v4']
    if len(bases)!=1:raise RuntimeError('Exactly one full-runtime base supplement required')
    base=bases[0]
    receipt_sha=hashlib.sha256(b.canonical(b.sign_supplement(base))).hexdigest()
    return listing,base,receipt_sha,overlays


def _write_ledger(path, work_root, state):
    temp=path.with_name(path.name+'.tmp')
    if temp.exists() or temp.is_symlink():raise RuntimeError('g16 ledger temporary already exists; preserve for review')
    with temp.open('x') as out:
        os.chmod(temp,0o600)
        json.dump(state,out,sort_keys=True,separators=(',',':'))
        out.flush();os.fsync(out.fileno())
    os.replace(temp,path);_fsync_dir(work_root)


def _read_ledger(path, work_root):
    if not path.exists() and not path.is_symlink():return None
    _private(path,work_root)
    raw=path.read_bytes()
    if len(raw)>4*1024*1024:raise RuntimeError('g16 ledger exceeds bound')
    state=json.loads(raw)
    if state.get('schema')!='platform.source-overlay-g16-upload-ledger/v1' or not isinstance(state.get('payload'),dict):
        raise RuntimeError('g16 ledger schema invalid; preserve for review')
    work=Path(state.get('workDir',''))
    if work.parent!=work_root or work.is_symlink() or not work.is_dir() or work.resolve()!=work:
        raise RuntimeError('g16 ledger work directory is unsafe')
    _private(work,work_root,directory=True)
    payload=state['payload']
    if state.get('parentManifestDigest')!=payload.get('parentManifestDigest') or state.get('ciphertext')!=payload.get('ciphertext') or state.get('encryptedSha256')!=payload.get('encryptedSha256') or state.get('parts')!=payload.get('parts'):
        raise RuntimeError('g16 ledger bindings differ; preserve for review')
    cipher=work/'overlay.tar.gz.gpg'
    _private(cipher,work_root)
    if _hash(cipher)!=payload['encryptedSha256'] or cipher.stat().st_size!=payload['encryptedBytes']:
        raise RuntimeError('g16 preserved ciphertext differs')
    for part in payload['parts']:
        local=work/part['name'];_private(local,work_root)
        if local.stat().st_size!=part['bytes'] or _hash(local)!=part['sha256']:
            raise RuntimeError('g16 preserved part differs')
    return state


_PACKAGE_MEMBER_SPOOL = {
    'metadata/records.ndjson.gz': 'metadata.records.ndjson.gz',
    'host-capsule/current.gpg': 'host-capsule.current.gpg',
    'mounted-config/records.json': 'mounted-config.records.json',
}


def _validate_and_spool_package_members(package, payload, work, work_root):
    """Validate and durably spool all three non-receipt members for retries."""
    import tarfile
    files = payload.get('files')
    if not isinstance(files, list):
        raise RuntimeError('g16 package member list invalid')
    expected = {row.get('name'): row for row in files if isinstance(row, dict)}
    if len(expected) != len(files) or set(expected) != {'receipt.json', *_PACKAGE_MEMBER_SPOOL}:
        raise RuntimeError('g16 package member set differs')
    seen = set()
    temp_root = Path(tempfile.mkdtemp(prefix='.g16-spool-', dir=work))
    os.chmod(temp_root, 0o700)
    try:
        _private(temp_root, work_root, directory=True)
        with tarfile.open(package, 'r:gz') as tf:
            for member in tf:
                name = member.name
                if name not in expected or name in seen or not member.isfile() or member.issym() or member.islnk():
                    raise RuntimeError('g16 package member type/set differs')
                row = expected[name]
                if type(row.get('bytes')) is not int or row['bytes'] < 0 or member.size != row['bytes']:
                    raise RuntimeError('g16 package member size differs')
                seen.add(name)
                if name == 'receipt.json':
                    h = hashlib.sha256(); count = 0
                    src = tf.extractfile(member)
                    while True:
                        block = src.read(1024 * 1024)
                        if not block: break
                        count += len(block); h.update(block)
                    if count != row['bytes'] or h.hexdigest() != row['sha256']:
                        raise RuntimeError('g16 package receipt member differs')
                    continue
                target = temp_root / _PACKAGE_MEMBER_SPOOL[name]
                h = hashlib.sha256(); count = 0
                src = tf.extractfile(member)
                with target.open('xb') as dst:
                    os.chmod(target, 0o600)
                    while True:
                        block = src.read(1024 * 1024)
                        if not block: break
                        count += len(block)
                        if count > row['bytes']: raise RuntimeError('g16 package member exceeds bound')
                        h.update(block); dst.write(block)
                    dst.flush(); os.fsync(dst.fileno())
                if count != row['bytes'] or h.hexdigest() != row['sha256']:
                    raise RuntimeError('g16 package member digest differs')
        if seen != set(expected): raise RuntimeError('g16 package member missing')
        for name, spool_name in _PACKAGE_MEMBER_SPOOL.items():
            destination = work / spool_name
            if destination.exists() or destination.is_symlink():
                raise RuntimeError('g16 retry spool already exists; preserve for review')
            os.replace(temp_root / spool_name, destination)
            _fsync_dir(work_root)
    finally:
        # The temporary directory is private and contains only freshly-created
        # validated spool files; destination files are moved out above.
        shutil.rmtree(temp_root)


def _validate_retry_spool(work, work_root, payload):
    expected = {row.get('name'): row for row in payload.get('files', []) if isinstance(row, dict)}
    if len(expected) != len(payload.get('files', [])) or set(expected) != {'receipt.json', *_PACKAGE_MEMBER_SPOOL}:
        raise RuntimeError('g16 retry package member set differs')
    for member_name, spool_name in _PACKAGE_MEMBER_SPOOL.items():
        member_path = work / spool_name
        _private(member_path, work_root)
        row = expected[member_name]
        if member_path.stat().st_size != row['bytes'] or _hash(member_path) != row['sha256']:
            raise RuntimeError('g16 preserved package member source differs')


def _verify_remote_parts(b, f, payload):
    observations=[]
    for part in payload['parts']:
        digest=hashlib.sha256();received=0
        def collect(chunk):
            nonlocal received
            received+=len(chunk)
            if received>part['bytes']:raise RuntimeError('completed g16 part exceeds bound')
            digest.update(chunk)
        f.retrbinary('RETR '+part['name'],collect,blocksize=1024*1024)
        if received!=part['bytes'] or digest.hexdigest()!=part['sha256']:
            raise RuntimeError('completed g16 part readback differs')
        observations.append({'name':part['name'],'bytes':received,'sha256':digest.hexdigest()})
    return observations


def _refresh_parent_session(b, old_f, bundle, parent, base, base_receipt_sha, owned_names):
    """Reopen TLS after local capture/GPG work and revalidate its exact point group."""
    try:old_f.close()
    except Exception:pass
    f=b.connect();b.verify_owner(f)
    _,fresh_base,fresh_receipt,fresh_overlays=_parent_base(b,f,parent,owned_names)
    if (parent.get('bundle')!=bundle or fresh_base!=base or fresh_receipt!=base_receipt_sha):
        try:f.close()
        except Exception:pass
        raise RuntimeError('g16 parent or completeness base changed during local preparation')
    return f,fresh_overlays


def _reconcile_committed(b, f, state, work_root, parent, base, base_receipt,
                         remote_overlay, ledger_path=None):
    payload=state['payload']
    if (not isinstance(payload,dict) or remote_overlay!=payload or
        state.get('parentManifestDigest')!=parent['manifestDigest'] or
        payload.get('baseCompletenessEncryptedSha256')!=base['encryptedSha256'] or
        payload.get('baseCompletenessReceiptSha256')!=base_receipt):
        raise RuntimeError('g16 completed evidence differs from authenticated remote attachment')
    observations=_verify_remote_parts(b,f,payload)
    state['receiptCommitted']=True
    if ledger_path is not None:
        _write_ledger(ledger_path,work_root,state)
        done=work_root/(G16_DONE_NAME+'-'+payload['encryptedSha256'][:16]+'.json')
        if done.exists() or done.is_symlink():raise RuntimeError('g16 completed evidence already exists')
        os.replace(ledger_path,done);_fsync_dir(work_root)
    return {'schema':'platform.g16-native-publisher-readback/v1','status':'published-readback-verified','fullyRecoverable':False,
            'parentManifestId':parent['manifestId'],'encryptedSha256':payload['encryptedSha256'],
            'encryptedBytes':payload['encryptedBytes'],'partCount':len(payload['parts']),
            'receipt':payload['ciphertext']+'.receipt.json','offsiteVerified':True,
            'automaticMetadataApplication':False,'reconciledAfterCommit':True,
            'receiptDocument':b.sign(parent),'baseCompletenessDocument':b.sign_supplement(base),
            'overlayReceiptDocument':b.sign_supplement(payload),'parentReceiptSha256':hashlib.sha256(b.canonical(b.sign(parent))).hexdigest(),
            'baseCompletenessReceiptSha256':base_receipt,'overlayReceiptSha256':hashlib.sha256(b.canonical(b.sign_supplement(payload))).hexdigest(),
            'remoteReceiptReadbackVerified':True,'remotePartReadback':observations,
            'sourceArchiveSha256':parent['encryptedSha256'],'sourceOverlaySha256':payload['encryptedSha256'],
            'baseArchiveSha256':payload['baseArchiveSha256'],'baseArchiveBytes':payload['baseArchiveBytes'],
            'hostCapsuleSha256':payload['capsuleSha256'],'hostCapsuleProofSha256':payload['capsuleProofSha256']}


def _reconcile_existing_attachment(b, f, existing_overlays, state, ledger, work_root,
                                   parent, base, base_receipt):
    if len(existing_overlays)!=1:
        raise RuntimeError('multiple g16 overlays exist; preserve and stop')
    remote_overlay=existing_overlays[0]
    evidence_path=(ledger if state else
        work_root/(G16_DONE_NAME+'-'+remote_overlay['encryptedSha256'][:16]+'.json'))
    if not evidence_path.exists() or evidence_path.is_symlink():
        raise RuntimeError('existing g16 overlay lacks exact local completion evidence; no recapture')
    evidence=_read_ledger(evidence_path,work_root)
    if not evidence.get('receiptCommitted') and evidence_path!=ledger:
        raise RuntimeError('completed g16 evidence lacks durable commit marker')
    return _reconcile_committed(b,f,evidence,work_root,parent,base,base_receipt,
                               remote_overlay,ledger if evidence_path==ledger else None)


def build_source_overlay(b, parent, base, base_receipt_sha, live_root, v1_root,
                         expected_sources_path, capsule_path, capsule_sha, capsule_proof_sha,
                         work_root, key_bytes, source_proof_path):
    work_root=Path(work_root);live_root=Path(live_root);v1_root=Path(v1_root)
    mapping=overlay.load_expected_sources(Path(expected_sources_path),live_root)
    archives=[m for m in base.get('files',[]) if m.get('name')=='full-runtime.tar.gz']
    if len(archives)!=1 or type(archives[0].get('bytes')) is not int or not re.fullmatch('[a-f0-9]{64}',str(archives[0].get('sha256',''))):
        raise RuntimeError('authenticated base must contain exactly one full-runtime.tar.gz member')
    source_proof=json.loads(Path(source_proof_path).read_text())
    if (source_proof.get('status')!='passed' or source_proof.get('sourceCount')!=57 or
        source_proof.get('manifestDigest')!=parent['manifestDigest'] or
        source_proof.get('archiveSha256')!=archives[0]['sha256'] or
        Path(source_proof.get('restoredRoot','')).resolve()!=v1_root.resolve()):
        raise RuntimeError('extracted source root is not bound to this parent/base proof')
    capture=overlay.capture_overlay(live_root,v1_root,parent['manifestDigest'],base['encryptedSha256'],
                                   base_receipt_sha,Path(capsule_path),capsule_sha,capsule_proof_sha,mapping,
                                   archives[0]['sha256'],archives[0]['bytes'])
    hmac_key=key_bytes
    sidecar_module=_load_mounted_config_module()
    sidecar_bytes,sidecar_document=_read_mounted_config_capture()
    inner_receipt,index=overlay.sign_receipt(capture,hmac_key)
    v5_payload=sidecar_module.extend_signed_payload(inner_receipt['payload'],sidecar_bytes,sidecar_document)
    receipt=sidecar_module.sign_v5_receipt(v5_payload,hmac_key)
    package=work_root/'source-overlay-package.tar.gz'
    cap_sha,cap_bytes,members=sidecar_module.build_v5_package(
        receipt,index,Path(capsule_path),sidecar_bytes,package)
    payload={
        'schema':'platform.ftps-source-metadata-overlay/v4','status':'passed','kind':'source-metadata-overlay-v4',
        'parentManifestId':parent['manifestId'],'parentManifestDigest':parent['manifestDigest'],
        'parentReceiptSha256':hashlib.sha256(b.canonical(b.sign(parent))).hexdigest(),
        'parentEncryptedSha256':parent['encryptedSha256'],'backupAt':parent['backupAt'],
        'ciphertext':'pending','encryptedBytes':0,'encryptedSha256':'0'*64,'parts':[],
        'verifiedAt':None,'fullyRecoverable':False,
        'knownGaps':['global restore not executed','metadata application remains on private restore staging'],
        'baseCompletenessCiphertext':base['ciphertext'],
        'baseCompletenessEncryptedSha256':base['encryptedSha256'],
        'baseCompletenessReceiptSha256':base_receipt_sha,
        'baseArchiveSha256':archives[0]['sha256'],'baseArchiveBytes':archives[0]['bytes'],
        'overlayPackageSha256':cap_sha,
        'overlayReceiptSha256':hashlib.sha256(sidecar_module.canonical(receipt)).hexdigest(),
        'sourceMapSha256':receipt['payload']['sourceCapture']['sourceMapSha256'],
        'metadataIndexSha256':receipt['payload']['metadataIndex']['sha256'],
        'metadataIndexRawSha256':receipt['payload']['metadataIndex']['rawSha256'],
        'metadataIndexCompressedBytes':receipt['payload']['metadataIndex']['compressedBytes'],
        'metadataIndexRawBytes':receipt['payload']['metadataIndex']['rawBytes'],
        'metadataRecordCount':receipt['payload']['metadataIndex']['recordCount'],
        'capsuleSha256':receipt['payload']['capsule']['ciphertextSha256'],
        'capsuleProofSha256':receipt['payload']['capsule']['proofSha256'],'files':members,
        'mountedConfigCapture':sidecar_module.descriptor(sidecar_bytes,sidecar_document),
    }
    return package,payload


def encrypt_split(b, package, payload, work, key_fd, parent, part_bytes=G16_PART_BYTES):
    if type(part_bytes) is not int or not 1_000_000<=part_bytes<=b.PART_BYTES:
        raise RuntimeError('g16 part size outside allowed range')
    sidecar_module=_load_mounted_config_module()
    home=sidecar_module.new_short_gpg_home()
    cipher=work/'overlay.tar.gz.gpg'
    try:
        subprocess.run(['gpg','--no-options','--homedir',str(home),'--batch','--yes','--pinentry-mode','loopback',
                        '--passphrase-file',f'/proc/self/fd/{key_fd}','--symmetric','--cipher-algo','AES256','--output',str(cipher),str(package)],
                       capture_output=True,check=True,pass_fds=(key_fd,),timeout=120)
    finally:
        sidecar_module.cleanup_short_gpg_home(home)
    os.chmod(cipher,0o600)
    with cipher.open('rb') as f:os.fsync(f.fileno())
    size=cipher.stat().st_size;digest=_hash(cipher)
    if not 0<size<=b.CAP:raise RuntimeError('g16 encrypted package exceeds hard cap')
    logical=f"{parent['bundle']}.supplement-source-v4-{digest[:16]}.tar.gz.gpg"
    parts=[]
    with cipher.open('rb') as source:
        while source.tell()<size:
            i=len(parts);target=work/(logical+'.part'+str(i).zfill(3));remaining=min(part_bytes,size-source.tell());h=hashlib.sha256()
            with target.open('xb') as output:
                os.chmod(target,0o600)
                while remaining:
                    block=source.read(min(1024*1024,remaining))
                    if not block:raise RuntimeError('g16 ciphertext split truncated')
                    output.write(block);h.update(block);remaining-=len(block)
                output.flush();os.fsync(output.fileno())
            parts.append({'name':target.name,'bytes':target.stat().st_size,'sha256':h.hexdigest()})
            if len(parts)>70:raise RuntimeError('g16 part count exceeds native bound')
    payload.update(ciphertext=logical,encryptedBytes=size,encryptedSha256=digest,parts=parts)
    return cipher


def remote_part_size(f, name):
    """Use SIZE even when MLSD hides a server-side partial object."""
    try:
        f.voidcmd('TYPE I')
        size=f.size(name)
        return int(size) if size is not None else None
    except Exception as exc:
        text=str(exc).lower()
        if '550' in text or 'not found' in text or 'unavailable' in text:
            return None
        raise


def upload_part_resumable(b, f, local, remote, expected_bytes, reserve_bytes=131072, attempts=5):
    """Resume an owned exact part from FTP SIZE, including MLSD-hidden files."""
    import ftplib
    for attempt in range(attempts):
        try:
            visible=b.inventory(f).get(remote)
            direct=remote_part_size(f,remote)
            offset=direct if direct is not None else visible if visible is not None else 0
            if visible is not None and direct is not None and visible!=direct:
                raise RuntimeError('Remote part SIZE/MLSD disagreement')
            if not 0<=offset<=expected_bytes:raise RuntimeError('Remote hidden part exceeds owned expected size')
            listing=b.inventory(f)
            hidden_occupied=offset if visible is None and direct is not None else 0
            if sum(listing.values())+hidden_occupied+(expected_bytes-offset)+reserve_bytes>b.CAP:
                raise RuntimeError('Resumed g16 upload exceeds hard cap')
            if offset<expected_bytes:
                with Path(local).open('rb') as source:
                    source.seek(offset)
                    f.storbinary(('APPE ' if offset else 'STOR ')+remote,source,blocksize=1024*1024)
            direct=remote_part_size(f,remote)
            if direct is None: direct=b.inventory(f).get(remote)
            if direct!=expected_bytes:raise RuntimeError('Resumed g16 part SIZE differs')
            return f
        except (OSError,EOFError,ftplib.Error):
            try:f.close()
            except Exception:pass
            if attempt+1==attempts:raise
            time.sleep(2);f=b.connect()
    raise RuntimeError('g16 upload attempts exhausted')


def publish_source_overlay(b, bundle, live_root, v1_root, expected_sources_path,
                           capsule_path, capsule_proof_path, work_root, key_path, source_proof_path, precommit_guard=None):
    """Publish one g16 extension; resume only from an exact private ledger."""
    if os.geteuid() != 0:
        raise RuntimeError('g16 source overlay requires root')
    work_root=Path(work_root).absolute();work_root.mkdir(mode=0o700,parents=True,exist_ok=True)
    info=work_root.lstat()
    if work_root.is_symlink() or not work_root.is_dir() or work_root.resolve()!=work_root or info.st_uid!=0 or info.st_mode&0o077:
        raise RuntimeError('g16 work root must be canonical root-private directory')
    ledger=work_root/G16_LEDGER_NAME
    state=_read_ledger(ledger,work_root)
    owned=([x['name'] for x in state['payload']['parts']]+[state['payload']['ciphertext']+'.receipt.json.partial']) if state else []
    capsule_path=Path(capsule_path);capsule_proof_path=Path(capsule_proof_path)
    work=Path(state['workDir']) if state else work_root/('capture-'+uuid.uuid4().hex)
    if not state:
        work.mkdir(mode=0o700);os.chmod(work,0o700);_fsync_dir(work_root)
    with (work/'operation.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        f=b.connect()
        key_fd,key_bytes=_open_gpg_key(key_path)
        try:
            b.verify_owner(f)
            if precommit_guard is not None:precommit_guard(None)
            listing=b.inventory(f)
            remote_receipt=(state['payload']['ciphertext']+'.receipt.json') if state else None
            already_committed=bool(state and remote_receipt in listing)
            discovery_owned=([remote_receipt+'.partial'] if already_committed else owned)
            # A previous failed run may leave only exact locally-owned parts.
            # Every other unknown object remains visible to normal inventory.
            clean={n:v for n,v in listing.items() if n not in set(discovery_owned)}
            points=b.points(f,clean)
            parents=[p for p in points if p.get('bundle')==bundle]
            if len(parents)!=1: raise RuntimeError('exact authenticated parent must be retained')
            parent=parents[0]
            listing,base,base_receipt,existing_overlays=_parent_base(b,f,parent,discovery_owned)
            if existing_overlays:
                return _reconcile_existing_attachment(b,f,existing_overlays,state,ledger,work_root,
                                                      parent,base,base_receipt)
            if state:
                payload=state['payload']
                if payload['parentManifestDigest']!=parent['manifestDigest'] or payload['baseCompletenessEncryptedSha256']!=base['encryptedSha256'] or payload['baseCompletenessReceiptSha256']!=base_receipt:
                    raise RuntimeError('g16 resume parent/base differs from exact ledger')
                package=work/'source-overlay-package.tar.gz'
                _private(package,work_root)
                if _hash(package)!=payload['overlayPackageSha256']:
                    raise RuntimeError('g16 preserved package differs')
                _validate_retry_spool(work, work_root, payload)
            else:
                capsule_proof=json.loads(capsule_proof_path.read_text())
                capsule_sha=_hash(capsule_path);proof_sha=_hash(capsule_proof_path)
                if capsule_proof.get('encryptedSha256') != capsule_sha or capsule_proof.get('status') != 'passed':
                    raise RuntimeError('latest host capsule proof does not bind current ciphertext')
                package,payload=build_source_overlay(b,parent,base,base_receipt,Path(live_root),Path(v1_root),
                    Path(expected_sources_path),capsule_path,capsule_sha,proof_sha,work,key_bytes,Path(source_proof_path))
                # Save every non-receipt package member needed for an exact
                # retry; never rebuild ciphertext after remote parts may exist.
                _validate_and_spool_package_members(package, payload, work, work_root)
                encrypt_split(b,package,payload,work,key_fd,parent)
                payload['verifiedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat()
                state={'schema':'platform.source-overlay-g16-upload-ledger/v1','parentManifestDigest':parent['manifestDigest'],
                       'ciphertext':payload['ciphertext'],'encryptedSha256':payload['encryptedSha256'],
                       'parts':payload['parts'],'completedParts':[],'receiptCommitted':False,
                       'workDir':str(work),'payload':payload}
                _write_ledger(ledger,work_root,state)
                owned=[x['name'] for x in payload['parts']]+[payload['ciphertext']+'.receipt.json.partial']
            f,fresh_overlays=_refresh_parent_session(b,f,bundle,parent,base,base_receipt,owned)
            if fresh_overlays:
                raise RuntimeError('g16 overlay appeared during local preparation; preserve and reconcile on next run')
            if precommit_guard is not None:precommit_guard(payload)
            listing,objects,receipt_name=reserve_overlay(b,f,payload,parent,owned_names=owned)
            state.setdefault('completedParts',[])
            remote_observations=[]
            for part in payload['parts']:
                if precommit_guard is not None:precommit_guard(payload)
                local=work/part['name'];remote=part['name']
                f=upload_part_resumable(b,f,local,remote,part['bytes'])
                digest=hashlib.sha256();received=0
                def collect(chunk):
                    nonlocal received
                    received+=len(chunk)
                    if received>part['bytes']: raise RuntimeError('remote g16 part exceeds bound')
                    digest.update(chunk)
                f.retrbinary('RETR '+remote,collect,blocksize=1024*1024)
                if received!=part['bytes'] or digest.hexdigest()!=part['sha256']:
                    raise RuntimeError('remote g16 part readback differs')
                remote_observations.append({'name':part['name'],'bytes':received,'sha256':digest.hexdigest()})
                if part['name'] not in state['completedParts']:
                    state['completedParts'].append(part['name']);_write_ledger(ledger,work_root,state)
            if set(state['completedParts'])!={p['name'] for p in payload['parts']}:
                raise RuntimeError('g16 upload ledger is incomplete')
            f.close();f=b.connect();b.verify_owner(f)
            if precommit_guard is not None:precommit_guard(payload)
            f=b.publish_supplement_receipt(payload,parent,precommit_guard=lambda: precommit_guard(payload) if precommit_guard is not None else None)
            state['receiptCommitted']=True;_write_ledger(ledger,work_root,state)
            final_listing=b.inventory(f);final_points=b.points(f,final_listing)
            attached=b.point_supplements(f,final_listing,final_points).get(parent['bundle'],[])
            match=[item for item in attached if item.get('kind')=='source-metadata-overlay-v4']
            if len(match)!=1 or match[0]['encryptedSha256']!=payload['encryptedSha256']:
                raise RuntimeError('g16 point attachment readback differs')
            done=work_root/(G16_DONE_NAME+'-'+payload['encryptedSha256'][:16]+'.json')
            if done.exists() or done.is_symlink():raise RuntimeError('g16 completed evidence already exists')
            os.replace(ledger,done);_fsync_dir(work_root)
            overlay_document=b.sign_supplement(payload)
            parent_document=b.sign(parent)
            base_document=b.sign_supplement(base)
            return {'schema':'platform.g16-native-publisher-readback/v1','status':'published-readback-verified','fullyRecoverable':False,
                    'parentManifestId':parent['manifestId'],'encryptedSha256':payload['encryptedSha256'],
                    'encryptedBytes':payload['encryptedBytes'],'partCount':len(payload['parts']),
                    'receipt':receipt_name,'offsiteVerified':True,'automaticMetadataApplication':False,
                    'receiptDocument':parent_document,'baseCompletenessDocument':b.sign_supplement(base),
                    'overlayReceiptDocument':overlay_document,
                    'parentReceiptSha256':hashlib.sha256(b.canonical(parent_document)).hexdigest(),
                    'baseCompletenessReceiptSha256':base_receipt,
                    'overlayReceiptSha256':hashlib.sha256(b.canonical(overlay_document)).hexdigest(),
                    'remoteReceiptReadbackVerified':True,'remotePartReadback':remote_observations,
                    'sourceArchiveSha256':parent['encryptedSha256'],'sourceOverlaySha256':payload['encryptedSha256'],
                    'baseArchiveSha256':payload['baseArchiveSha256'],'baseArchiveBytes':payload['baseArchiveBytes'],
                    'hostCapsuleSha256':payload['capsuleSha256'],'hostCapsuleProofSha256':payload['capsuleProofSha256']}
        finally:
            try:f.close()
            except Exception:pass
            os.close(key_fd)


def reserve_overlay(b, f, payload, parent, owned_names=()):
    b.verify_supplement(b.sign_supplement(payload),parent,staged=True)
    listing=b.inventory(f)
    clean={n:v for n,v in listing.items() if n not in set(owned_names)}
    points=b.points(f,clean)
    if parent not in points:raise RuntimeError('g16 parent point is not authenticated')
    b.verify_exact_parent_receipt(f,parent)
    attachments=b.point_supplements(f,clean,points)[parent['bundle']]
    b.validate_supplement_set([*attachments,payload])
    objects=b.supplement_objects(payload);receipt=payload['ciphertext']+'.receipt.json'
    extra=sum(size for name,size in objects.items() if name not in listing)
    reserved=b.supplement_receipt_bytes({**payload,'verifiedAt':'9999-12-31T23:59:59.999999+00:00'})
    if receipt not in listing:extra+=len(reserved)
    if sum(listing.values())+extra>b.CAP:raise RuntimeError('g16 overlay reservation exceeds cap; existing points preserved')
    for name,size in objects.items():
        if name in listing:
            if name in set(owned_names) and not 0<=listing[name]<=size:raise RuntimeError('g16 owned remote part exceeds expected size')
            if name not in set(owned_names) and listing[name]!=size:raise RuntimeError('g16 existing remote part conflicts')
    return listing,objects,receipt
