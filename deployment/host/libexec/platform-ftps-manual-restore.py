#!/usr/bin/env python3
"""Local candidate only. Exact-point staging works; production promotion is disabled.

JSON stdin protocol. No caller-supplied command, path, endpoint, key or image.
All files written by the CLI are confined to the fixed root-private candidate state.
"""
import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import uuid

STATE = Path('/var/lib/platform-manual-restore-candidate')
DATA = Path('/home/platform_infrastructure/v1-fresh-runtime/local-private-backup/data/backups')
MANIFEST = re.compile(r'manifest-[a-z0-9][a-z0-9-]{15,127}')
DIGEST = re.compile(r'[0-9a-f]{64}')
PLAN = re.compile(r'[0-9a-f]{32}')
HELPERS = {
 '/usr/local/libexec/platform-ftps-backup.py': 'ffcaaf6f40a7994cf859309607484c3ed4c83dce3302f51a0f1231e1d26e2181',
 '/usr/local/libexec/platform-ftps-restore.py': '53e0bf9c602d708ac5355fb65ef4fe1eb825829ce2352146eb6871c6f6be690f',
 '/usr/local/libexec/platform-rustfs-restore.py': '9a7579dc65ab881072fbc3abe1464904a2c81177cd2d9b8483645e95fa5588c9',
 '/usr/local/libexec/platform-local-dedup.py': 'bda1185196e8688cc7e1f54178edce57f904107cb098407ea8a6b78a58577276',
 '/usr/local/libexec/platform_backup_safe_state.py': 'd2a781d6665ca7ce68081c85b3e3adbe1fdd82f2bece188fc9cb797689eba5b7',
 '/usr/local/libexec/verify-local-dedup-input.mjs': '25f0a552acf2404dadc59694c688a5a7097de2c0dbab825f120a8015a56f7c20',
 '/usr/local/libexec/platform-host-recovery-verify-historical-record.py': '800eca18ff492250b948bc6997c9111016741052f26cadac289b33e1ea8c60c9',
 '/usr/local/libexec/prescan_source_metadata_g16_v3.py': '372626ffd93aa8944e1078ead094d30b9d6ca62a333fb16e99d9bf2017d62d9a',







 '/usr/local/libexec/platform-native-point-readback.py': 'bedf996c8bf5ee5d0c7e57e1086e7e104543480887b063c9ceffa9412acc5f22',
 '/usr/local/libexec/platform-mounted-config-v5/native/g16_overlay_native.py': 'ae35f52e33cb03d1621a7b98ee897bdcf3723ad69dffe3ed48baff76d03e8581',
 '/usr/local/libexec/platform-mounted-config-v5/native/source_metadata_overlay_producer_g16.py': '5e49d27bbee688d519570b3d7d1c7168a7c92c03e6025aa5de468f60ef200f50',
 '/usr/local/libexec/platform-mounted-config-v5/native/source_metadata_overlay_v3.py': '30bfde6ae7d68d8ed22f016e67f2bf23f2bbc79933b6047f4201eed536cdd79d',
 '/usr/local/libexec/platform-mounted-config-v5/native/mounted_config_sidecar_v5.py': 'adc2406fba1cce0aa4086cc15cd50ac76411c8f4b144cbe33cb8284e1dcda99a',
 '/usr/local/libexec/platform-mounted-config-v5/native/expected-sources.json': '7ca377a9e7e724c4aa475d2fda8f75402c4836113dd83af405c0d597732d3605',
 '/usr/local/libexec/platform-mounted-config-v5/native/stream-expired-cache-descriptor-actual.json': '31a788278a35f189770996f4c224e1c67f9a7bb3223447e90ac7ae85354665f2',
 '/usr/local/libexec/platform-mounted-config-v5/native/g16-pins.json': '7c57d994d4b53fcea94dd3c0d495c64829043303149f12be06b14ce602c7b137',
 '/usr/local/libexec/platform-mounted-config-g17/native/g17-pins.json': '709879c17509cdb4a3dc82711dae013d15e4766481624e80b2b9be3b7c23c320',
 '/usr/local/libexec/platform-mounted-config-g17/native/g16_overlay_native.py': '45c7263951fde86bc064c425e9224c233ce73669d88b4aa1f0e02c81e2b5db60',
 '/usr/local/libexec/platform-mounted-config-g17/native/mounted_config_sidecar_v5.py': '7aa7e21c927317e9c5a384099d59f23d991ecddc447c1f2a8d1cad1bf81bf178',
 '/usr/local/libexec/platform-mounted-config-g17/native/source_metadata_overlay_producer_g16.py': 'ea3f572ae42bf78447e4bc392732c80f51cb916a01361086a452c6ec4878bcee',
 '/usr/local/libexec/platform-mounted-config-g17/native/source_metadata_overlay_v3.py': '30bfde6ae7d68d8ed22f016e67f2bf23f2bbc79933b6047f4201eed536cdd79d',
 '/usr/local/libexec/platform-mounted-config-g17/native/expected-sources.json': '7ca377a9e7e724c4aa475d2fda8f75402c4836113dd83af405c0d597732d3605',
 '/usr/local/libexec/platform-mounted-config-g17/native/stream-expired-cache-descriptor-actual.json': '31a788278a35f189770996f4c224e1c67f9a7bb3223447e90ac7ae85354665f2',
}
BLOCKERS = ['SIGNED_FORWARD_ADMISSION_REQUIRED', 'PRODUCTION_RESOURCE_ADAPTERS_UNIMPLEMENTED',
            'PREAPPLY_SNAPSHOT_AND_ROLLBACK_NOT_PROVEN', 'WHOLE_SERVER_RECOVERY_NOT_PROVEN']

class RestoreError(Exception):
    pass

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def read_regular(path, limit=2*1024*1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise RestoreError('INVALID_FILE')
        return stream.read(limit+1)

def relative_path(value):
    path = PurePosixPath(value)
    if not value or path.is_absolute() or '..' in path.parts or path.as_posix() != value:
        raise RestoreError('UNSAFE_ARTIFACT_PATH')
    return path

def safe_source(root, value):
    path = root
    for part in relative_path(value).parts:
        path = path / part
        if path.is_symlink():
            raise RestoreError('SYMLINK_ARTIFACT_PATH')
    if not path.is_file():
        raise RestoreError('MISSING_ARTIFACT')
    return path

def parse_point(point_id, digest):
    if not isinstance(point_id, str) or ':' not in point_id or not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise RestoreError('INVALID_POINT')
    source, manifest_id = point_id.split(':', 1)
    if source not in ('local', 'ftps') or not MANIFEST.fullmatch(manifest_id):
        raise RestoreError('INVALID_POINT')
    return source, manifest_id

def coverage(manifest):
    """No payload data exposed; identify every resource requiring a typed adapter."""
    artifacts = manifest.get('artifacts', [])
    ids = [item['resourceId'] for item in artifacts]
    if not ids or len(ids) != len(set(ids)) or not manifest.get('coverage', {}).get('complete'):
        raise RestoreError('INCOMPLETE_OR_DUPLICATE_RESOURCE_COVERAGE')
    return sorted(ids)

class InstalledProvider:
    """Uses reviewed installed verifiers. Construction has no mutations/network IO."""
    def __init__(self):
        for name, expected in HELPERS.items():
            path = Path(name)
            info = path.lstat()
            if info.st_uid != 0 or info.st_mode & 0o022 or path.is_symlink() or sha(read_regular(path)) != expected:
                raise RestoreError('INSTALLED_HELPER_BINDING_CHANGED')
        sys.path.insert(0, '/usr/local/libexec')
        spec = importlib.util.spec_from_file_location('candidate_ftps', '/usr/local/libexec/platform-ftps-backup.py')
        self.b = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.b)

    @contextlib.contextmanager
    def remote(self):
        connection = self.b.connect()
        try:
            yield connection
        finally:
            connection.close()

    def local_point(self, manifest_id):
        raw = read_regular(safe_source(DATA, 'manifests/'+manifest_id+'.json'))
        manifest = json.loads(raw)
        proof = self.b.d.verify(DATA, manifest_id+'.json')
        if manifest['id'] != manifest_id or proof['manifestId'] != manifest_id or proof['manifestDigest'] != manifest['signature']['digest']:
            raise RestoreError('MANIFEST_BINDING_CHANGED')
        coverage(manifest)
        # Hash raw bytes before AND after verification. Stage is verified again.
        if read_regular(DATA/'manifests'/(manifest_id+'.json')) != raw:
            raise RestoreError('MANIFEST_CHANGED_DURING_READ')
        return dict(pointId='local:'+manifest_id, receiptDigest=sha(raw), source='local',
                    createdAt=manifest['createdAt'], verified=True, status='authenticated',
                    manifestId=manifest_id, manifestDigest=proof['manifestDigest'],
                    artifactCount=proof['artifactCount'], sizeBytes=proof['artifactBytes'])

    def list(self):
        points, errors = [], []
        candidates = sorted((DATA/'manifests').glob('manifest-*.json'))
        if len(candidates) > 1000:
            raise RestoreError('LOCAL_INVENTORY_BOUND_EXCEEDED')
        for path in candidates:
            try:
                manifest = json.loads(read_regular(path))
                if manifest.get('operation') != 'backup' or manifest.get('scope', {}).get('kind') != 'platform' or not manifest.get('coverage', {}).get('complete'):
                    continue
                points.append(self.local_point(path.stem))
            except Exception:
                errors.append({'source':'local', 'code':'POINT_UNVERIFIED'})
        try:
            with self.remote() as f:
                listing = self.b.inventory(f)
                for receipt in self.b.points(f, listing):
                    self.b.ensure_source_fresh(receipt['backupAt'], dt.datetime.now().timestamp())
                    raw = bytearray()
                    def collect(chunk):
                        raw.extend(chunk)
                        if len(raw)>131072:
                            raise RestoreError('RECEIPT_TOO_LARGE')
                    f.retrbinary('RETR '+receipt['bundle']+'.receipt.json', collect)
                    if self.b.verify(json.loads(raw)) != receipt:
                        raise RestoreError('RECEIPT_CHANGED_DURING_READ')
                    points.append(dict(pointId='ftps:'+receipt['manifestId'], receiptDigest=sha(raw),
                        source='ftps', createdAt=receipt['backupAt'], verified=True,
                        status='authenticated', manifestId=receipt['manifestId'], manifestDigest=receipt['manifestDigest'],
                        artifactCount=receipt['artifactCount'], sizeBytes=receipt['encryptedBytes']))
        except Exception:
            errors.append({'source':'ftps', 'code':'REMOTE_INVENTORY_UNAVAILABLE_OR_UNVERIFIED'})
        return {'points':sorted(points, key=lambda p:p['createdAt'], reverse=True), 'errors':errors,
                'applyAllowed':False, 'blockers':BLOCKERS,
                'verificationScope':'local-artifact-integrity; ftps-receipt-authentication-and-part-sizes; no-live-restore'}

    def resolve(self, point_id, digest):
        source, manifest_id = parse_point(point_id, digest)
        candidates = [self.local_point(manifest_id)] if source == 'local' else self.list()['points']
        for point in candidates:
            if point['pointId'] == point_id and point['receiptDigest'] == digest:
                return point
        raise RestoreError('POINT_NOT_AVAILABLE_OR_CHANGED')

    def stage(self, point, target):
        source, manifest_id = parse_point(point['pointId'], point['receiptDigest'])
        if source == 'local':
            proof = self.b.d.verify(DATA, manifest_id+'.json')
            if proof['manifestDigest'] != point['manifestDigest']:
                raise RestoreError('MANIFEST_BINDING_CHANGED')
            if shutil.disk_usage(target).free < proof['artifactBytes']+10*1024**3:
                raise RestoreError('INSUFFICIENT_STAGE_SPACE')
            restored = target/'backups'
            restored.mkdir(mode=0o700)
            # Verifier runs as UID1000 in a network-none, read-only container.
            os.chown(target, 1000, 1000)
            os.chown(restored, 1000, 1000)
            for value in proof['paths']:
                src = safe_source(DATA, value)
                dst = restored/relative_path(value)
                dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with src.open('rb') as incoming, dst.open('xb') as out:
                    shutil.copyfileobj(incoming, out, 1024*1024)
                os.chmod(dst, 0o600)
            for item in restored.rglob('*'):
                os.chown(item,1000,1000)
            checked = self.b.d.verify(restored, manifest_id+'.json')
            if checked != proof or sha(read_regular(restored/'manifests'/(manifest_id+'.json'))) != point['receiptDigest']:
                raise RestoreError('STAGED_SET_DIFFERS')
            for item in restored.rglob('*'):
                os.chown(item,0,0)
            os.chown(restored,0,0)
            os.chown(target,0,0)
            return {'manifest':json.loads(read_regular(restored/'manifests'/(manifest_id+'.json'))),
                    'proof':checked, 'restoredPath':str(restored), 'productionModified':False}
        # Existing helper validates exact receipt again and restores its supplement.
        # Independent root scratch remains under the helper's fixed WORK directory.
        result = subprocess.run(['/usr/bin/python3', '/usr/local/libexec/platform-ftps-restore.py',
            'backup-'+manifest_id+'.tar.gpg', '--expected-receipt-sha256', point['receiptDigest'],
            '--expected-rustfs-image', 'rustfs/rustfs@sha256:8cc9801755448b71a786705ce76692c77e14936cccd87cf2fc31842e58f4d1ff',
            '--expected-rustfs-image-id', 'sha256:8cc9801755448b71a786705ce76692c77e14936cccd87cf2fc31842e58f4d1ff'],
            capture_output=True, text=True, timeout=43200)
        if result.returncode:
            raise RestoreError('ISOLATED_FTPS_PREPARATION_FAILED')
        proof=json.loads(result.stdout)
        restored=Path(proof['restoredPath'])
        if proof.get('productionModified') is not False or proof.get('manifestDigest')!=point['manifestDigest'] or proof.get('receiptSha256')!=point['receiptDigest'] or restored.parent.parent!=self.b.WORK or not restored.parent.name.startswith('recovered-'):
            raise RestoreError('ISOLATED_FTPS_RESULT_INVALID')
        return {'manifest':json.loads(read_regular(restored/'manifests'/(manifest_id+'.json'))),
                'proof':proof, 'restoredPath':str(restored), 'productionModified':False}

class Engine:
    def __init__(self, root, provider):
        self.root, self.provider = Path(root), provider
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info=self.root.lstat()
        if self.root.is_symlink() or info.st_uid!=os.geteuid() or info.st_mode&0o077:
            raise RestoreError('UNPROTECTED_STATE_ROOT')

    @contextlib.contextmanager
    def locked(self):
        fd=os.open(self.root/'operation.lock', os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
            yield

    def directory(self, plan_id):
        if not isinstance(plan_id,str) or not PLAN.fullmatch(plan_id):
            raise RestoreError('INVALID_PLAN_ID')
        path=self.root/plan_id
        if path.is_symlink():
            raise RestoreError('INVALID_PLAN_DIRECTORY')
        return path

    def save(self, path, value):
        tmp=path.with_name(path.name+'.'+uuid.uuid4().hex)
        fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)

    def plan(self, point_id, digest):
        parse_point(point_id,digest)
        point=self.provider.resolve(point_id,digest)
        plan_id=uuid.uuid4().hex;directory=self.directory(plan_id);directory.mkdir(mode=0o700)
        plan={'schema':'platform.manual-restore-plan/v1','planId':plan_id,'createdAt':now(),
              'point':point,'selectionDigest':sha(canonical(point))}
        self.save(directory/'selection.json',plan)
        status={'planId':plan_id,'state':'planned','phase':'selection-frozen','progress':None,
                'point':point,'applyAllowed':False,'blockers':BLOCKERS,
                'rollback':{'state':'not-required'},'productionModified':False}
        self.save(directory/'status.json',status)
        return status

    def status(self, plan_id):
        return json.loads(read_regular(self.directory(plan_id)/'status.json'))

    def prepare(self, plan_id):
        directory=self.directory(plan_id)
        selection=json.loads(read_regular(directory/'selection.json'))
        point=selection['point']
        if selection['planId']!=plan_id or selection['selectionDigest']!=sha(canonical(point)):
            raise RestoreError('SELECTION_CHANGED')
        status=self.status(plan_id)
        if status['state']=='prepared':
            return status
        if status['state']!='planned':
            raise RestoreError('PREPARATION_REQUIRES_NEW_PLAN')
        self.provider.resolve(point['pointId'],point['receiptDigest'])
        status.update(state='preparing',phase='verify-and-stage')
        self.save(directory/'status.json',status)
        target=directory/'staging';target.mkdir(mode=0o700)
        try:
            result=self.provider.stage(point,target)
            if result.get('productionModified') is not False:
                raise RestoreError('PROVIDER_TOUCHED_PRODUCTION')
            manifest=result['manifest']
            if manifest.get('id')!=point['manifestId'] or manifest.get('signature',{}).get('digest')!=point['manifestDigest']:
                raise RestoreError('STAGED_MANIFEST_CHANGED')
            ids=coverage(manifest)
            self.save(directory/'stage-result.json',result)
            status.update(state='prepared',phase='artifacts-verified',resourceCount=len(ids),
                          resources=ids,preparedAt=now(),progress=100)
            # Prepared means inert signed artifacts, never production recovery readiness.
            status['preparationScope']='inert-artifacts-only'
            self.save(directory/'status.json',status)
            return status
        except Exception:
            status.update(state='failed',phase='preparation-failed',errorCode='PREPARATION_FAILED')
            self.save(directory/'status.json',status)
            raise RestoreError('PREPARATION_FAILED') from None

    def apply(self, plan_id, confirmation):
        status=self.status(plan_id)
        if confirmation!='RIPRISTINA '+status['point']['pointId']:
            raise RestoreError('EXACT_CONFIRMATION_REQUIRED')
        # No path to production writes exists in this candidate, regardless of state.
        raise RestoreError('PRODUCTION_RESTORE_UNAVAILABLE')

def dispatch(engine, request):
    allowed={'list':{'operation'},'plan':{'operation','pointId','receiptDigest'},
             'prepare':{'operation','planId'},'status':{'operation','planId'},
             'apply':{'operation','planId','confirmation'}}
    op=request.get('operation')
    if op not in allowed or set(request)!=allowed[op]:
        raise RestoreError('INVALID_REQUEST')
    # Status is an atomic file read. Holding the operation lock here would hide
    # progress for the whole duration of a multi-gigabyte prepare.
    if op=='status':return engine.status(request['planId'])
    with engine.locked():
        if op=='list':return engine.provider.list()
        if op=='plan':return engine.plan(request['pointId'],request['receiptDigest'])
        if op=='prepare':return engine.prepare(request['planId'])
        return engine.apply(request['planId'],request['confirmation'])

def main():
    try:
        if os.geteuid()!=0:raise RestoreError('ROOT_REQUIRED')
        raw=sys.stdin.buffer.read(16385)
        if len(raw)>16384:raise RestoreError('REQUEST_TOO_LARGE')
        value=dispatch(Engine(STATE,InstalledProvider()),json.loads(raw))
        print(json.dumps({'ok':True,'result':value}))
    except Exception as error:
        code=str(error) if isinstance(error,RestoreError) else 'INTERNAL_ERROR'
        print(json.dumps({'ok':False,'error':{'code':code},'productionModified':False}))
        return 1
    return 0

if __name__=='__main__':
    sys.exit(main())
