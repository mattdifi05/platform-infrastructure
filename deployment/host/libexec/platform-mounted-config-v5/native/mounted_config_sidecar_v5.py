"""V5 typed-overlay binding for the current mounted-config capture sidecar.

This is an additive G16 delta. The sidecar is a regular member of the same
encrypted package as the host capsule, and its descriptor is covered by the
existing typed overlay HMAC. No post-readback reference proof is signed here.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import io
import gzip
import json
from pathlib import Path
import re
import sys
import os
import stat
import tarfile
import gzip
import subprocess
import secrets
import shutil
from pathlib import PurePosixPath

MEMBER = 'mounted-config/records.json'
GPG_KEY_PATH = Path('/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase')
MAX_SIDECAR_BYTES = 512 * 1024 * 1024
EXPECTED_PACKAGE_MEMBERS = {
    'receipt.json',
    'metadata/records.ndjson.gz',
    'host-capsule/current.gpg',
}
HEX = re.compile(r'^[0-9a-f]{64}$')
ESCAPED_REGULAR_MEMBERS={'host/etc/systemd/system/snap-canonical\\x2dlivepatch-414.mount'}
ESCAPED_SYMLINK_MEMBERS={
    'host/etc/systemd/system/multi-user.target.wants/snap-canonical\\x2dlivepatch-414.mount',
    'host/etc/systemd/system/snapd.mounts.target.wants/snap-canonical\\x2dlivepatch-414.mount',
}
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'host'))
CAPTURE_MODULE_SHA256='d9eb8a53a02c44daa7d1023e3778ce3c4b435d43e310389c6eafe25ae38d63d7'
VERIFY_MODULE_SHA256='61d0d6f797c7b9c31f96456299fb74bd2cfe8338b50b509a84b98a75f05c51c6'
HOST_DIR=Path(__file__).resolve().parent.parent/'host'


class Blocked(RuntimeError):
    pass


GPG_RUNTIME_ROOT = (Path('/run') if sys.platform.startswith('linux') else
                   Path('/tmp').resolve() / ('g16-runtime-' + str(os.geteuid())))
GPG_HOME_PREFIX = 'g16-'


def short_gpg_home_path() -> Path:
    """Return a unique, canonical, short path for this operation's GPG agent."""
    root = GPG_RUNTIME_ROOT
    if not root.exists() and not root.is_symlink() and not sys.platform.startswith('linux'):
        os.mkdir(root, 0o700)
        os.chmod(root, 0o700)
    info = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(info.st_mode) or root.resolve(strict=True) != root:
        raise Blocked('GPG_RUNTIME_ROOT')
    if sys.platform.startswith('linux'):
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise Blocked('GPG_RUNTIME_ROOT_CUSTODY')
    elif info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Blocked('GPG_RUNTIME_ROOT_CUSTODY')
    for _ in range(8):
        home = root / (GPG_HOME_PREFIX + secrets.token_hex(16))
        if len(str(home) + '/S.gpg-agent') >= 100:
            raise Blocked('GPG_AGENT_SOCKET_PATH_TOO_LONG')
        try:
            home.lstat()
        except FileNotFoundError:
            return home
    raise Blocked('GPG_HOME_NAME_COLLISION')


def new_short_gpg_home() -> Path:
    home = short_gpg_home_path()
    os.mkdir(home, 0o700)
    os.chmod(home, 0o700)
    info = home.lstat()
    if (home.is_symlink() or not stat.S_ISDIR(info.st_mode) or
            info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise Blocked('GPG_HOME_CUSTODY')
    return home


def cleanup_short_gpg_home(home: Path) -> None:
    """Kill only this operation's agent, then remove only its exact private home."""
    home = Path(home)
    if (home.parent != GPG_RUNTIME_ROOT or home.name[:len(GPG_HOME_PREFIX)] != GPG_HOME_PREFIX or
            not re.fullmatch(r'g16-[0-9a-f]{32}', home.name) or len(str(home) + '/S.gpg-agent') >= 100):
        raise Blocked('GPG_HOME_CLEANUP_SCOPE')
    if not home.exists() and not home.is_symlink():
        return
    info = home.lstat()
    if (home.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) != 0o700 or home.resolve(strict=True) != home):
        raise Blocked('GPG_HOME_CLEANUP_CUSTODY')
    try:
        result = subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'gpg-agent'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=10, check=False)
    except subprocess.TimeoutExpired:
        raise Blocked('GPG_AGENT_CLEANUP_TIMEOUT') from None
    if result.returncode != 0:
        raise Blocked('GPG_AGENT_SCOPED_CLEANUP_FAILED')
    shutil.rmtree(home)


def _load_pinned_host_module(name: str, expected_sha256: str):
    path=HOST_DIR/(name+'.py');st=path.lstat()
    if (path.is_symlink() or path.resolve(strict=True)!=path or not stat.S_ISREG(st.st_mode) or
            st.st_uid not in {0,os.geteuid()} or st.st_mode&0o022 or st.st_nlink!=1 or
            hashlib.sha256(path.read_bytes()).hexdigest()!=expected_sha256):
        raise Blocked('MOUNTED_CONFIG_HOST_MODULE_PIN:'+name)
    for ancestor in (path.parent,*path.parent.parents):
        ast=ancestor.lstat()
        if ancestor.is_symlink() or not stat.S_ISDIR(ast.st_mode) or ast.st_mode&0o022:
            raise Blocked('MOUNTED_CONFIG_HOST_MODULE_ANCESTRY:'+name)
    spec=importlib.util.spec_from_file_location('mounted_config_v5_'+name,path)
    if spec is None or spec.loader is None:raise Blocked('MOUNTED_CONFIG_HOST_MODULE_IMPORT:'+name)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    return module


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def descriptor(sidecar_bytes: bytes, sidecar: dict) -> dict:
    if not isinstance(sidecar_bytes, bytes) or not 0 < len(sidecar_bytes) <= MAX_SIDECAR_BYTES:
        raise Blocked('MOUNTED_CONFIG_SIDECAR_SIZE')
    try:
        parsed = json.loads(sidecar_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise Blocked('MOUNTED_CONFIG_SIDECAR_JSON') from None
    if parsed != sidecar:
        raise Blocked('MOUNTED_CONFIG_SIDECAR_BYTES_DIFFERS')
    if canonical(parsed) + b'\n' != sidecar_bytes:
        raise Blocked('MOUNTED_CONFIG_SIDECAR_CANONICAL_ENCODING')
    if (sidecar.get('schema') != 'platform.mounted-config-tree-capture/v1' or
            sidecar.get('sourceCount') != 89 or
            sidecar.get('catalogSha256') != 'f5cea1410282bcf5df8b722b11b7e1ccb67cc497c5fc401bab549152b5b52e69' or
            sidecar.get('planSha256') != 'c6f09fd00d7f8a7e1dc8794e214dfec1f0bf48f663fec2b0f26b8575b34d4c29' or
            sidecar.get('providerCounts') != {'parent-capsule-exact-binding': 76,
                'fresh-capsule-regular-file': 8, 'authenticated-students-secret-file': 5}):
        raise Blocked('MOUNTED_CONFIG_SIDECAR_SCHEMA')
    validate_capture_document_structure(sidecar)
    if not isinstance(sidecar.get('cycleId'), str) or not sidecar['cycleId']:
        raise Blocked('MOUNTED_CONFIG_CYCLE_ID')
    excluded=sidecar.get('excludedSensitiveEntries')
    if (not isinstance(excluded,list) or len(excluded)!=1 or
            set(excluded[0])!={'sourcePath','relativePath','type','uid','gid','mode','bytes',
                               'mtimeNs','nlink','contentRead','contentHash','xattrsRead'} or
            excluded[0].get('sourcePath')!='/home/platform_infrastructure/v1-fresh-runtime/critical' or
            excluded[0].get('relativePath')!='v1-local-private_confidential-backup-passphrase' or
            excluded[0].get('type')!='regular-file' or type(excluded[0].get('uid')) is not int or
            excluded[0].get('uid')<0 or type(excluded[0].get('gid')) is not int or excluded[0].get('gid')<0 or
            excluded[0].get('mode')!=0o600 or
            excluded[0].get('nlink')!=1 or type(excluded[0].get('bytes')) is not int or
            excluded[0]['bytes']<=0 or type(excluded[0].get('mtimeNs')) is not int or
            excluded[0].get('contentRead') is not False or excluded[0].get('contentHash') is not None or
            excluded[0].get('xattrsRead') is not False):
        raise Blocked('MOUNTED_CONFIG_CREDENTIAL_EXCLUSION')
    return {
        'member': MEMBER,
        'bytes': len(sidecar_bytes),
        'sha256': hashlib.sha256(sidecar_bytes).hexdigest(),
        'cycleId': sidecar['cycleId'],
        'catalogSha256': sidecar['catalogSha256'],
        'planSha256': sidecar['planSha256'],
        'sourceCount': 89,
        'recordCount': sidecar['recordCount'],
        'providerCounts': sidecar['providerCounts'],
    }


def validate_capture_document_structure(document: dict) -> None:
    capture_module=_load_pinned_host_module('capture_mounted_config_trees',CAPTURE_MODULE_SHA256)
    fixed_sources=capture_module.fixed_sources
    REDACTED_SOURCE=capture_module.REDACTED_SOURCE;REDACTED_MEMBER=capture_module.REDACTED_MEMBER
    expected_outer={'schema','status','cycleId','capturedAt','parent','catalogSha256','planSha256',
        'sourceCount','recordCount','regularBytes','providerCounts','excludedSensitiveEntries',
        'recoveryLimitations','sources','claims'}
    if (set(document)!=expected_outer or document.get('schema')!='platform.mounted-config-tree-capture/v1' or
            document.get('status')!='captured-local-unpublished' or document.get('sourceCount')!=89 or
            document.get('parent')!={'manifestId':'manifest-scheduled-platform-20260929-182357-1f9954',
                'manifestDigest':'baf72a7c4ff5d2266b71afe4865ebffeb8be6c363dfc31c12f3a865389009b2c'} or
            document.get('claims')!={'sameCycleCapsuleVerified':False,'offsiteVerified':False,'productionModified':False} or
            document.get('recoveryLimitations')!={'originalGpgCredentialArchived':False,
                'separateGpgCredentialCustodyRequiredForRestore':True}):
        raise Blocked('MOUNTED_CONFIG_CAPTURE_SCHEMA')
    fixed=fixed_sources();sources=document.get('sources')
    if not isinstance(sources,list) or len(sources)!=89 or any('referenceProofSha256' in row for row in sources):
        raise Blocked('MOUNTED_CONFIG_SIDECAR_SOURCE_SET')
    if [(r.get('sourcePath'),r.get('resourceId'),r.get('scopeMappingClass')) for r in sources] != [
            (r['sourcePath'],r['resourceId'],r['provider']) for r in fixed]:
        raise Blocked('MOUNTED_CONFIG_SIDECAR_SOURCE_SET')
    total_records=total_bytes=0
    for row in sources:
        if set(row)!={'sourcePath','resourceId','scopeMappingClass','treeDigest','recordSetSha256',
                      'recordCount','regularBytes','records'}:
            raise Blocked('MOUNTED_CONFIG_SOURCE_FIELDS')
        records=row['records']
        if not isinstance(records,list) or not records or type(row['recordCount']) is not int or row['recordCount']!=len(records):
            raise Blocked('MOUNTED_CONFIG_RECORD_COUNT')
        paths={}
        for record in records:
            if not isinstance(record,dict) or record.get('kind') not in ('directory','file','symlink'):
                raise Blocked('MOUNTED_CONFIG_RECORD_KIND')
            kind=record['kind']
            extra={'bytes','sha256','hardlinkGroup'} if kind=='file' else {'target'} if kind=='symlink' else set()
            if set(record)!={'path','mode','uid','gid','mtimeNs','xattrs','kind'}|extra:
                raise Blocked('MOUNTED_CONFIG_RECORD_FIELDS')
            rel=record.get('path')
            if (not isinstance(rel,str) or rel.startswith('/') or '\\' in rel or '\x00' in rel or
                    (rel!='.' and any(p in ('','.','..') for p in rel.split('/'))) or rel in paths):
                raise Blocked('MOUNTED_CONFIG_RECORD_PATH')
            if (type(record.get('mode')) is not int or not 0<=record['mode']<=0o7777 or
                    type(record.get('uid')) is not int or record['uid']<0 or
                    type(record.get('gid')) is not int or record['gid']<0 or
                    type(record.get('mtimeNs')) is not int):
                raise Blocked('MOUNTED_CONFIG_RECORD_METADATA')
            attrs=record.get('xattrs')
            if not isinstance(attrs,dict) or len(attrs)>128:
                raise Blocked('MOUNTED_CONFIG_XATTR_SET')
            for name,digest in attrs.items():
                if not isinstance(name,str) or not name or not HEX.fullmatch(str(digest)):
                    raise Blocked('MOUNTED_CONFIG_XATTR_HASH')
            if kind=='file':
                if type(record.get('bytes')) is not int or record['bytes']<0 or not HEX.fullmatch(str(record.get('sha256'))) or not isinstance(record.get('hardlinkGroup'),str):
                    raise Blocked('MOUNTED_CONFIG_FILE_RECORD')
            elif kind=='symlink':
                target=record.get('target')
                if not isinstance(target,str) or not target or '\x00' in target:
                    raise Blocked('MOUNTED_CONFIG_SYMLINK_RECORD')
            paths[rel]=record
        if list(paths)!=sorted(paths):
            raise Blocked('MOUNTED_CONFIG_RECORD_ORDER')
        root_record=paths.get('.')
        if root_record is None or root_record.get('kind') not in ('directory','file'):
            raise Blocked('MOUNTED_CONFIG_ROOT_RECORD')
        if root_record.get('kind')=='file' and len(paths)!=1:
            raise Blocked('MOUNTED_CONFIG_FILE_ROOT_CHILDREN')
        for rel,record in paths.items():
            if rel=='.':continue
            parent=str(PurePosixPath(rel).parent) or '.'
            if parent not in paths or paths[parent].get('kind')!='directory':
                raise Blocked('MOUNTED_CONFIG_PARENT_RECORD')
            if record.get('kind')=='file':
                group=record['hardlinkGroup'];target=paths.get(group)
                if (target is None or target.get('kind')!='file' or group>rel or
                        target.get('bytes')!=record.get('bytes') or target.get('sha256')!=record.get('sha256')):
                    raise Blocked('MOUNTED_CONFIG_HARDLINK_GROUP')
        if row['sourcePath']==REDACTED_SOURCE and REDACTED_MEMBER in paths:
            raise Blocked('MOUNTED_CONFIG_CREDENTIAL_INCLUDED')
        digest=hashlib.sha256(canonical(records)).hexdigest()
        bytes_total=sum(r.get('bytes',0) for r in records if r.get('kind')=='file')
        if (row.get('treeDigest')!=digest or row.get('recordSetSha256')!=digest or
                row.get('regularBytes')!=bytes_total):
            raise Blocked('MOUNTED_CONFIG_TREE_DIGEST')
        total_records+=len(records);total_bytes+=bytes_total
    if total_records!=document.get('recordCount') or total_bytes!=document.get('regularBytes'):
        raise Blocked('MOUNTED_CONFIG_CAPTURE_TOTALS')
    expired=document.get('excludedSensitiveEntries')
    if (not isinstance(expired,list) or len(expired)!=1 or
            set(expired[0])!={'sourcePath','relativePath','type','uid','gid','mode','bytes','mtimeNs',
                              'nlink','contentRead','contentHash','xattrsRead'} or
            expired[0].get('sourcePath')!=REDACTED_SOURCE or expired[0].get('relativePath')!=REDACTED_MEMBER or
            expired[0].get('type')!='regular-file' or type(expired[0].get('uid')) is not int or
            type(expired[0].get('gid')) is not int or expired[0].get('mode')!=0o600 or
            expired[0].get('nlink')!=1 or type(expired[0].get('bytes')) is not int or
            expired[0].get('bytes')<=0 or type(expired[0].get('mtimeNs')) is not int or
            expired[0].get('contentRead') is not False or expired[0].get('contentHash') is not None or
            expired[0].get('xattrsRead') is not False):
        raise Blocked('MOUNTED_CONFIG_CREDENTIAL_EXCLUSION')


def extend_signed_payload(payload: dict, sidecar_bytes: bytes, sidecar: dict) -> dict:
    """Return the added typed field before HMAC signing; no self-reference."""
    result = dict(payload)
    if 'mountedConfigCapture' in result:
        raise Blocked('MOUNTED_CONFIG_BINDING_ALREADY_PRESENT')
    result['mountedConfigCapture'] = descriptor(sidecar_bytes, sidecar)
    return result


def sign_v5_receipt(payload: dict, hmac_key: bytes) -> dict:
    """Authenticate the V4 payload plus the additional cycle-bound member."""
    if len(hmac_key) < 32 or 'mountedConfigCapture' not in payload:
        raise Blocked('MOUNTED_CONFIG_HMAC_INPUT')
    raw = canonical(payload)
    return {'schema': 'platform.source-metadata-overlay-receipt/v4',
            'payload': payload, 'payloadSha256': hashlib.sha256(raw).hexdigest(),
            'hmacSha256': hmac.new(hmac_key, raw, hashlib.sha256).hexdigest()}


def verify_v5_receipt(receipt: dict, hmac_key: bytes, sidecar_bytes: bytes,
                      sidecar: dict, base_module, expected_parent: str,
                      expected_base_cipher: str, expected_base_receipt: str,
                      expected_archive_sha256: str, expected_archive_bytes: int) -> None:
    """Verify V5 HMAC/member then reuse the pinned V4 typed-receipt validator."""
    if (not isinstance(receipt, dict) or set(receipt) != {'schema', 'payload', 'payloadSha256', 'hmacSha256'} or
            receipt.get('schema') != 'platform.source-metadata-overlay-receipt/v4' or
            not isinstance(receipt.get('payload'), dict) or len(hmac_key) < 32):
        raise Blocked('MOUNTED_CONFIG_RECEIPT_SHAPE')
    payload = receipt['payload']
    _verify_v5_hmac(receipt, hmac_key)
    if payload.get('mountedConfigCapture') != descriptor(sidecar_bytes, sidecar):
        raise Blocked('MOUNTED_CONFIG_RECEIPT_MEMBER_BINDING')
    # The V4 schema validator remains the authority for every pre-existing
    # field. First authenticate V5 above; then pass a locally normalized copy
    # containing exactly the older authenticated fields to that pinned reader.
    base_payload = dict(payload)
    base_payload.pop('mountedConfigCapture')
    normalized_raw = canonical(base_payload)
    normalized = {
        'schema': 'platform.source-metadata-overlay-receipt/v3',
        'payload': base_payload,
        'payloadSha256': hashlib.sha256(normalized_raw).hexdigest(),
        'hmacSha256': hmac.new(hmac_key, normalized_raw, hashlib.sha256).hexdigest(),
    }
    base_module.verify_receipt(normalized, hmac_key, expected_parent,
                               expected_base_cipher, expected_base_receipt,
                               expected_archive_sha256, expected_archive_bytes)


def _verify_v5_hmac(receipt: dict, hmac_key: bytes) -> None:
    if (not isinstance(receipt, dict) or set(receipt) != {'schema', 'payload', 'payloadSha256', 'hmacSha256'} or
            receipt.get('schema') != 'platform.source-metadata-overlay-receipt/v4' or
            not isinstance(receipt.get('payload'), dict) or len(hmac_key) < 32):
        raise Blocked('MOUNTED_CONFIG_RECEIPT_SHAPE')
    raw = canonical(receipt['payload'])
    if (receipt.get('payloadSha256') != hashlib.sha256(raw).hexdigest() or
            not hmac.compare_digest(str(receipt.get('hmacSha256', '')),
                                    hmac.new(hmac_key, raw, hashlib.sha256).hexdigest())):
        raise Blocked('MOUNTED_CONFIG_RECEIPT_HMAC')


def build_v5_package(receipt: dict, metadata_gzip: bytes, capsule_path: Path,
                     sidecar_bytes: bytes, output: Path) -> tuple[str, int, list]:
    """Build the exact four-member USTAR package consumed by the V5 reader."""
    import tarfile
    from pathlib import Path
    capsule_path, output = Path(capsule_path), Path(output)
    payload = receipt.get('payload', {})
    sidecar = json.loads(sidecar_bytes)
    config = descriptor(sidecar_bytes, sidecar)
    cap_sha, cap_size = _secure_file_hash(capsule_path)
    if (receipt.get('schema') != 'platform.source-metadata-overlay-receipt/v4' or
            payload.get('mountedConfigCapture') != config or
            payload.get('metadataIndex', {}).get('sha256') != hashlib.sha256(metadata_gzip).hexdigest() or
            payload.get('metadataIndex', {}).get('compressedBytes') != len(metadata_gzip) or
            payload.get('capsule', {}).get('ciphertextSha256') != cap_sha or
            payload.get('capsule', {}).get('sizeBytes') != cap_size):
        raise Blocked('MOUNTED_CONFIG_PACKAGE_INPUT_BINDING')
    if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.resolve() != output.parent or output.parent.stat().st_mode & 0o077:
        raise Blocked('MOUNTED_CONFIG_PACKAGE_OUTPUT')
    rows = []
    with tarfile.open(output, 'w:gz', format=tarfile.USTAR_FORMAT) as tf:
        for name, body in (('receipt.json', canonical(receipt) + b'\n'),
                           ('metadata/records.ndjson.gz', metadata_gzip)):
            info = tarfile.TarInfo(name)
            info.size = len(body); info.mode = 0o600; info.uid = info.gid = 0
            tf.addfile(info, io.BytesIO(body))
        capsule_info = tarfile.TarInfo('host-capsule/current.gpg')
        capsule_info.size = cap_size; capsule_info.mode = 0o600; capsule_info.uid = capsule_info.gid = 0
        with capsule_path.open('rb') as source:
            tf.addfile(capsule_info, source)
        info = tarfile.TarInfo(MEMBER)
        info.size = len(sidecar_bytes); info.mode = 0o600; info.uid = info.gid = 0
        tf.addfile(info, io.BytesIO(sidecar_bytes))
    rows = package_member_index(output)
    if {x['name'] for x in rows} != EXPECTED_PACKAGE_MEMBERS | {MEMBER}:
        raise Blocked('MOUNTED_CONFIG_PACKAGE_MEMBER_SET')
    os.chmod(output, 0o600)
    with output.open('rb') as stream:
        os.fsync(stream.fileno())
    dfd = os.open(output.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return _secure_file_hash(output)[0], output.stat().st_size, rows


def _hash_path(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def _secure_file_hash(path: Path) -> tuple[str, int]:
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path or path.is_symlink():
        raise Blocked('MOUNTED_CONFIG_FILE_NOT_CANONICAL')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise Blocked('MOUNTED_CONFIG_FILE_METADATA')
        h = hashlib.sha256(); total = 0
        while True:
            data = os.read(fd, 1024 * 1024)
            if not data: break
            total += len(data); h.update(data)
        after = os.fstat(fd)
        ident = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        if ident(before) != ident(after) or total != before.st_size:
            raise Blocked('MOUNTED_CONFIG_FILE_CHANGED_DURING_HASH')
        return h.hexdigest(), total
    finally:
        os.close(fd)


def package_member_index(package: Path) -> list:
    """Read only the locally produced USTAR package and return member hashes."""
    import tarfile
    rows = []
    total = 0
    with tarfile.open(package, 'r:gz') as tf:
        members = tf.getmembers()
        names = [m.name for m in members]
        expected = ['receipt.json', 'metadata/records.ndjson.gz',
                    'host-capsule/current.gpg', MEMBER]
        if names != expected or any(not m.isfile() or m.linkname or m.pax_headers for m in members):
            raise Blocked('MOUNTED_CONFIG_PACKAGE_USTAR_SHAPE')
        for member in members:
            if member.size < 0 or total + member.size > 1_500_000_000:
                raise Blocked('MOUNTED_CONFIG_PACKAGE_SIZE_BOUND')
            source = tf.extractfile(member)
            digest = hashlib.sha256(); count = 0
            for block in iter(lambda: source.read(1024 * 1024), b''):
                count += len(block); digest.update(block)
            if count != member.size:
                raise Blocked('MOUNTED_CONFIG_PACKAGE_MEMBER_TRUNCATED')
            total += count
            rows.append({'name': member.name, 'bytes': count, 'sha256': digest.hexdigest()})
    return rows


def read_v5_package(package: Path, *, metadata_out: Path, capsule_out: Path,
                    sidecar_out: Path, hmac_key: bytes, base_module,
                    expected_parent: str, expected_base_cipher: str,
                    expected_base_receipt: str, expected_archive_sha256: str,
                    expected_archive_bytes: int) -> tuple[dict, dict, list]:
    """Stream the exact four-member V5 package and authenticate every member.

    The package is root-private GPG plaintext. Each output is a new file in a
    canonical private directory. No archive paths are extracted from headers.
    """
    package = Path(package)
    if (package.is_symlink() or not package.is_file() or package.stat().st_nlink != 1 or
            package.stat().st_size > 1_500_000_000):
        raise Blocked('MOUNTED_CONFIG_PACKAGE_INPUT')
    outputs = [Path(metadata_out), Path(capsule_out), Path(sidecar_out)]
    if len(set(outputs)) != 3:
        raise Blocked('MOUNTED_CONFIG_OUTPUT_ALIAS')
    for output in outputs:
        if not output.is_absolute(): raise Blocked('MOUNTED_CONFIG_OUTPUT_NOT_ABSOLUTE')
        if output.parent.resolve(strict=True) != output.parent: raise Blocked('MOUNTED_CONFIG_OUTPUT_PARENT_ALIAS')
        if output.parent.is_symlink(): raise Blocked('MOUNTED_CONFIG_OUTPUT_PARENT_SYMLINK')
        if output.exists() or output.is_symlink(): raise Blocked('MOUNTED_CONFIG_OUTPUT_NOT_FRESH')
        pinfo = output.parent.lstat()
        if (not stat.S_ISDIR(pinfo.st_mode) or pinfo.st_mode & 0o077 or
                (os.geteuid() == 0 and pinfo.st_uid != 0)):
            raise Blocked('MOUNTED_CONFIG_OUTPUT_PARENT_MODE')
    expected_order = ['receipt.json', 'metadata/records.ndjson.gz',
                      'host-capsule/current.gpg', MEMBER]
    total = 0
    raw_total = 0
    found_receipt = None
    sidecar_doc = None
    rows = []
    streams = None
    created = []
    try:
        with package.open('rb') as raw, gzip.GzipFile(fileobj=raw, mode='rb') as stream:
            def read_exact(size):
                nonlocal raw_total
                if type(size) is not int or size < 0 or raw_total + size > 1_600_000_000:
                    raise Blocked('MOUNTED_CONFIG_TAR_STREAM_BOUND')
                chunks=[]; remaining=size
                while remaining:
                    block=stream.read(min(65536,remaining))
                    if not block: raise Blocked('MOUNTED_CONFIG_TAR_TRUNCATED')
                    chunks.append(block); remaining-=len(block); raw_total+=len(block)
                return b''.join(chunks)
            for i, name in enumerate(expected_order):
                header=read_exact(512)
                if header == bytes(512): raise Blocked('MOUNTED_CONFIG_TAR_EARLY_END')
                stored=header[:100].split(b'\0',1)[0]
                prefix=header[345:500].split(b'\0',1)[0]
                if prefix or stored.decode('ascii','strict') != name:
                    raise Blocked('MOUNTED_CONFIG_PACKAGE_HEADER')
                if header[156:157] not in (b'\0',b'0') or header[157:257].strip(b'\0'):
                    raise Blocked('MOUNTED_CONFIG_PACKAGE_LINK_OR_EXTENDED_HEADER')
                try:
                    checksum=int(header[148:156].rstrip(b'\0 ').decode('ascii'),8)
                    member_size=int(header[124:136].rstrip(b'\0 ').decode('ascii'),8)
                    member_mode=int(header[100:108].rstrip(b'\0 ').decode('ascii'),8)
                    member_uid=int(header[108:116].rstrip(b'\0 ').decode('ascii'),8)
                    member_gid=int(header[116:124].rstrip(b'\0 ').decode('ascii'),8)
                except (ValueError,UnicodeDecodeError):
                    raise Blocked('MOUNTED_CONFIG_TAR_NUMERIC_FIELD') from None
                checked=bytearray(header); checked[148:156]=b' '*8
                if sum(checked)!=checksum: raise Blocked('MOUNTED_CONFIG_TAR_CHECKSUM')
                if member_uid!=0 or member_gid!=0 or member_mode!=0o600 or member_size<0 or total+member_size>1_500_000_000:
                    raise Blocked('MOUNTED_CONFIG_PACKAGE_MEMBER_METADATA')
                if i == 0:
                    limit = 8 * 1024 * 1024
                    if member_size > limit:
                        raise Blocked('MOUNTED_CONFIG_RECEIPT_SIZE')
                    body = read_exact(member_size)
                    try:
                        found_receipt = json.loads(body)
                    except json.JSONDecodeError:
                        raise Blocked('MOUNTED_CONFIG_RECEIPT_JSON') from None
                    _verify_v5_hmac(found_receipt, hmac_key)
                    # Verify V5 HMAC and all baseline V3 receipt invariants before
                    # processing potentially large remaining members.
                    descriptor_row = found_receipt.get('payload', {}).get('mountedConfigCapture')
                    if not isinstance(descriptor_row, dict):
                        raise Blocked('MOUNTED_CONFIG_RECEIPT_SIDECAR_DESCRIPTOR')
                else:
                    if i == 1:
                        limit = base_module.MAX_METADATA_COMPRESSED
                        expected_bytes = found_receipt['payload']['metadataIndex']['compressedBytes']
                        expected_sha = found_receipt['payload']['metadataIndex']['sha256']
                        out = outputs[0]
                    elif i == 2:
                        limit = base_module.MAX_CAPSULE_BYTES
                        expected_bytes = found_receipt['payload']['capsule']['sizeBytes']
                        expected_sha = found_receipt['payload']['capsule']['ciphertextSha256']
                        out = outputs[1]
                    else:
                        limit = MAX_SIDECAR_BYTES
                        expected_bytes = found_receipt['payload']['mountedConfigCapture']['bytes']
                        expected_sha = found_receipt['payload']['mountedConfigCapture']['sha256']
                        out = outputs[2]
                    if member_size != expected_bytes or member_size > limit:
                        raise Blocked('MOUNTED_CONFIG_MEMBER_SIZE_BINDING')
                    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
                    created.append(out)
                    digest = hashlib.sha256(); count = 0; remaining=member_size
                    with os.fdopen(fd, 'wb') as output:
                        while remaining:
                            chunk=read_exact(min(1024*1024,remaining))
                            count += len(chunk); total += len(chunk); digest.update(chunk); output.write(chunk)
                            remaining-=len(chunk)
                            if total > 1_500_000_000: raise Blocked('MOUNTED_CONFIG_PACKAGE_TOTAL_BOUND')
                        output.flush(); os.fsync(output.fileno())
                    if count != member_size or digest.hexdigest() != expected_sha:
                        raise Blocked('MOUNTED_CONFIG_MEMBER_HASH')
                    if i == 3:
                        raw = out.read_bytes()
                        try:
                            sidecar_doc = json.loads(raw)
                        except json.JSONDecodeError:
                            raise Blocked('MOUNTED_CONFIG_SIDECAR_JSON') from None
                        if found_receipt['payload'].get('mountedConfigCapture') != descriptor(raw, sidecar_doc):
                            raise Blocked('MOUNTED_CONFIG_RECEIPT_SIDECAR_DESCRIPTOR')
                padding=(-member_size)%512
                if padding and any(read_exact(padding)):
                    raise Blocked('MOUNTED_CONFIG_TAR_PADDING')
                total += member_size if i == 0 else 0
                rows.append({'name': name, 'bytes': member_size,
                             'sha256': (hashlib.sha256(body).hexdigest() if i == 0 else expected_sha)})
            terminators=read_exact(1024)
            if terminators != bytes(1024):
                raise Blocked('MOUNTED_CONFIG_PACKAGE_TERMINATOR')
            while True:
                tail = stream.read(65536)
                if not tail: break
                raw_total += len(tail)
                if raw_total > 1_600_000_000 or any(tail):
                    raise Blocked('MOUNTED_CONFIG_PACKAGE_TRAILING_BYTES')
        if found_receipt is None or sidecar_doc is None:
            raise Blocked('MOUNTED_CONFIG_PACKAGE_INCOMPLETE')
        sidecar_raw = outputs[2].read_bytes()
        verify_v5_receipt(found_receipt, hmac_key, sidecar_raw, sidecar_doc, base_module,
                          expected_parent, expected_base_cipher, expected_base_receipt,
                          expected_archive_sha256, expected_archive_bytes)
        payload = found_receipt['payload']
        expected_map = base_module.load_expected_sources(
            Path(base_module.__file__).resolve().with_name('expected-sources.json'), None)
        expiry = payload['sourceCapture']['expiredDerivedCacheFiles']
        expired_paths = {x['path'] for x in expiry['entries']} if isinstance(expiry, dict) else set()
        resource_ids = base_module.validate_metadata_gzip(
            outputs[0], payload['metadataIndex'], set(expected_map), expired_paths)
        return found_receipt, sidecar_doc, rows, resource_ids
    except Exception:
        for path in created:
            try: path.unlink()
            except OSError: pass
        raise


def _read_member(tf, member, limit):
    if member.size > limit:
        raise Blocked('MOUNTED_CONFIG_MEMBER_LIMIT')
    source = tf.extractfile(member)
    body = source.read(limit + 1)
    if len(body) != member.size:
        raise Blocked('MOUNTED_CONFIG_MEMBER_TRUNCATED')
    return body


def verify_same_cycle(capture_document: dict, sidecar_bytes_from_capsule: bytes,
                      capsule_host_root: Path, *, capsule_cipher_sha256: str,
                      sidecar_member_sha256: str, fs=None) -> dict:
    """Bind the typed sidecar copy to the identical file inside same-cycle capsule."""
    if not isinstance(sidecar_bytes_from_capsule, bytes) or not sidecar_bytes_from_capsule:
        raise Blocked('MOUNTED_CONFIG_CAPSULE_MEMBER_MISSING')
    expected = canonical(capture_document) + b'\n'
    if hashlib.sha256(sidecar_bytes_from_capsule).hexdigest() != hashlib.sha256(expected).hexdigest():
        raise Blocked('MOUNTED_CONFIG_CAPSULE_SIDECAR_BYTES_DIFFERS')
    sidecar_sha = hashlib.sha256(sidecar_bytes_from_capsule).hexdigest()
    if (not HEX.fullmatch(str(capsule_cipher_sha256)) or
            sidecar_member_sha256 != sidecar_sha):
        raise Blocked('MOUNTED_CONFIG_CAPSULE_INDEX_BINDING')
    verify_module=_load_pinned_host_module('verify_mounted_config_trees',VERIFY_MODULE_SHA256)
    result = verify_module.verify_document(capture_document, capsule_host_root, fs=fs,
                             expected_cycle_id=capture_document.get('cycleId'))
    result['hostCapsuleCipherSha256'] = capsule_cipher_sha256
    result['sidecarMemberSha256'] = sidecar_sha
    return result


def verify_current_live(capture_document: dict, live_host_root: Path, *, fs=None) -> dict:
    """Recompute CURRENT89 against the typed snapshot with the exact key exclusion."""
    validate_capture_document_structure(capture_document)
    verify_module=_load_pinned_host_module('verify_mounted_config_trees',VERIFY_MODULE_SHA256)
    return verify_module.verify_current_document(capture_document, Path(live_host_root), fs=fs)


class _BoundedReader:
    def __init__(self, stream, maximum):
        self.stream, self.maximum, self.total = stream, maximum, 0
    def read(self, size=-1):
        if size < 0 or size > 16 * 1024 * 1024:
            raise Blocked('CAPSULE_TAR_READ_CHUNK_BOUND')
        data = self.stream.read(size)
        self.total += len(data)
        if self.total > self.maximum:
            raise Blocked('CAPSULE_TAR_DECOMPRESSED_BOUND')
        return data


class _DigestReader:
    def __init__(self, stream, maximum=1_500_000_000):
        self.stream, self.maximum, self.total = stream, maximum, 0
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        if size < 0 or size > 16 * 1024 * 1024:
            raise Blocked('CAPSULE_PLAINTEXT_STREAM_CHUNK_BOUND')
        data = self.stream.read(size)
        self.total += len(data)
        if self.total > self.maximum:
            raise Blocked('CAPSULE_PLAINTEXT_STREAM_BOUND')
        self.digest.update(data)
        return data


def verify_capsule_plaintext(capture_document: dict, sidecar_bytes: bytes,
                             archive_stream) -> dict:
    """Verify capsule members without materializing the decrypted archive.

    The fixed passphrase member is only compared by archive header custody
    metadata; its bytes are never extracted, hashed, or written to disk.
    """
    capture_module=_load_pinned_host_module('capture_mounted_config_trees',CAPTURE_MODULE_SHA256)
    REDACTED_SOURCE=capture_module.REDACTED_SOURCE;REDACTED_MEMBER=capture_module.REDACTED_MEMBER
    descriptor(sidecar_bytes, capture_document)
    expected = {}
    sources = capture_document['sources']
    prefixes = []
    for row in sources:
        root_member = 'host' + row['sourcePath']
        prefixes.append(root_member.rstrip('/') + '/')
        for record in row['records']:
            rel = '' if record['path'] == '.' else '/' + record['path']
            expected.setdefault(root_member + rel, []).append((row, record))
    sensitive = 'host' + REDACTED_SOURCE + '/' + REDACTED_MEMBER
    if sensitive in expected:
        raise Blocked('CAPSULE_CREDENTIAL_IN_HASH_SET')
    sidecar_member = 'host/var/lib/platform-host-recovery/mounted-config-tree-records.json'
    seen, credential_seen, sidecar_seen = set(), False, None
    matched = data_total = 0
    bounded = _BoundedReader(archive_stream, 1_600_000_000)
    with tarfile.open(fileobj=bounded, mode='r|') as tf:
        for member in tf:
            raw_name = member.name
            name = raw_name
            while name.startswith('./'):
                name = name[2:]
            if name == 'host/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase':
                raise Blocked('CAPSULE_CREDENTIAL_MUST_BE_OMITTED')
            if (not isinstance(name, str) or name.startswith('/') or
                    ('\\' in name and name not in ESCAPED_REGULAR_MEMBERS | ESCAPED_SYMLINK_MEMBERS) or
                    any(part in ('', '.', '..') for part in name.split('/'))):
                raise Blocked('CAPSULE_MEMBER_PATH')
            if name in ESCAPED_REGULAR_MEMBERS:
                if not member.isfile():raise Blocked('CAPSULE_ESCAPED_MEMBER_TYPE')
                continue
            if name in ESCAPED_SYMLINK_MEMBERS:
                if not member.issym():raise Blocked('CAPSULE_ESCAPED_MEMBER_TYPE')
                continue
            if name == sensitive:
                if credential_seen or not member.isfile():
                    raise Blocked('CAPSULE_CREDENTIAL_MEMBER_SHAPE')
                credential_seen = True
                policy = capture_document['excludedSensitiveEntries'][0]
                if (member.uid != policy['uid'] or member.gid != policy['gid'] or
                        stat.S_IMODE(member.mode) != policy['mode'] or member.size != policy['bytes']):
                    raise Blocked('CAPSULE_CREDENTIAL_HEADER_DIFFERS')
                # Do not call extractfile for this member.
                continue
            if name == sidecar_member:
                if sidecar_seen is not None or not member.isfile() or member.size > MAX_SIDECAR_BYTES:
                    raise Blocked('CAPSULE_SIDECAR_MEMBER_SHAPE')
                if member.uid != 0 or member.gid != 0 or stat.S_IMODE(member.mode) != 0o600:
                    raise Blocked('CAPSULE_SIDECAR_MEMBER_METADATA')
                stream = tf.extractfile(member)
                data = stream.read(MAX_SIDECAR_BYTES + 1)
                if len(data) != member.size or data != sidecar_bytes:
                    raise Blocked('CAPSULE_SIDECAR_MEMBER_DIFFERS')
                sidecar_seen = hashlib.sha256(data).hexdigest()
                continue
            rows = expected.get(name)
            if rows is None:
                if any(name.startswith(prefix) for prefix in prefixes):
                    raise Blocked('CAPSULE_CONFIG_UNEXPECTED_MEMBER')
                continue
            if name in seen:
                raise Blocked('CAPSULE_CONFIG_DUPLICATE_MEMBER')
            seen.add(name)
            kinds = {record.get('kind') for _, record in rows}
            if len(kinds) != 1:
                raise Blocked('CAPSULE_CONFIG_OVERLAPPING_TYPE')
            kind = next(iter(kinds))
            if kind == 'directory':
                valid = member.isdir()
            elif kind == 'symlink':
                valid = member.issym() and member.linkname == rows[0][1].get('target')
            else:
                # Overlapping fixed roots may name the same absolute inode with
                # distinct *relative* groups (directory child versus a file
                # root).  Compare only their fully qualified archive heads.
                heads={'host'+row['sourcePath']+
                       ('/'+record['hardlinkGroup'] if record['hardlinkGroup']!='.' else '')
                       for row,record in rows}
                if len(heads)!=1:
                    raise Blocked('CAPSULE_CONFIG_HARDLINK_OVERLAP')
                head=next(iter(heads))
                if any(record.get('bytes')!=rows[0][1].get('bytes') or
                       record.get('sha256')!=rows[0][1].get('sha256')
                       for _,record in rows):
                    raise Blocked('CAPSULE_CONFIG_CONTENT_HASH')
                if head == name:
                    valid=member.isfile()
                else:
                    valid=member.islnk() and member.linkname==head and member.size==0
            if not valid:
                raise Blocked('CAPSULE_CONFIG_MEMBER_TYPE')
            for _, record in rows:
                if (member.uid != record['uid'] or member.gid != record['gid'] or
                        stat.S_IMODE(member.mode) != record['mode']):
                    raise Blocked('CAPSULE_CONFIG_HEADER_METADATA')
            if kind == 'file' and head == name:
                if member.size != rows[0][1].get('bytes'):
                    raise Blocked('CAPSULE_CONFIG_MEMBER_SIZE')
                data_total += member.size
                if data_total > 70_000_000_000:
                    raise Blocked('CAPSULE_CONFIG_CONTENT_BOUND')
                stream = tf.extractfile(member)
                digest = hashlib.sha256(); count = 0
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    count += len(block); digest.update(block)
                    if count > member.size:
                        raise Blocked('CAPSULE_CONFIG_MEMBER_OVERRUN')
                if count != member.size or any(digest.hexdigest() != r.get('sha256') for _, r in rows):
                    raise Blocked('CAPSULE_CONFIG_CONTENT_HASH')
            matched += len(rows)
    # Bound and consume any trailing decompressed tar bytes as well.
    while bounded.read(1024 * 1024):
        pass
    if credential_seen or sidecar_seen is None or seen != set(expected):
        raise Blocked('CAPSULE_CONFIG_MEMBER_SET_INCOMPLETE')
    return {'schema': 'platform.mounted-config-capsule-readback/v1', 'status': 'passed',
            'cycleId': capture_document['cycleId'], 'sourceCount': 89,
            'matchedRecords': matched, 'regularBytes': capture_document['regularBytes'],
            'archiveFilePayloadBytes': data_total,
            'treeDigests': [{'sourcePath': r['sourcePath'], 'resourceId': r['resourceId'],
                             'scopeMappingClass': r['scopeMappingClass'], 'treeDigest': r['treeDigest'],
                             'recordSetSha256': r['recordSetSha256'], 'recordCount': r['recordCount'],
                             'regularBytes': r['regularBytes']} for r in sources],
            'sameCycleCapsuleVerified': True, 'sidecarMemberSha256': sidecar_seen,
            'credentialContentRead': False, 'credentialArchived': False,
            'separateGpgCredentialCustodyRequiredForRestore': True, 'offsiteVerified': False}


def read_capsule_sidecar_member(archive_path: Path) -> tuple[bytes,str,str,int]:
    """Read the one bounded metadata-only sidecar, never the credential member."""
    archive_path=Path(archive_path)
    archive_sha,archive_bytes=_secure_file_hash(archive_path)
    if archive_bytes>1_500_000_000:raise Blocked('CAPSULE_PLAINTEXT_SIZE')
    target='host/var/lib/platform-host-recovery/mounted-config-tree-records.json'
    found=None
    with archive_path.open('rb') as raw:
        decompressor=gzip.GzipFile(fileobj=raw,mode='rb')
        bounded=_BoundedReader(decompressor,1_600_000_000)
        try:
            with tarfile.open(fileobj=bounded,mode='r|') as tf:
                for member in tf:
                    normalized=member.name
                    while normalized.startswith('./'):
                        normalized=normalized[2:]
                    if normalized=='host/home/platform_infrastructure/v1-fresh-runtime/critical/v1-local-private_confidential-backup-passphrase':
                        raise Blocked('CAPSULE_CREDENTIAL_MUST_BE_OMITTED')
                    if normalized==target:
                        if found is not None or not member.isfile() or member.size>MAX_SIDECAR_BYTES:
                            raise Blocked('CAPSULE_SIDECAR_MEMBER_SHAPE')
                        if (member.uid!=0 or member.gid!=0 or stat.S_IMODE(member.mode)!=0o600):
                            raise Blocked('CAPSULE_SIDECAR_MEMBER_METADATA')
                        stream=tf.extractfile(member); data=stream.read(MAX_SIDECAR_BYTES+1)
                        if len(data)!=member.size:raise Blocked('CAPSULE_SIDECAR_MEMBER_TRUNCATED')
                        found=data
            while bounded.read(1024*1024):
                pass
        finally:
            decompressor.close()
    if found is None:raise Blocked('CAPSULE_SIDECAR_MEMBER_MISSING')
    return found,hashlib.sha256(found).hexdigest(),archive_sha,archive_bytes


def verify_capsule_archive_file(archive_path: Path, expected_capture_descriptor: dict) -> dict:
    """Recompute the same-cycle result from the authenticated plaintext archive."""
    sidecar_bytes,sidecar_sha,archive_sha,archive_bytes=read_capsule_sidecar_member(archive_path)
    try:sidecar=json.loads(sidecar_bytes)
    except (ValueError,UnicodeDecodeError):raise Blocked('CAPSULE_SIDECAR_JSON') from None
    actual=descriptor(sidecar_bytes,sidecar)
    if actual!=expected_capture_descriptor:
        raise Blocked('CAPSULE_SIDECAR_TYPED_RECEIPT_DIFFERS')
    with Path(archive_path).open('rb') as raw:
        archive=gzip.GzipFile(fileobj=raw,mode='rb')
        try:
            result=verify_capsule_plaintext(sidecar,sidecar_bytes,archive)
        finally:
            archive.close()
    result.update({'sidecarMemberSha256':sidecar_sha,
                   'capsulePlaintextSha256':archive_sha,
                   'capsulePlaintextBytes':archive_bytes})
    return result


def decrypt_and_verify_capsule(capsule_cipher: Path, sidecar_bytes: bytes,
                               sidecar_document: dict, gnupg_home: Path,
                               expected_capsule_sha256: str,
                               key_path: Path = GPG_KEY_PATH) -> dict:
    """Stream-decrypt and verify the nested host capsule without a plaintext copy."""
    capsule_cipher, gnupg_home, key_path = Path(capsule_cipher), Path(gnupg_home), Path(key_path)
    if key_path != GPG_KEY_PATH:
        raise Blocked('CAPSULE_KEY_PATH')
    cap_sha, cap_bytes = _secure_file_hash(capsule_cipher)
    if not HEX.fullmatch(str(expected_capsule_sha256)) or cap_sha != expected_capsule_sha256:
        raise Blocked('CAPSULE_CIPHERTEXT_BINDING')
    if (gnupg_home.exists() or gnupg_home.is_symlink() or
            gnupg_home.parent != GPG_RUNTIME_ROOT or
            not re.fullmatch(r'g16-[0-9a-f]{32}', gnupg_home.name) or
            len(str(gnupg_home) + '/S.gpg-agent') >= 100 or
            gnupg_home.parent.resolve(strict=True) != gnupg_home.parent):
        raise Blocked('CAPSULE_GNUPG_HOME')
    gnupg_home.mkdir(mode=0o700); os.chmod(gnupg_home, 0o700)
    info = gnupg_home.lstat()
    if (gnupg_home.is_symlink() or not stat.S_ISDIR(info.st_mode) or
            info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise Blocked('CAPSULE_GNUPG_HOME_CUSTODY')
    proc = None
    try:
        proc = subprocess.Popen(['gpg', '--no-options', '--homedir', str(gnupg_home), '--batch',
            '--pinentry-mode', 'loopback', '--passphrase-file', str(key_path),
            '--decrypt', str(capsule_cipher)], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        raw = _DigestReader(proc.stdout)
        archive = gzip.GzipFile(fileobj=raw, mode='rb')
        result = verify_capsule_plaintext(sidecar_document, sidecar_bytes, archive)
        proc.stdout.close()
        try:
            code = proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise Blocked('CAPSULE_DECRYPT_PROCESS_WONT_STOP') from None
            raise Blocked('CAPSULE_DECRYPT_TIMEOUT') from None
        if code != 0:
            raise Blocked('CAPSULE_DECRYPT_FAILED')
        result.update({'capsuleCipherSha256': cap_sha, 'capsuleCipherBytes': cap_bytes,
            'capsulePlaintextSha256': raw.digest.hexdigest(), 'capsulePlaintextBytes': raw.total,
            'encryptedCapsuleDecrypted': True})
        return result
    except BaseException:
        if proc is not None:
            try:
                proc.stdout.close()
            except Exception:
                pass
            try:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass
        raise
    finally:
        cleanup_short_gpg_home(gnupg_home)

def finalize_equivalence(readback: dict, authenticated_point: dict) -> dict:
    """Derive scope-gate inputs from a recomputed native point plus capsule result."""
    membership = authenticated_point.get('authenticatedMembership') if isinstance(authenticated_point, dict) else None
    if (not isinstance(membership, dict) or membership.get('schema') != 'platform.active87-authenticated-membership/v1' or
            membership.get('status') != 'passed' or authenticated_point.get('status') != 'passed' or
            authenticated_point.get('manifestId') != 'manifest-scheduled-platform-20260929-182357-1f9954' or
            authenticated_point.get('manifestDigest') != 'baf72a7c4ff5d2266b71afe4865ebffeb8be6c363dfc31c12f3a865389009b2c'):
        raise Blocked('NATIVE_ACTIVE87_MEMBERSHIP_REQUIRED')
    overlay_sha = authenticated_point.get('sourceOverlaySha256')
    membership_sha = hashlib.sha256(canonical(membership)).hexdigest()
    if (readback.get('hostCapsuleCipherSha256') != authenticated_point.get('hostCapsuleSha256') or
            readback.get('sidecarMemberSha256') != membership.get('sourceProofs', {}).get('mountedConfigSidecarSha256') or
            membership.get('receipts', {}).get('source-overlay') != authenticated_point.get('overlayReceiptSha256')):
        raise Blocked('MOUNTED_CONFIG_POINT_READBACK_BINDING')
    derived = output_equivalence_rows(readback, overlay_sha, membership_sha)
    return {
        'schema': 'platform.active87-mounted-config-equivalence/v2',
        'status': 'passed',
        'manifestId': authenticated_point['manifestId'],
        'manifestDigest': authenticated_point['manifestDigest'],
        'nativePointProofSha256': authenticated_point.get('proofSha256'),
        'nativeMembershipSha256': membership_sha,
        'hostCapsuleCipherSha256': readback['hostCapsuleCipherSha256'],
        'mountedConfigSidecarSha256': readback['sidecarMemberSha256'],
        'cycleId': readback['cycleId'],
        **derived,
        'offsiteVerified': True,
        'productionModified': False,
    }


def extend_package_file_index(files: list, sidecar_bytes: bytes, sidecar: dict) -> list:
    if not isinstance(files, list) or len(files) != 3:
        raise Blocked('BASE_TYPED_MEMBER_SET')
    names = [row.get('name') for row in files if isinstance(row, dict)]
    if set(names) != EXPECTED_PACKAGE_MEMBERS or len(set(names)) != 3:
        raise Blocked('BASE_TYPED_MEMBER_NAMES')
    result = [dict(row) for row in files]
    result.append({'name': MEMBER, 'bytes': len(sidecar_bytes),
                   'sha256': hashlib.sha256(sidecar_bytes).hexdigest()})
    return result


def verify_binding(payload: dict, files: list, sidecar_bytes: bytes, sidecar: dict) -> dict:
    """Validate HMAC-authenticated payload/file-index data supplied by reader."""
    expected = descriptor(sidecar_bytes, sidecar)
    if payload.get('mountedConfigCapture') != expected:
        raise Blocked('MOUNTED_CONFIG_TYPED_RECEIPT_BINDING')
    rows = [r for r in files if isinstance(r, dict) and r.get('name') == MEMBER]
    if len(rows) != 1 or rows[0] != {
            'name': MEMBER, 'bytes': len(sidecar_bytes),
            'sha256': hashlib.sha256(sidecar_bytes).hexdigest()}:
        raise Blocked('MOUNTED_CONFIG_TYPED_FILE_INDEX_BINDING')
    if len(files) != 4 or {r.get('name') for r in files if isinstance(r, dict)} != EXPECTED_PACKAGE_MEMBERS | {MEMBER}:
        raise Blocked('MOUNTED_CONFIG_TYPED_MEMBER_SET')
    return expected


def output_equivalence_rows(readback: dict, artifact_sha256: str, native_membership_sha256: str) -> dict:
    """Compute post-readback reference proofs; never include these in signed sidecar."""
    if not HEX.fullmatch(str(artifact_sha256)) or not HEX.fullmatch(str(native_membership_sha256)):
        raise Blocked('MOUNTED_CONFIG_POSTREADBACK_IDENTITY')
    if readback.get('schema') != 'platform.mounted-config-capsule-readback/v1' or readback.get('status') != 'passed' or readback.get('sameCycleCapsuleVerified') is not True:
        raise Blocked('MOUNTED_CONFIG_CAPSULE_READBACK_REQUIRED')
    rows = readback.get('treeDigests')
    if not isinstance(rows, list) or len(rows) != 89:
        raise Blocked('MOUNTED_CONFIG_READBACK_COVERAGE')
    expected = _load_pinned_host_module('capture_mounted_config_trees',CAPTURE_MODULE_SHA256).fixed_sources()
    if [row.get('sourcePath') for row in rows] != [row['sourcePath'] for row in expected]:
        raise Blocked('MOUNTED_CONFIG_READBACK_SOURCE_SET')
    result = {}
    verified_trees = {}
    resources = []
    for row, fixed in zip(rows, expected):
        source = row.get('sourcePath')
        resource = row.get('resourceId')
        tree = row.get('treeDigest')
        if (not isinstance(source, str) or not isinstance(resource, str) or
                resource != fixed['resourceId'] or row.get('scopeMappingClass') != fixed['provider'] or
                not HEX.fullmatch(str(tree)) or source in result):
            raise Blocked('MOUNTED_CONFIG_READBACK_ROW')
        reference = {
            'schema': 'platform.mounted-config-reference-proof/v1',
            'sourcePath': source, 'resourceId': resource,
            'treeDigest': tree, 'recordSetSha256': row.get('recordSetSha256'),
            'recordCount': row.get('recordCount'), 'regularBytes': row.get('regularBytes'),
            'artifactSha256': artifact_sha256,
            'nativeMembershipSha256': native_membership_sha256,
            'captureCycleId': readback['cycleId'],
        }
        result[source] = {
            'treeDigest': tree,
            'artifactSha256': artifact_sha256,
            'referenceProofSha256': hashlib.sha256(canonical(reference)).hexdigest(),
        }
        verified_trees[source] = {'treeDigest': tree,
                                  'referenceProofSha256': result[source]['referenceProofSha256']}
        resources.append(resource)
    if len(result) != 89:
        raise Blocked('MOUNTED_CONFIG_READBACK_DUPLICATES')
    return {
        'configEquivalence': result,
        'authenticatedArtifacts': {artifact_sha256: {
            'manifestDigest': 'baf72a7c4ff5d2266b71afe4865ebffeb8be6c363dfc31c12f3a865389009b2c',
            'resourceIds': sorted(resources),
            'verifiedConfigTrees': verified_trees,
        }},
    }
