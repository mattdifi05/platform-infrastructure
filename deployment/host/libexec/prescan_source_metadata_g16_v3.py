#!/usr/bin/python3
"""Root-only, read-only, unsigned 57-source metadata prescan for later g16 binding."""
from __future__ import annotations
import datetime
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile


OVERLAY_MODULE_SHA256 = '30bfde6ae7d68d8ed22f016e67f2bf23f2bbc79933b6047f4201eed536cdd79d'

def _load_pinned_overlay():
    script = Path(__file__).absolute()
    if script.is_symlink() or script.resolve() != script:
        raise RuntimeError('prescan helper path is not canonical')
    path = script.with_name('source_metadata_overlay_v3.py')
    info = path.lstat()
    expected_owner = 0 if os.geteuid() == 0 else os.geteuid()
    if (path.is_symlink() or path.resolve() != path or not stat.S_ISREG(info.st_mode) or
            info.st_nlink != 1 or info.st_uid != expected_owner or info.st_mode & 0o022):
        raise RuntimeError('metadata overlay module is not a regular single-link file')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != OVERLAY_MODULE_SHA256:
        raise RuntimeError('metadata overlay module pin differs')
    spec = importlib.util.spec_from_file_location('source_metadata_overlay_v3_pinned', path)
    if spec is None or spec.loader is None:
        raise RuntimeError('metadata overlay module cannot be loaded')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


overlay = _load_pinned_overlay()

LIVE_ROOT=Path('/home/platform_infrastructure/v1-fresh-data/src')
BASELINE_ROOT=Path('/var/lib/platform-completeness-candidate-20260930/isolated-source-restored')
SOURCE_PROOF=Path('/var/lib/platform-completeness-candidate-20260930/isolated-source-proof.json')
EXPECTED_SOURCES=Path('/usr/local/libexec/expected-sources.json')
OUTPUT_ROOT=Path('/var/lib/platform-completeness-candidate-20260930/source-metadata-prescan-v3')
MAX_OUTPUT=600_000_000
BASELINE_PROOF_SHA256='a98afab03659fb1f833c8890dcaeb5876d454f80bc3d6f878a432174456b3be6'
BASELINE_MANIFEST_ID='manifest-scheduled-platform-20260929-182357-1f9954'
BASELINE_MANIFEST_DIGEST='baf72a7c4ff5d2266b71afe4865ebffeb8be6c363dfc31c12f3a865389009b2c'
BASELINE_MEMBER_COUNT=771615
BASELINE_REGULAR_BYTES=13345853860


def _sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def _private_dir(path):
    path=Path(path)
    if path.is_symlink() or not path.is_dir() or path.resolve()!=path:
        raise RuntimeError('prescan output must be a canonical directory')
    st=path.lstat()
    if st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o700:
        raise RuntimeError('prescan output directory must be caller-private mode 0700')


def _byte_identity_equal(left,right):
    if len(left)!=len(right):return False
    keys=('path','type','size','sha256','target')
    for a,b in zip(left,right):
        if {k:a[k] for k in keys if k in a}!={k:b[k] for k in keys if k in b}:return False
    return True


def _atomic_json(path,value):
    path=Path(path)
    temp=path.with_name(path.name+'.tmp')
    if path.exists() or path.is_symlink() or temp.exists() or temp.is_symlink():
        raise RuntimeError('prescan output already exists; no overwrite')
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()+b'\n'
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    os.replace(temp,path)


def prescan(live_root,baseline_root,expected_sources_path,source_proof,output_root):
    live_root=Path(live_root).absolute();baseline_root=Path(baseline_root).absolute();output_root=Path(output_root).absolute()
    if live_root.is_symlink() or live_root.resolve()!=live_root or not live_root.is_dir():raise RuntimeError('live root is not canonical')
    if baseline_root.is_symlink() or baseline_root.resolve()!=baseline_root or not baseline_root.is_dir():raise RuntimeError('baseline root is not canonical')
    if output_root.exists() or output_root.is_symlink():raise RuntimeError('prescan output already exists')
    output_parent=output_root.parent
    if output_parent.is_symlink() or output_parent.resolve()!=output_parent or not output_parent.is_dir():
        raise RuntimeError('prescan output parent is not canonical')
    parent_info=output_parent.lstat()
    if parent_info.st_uid!=os.geteuid() or stat.S_IMODE(parent_info.st_mode)!=0o700:
        raise RuntimeError('prescan output parent must be caller-private mode 0700')
    proof_path=Path(source_proof)
    proof_info=proof_path.lstat()
    if (proof_path.is_symlink() or not stat.S_ISREG(proof_info.st_mode) or proof_info.st_nlink!=1 or
            proof_info.st_uid!=os.geteuid() or proof_info.st_mode&0o077):
        raise RuntimeError('source restore proof must be a regular nofollow file')
    proof_bytes=proof_path.read_bytes()
    if len(proof_bytes)>8*1024*1024:raise RuntimeError('source restore proof exceeds bound')
    proof=json.loads(proof_bytes)
    proof_sha=hashlib.sha256(proof_bytes).hexdigest()
    mapping=overlay.load_expected_sources(Path(expected_sources_path),live_root)
    live_info=live_root.lstat();baseline_info=baseline_root.lstat()
    if live_root == LIVE_ROOT:
        if live_info.st_uid!=1000 or stat.S_IMODE(live_info.st_mode)!=0o755:
            raise RuntimeError('fixed live source root ownership or mode differs')
    elif live_info.st_uid!=os.geteuid():
        raise RuntimeError('fixture live root must be caller-owned')
    if (baseline_info.st_uid!=os.geteuid() or stat.S_IMODE(baseline_info.st_mode)!=0o700):
        raise RuntimeError('authenticated baseline root must be caller-owned mode 0700')
    if (proof_sha!=BASELINE_PROOF_SHA256 or proof.get('schema')!='platform.isolated-full-source-proof/v1' or
        proof.get('status')!='passed' or proof.get('sourceRestoreVerified') is not True or
        proof.get('streamIncluded') is not True or proof.get('memberCount')!=BASELINE_MEMBER_COUNT or
        proof.get('regularSourceBytes')!=BASELINE_REGULAR_BYTES or
        proof.get('sourceCount')!=57 or proof.get('manifestId')!=BASELINE_MANIFEST_ID or
        proof.get('manifestDigest')!=BASELINE_MANIFEST_DIGEST or proof.get('restoredRoot')!=str(baseline_root) or
        proof.get('archiveSha256')!=overlay.BASE_ARCHIVE_SHA256):
        raise RuntimeError('baseline extraction proof does not authenticate the fixed 57-source root')
    live_map=overlay._read_source_map(live_root,mapping);base_map=overlay._read_source_map(baseline_root,mapping)
    root_entries_before=overlay.capture_live_root_entries(live_root)
    output_root.mkdir(mode=0o700,parents=False);os.chmod(output_root,0o700);_private_dir(output_root)
    stage=output_root/'metadata-records.ndjson.gz.tmp';final=output_root/'metadata-records.ndjson.gz'
    source_rows=[];record_count=0;raw_hash=hashlib.sha256();raw_bytes=0
    try:
        with stage.open('xb') as raw_file:
            os.chmod(stage,0o600)
            with gzip.GzipFile(fileobj=raw_file,filename='',mode='wb',compresslevel=6,mtime=0) as gz:
                for rid in sorted(live_map):
                    first=overlay.inventory(live_map[rid]);baseline=overlay.inventory(base_map[rid])
                    if rid == overlay.EXPIRATION_RESOURCE:
                        descriptor=overlay.load_expiration_descriptor()
                        expired=overlay.validate_expiration_descriptor(descriptor)
                        base_by_path={row['path']:row for row in baseline}
                        live_paths={row['path'] for row in first}
                        if live_paths & {row['path'] for row in expired}:
                            raise RuntimeError('approved expired Stream cache entries unexpectedly exist live')
                        for entry in expired:
                            base_row=base_by_path.get(entry['path'])
                            if (base_row is None or base_row.get('type')!='file' or
                                base_row.get('size')!=entry['baseBytes'] or base_row.get('sha256')!=entry['baseSha256']):
                                raise RuntimeError('expired cache descriptor differs from authenticated baseline')
                        filtered=[row for row in baseline if row['path'] not in {entry['path'] for entry in expired}]
                        if not _byte_identity_equal(first,filtered):
                            raise RuntimeError('live Stream differs beyond exact approved 15 cache expirations')
                    elif not _byte_identity_equal(first,baseline):
                        raise RuntimeError('live bytes/names/types/targets differ from authenticated baseline: '+rid)
                    second=overlay.inventory(live_map[rid])
                    if first!=second:raise RuntimeError('live source changed during read-only metadata prescan: '+rid)
                    local=hashlib.sha256();bytes_count=sum(row.get('size',0) for row in first if row['type']=='file')
                    for row in first:
                        record={'resource':rid,**row};line=overlay.canonical(record)+b'\n'
                        raw_hash.update(line);local.update(line);raw_bytes+=len(line);record_count+=1
                        if raw_bytes>overlay.MAX_METADATA_UNCOMPRESSED or record_count>overlay.MAX_MEMBERS:
                            raise RuntimeError('metadata prescan exceeds fixed record/byte limit')
                        gz.write(line)
                    source_rows.append({'resource':rid,'directory':mapping[rid],'recordCount':len(first),
                                        'regularBytes':bytes_count,'metadataRowsSha256':local.hexdigest()})
                    del first,baseline,second
            raw_file.flush();os.fsync(raw_file.fileno())
        compressed_bytes=stage.stat().st_size;compressed_sha=_sha(stage)
        root_entries_after=overlay.capture_live_root_entries(live_root)
        if root_entries_before!=root_entries_after:raise RuntimeError('live root alias/cache declaration changed during prescan')
        if compressed_bytes>MAX_OUTPUT:raise RuntimeError('compressed prescan exceeds 600MB local bound')
        os.replace(stage,final)
        dfd=os.open(output_root,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(dfd);os.close(dfd)
        proof_out={'schema':'platform.source-metadata-prescan/v1','status':'passed-unbound-prescan',
          'capturedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'liveRoot':str(live_root),'baselineRoot':str(baseline_root),
          'baselineProofSha256':proof_sha,
          'baselineManifestId':proof['manifestId'],'baselineManifestDigest':proof['manifestDigest'],
          'baselineArchiveSha256':proof['archiveSha256'],'expectedSourcesSha256':overlay.EXPECTED_SOURCES_SHA256,
          'sourceMapSha256':overlay.EXPECTED_SOURCE_MAP_SHA256,'sourceCount':len(mapping),
          'recordCount':record_count,'rawBytes':raw_bytes,'rawSha256':raw_hash.hexdigest(),
          'compressedBytes':compressed_bytes,'compressedSha256':compressed_sha,
          'recordFile':'metadata-records.ndjson.gz','sources':source_rows,
          'liveRootEntries':root_entries_before,
          'expiredDerivedCacheFiles':{'catalogSha256':overlay.EXPIRATION_CATALOG_SHA256,
            'entries':overlay.validate_expiration_descriptor(overlay.load_expiration_descriptor())},
          'offsiteVerified':False,'fullyRecoverable':False,
          'bindingStatus':'no-current-ftps-parent-receipt-or-capsule-binding'}
        _atomic_json(output_root/'prescan-proof.json',proof_out)
        return proof_out
    except BaseException:
        try:stage.unlink()
        except OSError:pass
        raise


def main():
    if os.geteuid()!=0:raise SystemExit('root required for fixed server source paths')
    own_path = Path(__file__).absolute()
    own = own_path.lstat()
    overlay_path = own_path.with_name('source_metadata_overlay_v3.py')
    overlay_stat = overlay_path.lstat()
    expected_owner = 0 if os.geteuid() == 0 else os.geteuid()
    if (own_path.is_symlink() or own_path.resolve() != own_path or own.st_uid != 0 or
        stat.S_IMODE(own.st_mode) & 0o022 or overlay_path.is_symlink() or
        overlay_path.resolve() != overlay_path or overlay_stat.st_uid != expected_owner or
        stat.S_IMODE(overlay_stat.st_mode) & 0o022):
        raise SystemExit('prescan helper must be root-owned and not group/world writable')
    result=prescan(LIVE_ROOT,BASELINE_ROOT,EXPECTED_SOURCES,SOURCE_PROOF,OUTPUT_ROOT)
    print(json.dumps({'status':result['status'],'sourceCount':result['sourceCount'],
                      'recordCount':result['recordCount'],'compressedSha256':result['compressedSha256']},sort_keys=True))

if __name__=='__main__':main()
