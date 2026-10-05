#!/usr/bin/python3
"""Recompute mounted-config metadata against the extracted same-cycle capsule.

Call only after the native G16 package reader has verified the typed overlay
HMAC and authenticated this sidecar as a package member. This routine checks
that the sidecar's full records match the actual extracted capsule trees.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

CAPTURE_MODULE_SHA256='f32d81ddf3809f6b19eacef069f9a823e7036472f562482f1534caef25fd5880'
CAPTURE_MODULE_PATH=Path(__file__).resolve().with_name('capture_mounted_config_trees.py')
def _load_capture_module():
    path=CAPTURE_MODULE_PATH;st=path.lstat()
    if (path.is_symlink() or path.resolve(strict=True)!=path or not stat.S_ISREG(st.st_mode) or
            st.st_uid not in {0,os.geteuid()} or st.st_mode&0o022 or st.st_nlink!=1 or
            hashlib.sha256(path.read_bytes()).hexdigest()!=CAPTURE_MODULE_SHA256):
        raise RuntimeError('CONFIG_CAPTURE_MODULE_PIN')
    for ancestor in (path.parent,*path.parent.parents):
        ast=ancestor.lstat()
        if ancestor.is_symlink() or not stat.S_ISDIR(ast.st_mode) or ast.st_mode&0o022:
            raise RuntimeError('CONFIG_CAPTURE_MODULE_ANCESTRY')
    spec=importlib.util.spec_from_file_location('mounted_config_capture_pinned',path)
    if spec is None or spec.loader is None:raise RuntimeError('CONFIG_CAPTURE_MODULE_IMPORT')
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    return module

_capture=_load_capture_module()
Blocked=_capture.Blocked
CATALOG_SHA=_capture.CATALOG_SHA;PLAN_SHA=_capture.PLAN_SHA
PARENT_DIGEST=_capture.PARENT_DIGEST;PARENT_ID=_capture.PARENT_ID
PROVIDER_COUNTS=_capture.PROVIDER_COUNTS
canonical=_capture.canonical;fixed_sources=_capture.fixed_sources
load_filesystem=_capture.load_filesystem;sha_bytes=_capture.sha_bytes
REDACTED_SOURCE=_capture.REDACTED_SOURCE;REDACTED_MEMBER=_capture.REDACTED_MEMBER


def verify_document(document: dict, capsule_host_root: Path, *,
                    fs=None, expected_cycle_id: str | None = None) -> dict:
    if not isinstance(document, dict) or document.get('schema') != 'platform.mounted-config-tree-capture/v1':
        raise Blocked('CONFIG_SIDECAR_SCHEMA')
    if (document.get('status') != 'captured-local-unpublished' or
            document.get('historicalRegistryOrigin') != {
                'manifestId': PARENT_ID, 'manifestDigest': PARENT_DIGEST,
                'catalogSha256': _capture.HISTORICAL_CATALOG_SHA} or
            document.get('sourceCount') != 91 or document.get('providerCounts') != PROVIDER_COUNTS or
            document.get('catalogSha256') != CATALOG_SHA or document.get('planSha256') != PLAN_SHA or
            document.get('claims') != {'sameCycleCapsuleVerified': False, 'offsiteVerified': False,
                                       'productionModified': False} or
            document.get('recoveryLimitations') != {'originalGpgCredentialArchived': False,
                'separateGpgCredentialCustodyRequiredForRestore': True}):
        raise Blocked('CONFIG_SIDECAR_SCOPE')
    excluded = document.get('excludedSensitiveEntries')
    if (not isinstance(excluded, list) or len(excluded) != 1 or
            set(excluded[0]) != {'sourcePath','relativePath','type','uid','gid','mode','bytes',
                                 'mtimeNs','nlink','contentRead','contentHash','xattrsRead'} or
            excluded[0].get('sourcePath') != REDACTED_SOURCE or
            excluded[0].get('relativePath') != REDACTED_MEMBER or
            excluded[0].get('type') != 'regular-file' or
            type(excluded[0].get('uid')) is not int or excluded[0].get('uid') < 0 or
            type(excluded[0].get('gid')) is not int or excluded[0].get('gid') < 0 or
            excluded[0].get('mode') != 0o600 or excluded[0].get('nlink') != 1 or
            excluded[0].get('contentRead') is not False or
            excluded[0].get('contentHash') is not None or
            excluded[0].get('xattrsRead') is not False or
            type(excluded[0].get('bytes')) is not int or excluded[0]['bytes'] <= 0 or
            type(excluded[0].get('mtimeNs')) is not int):
        raise Blocked('CONFIG_CREDENTIAL_EXCLUSION')
    cycle_id = document.get('cycleId')
    if not isinstance(cycle_id, str) or (expected_cycle_id is not None and cycle_id != expected_cycle_id):
        raise Blocked('CONFIG_SIDECAR_CYCLE')
    capsule_host_root = Path(capsule_host_root)
    if (not capsule_host_root.is_absolute() or capsule_host_root.resolve(strict=True) != capsule_host_root or
            capsule_host_root.is_symlink()):
        raise Blocked('CAPSULE_HOST_ROOT_NOT_CANONICAL')
    fs = fs or load_filesystem()
    fixed = fixed_sources()
    entries = document.get('sources')
    if not isinstance(entries, list) or len(entries) != 91:
        raise Blocked('CONFIG_SIDECAR_SOURCE_COUNT')
    if [row.get('sourcePath') for row in entries] != [row['sourcePath'] for row in fixed]:
        raise Blocked('CONFIG_SIDECAR_SOURCE_SET')
    seen_records = 0
    total_bytes = 0
    derived = []
    for row, pinned in zip(entries, fixed):
        if set(row) != {'sourcePath', 'resourceId', 'scopeMappingClass', 'treeDigest', 'recordSetSha256',
                        'recordCount', 'regularBytes', 'records'}:
            raise Blocked('CONFIG_SIDECAR_ROW_FIELDS')
        if (row.get('sourcePath') != pinned['sourcePath'] or row.get('resourceId') != pinned['resourceId'] or
                row.get('scopeMappingClass') != pinned['provider']):
            raise Blocked('CONFIG_SIDECAR_SOURCE_BINDING')
        rel = Path(pinned['sourcePath'].lstrip('/'))
        root = capsule_host_root.joinpath(*rel.parts)
        if root.is_symlink() or root.resolve(strict=True) != root:
            raise Blocked('CAPSULE_CONFIG_PATH_ALIAS')
        if pinned['sourcePath'] == REDACTED_SOURCE:
            # The new capsule intentionally omits the credential leaf. Check
            # its absence without following aliases; custody is separately
            # recorded by the live capture's metadata-only lstat row.
            secret = root / REDACTED_MEMBER
            try:
                secret.lstat()
            except FileNotFoundError:
                pass
            else:
                raise Blocked('CAPSULE_CREDENTIAL_MUST_BE_EXCLUDED')
            records = fs.records(root, excluded_relative=(REDACTED_MEMBER,))
        else:
            records = fs.records(root)
        digest = sha_bytes(canonical(records))
        if (records != row.get('records') or digest != row.get('treeDigest') or
                digest != row.get('recordSetSha256') or len(records) != row.get('recordCount')):
            raise Blocked('CAPSULE_CONFIG_TREE_DIFFERS_FROM_SIDECAR')
        regular_bytes = sum(x.get('bytes', 0) for x in records if x.get('kind') == 'file')
        if regular_bytes != row.get('regularBytes'):
            raise Blocked('CAPSULE_CONFIG_BYTE_COUNT')
        seen_records += len(records)
        total_bytes += regular_bytes
        derived.append({'sourcePath': pinned['sourcePath'], 'resourceId': pinned['resourceId'],
                        'scopeMappingClass': pinned['provider'], 'treeDigest': digest,
                        'recordSetSha256': digest, 'recordCount': len(records),
                        'regularBytes': regular_bytes})
    if seen_records != document.get('recordCount') or total_bytes != document.get('regularBytes'):
        raise Blocked('CONFIG_SIDECAR_AGGREGATE_COUNTS')
    return {
        'schema': 'platform.mounted-config-capsule-readback/v1',
        'status': 'passed', 'cycleId': cycle_id,
        'catalogSha256': document['catalogSha256'], 'planSha256': document['planSha256'],
        'sourceCount': 91, 'recordCount': seen_records, 'regularBytes': total_bytes,
        'treeDigests': derived, 'sameCycleCapsuleVerified': True,
        'offsiteVerified': False,
    }


def verify_current_document(document: dict, live_host_root: Path, *, fs=None) -> dict:
    """Compare current live config with the signed capture, excluding only the key leaf.

    Unlike ``verify_document``, the live passphrase is expected to remain
    present. It is checked with lstat-only custody metadata and passed as one
    exact excluded relative path to both records() and tree_seal(). The signed
    capsule still requires byte-exact mtime records in verify_document(); only
    a live timestamp change is non-semantic for recovery.
    """
    if not isinstance(document, dict) or document.get('schema') != 'platform.mounted-config-tree-capture/v1':
        raise Blocked('CONFIG_SIDECAR_SCHEMA')
    fixed=fixed_sources()
    entries=document.get('sources')
    if (document.get('status')!='captured-local-unpublished' or document.get('sourceCount')!=91 or
            document.get('catalogSha256')!=CATALOG_SHA or document.get('planSha256')!=PLAN_SHA or
            not isinstance(entries,list) or len(entries)!=91 or
            [row.get('sourcePath') for row in entries]!=[row['sourcePath'] for row in fixed]):
        raise Blocked('LIVE_CONFIG_SIDECAR_SCOPE')
    secret_rows=document.get('excludedSensitiveEntries')
    if not isinstance(secret_rows,list) or len(secret_rows)!=1:
        raise Blocked('LIVE_CONFIG_CREDENTIAL_EXCLUSION')
    secret=secret_rows[0]
    if (secret.get('sourcePath')!=REDACTED_SOURCE or secret.get('relativePath')!=REDACTED_MEMBER or
            secret.get('type')!='regular-file' or secret.get('mode')!=0o600 or secret.get('nlink')!=1 or
            secret.get('contentRead') is not False or secret.get('contentHash') is not None or
            secret.get('xattrsRead') is not False):
        raise Blocked('LIVE_CONFIG_CREDENTIAL_POLICY')
    live_host_root=Path(live_host_root)
    if (not live_host_root.is_absolute() or live_host_root.resolve(strict=True)!=live_host_root or
            live_host_root.is_symlink()):
        raise Blocked('LIVE_HOST_ROOT_NOT_CANONICAL')
    fs=fs or load_filesystem()
    before={};total_records=total_bytes=0
    for row,pinned in zip(entries,fixed):
        if (row.get('sourcePath')!=pinned['sourcePath'] or row.get('resourceId')!=pinned['resourceId'] or
                row.get('scopeMappingClass')!=pinned['provider']):
            raise Blocked('LIVE_CONFIG_SOURCE_BINDING')
        root=live_host_root.joinpath(*Path(pinned['sourcePath'].lstrip('/')).parts)
        if root.is_symlink() or root.resolve(strict=True)!=root:
            raise Blocked('LIVE_CONFIG_PATH_ALIAS')
        excluded=(REDACTED_MEMBER,) if pinned['sourcePath']==REDACTED_SOURCE else ()
        if excluded:
            key=root/REDACTED_MEMBER
            item=key.lstat()
            if (stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode) or item.st_uid!=secret.get('uid') or
                    item.st_gid!=secret.get('gid') or stat.S_IMODE(item.st_mode)!=secret.get('mode') or
                    item.st_size!=secret.get('bytes') or item.st_nlink!=secret.get('nlink')):
                raise Blocked('LIVE_CONFIG_CREDENTIAL_CUSTODY_DIFFERS')
        seal=fs.tree_seal(root,excluded_relative=excluded)
        records=fs.records(root,excluded_relative=excluded)
        captured=row.get('records')
        if (not isinstance(captured,list) or not all(isinstance(item,dict) for item in captured) or
                [{k:v for k,v in item.items() if k!='mtimeNs'} for item in records] !=
                [{k:v for k,v in item.items() if k!='mtimeNs'} for item in captured] or
                len(records)!=row.get('recordCount')):
            raise Blocked('LIVE_CONFIG_TREE_DIFFERS_FROM_CAPTURE')
        bytes_total=sum(r.get('bytes',0) for r in records if r.get('kind')=='file')
        if bytes_total!=row.get('regularBytes') or fs.tree_seal(root,excluded_relative=excluded)!=seal:
            raise Blocked('LIVE_CONFIG_TREE_CHANGED_DURING_VERIFY')
        total_records+=len(records);total_bytes+=bytes_total
        # Expose the HMAC/capsule-verified reference digest after a complete
        # semantic comparison. A live mtime-only change must not change the
        # canonical point or make later membership verification nondeterministic.
        before[pinned['sourcePath']]=row['treeDigest']
    if total_records!=document.get('recordCount') or total_bytes!=document.get('regularBytes'):
        raise Blocked('LIVE_CONFIG_AGGREGATE_DIFFERS')
    return {'schema':'platform.mounted-config-current-verification/v1','status':'passed',
            'cycleId':document['cycleId'],'sourceCount':91,'recordCount':total_records,
            'credentialContentRead':False,'credentialContentHashed':False,'credentialXattrsRead':False,
            'treeDigests':before,'offsiteVerified':False,'productionModified':False}
