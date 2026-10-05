#!/usr/bin/env python3
"""Build a local-only supplemental payload from explicit offline inputs.

This deliberately does not contact Docker, a database, FTPS, or a production
host. Source trees are compared with their catalog tar members; only omitted
members are staged. The result is plaintext and must be passed to the existing
authenticated/encrypted FTPS supplement publisher on the host.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import uuid

MAX_REMOTE_BYTES = 70_000_000_000
SENSITIVE_KEY = re.compile(r"password|secret|token|private.?key|credential", re.I)
MAX_XATTRS_PER_MEMBER = 128
MAX_XATTR_NAME_BYTES = 1024
MAX_XATTR_VALUE_BYTES = 65536
MAX_XATTR_BYTES_PER_MEMBER = 262144
PAX_XATTR_PREFIX = "CODEX.xattr.b64."
PAX_MTIME_NS = "CODEX.mtime_ns"
PAX_HARDLINK_GROUP = "CODEX.hardlink_group"


def digest_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _capture_fingerprint(path):
    info=path.lstat()
    base=(info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_nlink)
    xattrs = tuple((row["nameB64"], row["valueB64"]) for row in _xattrs(path))
    if stat.S_ISREG(info.st_mode): return base+(xattrs,digest_file(path))
    if stat.S_ISLNK(info.st_mode): return base+(xattrs,os.readlink(path))
    if stat.S_ISDIR(info.st_mode): return base+(xattrs,)
    raise ValueError("unsupported file type during capture")


def _xattrs(path):
    """Read bounded raw Linux xattrs without following a symlink."""
    try:
        names = os.listxattr(path, follow_symlinks=False)
        if len(names) > MAX_XATTRS_PER_MEMBER:
            raise ValueError("xattr count exceeds per-member bound")
        rows=[]; total=0
        for name in names:
            raw_name=os.fsencode(name)
            if not raw_name or len(raw_name)>MAX_XATTR_NAME_BYTES:
                raise ValueError("xattr name exceeds per-member bound")
            value=os.getxattr(path,name,follow_symlinks=False)
            if len(value)>MAX_XATTR_VALUE_BYTES:
                raise ValueError("xattr value exceeds per-member bound")
            total += len(raw_name)+len(value)
            if total>MAX_XATTR_BYTES_PER_MEMBER:
                raise ValueError("xattr bytes exceed per-member bound")
            rows.append({"nameB64":base64.b64encode(raw_name).decode("ascii"),
                         "valueB64":base64.b64encode(value).decode("ascii")})
        return sorted(rows,key=lambda row:row["nameB64"])
    except (AttributeError, OSError) as exc:
        raise ValueError("xattrs are unavailable or unreadable") from exc


def _pax_metadata(member,path,hardlink_group=None):
    info=path.lstat()
    headers={PAX_MTIME_NS:str(info.st_mtime_ns)}
    for row in _xattrs(path):
        name=base64.b64decode(row["nameB64"],validate=True)
        key=PAX_XATTR_PREFIX+base64.urlsafe_b64encode(name).decode("ascii").rstrip("=")
        headers[key]=row["valueB64"]
    if hardlink_group:
        headers[PAX_HARDLINK_GROUP]=hardlink_group
        headers["CODEX.hardlink_policy"]="materialized-independent-files"
    member.pax_headers=headers


def _read_json_input(path):
    path=Path(path)
    info=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
        raise ValueError("JSON input must be a regular unlinked file")
    return json.loads(path.read_text())


def _add_stable(tf,path,arcname):
    before=_capture_fingerprint(path)
    tf.add(path,arcname=arcname,recursive=False)
    after=_capture_fingerprint(path)
    if before!=after: raise ValueError("source changed during supplemental capture")
    return before


def _validate_output_directory(directory,require_root_owned):
    directory=Path(directory).absolute()
    if not require_root_owned: directory=directory.resolve(strict=True)
    parts=[Path("/")]
    cur=Path("/")
    for part in directory.parts[1:]:
        cur=cur/part; parts.append(cur)
    for index,path in enumerate(parts):
        info=path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("output path contains a symlink or non-directory")
        if require_root_owned:
            if info.st_uid!=0 or info.st_mode & 0o022:
                raise ValueError("root-owned non-writable output ancestry required")
        elif index==len(parts)-1:
            if info.st_uid!=os.geteuid() or info.st_mode & 0o077:
                raise ValueError("output directory must belong to caller with mode 0700")
        elif info.st_mode & 0o022:
            raise ValueError("writable ancestor in output path")


def archive_names(path, prefix):
    prefix = prefix.rstrip("/") + "/"
    with tarfile.open(path, "r:*") as tf:
        names = set()
        for m in tf.getmembers():
            p = PurePosixPath(m.name)
            if p.is_absolute() or ".." in p.parts:
                raise ValueError("unsafe catalog archive member")
            raw = p.as_posix().removeprefix("./")
            if raw == prefix[:-1] and m.isdir(): continue
            if not raw.startswith(prefix): raise ValueError("catalog member outside source resource prefix")
            rel=raw[len(prefix):].rstrip("/")
            if rel in names: raise ValueError("duplicate catalog archive member")
            if m.issym() or m.islnk():
                target=PurePosixPath(m.linkname)
                if target.is_absolute() or ".." in target.parts:
                    raise ValueError("unsafe catalog archive link")
            elif not (m.isfile() or m.isdir()):
                raise ValueError("special catalog archive member")
            names.add(rel)
        return names


def validate_baseline_unchanged(root, baseline_tar, prefix):
    """Fail closed if a catalog member changed or disappeared since its point."""
    root = Path(root).resolve(strict=True)
    prefix = prefix.rstrip("/") + "/"
    with tarfile.open(baseline_tar, "r:*") as tf:
        for member in tf.getmembers():
            raw = PurePosixPath(member.name).as_posix().removeprefix("./")
            if raw == prefix[:-1] and member.isdir():
                continue
            if not raw.startswith(prefix):
                raise ValueError("catalog member outside source resource prefix")
            rel = raw[len(prefix):].rstrip("/")
            if not rel:
                continue
            current = root.joinpath(*PurePosixPath(rel).parts)
            try:
                info = current.lstat()
            except FileNotFoundError as exc:
                raise ValueError("baseline member deleted; tombstone handling required") from exc
            expected_mode = member.mode & 0o7777
            if stat.S_IMODE(info.st_mode) != expected_mode or info.st_uid != member.uid or info.st_gid != member.gid:
                raise ValueError("baseline member metadata changed")
            if int(info.st_mtime) != int(member.mtime):
                raise ValueError("baseline member metadata changed")
            if member.isfile():
                if not stat.S_ISREG(info.st_mode) or info.st_size != member.size:
                    raise ValueError("baseline member type or size changed")
                stream = tf.extractfile(member)
                h = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(block)
                if digest_file(current) != h.hexdigest():
                    raise ValueError("baseline member content changed")
            elif member.isdir():
                if not stat.S_ISDIR(info.st_mode):
                    raise ValueError("baseline member type changed")
            elif member.issym():
                if not stat.S_ISLNK(info.st_mode) or os.readlink(current) != member.linkname:
                    raise ValueError("baseline symlink changed")
            else:
                raise ValueError("unsupported baseline member type")


def source_omissions(root, baseline_tar, archive_prefix):
    root = Path(root)
    if root.is_symlink(): raise ValueError("source root is a symlink")
    root = root.resolve(strict=True)
    if not root.is_dir(): raise ValueError("source root is not a directory")
    if (Path(baseline_tar).is_symlink() or not Path(baseline_tar).is_file() or
            Path(baseline_tar).lstat().st_nlink!=1):
        raise ValueError("baseline archive is missing or linked")
    baseline = archive_names(baseline_tar, archive_prefix)
    omitted = []
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs.sort(); files.sort()
        base = Path(current)
        # Do not traverse symlinked directories; record only safe relative links.
        for name in list(dirs):
            p = base / name
            if p.is_symlink():
                dirs.remove(name)
                _validate_link(root, p)
                rel = p.relative_to(root).as_posix()
                if rel not in baseline: omitted.append((p, rel, "symlink"))
            else:
                rel=p.relative_to(root).as_posix()
                if rel not in baseline: omitted.append((p,rel,"directory"))
        for name in files:
            p = base / name
            rel = p.relative_to(root).as_posix()
            if rel in baseline: continue
            mode = p.lstat().st_mode
            if stat.S_ISREG(mode):
                omitted.append((p, rel, "file"))
            elif stat.S_ISLNK(mode):
                _validate_link(root, p)
                omitted.append((p, rel, "symlink"))
            else: raise ValueError("special file in runtime source tree")
    return omitted


def _tree_fingerprint(root):
    root = Path(root).absolute()
    if root.resolve(strict=True)!=root:
        raise ValueError("source root contains a symlink or non-canonical ancestor")
    cur=Path("/")
    for part in root.parts[1:]:
        cur=cur/part
        info=cur.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            if cur!=root: raise ValueError("unsafe source ancestor")
            if not stat.S_ISDIR(info.st_mode): raise ValueError("source root is not a directory")
    rows = [(".", _capture_fingerprint(root))]
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs.sort(); files.sort()
        base = Path(current)
        for name in list(dirs):
            path = base / name
            if path.is_symlink():
                dirs.remove(name)
            _validate_link(root, path) if path.is_symlink() else None
            rows.append((path.relative_to(root).as_posix(), _capture_fingerprint(path)))
        for name in files:
            path = base / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode): _validate_link(root, path)
            elif not stat.S_ISREG(mode): raise ValueError("special file in source snapshot")
            rows.append((path.relative_to(root).as_posix(), _capture_fingerprint(path)))
    h = hashlib.sha256()
    for rel, fingerprint in sorted(rows):
        h.update(rel.encode()); h.update(b"\0"); h.update(repr(fingerprint).encode()); h.update(b"\n")
    return h.hexdigest()


def portable_tree_sha256(records):
    h = hashlib.sha256()
    for record in sorted(records, key=lambda row: row["path"]):
        line = json.dumps(record, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")
        h.update(line); h.update(b"\n")
    return h.hexdigest()


def _restorable_record(path, rel, kind, info, size=None, sha256=None, target=None,
                       hardlink_group=None):
    row = {"path": rel, "type": kind, "mode": stat.S_IMODE(info.st_mode),
           "uid": info.st_uid, "gid": info.st_gid, "mtime": int(info.st_mtime),
           "mtimeNs": info.st_mtime_ns, "xattrs": _xattrs(path)}
    if kind == "file": row.update(size=size, sha256=sha256)
    if kind == "symlink": row["target"] = target
    if hardlink_group: row["hardlinkGroup"] = hardlink_group
    return row


def _add_full_source_snapshot(tf, root, arcbase):
    """Write a current tree as replacement-ready regular files/directories/symlinks."""
    root = Path(root)
    if root.is_symlink(): raise ValueError("source root is a symlink")
    root = root.absolute()
    if root.resolve(strict=True)!=root: raise ValueError("source root contains unsafe ancestor")
    if not root.is_dir(): raise ValueError("source root is not a directory")
    before_tree = _tree_fingerprint(root)
    portable_records = []
    root_info = root.lstat()
    root_member = tarfile.TarInfo(arcbase); root_member.type = tarfile.DIRTYPE
    root_member.mode = stat.S_IMODE(root_info.st_mode); root_member.uid = root_info.st_uid
    root_member.gid = root_info.st_gid; root_member.mtime = root_info.st_mtime_ns / 1_000_000_000
    root_member.uname = ""; root_member.gname = ""
    _pax_metadata(root_member,root)
    tf.addfile(root_member)
    portable_records.append(_restorable_record(root, ".", "directory", root_info))
    inode_paths={}
    for current,dirs,files in os.walk(root,followlinks=False):
        dirs.sort();files.sort();base=Path(current)
        for name in list(dirs):
            p=base/name
            if p.is_symlink(): dirs.remove(name); _validate_link(root,p)
        for name in files:
            p=base/name; info=p.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_nlink>1:
                inode_paths.setdefault((info.st_dev,info.st_ino),[]).append(p.relative_to(root).as_posix())
            elif not stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                raise ValueError("special file in source snapshot")
    hardlink_groups={}
    for paths in inode_paths.values():
        if len(paths)>1:
            group="hg-"+hashlib.sha256("\n".join(sorted(paths)).encode()).hexdigest()[:24]
            hardlink_groups.update({rel:group for rel in paths})
    regular_bytes = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs.sort(); files.sort(); base = Path(current)
        for name in list(dirs):
            path = base / name; rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                dirs.remove(name); _validate_link(root, path)
                portable_records.append(_add_snapshot_symlink(tf, path, f"{arcbase}/{rel}", rel))
            else:
                info = path.lstat(); member = tarfile.TarInfo(f"{arcbase}/{rel}")
                member.type = tarfile.DIRTYPE; member.mode = stat.S_IMODE(info.st_mode)
                member.uid = info.st_uid; member.gid = info.st_gid; member.mtime = info.st_mtime_ns/1_000_000_000
                member.uname = ""; member.gname = ""; _pax_metadata(member,path); tf.addfile(member)
                portable_records.append(_restorable_record(path, rel, "directory", info))
        for name in files:
            path = base / name; rel = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                _validate_link(root, path)
                portable_records.append(_add_snapshot_symlink(tf, path, f"{arcbase}/{rel}", rel))
            elif stat.S_ISREG(info.st_mode):
                regular_bytes += info.st_size
                before = _capture_fingerprint(path)
                member = tarfile.TarInfo(f"{arcbase}/{rel}"); member.size = info.st_size
                member.mode = stat.S_IMODE(info.st_mode); member.uid = info.st_uid
                member.gid = info.st_gid; member.mtime = info.st_mtime_ns/1_000_000_000
                member.uname = ""; member.gname = ""
                group=hardlink_groups.get(rel)
                _pax_metadata(member,path,group)
                file_hash = before[-1]
                with open(path, "rb") as stream: tf.addfile(member, stream)
                if _capture_fingerprint(path) != before:
                    raise ValueError("source changed during supplemental capture")
                portable_records.append(_restorable_record(path, rel, "file", info,
                                                           size=info.st_size, sha256=file_hash,
                                                           hardlink_group=group))
            else: raise ValueError("special file in source snapshot")
    if _tree_fingerprint(root) != before_tree:
        raise ValueError("source tree changed during full snapshot")
    return before_tree, portable_tree_sha256(portable_records), regular_bytes, len(set(hardlink_groups.values()))


def _add_snapshot_symlink(tf, path, arcname, rel):
    before = _capture_fingerprint(path); info = path.lstat()
    member = tarfile.TarInfo(arcname); member.type = tarfile.SYMTYPE
    member.linkname = os.readlink(path); member.mode = stat.S_IMODE(info.st_mode)
    member.uid = info.st_uid; member.gid = info.st_gid; member.mtime = info.st_mtime_ns/1_000_000_000
    member.uname = ""; member.gname = ""; _pax_metadata(member,path); tf.addfile(member)
    if _capture_fingerprint(path) != before:
        raise ValueError("source changed during supplemental capture")
    return _restorable_record(path, rel, "symlink", info, target=member.linkname)


def _validate_link(root, path):
    target = os.readlink(path)
    if os.path.isabs(target): raise ValueError("absolute symlink in source tree")
    resolved = (path.parent / target).resolve(strict=False)
    if resolved != root and root not in resolved.parents:
        raise ValueError("symlink escapes source root")


def validate_acl_inventory(path, manifest):
    data = _read_json_input(path)
    if data.get("schema") != "platform.database-acl-inventory/v1":
        raise ValueError("ACL inventory schema missing")
    databases = data.get("databases")
    if (data.get("manifestId") != manifest.get("id") or
            data.get("manifestSignatureDigest") != manifest.get("signature", {}).get("digest") or
            data.get("manifestSignatureVerifiedByCollector") is not False or
            data.get("databaseCount") != 8 or not isinstance(databases, list) or len(databases) != 8):
        raise ValueError("ACL inventory incomplete")
    expected = {r["id"]: (r.get("engine"), r.get("name")) for r in manifest.get("resources", [])
                if r.get("kind") == "database"}
    if len(expected) != 8: raise ValueError("bound manifest database scope differs")
    if any(not isinstance(d, dict) or d.get("engine") not in ("postgres", "mariadb") or
           d.get("resourceId") not in expected or
           (d.get("engine"), d.get("database")) != expected[d.get("resourceId")] or
           not isinstance(d.get("rows"), list) or not d["rows"]
           for d in databases):
        raise ValueError("ACL database coverage incomplete")
    if {d["resourceId"] for d in databases} != set(expected):
        raise ValueError("ACL inventory database set differs from manifest")
    def scan(value):
        if isinstance(value, dict):
            if any(SENSITIVE_KEY.search(str(k)) or re.search(r"verifier|authentication", str(k), re.I) for k in value):
                raise ValueError("ACL inventory contains secret-bearing field")
            for v in value.values(): scan(v)
        elif isinstance(value, list):
            for v in value: scan(v)
        elif isinstance(value, str) and re.search(r"\b(?:md5|SCRAM-SHA-256)\$", value, re.I):
            raise ValueError("ACL inventory contains credential verifier")
    scan(data)
    return data


def docker_archive_ids(path, details=None, required_platform=('linux','amd64')):
    """Verify native image graphs, including sparse multi-platform OCI indexes."""
    ids = set()
    proof={'requiredPlatform':'/'.join(required_platform),'verifiedBlobs':0,
           'missingOtherPlatformDescriptors':0,'omittedAttestations':0}
    with tarfile.open(path, "r:*") as tf:
        archive_members = {}
        for member in tf.getmembers():
            if member.name in archive_members: raise ValueError("duplicate Docker archive member")
            member_path=PurePosixPath(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError("unsafe Docker archive member path")
            if not (member.isfile() or member.isdir()):
                raise ValueError("non-regular Docker archive member")
            archive_members[member.name] = member
        def read_json(name):
            member=archive_members.get(name)
            if member is None or not member.isfile(): raise ValueError("Docker metadata file is missing")
            stream=tf.extractfile(name)
            try: return json.load(stream)
            except (TypeError,json.JSONDecodeError) as exc: raise ValueError("invalid Docker metadata JSON") from exc
        verified=set()
        def verify_oci_blob(descriptor):
            digest=descriptor.get("digest") if isinstance(descriptor,dict) else None
            match=re.fullmatch(r"sha256:([0-9a-f]{64})",str(digest))
            if not match: raise ValueError("invalid OCI descriptor digest")
            name=f"blobs/sha256/{match.group(1)}"
            member=archive_members.get(name)
            if member is None or not member.isfile(): raise ValueError("OCI referenced blob is missing")
            if descriptor.get("size") is not None and descriptor["size"]!=member.size:
                raise ValueError("OCI blob size differs from descriptor")
            if digest not in verified:
                stream=tf.extractfile(name); h=hashlib.sha256()
                for block in iter(lambda:stream.read(1024*1024),b""): h.update(block)
                if h.hexdigest()!=match.group(1): raise ValueError("OCI blob digest mismatch")
                verified.add(digest);proof['verifiedBlobs']+=1
            return name

        if "index.json" in archive_members:
            layout=read_json("oci-layout")
            if not isinstance(layout,dict) or layout.get("imageLayoutVersion")!="1.0.0":
                raise ValueError("OCI image layout marker is invalid")
            index=read_json("index.json")
            descriptors=index.get("manifests") if isinstance(index,dict) else None
            if not isinstance(descriptors,list) or not descriptors:
                raise ValueError("OCI image index is empty")
            visiting=set();cache={}
            def graph(desc,depth=0,allow_sparse=False):
                if depth>8 or len(cache)>2048:raise ValueError('OCI graph exceeds bound')
                digest=desc.get('digest') if isinstance(desc,dict) else None
                if not re.fullmatch(r'sha256:[0-9a-f]{64}',str(digest)):
                    raise ValueError('invalid OCI descriptor digest')
                media=desc.get('mediaType','')
                platform=desc.get('platform',{})
                annotation=desc.get('annotations',{}).get('vnd.docker.reference.type')
                attestation=(platform.get('os'),platform.get('architecture'))==('unknown','unknown') and annotation=='attestation-manifest'
                name='blobs/sha256/'+digest.split(':')[1]
                if name not in archive_members:
                    other=(platform.get('os'),platform.get('architecture'))
                    manifest_type=media in ('application/vnd.oci.image.manifest.v1+json',
                                           'application/vnd.docker.distribution.manifest.v2+json',
                                           'application/vnd.oci.image.index.v1+json',
                                           'application/vnd.docker.distribution.manifest.list.v2+json')
                    if allow_sparse and manifest_type and attestation:
                        proof['omittedAttestations']+=1;return False
                    if (allow_sparse and manifest_type and all(other) and 'unknown' not in other and
                        other!=required_platform):
                        proof['missingOtherPlatformDescriptors']+=1;return False
                    raise ValueError('OCI required descriptor or payload blob is missing')
                if digest in visiting:raise ValueError('OCI descriptor cycle')
                if digest in cache:return cache[digest]
                visiting.add(digest);obj=read_json(verify_oci_blob(desc))
                if not isinstance(obj,dict) or obj.get('schemaVersion')!=2:
                    raise ValueError('invalid OCI manifest/index schema')
                if 'manifests' in obj:
                    children=obj['manifests']
                    if not isinstance(children,list) or not children or 'config' in obj or 'layers' in obj:
                        raise ValueError('invalid nested OCI index')
                    found=False
                    for child in children:found=graph(child,depth+1,True) or found
                else:
                    config=obj.get('config');layers=obj.get('layers')
                    if not isinstance(config,dict) or not isinstance(layers,list):
                        raise ValueError('OCI image manifest lacks config or layers')
                    config_name=verify_oci_blob(config);config_doc=read_json(config_name)
                    if not isinstance(config_doc,dict):raise ValueError('invalid OCI image config')
                    for layer in layers:verify_oci_blob(layer)
                    actual=(config_doc.get('os'),config_doc.get('architecture'))
                    if not all(actual) and not attestation:raise ValueError('OCI image platform config missing')
                    found=actual==required_platform and not attestation
                visiting.remove(digest);cache[digest]=found;return found
            for desc in descriptors:
                if not graph(desc):raise ValueError('OCI root lacks complete required platform image')
                ids.add(desc['digest'])
            if len(ids)!=len(descriptors): raise ValueError("duplicate OCI image manifest descriptor")
        else:
            manifest = read_json("manifest.json")
            if not isinstance(manifest, list) or not manifest:
                raise ValueError("Docker save manifest is empty")
            for image in manifest:
                config = image.get("Config")
                if not isinstance(config, str) or config.startswith("/") or ".." in Path(config).parts:
                    raise ValueError("unsafe Docker config path")
                cm = archive_members.get(config)
                if cm is None or not cm.isfile(): raise ValueError("Docker image config is not a regular archive file")
                stream = tf.extractfile(config); h = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b""): h.update(block)
                ids.add("sha256:" + h.hexdigest())
                layers = image.get("Layers")
                if not isinstance(layers, list): raise ValueError("Docker image layers missing")
                for layer in layers:
                    if (not isinstance(layer, str) or layer.startswith("/") or ".." in Path(layer).parts or
                            layer not in archive_members or not archive_members[layer].isfile()):
                        raise ValueError("Docker image layer is missing or unsafe")
    if details is not None:details.update(proof)
    return ids


def _manifest_bindings(manifest_path, expected_digest):
    manifest = _read_json_input(manifest_path)
    sig = manifest.get("signature", {})
    if (not expected_digest or sig.get("digest") != expected_digest or
            sig.get("digest") != manifest_document_digest(manifest)):
        raise ValueError("manifest digest differs from authenticated expected digest")
    resources = {r["id"]: r for r in manifest.get("resources", [])}
    artifacts = {a["resourceId"]: a for a in manifest.get("artifacts", [])}
    if len(artifacts) != len(manifest.get("artifacts", [])):
        raise ValueError("manifest has duplicate resource artifacts")
    return manifest, resources, artifacts


def manifest_document_digest(document):
    def canonical(value):
        if isinstance(value,list): return [canonical(item) for item in value]
        if isinstance(value,dict):
            return {key:canonical(value[key]) for key in sorted(value) if key!="signature"}
        return value
    encoded=json.dumps(canonical(document),separators=(",",":"),ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build(out, source_specs, image_archives, image_inventory_path, acl_path, budget,
          manifest_path, expected_manifest_digest, existing_bytes, require_root_owned=True,
          source_mode="full-current-source-snapshot"):
    if existing_bytes < 0 or existing_bytes > MAX_REMOTE_BYTES:
        raise ValueError("invalid current FTPS usage")
    if budget <= 0 or budget > MAX_REMOTE_BYTES - existing_bytes:
        raise ValueError("budget exceeds available FTPS headroom")
    manifest, manifest_resources, manifest_artifacts = _manifest_bindings(manifest_path, expected_manifest_digest)
    resource_ids = [spec[0] for spec in source_specs]
    expected_source_ids={r["id"] for r in manifest.get("resources",[]) if r.get("kind")=="source"}
    if len(expected_source_ids)!=16 or set(resource_ids)!=expected_source_ids:
        raise ValueError("all 16 manifest source roots are required for full-server completeness")
    if source_mode not in ("full-current-source-snapshot", "delta-fail-closed"):
        raise ValueError("unknown source capture mode")
    if len(image_archives) != 1:
        raise ValueError("one complete docker save archive for the running image inventory is required")
    inventory = _read_json_input(image_inventory_path)
    expected_images = {c.get("imageId") for c in inventory.get("containers", []) if c.get("running")}
    if not expected_images or None in expected_images:
        raise ValueError("running Docker image inventory is incomplete")
    image=Path(image_archives[0])
    if image.is_symlink() or not image.is_file() or image.stat().st_nlink!=1:
        raise ValueError('Docker archive is not a regular unlinked input')
    image_hash=digest_file(image);image_proof={}
    if docker_archive_ids(image,image_proof)!=expected_images:
        raise ValueError('Docker archive image IDs differ from running inventory')
    out = Path(out).absolute()
    report_path = out.with_suffix(out.suffix + ".json")
    if out.exists() or report_path.exists(): raise ValueError("output or report already exists")
    _validate_output_directory(out.parent,require_root_owned)
    acl = validate_acl_inventory(acl_path, manifest)
    tmp = out.with_name("." + out.name + "." + uuid.uuid4().hex + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    entries = []
    import io
    try:
      old_umask = os.umask(0o077)
      try:
        with open(tmp, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
          for resource, root, baseline, artifact_path, artifact_hash in source_specs:
            if resource not in manifest_resources or resource not in manifest_artifacts:
                raise ValueError("source resource missing from bound manifest")
            r, a = manifest_resources[resource], manifest_artifacts[resource]
            if r.get("kind") != "source" or not r.get("sourceDirectory"):
                raise ValueError("manifest resource is not a source")
            if a.get("path") != artifact_path or a.get("sha256") != artifact_hash:
                raise ValueError("baseline artifact path or digest differs from bound manifest")
            if digest_file(baseline) != artifact_hash:
                raise ValueError("baseline archive SHA-256 differs from manifest")
            if r["sourceDirectory"] != resource.split(":", 1)[1]:
                raise ValueError("source directory identity differs from resource ID")
            prefix = r["sourceDirectory"] + "/"
            archive_names(baseline, prefix)
            if source_mode == "full-current-source-snapshot":
              guard_hash, restorable_hash, tree_bytes, hardlink_groups = _add_full_source_snapshot(tf, root, f"runtime/{resource}")
              entries.append({"kind":"full-current-source-snapshot","resource":resource,
                              "path":f"runtime/{resource}","captureGuardSha256":guard_hash,
                              "restorableTreeSha256":restorable_hash,"regularBytes":tree_bytes,
                              "restore":"replace-entire-directory",
                              "metadataPolicy":"pax-xattrs-mtime-ns-v2",
                              "hardlinkPolicy":"materialized-independent-files",
                              "hardlinkGroups":hardlink_groups})
            else:
              validate_baseline_unchanged(root, baseline, prefix)
              for path, rel, kind in source_omissions(root, baseline, prefix):
                arc = f"runtime/{resource}/{rel}"
                fingerprint=_add_stable(tf,path,arc)
                entries.append({"kind":"omitted-source","resource":resource,"path":rel,"type":kind,
                                "bytes":path.lstat().st_size if kind=="file" else 0,
                                "sha256":fingerprint[-1] if kind == "file" else None})
          for p in image_archives:
            p = Path(p)
            if p.is_symlink(): raise ValueError("Docker image archive path is a symlink")
            p = p.resolve(strict=True)
            if p.stat().st_nlink!=1: raise ValueError("Docker image archive is hard-linked")
            if not tarfile.is_tarfile(p): raise ValueError("Docker image archive is not a tar")
            before_hash = digest_file(p)
            if before_hash!=image_hash:raise ValueError('Docker archive changed after preflight')
            arc = f"docker-images/{p.name}"
            tf.add(p, arcname=arc, recursive=False)
            if digest_file(p) != before_hash: raise ValueError("Docker archive changed during capture")
            entries.append({"kind":"docker-image-archive","path":arc,"bytes":p.stat().st_size,"sha256":before_hash})
          acl_bytes = json.dumps(acl, sort_keys=True, separators=(",", ":")).encode()
          info = tarfile.TarInfo("database-acl/inventory.json"); info.mode = 0o600; info.size = len(acl_bytes)
          tf.addfile(info, io.BytesIO(acl_bytes))
          entries.append({"kind":"database-acl-inventory","path":info.name,"bytes":len(acl_bytes),
                          "sha256":hashlib.sha256(acl_bytes).hexdigest()})
          docker_bytes = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
          info = tarfile.TarInfo("docker-images/runtime-inventory.json"); info.mode = 0o600; info.size = len(docker_bytes)
          tf.addfile(info, io.BytesIO(docker_bytes))
          entries.append({"kind":"docker-image-inventory","path":info.name,"bytes":len(docker_bytes),
                          "sha256":hashlib.sha256(docker_bytes).hexdigest()})
        syncfd=os.open(tmp,os.O_RDWR)
        try: os.fsync(syncfd)
        finally: os.close(syncfd)
      finally: os.umask(old_umask)
      size = tmp.stat().st_size
      if size > budget: raise ValueError("supplement exceeds FTPS headroom budget")
      os.replace(tmp, out)
      dfd = os.open(out.parent, os.O_RDONLY)
      try: os.fsync(dfd)
      finally: os.close(dfd)
    except Exception:
      tmp.unlink(missing_ok=True)
      raise
    omitted_bytes = sum(e["bytes"] for e in entries if e["kind"] == "omitted-source")
    full_source_bytes = sum(e["regularBytes"] for e in entries if e["kind"] == "full-current-source-snapshot")
    report = {"schema": "platform.backup-completeness-candidate/v1",
              "status": "local-plaintext-pending-authenticated-encryption",
              "fullyRecoverable": False, "atomicSnapshot": False,
              "consistency": "per-file drift guarded; cross-resource consistency not established",
              "sourceMetadataVersion": 2,
              "sourceMetadata": {"xattrs": "PAX CODEX base64 values; includes ACL xattrs",
                                 "mtime": "nanosecond exact via CODEX.mtime_ns",
                                 "hardlinks": "materialized independent regular files; source groups recorded"},
              "sourceCaptureMode": source_mode,
              "dockerArchiveVerification":image_proof,
              "sourceCount": len(resource_ids), "omittedSourceBytes": omitted_bytes,
              "fullSourceRegularBytes": full_source_bytes,
              "supplementBytes": size,
              "budgetBytes": budget, "ftpsLimitBytes": MAX_REMOTE_BYTES,
              "observedRemoteBytes": existing_bytes,
              "remoteAdmission": "not-evaluated-ciphertext-overhead-or-retention",
              "retention": {"schedule": "Monday/Wednesday/Friday", "maxAgeDays": 14,
                            "maxFtpsPoints": 6, "maxLocalPoints": 2},
              "manifestId": manifest.get("id"),
              "manifestDigest": expected_manifest_digest,
              "entries": entries, "archiveSha256": digest_file(out)}
    report_tmp = report_path.with_name("." + report_path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        fd = os.open(report_tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True); stream.write("\n")
            stream.flush(); os.fsync(stream.fileno())
        os.replace(report_tmp, report_path)
        dfd = os.open(out.parent, os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    except Exception:
        report_tmp.unlink(missing_ok=True); report_path.unlink(missing_ok=True); out.unlink(missing_ok=True)
        raise
    return report


def main():
    if os.geteuid() != 0: raise SystemExit("ROOT_HOST_REQUIRED")
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--source", action="append", default=[],
                   metavar="RESOURCE=ROOT=BASELINE_TAR=ARTIFACT_PATH=ARTIFACT_SHA256")
    p.add_argument("--image-archive", action="append", default=[])
    p.add_argument("--docker-inventory", required=True)
    p.add_argument("--acl-inventory", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--expected-manifest-digest", required=True,
                   help="digest copied from authenticated FTPS/manifest verification")
    p.add_argument("--existing-ftps-bytes", type=int, required=True,
                   help="fresh authenticated byte total for all objects in FTPS retention")
    p.add_argument("--budget-bytes", type=int)
    p.add_argument("--source-mode", choices=("full-current-source-snapshot", "delta-fail-closed"),
                   default="full-current-source-snapshot")
    a = p.parse_args()
    specs = []
    for value in a.source:
        parts = value.split("=", 4)
        if len(parts) != 5: p.error("--source must be RESOURCE=ROOT=BASELINE_TAR=ARTIFACT_PATH=ARTIFACT_SHA256")
        specs.append(tuple(parts))
    budget = a.budget_bytes if a.budget_bytes is not None else MAX_REMOTE_BYTES-a.existing_ftps_bytes
    print(json.dumps(build(a.out, specs, a.image_archive, a.docker_inventory,
                          a.acl_inventory, budget, a.manifest, a.expected_manifest_digest,
                          a.existing_ftps_bytes, source_mode=a.source_mode), indent=2))

if __name__ == "__main__": main()
