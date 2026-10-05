"""Real filesystem primitives; no service control, network, deletion or authority writes."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


class Blocked(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def sha(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise Blocked('EXPECTED_REGULAR_FILE')
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
        result = digest.hexdigest()
        after = os.fstat(stream.fileno())
        if any(getattr(before, k) != getattr(after, k) for k in
               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise Blocked('FILE_CHANGED_DURING_HASH')
        return result


def no_alias(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path or path.is_symlink():
        raise Blocked('PATH_ALIAS_OR_SYMLINK')
    return path


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, value):
    path = Path(path)
    no_alias(path.parent)
    if path.is_symlink():
        raise Blocked('JOURNAL_SYMLINK')
    fd, name = tempfile.mkstemp(prefix='.intent-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        sync_dir(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def identity(path):
    no_alias(path)
    item = Path(path).lstat()
    if not (stat.S_ISDIR(item.st_mode) or stat.S_ISREG(item.st_mode)):
        raise Blocked('EXPECTED_DIRECTORY_OR_REGULAR_FILE')
    return [item.st_dev, item.st_ino]


def xattrs(path):
    if hasattr(os, 'listxattr'):
        return {name: os.getxattr(path, name, follow_symlinks=False)
                for name in os.listxattr(path, follow_symlinks=False)}
    if sys.platform != 'darwin':
        raise Blocked('XATTR_ENUMERATION_UNAVAILABLE')
    # CPython macOS lacks the Linux os.*xattr API. Native read-only equivalents
    # permit real local metadata tests; the root production entry requires Linux.
    libc = ctypes.CDLL(None, use_errno=True)
    listing = libc.listxattr
    listing.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    listing.restype = ctypes.c_ssize_t
    getter = libc.getxattr
    getter.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    getter.restype = ctypes.c_ssize_t
    count = listing(os.fsencode(path), None, 0, 1)
    if not 0 <= count <= 1024 * 1024:
        raise Blocked('XATTR_ENUMERATION_FAILED')
    buffer = ctypes.create_string_buffer(count)
    if listing(os.fsencode(path), buffer, count, 1) != count:
        raise Blocked('XATTR_ENUMERATION_CHANGED')
    result = {}
    for name in filter(None, buffer.raw.split(b'\0')):
        size = getter(os.fsencode(path), name, None, 0, 0, 1)
        if not 0 <= size <= 1024 * 1024:
            raise Blocked('XATTR_READ_FAILED')
        value = ctypes.create_string_buffer(size)
        if getter(os.fsencode(path), name, value, size, 0, 1) != size:
            raise Blocked('XATTR_CHANGED_DURING_READ')
        result[os.fsdecode(name)] = value.raw
    return result


def records(root, *, excluded_relative=()):
    """Compare content, ownership, mode, nanosecond mtime, ACL/xattrs and hardlinks.

    atime is intentionally excluded: verification reads may update it. ctime and
    inode are not portable metadata; retained-original inode is bound separately.
    Symlinks are recorded without traversal. Devices/FIFOs/sockets are rejected.
    ACLs are included as xattrs on Linux; inability to enumerate them is fatal.
    """
    root = no_alias(root)
    device = root.stat().st_dev
    result, groups, links = [], {}, {}
    excluded = set(excluded_relative)
    for name in excluded:
        if (not isinstance(name, str) or name.startswith('/') or '\\' in name or
                any(part in ('', '.', '..') for part in name.split('/'))):
            raise Blocked('INVALID_EXCLUDED_RELATIVE_PATH')
    paths = [root]
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort(); files.sort()
        paths.extend(Path(current) / name for name in directories + files)
    for path in sorted(paths, key=lambda p: p.relative_to(root).as_posix()):
        before = path.lstat()
        if before.st_dev != device:
            raise Blocked('NESTED_FILESYSTEM')
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            # The caller handles exact credential metadata using lstat only.
            # Do not open, hash, list xattrs for, or otherwise read this object.
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise Blocked('EXCLUDED_OBJECT_TYPE_OR_LINK_COUNT')
            after = path.lstat()
            if any(getattr(before, k) != getattr(after, k) for k in
                   ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_uid', 'st_gid',
                    'st_mtime_ns', 'st_ctime_ns')):
                raise Blocked('EXCLUDED_OBJECT_CHANGED_DURING_CAPTURE')
            continue
        item = {'path': relative, 'mode': stat.S_IMODE(before.st_mode),
                'uid': before.st_uid, 'gid': before.st_gid, 'mtimeNs': before.st_mtime_ns}
        attrs = xattrs(path)
        item['xattrs'] = {name: hashlib.sha256(attrs[name]).hexdigest() for name in sorted(attrs)}
        if stat.S_ISLNK(before.st_mode):
            item.update(kind='symlink', target=os.readlink(path))
        elif stat.S_ISDIR(before.st_mode):
            item['kind'] = 'directory'
        elif stat.S_ISREG(before.st_mode):
            key = (before.st_dev, before.st_ino)
            groups.setdefault(key, []).append(relative)
            links[key] = before.st_nlink
            item.update(kind='file', bytes=before.st_size, sha256=sha(path))
        else:
            raise Blocked('SPECIAL_FILE_NOT_RESTORABLE')
        after = path.lstat()
        if any(getattr(before, k) != getattr(after, k) for k in
               ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_uid', 'st_gid', 'st_mtime_ns', 'st_ctime_ns')):
            raise Blocked('TREE_CHANGED_DURING_HASH')
        result.append(item)
    peers = {}
    for key, members in groups.items():
        if len(members) != links[key]:
            raise Blocked('EXTERNAL_HARDLINK')
        for member in members:
            peers[member] = sorted(members)[0]
    for item in result:
        if item['kind'] == 'file':
            item['hardlinkGroup'] = peers[item['path']]
    return result


def tree_digest(root):
    return hashlib.sha256(canonical(records(root))).hexdigest()


def tree_seal(root, *, excluded_relative=()):
    """Cheap inode/metadata seal for already content-verified immutable trees.

    File ctime detects writes even if size/mtime are reset. Atomic exchange can
    change only the root ctime, so root files additionally bind their bytes and
    root directories bind xattrs directly. No nested ctime is ignored.
    """
    root = no_alias(root)
    excluded = set(excluded_relative)
    for name in excluded:
        if (not isinstance(name, str) or name.startswith('/') or '\\' in name or
                any(part in ('', '.', '..') for part in name.split('/'))):
            raise Blocked('INVALID_EXCLUDED_RELATIVE_PATH')
    paths = [root]
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort(); files.sort()
        paths.extend(Path(current) / n for n in directories + files)
    values = []
    for path in paths:
        s = path.lstat()
        relative = path.relative_to(root).as_posix()
        value = [relative, s.st_dev, s.st_ino, s.st_mode, s.st_uid,
                 s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink]
        if relative in excluded:
            if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
                raise Blocked('EXCLUDED_OBJECT_TYPE_OR_LINK_COUNT')
            after = path.lstat()
            if any(getattr(s, k) != getattr(after, k) for k in
                   ('st_dev','st_ino','st_size','st_mode','st_uid','st_gid','st_mtime_ns','st_ctime_ns')):
                raise Blocked('EXCLUDED_OBJECT_CHANGED_DURING_SEAL')
            value.append('excluded-sensitive-metadata-only')
        else:
            if path != root:
                value.append(s.st_ctime_ns)
            else:
                value.append({k: hashlib.sha256(v).hexdigest() for k, v in xattrs(path).items()})
                if stat.S_ISREG(s.st_mode): value.append(sha(path))
            if stat.S_ISLNK(s.st_mode): value.append(os.readlink(path))
        values.append(value)
    return hashlib.sha256(canonical(values)).hexdigest()


def sync_tree(root):
    # Call only for a stopped/immutable tree; symlinks are never opened.
    if sys.platform == 'linux':
        # Flush the filesystem once rather than issuing a million individual
        # fsync calls. Content/metadata verification is performed by clone_tree.
        fd = os.open(root, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            call = ctypes.CDLL(None, use_errno=True).syncfs
            call.argtypes = [ctypes.c_int]
            if call(fd): raise OSError(ctypes.get_errno(), 'syncfs failed')
        finally:
            os.close(fd)
        sync_dir(Path(root).parent)
        return
    records(root)
    if Path(root).is_file():
        fd = os.open(root, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        sync_dir(Path(root).parent)
        return
    directories = [Path(root)]
    for current, dirs, files in os.walk(root, followlinks=False):
        directories.extend(Path(current) / n for n in dirs if not (Path(current) / n).is_symlink())
        for name in files:
            path = Path(current) / name
            if path.is_symlink():
                continue
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        sync_dir(path)
    sync_dir(Path(root).parent)


def clone_tree(source, destination):
    """GNU cp preserves ACLs, xattrs, hardlinks and numeric ownership; verify all."""
    source, destination = no_alias(source), Path(destination)
    no_alias(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise Blocked('SNAPSHOT_ALREADY_EXISTS')
    seal = tree_seal(source)
    original = tree_digest(source)
    if tree_seal(source) != seal:
        raise Blocked('SOURCE_CHANGED_DURING_HASH')
    command = ['/bin/cp', '-a', '--reflink=auto', '--', str(source), str(destination)]
    if sys.platform != 'linux':
        raise Blocked('LINUX_METADATA_COPY_REQUIRED')
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=7200)
    if result.returncode:
        raise Blocked('METADATA_COPY_FAILED_RETAIN_PARTIAL')
    sync_tree(destination)
    if tree_digest(destination) != original or tree_seal(source) != seal:
        raise Blocked('SAFETY_COPY_METADATA_OR_CONTENT_DIFFERS')
    return original


def exchange(first, second):
    """Kernel atomic swap; never emulate with a window in which the live path vanishes."""
    first, second = no_alias(first), no_alias(second)
    if identity(first)[0] != identity(second)[0]:
        raise Blocked('CROSS_FILESYSTEM_EXCHANGE')
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == 'linux':
        call = libc.renameat2
        call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        result = call(-100, os.fsencode(first), -100, os.fsencode(second), 2)
    elif sys.platform == 'darwin':
        # Enables actual local kernel-journal tests; production runtime rejects macOS.
        call = libc.renamex_np
        call.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        result = call(os.fsencode(first), os.fsencode(second), 2)
    else:
        raise Blocked('ATOMIC_EXCHANGE_UNAVAILABLE')
    if result:
        raise OSError(ctypes.get_errno(), 'atomic directory exchange failed')
    sync_dir(first.parent)
    if first.parent != second.parent:
        sync_dir(second.parent)
