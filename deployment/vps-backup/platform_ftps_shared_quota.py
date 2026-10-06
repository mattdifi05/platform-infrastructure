"""Shared FTPS writer exclusion and bounded accounting for the two server folders.

Both native writers must hold this lease throughout every remote mutation. A lost
session leaves the lock behind: only an operator may reconcile/remove it after
confirming neither writer is running. Never auto-expire or steal a remote lock.
"""
import contextlib, ftplib, json, pathlib, ssl, stat, threading

LIMIT = 70_000_000_000
FOLDERS = ('/server-platform-backups', '/platform-server-public-backups')
LOCK = '/.platform-server-backup-writer-lock'
POLICY = pathlib.Path('/etc/platform-ftps-backup/shared-quota.json')

class SharedQuotaBusy(RuntimeError):
    pass

def protected_json(path):
    path = pathlib.Path(path)
    for parent in [path, *path.parents]:
        info = parent.lstat()
        if parent.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Shared quota configuration is not root protected')
    if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > 16384:
        raise RuntimeError('Shared quota configuration is invalid')
    return json.loads(path.read_text())

def tree_bytes(ftp, root):
    """Only the two declared server trees; no owner verification/deletion of peer."""
    if root not in FOLDERS:
        raise RuntimeError('Unexpected quota scope')
    total = 0
    pending = [(root, 0)]
    seen = 0
    while pending:
        directory, depth = pending.pop()
        if depth > 8:
            raise RuntimeError('Server quota depth exceeds bound')
        for name, facts in ftp.mlsd(directory):
            kind = facts.get('type')
            if kind in ('cdir', 'pdir'):
                continue
            seen += 1
            if seen > 10000 or not name or name in ('.', '..') or '/' in name or '\\' in name or any(ord(c) < 32 for c in name):
                raise RuntimeError('Invalid or excessive quota inventory')
            if kind == 'dir':
                pending.append((directory + '/' + name, depth + 1))
            elif kind == 'file':
                size = facts.get('size', '')
                if not str(size).isdigit():
                    raise RuntimeError('Remote byte count unavailable')
                total += int(size)
            else:
                raise RuntimeError('Unsupported remote object in server quota')
    return total

@contextlib.contextmanager
def writer_budget(config_path, own_folder, policy_path=POLICY):
    policy = protected_json(policy_path)
    if policy != {'version': 1, 'bothWritersQualified': True, 'folders': list(FOLDERS), 'maximumBytes': LIMIT, 'lockDirectory': LOCK}:
        raise RuntimeError('Both writers must be qualified for shared quota before activation')
    if own_folder not in FOLDERS:
        raise RuntimeError('Unexpected writer namespace')
    cfg = protected_json(config_path)
    if cfg.get('host') != '92.113.28.106' or cfg.get('port') != 21 or cfg.get('tlsName') != 'hstgr.io' or cfg.get('folder') != own_folder:
        raise RuntimeError('Unexpected native FTPS endpoint')
    ftp = ftplib.FTP_TLS(context=ssl.create_default_context(), timeout=90)
    acquired = False
    stop = threading.Event()
    lease_error = []
    keeper = None
    try:
        ftp.connect(cfg['host'], cfg['port'])
        ftp.host = cfg['tlsName']
        ftp.auth(); ftp.login(cfg['username'], cfg['password']); ftp.prot_p()
        # FTP MKD must be exclusive on this provider; qualification verifies it.
        # A denial (including an existing lock) always fails closed.
        try:
            ftp.mkd(LOCK)
        except ftplib.error_perm as denied:
            # Retryable only when this is demonstrably an existing lock directory.
            if str(denied).split()[0] in ('550', '521'):
                try:
                    ftp.cwd(LOCK)
                    exists = ftp.pwd() == LOCK
                except ftplib.Error:
                    exists = False
                if exists:
                    raise SharedQuotaBusy('Another qualified server writer holds the FTPS lease') from denied
            raise
        acquired = True
        own = tree_bytes(ftp, own_folder)
        peer = tree_bytes(ftp, next(p for p in FOLDERS if p != own_folder))
        if own + peer > LIMIT:
            raise RuntimeError('Combined server quota already exceeds 70 GB')
        def keepalive():
            while not stop.wait(20):
                try:
                    ftp.voidcmd('NOOP')
                except Exception:
                    lease_error.append(True)
                    return
        keeper = threading.Thread(target=keepalive, daemon=True)
        keeper.start()
        yield LIMIT - peer
    finally:
        stop.set()
        if keeper is not None:
            keeper.join(timeout=95)
        try:
            if lease_error or (keeper is not None and keeper.is_alive()):
                raise RuntimeError('Shared FTPS lease session lost; lock preserved for operator reconciliation')
            if acquired:
                # Empty directory only; no recursive delete and no peer writes.
                ftp.rmd(LOCK)
        finally:
            ftp.close()
