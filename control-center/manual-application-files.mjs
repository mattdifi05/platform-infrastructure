import path from 'node:path';
import { constants, closeSync, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';

const MAX_BYTES = 256 * 1024;
const HIDDEN_SEGMENTS = new Set([
  '.git', '.svn', '.hg', '.ssh', '.aws', '.azure', '.gnupg', '.config',
  '.npmrc', '.pypirc', '.netrc', '.ds_store', 'secrets', 'secret',
  'credentials', 'private', 'tls', 'certs', 'certificates',
  'data', 'runtime', 'logs', 'backups', 'backup', 'snapshots',
  'node_modules', 'vendor', '.next', 'dist', 'build', '.turbo', '.cache',
  'coverage', 'deriveddata', '__pycache__', '.venv', 'venv',
]);
const PRIVATE_FILE = /(?:\.(?:pem|key|p12|pfx|crt|cer|der|jks|keystore|sqlite|sqlite3|db|rdb|aof|dump|pgpass)|\.env[^/]*|\.(?:secret|credentials)(?:\.[^/]*)?)$/i;
const PRIVATE_KEY_NAME = /^id_(?:rsa|dsa|ecdsa|ed25519)(?:\.|$)/i;

export class ManualApplicationFileError extends Error {
  constructor(code = 'APPLICATION_FILE_UNAVAILABLE', status = 422) {
    super('File non disponibile per la consultazione manuale.');
    this.name = 'ManualApplicationFileError';
    this.code = code;
    this.status = status;
  }
}

function segments(value) {
  if (typeof value !== 'string' || value.length > 2048 || path.posix.isAbsolute(value)
    || /[\\%\u0000-\u001f\u007f]/u.test(value) || /^[A-Za-z]:/.test(value)) return null;
  if (value === '') return [];
  const parts = value.split('/');
  return parts.some(part => part === '' || part === '.' || part === '..') ? null : parts;
}

/** Listing and direct reads use the same path-level denial, including ancestors. */
export function isHiddenProjectPath(relativePath) {
  const parts = segments(relativePath);
  return parts === null || parts.some(part => {
    const lower = part.toLowerCase();
    return HIDDEN_SEGMENTS.has(lower) || lower.startsWith('.env')
      || PRIVATE_FILE.test(part) || PRIVATE_KEY_NAME.test(part);
  });
}

function sameFile(left, right) {
  return left.isFile() && right.isFile() && left.dev === right.dev && left.ino === right.ino
    && left.size === right.size && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

function checkedPath(root, parts) {
  let target = root;
  for (let index = 0; index < parts.length; index += 1) {
    target = path.join(target, parts[index]);
    const stat = lstatSync(target);
    if (stat.isSymbolicLink() || (index < parts.length - 1 && !stat.isDirectory())) throw new ManualApplicationFileError();
  }
  const resolved = realpathSync(target);
  if (resolved !== target || !resolved.startsWith(`${root}${path.sep}`)) throw new ManualApplicationFileError();
  return target;
}

/** The caller supplies an authorized, read-only mounted root; never a UI-selected host path. */
export function readManualApplicationFile(projectRoot, relativePath) {
  let fd;
  try {
    const parts = segments(relativePath);
    if (!parts?.length || isHiddenProjectPath(relativePath)) throw new ManualApplicationFileError('APPLICATION_FILE_FORBIDDEN', 403);
    if (typeof projectRoot !== 'string' || !path.isAbsolute(projectRoot)
      || lstatSync(projectRoot).isSymbolicLink()) throw new ManualApplicationFileError();
    const root = realpathSync(projectRoot);
    if (!lstatSync(root).isDirectory() || typeof constants.O_NOFOLLOW !== 'number') throw new ManualApplicationFileError();
    const target = checkedPath(root, parts);
    const before = lstatSync(target);
    if (!before.isFile() || before.nlink !== 1 || before.size > MAX_BYTES) throw new ManualApplicationFileError();
    fd = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const opened = fstatSync(fd);
    if (!sameFile(before, opened) || opened.nlink !== 1) throw new ManualApplicationFileError();
    const bytes = Buffer.alloc(opened.size + 1);
    let used = 0;
    while (used < bytes.length) {
      const count = readSync(fd, bytes, used, bytes.length - used, used);
      if (count === 0) break;
      used += count;
    }
    // A changed path, inode, length or timestamp invalidates the entire read.
    if (used !== opened.size || checkedPath(root, parts) !== target
      || !sameFile(opened, fstatSync(fd)) || !sameFile(opened, lstatSync(target))) throw new ManualApplicationFileError();
    const raw = bytes.subarray(0, used);
    const content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(content)) throw new ManualApplicationFileError();
    return { path: parts.join('/'), name: parts.at(-1), content, sizeBytes: used, sha256: createHash('sha256').update(raw).digest('hex') };
  } catch (error) {
    if (error instanceof ManualApplicationFileError) throw error;
    // Filesystem errors must not expose credentials, host paths or OS messages.
    throw new ManualApplicationFileError();
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
