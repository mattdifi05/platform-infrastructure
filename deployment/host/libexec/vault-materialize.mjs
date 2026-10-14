import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const ROOT = '/srv/platform-infrastructure';
const LIMIT = 1024 * 1024;
const FORMATS = new Set(['raw-file', 'env-key', 'json-key']);
const CONSUMER_FORMATS = new Set([...FORMATS, 'container-env']);
const MODES = new Set(['in-place', 'atomic']);
export class VaultMaterializationError extends Error {}
const reject = message => { throw new VaultMaterializationError(message); };
const equal = (a, b) => a.length === b.length && timingSafeEqual(a, b);
const ioFor = options => options?.fsImpl || fs;

function admittedTarget(filename, binding) {
  if (!binding || typeof binding.id !== 'string' || !Array.isArray(binding.targets)
      || !binding.targets.length || binding.targets.length > 16) reject('Invalid admitted binding');
  const matches = binding.targets.filter(target => target?.path === filename);
  if (matches.length !== 1) reject('Target is outside the exact binding policy');
  const target = matches[0];
  if (!FORMATS.has(target.format) || !MODES.has(target.writeMode)) reject('Unsupported target format or write mode');
  if (target.format !== 'raw-file' && (typeof target.key !== 'string'
      || !/^[A-Za-z_][A-Za-z0-9_-]{0,127}$/.test(target.key)
      || ['__proto__', 'prototype', 'constructor'].includes(target.key))) reject('Invalid admitted field name');
  return target;
}

/** The binding comes exclusively from the root-owned policy, never the request. */
export function validateTarget(filename, binding, options = {}) {
  const target = admittedTarget(filename, binding);
  if (typeof filename !== 'string' || !path.isAbsolute(filename) || path.normalize(filename) !== filename
      || !filename.startsWith(ROOT + '/') || /[\x00-\x1f]/.test(filename)) reject('Target is outside the fixed runtime root');
  const io = ioFor(options);
  const ancestors = new Map();
  if (target.ancestorMetadata !== undefined && !Array.isArray(target.ancestorMetadata)) reject('Invalid admitted ancestor metadata');
  for (const record of target.ancestorMetadata || []) {
    if (!record || typeof record.path !== 'string' || path.normalize(record.path) !== record.path
        || !(record.path === ROOT || record.path.startsWith(ROOT + '/'))
        || !filename.startsWith(record.path + '/') || ancestors.has(record.path)
        || !Number.isInteger(record.uid) || record.uid < 0 || !Number.isInteger(record.gid) || record.gid < 0
        || !Number.isInteger(record.mode) || record.mode < 0 || record.mode > 0o7777 || record.mode & 0o002) reject('Invalid admitted ancestor metadata');
    ancestors.set(record.path, record);
  }
  for (let ancestor = path.dirname(filename); ; ancestor = path.dirname(ancestor)) {
    const info = io.lstatSync(ancestor);
    const admitted = ancestors.get(ancestor);
    if (!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o002
        || (admitted ? info.uid !== admitted.uid || info.gid !== admitted.gid || (info.mode & 0o7777) !== admitted.mode
          : info.uid !== 0 || info.mode & 0o022)) reject('Target ancestor ownership or mode changed');
    if (ancestor === '/') break;
  }
  const info = io.lstatSync(filename);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.mode & 0o022
      || info.size > LIMIT || (target.ownerUid !== undefined && info.uid !== target.ownerUid)
      || (target.ownerGid !== undefined && info.gid !== target.ownerGid)
      || (target.mode !== undefined && (info.mode & 0o7777) !== target.mode)) reject('Target ownership, mode or file type changed');
  return { target, identity: identity(info) };
}

const identity = info => ({ dev: info.dev, ino: info.ino, mode: info.mode & 0o7777, uid: info.uid, gid: info.gid, size: info.size });
function sameIdentity(left, right) {
  return ['dev', 'ino', 'mode', 'uid', 'gid', 'size'].every(key => left[key] === right[key]);
}
function text(buffer) {
  const value = buffer.toString('utf8');
  if (value.includes('\0') || !Buffer.from(value, 'utf8').equals(buffer)) reject('Target must contain bounded UTF-8 text');
  return value;
}
function readTarget(filename, binding, options) {
  const io = ioFor(options), checked = validateTarget(filename, binding, options);
  const fd = io.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    if (!sameIdentity(checked.identity, identity(io.fstatSync(fd)))) reject('Target identity changed while opening');
    const bytes = io.readFileSync(fd);
    if (bytes.length > LIMIT) reject('Target exceeds the bounded size');
    return { ...checked, bytes };
  } finally { io.closeSync(fd); }
}
function envField(source, key) {
  const rows = source.split(/\r?\n/), expression = new RegExp(`^([ \\t]*(?:export[ \\t]+)?${key}[ \\t]*=[ \\t]*)(.*)$`);
  const matches = rows.map((line, index) => ({ match: expression.exec(line), index })).filter(row => row.match);
  if (matches.length !== 1) reject('Environment field must exist exactly once');
  return { rows, ...matches[0], newline: source.includes('\r\n') ? '\r\n' : '\n' };
}
function envValue(raw) {
  const value = raw.trim();
  if (value.startsWith("'")) {
    const end = value.indexOf("'", 1);
    if (end < 0 || !/^(?:\s*#.*)?$/.test(value.slice(end + 1))) reject('Unsupported environment quoting');
    return value.slice(1, end);
  }
  if (value.startsWith('"')) {
    const match = /^"((?:[^"\\]|\\.)*)"(?:\s*#.*)?$/.exec(value);
    if (!match) reject('Unsupported environment quoting');
    return match[1].replace(/\\(.)/g, (_, ch) => {
      const escapes = { n: '\n', r: '\r', t: '\t', '"': '"', '\\': '\\', '$': '$', '`': '`' };
      if (!Object.hasOwn(escapes, ch)) reject('Unsupported environment quoting');
      return escapes[ch];
    });
  }
  return value.replace(/\s+#.*$/, '').trimEnd();
}
function jsonDocument(source, key) {
  let document;
  try { document = JSON.parse(source); } catch { reject('Target JSON is invalid'); }
  if (!document || typeof document !== 'object' || Array.isArray(document)
      || !Object.hasOwn(document, key) || typeof document[key] !== 'string') reject('JSON field must be an existing string');
  return document;
}
function extractValue(bytes, target) {
  const source = text(bytes);
  if (target.format === 'raw-file') return source;
  if (target.format === 'env-key') return envValue(envField(source, target.key).match[2]);
  return jsonDocument(source, target.key)[target.key];
}
function replaceValue(bytes, target, value) {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > 65536 || value.includes('\0')) reject('New value is invalid');
  const source = text(bytes);
  if (target.format === 'raw-file') return Buffer.from(value);
  if (target.format === 'env-key') {
    const field = envField(source, target.key);
    const quoted = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t').replace(/\$/g, '\\$').replace(/`/g, '\\`');
    field.rows[field.index] = field.match[1] + '"' + quoted + '"';
    return Buffer.from(field.rows.join(field.newline));
  }
  const document = jsonDocument(source, target.key);
  document[target.key] = value;
  const indent = /\n([ \t]+)"/.exec(source)?.[1] || 2;
  return Buffer.from(JSON.stringify(document, null, indent) + (source.endsWith('\n') ? '\n' : ''));
}

export function readValues(binding, options = {}) {
  return binding.targets.map(target => {
    const read = readTarget(target.path, binding, options);
    try { return { path: target.path, value: extractValue(read.bytes, read.target) }; }
    finally { read.bytes.fill(0); }
  });
}

/** Plaintext rollback buffers remain in memory; the worker owns encrypted journaling. */
export function prepare(binding, value, options = {}) {
  const prepared = { binding, bindingId: binding?.id, entries: [], state: 'prepared' };
  try {
    if (!Array.isArray(binding?.targets) || !binding.targets.length) reject('Invalid admitted binding');
    for (const target of binding.targets) {
      const read = readTarget(target.path, binding, options);
      let next;
      try { next = replaceValue(read.bytes, read.target, value); } catch (error) { read.bytes.fill(0); throw error; }
      prepared.entries.push({ target: read.target, identity: read.identity, previous: read.bytes, next, written: false });
      if (prepared.entries.at(-1).next.length > LIMIT) reject('Replacement target exceeds the bounded size');
    }
    return prepared;
  } catch (error) { disposePrepared(prepared); throw error; }
}

function assertCurrent(entry, binding, expected, expectedIdentity, options) {
  const read = readTarget(entry.target.path, binding, options);
  try {
    if (!sameIdentity(read.identity, expectedIdentity) || !equal(read.bytes, expected)) reject('Target changed since preparation');
  } finally { read.bytes.fill(0); }
}
function writeFile(entry, bytes, binding, expected, expectedIdentity, options) {
  const io = ioFor(options), filename = entry.target.path;
  assertCurrent(entry, binding, expected, expectedIdentity, options);
  const writeBytes = fd => {
    let offset = 0;
    while (offset < bytes.length) {
      const count = io.writeSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!count) reject('Target write made no progress');
      offset += count;
    }
    io.ftruncateSync(fd, bytes.length);
    io.fsyncSync(fd);
  };
  if (entry.target.writeMode === 'in-place') {
    const fd = io.openSync(filename, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW);
    try {
      if (!sameIdentity(identity(io.fstatSync(fd)), expectedIdentity)) reject('Target inode changed before write');
      entry.attempted = true;
      writeBytes(fd);
    } finally { io.closeSync(fd); }
  } else {
    const temporary = path.join(path.dirname(filename), '.vault-materialize-' + randomBytes(12).toString('hex'));
    let fd;
    try {
      fd = io.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      const created = io.fstatSync(fd);
      if (created.uid !== entry.identity.uid || created.gid !== entry.identity.gid) io.fchownSync(fd, entry.identity.uid, entry.identity.gid);
      io.fchmodSync(fd, entry.identity.mode);
      writeBytes(fd); io.closeSync(fd); fd = undefined;
      assertCurrent(entry, binding, expected, expectedIdentity, options);
      entry.attempted = true;
      io.renameSync(temporary, filename);
      const directory = io.openSync(path.dirname(filename), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      try { io.fsyncSync(directory); } finally { io.closeSync(directory); }
    } finally {
      if (fd !== undefined) io.closeSync(fd);
      try { io.unlinkSync(temporary); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
  }
  const current = readTarget(filename, binding, options);
  try {
    if (!equal(current.bytes, bytes)) reject('Materialization readback failed');
    return current.identity;
  } finally { current.bytes.fill(0); }
}

export function writePrepared(prepared, options = {}) {
  if (prepared?.state !== 'prepared' || !prepared.entries.length) reject('Materialization is not prepared');
  try {
    for (const entry of prepared.entries) {
      entry.appliedIdentity = writeFile(entry, entry.next, prepared.binding, entry.previous, entry.identity, options);
      entry.written = true;
    }
    prepared.state = 'applied';
    return { bindingId: prepared.bindingId, materialized: true, targetCount: prepared.entries.length, runtimeVerified: false, targets: prepared.entries.map(entry => ({ path: entry.target.path, writeMode: entry.target.writeMode, ...entry.appliedIdentity })) };
  } catch {
    try { rollbackPrepared(prepared, options); }
    catch { prepared.state = 'requires-reconciliation'; reject('Materialization failed; rollback requires reconciliation'); }
    reject('Materialization failed; previous files restored');
  }
}

export function rollbackPrepared(prepared, options = {}) {
  if (prepared?.state === 'rolled-back') return { bindingId: prepared.bindingId, restored: true, runtimeVerified: false };
  if (!['prepared', 'applied', 'requires-reconciliation'].includes(prepared?.state)) reject('Rollback state is invalid');
  for (const entry of [...prepared.entries].reverse()) {
    if (!entry.attempted) continue;
    const current = readTarget(entry.target.path, prepared.binding, options);
    try {
      // A failed in-place write may have changed only part of the original inode.
      const originalInode = current.identity.dev === entry.identity.dev && current.identity.ino === entry.identity.ino;
      if (!entry.written && entry.target.writeMode === 'in-place' && originalInode) {
        entry.appliedIdentity = current.identity;
      } else if (equal(current.bytes, entry.previous)) {
        entry.attempted = false; entry.written = false; continue;
      } else if (!equal(current.bytes, entry.next)) reject('Rollback target changed outside this operation');
      const expectedIdentity = entry.appliedIdentity || current.identity;
      entry.identity = writeFile(entry, entry.previous, prepared.binding, current.bytes, expectedIdentity, options);
      entry.attempted = false; entry.written = false;
    } finally { current.bytes.fill(0); }
  }
  prepared.state = 'rolled-back';
  return { bindingId: prepared.bindingId, restored: true, runtimeVerified: false };
}

export function disposePrepared(prepared) {
  for (const entry of prepared?.entries || []) { entry.previous?.fill(0); entry.next?.fill(0); }
  if (prepared) prepared.state = 'disposed';
}

export function readConsumerValue(consumer, options = {}) {
  if (!consumer || !/^[a-f0-9]{64}$/.test(consumer.containerId || '') || !CONSUMER_FORMATS.has(consumer.format)) reject('Invalid admitted consumer');
  if (consumer.format === 'container-env') {
    if (typeof consumer.key !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(consumer.key)) reject('Invalid admitted consumer field');
  } else if (typeof consumer.path !== 'string' || path.normalize(consumer.path) !== consumer.path
      || /[\x00-\x1f]/.test(consumer.path) || consumer.path.endsWith('/')
      || !/^(?:\/run\/secrets\/|\/var\/www\/projects\/)[A-Za-z0-9_./-]+$/.test(consumer.path)) reject('Invalid admitted consumer');
  const args = consumer.format === 'container-env'
    ? ['inspect', '--format', '{{json .Config.Env}}', consumer.containerId]
    : ['exec', consumer.containerId, 'cat', '--', consumer.path];
  // No shell, inherited stdio or secret-bearing diagnostics. Root validates the live identity first.
  const result = (options.spawnSyncImpl || spawnSync)('/usr/bin/docker', args,
    { encoding: 'buffer', timeout: 15000, maxBuffer: LIMIT, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    if (result.error || result.status !== 0 || !Buffer.isBuffer(result.stdout) || result.stdout.length > LIMIT) reject('Consumer secret readback unavailable');
    if (consumer.format === 'container-env') {
      let rows; try { rows = JSON.parse(result.stdout.toString('utf8')); } catch { reject('Consumer environment readback invalid'); }
      if (!Array.isArray(rows) || rows.length > 1024 || rows.some(row => typeof row !== 'string')) reject('Consumer environment readback invalid');
      const prefix = consumer.key + '=';
      const matches = rows.filter(row => row.startsWith(prefix));
      if (matches.length !== 1) reject('Consumer environment field must exist exactly once');
      return matches[0].slice(prefix.length);
    }
    if (consumer.format !== 'raw-file' && (typeof consumer.key !== 'string' || !/^[A-Za-z_][A-Za-z0-9_-]{0,127}$/.test(consumer.key))) reject('Invalid admitted consumer field');
    return extractValue(result.stdout, consumer);
  } finally { if (Buffer.isBuffer(result.stdout)) result.stdout.fill(0); if (Buffer.isBuffer(result.stderr)) result.stderr.fill(0); }
}

export function consumerMatches(consumer, expected, options = {}) {
  const actual = Buffer.from(readConsumerValue(consumer, options));
  const wanted = Buffer.from(expected);
  try { return equal(actual, wanted); }
  finally { actual.fill(0); wanted.fill(0); }
}
