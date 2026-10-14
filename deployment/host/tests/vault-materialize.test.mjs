import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  VaultMaterializationError, validateTarget, readValues, prepare, writePrepared,
  rollbackPrepared, disposePrepared, readConsumerValue, consumerMatches,
} from '../libexec/vault-materialize.mjs';

// Model root-owned logical /srv ancestors using real disposable files on macOS.
// Production has no runtime-root override; only filesystem operations are injected.
function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-materialize-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const base = '/srv/platform-infrastructure/fixture';
  const physical = filename => path.join(directory, filename);
  fs.mkdirSync(physical(base), { recursive: true, mode: 0o700 });
  const mapped = { ...fs };
  mapped.lstatSync = filename => {
    const info = fs.lstatSync(physical(filename));
    if (info.isDirectory()) Object.defineProperty(info, 'uid', { value: 0 });
    return info;
  };
  mapped.openSync = (filename, ...args) => fs.openSync(physical(filename), ...args);
  mapped.renameSync = (source, destination) => fs.renameSync(physical(source), physical(destination));
  mapped.unlinkSync = filename => fs.unlinkSync(physical(filename));
  const target = (name, source, format = 'raw-file', writeMode = 'in-place', key) => {
    const filename = base + '/' + name;
    fs.writeFileSync(physical(filename), source, { mode: 0o640 });
    const info = fs.statSync(physical(filename));
    return { path: filename, format, writeMode, ...(key ? { key } : {}), ownerUid: info.uid, ownerGid: info.gid, mode: 0o640 };
  };
  return { physical, target, binding: (...targets) => ({ id: 'fixture-secret', targets }), options: { fsImpl: mapped }, mapped };
}

test('raw-file adoption and same-version delivery preserve exact newline bytes, ownership and inode', t => {
  const f = fixture(t), target = f.target('token', 'prior-secret\r\n'), binding = f.binding(target);
  const before = fs.statSync(f.physical(target.path));
  const values = readValues(binding, f.options);
  assert.deepEqual(values, [{ path: target.path, value: 'prior-secret\r\n' }]);
  const prepared = prepare(binding, values[0].value, f.options);
  const receipt = writePrepared(prepared, f.options), after = fs.statSync(f.physical(target.path));
  assert.equal(fs.readFileSync(f.physical(target.path), 'utf8'), 'prior-secret\r\n');
  assert.equal(after.ino, before.ino); assert.equal(after.mode, before.mode);
  assert.equal(after.uid, before.uid); assert.equal(after.gid, before.gid);
  assert.equal(receipt.runtimeVerified, false);
  assert.equal(receipt.targets[0].ino, before.ino);
  assert.doesNotMatch(JSON.stringify(receipt), /prior-secret/);
  disposePrepared(prepared); assert.ok(prepared.entries[0].previous.every(byte => byte === 0));
});

test('in-place writes truncate safely and rollback restores the same inode and exact original bytes', t => {
  const f = fixture(t), target = f.target('token', 'long-original-secret\n'), binding = f.binding(target);
  const inode = fs.statSync(f.physical(target.path)).ino;
  const prepared = prepare(binding, 'new', f.options);
  writePrepared(prepared, f.options);
  assert.equal(fs.readFileSync(f.physical(target.path), 'utf8'), 'new');
  assert.equal(fs.statSync(f.physical(target.path)).ino, inode);
  rollbackPrepared(prepared, f.options);
  assert.equal(fs.readFileSync(f.physical(target.path), 'utf8'), 'long-original-secret\n');
  assert.equal(fs.statSync(f.physical(target.path)).ino, inode);
  disposePrepared(prepared);
});

test('atomic rename fsyncs parent, preserves mode and owner, and rolls back without leaving temp files', t => {
  const f = fixture(t), target = f.target('token', 'original', 'raw-file', 'atomic'), binding = f.binding(target);
  const before = fs.statSync(f.physical(target.path)); let directorySyncs = 0;
  f.mapped.fsyncSync = fd => { if (fs.fstatSync(fd).isDirectory()) directorySyncs++; return fs.fsyncSync(fd); };
  const prepared = prepare(binding, 'replacement', f.options);
  writePrepared(prepared, f.options);
  const after = fs.statSync(f.physical(target.path));
  assert.notEqual(after.ino, before.ino); assert.equal(after.mode, before.mode);
  assert.equal(after.uid, before.uid); assert.equal(after.gid, before.gid);
  assert.equal(directorySyncs, 1);
  rollbackPrepared(prepared, f.options);
  assert.equal(fs.readFileSync(f.physical(target.path), 'utf8'), 'original');
  assert.equal(directorySyncs, 2);
  assert.deepEqual(fs.readdirSync(path.dirname(f.physical(target.path))), ['token']);
  disposePrepared(prepared);
});

test('env-key and json-key modify only the admitted field and preserve other settings', t => {
  const f = fixture(t);
  const env = f.target('runtime.env', '# keep\r\nUNCHANGED=value\r\nPASSWORD="old"\r\n', 'env-key', 'in-place', 'PASSWORD');
  const json = f.target('runtime.json', '{\n  "password": "old",\n  "other": {"keep": true}\n}\n', 'json-key', 'atomic', 'password');
  const binding = f.binding(env, json), value = 'new"value\\with\nline$(literal)`literal`';
  const prepared = prepare(binding, value, f.options); writePrepared(prepared, f.options);
  assert.equal(fs.readFileSync(f.physical(env.path), 'utf8').split('\r\n')[1], 'UNCHANGED=value');
  assert.deepEqual(readValues(binding, f.options).map(item => item.value), [value, value]);
  assert.deepEqual(JSON.parse(fs.readFileSync(f.physical(json.path), 'utf8')).other, { keep: true });
  rollbackPrepared(prepared, f.options);
  assert.equal(fs.readFileSync(f.physical(env.path), 'utf8'), '# keep\r\nUNCHANGED=value\r\nPASSWORD="old"\r\n');
  disposePrepared(prepared);
});

test('target admission rejects paths outside root, duplicate targets, symlinks, hard links and writable ancestors/files', t => {
  const f = fixture(t), target = f.target('token', 'original'), binding = f.binding(target);
  assert.throws(() => validateTarget('/etc/password', f.binding({ ...target, path: '/etc/password' }), f.options), VaultMaterializationError);
  assert.throws(() => validateTarget(target.path, f.binding(target, target), f.options), VaultMaterializationError);
  assert.throws(() => validateTarget(target.path, f.binding({ ...target, ownerUid: target.ownerUid + 1 }), f.options), VaultMaterializationError);
  fs.chmodSync(f.physical(target.path), 0o666);
  assert.throws(() => validateTarget(target.path, binding, f.options), VaultMaterializationError);
  fs.chmodSync(f.physical(target.path), 0o640);
  fs.chmodSync(path.dirname(f.physical(target.path)), 0o777);
  assert.throws(() => validateTarget(target.path, binding, f.options), VaultMaterializationError);
  fs.chmodSync(path.dirname(f.physical(target.path)), 0o700);
  fs.linkSync(f.physical(target.path), f.physical(target.path + '-link'));
  assert.throws(() => validateTarget(target.path, binding, f.options), VaultMaterializationError);
  fs.unlinkSync(f.physical(target.path + '-link'));
  fs.renameSync(f.physical(target.path), f.physical(target.path + '-real'));
  fs.symlinkSync(f.physical(target.path + '-real'), f.physical(target.path));
  assert.throws(() => validateTarget(target.path, binding, f.options), VaultMaterializationError);
});

test('a changed file is rejected before writes and rollback does not overwrite external changes', t => {
  const f = fixture(t), target = f.target('token', 'original'), binding = f.binding(target);
  const prepared = prepare(binding, 'new', f.options);
  fs.writeFileSync(f.physical(target.path), 'external');
  assert.throws(() => writePrepared(prepared, f.options), /Materialization failed/);
  assert.equal(fs.readFileSync(f.physical(target.path), 'utf8'), 'external');
  disposePrepared(prepared);
});

test('partial in-place failure restores all attempted files in reverse order with original inodes', t => {
  const f = fixture(t), first = f.target('first', 'first-original\n'), second = f.target('second', 'second-original\n');
  const binding = f.binding(first, second), inodes = [first, second].map(target => fs.statSync(f.physical(target.path)).ino);
  const prepared = prepare(binding, 'replacement', f.options);
  const original = fs.writeSync; let writes = 0;
  f.mapped.writeSync = (fd, buffer, offset, length, position) => {
    writes++;
    if (writes === 2) return original(fd, buffer, offset, 2, position);
    if (writes === 3) throw Object.assign(Error('injected failure'), { code: 'EIO' });
    return original(fd, buffer, offset, length, position);
  };
  assert.throws(() => writePrepared(prepared, f.options), /previous files restored/);
  assert.deepEqual([first, second].map(target => fs.readFileSync(f.physical(target.path), 'utf8')), ['first-original\n', 'second-original\n']);
  assert.deepEqual([first, second].map(target => fs.statSync(f.physical(target.path)).ino), inodes);
  assert.equal(prepared.state, 'rolled-back');
  assert.equal(rollbackPrepared(prepared, f.options).restored, true);
  disposePrepared(prepared);
});

test('failed rollback reports reconciliation and does not claim restored or runtime success', t => {
  const f = fixture(t), target = f.target('token', 'original'), binding = f.binding(target);
  const prepared = prepare(binding, 'new', f.options); let count = 0;
  f.mapped.fsyncSync = fd => { count++; if (count <= 2) throw Error('injected sync failure'); return fs.fsyncSync(fd); };
  assert.throws(() => writePrepared(prepared, f.options), /rollback requires reconciliation/);
  assert.equal(prepared.state, 'requires-reconciliation'); disposePrepared(prepared);
});

test('invalid fields and duplicate environment entries fail without changing files', t => {
  const f = fixture(t), target = f.target('runtime.env', 'PASSWORD=first\nPASSWORD=second\n', 'env-key', 'in-place', 'PASSWORD');
  assert.throws(() => prepare(f.binding(target), 'new', f.options), /exactly once/);
  assert.equal(fs.readFileSync(f.physical(target.path), 'utf8'), 'PASSWORD=first\nPASSWORD=second\n');
  const json = f.target('runtime.json', '{"password":22}', 'json-key', 'in-place', 'password');
  assert.throws(() => prepare(f.binding(json), 'new', f.options), /existing string/);
});

test('consumer readback uses pinned ID and exact file with binary pipes and no shell or printed diagnostics', () => {
  const consumer = { containerId: 'a'.repeat(64), path: '/run/secrets/password', format: 'raw-file' };
  let lastOutput;
  const options = { spawnSyncImpl(command, args, settings) {
    assert.equal(command, '/usr/bin/docker');
    assert.deepEqual(args, ['exec', consumer.containerId, 'cat', '--', consumer.path]);
    assert.deepEqual(settings.stdio, ['ignore', 'pipe', 'pipe']); assert.equal(settings.encoding, 'buffer');
    lastOutput = Buffer.from('consumer-secret\n');
    return { status: 0, stdout: lastOutput, stderr: Buffer.alloc(0) };
  } };
  assert.equal(readConsumerValue(consumer, options), 'consumer-secret\n');
  assert.ok(lastOutput.every(byte => byte === 0));
  assert.equal(consumerMatches(consumer, 'consumer-secret\n', options), true);
  assert.equal(consumerMatches(consumer, 'other-secret\n', options), false);
  assert.throws(() => readConsumerValue({ ...consumer, containerId: 'container-name' }, options), /Invalid admitted consumer/);
  assert.throws(() => readConsumerValue(consumer, { spawnSyncImpl: () => ({ status: 1, stdout: Buffer.from('secret'), stderr: Buffer.from('secret') }) }), /readback unavailable/);
});

test('non-root ancestors require exact reviewed metadata and reject owner, group and mode drift', t => {
  const f = fixture(t), target = f.target('token', 'original'), parent = path.dirname(target.path);
  const realLstat = f.mapped.lstatSync;
  let uid = 1000, gid = 33, mode = 0o750;
  f.mapped.lstatSync = filename => {
    const info = realLstat(filename);
    if (filename === parent) {
      Object.defineProperty(info, 'uid', { value: uid, configurable: true });
      Object.defineProperty(info, 'gid', { value: gid, configurable: true });
      Object.defineProperty(info, 'mode', { value: (info.mode & ~0o7777) | mode, configurable: true });
    }
    return info;
  };
  assert.throws(() => validateTarget(target.path, f.binding(target), f.options), /ancestor/);
  target.ancestorMetadata = [{ path: parent, uid: 1000, gid: 33, mode: 0o750 }];
  assert.equal(validateTarget(target.path, f.binding(target), f.options).target.path, target.path);
  uid = 1001; assert.throws(() => validateTarget(target.path, f.binding(target), f.options), /ancestor/); uid = 1000;
  gid = 1000; assert.throws(() => validateTarget(target.path, f.binding(target), f.options), /ancestor/); gid = 33;
  mode = 0o770; assert.throws(() => validateTarget(target.path, f.binding(target), f.options), /ancestor/);
  target.ancestorMetadata[0].mode = 0o777;
  assert.throws(() => validateTarget(target.path, f.binding(target), f.options), /ancestor metadata/);
});

test('declared project env consumer paths use pinned container ID and reject traversal', () => {
  const consumer = { containerId: 'b'.repeat(64), path: '/var/www/projects/fiplatform/private/.env', format: 'env-key', key: 'SMTP_PASSWORD' };
  const options = { spawnSyncImpl(command, args) {
    assert.deepEqual(args, ['exec', consumer.containerId, 'cat', '--', consumer.path]);
    return { status: 0, stdout: Buffer.from('UNCHANGED=yes\nSMTP_PASSWORD="consumer-value"\n'), stderr: Buffer.alloc(0) };
  } };
  assert.equal(readConsumerValue(consumer, options), 'consumer-value');
  assert.throws(() => readConsumerValue({ ...consumer, path: '/var/www/projects/../../etc/passwd' }, options), /Invalid admitted consumer/);
  assert.throws(() => readConsumerValue({ ...consumer, path: '/etc/passwd' }, options), /Invalid admitted consumer/);
});

test('container environment readback captures only the declared key internally and erases binary pipes', () => {
  const consumer = { containerId: 'c'.repeat(64), format: 'container-env', key: 'DB_PASSWORD' };
  let output;
  const options = { spawnSyncImpl(command, args, settings) {
    assert.deepEqual(args, ['inspect', '--format', '{{json .Config.Env}}', consumer.containerId]);
    assert.deepEqual(settings.stdio, ['ignore', 'pipe', 'pipe']);
    output = Buffer.from(JSON.stringify(['OTHER=unchanged', 'DB_PASSWORD=fixture-current-value']));
    return { status: 0, stdout: output, stderr: Buffer.alloc(0) };
  } };
  assert.equal(consumerMatches(consumer, 'fixture-current-value', options), true);
  assert.ok(output.every(byte => byte === 0));
  assert.throws(() => readConsumerValue(consumer, { spawnSyncImpl: () => ({ status: 0, stdout: Buffer.from('["DB_PASSWORD=one","DB_PASSWORD=two"]'), stderr: Buffer.alloc(0) }) }), /exactly once/);
});
