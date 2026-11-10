import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import test from 'node:test';
import { createDatabaseSizeReader } from '../database/size-reader.mjs';

const postgres = { engine: 'postgres', host: 'postgres', port: 5432, user: 'measure', password: 'p:a\\ss"word' };
const mariadb = { ...postgres, engine: 'mariadb', host: 'mariadb', port: 3306 };

test('PostgreSQL limits the query to admitted databases and verifies TLS when given a CA', async () => {
  let passwordFile;
  const reader = createDatabaseSizeReader({ async run(file, args, options) {
    assert.equal(file, 'psql');
    assert.match(args.at(-1), /pg_database_size\(oid\).*IN \('app', 'empty', 'missing'\)/s);
    assert.match(options.env.PGOPTIONS, /default_transaction_read_only=on/);
    assert.equal(options.env.PGSSLMODE, 'verify-full');
    assert.equal(options.env.PGGSSENCMODE, 'disable');
    assert.equal(await readFile(options.env.PGSSLROOTCERT, 'utf8'), 'test ca');
    assert.ok(options.timeout <= 4000);
    assert.ok(!args.some(arg => arg.includes(postgres.password)));
    assert.ok(!Object.values(options.env).includes(postgres.password));
    passwordFile = options.env.PGPASSFILE;
    assert.equal((await stat(passwordFile)).mode & 0o777, 0o600);
    assert.equal(await readFile(passwordFile, 'utf8'), '*:*:*:*:p\\:a\\\\ss"word\n');
    return { stdout: 'app\t120\nempty\t0\nforeign\t10\nmissing\t9007199254740992\n' };
  } });
  assert.deepEqual(await reader.measure({ ...postgres, tlsCA: 'test ca' }, ['missing', 'app', 'empty', 'app']), new Map([['app', 120], ['empty', 0]]));
  await assert.rejects(stat(passwordFile), { code: 'ENOENT' });
});

test('MariaDB reads approximate data and index lengths and preserves known zero sizes', async () => {
  let defaultsFile;
  const reader = createDatabaseSizeReader({ async run(file, args, options) {
    assert.equal(file, 'mariadb');
    assert.match(args.at(-1), /LEFT JOIN information_schema\.TABLES/);
    assert.match(args.at(-1), /t\.DATA_LENGTH.*t\.INDEX_LENGTH/);
    assert.ok(args.includes('--ssl-verify-server-cert'));
    assert.ok(!args.some(arg => arg.includes(mariadb.password)));
    assert.ok(!Object.values(options.env).includes(mariadb.password));
    defaultsFile = args[0].slice('--defaults-file='.length);
    assert.equal((await stat(defaultsFile)).mode & 0o777, 0o600);
    assert.equal(await readFile(defaultsFile, 'utf8'), '[client]\npassword="p:a\\\\ss\\"word"\n');
    return { stdout: 'app\t4096\r\nempty\t0\r\n' };
  } });
  assert.deepEqual(await reader.measure({ ...mariadb, tlsCA: Buffer.from('test ca') }, ['app', 'empty', 'missing']), new Map([['app', 4096], ['empty', 0]]));
  await assert.rejects(stat(defaultsFile), { code: 'ENOENT' });
});

test('invalid input and failures yield no measurements, and concurrent duplicates share one process', async () => {
  let calls = 0;
  let passwordFile;
  const reader = createDatabaseSizeReader({ async run(_, __, { env }) {
    calls += 1;
    passwordFile = env.PGPASSFILE;
    throw new Error('client failed');
  } });
  assert.deepEqual(await reader.measure(postgres, ["bad'); DROP SCHEMA app; --"]), new Map());
  assert.deepEqual(await reader.measure({ ...postgres, host: '/tmp' }, ['app']), new Map());
  assert.deepEqual(await reader.measure({ ...postgres, database: 'host=external' }, ['app']), new Map());
  assert.equal(calls, 0);
  const results = await Promise.all([reader.measure(postgres, ['app', 'other']), reader.measure(postgres, ['other', 'app'])]);
  assert.deepEqual(results, [new Map(), new Map()]);
  assert.equal(calls, 1);
  await assert.rejects(stat(passwordFile), { code: 'ENOENT' });
});
