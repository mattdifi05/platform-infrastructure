import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const databaseName = /^[a-z][a-z0-9_]{0,62}$/;
const maxNames = 100;
const maxConcurrentMeasurements = 4;
const timeoutMs = 3500;

function validConnection({ engine, host, port, user, password, database, tlsCA } = {}) {
  return (engine === 'postgres' || engine === 'mariadb')
    && typeof host === 'string' && /^[a-zA-Z0-9._:-]{1,253}$/.test(host) && !host.startsWith('-')
    && Number.isInteger(port) && port >= 1 && port <= 65535
    && typeof user === 'string' && user.length > 0 && !/[\0\r\n]/.test(user)
    && typeof password === 'string' && password.length > 0 && !/[\0\r\n]/.test(password)
    && (database === undefined || typeof database === 'string' && databaseName.test(database))
    && (tlsCA == null || ((typeof tlsCA === 'string' || Buffer.isBuffer(tlsCA)) && tlsCA.length > 0));
}

function parseSizes(stdout, names) {
  const allowed = new Set(names);
  const sizes = new Map();
  for (const line of stdout.split(/\r?\n/)) {
    const fields = line.split('\t');
    if (fields.length !== 2 || !allowed.has(fields[0]) || !/^\d+$/.test(fields[1])) continue;
    const bytes = Number(fields[1]);
    if (Number.isSafeInteger(bytes)) sizes.set(fields[0], bytes);
  }
  return sizes;
}

async function measureWithClient(run, connection, names) {
  const { engine, host, port, user, password, database, tlsCA } = connection;
  const directory = await mkdtemp(join(tmpdir(), 'control-db-size-'));
  try {
    const env = { PATH: process.env.PATH, HOME: directory, LANG: 'C' };
    const options = { env, encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL', maxBuffer: 32 * 1024 };
    const list = names.map(name => `'${name}'`).join(', ');
    const caFile = tlsCA == null ? null : join(directory, 'ca.pem');
    if (caFile) await writeFile(caFile, tlsCA, { mode: 0o600 });
    if (engine === 'postgres') {
      const passwordFile = join(directory, 'pgpass');
      await writeFile(passwordFile, `*:*:*:*:${password.replace(/[\\:]/g, '\\$&')}\n`, { mode: 0o600 });
      Object.assign(env, {
        PGPASSFILE: passwordFile,
        PGCONNECT_TIMEOUT: '2',
        PGOPTIONS: '-c statement_timeout=2000 -c default_transaction_read_only=on',
        PGSSLMODE: caFile ? 'verify-full' : 'prefer',
      });
      if (caFile) Object.assign(env, { PGSSLROOTCERT: caFile, PGGSSENCMODE: 'disable' });
      const query = `SELECT datname, pg_catalog.pg_database_size(oid)
        FROM pg_catalog.pg_database WHERE datname IN (${list})
          AND (pg_catalog.has_database_privilege(oid, 'CONNECT') OR pg_catalog.pg_has_role('pg_read_all_stats', 'USAGE'))`;
      const { stdout } = await run('psql', [
        '--no-psqlrc', '--no-password', '--no-align', '--tuples-only', '--field-separator=\t',
        '--set=ON_ERROR_STOP=1', `--host=${host}`, `--port=${port}`, `--username=${user}`,
        `--dbname=${database ?? 'postgres'}`, `--command=${query}`,
      ], options);
      return parseSizes(stdout, names);
    }

    const defaultsFile = join(directory, 'client.cnf');
    await writeFile(defaultsFile, `[client]\npassword="${password.replace(/[\\"]/g, '\\$&')}"\n`, { mode: 0o600 });
    const tls = caFile ? ['--ssl', '--ssl-verify-server-cert', `--ssl-ca=${caFile}`] : [];
    // Existing empty schemas have zero bytes. Missing or invisible schemas return no row.
    const query = `SET STATEMENT max_statement_time=2 FOR
      SELECT s.SCHEMA_NAME, COALESCE(SUM(COALESCE(t.DATA_LENGTH, 0) + COALESCE(t.INDEX_LENGTH, 0)), 0)
      FROM information_schema.SCHEMATA AS s
      LEFT JOIN information_schema.TABLES AS t
        ON t.TABLE_SCHEMA = s.SCHEMA_NAME AND BINARY t.TABLE_SCHEMA = BINARY s.SCHEMA_NAME
      WHERE s.SCHEMA_NAME IN (${list}) AND BINARY s.SCHEMA_NAME IN (${list})
      GROUP BY s.SCHEMA_NAME`;
    const { stdout } = await run('mariadb', [
      `--defaults-file=${defaultsFile}`, '--protocol=TCP', '--batch', '--raw', '--skip-column-names',
      '--skip-reconnect', '--connect-timeout=2', `--host=${host}`, `--port=${port}`, `--user=${user}`,
      ...tls, `--execute=${query}`,
    ], options);
    return parseSizes(stdout, names);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

export function createDatabaseSizeReader({ run = execute } = {}) {
  const pending = new Map();
  return {
    async measure(connection, names) {
      if (!connection || !validConnection(connection) || !Array.isArray(names) || names.length > maxNames
          || names.some(name => typeof name !== 'string' || !databaseName.test(name))) return new Map();
      const unique = [...new Set(names)].sort();
      if (!unique.length) return new Map();
      const { engine, host, port, user, password, database, tlsCA } = connection;
      const key = createHash('sha256').update(JSON.stringify([engine, host, port, user, password, database, unique]))
        .update(tlsCA ?? '').digest('hex');
      let measurement = pending.get(key);
      if (!measurement) {
        if (pending.size >= maxConcurrentMeasurements) return new Map();
        measurement = measureWithClient(run, connection, unique).catch(() => new Map()).finally(() => pending.delete(key));
        pending.set(key, measurement);
      }
      return new Map(await measurement);
    },
  };
}
