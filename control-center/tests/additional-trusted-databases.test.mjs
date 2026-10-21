import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

// The runtime source is exercised without starting its HTTP server or touching
// a live catalog, credential file or database. All host policy is synthetic.
const source = readFileSync(new URL('../server.mjs', import.meta.url), 'utf8');
const EXAMPLE_IDS = ['example-a', 'example-b'];
const EXAMPLE_PROJECTS = ['application-a', 'application-b'];
const EXAMPLE_FILES = ['/run/trusted-db/profiles/example-a.json', '/run/trusted-db/profiles/example-b.json'];
class RejectedOperationError extends Error {}

function profile(index) {
  return {
    id: EXAMPLE_IDS[index], projectId: EXAMPLE_PROJECTS[index], engine: 'postgres', name: `example_${index}`, displayName: `Example ${index}`,
    ownerRole: `owner_${index}`, connection: { host: `database-${index}`, port: 5432, tlsMode: 'verify-full', username: `manager_${index}`, credentialFile: `/run/secrets/example_${index}_management`, defaultDatabase: `example_${index}`, internalUrl: 'http://database-browser:80' },
    capabilities: { browse: true, backup: index === 0, restore: index === 0, rotateCredentials: false, dropDatabase: false, managePrincipals: false },
  };
}
function digest(value) { return createHash('sha256').update(JSON.stringify(value)).digest('hex'); }
function extractFunction(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `Missing function ${name}`);
  const end = source.indexOf('\n}', start);
  assert.ok(end > start, `Missing function boundary ${name}`);
  return source.slice(start, end + 2);
}
const FUNCTION_NAMES = [
  'slugify', 'assertExternalDatabaseOperation', 'databaseAdminCredentials', 'phpPgAdminServerId', 'databaseAdminAction', 'databaseAdminTool',
  'renderDatabaseActions', 'renderProjectDetailDatabaseRow', 'renderProjectDetailDatabaseList', 'planDatabaseCreate', 'applyLiveDatabaseCreate',
  'applyLiveDatabaseCredential', 'applyLiveDatabaseDelete', 'applyLiveDatabasePrincipalCleanup', 'removeDatabaseCredentialFile',
  'deleteDatabaseNow', 'approveDatabaseDelete', 'executeDatabaseDelete', 'createDirectDatabaseBackupArtifact',
];
function runtime({ first = true, second = true, extension = true, additionalRaw, readOverride } = {}) {
  const candidates = new Map(EXAMPLE_FILES.map((file, index) => [file, profile(index)]));
  const approved = new WeakSet();
  const calls = [];
  const env = {
    ...(first ? { CONTROL_CENTER_TRUSTED_EXTERNAL_DATABASE_FILE: EXAMPLE_FILES[0], CONTROL_CENTER_TRUSTED_EXTERNAL_DATABASE_SHA256: digest(profile(0)) } : {}),
    ...(second ? { CONTROL_CENTER_ADDITIONAL_TRUSTED_DATABASES: JSON.stringify([{ file: EXAMPLE_FILES[1], digest: digest(profile(1)) }]) } : {}),
    ...(additionalRaw === undefined ? {} : { CONTROL_CENTER_ADDITIONAL_TRUSTED_DATABASES: additionalRaw }),
  };
  function trusted(value) { if (!approved.has(value)) throw new Error('Unapproved synthetic profile'); return value; }
  const hooks = extension ? {
    readTrustedExternalDatabase: readOverride || ((file, options) => {
      calls.push(['admission', file, options]);
      const raw = candidates.get(file);
      if (!raw || options.approvedDigest !== digest(raw)) throw new Error('Synthetic admission denied');
      const result = structuredClone(raw); approved.add(result); return result;
    }),
    TRUSTED_EXTERNAL_DATABASE_IDS: EXAMPLE_IDS,
    TRUSTED_EXTERNAL_PROJECT_IDS: EXAMPLE_PROJECTS,
    externalDatabaseRecord: value => {
      const p = trusted(value);
      return { id: p.id, projectId: p.projectId, engine: p.engine, name: p.name, displayName: p.displayName, ownerRole: p.ownerRole, credentialFile: p.connection.credentialFile };
    },
    externalDatabaseCapabilities: value => ({ ...trusted(value).capabilities }),
    externalDatabaseAdminTarget: value => {
      const p = trusted(value), c = p.connection;
      return { ...c, serverId: `${c.host}:${c.port}:${c.tlsMode}`, allowPlatformCredentialFallback: false, readOnly: false };
    },
    assertExternalDatabaseAction: (value, action) => {
      const p = trusted(value);
      if (!['browse', 'backup', 'restore'].includes(action) || p.capabilities[action] !== true) throw new Error('Synthetic operation denied');
      return p;
    },
    externalDatabaseAdminCredentials: (value, readPassword) => {
      const p = trusted(value);
      return [{ user: p.connection.username, password: readPassword(p.connection.credentialFile), source: 'synthetic-dedicated-file' }];
    },
  } : { readTrustedExternalDatabase: undefined, TRUSTED_EXTERNAL_DATABASE_IDS: [], TRUSTED_EXTERNAL_PROJECT_IDS: [] };
  const ctx = vm.createContext({
    ...hooks, hostExtension: {}, process: { env }, path, URLSearchParams, RejectedOperationError,
    readCredentialPasswordFile: file => { calls.push(['credential-file', file]); return 'synthetic-test-password'; },
    resolvePostgresCredential: () => { calls.push(['generic-credential']); return { user: 'generic-app' }; },
    resolveMariaDbCredential: () => null,
    resolvePlatformDatabaseAdminCredential: () => { calls.push(['platform-fallback']); return { user: 'platform-admin' }; },
    databaseLiveApply: false,
    readDatabaseDeleteOperationsState: () => ({ operations: {} }),
    findDatabaseDeleteOperation: () => ({ database: { id: EXAMPLE_IDS[1] }, status: 'approved' }),
    findById: (rows, id) => rows.find(row => row.id === id || row.slug === id),
    validateSlug: () => {},
    postgresHost: 'platform-database', postgresPort: 5432,
    escapeHtml: value => String(value), databaseDisplayName: database => database.displayName, controlIcon: name => name,
    empty: () => '', renderProjectDetailDatabaseCreateForm: () => '<form data-test-create></form>',
  });
  const start = source.indexOf('function additionalTrustedDatabaseAdmissions(');
  const end = source.indexOf('const vaultFile =', start);
  assert.ok(start >= 0 && end > start);
  const exposed = ['trustedExternalDatabases', 'trustedExternalDatabaseIds', 'trustedExternalDatabaseFor', 'projectUsesTrustedExternalDatabase', 'additionalTrustedDatabaseAdmissions', ...FUNCTION_NAMES];
  vm.runInContext(`${FUNCTION_NAMES.map(extractFunction).join('\n')}\n${source.slice(start, end)}\nglobalThis.api = {${exposed.join(',')}};`, ctx);
  return { api: ctx.api, calls, ctx, hooks };
}
function collectDatabaseRows(ctx, stored) {
  ctx.readDatabasesState = () => stored;
  const start = source.indexOf('  const databaseRows = Object.values(readDatabasesState())');
  const end = source.indexOf('  const databases = databaseRows', start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(`{${source.slice(start, end)} globalThis.collectedRows = databaseRows;}`, ctx);
  return ctx.collectedRows;
}

test('loads the legacy profile and an independent additional profile with explicit host admission', () => {
  const { api, calls } = runtime();
  assert.equal(api.trustedExternalDatabases.size, 2);
  assert.equal(calls[0][2].expectedId, undefined);
  assert.equal(calls[1][2].expectedId, null);
  for (let index = 0; index < EXAMPLE_IDS.length; index++) {
    assert.equal(api.phpPgAdminServerId({ id: EXAMPLE_IDS[index] }), `database-${index}:5432:verify-full`);
  }
});

test('duplicate admissions fail startup rather than replace an earlier trusted profile', () => {
  assert.throws(() => runtime({ additionalRaw: JSON.stringify([{ file: EXAMPLE_FILES[0], digest: digest(profile(0)) }]) }), /Duplicate trusted database admission/);
});

test('an unadmitted profile never enters the runtime map', () => {
  assert.throws(() => runtime({ additionalRaw: JSON.stringify([{ file: '/run/trusted-db/profiles/unknown.json', digest: 'a'.repeat(64) }]) }), /Synthetic admission denied/);
});

for (const raw of [
  '{}', 'null', '[null]', '[{}]', '["x"]', '[1]', '[',
  JSON.stringify([{ file: 'relative.json', digest: 'a'.repeat(64) }]),
  JSON.stringify([{ file: '/' + 'a'.repeat(1024), digest: 'a'.repeat(64) }]),
  JSON.stringify([{ file: '/run/trusted-db/profiles/example.json', digest: 'a'.repeat(64), id: 'untrusted-extra-field' }]),
  JSON.stringify([{ file: '/run/trusted-db/profiles/example.json', digest: 'bad' }]),
  JSON.stringify(Array(9).fill({ file: '/run/trusted-db/profiles/example.json', digest: 'a'.repeat(64) })),
  ' '.repeat(8193),
]) test(`rejects invalid or oversized additional admission input ${raw.slice(0, 32)}`, () => {
  assert.throws(() => runtime({ additionalRaw: raw }), /Invalid additional trusted database admissions/);
});

test('missing required extension fails closed for both legacy and additional configuration', () => {
  assert.throws(() => runtime({ extension: false, second: false }), /requires the reviewed host extension/);
  assert.throws(() => runtime({ extension: false, first: false }), /requires the reviewed host extension/);
});

test('an empty installation with no extension retains generic behavior', () => {
  const { api, calls } = runtime({ extension: false, first: false, second: false });
  assert.equal(api.trustedExternalDatabases.size, 0);
  assert.equal(api.projectUsesTrustedExternalDatabase({ slug: 'ordinary-project' }), false);
  assert.match(api.renderProjectDetailDatabaseList({}, { slug: 'ordinary-project' }, []), /data-test-create/);
  assert.doesNotThrow(() => api.assertExternalDatabaseOperation('ordinary-database', 'credential'));
  assert.equal(api.phpPgAdminServerId({ id: 'ordinary-database' }), 'platform-database:5432:allow');
  const credentials = api.databaseAdminCredentials({ id: 'ordinary-database', engine: 'postgres' }, {});
  assert.equal(credentials.length, 2);
  assert.deepEqual(calls, [['generic-credential'], ['platform-fallback']]);
});

for (let index = 0; index < EXAMPLE_IDS.length; index++) {
  test(`profile ${index} credentials never invoke generic or platform fallback`, () => {
    const { api, calls } = runtime(); calls.length = 0;
    const credentials = api.databaseAdminCredentials({ id: EXAMPLE_IDS[index], engine: 'postgres', credentialFile: '/run/secrets/wrong-platform-secret' }, {});
    assert.equal(credentials.length, 1);
    assert.equal(credentials[0].user, `manager_${index}`);
    assert.deepEqual(calls, [['credential-file', `/run/secrets/example_${index}_management`]]);
  });
  test(`profile ${index} credential failure cannot fall through to platform credentials`, () => {
    const { api, calls, ctx } = runtime(); calls.length = 0;
    ctx.readCredentialPasswordFile = () => { throw new Error('Dedicated credential unavailable'); };
    assert.throws(() => api.databaseAdminCredentials({ id: EXAMPLE_IDS[index], engine: 'postgres' }, {}), /Dedicated credential unavailable/);
    assert.deepEqual(calls, []);
  });
  test(`reserved profile ${index} without admission rejects credentials and routing`, () => {
    const { api, calls } = runtime({ first: index !== 0, second: index !== 1 }); calls.length = 0;
    assert.throws(() => api.databaseAdminCredentials({ id: EXAMPLE_IDS[index], engine: 'postgres' }, {}), RejectedOperationError);
    assert.throws(() => api.phpPgAdminServerId({ id: EXAMPLE_IDS[index] }), RejectedOperationError);
    assert.throws(() => api.assertExternalDatabaseOperation(EXAMPLE_IDS[index], 'browse'), RejectedOperationError);
    assert.deepEqual(calls, []);
  });
  test(`profile ${index} blocks parallel principal creation through project or aliases`, () => {
    const { api } = runtime();
    const project = { id: EXAMPLE_PROJECTS[index], slug: EXAMPLE_PROJECTS[index] };
    assert.equal(api.projectUsesTrustedExternalDatabase(project), true);
    assert.equal(api.projectUsesTrustedExternalDatabase({ slug: 'alternate', aliases: [EXAMPLE_PROJECTS[index]] }), true);
    assert.throws(() => api.planDatabaseCreate({ projectId: project.slug }, { projects: [project] }), RejectedOperationError);
    const panel = api.renderProjectDetailDatabaseList({}, project, []);
    assert.doesNotMatch(panel, /data-test-create|cc-app-database-create/);
  });
  test(`profile ${index} renders the admitted login and omits destructive/credential editors`, () => {
    const { api, hooks } = runtime();
    const admitted = api.trustedExternalDatabases.get(EXAMPLE_IDS[index]);
    const row = api.renderProjectDetailDatabaseRow({}, { slug: EXAMPLE_PROJECTS[index] }, hooks.externalDatabaseRecord(admitted));
    assert.match(row, new RegExp(`manager_${index}`));
    assert.match(row, /Accesso gestito ai dati/);
    assert.doesNotMatch(row, /database-delete|type="password"|cc-app-database-manage/);
  });
  for (const name of ['applyLiveDatabaseCreate', 'applyLiveDatabaseCredential', 'applyLiveDatabaseDelete', 'applyLiveDatabasePrincipalCleanup', 'removeDatabaseCredentialFile']) {
    test(`profile ${index} is protected at low-level ${name}`, () => {
      const { api } = runtime();
      assert.throws(() => api[name]({ id: EXAMPLE_IDS[index] }), RejectedOperationError);
    });
  }
  for (const name of ['approveDatabaseDelete', 'executeDatabaseDelete']) {
    test(`profile ${index} rechecks exact DB identity at ${name}`, () => {
      const { api, ctx } = runtime();
      ctx.findDatabaseDeleteOperation = () => ({ database: { id: EXAMPLE_IDS[index] }, status: 'approved' });
      assert.throws(() => api[name]('synthetic-stale-operation', {}, {}), RejectedOperationError);
    });
  }
  test(`profile ${index} immediate deletion is rejected before the confirmation flow`, () => {
    const { api } = runtime();
    assert.throws(() => api.deleteDatabaseNow(EXAMPLE_IDS[index], {}, { databases: [{ id: EXAMPLE_IDS[index] }] }), RejectedOperationError);
  });
}

test('stored ID collisions are replaced with authoritative admitted records', () => {
  const { ctx } = runtime();
  const rows = collectDatabaseRows(ctx, {
    first: { id: EXAMPLE_IDS[0], credentialFile: '/run/secrets/wrong-credential' },
    second: { id: EXAMPLE_IDS[1], ownerRole: 'wrong-platform-owner' },
    ordinary: { id: 'ordinary-database' },
  });
  assert.equal(rows.length, 3);
  for (let index = 0; index < EXAMPLE_IDS.length; index++) {
    assert.equal(rows.filter(row => row.id === EXAMPLE_IDS[index]).length, 1);
    assert.equal(rows.find(row => row.id === EXAMPLE_IDS[index]).credentialFile, `/run/secrets/example_${index}_management`);
  }
});

test('reserved IDs are hidden when their root admission is absent', () => {
  const { ctx } = runtime({ first: false, second: false });
  const rows = collectDatabaseRows(ctx, { stale: { id: EXAMPLE_IDS[1], credentialFile: '/run/secrets/wrong-credential' }, ordinary: { id: 'ordinary-database' } });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].id, 'ordinary-database');
});

test('per-profile backup/restore capability buttons and guards remain isolated', () => {
  const { api } = runtime();
  const first = api.renderDatabaseActions([{ id: EXAMPLE_IDS[0], engine: 'postgres', displayName: 'Example A' }]);
  const second = api.renderDatabaseActions([{ id: EXAMPLE_IDS[1], engine: 'postgres', displayName: 'Example B' }]);
  assert.match(first, /value="backup"/); assert.match(first, /value="restore"/);
  assert.doesNotMatch(second, /value="backup"|value="restore"/); assert.match(second, /phppgadmin-login/);
  assert.doesNotThrow(() => api.assertExternalDatabaseOperation(EXAMPLE_IDS[0], 'backup'));
  assert.throws(() => api.assertExternalDatabaseOperation(EXAMPLE_IDS[1], 'backup'), RejectedOperationError);
  assert.throws(() => api.createDirectDatabaseBackupArtifact({ externalId: EXAMPLE_IDS[1] }, { databases: [{ id: EXAMPLE_IDS[1] }] }, {}, 0), RejectedOperationError);
});

test('all entry points retain map-based guards and no singleton admission path remains', () => {
  assert.doesNotMatch(source, /trustedExternalDatabase\?\.|if \(trustedExternalDatabase\)|externalDatabaseAdminCredentials\(trustedExternalDatabase,/);
  for (const name of ['planDatabaseUpdate', 'planDatabaseCredentialUpdate', 'planDatabaseDelete', 'planDatabaseBackup', 'planDatabaseRestore']) assert.match(extractFunction(name), /assertExternalDatabaseOperation\(database.id,/);
  assert.match(extractFunction('handlePhpPgAdminLogin'), /assertExternalDatabaseOperation\(database.id, "browse"\)/);
});


test('the bounded parser accepts its eight-entry boundary before host admission', () => {
  const { api } = runtime();
  const entries = Array.from({ length: 8 }, (_, index) => ({ file: `/run/trusted-db/profiles/example-${index}.json`, digest: 'a'.repeat(64) }));
  assert.equal(api.additionalTrustedDatabaseAdmissions(JSON.stringify(entries)).length, 8);
});

test('the bounded parser accepts a maximum-length absolute metadata path', () => {
  const { api } = runtime();
  const entries = api.additionalTrustedDatabaseAdmissions(JSON.stringify([{ file: '/' + 'a'.repeat(1023), digest: 'a'.repeat(64) }]));
  assert.equal(entries[0].file.length, 1024);
});

test('an explicit empty additional list does not require a host extension', () => {
  const { api } = runtime({ first: false, second: false, extension: false, additionalRaw: '[]' });
  assert.equal(api.trustedExternalDatabases.size, 0);
});
