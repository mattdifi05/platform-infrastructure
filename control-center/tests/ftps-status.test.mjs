import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import test from 'node:test';
import { readVpsBackupCatalog } from '../backup/vps-catalog.mjs';

const source = fs.readFileSync(new URL('../server.mjs', import.meta.url), 'utf8');
const start = source.indexOf('function readFtpsOffsiteSummary(');
const end = source.indexOf('\nfunction buildBackupInventory(', start);
assert.ok(start > 0 && end > start);
const now = Date.parse('2026-09-28T04:00:00Z');
const good = {
  schema: 'platform.ftps-recovery-point/v2', status: 'passed', backupAt: '2026-09-28T03:00:00Z',
  manifestId: 'manifest-final', manifestDigest: 'a'.repeat(64), artifactCount: 69, retainedPointCount: 2,
  tlsVerified: true, actualDownloadVerified: true, decryptVerified: true,
  manifestHmacVerified: true, everyArtifactShaAndHmacVerified: true,
};

function evaluate(proof, destination = { backend: 'ftps-encrypted-bundles' }, linked = false) {
  const files = { 'ftps-proof.json': proof, 'offsite-destination.json': destination };
  const bind = {
    path,
    readVpsBackupCatalog,
    process: { env: {} },
    lstatSync(file) {
      if (!(path.basename(file) in files)) throw Error('missing');
      return { isFile: () => true, isSymbolicLink: () => linked, size: 1024 };
    },
    readFileSync(file) { return JSON.stringify(files[path.basename(file)]); },
  };
  return new Function(...Object.keys(bind), `${source.slice(start, end)}\nreturn readFtpsOffsiteSummary;`)(...Object.values(bind))(now);
}

test('full V2 remote download and 69-artifact proof is recognized without claiming RustFS drill', () => {
  assert.deepEqual(evaluate(good), {
    verified: true, backupAt: good.backupAt, manifestId: good.manifestId,
    retainedPointCount: 2, reportPath: 'host-recovery/ftps-proof.json',
  });
  const builder = source.slice(end, source.indexOf('\nfunction applicationBackupInventory(', end));
  assert.match(builder, /offsite: ftps\?\.verified \|\| offsite\.status === "success"/);
  assert.match(builder, /rustfsRestoreVerified: null/);
  const bindings = {
    safeReadBackupFiles: () => ({ available: true }), readBackupJobs: () => [], backupFamilySpecs: () => [],
    readBackupFamily: () => ({}), latestDocumentedReport: () => null,
    readFtpsOffsiteSummary: () => evaluate(good), backupRootSummary: () => ({}),
    relativeTimeLabel: () => '1 ora fa', sanitizeEvent: (value) => value,
    environment: 'production', existsSync: () => true, backupJobsDir: '/fixture/jobs',
    process: { env: {} },
  };
  const inventory = new Function(...Object.keys(bindings), `${builder}\nreturn buildBackupInventory;`)(...Object.values(bindings))();
  assert.equal(inventory.offsite, 'verified-off-site');
  assert.equal(inventory.offsiteRestore.actualDownloadVerified, true);
  assert.equal(inventory.offsiteRestore.proofScope, 'download-decrypt-artifact-integrity');
  assert.equal(inventory.offsiteRestore.rustfsRestoreVerified, null);
  assert.equal(inventory.offsiteRestore.status, 'success');
});

test('partial, stale, symlinked and legacy proof never count as V2 verification', () => {
  assert.equal(evaluate({ ...good, everyArtifactShaAndHmacVerified: false }).verified, false);
  assert.equal(evaluate({ ...good, backupAt: '2026-09-01T03:00:00Z' }).verified, false);
  assert.equal(evaluate({ ...good, schema: 'platform.ftps-recovery-point/v1' }).verified, false);
  assert.equal(evaluate(good, undefined, true), null);
  assert.equal(evaluate(good, { backend: 'restic' }), null);
});
