import fs from 'node:fs';
import path from 'node:path';

const names = ['node-scriptastudents', 'scripta-postgres', 'students-beta-redis', 'scriptastudents-ingress'];
const hash = /^[a-f0-9]{64}$/;
const image = /^sha256:[a-f0-9]{64}$/;
const version = /^[0-9]{1,2}\.[0-9]{1,2}(?:\.[0-9]{1,2})?$/;
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join() !== [...keys].sort().join()) throw Error('Invalid observed application catalog');
}
function integer(value) { if (!Number.isSafeInteger(value) || value < 0) throw Error('Invalid observed metric'); }
function flag(value) { if (typeof value !== 'boolean') throw Error('Invalid observed state'); }
function timestamp(value) { if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) throw Error('Invalid observation time'); }

// Observations never enter managed projects/databases, ownership bindings or AI
// source readers. The root publisher is the only writer of this finite catalog.
export function validateObservedApplications(raw, profileSha256, now = Date.now()) {
  exact(raw, ['schema','host','profileSha256','observedAt','application']);
  if (raw.schema !== 'platform.observed-applications/v1' || raw.host !== 'platform-server-public' || typeof raw.profileSha256 !== 'string' || !hash.test(raw.profileSha256) || raw.profileSha256 !== profileSha256) throw Error('Observation admission differs');
  timestamp(raw.observedAt);
  if (Date.parse(raw.observedAt) > now + 30000) throw Error('Observation time is in the future');
  const app = raw.application;
  exact(app, ['id','name','version','apiOrigin','siteOrigin','apiReachable','services','database','redis','backup']);
  if (app.id !== 'scripta-students' || app.name !== 'Scripta Students' || app.version !== '1.0' || app.apiOrigin !== 'https://api.scriptastudents.com' || app.siteOrigin !== 'https://scriptastudents.com') throw Error('Unexpected observed application');
  flag(app.apiReachable);
  if (!Array.isArray(app.services) || app.services.length !== 4 || new Set(app.services.map(s => s.name)).size !== 4 || new Set(app.services.map(s => s.containerId)).size !== 4) throw Error('Unexpected observed service scope');
  for (const service of app.services) {
    exact(service, ['name','containerId','image','running','health','restartCount']);
    if (!names.includes(service.name) || typeof service.containerId !== 'string' || !hash.test(service.containerId) || typeof service.image !== 'string' || !image.test(service.image) || !['healthy','unhealthy','starting','unknown'].includes(service.health)) throw Error('Unexpected observed service identity');
    flag(service.running); integer(service.restartCount);
  }
  const db = app.database, redis = app.redis, backup = app.backup;
  exact(db, ['engine','name','role','version','connected','tls']);
  if (db.engine !== 'postgres' || db.name !== 'students_beta_app' || db.role !== 'scripta_app' || typeof db.version !== 'string' || !version.test(db.version)) throw Error('Unexpected observed database');
  flag(db.connected); flag(db.tls);
  exact(redis, ['version','connected','tls','aof','keyCount','usedBytes','maxBytes']);
  if (typeof redis.version !== 'string' || !version.test(redis.version)) throw Error('Unexpected observed Redis');
  for (const key of ['connected','tls','aof']) flag(redis[key]);
  for (const key of ['keyCount','usedBytes','maxBytes']) integer(redis[key]);
  exact(backup, ['covered','offsiteVerified','manifestId','verifiedAt']);
  flag(backup.covered); flag(backup.offsiteVerified);
  if (backup.manifestId !== null && (typeof backup.manifestId !== 'string' || !/^manifest-vps-[a-z0-9-]{16,100}$/.test(backup.manifestId))) throw Error('Invalid observed backup identity');
  if (backup.verifiedAt !== null) timestamp(backup.verifiedAt);
  if (backup.offsiteVerified && (!backup.covered || !backup.manifestId || !backup.verifiedAt)) throw Error('Incomplete backup observation');
  const stale = now - Date.parse(raw.observedAt) > 120000;
  const healthy = app.apiReachable && app.services.every(s => s.running && s.health === 'healthy') && db.connected && db.tls && redis.connected && redis.tls && redis.aof;
  return Object.freeze({ ...app, management: 'external-readonly', observedAt: raw.observedAt, stale, status: stale ? 'unknown' : healthy ? 'healthy' : 'degraded' });
}

export function readObservedApplications(root, profileSha256) {
  if (!root) return [];
  const file = path.join(root, 'applications-observed.json');
  if (!fs.existsSync(file)) return [];
  const directory = fs.lstatSync(root), before = fs.lstatSync(file);
  if (!directory.isDirectory() || directory.isSymbolicLink() || directory.uid !== 0 || directory.mode & 0o022 || !before.isFile() || before.isSymbolicLink() || before.uid !== 0 || before.mode & 0o022 || before.size > 65536) throw Error('Observed application catalog unavailable');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const actual = fs.fstatSync(fd);
    if (actual.dev !== before.dev || actual.ino !== before.ino || actual.size !== before.size || actual.uid !== 0 || actual.mode & 0o022) throw Error('Observed application catalog changed');
    return [validateObservedApplications(JSON.parse(fs.readFileSync(fd,'utf8')), profileSha256)];
  } finally { fs.closeSync(fd); }
}

function esc(value) { return String(value).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;'); }
function state(app) { return app.status === 'healthy' ? ['good','Operativa'] : app.status === 'unknown' ? ['warn','Da aggiornare'] : ['bad','Da verificare']; }
export function renderObservedApplicationRow(app, icon) {
  const [tone,label] = state(app), href='/?section=projects&observed=scripta-students';
  return `<div class="ops-project-row" id="observed-scripta-students" role="link" tabindex="0" data-project-row-link="${href}" aria-label="Apri dettagli Scripta Students">
    <span class="ops-project-row-icon node" aria-hidden="true">${icon('applications')}</span>
    <span class="ops-project-row-name"><span class="ops-project-state-dot ${tone}" aria-hidden="true"></span><strong>Scripta Students</strong></span>
    <span class="ops-project-row-host"><small>Host</small><a class="ops-project-host-link ops-fit-link" href="${app.siteOrigin}" target="_blank" rel="noopener noreferrer">scriptastudents.com</a></span>
    <span class="ops-project-row-runtime"><small>Runtime</small><strong>API · iOS · Android</strong></span>
    <span class="ops-state ${tone}">${label}</span>
  </div>`;
}
export function renderObservedApplicationDetail(app, icon) {
  const [tone,label]=state(app);
  const services=app.services.map(s=>`<tr><td>${esc(s.name)}</td><td>${s.running ? s.health === 'healthy' ? 'Operativo' : s.health === 'starting' ? 'Avvio' : 'Da verificare' : 'Fermo'}</td><td>${s.restartCount}</td></tr>`).join('');
  return `<section class="ops-section" data-observed-application="scripta-students">
    <a class="ops-button secondary compact" href="/?section=projects">← Applicazioni</a>
    <section class="ops-card"><h2>Scripta Students <span class="ops-state ${tone}">${label}</span></h2><p>Versione ${app.version} · Backend per iOS e Android</p><p>Stato aggiornato: <time datetime="${esc(app.observedAt)}">${esc(new Date(app.observedAt).toLocaleString('it-IT'))}</time>${app.stale ? ' · osservazione scaduta' : ''}</p>
      <p><a href="${app.siteOrigin}" target="_blank" rel="noopener noreferrer">Sito pubblico</a> · <a href="${app.apiOrigin}/api/health" target="_blank" rel="noopener noreferrer">Stato API</a></p></section>
    <section class="ops-card"><h2>Servizi</h2><table class="ops-table"><thead><tr><th>Servizio</th><th>Stato</th><th>Riavvii</th></tr></thead><tbody>${services}</tbody></table></section>
    <section class="ops-card"><h2>Database</h2><p>PostgreSQL ${app.database.version} · ${app.database.connected ? 'Connesso' : 'Da verificare'} · ${app.database.tls ? 'TLS attivo' : 'TLS da verificare'}</p><p><strong>${app.database.name}</strong> · ruolo ${app.database.role}</p></section>
    <section class="ops-card"><h2>Redis</h2><p>Redis ${app.redis.version} · ${app.redis.connected ? 'Connesso' : 'Da verificare'} · ${app.redis.tls ? 'TLS attivo' : 'TLS da verificare'} · ${app.redis.aof ? 'Persistenza attiva' : 'Persistenza da verificare'}</p><p>${app.redis.keyCount} chiavi · ${(app.redis.usedBytes/1048576).toFixed(2)} MiB usati / ${(app.redis.maxBytes/1048576).toFixed(0)} MiB</p></section>
    <section class="ops-card"><h2>Backup</h2><p>${app.backup.offsiteVerified ? 'Copia esterna verificata, con dati di Scripta inclusi.' : 'Verifica della copia esterna di Scripta in attesa.'}</p>${app.backup.manifestId ? `<p><code>${esc(app.backup.manifestId)}</code></p>` : ''}<p>La gestione dell’applicazione resta nell’installazione VPS; questa scheda mostra le osservazioni reali dei servizi.</p></section>
  </section>`;
}
