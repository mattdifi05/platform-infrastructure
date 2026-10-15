import { controlIcon } from '../components/ui/controlIcons.mjs';

const actions = new Set(['catalog', 'adopt', 'plan', 'apply', 'rollback', 'status', 'detach']);
const fields = new Set(['action', 'bindingId', 'itemId', 'versionId', 'expectedVaultRevision', 'expectedBindingRevision', 'planId', 'confirmation', 'operationId']);
const secretFields = /^(?:value|newValue|plainValue|plaintext|sealedValue|ciphertext|token|password|path|command|destination|source)$/i;
export class VaultRuntimeError extends Error {}
const reject = () => { throw new VaultRuntimeError('Distribuzione Vault non disponibile, non autorizzata o cambiata: aggiorna il piano.'); };
function inspect(value, depth = 0) {
  if (depth > 8) reject();
  if (Array.isArray(value)) { if (value.length > 2000) reject(); value.forEach(item => inspect(item, depth + 1)); }
  else if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) { if (secretFields.test(key)) reject(); inspect(item, depth + 1); }
  } else if (typeof value === 'string' && value.length > 4096) reject();
}
export function validateRuntimeRequest(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !fields.has(key)) || !actions.has(body.action)) reject();
  for (const [key, value] of Object.entries(body)) if (typeof value !== 'string' || !value || value.length > 512 || /[\r\n\0]/.test(value)) reject();
  if (body.action !== 'catalog' && body.action !== 'status' && !body.bindingId) reject();
  if (body.action === 'detach' && (!body.itemId || !body.expectedVaultRevision || !body.expectedBindingRevision || body.confirmation !== `DETACH:${body.bindingId}` || Object.keys(body).length !== 6)) reject();
  if (body.action === 'adopt' && body.confirmation !== `ADOPT:${body.bindingId}`) reject();
  if (body.action === 'plan' && (!body.itemId || !body.versionId || !body.expectedVaultRevision || !body.expectedBindingRevision)) reject();
  if (body.action === 'apply' && (!body.planId || body.confirmation !== `APPLY:${body.planId}`)) reject();
  if (body.action === 'status' && !body.operationId && !body.bindingId) reject();
  return Object.freeze({ ...body });
}
export function createVaultRuntime(native) {
  return {
    async call(body) {
      const request = validateRuntimeRequest(body);
      if (typeof native !== 'function') reject();
      try {
        const result = await native(request); inspect(result);
        if (!result || typeof result !== 'object' || result.error) reject();
        if (request.action === 'catalog' && (result.available !== true || !Array.isArray(result.bindings) || typeof result.vaultRevision !== 'string')) reject();
        if (['plan', 'rollback'].includes(request.action) && (result.status !== 'validated' || !result.planId || result.confirmation !== `APPLY:${result.planId}` || result.bindingId !== request.bindingId)) reject();
        if (request.action === 'plan' && (result.itemId !== request.itemId || result.versionId !== request.versionId || result.expectedVaultRevision !== request.expectedVaultRevision || result.expectedBindingRevision !== request.expectedBindingRevision)) reject();
        if (request.action === 'apply' && (!result.operationId || result.phase !== 'queued')) reject();
        return result;
      } catch { reject(); }
    },
    async catalog() {
      try { return await this.call({ action: 'catalog' }); }
      catch { return { available: false, bindings: [], reason: 'Distribution native non configurata o non disponibile.' }; }
    },
  };
}

const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
const hidden = (name, value) => `<input type="hidden" name="${name}" value="${escape(value)}">`;
const displayDate = value => { const date = new Date(value); return value && !Number.isNaN(date.getTime()) ? new Intl.DateTimeFormat('it-IT', { dateStyle: 'short', timeStyle: 'short', timeZone: 'Europe/Rome' }).format(date) : 'non disponibile'; };
export function renderVaultRuntime(catalog, items = []) {
  if (!catalog.available) return '<section class="ops-vault-panel"><h2>Consegna alle applicazioni</h2><p>Distribuzione non configurata. I valori salvati restano nel Vault e non cambiano le credenziali in uso.</p></section>';
  return `<details class="ops-vault-panel ops-vault-runtime-panel" data-vault-runtime-panel><summary><strong>${controlIcon("cube")}Consegna alle applicazioni</strong><span>${catalog.bindings.length} collegamenti · Apri gestione${controlIcon("chevron-down")}</span></summary><p>Centralizza le credenziali attuali senza cambiarle. Per una nuova versione: verifica il piano, poi applicalo. La verifica del provider è distinta dalla salute dell’applicazione.</p><div class="ops-vault-list ops-vault-runtime-scroll" role="region" tabindex="0" aria-label="Collegamenti applicazioni, elenco scorrevole">${catalog.bindings.map(binding => {
    const item = items.find(row => row.id === binding.itemId);
    const operationId = typeof binding.lastOperation === 'string' ? binding.lastOperation : binding.lastOperation?.operationId;
    const rotationUnsupported = binding.rotation === 'coupled-service' || binding.rotation === false || binding.rotation?.supported === false || /unsupported|disabled|coupled/i.test(String(binding.rotation));
    return `<article class="ops-vault-item ops-vault-runtime-item" id="vault-runtime-${escape(binding.bindingId)}" data-vault-binding="${escape(binding.bindingId)}"><div class="ops-vault-item-main"><strong>${escape(binding.label)}</strong><small>${escape(binding.project)} · ${escape(binding.environment)}</small><p>${binding.deliveryVerified === true ? 'Versione consegnata e riletta' : 'Consegna non verificata'} · ${binding.runtimeHealthy === true ? 'Ultima verifica applicazione riuscita' : 'Salute applicazione non verificata'} · ${binding.providerVerified === true ? 'Provider verificato' : 'Provider non verificato'}</p><small>Ultima verifica: ${escape(displayDate(binding.verifiedAt))} · ${binding.appliedVersionId ? 'Una versione applicata' : 'Nessuna versione applicata'}${rotationUnsupported ? ' · Cambio credenziali non supportato per questo collegamento' : ''}</small>
      <details class="ops-vault-technical"><summary>${controlIcon("chevron")}Dettagli tecnici</summary><small>Collegamento: ${escape(binding.bindingId)} · Versione applicata: ${escape(binding.appliedVersionId || 'nessuna')}</small></details>
      ${!binding.adopted ? `<form data-vault-runtime-form action="/control/vault/runtime/adopt" method="post">${hidden('bindingId', binding.bindingId)}${hidden('confirmation', `ADOPT:${binding.bindingId}`)}<button class="ops-button secondary" type="submit">Centralizza credenziale attuale</button></form>` : ''}
      ${item && !rotationUnsupported ? `<form data-vault-runtime-form action="/control/vault/runtime/plan" method="post">${hidden('bindingId', binding.bindingId)}${hidden('itemId', binding.itemId)}${hidden('expectedVaultRevision', catalog.vaultRevision)}${hidden('expectedBindingRevision', binding.bindingRevision)}<label>Versione da consegnare<select name="versionId">${(item.versions || []).map((version, index) => `<option value="${escape(version.versionId)}"${version.versionId === item.currentVersionId ? " selected" : ""}>Versione ${index + 1} · ${escape(displayDate(version.createdAt))}${version.versionId === binding.appliedVersionId ? ' · in uso' : ''}</option>`).join('')}</select></label><button class="ops-button secondary" type="submit">Verifica piano</button></form>` : ''}
      ${binding.previousVersionId ? `<form data-vault-runtime-form action="/control/vault/runtime/rollback" method="post">${hidden('bindingId', binding.bindingId)}${hidden('expectedVaultRevision', catalog.vaultRevision)}${hidden('expectedBindingRevision', binding.bindingRevision)}<button class="ops-button secondary" type="submit">Verifica ripristino precedente</button></form>` : ''}
      ${operationId ? `<form data-vault-runtime-form action="/control/vault/runtime/status" method="post">${hidden('operationId', operationId)}<button class="ops-button secondary" type="submit">Controlla risultato</button></form>` : ''}
      <div data-vault-runtime-result role="status" aria-live="polite"></div></div></article>`;
  }).join('')}</div></details>`;
}
