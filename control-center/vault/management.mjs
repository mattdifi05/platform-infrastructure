import { loadStore, withStoreLock, VaultConflictError, VaultStoreError, protectedVaultItem } from './store.mjs';

/** Remove only encrypted Vault state. Native detach never changes a consumer. */
export async function removeVaultItem({ config, runtime, runtimeConfigured = false, itemId, expectedRevision }) {
  const current = await loadStore(config);
  const revision = expectedRevision || current.revision;
  if (revision !== current.revision) throw new VaultConflictError('Vault changed; refresh before removing this item');
  if (!current.items[itemId]) throw new VaultStoreError('Vault item is absent');
  if (protectedVaultItem(current.items[itemId])) throw new VaultStoreError('Materiale di custodia escluso dal Vault applicativo.');
  const catalog = await runtime.catalog();
  if (runtimeConfigured && !catalog.available) throw new VaultStoreError('Verifica dei collegamenti non disponibile: rimozione bloccata.');
  const detached = [];
  for (const binding of catalog.bindings.filter(row => row.itemId === itemId && (row.adopted === true || row.appliedVersionId))) {
    const result = await runtime.call({ action: 'detach', bindingId: binding.bindingId, itemId, expectedVaultRevision: revision, expectedBindingRevision: binding.bindingRevision, confirmation: `DETACH:${binding.bindingId}` });
    if (result.detached !== true || result.bindingId !== binding.bindingId || result.itemId !== itemId || result.vaultRevision !== revision) throw new VaultStoreError('Rimozione del collegamento non verificata: record cifrato conservato.');
    detached.push(binding.bindingId);
  }
  // A concurrent edit must retain the newly written version, even after detach.
  await withStoreLock(config, tx => tx.deleteItem({ itemId, expectedRevision: revision }));
  return { detachedBindings: detached, runtimeCredentialsChanged: false, encryptedRecordRemoved: true };
}

const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
export function renderVaultManagementControls(item, { expectedRevision = '', bindings = [] } = {}) {
  return `<div class="ops-vault-management">
    <details class="ops-vault-edit" data-vault-edit><summary class="ops-button secondary compact">Modifica</summary>
      <p>Salva una nuova versione cifrata. La credenziale in uso non cambia: per consegnarla, verifica e applica il piano dell’applicazione.</p>
      <form data-vault-manage-form class="ops-vault-version-form" method="post" action="/actions/vault-command" autocomplete="off"><input type="hidden" name="action" value="version"><input type="hidden" name="itemId" value="${escape(item.id)}"><input type="hidden" name="expectedVaultRevision" value="${escape(expectedRevision)}"><textarea class="ops-vault-version-value" name="newValue" rows="2" placeholder="Nuovo valore" aria-label="Nuovo valore ${escape(item.label)}; ritorni a capo conservati" autocomplete="new-password" spellcheck="false" required></textarea><button class="ops-button secondary" type="submit">Salva modifica nel Vault</button></form>
    </details>
    <span class="ops-vault-reveal" data-vault-reveal-box><textarea class="ops-vault-secret-value" rows="1" placeholder="Protetto" readonly aria-label="Valore ${escape(item.label)}" data-vault-reveal-value data-vault-visible="false" spellcheck="false"></textarea><button class="ops-button secondary compact" type="button" data-vault-reveal-action data-vault-id="${escape(item.id)}" data-vault-confirm="REVEAL-VAULT-SECRET:${escape(item.id)}">Mostra</button><button class="ops-button secondary compact" type="button" data-vault-copy-action disabled>Copia</button></span>
    <details class="ops-vault-delete-confirm" data-vault-delete-confirm><summary class="ops-button danger compact">Elimina</summary>
      <p>Rimuovi dal Vault; la credenziale in uso resta al servizio. Non vengono eliminati file delle applicazioni o credenziali del provider.</p>
      <form method="post" action="/actions/vault-command" class="ops-vault-delete-form" data-vault-manage-form><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="${escape(item.id)}"><input type="hidden" name="confirm" value="DELETE-VAULT-SECRET:${escape(item.id)}"><input type="hidden" name="expectedVaultRevision" value="${escape(expectedRevision)}"><label>Scrivi RIMUOVI per confermare<input name="typedConfirmation" pattern="RIMUOVI" autocomplete="off" aria-label="Conferma rimozione ${escape(item.label)}" required></label><button class="ops-button danger compact" type="submit">Rimuovi dal Vault</button></form>
    </details>
    ${bindings.map(binding => `<a class="ops-button secondary compact" data-vault-binding-link="${escape(binding.bindingId)}" href="#vault-runtime-${escape(binding.bindingId)}">Collegamento: ${escape(binding.label)}</a>`).join('')}
  </div>`;
}
