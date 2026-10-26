import { controlIcon } from '../components/ui/controlIcons.mjs';

export function renderRuntimeUpdates() {
  return `<section class="ops-project-detail-panel cc-updates" data-runtime-updates aria-labelledby="runtime-updates-title">
    <header class="cc-updates-header"><div><h2 id="runtime-updates-title">Aggiornamenti</h2><p class="cc-settings-note">Runtime e strumenti del server</p></div><div class="cc-updates-actions"><button type="button" class="ops-button secondary compact" data-updates-refresh aria-label="Ricarica aggiornamenti">${controlIcon('refresh')}</button><button type="button" class="ops-button primary compact" data-updates-check disabled>${controlIcon('search')} Verifica versioni stabili</button></div></header>
    <p data-updates-summary class="cc-settings-note">Caricamento componenti…</p>
    <div class="cc-updates-filters"><label>Cerca componente<input type="search" data-updates-search placeholder="PHP, Node, database…"></label><label>Categoria<select data-updates-category><option value="all">Tutte le categorie</option></select></label></div>
    <p data-updates-status role="status" aria-live="polite"></p><div data-updates-progress hidden><progress aria-label="Avanzamento operazione"></progress><span data-updates-stage></span></div>
    <div data-updates-list class="cc-updates-list"></div><p data-updates-empty hidden>Nessun componente corrispondente.</p>
    <dialog class="cc-updates-dialog" data-updates-dialog aria-labelledby="updates-plan-title"><h2 id="updates-plan-title">Rivedi aggiornamento</h2><p data-updates-plan-status role="status" aria-live="polite"></p><div data-updates-plan-details></div><label data-updates-confirm-label hidden>Scrivi UPDATE per confermare<input data-updates-confirm autocomplete="off" spellcheck="false"></label><div class="cc-updates-actions"><button type="button" class="ops-button secondary compact" data-updates-close>Chiudi</button><button type="button" class="ops-button primary compact" data-updates-apply disabled>Aggiorna componente</button></div></dialog>
  </section>`;
}
