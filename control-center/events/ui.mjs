import { controlIcon } from '../components/ui/controlIcons.mjs';

export function renderServerEvents() {
  return `<section class="ops-project-detail-panel cc-server-events" data-server-events aria-labelledby="server-events-title">
    <header class="cc-events-header"><div><h2 id="server-events-title">Errori e avvisi</h2><p class="cc-settings-note">Stato del server e dei servizi</p></div><button type="button" class="ops-button secondary compact" data-events-refresh aria-label="Aggiorna errori e avvisi">${controlIcon('refresh')}</button></header>
    <div class="cc-events-summary" aria-label="Problemi attivi"><div><span>Errori attivi</span><strong data-events-errors>—</strong></div><div><span>Avvisi attivi</span><strong data-events-warnings>—</strong></div></div>
    <p class="cc-events-status" data-events-status role="status" aria-live="polite">Lettura dello stato del server…</p>
    <div class="cc-events-toolbar"><div class="cc-events-views" role="group" aria-label="Visualizza segnalazioni"><button type="button" data-events-view="active" aria-pressed="true">Attivi</button><button type="button" data-events-view="recent" aria-pressed="false">Recenti</button></div><span data-events-checked class="cc-settings-note"></span></div>
    <p class="cc-settings-note" data-events-description>Problemi ancora presenti nell’ultima verifica.</p>
    <ul class="cc-events-list" data-events-list aria-label="Segnalazioni del server"></ul><p class="cc-events-empty" data-events-empty hidden></p>
    <p class="cc-events-sources cc-settings-note" data-events-sources></p>
  </section>`;
}
