(function () {
  'use strict';
  var mounted = new WeakSet(), active = new Set();
  var sourceLabels = { host: 'Sistema', systemd: 'Servizi', docker: 'Container', updates: 'Manutenzione', journal: 'Registro di sistema' };
  function text(value, fallback, limit) { return typeof value === 'string' && value.trim() ? value.trim().slice(0, limit || 500) : fallback; }
  function time(value) { var stamp = typeof value === 'number' ? (value < 100000000000 ? value * 1000 : value) : value; var date = new Date(stamp); return value && Number.isFinite(date.getTime()) ? date.toLocaleString('it-IT') : ''; }
  function timestamp(value) { var stamp = typeof value === 'number' && value < 100000000000 ? value * 1000 : value; var parsed = new Date(stamp).getTime(); return Number.isFinite(parsed) ? parsed : 0; }
  function element(tag, value, className) { var node = document.createElement(tag); if (value !== undefined) node.textContent = value; if (className) node.className = className; return node; }
  function normalize(records, onlyActive) {
    var rows = new Map(), malformed = !Array.isArray(records);
    (Array.isArray(records) ? records : []).forEach(function (record) {
      if (!record || typeof record.id !== 'string' || !record.id.trim() || !['error', 'warning'].includes(record.severity) || !Object.prototype.hasOwnProperty.call(sourceLabels, record.source) || typeof record.message !== 'string' || !record.message.trim()) { malformed = true; return; }
      if (onlyActive && record.active === false) return;
      var id = record.source + ':' + record.id.slice(0, 200), previous = rows.get(id);
      var item = { id: id, severity: record.severity, source: record.source, service: text(record.service, sourceLabels[record.source], 120), message: text(record.message, 'Dettagli non disponibili', 1600), code: text(record.code, '', 80), count: Number.isSafeInteger(record.count) && record.count > 0 ? record.count : 1, firstSeen: record.firstSeen, lastSeen: record.lastSeen, active: onlyActive ? true : record.active === true ? true : record.active === false ? false : null };
      if (previous) {
        var newest = timestamp(item.lastSeen) >= timestamp(previous.lastSeen) ? item : previous;
        newest = Object.assign({}, newest, { count: Math.max(previous.count, item.count), firstSeen: timestamp(previous.firstSeen) && (!timestamp(item.firstSeen) || timestamp(previous.firstSeen) < timestamp(item.firstSeen)) ? previous.firstSeen : item.firstSeen, active: previous.active === true || item.active === true ? true : previous.active === null || item.active === null ? null : false });
        rows.set(id, newest);
      } else rows.set(id, item);
    });
    return { rows: Array.from(rows.values()).sort(function (left, right) { return Number(right.severity === 'error') - Number(left.severity === 'error') || timestamp(right.lastSeen) - timestamp(left.lastSeen) || left.id.localeCompare(right.id); }), malformed: malformed };
  }
  function mount(root) {
    if (mounted.has(root)) return;
    mounted.add(root);
    var select = function (name) { return root.querySelector('[data-events-' + name + ']'); };
    var state = { value: null, view: 'active', loading: false, failed: false, stopped: false, generation: 0, timer: null, rows: new Map() };
    var list = select('list'), status = select('status'), empty = select('empty'), refresh = select('refresh');
    var views = Array.from(root.querySelectorAll('[data-events-view]'));
    function alive(generation) { return !state.stopped && root.isConnected && generation === state.generation; }
    function render() {
      if (!root.isConnected) return;
      var value = state.value, issues = normalize(value && value.issues, true), recent = normalize(value && value.events, false);
      var sources = value && Array.isArray(value.sources) ? value.sources : [];
      var partial = !value || value.partial !== false || issues.malformed || recent.malformed || !sources.length || sources.some(function (item) { return !item || item.available !== true; });
      var complete = Boolean(value && value.available === true && !partial && !state.failed);
      var unavailable = state.failed || !value || value.available !== true;
      root.setAttribute('data-feed-state', unavailable ? 'unavailable' : complete ? 'complete' : 'partial');
      root.setAttribute('aria-busy', state.loading ? 'true' : 'false');
      refresh.disabled = state.loading;
      select('errors').textContent = value ? String(issues.rows.filter(function (item) { return item.severity === 'error'; }).length) : '—';
      select('warnings').textContent = value ? String(issues.rows.filter(function (item) { return item.severity === 'warning'; }).length) : '—';
      if (state.loading && !value) status.textContent = 'Lettura dello stato del server…';
      else if (state.failed) status.textContent = value ? 'Aggiornamento non riuscito. Sono mostrati gli ultimi dati ricevuti: lo stato attuale non è verificato.' : 'Stato del server non disponibile. Riprova con Aggiorna.';
      else if (!value || value.available !== true) status.textContent = 'Verifica non disponibile: non è possibile confermare lo stato del server.';
      else if (!complete) status.textContent = 'Verifica parziale. Il risultato è incompleto: potrebbero esserci altre segnalazioni.';
      else status.textContent = issues.rows.length ? 'Verifica completata. Le segnalazioni attive sono elencate qui sotto.' : 'Verifica completata. Nessun errore o avviso attivo nelle fonti controllate.';
      select('checked').textContent = value && time(value.checkedAt) ? 'Ultima verifica: ' + time(value.checkedAt) : 'Verifica non ancora disponibile';
      select('sources').textContent = sources.length ? 'Fonti: ' + sources.map(function (source) { source = source || {}; return text(sourceLabels[source.id], text(source.id, 'Fonte', 60)) + (source.available === true ? '' : ' · non disponibile'); }).join(' / ') : '';
      views.forEach(function (button) { button.setAttribute('aria-pressed', button.getAttribute('data-events-view') === state.view ? 'true' : 'false'); });
      select('description').textContent = state.view === 'active' ? 'Problemi ancora presenti nell’ultima verifica.' : 'Segnalazioni registrate di recente. Lo storico non conferma che il problema sia ancora presente o risolto.';
      var records = state.view === 'active' ? issues.rows : recent.rows;
      var wanted = new Set(records.map(function (record) { return record.id; }));
      state.rows.forEach(function (row, id) { if (!wanted.has(id)) { row.node.remove(); state.rows.delete(id); } });
      records.forEach(function (record, index) {
        var row = state.rows.get(record.id);
        if (!row) {
          var node = element('li', undefined, 'cc-event-row'), heading = element('div', undefined, 'cc-event-heading');
          row = { node: node, title: element('strong'), severity: element('span', undefined, 'cc-event-severity'), state: element('span', undefined, 'cc-event-state'), count: element('span', undefined, 'cc-event-count'), message: element('p', undefined, 'cc-event-message'), meta: element('small', undefined, 'cc-event-meta') };
          heading.append(row.severity, row.title, row.state); node.append(heading, row.count, row.message, row.meta); state.rows.set(record.id, row);
        }
        row.node.setAttribute('data-severity', record.severity);
        row.node.setAttribute('data-active', record.active === true ? 'true' : record.active === false ? 'false' : 'unknown');
        row.title.textContent = record.service; row.severity.textContent = record.severity === 'error' ? 'Errore' : 'Avviso';
        row.state.textContent = record.active === true ? 'Attivo' : record.active === false ? 'Storico' : 'Recente';
        row.count.textContent = record.count > 1 ? record.count + ' occorrenze' : '1 occorrenza';
        row.message.textContent = record.message;
        row.meta.textContent = [sourceLabels[record.source], record.code, time(record.firstSeen) ? 'Prima: ' + time(record.firstSeen) : '', time(record.lastSeen) ? 'Ultima: ' + time(record.lastSeen) : ''].filter(Boolean).join(' · ');
        // Keep stable nodes when a poll reports the same issue. Move only when
        // order changed, preserving focus, selection and the surrounding layout.
        if (list.children[index] !== row.node) list.insertBefore(row.node, list.children[index] || null);
      });
      empty.hidden = records.length > 0 || state.loading && !value;
      empty.textContent = state.view === 'recent' ? complete ? 'Nessuna segnalazione recente nelle fonti controllate.' : 'Nessun evento ricevuto. La verifica delle fonti non è completa.' : complete ? 'Nessun problema attivo.' : 'Nessuna segnalazione ricevuta. Lo stato del server non è confermato.';
    }
    function schedule() { clearTimeout(state.timer); if (!state.stopped && root.isConnected && !document.hidden) state.timer = setTimeout(load, 15000); }
    async function load() {
      if (state.loading || state.stopped || !root.isConnected || document.hidden) return;
      var generation = state.generation; state.loading = true; render();
      try {
        var bridge = window.controlCenterRuntimeUpdates;
        if (!bridge || typeof bridge.request !== 'function') throw Error('Collegamento non disponibile');
        var value = await bridge.request('/control/server-events');
        if (!alive(generation)) return;
        if (!value || value.schema !== 'server-events/v1') throw Error('Risposta non valida');
        state.value = value; state.failed = false;
      } catch (_) { if (alive(generation)) state.failed = true; }
      finally { if (alive(generation)) { state.loading = false; render(); schedule(); } }
    }
    refresh.addEventListener('click', function () { if (!refresh.disabled) load(); });
    views.forEach(function (button) { button.addEventListener('click', function () { state.view = button.getAttribute('data-events-view') === 'recent' ? 'recent' : 'active'; render(); }); });
    active.add({ root: root, pause: function () { clearTimeout(state.timer); }, resume: load, stop: function () { state.stopped = true; state.generation++; clearTimeout(state.timer); } });
    load();
  }
  function scan() { active.forEach(function (entry) { if (!entry.root.isConnected) { entry.stop(); active.delete(entry); } }); document.querySelectorAll('[data-server-events]').forEach(mount); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', scan); else scan();
  if (window.MutationObserver) new MutationObserver(scan).observe(document.body, { childList: true, subtree: true });
  document.addEventListener('visibilitychange', function () { active.forEach(function (entry) { if (document.hidden) entry.pause(); else entry.resume(); }); });
  window.addEventListener('pagehide', function () { active.forEach(function (entry) { entry.stop(); }); active.clear(); });
})();
