(function () {
  'use strict';
  var mounted = new WeakSet(), active = new Set();
  var pending = function (operation) { return operation && ['queued', 'running'].includes(operation.status); };
  var labels = { current: 'Aggiornato', 'update-available': 'Aggiornamento disponibile', unsupported: 'Aggiornamento non supportato', unavailable: 'Versione non verificabile', 'not-installed': 'Non installato', queued: 'In coda', running: 'In corso', succeeded: 'Operazione completata', failed: 'Operazione non riuscita', 'rolled-back': 'Versione precedente ripristinata', completed: 'Operazione completata', rolled_back: 'Versione precedente ripristinata', rollback_failed: 'Ripristino non riuscito', interrupted: 'Operazione interrotta' };
  function text(value, fallback) { return typeof value === 'string' && value.trim() ? value : fallback; }
  function element(tag, value) { var node = document.createElement(tag); if (value !== undefined) node.textContent = value; return node; }
  function operationId(value) { return value && (value.operationId || value.id || value.operation && value.operation.id); }
  function mount(root) {
    if (mounted.has(root)) return;
    mounted.add(root);
    var select = function (selector) { return root.querySelector(selector); };
    var state = { value: null, operation: null, busy: false, timer: null, generation: 0, dialogGeneration: 0, plan: null, component: null, applying: false, stopped: false };
    var list = select('[data-updates-list]'), status = select('[data-updates-status]'), check = select('[data-updates-check]'), refresh = select('[data-updates-refresh]');
    var dialog = select('[data-updates-dialog]'), confirm = select('[data-updates-confirm]'), apply = select('[data-updates-apply]'), planStatus = select('[data-updates-plan-status]');
    function alive(generation) { return !state.stopped && root.isConnected && generation === state.generation; }
    function request(path, payload) {
      var bridge = window.controlCenterRuntimeUpdates;
      if (!bridge || typeof bridge.request !== 'function') return Promise.reject(Error('Collegamento al server non disponibile. Ricarica la pagina.'));
      return bridge.request(path, payload);
    }
    async function authenticate() {
      var bridge = window.controlCenterRuntimeUpdates;
      if (!bridge || typeof bridge.authenticate !== 'function') throw Error('Conferma passkey non disponibile.');
      await bridge.authenticate();
    }
    function updateApply() {
      var plan = state.plan;
      apply.disabled = state.applying || !plan || confirm.value !== 'UPDATE' || plan.confirmationRequired !== 'UPDATE' || !Number.isFinite(Date.parse(plan.expiresAt)) || Date.parse(plan.expiresAt) <= Date.now();
    }
    function render() {
      if (!root.isConnected) return;
      var value = state.value, components = value && Array.isArray(value.components) ? value.components : [];
      var operation = state.operation, working = Boolean(state.busy || pending(operation));
      check.disabled = !value || value.available !== true || value.canCheck === false || working;
      refresh.disabled = state.busy;
      root.setAttribute('aria-busy', working ? 'true' : 'false');
      select('[data-updates-summary]').textContent = components.length + ' componenti · ' + components.filter(function (item) { return item.status === 'update-available'; }).length + ' aggiornamenti disponibili' + (value && value.checkedAt ? ' · Verifica: ' + new Date(value.checkedAt).toLocaleString('it-IT') : ' · Versioni stabili non ancora verificate');
      var progressBox = select('[data-updates-progress]'), progress = progressBox.querySelector('progress');
      progressBox.hidden = !working;
      var total = operation && operation.totalSteps, completed = operation && operation.completedSteps;
      if (Number.isFinite(total) && total > 0 && Number.isFinite(completed) && completed >= 0 && completed <= total) { progress.max = total; progress.value = completed; }
      else progress.removeAttribute('value');
      select('[data-updates-stage]').textContent = operation ? text(operation.stage, labels[operation.status] || 'Verifica in corso…') : 'Verifica in corso…';
      var query = select('[data-updates-search]').value.trim().toLocaleLowerCase('it'), category = select('[data-updates-category]').value;
      list.replaceChildren(); var count = 0;
      components.forEach(function (item) {
        if (category !== 'all' && item.category !== category || !(String(item.label || '') + ' ' + item.id + ' ' + (item.services || []).join(' ')).toLocaleLowerCase('it').includes(query)) return;
        count++;
        var row = element('article'); row.className = 'cc-update-row';
        var name = element('div'); name.append(element('strong', text(item.label, item.id)), element('small', text(item.category, 'Componente'))); row.append(name);
        var current = element('div'); current.append(element('small', 'In esecuzione'), element('strong', item.installed === false ? 'Non installato' : text(item.current && item.current.version, 'Non verificata'))); row.append(current);
        var latest = element('div'); latest.append(element('small', 'Ultima stabile'), element('strong', text(item.latestStable && item.latestStable.version, 'Non disponibile'))); row.append(latest);
        var button = element('button', 'Rivedi aggiornamento'); button.type = 'button'; button.className = 'ops-button secondary compact';
        button.disabled = working || value.available !== true || value.canApply === false || !item.canUpdate || item.installed === false || item.status !== 'update-available' || !item.candidateRelease || !item.candidateRelease.imageDigest;
        button.addEventListener('click', function () { openPlan(item); }); row.append(button);
        if (item.candidateRelease && item.latestStable && item.candidateRelease.version !== item.latestStable.version) row.append(element('p', 'Aggiornamento compatibile: ' + item.candidateRelease.version + ' · Ultima stabile: ' + item.latestStable.version + (item.compatibilityReason ? ' · ' + item.compatibilityReason : ' · La versione stabile più recente richiede una migrazione.')));
        row.append(element('p', (labels[item.status] || 'Stato non disponibile') + (item.blockedReason ? ' · ' + item.blockedReason : item.installed !== false && !item.candidateRelease && item.status !== 'current' ? ' · Nessun aggiornamento compatibile verificato.' : '') + ((item.services || []).length ? ' · Servizi: ' + item.services.join(', ') : '')));
        list.append(row);
      });
      select('[data-updates-empty]').hidden = count > 0;
      updateApply();
    }
    function schedule() {
      clearTimeout(state.timer);
      if (!state.stopped && root.isConnected && !document.hidden) state.timer = setTimeout(load, pending(state.operation) ? 2000 : 30000);
    }
    async function load() {
      if (state.stopped || !root.isConnected || document.hidden || state.busy) return;
      var generation = state.generation; state.busy = true; render();
      try {
        if (pending(state.operation)) {
          var operation = await request('/control/runtime-updates/operations/' + encodeURIComponent(state.operation.id));
          if (!alive(generation)) return;
          state.operation = operation.operation || operation;
          status.textContent = text(state.operation.error && (state.operation.error.message || state.operation.error), labels[state.operation.status] || 'Stato operazione non disponibile');
        }
        var value = await request('/control/runtime-updates');
        if (!alive(generation)) return;
        state.value = value;
        if (!pending(state.operation)) state.operation = (value.operations || []).find(pending) || state.operation;
        var category = select('[data-updates-category]'), selected = category.value;
        category.replaceChildren(); var all = element('option', 'Tutte le categorie'); all.value = 'all'; category.append(all);
        Array.from(new Set((value.components || []).map(function (item) { return item.category; }).filter(Boolean))).sort().forEach(function (name) { var option = element('option', name); option.value = name; category.append(option); });
        category.value = Array.from(category.options).some(function (option) { return option.value === selected; }) ? selected : 'all';
        if (value.available !== true) status.textContent = text(value.unavailableReason, 'Aggiornamenti non disponibili su questo server.');
        else if (!state.operation) status.textContent = 'Le versioni installate sono confermate dal server.';
      } catch (error) { if (alive(generation)) { status.textContent = text(error.message, 'Impossibile verificare gli aggiornamenti.'); if (state.value) state.value.available = false; } }
      finally { if (alive(generation)) { state.busy = false; render(); schedule(); } }
    }
    function acceptOperation(value) {
      var id = operationId(value); if (!id) throw Error('Il server non ha restituito un identificativo operazione.');
      state.operation = { id: id, status: value.status || 'queued', stage: value.stage || 'In coda' };
      status.textContent = 'Richiesta accettata. In attesa della verifica del server.';
    }
    check.addEventListener('click', async function () {
      if (check.disabled) return; var generation = state.generation; state.busy = true; clearTimeout(state.timer); render();
      try { var value = await request('/control/runtime-updates/check', {}); if (alive(generation)) acceptOperation(value); }
      catch (error) { if (alive(generation)) status.textContent = error.message; }
      finally { if (alive(generation)) { state.busy = false; render(); schedule(); } }
    });
    function close() { if (state.applying) return; state.dialogGeneration++; state.plan = null; state.component = null; confirm.value = ''; updateApply(); if (dialog.open) dialog.close(); }
    async function openPlan(item) {
      if (state.busy || pending(state.operation)) return;
      var generation = state.generation, dialogGeneration = ++state.dialogGeneration;
      state.plan = null; state.component = item; confirm.value = ''; select('[data-updates-confirm-label]').hidden = true;
      select('[data-updates-plan-details]').replaceChildren(); planStatus.textContent = 'Conferma la tua identità per preparare il piano…'; updateApply(); dialog.showModal();
      try {
        await authenticate();
        if (!alive(generation) || dialogGeneration !== state.dialogGeneration || !dialog.open) return;
        var value = await request('/control/runtime-updates/' + encodeURIComponent(item.id) + '/plan', { revision: state.value.revision });
        if (!alive(generation) || dialogGeneration !== state.dialogGeneration || !dialog.open) return;
        var plan = value.plan || value;
        if (!plan.planId || !plan.targetVersion || !plan.targetDigest || plan.confirmationRequired !== 'UPDATE') throw Error('Piano di aggiornamento non valido.');
        state.plan = plan; state.idempotencyKey = crypto.randomUUID();
        var details = select('[data-updates-plan-details]');
        details.append(element('p', item.label + ': ' + text(item.current && item.current.version, 'Non verificata') + ' → ' + plan.targetVersion));
        details.append(element('p', 'Servizi interessati: ' + (plan.affectedServices || []).join(', ')));
        ['steps', 'risks'].forEach(function (key) { details.append(element('h3', key === 'steps' ? 'Passaggi' : 'Impatto e rischi')); var ul = element('ul'); (plan[key] || []).forEach(function (entry) { ul.append(element('li', typeof entry === 'string' ? entry : text(entry.label || entry.description, 'Passaggio'))); }); details.append(ul); });
        select('[data-updates-confirm-label]').hidden = false; planStatus.textContent = 'Rivedi il piano prima di confermare.'; updateApply();
      } catch (error) { if (alive(generation) && dialogGeneration === state.dialogGeneration && dialog.open) planStatus.textContent = error.message; }
    }
    apply.addEventListener('click', async function () {
      updateApply(); if (apply.disabled) return;
      var generation = state.generation, dialogGeneration = state.dialogGeneration, plan = state.plan, item = state.component;
      state.applying = true; updateApply();
      try {
        await authenticate();
        if (!alive(generation) || dialogGeneration !== state.dialogGeneration || !dialog.open) return;
        if (Date.parse(plan.expiresAt) <= Date.now()) throw Error('Piano scaduto. Chiudi e prepara un nuovo piano.');
        var value = await request('/control/runtime-updates/' + encodeURIComponent(item.id) + '/apply', { revision: plan.revision, planId: plan.planId, confirmation: 'UPDATE', idempotencyKey: state.idempotencyKey });
        if (!alive(generation) || dialogGeneration !== state.dialogGeneration) return;
        acceptOperation(value); state.applying = false; close(); render(); schedule();
      } catch (error) { if (alive(generation)) planStatus.textContent = error.message; }
      finally { if (alive(generation)) { state.applying = false; updateApply(); } }
    });
    confirm.addEventListener('input', updateApply);
    select('[data-updates-close]').addEventListener('click', close);
    dialog.addEventListener('cancel', function (event) { event.preventDefault(); close(); });
    refresh.addEventListener('click', load);
    select('[data-updates-search]').addEventListener('input', render);
    select('[data-updates-category]').addEventListener('change', render);
    var lifecycle = { root: root, stop: function () { state.stopped = true; state.generation++; state.dialogGeneration++; clearTimeout(state.timer); state.plan = null; if (dialog.open) dialog.close(); }, resume: load, pause: function () { clearTimeout(state.timer); } };
    active.add(lifecycle); load();
  }
  function scan() { active.forEach(function (entry) { if (!entry.root.isConnected) { entry.stop(); active.delete(entry); } }); document.querySelectorAll('[data-runtime-updates]').forEach(mount); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', scan); else scan();
  if (window.MutationObserver) new MutationObserver(scan).observe(document.body, { childList: true, subtree: true });
  document.addEventListener('visibilitychange', function () { active.forEach(function (entry) { if (document.hidden) entry.pause(); else entry.resume(); }); });
  window.addEventListener('pagehide', function () { active.forEach(function (entry) { entry.stop(); }); active.clear(); });
})();
