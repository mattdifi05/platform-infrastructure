(function () {
  'use strict';
  var mounted = new WeakSet(), active = new Set();
  var terminal = function (operation) { return operation && ['succeeded', 'completed', 'failed', 'rolled-back', 'rolled_back', 'rollback_failed', 'interrupted', 'skipped'].includes(operation.status); };
  var pending = function (operation) { return Boolean(operation && !terminal(operation)); };
  var labels = { current: 'Aggiornato', 'update-available': 'Aggiornamento disponibile', unsupported: 'Aggiornamento non supportato', unavailable: 'Versione non verificabile', 'not-installed': 'Non installato', queued: 'In coda', running: 'In corso', succeeded: 'Operazione completata', failed: 'Operazione non riuscita', 'rolled-back': 'Versione precedente ripristinata', completed: 'Operazione completata', rolled_back: 'Versione precedente ripristinata', rollback_failed: 'Ripristino non riuscito', interrupted: 'Operazione interrotta' };
  function text(value, fallback) { return typeof value === 'string' && value.trim() ? value : fallback; }
  var serviceLabels = { queued: 'In attesa', checking: 'Verifica', preparing: 'Preparazione', updating: 'Aggiornamento', verifying: 'Verifica del servizio', verified: 'Verificato', succeeded: 'Completato', 'rolled-back': 'Ripristinato', rolled_back: 'Ripristinato', failed: 'Non riuscito', skipped: 'Non eseguito' };
  function updatable(item) { return Boolean(item && item.installed !== false && item.canUpdate && item.status === 'update-available' && item.candidateRelease && item.candidateRelease.imageDigest); }
  function currentVersion(item) {
    if (item.installed === false) return 'Non installato';
    var versions = item.current && Array.isArray(item.current.versions) ? Array.from(new Set(item.current.versions.filter(function (version) { return typeof version === 'string' && version.trim(); }))) : [];
    if (item.needsAlignment && versions.length > 1) return 'Da uniformare: ' + versions.join(' / ');
    return text(item.current && item.current.version, versions.length === 1 ? versions[0] : 'Non verificata');
  }
  function element(tag, value) { var node = document.createElement(tag); if (value !== undefined) node.textContent = value; return node; }
  function operationId(value) { return value && (value.operationId || value.id || value.operation && value.operation.id); }
  function mount(root) {
    if (mounted.has(root)) return;
    mounted.add(root);
    var select = function (selector) { return root.querySelector(selector); };
    var state = { value: null, operation: null, busy: false, loading: false, timer: null, generation: 0, dialogGeneration: 0, plan: null, component: null, applying: false, stopped: false };
    var list = select('[data-updates-list]'), status = select('[data-updates-status]'), check = select('[data-updates-check]'), refresh = select('[data-updates-refresh]');
    var dialog = select('[data-updates-dialog]'), confirm = select('[data-updates-confirm]'), apply = select('[data-updates-apply]'), planStatus = select('[data-updates-plan-status]');
    var updateAll = select('[data-updates-all]');
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
      updateAll.disabled = !value || value.available !== true || value.canApply === false || working || !components.some(updatable);
      refresh.disabled = state.busy;
      root.setAttribute('aria-busy', working ? 'true' : 'false');
      var updateCount = components.filter(function (item) { return item.status === 'update-available'; }).length;
      select('[data-updates-summary]').textContent = components.length + (components.length === 1 ? ' componente · ' : ' componenti · ') + updateCount + (updateCount === 1 ? ' aggiornamento disponibile' : ' aggiornamenti disponibili') + (value && value.checkedAt ? ' · Verifica: ' + new Date(value.checkedAt).toLocaleString('it-IT') : ' · Versioni stabili non ancora verificate');
      var progressBox = select('[data-updates-progress]'), progress = progressBox.querySelector('progress');
      progressBox.hidden = !working && !operation;
      var total = operation && operation.totalServices, completed = operation && operation.completedServices;
      var successful = operation && ['succeeded', 'completed'].includes(operation.status);
      if (Number.isSafeInteger(total) && total > 0 && Number.isSafeInteger(completed) && completed >= 0 && completed <= total && (completed < total || successful)) { progress.max = total; progress.value = completed; }
      else progress.removeAttribute('value');
      select('[data-updates-stage]').textContent = operation ? text(operation.stage, serviceLabels[operation.status] || labels[operation.status] || 'Operazione in corso…') + (operation.currentService ? ' · ' + operation.currentService : operation.currentComponent ? ' · ' + operation.currentComponent : '') + (Number.isSafeInteger(total) && total > 0 && Number.isSafeInteger(completed) ? ' · ' + completed + ' di ' + total + ' servizi' : '') : 'Verifica in corso…';
      var services = select('[data-updates-services]'); services.replaceChildren();
      (operation && Array.isArray(operation.serviceResults) ? operation.serviceResults : []).forEach(function (service) {
        var row = element('li'); row.className = 'cc-update-service'; row.setAttribute('data-service-status', service.status || 'queued');
        row.append(element('strong', text(service.service, 'Servizio')), element('span', serviceLabels[service.status] || labels[service.status] || 'Stato non disponibile'));
        if (service.stage) row.append(element('small', service.stage));
        services.append(row);
      });
      var category = select('[data-updates-category]').value;
      list.replaceChildren(); var count = 0;
      components.slice().sort(function (a, b) { return Number(updatable(b)) - Number(updatable(a)); }).forEach(function (item) {
        if (category !== 'all' && item.category !== category) return;
        count++;
        var row = element('article'); row.className = 'cc-update-row';
        var name = element('div'); name.append(element('strong', text(item.label, item.id)), element('small', text(item.category, 'Componente'))); row.append(name);
        var current = element('div'); current.append(element('small', 'Versione installata'), element('strong', currentVersion(item))); row.append(current);
        var latest = element('div'); latest.append(element('small', 'Ultima stabile'), element('strong', text(item.latestStable && item.latestStable.version, 'Non disponibile'))); row.append(latest);
        var button = element('button', 'Aggiorna'); button.type = 'button'; button.className = 'ops-button secondary compact';
        button.disabled = working || value.available !== true || value.canApply === false || !updatable(item);
        button.addEventListener('click', function () { openPlan(item); }); row.append(button);
        if (item.candidateRelease && item.candidateRelease.version && item.latestStable && item.latestStable.version && item.candidateRelease.version !== item.latestStable.version) row.append(element('p', 'Aggiornamento compatibile: ' + item.candidateRelease.version + ' · Ultima stabile: ' + item.latestStable.version + (item.compatibilityReason ? ' · ' + item.compatibilityReason : ' · La serie più recente richiede una verifica di compatibilità.')));
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
      if (state.stopped || !root.isConnected || document.hidden || state.busy || state.loading) return;
      var generation = state.generation; state.loading = true;
      try {
        if (pending(state.operation)) {
          var operation = await request('/control/runtime-updates/operations/' + encodeURIComponent(state.operation.id));
          if (!alive(generation)) return;
          state.operation = operation.operation || operation;
          status.textContent = text(state.operation.error && (state.operation.error.message || state.operation.error), labels[state.operation.status] || serviceLabels[state.operation.status] || 'Operazione in corso…');
          if (pending(state.operation)) return;
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
      } catch (error) { if (alive(generation)) status.textContent = pending(state.operation) ? 'Connessione temporaneamente interrotta. Riconnessione automatica; verifica dell’operazione in corso…' : text(error.message, 'Impossibile verificare gli aggiornamenti.'); }
      finally { if (alive(generation)) { state.loading = false; render(); schedule(); } }
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
    updateAll.addEventListener('click', function () { if (!updateAll.disabled) openPlan({ id: 'all', label: 'Tutti i componenti aggiornabili' }); });
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
        if (item.id === 'all' && (plan.kind !== 'batch' || !Array.isArray(plan.components) || !plan.components.length)) throw Error('Piano di aggiornamento completo non disponibile.');
        state.plan = plan; state.idempotencyKey = crypto.randomUUID();
        var details = select('[data-updates-plan-details]');
        apply.textContent = item.id === 'all' ? 'Aggiorna tutto' : 'Aggiorna componente';
        if (item.id === 'all') {
          details.append(element('p', 'Il piano aggiorna i componenti elencati alle versioni stabili indicate.'));
          var targets = element('ul');
          plan.components.forEach(function (component) { targets.append(element('li', text(component.label, component.id) + ' → ' + component.targetVersion + ' · ' + (component.affectedServices || []).join(', '))); }); details.append(targets);
        } else details.append(element('p', item.label + ': ' + currentVersion(item) + ' → ' + plan.targetVersion));
        details.append(element('p', 'Servizi interessati: ' + (plan.affectedServices || []).join(', ')));
        if (item.needsAlignment || (item.current && Array.isArray(item.current.versions))) details.append(element('p', 'Versione unica per tutti i servizi elencati.'));
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
    select('[data-updates-category]').addEventListener('change', render);
    var lifecycle = { root: root, stop: function () { state.stopped = true; state.generation++; state.dialogGeneration++; clearTimeout(state.timer); state.plan = null; if (dialog.open) dialog.close(); }, resume: load, pause: function () { clearTimeout(state.timer); } };
    active.add(lifecycle); load();
  }
  function mountHost(root) {
    if (mounted.has(root)) return;
    mounted.add(root);
    var select = function (name) { return root.querySelector('[data-host-updates-' + name + ']'); };
    var state = { value: null, operation: null, busy: false, loading: false, stopped: false, timer: null, generation: 0, review: 0, plan: null, applying: false };
    var status = select('status'), dialog = select('dialog'), confirm = select('confirm'), apply = select('apply'), check = select('check'), upgrade = select('upgrade'), reboot = select('reboot');
    function alive(generation) { return !state.stopped && root.isConnected && generation === state.generation; }
    function request(path, payload) { var bridge = window.controlCenterRuntimeUpdates; return bridge && typeof bridge.request === 'function' ? bridge.request(path, payload) : Promise.reject(Error('Collegamento al server non disponibile.')); }
    async function authenticate() { var bridge = window.controlCenterRuntimeUpdates; if (!bridge || typeof bridge.authenticate !== 'function') throw Error('Conferma passkey non disponibile.'); await bridge.authenticate(); }
    function updateApply() { var plan = state.plan; apply.disabled = state.applying || !plan || confirm.value !== plan.confirmationRequired || !Number.isFinite(Date.parse(plan.expiresAt)) || Date.parse(plan.expiresAt) <= Date.now(); }
    function render() {
      if (!root.isConnected) return;
      var value = state.value, working = state.busy || pending(state.operation), available = value && value.available === true;
      check.disabled = Boolean(working || available && value.canCheck === false);
      upgrade.disabled = !available || value.canApply === false || !(Number.isSafeInteger(value.updateCount) && value.updateCount > 0) || working;
      reboot.hidden = !available || value.rebootRequired !== true;
      reboot.disabled = !available || value.canReboot === false || value.rebootRequired !== true || working;
      root.setAttribute('aria-busy', working ? 'true' : 'false');
      select('os').textContent = value && value.os ? [text(value.os.name, value.os.id), value.os.version].filter(Boolean).join(' ') : 'Sistema non disponibile';
      select('summary').textContent = value ? (value.checkedAt ? (Number.isSafeInteger(value.updateCount) ? value.updateCount : 0) + ' aggiornamenti disponibili' + (Number.isSafeInteger(value.keptBackCount) && value.keptBackCount > 0 ? ' · ' + value.keptBackCount + ' mantenuti alla versione attuale' : '') + ' · Verifica: ' + new Date(value.checkedAt).toLocaleString('it-IT') : 'Aggiornamenti non ancora verificati') + (value.rebootRequired ? ' · Riavvio richiesto' : '') : '';
      var box = select('progress'), progress = box.querySelector('progress'), operation = state.operation;
      box.hidden = !working && !operation;
      var total = operation && operation.totalSteps, completed = operation && operation.completedSteps;
      if (Number.isSafeInteger(total) && total > 0 && Number.isSafeInteger(completed) && completed >= 0 && completed <= total && (completed < total || ['succeeded', 'completed'].includes(operation.status))) { progress.max = total; progress.value = completed; } else progress.removeAttribute('value');
      select('stage').textContent = operation ? text(operation.stage, labels[operation.status] || serviceLabels[operation.status] || 'Manutenzione in corso…') : 'Preparazione…';
      updateApply();
    }
    function schedule() { clearTimeout(state.timer); if (pending(state.operation) && !state.stopped && root.isConnected && !document.hidden) state.timer = setTimeout(load, 2000); }
    async function load() {
      if (state.stopped || !root.isConnected || document.hidden || state.loading || state.busy) return;
      var generation = state.generation; state.loading = true;
      try {
        if (pending(state.operation)) {
          var operation = await request('/control/runtime-updates/operations/' + encodeURIComponent(state.operation.id));
          if (!alive(generation)) return; state.operation = operation.operation || operation;
          status.textContent = text(state.operation.error && (state.operation.error.message || state.operation.error), labels[state.operation.status] || serviceLabels[state.operation.status] || 'Manutenzione in corso…');
          if (pending(state.operation)) return;
        }
        var value = await request('/control/runtime-updates/system');
        if (!alive(generation)) return; state.value = value;
        if (!pending(state.operation)) state.operation = (value.operations || []).find(pending) || state.operation;
        if (!value.available) status.textContent = text(value.unavailableReason, 'Gestione del sistema non disponibile su questo server.');
        else if (!state.operation) status.textContent = 'La manutenzione del sistema richiede una conferma esplicita.';
      } catch (error) { if (alive(generation)) status.textContent = pending(state.operation) ? 'Server temporaneamente non raggiungibile. Riconnessione automatica dopo la manutenzione o il riavvio…' : text(error.message, 'Impossibile verificare il sistema.'); }
      finally { if (alive(generation)) { state.loading = false; render(); schedule(); } }
    }
    function accept(value) { var id = operationId(value); if (!id) throw Error('Il server non ha restituito un identificativo operazione.'); state.operation = { id: id, status: value.status || 'queued', stage: 'In coda' }; status.textContent = 'Richiesta accettata. In attesa della verifica del server.'; }
    check.addEventListener('click', async function () {
      if (check.disabled) return; if (!state.value || !state.value.available) { load(); return; } var generation = state.generation; state.busy = true; render();
      try { var value = await request('/control/runtime-updates/system/check', {}); if (alive(generation)) accept(value); }
      catch (error) { if (alive(generation)) status.textContent = error.message; }
      finally { if (alive(generation)) { state.busy = false; render(); schedule(); } }
    });
    function close() { if (state.applying) return; state.review++; state.plan = null; confirm.value = ''; updateApply(); if (dialog.open) dialog.close(); }
    async function review(rebooting) {
      if (state.busy || pending(state.operation)) return;
      var generation = state.generation, review = ++state.review, expected = rebooting ? 'REBOOT' : 'UPDATE';
      state.plan = null; state.rebooting = rebooting; confirm.value = ''; select('confirm-label').hidden = true; select('plan-details').replaceChildren();
      select('review-title').textContent = rebooting ? 'Rivedi riavvio del server' : 'Rivedi aggiornamento del sistema';
      select('plan-status').textContent = 'Conferma la tua identità per preparare il piano…'; updateApply(); dialog.showModal();
      try {
        await authenticate(); if (!alive(generation) || review !== state.review || !dialog.open) return;
        var value = await request('/control/runtime-updates/system/' + (rebooting ? 'reboot/' : '') + 'plan', { revision: state.value.revision });
        if (!alive(generation) || review !== state.review || !dialog.open) return;
        var plan = value.plan || value;
        if (!plan.planId || !plan.revision || plan.kind !== (rebooting ? 'host-reboot' : 'host-upgrade') || plan.confirmationRequired !== expected) throw Error('Piano di manutenzione non valido.');
        state.plan = plan; state.idempotencyKey = crypto.randomUUID();
        var details = select('plan-details');
        if (!rebooting) details.append(element('p', (Number.isSafeInteger(plan.packageCount) ? plan.packageCount : 0) + ' pacchetti previsti dal piano verificato.'));
        ['steps', 'risks'].forEach(function (key) { details.append(element('h3', key === 'steps' ? 'Passaggi' : 'Impatto e rischi')); var list = element('ul'); (plan[key] || []).forEach(function (item) { list.append(element('li', typeof item === 'string' ? item : text(item.label || item.description, 'Passaggio'))); }); details.append(list); });
        select('confirm-prompt').textContent = 'Scrivi ' + expected + ' per confermare'; select('confirm-label').hidden = false;
        select('plan-status').textContent = rebooting ? 'Il portale sarà temporaneamente non raggiungibile durante il riavvio.' : 'Rivedi i pacchetti e l’impatto prima di aggiornare.';
        apply.textContent = rebooting ? 'Riavvia server' : 'Aggiorna sistema'; updateApply();
      } catch (error) { if (alive(generation) && review === state.review && dialog.open) select('plan-status').textContent = error.message; }
    }
    upgrade.addEventListener('click', function () { if (!upgrade.disabled) review(false); }); reboot.addEventListener('click', function () { if (!reboot.disabled) review(true); });
    apply.addEventListener('click', async function () {
      updateApply(); if (apply.disabled) return; var generation = state.generation, review = state.review, plan = state.plan, rebooting = state.rebooting; state.applying = true; updateApply();
      try {
        await authenticate(); if (!alive(generation) || review !== state.review || !dialog.open) return;
        if (Date.parse(plan.expiresAt) <= Date.now()) throw Error('Piano scaduto. Prepara un nuovo piano.');
        var value = await request('/control/runtime-updates/system/' + (rebooting ? 'reboot/' : '') + 'apply', { revision: plan.revision, planId: plan.planId, confirmation: plan.confirmationRequired, idempotencyKey: state.idempotencyKey });
        if (!alive(generation) || review !== state.review) return; accept(value); state.applying = false; close(); render(); schedule();
      } catch (error) { if (alive(generation)) select('plan-status').textContent = error.message; }
      finally { if (alive(generation)) { state.applying = false; updateApply(); } }
    });
    confirm.addEventListener('input', updateApply); select('close').addEventListener('click', close); dialog.addEventListener('cancel', function (event) { event.preventDefault(); close(); });
    active.add({ root: root, stop: function () { state.stopped = true; state.generation++; state.review++; clearTimeout(state.timer); if (dialog.open) dialog.close(); }, resume: function () { if (pending(state.operation)) load(); }, pause: function () { clearTimeout(state.timer); } }); load();
  }
  function scan() { active.forEach(function (entry) { if (!entry.root.isConnected) { entry.stop(); active.delete(entry); } }); document.querySelectorAll('[data-runtime-updates]').forEach(mount); document.querySelectorAll('[data-host-updates]').forEach(mountHost); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', scan); else scan();
  if (window.MutationObserver) new MutationObserver(scan).observe(document.body, { childList: true, subtree: true });
  document.addEventListener('visibilitychange', function () { active.forEach(function (entry) { if (document.hidden) entry.pause(); else entry.resume(); }); });
  window.addEventListener('pagehide', function () { active.forEach(function (entry) { entry.stop(); }); active.clear(); });
})();
