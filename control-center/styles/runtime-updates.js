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
  var motions = new WeakMap(), visibilityGenerations = new WeakMap();
  function reducedMotion() { return !window.matchMedia || window.matchMedia('(prefers-reduced-motion: reduce)').matches; }
  function animate(node, frames, duration) {
    var previous = motions.get(node); if (previous) previous.cancel();
    if (reducedMotion() || !node.animate) return null;
    var animation = node.animate(frames, { duration: duration || 200, easing: 'cubic-bezier(.22,1,.36,1)' }); motions.set(node, animation);
    animation.finished.then(function () { if (motions.get(node) === animation) motions.delete(node); }, function () {}); return animation;
  }
  function setText(node, value) { if (node.textContent !== value) node.textContent = value; }
  function setProgress(progress, total, completed, successful) {
    var measured = Number.isSafeInteger(total) && total > 0 && Number.isSafeInteger(completed) && completed >= 0 && completed <= total && (completed < total || successful);
    if (measured) { progress.max = total; progress.value = completed; } else progress.removeAttribute('value');
    // The native element keeps the exact verified value for assistive tools.
    // Only the decorative fill interpolates visually between server targets.
    var track = progress.parentElement, fill = track && track.querySelector('[data-progress-fill]');
    if (fill) { track.setAttribute('data-progress-state', measured ? 'measured' : 'indeterminate'); fill.style.transform = measured ? 'scaleX(' + completed / total + ')' : ''; }
  }
  function panelVisible(node, visible) {
    if (node.hidden === !visible) return;
    var generation = (visibilityGenerations.get(node) || 0) + 1; visibilityGenerations.set(node, generation);
    if (visible) { node.hidden = false; animate(node, [{ opacity: 0, height: '0px' }, { opacity: 1, height: node.scrollHeight + 'px' }]); }
    else { var animation = animate(node, [{ opacity: 1, height: node.scrollHeight + 'px' }, { opacity: 0, height: '0px' }], 140); if (animation) animation.finished.then(function () { if (visibilityGenerations.get(node) === generation) node.hidden = true; }, function () {}); else node.hidden = true; }
  }
  function openDialog(dialog) { visibilityGenerations.set(dialog, (visibilityGenerations.get(dialog) || 0) + 1); if (!dialog.open) dialog.showModal(); animate(dialog, [{ opacity: 0, transform: 'translateY(8px) scale(.985)' }, { opacity: 1, transform: 'translateY(0) scale(1)' }]); }
  function closeDialog(dialog) {
    var generation = (visibilityGenerations.get(dialog) || 0) + 1; visibilityGenerations.set(dialog, generation);
    if (!dialog.open) return;
    var animation = animate(dialog, [{ opacity: 1, transform: 'translateY(0)' }, { opacity: 0, transform: 'translateY(5px)' }], 130);
    if (animation) animation.finished.then(function () { if (visibilityGenerations.get(dialog) === generation && dialog.open) dialog.close(); }, function () {}); else dialog.close();
  }
  function reconcile(container, records, views, keyFor, create, update) {
    var before = new Map(), present = new Set();
    views.forEach(function (view, key) { if (view.row.getBoundingClientRect) before.set(key, view.row.getBoundingClientRect().top); });
    records.forEach(function (record, index) {
      var key = keyFor(record); present.add(key); var view = views.get(key), fresh = !view;
      if (!view) { view = create(record); views.set(key, view); }
      update(view, record);
      if (container.children[index] !== view.row) container.insertBefore(view.row, container.children[index] || null);
      if (fresh) animate(view.row, [{ opacity: 0, transform: 'translateY(4px)' }, { opacity: 1, transform: 'translateY(0)' }]);
      else if (before.has(key) && view.row.getBoundingClientRect) { var delta = before.get(key) - view.row.getBoundingClientRect().top; if (Math.abs(delta) > 1) animate(view.row, [{ transform: 'translateY(' + delta + 'px)' }, { transform: 'translateY(0)' }]); }
    });
    views.forEach(function (view, key) { if (!present.has(key)) { view.row.remove(); views.delete(key); } });
  }
  function operationId(value) { return value && (value.operationId || value.id || value.operation && value.operation.id); }
  function mount(root) {
    if (mounted.has(root)) return;
    mounted.add(root);
    var select = function (selector) { return root.querySelector(selector); };
    var state = { value: null, operation: null, busy: false, loading: false, timer: null, generation: 0, dialogGeneration: 0, plan: null, component: null, applying: false, stopped: false };
    var list = select('[data-updates-list]'), status = select('[data-updates-status]'), check = select('[data-updates-check]'), refresh = select('[data-updates-refresh]');
    var dialog = select('[data-updates-dialog]'), confirm = select('[data-updates-confirm]'), apply = select('[data-updates-apply]'), planStatus = select('[data-updates-plan-status]');
    var updateAll = select('[data-updates-all]');
    var componentViews = new Map(), serviceViews = new Map(), resultsOperation = null, resultsPending = null;
    select('[data-updates-results]').addEventListener('toggle', function () { if (this.open) { var services = select('[data-updates-services]'); animate(services, [{ opacity: 0, height: '0px' }, { opacity: 1, height: services.scrollHeight + 'px' }]); } });
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
      panelVisible(progressBox, working || Boolean(operation));
      var total = operation && operation.totalServices, completed = operation && operation.completedServices;
      var barTotal = Number.isSafeInteger(total) && total > 0 ? total : operation && operation.totalSteps;
      var barCompleted = Number.isSafeInteger(total) && total > 0 ? completed : operation && operation.completedSteps;
      var successful = operation && ['succeeded', 'completed'].includes(operation.status);
      setProgress(progress, barTotal, barCompleted, successful);
      select('[data-updates-stage]').textContent = operation ? text(operation.stage, serviceLabels[operation.status] || labels[operation.status] || 'Operazione in corso…') + (operation.currentService ? ' · ' + operation.currentService : operation.currentComponent ? ' · ' + operation.currentComponent : '') + (Number.isSafeInteger(total) && total > 0 && Number.isSafeInteger(completed) ? ' · ' + completed + ' di ' + total + ' servizi' : '') : 'Verifica in corso…';
      var services = operation && Array.isArray(operation.serviceResults) ? operation.serviceResults : [];
      reconcile(select('[data-updates-services]'), services, serviceViews, function (service) { return service.componentId + ':' + service.service; }, function () {
        var row = element('li'), name = element('strong'), status = element('span'), stage = element('small'); row.className = 'cc-update-service'; row.append(name, status, stage); return { row: row, name: name, status: status, stage: stage };
      }, function (view, service) {
        var changed = view.phase !== service.status; view.row.setAttribute('data-service-status', service.status || 'queued'); setText(view.name, text(service.service, 'Servizio')); setText(view.status, serviceLabels[service.status] || labels[service.status] || 'Stato non disponibile'); setText(view.stage, text(service.stage, '')); view.stage.hidden = !service.stage;
        if (view.phase && changed) animate(view.status, [{ opacity: .35 }, { opacity: 1 }], 180); view.phase = service.status;
      });
      var results = select('[data-updates-results]'); results.hidden = !services.length;
      setText(select('[data-updates-results-summary]'), services.length + ' servizi · Dettagli');
      if (operation && (resultsOperation !== operation.id || resultsPending !== pending(operation))) { results.open = pending(operation) || !successful; resultsOperation = operation.id; resultsPending = pending(operation); }
      reconcile(list, components.slice().sort(function (a, b) { return Number(updatable(b)) - Number(updatable(a)); }), componentViews, function (item) { return item.id; }, function (item) {
        var row = element('article'); row.className = 'cc-update-row'; row.setAttribute('data-update-id', item.id);
        var name = element('div'), title = element('strong'), badge = element('small'); name.append(title, badge);
        var current = element('div'), currentValue = element('strong'); current.className = 'cc-update-current'; current.append(element('small', 'Installata'), currentValue);
        var latest = element('div'), latestValue = element('strong'); latest.className = 'cc-update-latest'; latest.append(element('small', 'Stabile'), latestValue);
        var button = element('button', 'Aggiorna'); button.type = 'button'; button.className = 'ops-button secondary compact';
        var details = element('details'), summary = element('summary', 'Dettagli'), reason = element('p'); details.className = 'cc-update-detail'; details.append(summary, reason);
        details.addEventListener('toggle', function () { if (details.open) animate(reason, [{ opacity: 0, height: '0px' }, { opacity: 1, height: reason.scrollHeight + 'px' }]); });
        row.append(name, current, latest, button, details);
        var view = { row: row, title: title, badge: badge, current: currentValue, latest: latestValue, button: button, details: details, reason: reason, item: item };
        button.addEventListener('click', function () { openPlan(view.item); }); return view;
      }, function (view, item) {
        view.item = item; setText(view.title, text(item.label, item.id)); setText(view.badge, labels[item.status] || 'Stato non disponibile'); setText(view.current, currentVersion(item)); setText(view.latest, text(item.latestStable && item.latestStable.version, 'Non disponibile'));
        view.button.disabled = working || value.available !== true || value.canApply === false || !updatable(item);
        var reason = item.blockedReason || (item.installed !== false && !item.candidateRelease && item.status !== 'current' ? 'Nessun aggiornamento compatibile verificato.' : '');
        if (item.candidateRelease && item.candidateRelease.version && item.latestStable && item.latestStable.version && item.candidateRelease.version !== item.latestStable.version) reason += (reason ? ' · ' : '') + 'Aggiornamento compatibile: ' + item.candidateRelease.version + ' · ' + text(item.compatibilityReason, 'La serie più recente richiede una verifica di compatibilità.');
        if ((item.services || []).length) reason += (reason ? ' · ' : '') + 'Servizi: ' + item.services.join(', ');
        setText(view.reason, reason); view.details.hidden = !reason;
        if (view.phase && view.phase !== item.status) animate(view.badge, [{ opacity: .35 }, { opacity: 1 }], 180); view.phase = item.status;
      });
      status.hidden = !status.textContent;
      select('[data-updates-empty]').hidden = components.length > 0;
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
        if (value.available !== true) status.textContent = text(value.unavailableReason, 'Aggiornamenti non disponibili su questo server.');
        else if (!state.operation) status.textContent = '';
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
    function close() { if (state.applying) return; state.dialogGeneration++; state.plan = null; state.component = null; confirm.value = ''; updateApply(); closeDialog(dialog); }
    async function openPlan(item) {
      if (state.busy || pending(state.operation)) return;
      var generation = state.generation, dialogGeneration = ++state.dialogGeneration;
      state.plan = null; state.component = item; confirm.value = ''; select('[data-updates-confirm-label]').hidden = true;
      select('[data-updates-plan-details]').replaceChildren(); planStatus.textContent = 'Conferma la tua identità per preparare il piano…'; updateApply(); openDialog(dialog);
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
      upgrade.disabled = !available || value.canApply === false || !(Number.isSafeInteger(value.updateCount) && value.updateCount > 0 || Number.isSafeInteger(value.autoremoveCount) && value.autoremoveCount > 0) || working;
      reboot.hidden = !available || value.rebootRequired !== true;
      reboot.disabled = !available || value.canReboot === false || value.rebootRequired !== true || working;
      root.setAttribute('aria-busy', working ? 'true' : 'false');
      select('os').textContent = value && value.os ? [text(value.os.name, value.os.id), value.os.version].filter(Boolean).join(' ') : 'Sistema non disponibile';
      select('summary').textContent = value ? (value.checkedAt ? (Number.isSafeInteger(value.updateCount) ? value.updateCount : 0) + ' aggiornamenti disponibili' + (Number.isSafeInteger(value.autoremoveCount) && value.autoremoveCount > 0 ? ' · ' + value.autoremoveCount + ' dipendenze da rimuovere' : '') + (Number.isSafeInteger(value.keptBackCount) && value.keptBackCount > 0 ? ' · ' + value.keptBackCount + ' mantenuti alla versione attuale' : '') + ' · Verifica: ' + new Date(value.checkedAt).toLocaleString('it-IT') : 'Aggiornamenti non ancora verificati') + (value.rebootRequired ? ' · Riavvio richiesto' : '') : '';
      var box = select('progress'), progress = box.querySelector('progress'), operation = state.operation;
      panelVisible(box, working || Boolean(operation));
      var total = operation && operation.totalSteps, completed = operation && operation.completedSteps;
      setProgress(progress, total, completed, operation && ['succeeded', 'completed'].includes(operation.status));
      select('stage').textContent = operation ? text(operation.stage, labels[operation.status] || serviceLabels[operation.status] || 'Manutenzione in corso…') : 'Preparazione…';
      status.hidden = !status.textContent;
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
        else if (!state.operation) status.textContent = '';
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
    function close() { if (state.applying) return; state.review++; state.plan = null; confirm.value = ''; updateApply(); closeDialog(dialog); }
    async function review(rebooting) {
      if (state.busy || pending(state.operation)) return;
      var generation = state.generation, review = ++state.review, expected = rebooting ? 'REBOOT' : 'UPDATE';
      state.plan = null; state.rebooting = rebooting; confirm.value = ''; select('confirm-label').hidden = true; select('plan-details').replaceChildren();
      select('review-title').textContent = rebooting ? 'Rivedi riavvio del server' : 'Rivedi aggiornamento del sistema';
      select('plan-status').textContent = 'Conferma la tua identità per preparare il piano…'; updateApply(); openDialog(dialog);
      try {
        await authenticate(); if (!alive(generation) || review !== state.review || !dialog.open) return;
        var value = await request('/control/runtime-updates/system/' + (rebooting ? 'reboot/' : '') + 'plan', { revision: state.value.revision });
        if (!alive(generation) || review !== state.review || !dialog.open) return;
        var plan = value.plan || value;
        if (!plan.planId || !plan.revision || plan.kind !== (rebooting ? 'host-reboot' : 'host-upgrade') || plan.confirmationRequired !== expected) throw Error('Piano di manutenzione non valido.');
        state.plan = plan; state.idempotencyKey = crypto.randomUUID();
        var details = select('plan-details');
        if (!rebooting) details.append(element('p', (Number.isSafeInteger(plan.packageCount) ? plan.packageCount : 0) + ' pacchetti da aggiornare · ' + (Number.isSafeInteger(plan.autoremoveCount) ? plan.autoremoveCount : 0) + ' dipendenze non più necessarie da rimuovere.'));
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
