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
  function catalogOperation(value, previous) {
    var operations = value.operations || [];
    return operations.find(pending) || operations.find(function (operation) { return operation.recoveryRequired === true; }) || (previous && operations.find(function (operation) { return operation.id === previous.id; })) || (previous && !previous.recoveryRequired ? previous : null);
  }
  function blockedStatus(value, operation) {
    if (operation && operation.recoveryRequired === true) return 'Verifica amministrativa richiesta prima di altri aggiornamenti. ' + text(operation.stage, 'Controlla lo stato della manutenzione interrotta.');
    if (value && value.available === true && value.canCheck === false && value.canApply === false && value.busy !== true && !pending(operation)) return 'Aggiornamenti bloccati da una manutenzione in corso o da verificare. Controlla lo stato del sistema e dei servizi.';
    return '';
  }
  function operationId(value) { return value && (value.operationId || value.id || value.operation && value.operation.id); }
  function mountPlatform(root) {
    if (mounted.has(root)) return;
    mounted.add(root);
    var select = function (name) { return root.querySelector('[data-platform-updates-' + name + ']'); };
    var scopes = [{ id: 'system', label: 'Sistema operativo', path: '/control/runtime-updates/system' }, { id: 'services', label: 'Runtime e servizi', path: '/control/runtime-updates' }];
    var state = { catalogs: {}, operations: {}, errors: {}, plans: [], busy: false, loading: false, applying: false, stopped: false, generation: 0, review: 0, timer: null };
    var versionViews = new Map(), installedViews = new Map(), resultViews = new Map(), hydrated = false;
    var check = select('check'), upgrade = select('upgrade'), reboot = select('reboot'), dialog = select('dialog'), confirm = select('confirm'), apply = select('apply');
    function alive(generation) { return !state.stopped && root.isConnected && generation === state.generation; }
    function request(path, payload) { var bridge = window.controlCenterRuntimeUpdates; return bridge && typeof bridge.request === 'function' ? bridge.request(path, payload) : Promise.reject(Error('Collegamento al server non disponibile.')); }
    async function authenticate() { var bridge = window.controlCenterRuntimeUpdates; if (!bridge || typeof bridge.authenticate !== 'function') throw Error('Conferma passkey non disponibile.'); await bridge.authenticate(); }
    function inProgress() { return Object.values(state.operations).some(pending); }
    function targets() { return scopes.filter(function (scope) { var value = state.catalogs[scope.id]; return value && (scope.id === 'system' ? value.updateCount > 0 || value.autoremoveCount > 0 : (value.components || []).some(updatable)); }); }
    function updateApply() { apply.disabled = state.applying || !state.plans.length || confirm.value !== 'REBOOT' || state.plans.some(function (entry) { return !Number.isFinite(Date.parse(entry.plan.expiresAt)) || Date.parse(entry.plan.expiresAt) <= Date.now(); }); }
    function setText(node, value) { if (node.textContent !== value) node.textContent = value; }
    function reconcile(container, records, views, create, update) {
      var present = new Set();
      records.forEach(function (record, index) { present.add(record.key); var view = views.get(record.key), fresh = !view;
        if (!view) { view = create(record); views.set(record.key, view); }
        update(view, record);
        if (container.children[index] !== view.row) container.insertBefore(view.row, container.children[index] || null);
        if (fresh && hydrated) animate(view.row, [{ opacity: 0, transform: 'translateY(3px)' }, { opacity: 1, transform: 'translateY(0)' }], 160);
      });
      views.forEach(function (view, key) { if (!present.has(key)) { view.row.remove(); views.delete(key); } });
    }
    function createVersion(record) {
      var row = element('div'), name = element('strong'), current = element('span'), arrow = element('span', '→'), target = element('span'), icon = element('span');
      row.className = 'cc-platform-version-row' + (record.installed ? ' cc-platform-installed-row' : record.empty ? ' cc-platform-empty-row' : ''); icon.className = 'cc-update-icon cc-update-icon-' + record.icon; icon.setAttribute('aria-hidden', 'true');
      var template = select('icon-' + record.icon); if (template && template.content && template.content.firstElementChild) icon.append(template.content.firstElementChild.cloneNode(true));
      current.className = 'cc-update-version-from'; target.className = 'cc-update-version-to'; arrow.className = 'cc-update-arrow'; arrow.setAttribute('aria-hidden', 'true');
      row.append(icon, name, current, arrow, target); return { row: row, name: name, current: current, target: target };
    }
    function updateVersion(view, record) { setText(view.name, record.name); setText(view.current, record.empty ? '' : record.current === null ? 'Nuova dipendenza' : text(record.current, 'Non verificata')); setText(view.target, record.target || ''); }
    function componentIcon(item) { return /nginx|traefik|gateway/i.test(item.id) ? 'network' : /rust|storage|redis|postgres|maria|mysql/i.test(item.id) ? 'storage' : 'runtime'; }
    function render() {
      if (!root.isConnected) return;
      var working = state.busy || state.applying || inProgress(), loaded = scopes.every(function (scope) { return state.catalogs[scope.id]; });
      check.disabled = working || !loaded || scopes.some(function (scope) { var value = state.catalogs[scope.id]; return !value || value.available !== true || value.canCheck === false; });
      upgrade.disabled = working || !loaded || !targets().length || targets().some(function (scope) { return state.catalogs[scope.id].available !== true || state.catalogs[scope.id].canApply === false; });
      root.setAttribute('aria-busy', working || !state.initialized ? 'true' : 'false');
      root.setAttribute('data-loading', state.initialized ? 'false' : 'true');
      var system = state.catalogs.system, services = state.catalogs.services;
      var candidates = [], installedRecords = [];
      if (system) (system.packages || []).forEach(function (item) { candidates.push({ key: 'package:' + item.name, name: item.name, current: item.currentVersion, target: item.targetVersion, icon: 'package' }); });
      if (services) (services.components || []).forEach(function (item) { if (item.installed === false) return; var record = { key: 'component:' + item.id, name: text(item.label, item.id), current: currentVersion(item), icon: componentIcon(item) }; installedRecords.push(Object.assign({}, record, { installed: true })); if (updatable(item)) candidates.push(Object.assign({}, record, { target: item.candidateRelease.version })); });
      var count = (system && system.updateCount || 0) + (services ? (services.components || []).filter(updatable).length : 0);
      setText(select('summary'), state.initialized ? count + ' disponibili' : '');
      setText(select('installed-count'), state.initialized ? String(installedRecords.length) : '');
      reboot.hidden = !system || system.rebootRequired !== true;
      reboot.disabled = working || !system || system.canReboot === false || system.rebootRequired !== true;
      if (state.initialized) {
        var list = select('list'), installed = select('installed-list');
        if (!hydrated) list.replaceChildren();
        if (system && system.autoremoveCount > 0) candidates.push({ key: 'cleanup', name: 'Dipendenze inutilizzate', current: String(system.autoremoveCount), target: 'Rimozione', icon: 'package' });
        if (!candidates.length) candidates.push({ key: 'empty', name: loaded ? 'Tutto aggiornato' : 'Aggiornamenti non disponibili', current: '', icon: 'runtime', empty: true });
        reconcile(list, candidates, versionViews, createVersion, updateVersion);
        reconcile(installed, installedRecords, installedViews, createVersion, updateVersion);
        hydrated = true;
      }
      select('status').textContent = scopes.map(function (scope) { return state.errors[scope.id] ? scope.label + ': ' + state.errors[scope.id] : ''; }).filter(Boolean).join(' · ');
      var operations = Object.values(state.operations), progress = select('progress'); panelVisible(progress, operations.length > 0);
      var completed = operations.filter(function (operation) { return ['succeeded', 'completed'].includes(operation.status); }).length;
      setProgress(progress.querySelector('progress'), operations.length, completed, operations.length > 0 && completed === operations.length);
      select('stage').textContent = inProgress() ? 'In corso · ' + completed + ' di ' + operations.length : operations.length ? (completed === operations.length ? 'Operazioni completate' : 'Controlla gli esiti') : '';
      var resultRecords = [];
      scopes.forEach(function (scope) {
        var operation = state.operations[scope.id]; if (!operation) return;
        var entries = scope.id === 'services' && Array.isArray(operation.serviceResults) && operation.serviceResults.length ? operation.serviceResults : [operation];
        entries.forEach(function (entry) { resultRecords.push({ key: scope.id + ':' + (entry.service || operation.id || 'submission'), name: entry.service || (scope.id === 'system' ? 'Pacchetti del server' : 'Aggiornamento servizi'), status: entry.status, stage: text(entry.stage, text(operation.stage, 'In attesa')) + (operation.waitingForMaintenance ? ' · In attesa dell’altra manutenzione' : '') }); });
      });
      reconcile(select('results'), resultRecords, resultViews, function () { var row = element('li'), name = element('strong'), status = element('span'), stage = element('small'); row.className = 'cc-update-service'; row.append(name, status, stage); return { row: row, name: name, status: status, stage: stage }; }, function (view, record) { setText(view.name, record.name); setText(view.status, labels[record.status] || serviceLabels[record.status] || 'In corso'); setText(view.stage, record.stage); view.row.setAttribute('data-service-status', record.status); });
      updateApply();
    }
    function schedule() { clearTimeout(state.timer); if (!state.stopped && root.isConnected && !document.hidden) state.timer = setTimeout(load, inProgress() ? 2000 : 30000); }
    async function load() {
      if (state.stopped || !root.isConnected || document.hidden || state.loading || state.busy || dialog.open) return;
      var generation = state.generation; state.loading = true;
      try {
        await Promise.all(scopes.map(async function (scope) {
          try {
            var operation = state.operations[scope.id];
            if (pending(operation)) { var response = await request('/control/runtime-updates/operations/' + encodeURIComponent(operation.id)); if (!alive(generation)) return; state.operations[scope.id] = response.operation || response; if (pending(state.operations[scope.id])) { delete state.errors[scope.id]; return; } }
            var value = await request(scope.path); if (!alive(generation)) return; state.catalogs[scope.id] = value;
            var previous = state.operations[scope.id];
            var latest = previous && previous.submissionFailed ? ((value.operations || []).find(pending) || previous) : catalogOperation(value, previous); if (latest) state.operations[scope.id] = latest;
            state.errors[scope.id] = value.available !== true ? text(value.unavailableReason, 'Aggiornamenti non disponibili') : blockedStatus(value, latest) || (latest && latest.error ? text(latest.error.message || latest.error, 'Operazione non riuscita') : '');
          } catch (error) { if (alive(generation)) state.errors[scope.id] = pending(state.operations[scope.id]) ? 'Connessione interrotta. Riconnessione automatica e verifica dell’operazione in corso…' : error.message; }
        }));
      } finally { if (alive(generation)) { state.loading = false; state.initialized = true; render(); schedule(); } }
    }
    function accept(scope, value) { var id = operationId(value); if (!id) throw Error('Il server non ha restituito un identificativo operazione.'); state.operations[scope.id] = { id: id, status: value.status || 'queued', stage: 'Richiesta accettata; verifica del server in attesa' }; delete state.errors[scope.id]; }
    check.addEventListener('click', async function () {
      if (check.disabled) return; var generation = state.generation; state.busy = true; clearTimeout(state.timer); render();
      await Promise.all(scopes.map(async function (scope) { try { var value = await request(scope.path + '/check', {}); if (alive(generation)) accept(scope, value); } catch (error) { if (alive(generation)) { state.errors[scope.id] = error.message; state.operations[scope.id] = { status: 'failed', stage: error.message, error: error.message, submissionFailed: true }; } } }));
      if (alive(generation)) { state.busy = false; render(); schedule(); }
    });
    function close() { if (state.applying) return; state.review++; state.plans = []; confirm.value = ''; updateApply(); closeDialog(dialog); schedule(); }
    upgrade.addEventListener('click', async function () {
      if (upgrade.disabled) return;
      var generation = state.generation; state.busy = true; clearTimeout(state.timer); render();
      try {
        await authenticate(); if (!alive(generation)) return;
        var catalogs = await Promise.all(scopes.map(function (scope) { return request(scope.path); })); if (!alive(generation)) return;
        catalogs.forEach(function (value, index) { state.catalogs[scopes[index].id] = value; });
        var selected = targets(); if (!selected.length) throw Error('Nessun aggiornamento disponibile.');
        if (selected.some(function (scope) { var value = state.catalogs[scope.id]; return value.available !== true || value.canApply === false; })) throw Error('Aggiornamenti bloccati. Verifica lo stato del server.');
        var plans = await Promise.all(selected.map(async function (scope) {
          var value = await request(scope.path + (scope.id === 'services' ? '/all' : '') + '/plan', Object.assign({ revision: state.catalogs[scope.id].revision }, scope.id === 'system' ? Object.assign({ rebootAfter: true }, selected.some(function (item) { return item.id === 'services'; }) ? { coordinatedReboot: true } : {}) : {})), plan = value.plan || value;
          if (!plan.planId || !plan.revision || plan.revision !== state.catalogs[scope.id].revision || plan.confirmationRequired !== (scope.id === 'system' ? 'UPDATE_AND_REBOOT' : 'UPDATE') || !Number.isFinite(Date.parse(plan.expiresAt)) || Date.parse(plan.expiresAt) <= Date.now() || (scope.id === 'system' ? plan.kind !== 'host-upgrade' || plan.rebootAfter !== true || (plan.coordinatedReboot === true) !== selected.some(function (item) { return item.id === 'services'; }) : plan.kind !== 'batch' || !Array.isArray(plan.components) || !plan.components.length || !plan.targetVersion || !plan.targetDigest)) throw Error('Piano di aggiornamento non valido o scaduto.');
          return { scope: scope, plan: plan, key: crypto.randomUUID() };
        }));
        if (!alive(generation)) return;
        if (plans.some(function (entry) { return Date.parse(entry.plan.expiresAt) <= Date.now(); })) throw Error('Piano scaduto. Verifica nuovamente gli aggiornamenti.');
        await Promise.all(plans.map(async function (entry) { try { var value = await request(entry.scope.path + (entry.scope.id === 'services' ? '/all' : '') + '/apply', { revision: entry.plan.revision, planId: entry.plan.planId, confirmation: entry.scope.id === 'system' ? 'UPDATE_AND_REBOOT' : 'UPDATE', idempotencyKey: entry.key }); if (alive(generation)) { accept(entry.scope, value); if (entry.scope.id === 'system') state.operations.system.stage = 'Aggiornamento avviato. Riavvio automatico se necessario; riconnessione automatica.'; } } catch (error) { if (alive(generation)) { state.errors[entry.scope.id] = error.message; state.operations[entry.scope.id] = { status: 'failed', stage: error.message, error: error.message, submissionFailed: true }; } } }));
      } catch (error) { if (alive(generation)) state.errors.system = error.message; }
      finally { if (alive(generation)) { state.busy = false; render(); schedule(); } }
    });
    reboot.addEventListener('click', async function () {
      if (reboot.disabled) return;
      var generation = state.generation, review = ++state.review; state.plans = []; confirm.value = ''; select('confirm-label').hidden = true; select('plan-details').replaceChildren(); select('plan-status').textContent = 'Conferma la tua identità per preparare il riavvio…'; updateApply(); openDialog(dialog); clearTimeout(state.timer);
      try {
        await authenticate(); if (!alive(generation) || review !== state.review || !dialog.open) return;
        var value = await request('/control/runtime-updates/system/reboot/plan', { revision: state.catalogs.system.revision }), plan = value.plan || value;
        if (!alive(generation) || review !== state.review || !dialog.open) return;
        if (!plan.planId || !plan.revision || plan.kind !== 'host-reboot' || plan.confirmationRequired !== 'REBOOT') throw Error('Piano di riavvio non valido.');
        state.plans = [{ plan: plan, key: crypto.randomUUID() }]; select('plan-details').append(element('p', 'Il server sarà temporaneamente irraggiungibile durante il riavvio.')); select('confirm-label').hidden = false; select('plan-status').textContent = 'Conferma il riavvio del server.'; updateApply();
      } catch (error) { if (alive(generation) && review === state.review) select('plan-status').textContent = error.message; }
    });
    apply.addEventListener('click', async function () {
      updateApply(); if (apply.disabled) return; var generation = state.generation, review = state.review, entry = state.plans[0]; state.applying = true; updateApply();
      try {
        await authenticate(); if (!alive(generation) || review !== state.review || !dialog.open) return;
        if (Date.parse(entry.plan.expiresAt) <= Date.now()) throw Error('Piano scaduto. Prepara un nuovo riavvio.');
        var value = await request('/control/runtime-updates/system/reboot/apply', { revision: entry.plan.revision, planId: entry.plan.planId, confirmation: 'REBOOT', idempotencyKey: entry.key });
        if (alive(generation)) { accept(scopes[0], value); state.applying = false; close(); render(); schedule(); }
      } catch (error) { if (alive(generation)) select('plan-status').textContent = error.message; }
      finally { if (alive(generation)) { state.applying = false; updateApply(); } }
    });
    confirm.addEventListener('input', updateApply); select('close').addEventListener('click', close); dialog.addEventListener('cancel', function (event) { event.preventDefault(); close(); });
    select('installed').addEventListener('toggle', function () { if (this.open) { var list = select('installed-list'); animate(list, [{ opacity: 0, height: '0px' }, { opacity: 1, height: list.scrollHeight + 'px' }]); } });
    active.add({ root: root, stop: function () { state.stopped = true; state.generation++; state.review++; clearTimeout(state.timer); if (dialog.open) dialog.close(); }, resume: load, pause: function () { clearTimeout(state.timer); } }); load();
  }
  function scan() { active.forEach(function (entry) { if (!entry.root.isConnected) { entry.stop(); active.delete(entry); } }); document.querySelectorAll('[data-platform-updates]').forEach(mountPlatform); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', scan); else scan();
  if (window.MutationObserver) new MutationObserver(scan).observe(document.body, { childList: true, subtree: true });
  document.addEventListener('visibilitychange', function () { active.forEach(function (entry) { if (document.hidden) entry.pause(); else entry.resume(); }); });
  window.addEventListener('pagehide', function () { active.forEach(function (entry) { entry.stop(); }); active.clear(); });
})();
