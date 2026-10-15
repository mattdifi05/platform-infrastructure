(function () {
  'use strict';
  var trigger = null;
  var mounted = new WeakSet();
  var lifecycles = new WeakMap();
  var motions = new WeakMap();
  function page() { return document.querySelector('[data-secrets-page]'); }
  function animate(element, closing, frames) {
    if (!element) return null;
    var previous = motions.get(element), current = previous && window.getComputedStyle ? window.getComputedStyle(element) : null;
    var interrupted = current ? { opacity: current.opacity, transform: current.transform } : null;
    if (previous) { previous.cancel(); motions.delete(element); }
    if (!element.animate || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return null;
    var animation = element.animate(frames || [interrupted || (closing ? { opacity: 1, transform: 'translateX(0)' } : { opacity: 0, transform: 'translateX(10px)' }), closing ? { opacity: 0, transform: 'translateX(8px)' } : { opacity: 1, transform: 'translateX(0)' }], { duration: closing ? 140 : 220, easing: 'cubic-bezier(.22,1,.36,1)' });
    motions.set(element, animation);
    var finish = function () { if (motions.get(element) === animation) motions.delete(element); };
    animation.finished.then(finish, finish);
    return animation;
  }
  function filter(root) {
    var query = root.querySelector('[data-secret-search]').value.trim().toLocaleLowerCase('it');
    var active = root.querySelector('[data-secret-filter][aria-pressed="true"]').dataset.secretFilter;
    var count = 0, total = 0;
    var rows = Array.from(root.querySelectorAll('[data-secret-row]'));
    var previous = new Map();
    var entering = new Set();
    rows.forEach(function (row) { if (!row.hidden && row.getBoundingClientRect) previous.set(row, row.getBoundingClientRect().top); });
    rows.forEach(function (row) { if (motions.has(row)) { motions.get(row).cancel(); motions.delete(row); } });
    rows.forEach(function (row) {
      total++;
      var matches = row.dataset.secretSearch.includes(query) && (active === 'all' || (active === 'linked') === (row.dataset.secretLinked === 'true'));
      var wasHidden = row.hidden;
      row.hidden = !matches;
      if (matches) count++;
      if (matches && wasHidden) entering.add(row);
    });
    root.querySelector('[data-secret-empty]').hidden = count > 0;
    root.querySelector('[data-secret-visible-count]').textContent = count === total ? total + ' elementi' : count + ' di ' + total + ' elementi';
    rows.forEach(function (row) {
      if (row.hidden) return;
      if (entering.has(row)) animate(row, false, [{ opacity: 0, transform: 'translateY(5px)' }, { opacity: 1, transform: 'translateY(0)' }]);
      else if (previous.has(row) && row.getBoundingClientRect) {
        var delta = previous.get(row) - row.getBoundingClientRect().top;
        if (Math.abs(delta) > 1) animate(row, false, [{ transform: 'translateY(' + delta + 'px)' }, { transform: 'translateY(0)' }]);
      }
    });
  }
  function resetEditor(root) {
    root.querySelectorAll('[data-secret-editor] form').forEach(function (form) { form.reset(); form.hidden = true; form.querySelector('[data-secret-form-status]').textContent = ''; form.querySelector('[data-secret-form-status]').removeAttribute('data-error'); });
    root.querySelectorAll('[data-secret-row][data-selected]').forEach(function (row) { row.removeAttribute('data-selected'); });
  }
  function close(root) {
    if (root.dataset.managementBusy === 'true') return;
    var editor = root.querySelector('[data-secret-editor]');
    var lifecycle = lifecycles.get(root) || { generation: 0, animation: null };
    var generation = ++lifecycle.generation; lifecycles.set(root, lifecycle);
    var animation = animate(editor, true); lifecycle.animation = animation;
    var finish = function () {
      if (!root.isConnected || lifecycle.generation !== generation) return;
      var restoreFocus = !document.activeElement || document.activeElement === document.body || editor.contains(document.activeElement);
      resetEditor(root); editor.hidden = true; delete root.dataset.editorOpen;
      if (restoreFocus && trigger && trigger.isConnected) trigger.focus({ preventScroll: true });
    };
    if (animation) animation.finished.then(finish, finish); else finish();
  }
  function open(root, mode, button) {
    if (root.dataset.managementBusy === 'true') return;
    var lifecycle = lifecycles.get(root) || { generation: 0, animation: null };
    ++lifecycle.generation; lifecycles.set(root, lifecycle);
    resetEditor(root); trigger = button;
    var editor = root.querySelector('[data-secret-editor]');
    var form = editor.querySelector('[data-secret-' + mode + '-form]');
    var row = button.closest('[data-secret-row]');
    if (row) {
      row.dataset.selected = 'true';
      var identity = row.dataset.secretLabel + ' · ' + row.dataset.secretOwner + ' · ' + row.dataset.secretEnvironment;
      if (mode === 'edit') { form.elements.itemId.value = row.dataset.secretId; form.querySelector('[data-secret-edit-identity]').textContent = identity; }
      if (mode === 'delete') { form.elements.id.value = row.dataset.secretId; form.elements.confirm.value = 'DELETE-VAULT-SECRET:' + row.dataset.secretId; form.querySelector('[data-secret-delete-identity]').textContent = identity; }
    }
    root.querySelector('#cc-secret-editor-title').textContent = { create: 'Nuovo secret', edit: 'Modifica secret', delete: 'Elimina secret' }[mode];
    form.hidden = false; editor.hidden = false; root.dataset.editorOpen = 'true'; lifecycle.animation = animate(editor);
    var first = form.querySelector('input:not([type="hidden"]),textarea,select');
    if (first) first.focus({ preventScroll: true });
  }
  document.addEventListener('click', function (event) {
    var root = event.target.closest('[data-secrets-page]'); if (!root) return;
    var button = event.target.closest('button'); if (!button) return;
    if (button.hasAttribute('data-secret-create')) open(root, 'create', button);
    if (button.hasAttribute('data-secret-edit')) open(root, 'edit', button);
    if (button.hasAttribute('data-secret-delete')) open(root, 'delete', button);
    if (button.hasAttribute('data-secret-close')) close(root);
    if (button.hasAttribute('data-secret-filter')) { root.querySelectorAll('[data-secret-filter]').forEach(function (tab) { tab.setAttribute('aria-pressed', String(tab === button)); }); filter(root); }
  });
  document.addEventListener('input', function (event) { if (event.target.matches('[data-secret-search]')) filter(event.target.closest('[data-secrets-page]')); });
  document.addEventListener('keydown', function (event) { var root = page(); if (event.key === 'Escape' && root?.dataset.editorOpen === 'true') { event.preventDefault(); close(root); } });
  document.addEventListener('cc-vault-management-complete', function (event) {
    var root = page(); if (!root) return;
    var feedback = root.querySelector('[data-secret-page-feedback]');
    feedback.textContent = { create: 'Secret salvato nel Vault.', version: 'Nuova versione salvata nel Vault. La credenziale in uso non cambia.', delete: 'Secret rimosso dal Vault. Le credenziali dei servizi restano invariate.', 'import-existing': 'Importazione completata. I file di origine restano invariati.' }[event.detail?.action] || 'Vault aggiornato.';
    feedback.hidden = false; animate(feedback);
  });
  function scan() { var root = page(); if (!root || mounted.has(root)) return; mounted.add(root); filter(root); }
  function start() { scan(); new MutationObserver(scan).observe(document.body, { childList: true, subtree: true }); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true }); else start();
})();
