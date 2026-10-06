import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import test from "node:test";
import { renderServerAi } from "../ai/ui.mjs";

const source = fs.readFileSync(new URL("../styles/server-ai.js", import.meta.url), "utf8");
const css = fs.readFileSync(new URL("../styles/server-ai.css", import.meta.url), "utf8");

function section(start, end) {
  const from = source.indexOf(start);
  const to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `${start} source exists`);
  return source.slice(from, to);
}

function node() {
  return {
    textContent: "", hidden: false, disabled: false,
    classList: { toggle() {}, add() {}, remove() {} },
  };
}

test("manual restore dialog is rendered only when a configured catalog is passed", () => {
  const withoutRestore = renderServerAi();
  assert.doesNotMatch(withoutRestore, /data-ai-restore-dialog|data-vps-restore/);

  const restoreMarkup = '<section class="ops-card" data-vps-restore><p data-restore-status></p></section>';
  const withRestore = renderServerAi({ manualRestore: restoreMarkup });
  assert.match(withRestore, /<dialog[^>]*data-ai-restore-dialog/);
  assert.ok(withRestore.includes(restoreMarkup), "configured restore controls are embedded in the dialog");
});

test("a rejected enable remains visible in the real gate while the chat is hidden on mobile", async () => {
  const markup = renderServerAi();
  const gateStart = markup.indexOf('data-ai-gate aria-live="polite"');
  const alert = markup.indexOf('data-ai-action-error role="alert"');
  const chat = markup.indexOf('data-ai-chat-area hidden');
  assert.ok(gateStart >= 0 && gateStart < alert && alert < chat, "action error belongs to the visible gate, outside the hidden chat");
  assert.match(css, /\.server-ai \[hidden\] \{ display: none !important; \}/);
  assert.match(css, /\.server-ai-gate \.server-ai-action-error \{[^}]*overflow-wrap: anywhere;/);

  let resolvePost;
  const disabled = { machineLabel: "Server", state: "disabled", enabled: false, canConfigure: true, generationAvailable: false, historyAvailable: false, label: "Disattivato", online: false };
  const active = { ...disabled, state: "active", enabled: true, generationAvailable: true, historyAvailable: true, label: "Attivo", online: true };
  let reportedStatus = disabled;
  const context = {
    Headers, String, Boolean, Date,
    machineState: status => status.state,
    stateTitle: state => state === "disabled" ? "Disattivato" : state,
    shortStateTitle: state => state,
    renderAdminDiagnostics() {}, missingRequirements: () => [],
    refreshModeAvailability() {}, refreshQuickReplyAvailability() {},
    csrfToken: () => "test-csrf", endpoint: () => "/control/v1/machines/server/server-ai/enable",
    fetch: () => new Promise(resolve => { resolvePost = resolve; }),
  };
  vm.runInNewContext([
    section("  function setState(instance, value, error)", "  function quickReplyOption"),
    section("  function formatHostBytes(value)", "  function renderMachine(instance, status)"),
    section("  function renderMachine(instance, status)", "  function resizePrompt"),
    section("  async function requestMachineAction(instance, action)", "  async function viewProjectSource"),
    "globalThis.renderMachine = renderMachine; globalThis.updateMachineStatusMessage = updateMachineStatusMessage; globalThis.requestMachineAction = requestMachineAction;",
  ].join("\n"), context);

  const strong = node();
  const instance = {
    root: { isConnected: true, classList: node().classList, setAttribute() {} },
    health: { classList: node().classList, querySelector: () => strong },
    state: node(), machineLabel: node(), gateTitle: node(), gateMessage: node(), actionErrorNode: node(),
    missing: { ...node(), replaceChildren() {} }, enable: node(), disable: node(), chatArea: node(), gate: node(),
    selectedMachineId: "server", selectedMachineLabel: "Server", machineState: "disabled", canConfigure: true,
    lastMachineStatus: disabled, actionError: "", actionErrorAction: "", pendingAction: "", actionBusy: false,
    generationAvailable: false, historyAvailable: false, enabled: false, busy: false, chatError: false, transientUntil: 0,
  };
  context.refreshStatus = async () => {
    context.renderMachine(instance, reportedStatus);
    context.updateMachineStatusMessage(instance, reportedStatus);
  };

  context.renderMachine(instance, disabled);
  assert.equal(instance.chatArea.hidden, true);
  assert.equal(instance.gate.hidden, false);
  const request = context.requestMachineAction(instance, "enable");
  assert.equal(instance.machineState, "disabled", "the UI must not claim starting before HTTP 202");
  assert.match(instance.gateMessage.textContent, /Invio della richiesta/);
  resolvePost({ status: 503, json: async () => ({ message: "Attivazione non disponibile: inizializzazione richiesta." }) });
  await request;

  assert.equal(instance.chatArea.hidden, true);
  assert.equal(instance.gate.hidden, false);
  assert.equal(instance.actionErrorNode.hidden, false);
  assert.match(instance.actionErrorNode.textContent, /inizializzazione richiesta/);
  context.renderMachine(instance, disabled);
  context.updateMachineStatusMessage(instance, disabled);
  assert.equal(instance.actionErrorNode.hidden, false, "a disabled status poll must retain the visible error");
  assert.match(instance.actionErrorNode.textContent, /inizializzazione richiesta/);

  const retry = context.requestMachineAction(instance, "enable");
  assert.equal(instance.actionErrorNode.hidden, true, "a deliberate retry clears the previous rejection");
  assert.equal(instance.machineState, "disabled", "the retry remains disabled until accepted");
  reportedStatus = active;
  resolvePost({ status: 202, json: async () => ({ accepted: true }) });
  await retry;
  assert.equal(instance.actionErrorNode.hidden, true);
  assert.equal(instance.machineState, "active");
  assert.equal(instance.chatArea.hidden, false);
});
