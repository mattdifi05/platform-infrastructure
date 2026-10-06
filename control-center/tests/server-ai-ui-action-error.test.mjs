import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import test from "node:test";

const source = fs.readFileSync(new URL("../styles/server-ai.js", import.meta.url), "utf8");
const begin = source.indexOf("function updateMachineStatusMessage(instance, status)");
const end = source.indexOf("\n  function quickReplyOption", begin);
assert.ok(begin >= 0 && end > begin, "machine status message helper exists");
const helper = source.slice(begin, end);

test("a rejected machine action remains visible after later disabled status polls", () => {
  const messages = [];
  const context = {
    setState: (instance, text, error) => messages.push({ text, error: Boolean(error) }),
    stateTitle: state => state,
    String,
  };
  vm.runInNewContext(`${helper}; globalThis.updateMachineStatusMessage = updateMachineStatusMessage;`, context);
  const instance = { actionError: "CSRF validation failed.", machineState: "disabled", busy: false, chatError: false };

  context.updateMachineStatusMessage(instance, { label: "Disattivato", online: false });

  assert.deepEqual(messages, [{ text: "CSRF validation failed.", error: true }]);
  assert.match(source, /updateMachineStatusMessage\(instance, status\);/);
});

test("a new successful action can clear the prior error and restore normal status text", () => {
  const messages = [];
  const context = {
    setState: (instance, text, error) => messages.push({ text, error: Boolean(error) }),
    stateTitle: state => state,
    String,
  };
  vm.runInNewContext(`${helper}; globalThis.updateMachineStatusMessage = updateMachineStatusMessage;`, context);
  const instance = { actionError: "CSRF validation failed.", machineState: "disabled", busy: false, chatError: false };
  instance.actionError = "";

  context.updateMachineStatusMessage(instance, { label: "Disattivato", online: false });

  assert.deepEqual(messages, [{ text: "Disattivato", error: false }]);
});
