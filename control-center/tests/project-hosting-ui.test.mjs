import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
const sourceRoot = new URL("../styles/", import.meta.url);
const script = readFileSync(new URL("control-center.js", sourceRoot), "utf8");
const css = readFileSync(new URL("control-center.css", sourceRoot), "utf8");

test("visibility writes require a loaded review plan and its current confirmation", () => {
  assert.match(script, /\.ops-project-detail-screen\[id\^='project-'\]/);
  assert.match(script, /\/control\/projects\/" \+ encodeURIComponent\(projectId\) \+ "\/hosting-status/);
  assert.match(script, /\/hosting-plan\?mode=/);
  assert.match(script, /visibility\.verified === true/);
  assert.match(script, /authenticateWithSystemPasskey\(\)/);
  assert.match(script, /expectedRevision: reviewedPlan\.revision/);
  assert.match(script, /confirm: reviewedPlan\.confirmationRequired/);
  assert.match(script, /plan\.revision/);
  assert.match(script, /plan\.actions/);
  assert.match(script, /plan\.hostnames/);
  assert.match(script, /plan\.hostPlans/);
  assert.match(script, /data-hosting-plan-hosts/);
  assert.match(script, /Host verificati:/);
  assert.doesNotMatch(script, /SET-VISIBILITY:/);
  assert.match(script, /CLONE-PRIVATE:/);
  assert.match(script, /CANCEL-CLONE:/);
});

test("private copy review exposes isolation and restricted access without app-specific hostnames", () => {
  assert.match(script, /Cloudflare Access · solo account owner/);
  assert.match(script, /Archivio e credenziali isolati dalla produzione/);
  assert.match(script, /Invio email/);
  assert.match(script, /Pianificazioni/);
  assert.match(script, /clone\.eligible === true/);
  assert.match(script, /privateCopyUnavailableReason\(clone\.reason\)/);
  assert.match(script, /source not admitted by native application operator/);
  assert.match(script, /non è ancora stata verificata per la copia privata/);
  assert.doesNotMatch(script, /return reason\.trim\(\)/);
  assert.match(script, /status === "absent"/);
  assert.match(script, /"staged", "publishing", "activating"/);
  assert.doesNotMatch(script, /scriptastudents\.com|stexor\.com/i);
});

test("hosting controls keep the detail panel usable at narrow widths", () => {
  assert.match(css, /\.cc-hosting-copy \{[^}]*flex-direction: column/s);
  assert.match(css, /\.cc-hosting-review \{[^}]*grid-template-columns: 1fr/s);
  assert.match(css, /\.cc-hosting-plan \{/);
  assert.match(css, /\.cc-hosting-plan-hosts \{/);
  assert.match(css, /\.cc-hosting-dialog-actions \.ops-button \{ width: 100%; \}/);
});

test("late hosting plan success or failure cannot revive a closing review or submit an operation", async () => {
  const begin = script.indexOf("    function updateApply()", script.indexOf("  function openHostingConfirm("));
  const end = script.indexOf("    dialog.showModal();", begin);
  assert.ok(begin >= 0 && end > begin);
  for (const fail of [false, true]) {
    let resolvePlan, rejectPlan, finishExit, closed = 0, focused = 0, requests = 0, challenges = 0;
    const plan = new Promise((resolve, reject) => { resolvePlan = resolve; rejectPlan = reject; });
    const exit = new Promise(resolve => { finishExit = resolve; });
    const feedback = [];
    const control = () => ({ disabled: false, listeners: {}, addEventListener(name, callback) { this.listeners[name] = callback; } });
    const input = { ...control(), value: "", focus() { focused++; } }, apply = control(), retry = { ...control(), hidden: true };
    const closeButtons = [control(), control()], listeners = {};
    const dialog = {
      isConnected: true, dataset: {},
      querySelectorAll: selector => selector === "[data-hosting-close]" ? closeButtons : [...closeButtons, input, apply, retry],
      addEventListener: (name, callback) => { listeners[name] = callback; },
      animate: () => ({ finished: exit }),
      close() { closed++; listeners.close(); },
      remove() { this.isConnected = false; },
    };
    const context = {
      input, apply, retry, dialog, busy: false, succeeded: false, submitted: false, reviewedPlan: null,
      operation: "visibility", actionLabel: "PUBLIC", projectId: "fixture-app", mode: "public", state: {}, panel: { isConnected: true },
      window: { matchMedia: () => ({ matches: false }) },
      syncHostingControls() {}, hostingModeLabel: value => value,
      dialogFeedback: phase => feedback.push(phase), hostingFeedback() {},
      hostingRequest: () => { requests++; return plan; },
      authenticateWithSystemPasskey: () => { challenges++; throw Error("Closing review must never authenticate"); },
    };
    vm.createContext(context);
    vm.runInContext(script.slice(begin, end), context);
    const pending = context.loadPlan();
    assert.equal(requests, 1);
    context.closeReview();
    assert.equal(dialog.dataset.closing, "true");
    assert.equal(closed, 0, "The close animation is still pending");
    if (fail) rejectPlan(new Error("Fixture plan failure"));
    else resolvePlan({ plan: { revision: "fixture-revision", confirmationRequired: "fixture-confirmation" } });
    await pending;
    assert.equal(context.reviewedPlan, null);
    assert.deepEqual(feedback, ["planning"], "Late response cannot render review/error UI");
    assert.equal(focused, 0);
    input.value = "PUBLIC"; context.updateApply();
    assert.ok([input, apply, ...closeButtons].every(control => control.disabled));
    retry.listeners.click();
    apply.disabled = false; // Even a previously queued click must fail closed.
    await apply.listeners.click();
    assert.equal(requests, 1);
    assert.equal(challenges, 0);
    finishExit(); await Promise.resolve();
    assert.equal(closed, 1);
    assert.equal(dialog.isConnected, false);
    assert.equal(context.state.operation, "");
  }
});
