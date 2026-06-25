import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createUiAsyncMachine } from "./AsyncState";
import { createUiFieldValidationState, uiFieldA11yProps } from "./FormValidation";

const workspaceRoot = new URL("../../../", import.meta.url);

function readText(relativePath: string) {
  return readFileSync(new URL(relativePath, workspaceRoot), "utf8").replace(/\r\n/g, "\n");
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

test("UiAsyncMachine protects against stale request races", async () => {
  const first = deferred<string>();
  const second = deferred<string>();
  const machine = createUiAsyncMachine<string>();

  const firstRun = machine.run(() => first.promise);
  const secondRun = machine.run(() => second.promise);
  first.resolve("old");
  second.resolve("new");

  await Promise.all([firstRun, secondRun]);
  assert.equal(machine.getSnapshot().status, "success");
  assert.equal(machine.getSnapshot().data, "new");
  assert.equal(machine.getSnapshot().requestId, 2);
});

test("UiAsyncMachine supports cancel, progress and stale states", async () => {
  const machine = createUiAsyncMachine<string>();
  const task = (signal: AbortSignal) => new Promise<string>((resolve, reject) => {
    signal.addEventListener("abort", () => reject(new Error("cancelled")));
    setTimeout(() => resolve("done"), 1);
  });

  const run = machine.run(task, { optimisticData: "preview", progress: 12 });
  assert.equal(machine.getSnapshot().status, "optimistic");
  machine.setProgress(44);
  assert.equal(machine.getSnapshot().status, "progress");
  assert.equal(machine.getSnapshot().progress, 44);
  machine.cancel();
  await run;
  assert.equal(machine.getSnapshot().status, "cancelled");

  machine.markStale();
  assert.equal(machine.getSnapshot().status, "stale");

  await machine.run(() => Promise.resolve("done"));
  assert.equal(machine.getSnapshot().status, "success");
});

test("form validation derives advanced field state and a11y attributes", () => {
  const issues = [
    { fieldId: "email", message: "Formato email non valido", severity: "error" as const },
    { fieldId: "profile", message: "Profilo incompleto", severity: "warning" as const },
  ];
  const state = createUiFieldValidationState({
    describedBy: "email-help",
    initialValue: "",
    issues,
    touched: true,
    value: "x",
  });

  assert.equal(state.dirty, true);
  assert.equal(state.status, "invalid");
  assert.deepEqual(uiFieldA11yProps(state), {
    "aria-busy": undefined,
    "aria-describedby": "email-help",
    "aria-disabled": undefined,
    "aria-invalid": true,
    "data-dirty": "true",
    "data-status": "invalid",
    "data-touched": "true",
  });
  const warningState = createUiFieldValidationState({
    issues: [{ message: "Verifica consigliata", severity: "warning" }],
    touched: true,
    value: "preview",
  });
  assert.equal(warningState.status, "warning");
  assert.equal(uiFieldA11yProps(warningState)["aria-invalid"], undefined);
});

test("Overlay manager exposes typed stack priorities and lifecycle subscriptions", () => {
  const overlaySource = readText("packages/ui/src/OverlayManager.ts");
  const modalSource = readText("packages/ui/src/Modal.tsx");

  for (const token of [
    "UiOverlayType",
    "command-palette",
    "interactionPriority",
    "onAfterOpen",
    "onBeforeClose",
    "subscribe(listener",
    "snapshot()",
  ]) {
    assert(overlaySource.includes(token), `Overlay runtime must expose ${token}.`);
  }
  assert(modalSource.includes("uiOverlayStack.register"));
  assert(modalSource.includes("uiOverlayStack.routeEscape()"));
  assert(modalSource.includes("getFocusableElements"));
});

test("Button asChild composes through Slot without adding wrapper variants", () => {
  const buttonSource = readText("packages/ui/src/Button.tsx");
  const slotSource = readText("packages/ui/src/Slot.tsx");

  assert(buttonSource.includes("asChild = false"));
  assert(buttonSource.includes("<Slot"));
  assert(buttonSource.includes("forwardRef<ButtonElement, ButtonProps>"));
  assert(buttonSource.includes("const isDisabled = Boolean(disabled);"));
  assert.equal(buttonSource.includes("disabled || loading"), false);
  assert(slotSource.includes("cloneElement"));
  assert(slotSource.includes("composeEventHandlers"));
});

test("Actions demo uses the shared Button primitive and builder surface", () => {
  const actionFlowSource = readText("packages/ui/src/ActionFlow.tsx");
  const buttonSource = readText("packages/ui/src/Button.tsx");
  const actionsSource = readText("packages/ui/src/catalog/UiCatalogActions.tsx");
  const builderSource = readText("packages/ui/src/catalog/UiCatalogActionBuilder.tsx");
  const actionConfigSource = readText("packages/ui/src/ActionConfig.ts");
  const actionsStyles = readText("packages/ui/src/styles/ui-app-03-actions.css");
  const controlsStyles = readText("packages/ui/src/styles/ui-02-controls.css");
  const motionSource = readText("packages/ui/src/styleMotion.ts");
  const asyncSource = readText("packages/ui/src/catalog/UiCatalogAsync.tsx");

  assert(buttonSource.includes("useDynamicCssProperties"));
  assert(actionFlowSource.includes("function ActionFlow"));
  assert(actionFlowSource.includes("showLabel = true"));
  assert(actionFlowSource.includes('size = "regular"'));
  assert(buttonSource.includes("buttonMorphing ? visibleWidth : previousWidth ?? visibleWidth"));
  assert(buttonSource.includes("previousWidthRef.current = readNaturalButtonWidth(button);"));
  assert.equal(buttonSource.includes("key={iconAnimationPulse}"), false, "Icon click animations must restart by class changes, not by remounting the icon node.");
  assert(motionSource.includes('clone.classList.add("ui-button-measure-clone")'));
  assert.equal(motionSource.includes('button.style.setProperty("width", "auto", "important")'), false);
  assert(motionSource.includes("useDynamicCssRuleSet"));
  assert(motionSource.includes("useLayoutEffect(() => {\n    const nextSelectors"), "Button dynamic CSS must be written before paint to avoid morph flicker.");
  assert.equal(actionsSource.includes("getUi" + "Action" + "Buttons"), false);
  assert.equal(asyncSource.includes("Action" + "Button"), false);
  assert(actionsSource.includes("UiButtonBuilderSurface"));
  assert(actionsSource.includes("<ActionFlow"));
  assert(actionsSource.includes("ui.action.stop"));
  assert(actionsSource.includes("ui.async.loading.badgeLoading"));
  assert(actionsSource.includes("showLabel={showLabel}"));
  assert(actionsSource.includes('size={compact ? "compact" : "regular"}'));
  assert(asyncSource.includes("<ActionFlow"));
  assert(builderSource.includes("spinIconOnClick={spinIconOnClick}"));
  assert(builderSource.includes("spinIconOnClickDirection={spinIconOnClickDirection}"));
  assert(builderSource.includes("getUiActionSpinDirection"));
  assert(actionConfigSource.includes('normalizedIconId === "refreshccw"'));
  assert(actionConfigSource.includes('normalizedIconId === "history"'));
  assert.equal(builderSource.includes("formatButtonConfig"), false);
  assert.equal(builderSource.includes("ui-action-builder-config"), false);
  assert(buttonSource.includes("is-spin-reverse"));
  assert(controlsStyles.includes("@keyframes ui-button-icon-spin-reverse"));
  assert(controlsStyles.includes(".ui-button-measure-clone"));
  assert(asyncSource.includes("const snapshot = machine.getSnapshot();"));
  assert(asyncSource.includes("toggleUiDemoAsync(syncMachine, \"sync\")"));
  assert(actionsStyles.includes("contain: layout style;"));
});

test("VirtualList is wired into large SelectList results", () => {
  const virtualListSource = readText("packages/ui/src/VirtualList.tsx");
  const selectSource = readText("packages/ui/src/Select.tsx");

  assert(virtualListSource.includes("data-virtual-list"));
  assert(virtualListSource.includes("data-virtual-index"));
  assert(selectSource.includes("options.length > 40"));
  assert(selectSource.includes("<VirtualList"));
});

