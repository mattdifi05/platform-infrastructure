"use client";

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, type MutableRefObject } from "react";
import { createDynamicCssRule } from "./cssom";

export const BUTTON_ICON_ANIMATION_DURATION_MS = 680;
export const BUTTON_MORPH_DURATION_MS = 640;
export const BUTTON_MORPH_HOVER_UNLOCK_DELAY_MS = 180;
export const BUTTON_SUBMIT_DELAY_MS = 180;
export const BUTTON_MORPH_SCALE = { from: 1, over: 1.065, under: 1 } as const;
export const BUTTON_DYNAMIC_STYLE_PROPERTIES = [
  "inline-size", "--ui-button-morph-out-bg", "--ui-button-morph-out-color", "--ui-button-morph-from-x",
  "--ui-button-morph-over-x", "--ui-button-morph-under-x", "width",
] as const;

type DynamicCssRuleEntry = {
  properties: Record<string, string | undefined>;
  selector: string;
};

export function readVisibleButtonWidth(button: HTMLElement) {
  return button.getBoundingClientRect().width;
}

export function readNaturalButtonWidth(button: HTMLElement) {
  const clone = button.cloneNode(true);
  if (!(clone instanceof HTMLElement)) return readVisibleButtonWidth(button);

  clone.classList.add("ui-button-measure-clone");
  clone.classList.remove("is-morphing", "is-morph-hover-locked", "is-morph-even", "is-morph-odd");
  clone.removeAttribute("data-ui-button-id");
  clone.setAttribute("aria-hidden", "true");
  clone.setAttribute("tabindex", "-1");
  clone.querySelectorAll("[id]").forEach((node) => node.removeAttribute("id"));
  clone.querySelectorAll(".button-morph-outgoing").forEach((node) => node.remove());

  document.body.appendChild(clone);
  const width = clone.getBoundingClientRect().width;
  clone.remove();
  return width;
}

export function clearTimeoutRef(ref: MutableRefObject<number | null>) {
  if (ref.current === null) return;
  window.clearTimeout(ref.current);
  ref.current = null;
}

export function cancelFrameRef(ref: MutableRefObject<number | null>) {
  if (ref.current === null) return;
  window.cancelAnimationFrame(ref.current);
  ref.current = null;
}

export function useRafCssRuleWriter(
  selector: string,
  writeStyles: (rule: CSSStyleRule) => void,
  cleanupProperties: readonly string[],
) {
  const frameRef = useRef(0);
  const ruleRef = useRef<CSSStyleRule | null>(null);
  const writeStylesRef = useRef(writeStyles);

  useEffect(() => {
    writeStylesRef.current = writeStyles;
  }, [writeStyles]);

  const write = useCallback(() => {
    frameRef.current = 0;
    const rule = ruleRef.current;
    if (rule) writeStylesRef.current(rule);
  }, []);

  const schedule = useCallback(() => {
    if (frameRef.current) return;
    frameRef.current = window.requestAnimationFrame(write);
  }, [write]);

  useLayoutEffect(() => {
    ruleRef.current = createDynamicCssRule(selector);
    schedule();
    return () => {
      if (frameRef.current) window.cancelAnimationFrame(frameRef.current);
      const rule = ruleRef.current;
      if (rule) removeRuleStyleProperties(rule, cleanupProperties);
      ruleRef.current = null;
    };
  }, [cleanupProperties, schedule, selector]);

  return schedule;
}

export function setRuleStyleProperties(rule: CSSStyleRule, properties: Record<string, string>) {
  for (const [property, value] of Object.entries(properties)) {
    rule.style.setProperty(property, value);
  }
}

export function useDynamicCssProperties(
  selector: string,
  properties: Record<string, string | undefined>,
  cleanupProperties: readonly string[],
  enabled = true,
) {
  const entries = useMemo(() => enabled ? [{ properties, selector }] : [], [enabled, properties, selector]);
  useDynamicCssRuleSet(entries, cleanupProperties);
}

function useDynamicCssRuleSet(entries: DynamicCssRuleEntry[], cleanupProperties: readonly string[]) {
  const rulesRef = useRef(new Map<string, CSSStyleRule>());

  useEffect(() => () => {
    for (const rule of rulesRef.current.values()) removeRuleStyleProperties(rule, cleanupProperties);
    rulesRef.current.clear();
  }, [cleanupProperties]);

  useLayoutEffect(() => {
    const nextSelectors = new Set(entries.map((entry) => entry.selector));
    for (const [selector, rule] of rulesRef.current) {
      if (nextSelectors.has(selector)) continue;
      removeRuleStyleProperties(rule, cleanupProperties);
      rulesRef.current.delete(selector);
    }

    for (const entry of entries) {
      const hasDynamicValue = cleanupProperties.some((property) => entry.properties[property] !== undefined);
      if (!hasDynamicValue) {
        const rule = rulesRef.current.get(entry.selector);
        if (rule) removeRuleStyleProperties(rule, cleanupProperties);
        continue;
      }

      let rule = rulesRef.current.get(entry.selector);
      if (!rule) {
        rule = createDynamicCssRule(entry.selector) ?? undefined;
        if (!rule) continue;
        rulesRef.current.set(entry.selector, rule);
      }
      for (const property of cleanupProperties) {
        const value = entry.properties[property];
        if (value === undefined) rule.style.removeProperty(property);
        else rule.style.setProperty(property, value);
      }
    }
  }, [cleanupProperties, entries]);
}

function removeRuleStyleProperties(rule: CSSStyleRule, properties: readonly string[]) {
  for (const property of properties) rule.style.removeProperty(property);
}
