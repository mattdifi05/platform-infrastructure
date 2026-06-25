"use client";

import { useCallback, useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import {
  animate,
  useMotionValue,
  useMotionValueEvent,
  useReducedMotion,
  useSpring,
  useTransform,
  useVelocity,
} from "framer-motion";
import type { IconType } from "./icons";
import { classNames } from "./classNames";
import { setRuleStyleProperties, useRafCssRuleWriter } from "./styleMotion";

export type PillTabItem<TId extends string = string> = {
  icon?: IconType;
  id: TId;
  label: ReactNode;
  panelId?: string;
};

type PillGeometry = {
  width: number;
  x: number;
};

type PillTabsTone = "gray" | "surface";

const PILL_TAB_STYLE_PROPERTIES = [
  "--pill-tab-x",
  "--pill-tab-width",
  "--pill-tab-scale-x",
  "--pill-tab-scale-y",
  "--pill-tab-organic-top",
  "--pill-tab-organic-right",
  "--pill-tab-organic-bottom",
  "--pill-tab-organic-left",
  "--pill-tab-organic-scale",
  "--pill-tab-organic-origin",
  "opacity",
] as const;

function readPositivePx(element: HTMLElement, property: string) {
  const value = Number.parseFloat(getComputedStyle(element).getPropertyValue(property));
  return Number.isFinite(value) && value > 0 ? value : null;
}

export function PillTabs<TId extends string = string>({
  activeId,
  ariaLabel,
  className,
  items,
  onSelect,
  tone = "surface",
}: {
  activeId: TId;
  ariaLabel: string;
  className?: string;
  items: Array<PillTabItem<TId>>;
  onSelect: (id: TId, index: number) => void;
  tone?: PillTabsTone;
}) {
  const navRef = useRef<HTMLElement | null>(null);
  const styleId = useId().replace(/:/g, "");
  const tabRefs = useRef(new Map<TId, HTMLButtonElement>());
  const [geometry, setGeometry] = useState<PillGeometry | null>(null);

  usePillTabsMotion({
    geometry,
    styleSelector: `.pill-tabs[data-pill-tabs-id="${styleId}"] .pill-tabs-pill`,
  });

  const setTabRef = useCallback((id: TId, node: HTMLButtonElement | null) => {
    if (node) tabRefs.current.set(id, node);
    else tabRefs.current.delete(id);
  }, []);

  const focusAndSelect = useCallback((index: number) => {
    const item = items[index];
    if (!item) return;
    onSelect(item.id, index);
    window.requestAnimationFrame(() => tabRefs.current.get(item.id)?.focus());
  }, [items, onSelect]);

  const handleKeyDown = useCallback((event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    if (items.length === 0) return;
    const lastIndex = items.length - 1;
    const nextIndexByKey: Record<string, number> = {
      ArrowLeft: index <= 0 ? lastIndex : index - 1,
      ArrowRight: index >= lastIndex ? 0 : index + 1,
      End: lastIndex,
      Home: 0,
    };
    const nextIndex = nextIndexByKey[event.key];
    if (nextIndex === undefined) return;
    event.preventDefault();
    focusAndSelect(nextIndex);
  }, [focusAndSelect, items.length]);

  const measureActiveTab = useCallback(() => {
    const nav = navRef.current;
    const activeTab = tabRefs.current.get(activeId);
    if (!nav || !activeTab) {
      setGeometry(null);
      return;
    }
    const navRect = nav.getBoundingClientRect();
    const tabRect = activeTab.getBoundingClientRect();
    const measuredWidth = Math.max(0, tabRect.width);
    const maxPillWidth = readPositivePx(nav, "--pill-tab-max-width");
    const width = maxPillWidth ? Math.min(measuredWidth, maxPillWidth) : measuredWidth;
    const nextGeometry = {
      width,
      x: Math.max(0, tabRect.left - navRect.left + (measuredWidth - width) / 2),
    };
    setGeometry((current) => {
      if (current && Math.abs(current.x - nextGeometry.x) < 0.5 && Math.abs(current.width - nextGeometry.width) < 0.5) {
        return current;
      }
      return nextGeometry;
    });
  }, [activeId]);

  useEffect(() => {
    measureActiveTab();
    const nav = navRef.current;
    if (!nav) return;

    if (typeof ResizeObserver === "undefined") {
      window.addEventListener("resize", measureActiveTab);
      return () => window.removeEventListener("resize", measureActiveTab);
    }

    const observer = new ResizeObserver(measureActiveTab);
    observer.observe(nav);
    for (const tab of tabRefs.current.values()) observer.observe(tab);
    window.addEventListener("resize", measureActiveTab);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", measureActiveTab);
    };
  }, [items, measureActiveTab]);

  return (
    <nav
      aria-label={ariaLabel}
      className={classNames("pill-tabs", className)}
      data-ui-surface={tone === "gray" ? "gray" : "white"}
      data-pill-tabs-id={styleId}
      ref={navRef}
      role="tablist"
    >
      <span aria-hidden="true" className="pill-tabs-backdrop" />
      {items.length > 0 ? (
        <span aria-hidden="true" className="pill-tabs-pill" />
      ) : null}
      {items.map((item, index) => {
        const Icon = item.icon;
        const active = item.id === activeId;
        return (
          <button
            aria-controls={item.panelId}
            aria-selected={active}
            className={classNames("pill-tab", active && "active")}
            id={item.panelId ? `${item.panelId}-tab` : undefined}
            key={item.id}
            onKeyDown={(event) => handleKeyDown(event, index)}
            onClick={() => onSelect(item.id, index)}
            ref={(node) => setTabRef(item.id, node)}
            role="tab"
            tabIndex={active ? 0 : -1}
            type="button"
          >
            {Icon ? <Icon aria-hidden="true" size={16} /> : null}
            <span>{item.label}</span>
          </button>
        );
      })}
    </nav>
  );
}

function usePillTabsMotion({
  geometry,
  styleSelector,
}: {
  geometry: PillGeometry | null;
  styleSelector: string;
}) {
  const reduceMotion = useReducedMotion();
  const x = useMotionValue(geometry?.x ?? 0);
  const width = useMotionValue(geometry?.width ?? 0);
  const velocity = useVelocity(x);
  const jellyVelocity = useSpring(velocity, { damping: 28, mass: 0.54, stiffness: 185 });
  const acceleration = useVelocity(velocity);
  const jellyAcceleration = useSpring(acceleration, { damping: 30, mass: 0.42, stiffness: 260 });
  const snap = useMotionValue(0);
  const jellySnap = useSpring(snap, { damping: 30, mass: 0.58, stiffness: 200 });
  const widthVelocity = useVelocity(width);
  const jellyWidthVelocity = useSpring(widthVelocity, { damping: 32, mass: 0.42, stiffness: 220 });
  const targetX = geometry?.x ?? 0;
  const targetWidth = geometry?.width ?? 0;
  const organic = useTransform([jellyVelocity, jellyAcceleration, jellySnap, jellyWidthVelocity], ([velocityValue, accelerationValue, snapValue, widthVelocityValue]) => {
    if (reduceMotion) return 0;
    const v = typeof velocityValue === "number" ? velocityValue : 0;
    const a = typeof accelerationValue === "number" ? accelerationValue : 0;
    const snapAmount = typeof snapValue === "number" ? snapValue : 0;
    const widthV = typeof widthVelocityValue === "number" ? widthVelocityValue : 0;
    const intensity = Math.min(Math.pow(Math.abs(v) / 880, 0.8), 1);
    const accelerationIntensity = Math.min(Math.pow(Math.abs(a) / 18500, 0.68), 1);
    const widthIntensity = Math.min(Math.pow(Math.abs(widthV) / 620, 0.7), 1);
    return Math.min(0.44, intensity * 0.26 + accelerationIntensity * 0.16 + widthIntensity * 0.08 + snapAmount * 0.22);
  });
  const organicLeft = useTransform([organic, jellyVelocity], ([organicValue, velocityValue]) => {
    const stretch = typeof organicValue === "number" ? organicValue : 0;
    const v = typeof velocityValue === "number" ? velocityValue : 0;
    return v < -2 ? `${stretch * -14}px` : "0px";
  });
  const organicRight = useTransform([organic, jellyVelocity], ([organicValue, velocityValue]) => {
    const stretch = typeof organicValue === "number" ? organicValue : 0;
    const v = typeof velocityValue === "number" ? velocityValue : 0;
    return v > 2 ? `${stretch * -14}px` : "0px";
  });
  const organicSide = useTransform(organic, (value) => `${value * -4}px`);
  const organicScale = useTransform(organic, (value) => 1 + value * 0.2);
  const organicOrigin = useTransform(jellyVelocity, (value) => value < -2 ? "center right" : "center left");
  const scaleX = useTransform([jellyVelocity, jellyAcceleration, jellySnap, jellyWidthVelocity], ([velocityValue, accelerationValue, snapValue, widthVelocityValue]) => {
    if (reduceMotion) return 1;
    const v = typeof velocityValue === "number" ? velocityValue : 0;
    const a = typeof accelerationValue === "number" ? accelerationValue : 0;
    const snapAmount = typeof snapValue === "number" ? snapValue : 0;
    const widthV = typeof widthVelocityValue === "number" ? widthVelocityValue : 0;
    const intensity = Math.min(Math.pow(Math.abs(v) / 920, 0.82), 1);
    const accelerationIntensity = Math.min(Math.pow(Math.abs(a) / 18500, 0.68), 1);
    const widthIntensity = Math.min(Math.pow(Math.abs(widthV) / 560, 0.7), 1);
    return 1 - intensity * 0.1 - accelerationIntensity * 0.055 - widthIntensity * 0.035 - snapAmount * 0.07;
  });
  const scaleY = useTransform([jellyVelocity, jellyAcceleration, jellySnap], ([velocityValue, accelerationValue, snapValue]) => {
    if (reduceMotion) return 1;
    const v = typeof velocityValue === "number" ? velocityValue : 0;
    const a = typeof accelerationValue === "number" ? accelerationValue : 0;
    const snapAmount = typeof snapValue === "number" ? snapValue : 0;
    const intensity = Math.min(Math.pow(Math.abs(v) / 980, 0.82), 1);
    const accelerationIntensity = Math.min(Math.pow(Math.abs(a) / 19000, 0.68), 1);
    return 1 - intensity * 0.055 - accelerationIntensity * 0.032 - snapAmount * 0.035;
  });

  const writeCss = useCallback((rule: CSSStyleRule) => {
    setRuleStyleProperties(rule, {
      "--pill-tab-x": `${x.get()}px`,
      "--pill-tab-width": `${width.get()}px`,
      "--pill-tab-scale-x": String(scaleX.get()),
      "--pill-tab-scale-y": String(scaleY.get()),
      "--pill-tab-organic-top": organicSide.get(),
      "--pill-tab-organic-right": organicRight.get(),
      "--pill-tab-organic-bottom": organicSide.get(),
      "--pill-tab-organic-left": organicLeft.get(),
      "--pill-tab-organic-scale": String(organicScale.get()),
      "--pill-tab-organic-origin": organicOrigin.get(),
      opacity: geometry ? "1" : "0",
    });
  }, [geometry, organicLeft, organicOrigin, organicRight, organicScale, organicSide, scaleX, scaleY, width, x]);

  const scheduleCssWrite = useRafCssRuleWriter(styleSelector, writeCss, PILL_TAB_STYLE_PROPERTIES);

  useMotionValueEvent(x, "change", scheduleCssWrite);
  useMotionValueEvent(width, "change", scheduleCssWrite);
  useMotionValueEvent(scaleX, "change", scheduleCssWrite);
  useMotionValueEvent(scaleY, "change", scheduleCssWrite);
  useMotionValueEvent(organicLeft, "change", scheduleCssWrite);
  useMotionValueEvent(organicRight, "change", scheduleCssWrite);
  useMotionValueEvent(organicSide, "change", scheduleCssWrite);
  useMotionValueEvent(organicOrigin, "change", scheduleCssWrite);
  useMotionValueEvent(organicScale, "change", scheduleCssWrite);

  useEffect(() => {
    if (reduceMotion) {
      x.set(targetX);
      width.set(targetWidth);
      snap.set(0);
      scheduleCssWrite();
      return;
    }

    const travel = Math.abs(targetX - x.get());
    if (geometry && travel > 0.5) {
      const tabWidth = Math.max(1, geometry.width);
      const travelTabs = Math.min(3, travel / tabWidth);
      const nextSnap = Math.max(0.12, Math.min(0.28, 0.28 - travelTabs * 0.03));
      snap.set(nextSnap);
      animate(snap, 0, { damping: 30, mass: 0.58, stiffness: 200, type: "spring" });
    }

    const xControls = animate(x, targetX, { damping: 32, mass: 1, stiffness: 300, type: "spring" });
    const widthControls = animate(width, targetWidth, { damping: 36, mass: 0.86, stiffness: 310, type: "spring" });
    return () => {
      xControls.stop();
      widthControls.stop();
    };
  }, [geometry, reduceMotion, scheduleCssWrite, snap, targetWidth, targetX, width, x]);
}
