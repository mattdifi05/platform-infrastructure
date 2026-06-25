"use client";

import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from "react";
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
import { Button } from "./Button";
import { classNames } from "./classNames";
import { setRuleStyleProperties, useRafCssRuleWriter } from "./styleMotion";

const defaultPillStep = 54;
const DOCK_PILL_STYLE_PROPERTIES = [
  "--dock-pill-y",
  "--dock-pill-scale-x",
  "--dock-pill-organic-top",
  "--dock-pill-organic-right",
  "--dock-pill-organic-bottom",
  "--dock-pill-organic-left",
  "--dock-pill-organic-scale",
  "--dock-pill-organic-origin",
] as const;

export type PillNavItem<TId extends string = string> = {
  disabled?: boolean;
  icon?: IconType;
  id: TId;
  label: ReactNode;
  title?: string;
};

export function PillSidebarNav<TId extends string = string>({
  activeId,
  ariaLabel,
  className,
  itemClassName = "nav-item",
  items,
  onSelect,
  pillClassName = "nav-active-pill",
  step = defaultPillStep,
}: {
  activeId: TId;
  ariaLabel: string;
  className?: string;
  itemClassName?: string;
  items: Array<PillNavItem<TId>>;
  onSelect: (id: TId, index: number) => void;
  pillClassName?: string;
  step?: number;
}) {
  const activeIndex = Math.max(0, items.findIndex((item) => item.id === activeId));
  const styleId = useId().replace(/:/g, "");
  const { getButtonProps, navRef, visualIndex } = usePillSidebarNavMotion({
    activeIndex,
    itemCount: items.length,
    onSelectIndex: (index) => {
      const item = items[index];
      if (item) onSelect(item.id, index);
    },
    step,
    styleSelector: `.pill-sidebar-nav[data-pill-sidebar-id="${styleId}"] [data-pill-sidebar-pill]`,
  });

  return (
    <aside
      aria-label={ariaLabel}
      className={classNames("ui-shell-navbar-surface", "pill-sidebar-nav", className)}
      data-pill-sidebar-active-index={activeIndex}
      data-pill-sidebar-id={styleId}
      ref={navRef}
    >
      {items.length > 0 ? (
        <span
          aria-hidden="true"
          className={classNames(pillClassName, `active-${visualIndex}`)}
          data-pill-sidebar-pill=""
        />
      ) : null}
      {items.map((item, index) => {
        const Icon = item.icon;
        const selected = item.id === activeId;
        return (
          <Button
            aria-current={selected ? "page" : undefined}
            disabled={item.disabled}
            key={item.id}
            title={item.title}
            variant="plain"
            {...getButtonProps(index, itemClassName)}
          >
            {Icon ? <Icon aria-hidden="true" size={18} /> : null}
            <span>{item.label}</span>
          </Button>
        );
      })}
    </aside>
  );
}

function usePillSidebarNavMotion({
  activeIndex,
  itemCount,
  onSelectIndex,
  step,
  styleSelector,
}: {
  activeIndex: number;
  itemCount: number;
  onSelectIndex: (index: number) => void;
  step: number;
  styleSelector: string;
}) {
  const reduceMotion = useReducedMotion();
  const navRef = useRef<HTMLElement | null>(null);
  const [visualIndex, setVisualIndex] = useState(activeIndex);
  const y = useMotionValue(activeIndex * step);
  const velocity = useVelocity(y);
  const jellyVelocity = useSpring(velocity, { damping: 28, mass: 0.54, stiffness: 185 });
  const acceleration = useVelocity(velocity);
  const jellyAcceleration = useSpring(acceleration, { damping: 30, mass: 0.42, stiffness: 260 });
  const edgePull = useMotionValue(0);
  const jellyEdgePull = useSpring(edgePull, { damping: 26, mass: 0.32, stiffness: 460 });
  const releasePull = useMotionValue(0);
  const jellyReleasePull = useSpring(releasePull, { damping: 30, mass: 0.36, stiffness: 460 });
  const snap = useMotionValue(0);
  const jellySnap = useSpring(snap, { damping: 28, mass: 0.62, stiffness: 190 });
  const press = useMotionValue(0);
  const jellyPress = useSpring(press, { damping: 24, mass: 0.38, stiffness: 220 });
  const dragActive = useMotionValue(0);
  const jellyDragActive = useSpring(dragActive, { damping: 30, mass: 0.32, stiffness: 300 });
  const organic = useTransform([jellyVelocity, jellyAcceleration, jellyEdgePull, jellyReleasePull, jellySnap, jellyPress, jellyDragActive], ([velocityValue, accelerationValue, edgePullValue, releasePullValue, snapValue, pressValue, dragActiveValue]) => {
    if (reduceMotion) return 0;
    const v = typeof velocityValue === "number" ? velocityValue : 0;
    const a = typeof accelerationValue === "number" ? accelerationValue : 0;
    const edge = typeof edgePullValue === "number" ? edgePullValue : 0;
    const release = typeof releasePullValue === "number" ? releasePullValue : 0;
    const snapAmount = typeof snapValue === "number" ? snapValue : 0;
    const pressAmount = typeof pressValue === "number" ? pressValue : 0;
    const dragAmount = typeof dragActiveValue === "number" ? dragActiveValue : 0;
    const intensity = Math.min(Math.pow(Math.abs(v) / 900, 0.78), 1);
    const accelerationIntensity = Math.min(Math.pow(Math.abs(a) / 18000, 0.68), 1);
    const edgeIntensity = Math.min(Math.abs(edge) / 82, 1);
    const releaseIntensity = Math.min(Math.abs(release) / 74, 1);
    const dragPull = dragAmount * pressAmount * 0.3;
    const movingStretch = intensity * 0.3 + accelerationIntensity * 0.22 + releaseIntensity * 0.26 + snapAmount * 0.34;
    const pulledStretch = edgeIntensity * 0.7 + dragPull;
    const maxStretch = edgeIntensity > 0.02 || dragPull > 0.02 ? 0.92 : 0.52;
    return Math.min(maxStretch, movingStretch + pulledStretch);
  });
  const organicTop = useTransform([organic, jellyVelocity, jellyEdgePull, jellyReleasePull], ([organicValue, velocityValue, edgePullValue, releasePullValue]) => {
    const stretch = typeof organicValue === "number" ? organicValue : 0;
    const v = typeof velocityValue === "number" ? velocityValue : 0;
    const edge = typeof edgePullValue === "number" ? edgePullValue : 0;
    const release = typeof releasePullValue === "number" ? releasePullValue : 0;
    return v + edge * 10 + release * 11 < -2 ? `${stretch * -16}px` : "0px";
  });
  const organicBottom = useTransform([organic, jellyVelocity, jellyEdgePull, jellyReleasePull], ([organicValue, velocityValue, edgePullValue, releasePullValue]) => {
    const stretch = typeof organicValue === "number" ? organicValue : 0;
    const v = typeof velocityValue === "number" ? velocityValue : 0;
    const edge = typeof edgePullValue === "number" ? edgePullValue : 0;
    const release = typeof releasePullValue === "number" ? releasePullValue : 0;
    return v + edge * 10 + release * 11 > 2 ? `${stretch * -16}px` : "0px";
  });
  const organicOrigin = useTransform([jellyVelocity, jellyEdgePull, jellyReleasePull], ([velocityValue, edgePullValue, releasePullValue]) => {
    const v = typeof velocityValue === "number" ? velocityValue : 0;
    const edge = typeof edgePullValue === "number" ? edgePullValue : 0;
    const release = typeof releasePullValue === "number" ? releasePullValue : 0;
    return v + edge * 10 + release * 11 < -2 ? "center bottom" : "center top";
  });
  const organicSide = useTransform(organic, (value) => `${value * -7}px`);
  const organicScale = useTransform(organic, (value) => 1 + value * 0.23);
  const scaleX = useTransform([jellyVelocity, jellyAcceleration, jellyEdgePull, jellySnap, jellyPress, jellyDragActive], ([velocityValue, accelerationValue, edgePullValue, snapValue, pressValue, dragActiveValue]) => {
    const v = typeof velocityValue === "number" ? velocityValue : 0;
    const a = typeof accelerationValue === "number" ? accelerationValue : 0;
    const edge = typeof edgePullValue === "number" ? edgePullValue : 0;
    const snapAmount = typeof snapValue === "number" ? snapValue : 0;
    const pressAmount = typeof pressValue === "number" ? pressValue : 0;
    const dragAmount = typeof dragActiveValue === "number" ? dragActiveValue : 0;
    const intensity = reduceMotion ? 0 : Math.min(Math.pow(Math.abs(v) / 980, 0.82), 1);
    const accelerationIntensity = reduceMotion ? 0 : Math.min(Math.pow(Math.abs(a) / 19000, 0.68), 1);
    const edgeIntensity = reduceMotion ? 0 : Math.min(Math.abs(edge) / 110, 1);
    return 1 - intensity * 0.105 - accelerationIntensity * 0.06 - edgeIntensity * 0.075 - snapAmount * 0.052 + dragAmount * pressAmount * 0.018;
  });

  const writeCss = useCallback((rule: CSSStyleRule) => {
    setRuleStyleProperties(rule, {
      "--dock-pill-y": `${y.get()}px`,
      "--dock-pill-scale-x": String(scaleX.get()),
      "--dock-pill-organic-top": organicTop.get(),
      "--dock-pill-organic-right": organicSide.get(),
      "--dock-pill-organic-bottom": organicBottom.get(),
      "--dock-pill-organic-left": organicSide.get(),
      "--dock-pill-organic-scale": String(organicScale.get()),
      "--dock-pill-organic-origin": organicOrigin.get(),
    });
  }, [organicBottom, organicOrigin, organicScale, organicSide, organicTop, scaleX, y]);

  const scheduleCssWrite = useRafCssRuleWriter(styleSelector, writeCss, DOCK_PILL_STYLE_PROPERTIES);

  useMotionValueEvent(y, "change", scheduleCssWrite);
  useMotionValueEvent(scaleX, "change", scheduleCssWrite);
  useMotionValueEvent(organicTop, "change", scheduleCssWrite);
  useMotionValueEvent(organicBottom, "change", scheduleCssWrite);
  useMotionValueEvent(organicSide, "change", scheduleCssWrite);
  useMotionValueEvent(organicOrigin, "change", scheduleCssWrite);
  useMotionValueEvent(organicScale, "change", scheduleCssWrite);

  useMotionValueEvent(y, "change", (latest) => {
    const nextIndex = Math.max(0, Math.min(Math.max(0, itemCount - 1), Math.round(latest / step)));
    setVisualIndex((currentIndex) => currentIndex === nextIndex ? currentIndex : nextIndex);
  });

  const animateNav = useCallback((index: number, mode: "select" | "settle" = "select") => {
    const target = index * step;
    if (reduceMotion) {
      y.set(target);
      scheduleCssWrite();
      return;
    }
    const travel = Math.abs(target - y.get());
    if (travel > 0.5) {
      const travelItems = travel / step;
      const baseSnap = mode === "settle"
        ? Math.min(0.24, travelItems * 0.34)
        : Math.max(0.3, Math.min(0.58, 0.58 - travelItems * 0.055 + (travelItems <= 1.15 ? 0.06 : 0)));
      const remainingSnap = Math.max(Math.abs(snap.get()), Math.abs(jellySnap.get()));
      const snapDamping = remainingSnap > 0.08 ? Math.max(0.24, 1 - remainingSnap * 1.4) : 1;
      const nextSnap = mode === "settle" ? baseSnap * snapDamping : Math.max(0.16, baseSnap * snapDamping);
      if (nextSnap > 0.015) {
        snap.set(nextSnap);
        animate(snap, 0, { damping: 29, mass: 0.64, stiffness: 190, type: "spring" });
      }
    }
    animate(y, target, { damping: 32, mass: 1, stiffness: 300, type: "spring" });
  }, [jellySnap, reduceMotion, scheduleCssWrite, snap, step, y]);

  useEffect(() => {
    void animateNav(activeIndex, "select");
  }, [activeIndex, animateNav]);

  const getButtonProps = useCallback((index: number, itemClassName: string) => {
    const visuallySelected = visualIndex === index;
    return {
      className: classNames(itemClassName, visuallySelected && "active"),
      onClick: () => onSelectIndex(index),
    };
  }, [onSelectIndex, visualIndex]);

  return { getButtonProps, navRef, visualIndex };
}
