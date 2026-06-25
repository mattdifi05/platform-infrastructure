"use client";

import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { AlertTriangle, BadgeCheck, Bell, CircleInfo, X, type IconType } from "./icons";
import { uiMotionDurations } from "./motion-tokens";
import { useDynamicCssProperties } from "./styleMotion";

export type UiPopupTone = "danger" | "good" | "info" | "neutral" | "warning";
export type UiPopupDuration = "short" | "normal" | "long" | "manual";

export type UiPopupOptions = {
  closeLabel?: string;
  copy?: ReactNode;
  duration?: UiPopupDuration;
  icon?: IconType;
  id?: string;
  title: ReactNode;
  tone?: UiPopupTone;
};

export type UiPopupController = {
  clearPopups: () => void;
  dismissPopup: (id: string) => void;
  showPopup: (popup: UiPopupOptions) => string;
};

type UiPopupState = "closing" | "open" | "opening";
type UiPopupRecord = Required<Pick<UiPopupOptions, "duration" | "id" | "tone">> & Omit<UiPopupOptions, "duration" | "id" | "tone"> & {
  styleId: string;
  state: UiPopupState;
};
type UiPopupTextMetrics = {
  timerMs: number;
};
type UiPopupMarqueeState = {
  copy: boolean;
  distance: number;
  durationMs: number;
  timerMs: number;
  title: boolean;
};

const UiPopupContext = createContext<UiPopupController | null>(null);

const popupDurationMs: Record<Exclude<UiPopupDuration, "manual">, number> = {
  long: 6800,
  normal: 4200,
  short: 2600,
};
const maxVisiblePopups = 5;
const popupMotionMs = uiMotionDurations.morph;
const popupDynamicStyleProperties = ["--ui-popup-marquee-distance", "--ui-popup-marquee-duration", "--ui-popup-timer-duration"] as const;

let popupIdCounter = 0;

export function UiPopupProvider({
  ariaLabel = "Popup notifications",
  children,
  defaultDuration = "normal",
}: {
  ariaLabel?: string;
  children: ReactNode;
  defaultDuration?: Exclude<UiPopupDuration, "manual">;
}) {
  const [mounted, setMounted] = useState(false);
  const [popups, setPopups] = useState<UiPopupRecord[]>([]);
  const openTimers = useRef(new Map<string, number>());
  const dismissTimers = useRef(new Map<string, number>());
  const removeTimers = useRef(new Map<string, number>());

  const clearTimer = useCallback((timers: Map<string, number>, id: string) => {
    const timer = timers.get(id);
    if (timer === undefined) return;
    window.clearTimeout(timer);
    timers.delete(id);
  }, []);

  const clearPopupTimers = useCallback((id: string) => {
    clearTimer(openTimers.current, id);
    clearTimer(dismissTimers.current, id);
    clearTimer(removeTimers.current, id);
  }, [clearTimer]);

  const dismissPopup = useCallback((id: string) => {
    clearTimer(openTimers.current, id);
    clearTimer(dismissTimers.current, id);
    clearTimer(removeTimers.current, id);
    setPopups((current) => current.map((popup) => popup.id === id ? { ...popup, state: "closing" } : popup));
    removeTimers.current.set(id, window.setTimeout(() => {
      removeTimers.current.delete(id);
      setPopups((current) => current.filter((popup) => popup.id !== id));
    }, popupMotionMs));
  }, [clearTimer]);

  const scheduleDismissPopup = useCallback((id: string, durationMs: number) => {
    clearTimer(dismissTimers.current, id);
    dismissTimers.current.set(id, window.setTimeout(() => dismissPopup(id), durationMs));
  }, [clearTimer, dismissPopup]);

  const updatePopupTextMetrics = useCallback((id: string, metrics: UiPopupTextMetrics) => {
    let nextTimerMs = 0;
    setPopups((current) => current.map((popup) => {
      if (popup.id !== id || popup.duration === "manual") return popup;
      const baseDurationMs = popupDurationMs[popup.duration];
      nextTimerMs = Math.max(baseDurationMs, metrics.timerMs);
      return popup;
    }));
    if (nextTimerMs > 0) scheduleDismissPopup(id, nextTimerMs);
  }, [scheduleDismissPopup]);

  const showPopup = useCallback((popup: UiPopupOptions) => {
    const counter = popupIdCounter++;
    const id = popup.id ?? `ui-popup-${Date.now()}-${counter}`;
    const duration = popup.duration ?? defaultDuration;
    clearPopupTimers(id);
    setPopups((current) => {
      const nextPopups = [
        ...current.filter((item) => item.id !== id),
        {
          ...popup,
          duration,
          id,
          styleId: `ui-popup-style-${counter}`,
          state: "opening" as const,
          tone: popup.tone ?? "info",
        },
      ];
      return nextPopups.slice(-maxVisiblePopups);
    });
    openTimers.current.set(id, window.setTimeout(() => {
      openTimers.current.delete(id);
      setPopups((current) => current.map((item) => item.id === id ? { ...item, state: "open" } : item));
    }, popupMotionMs));
    if (duration !== "manual") {
      scheduleDismissPopup(id, popupDurationMs[duration]);
    }
    return id;
  }, [clearPopupTimers, defaultDuration, scheduleDismissPopup]);

  useEffect(() => {
    const visibleIds = new Set(popups.map((popup) => popup.id));
    for (const timers of [openTimers.current, dismissTimers.current, removeTimers.current]) {
      for (const id of timers.keys()) {
        if (!visibleIds.has(id)) clearTimer(timers, id);
      }
    }
  }, [clearTimer, popups]);

  const clearPopups = useCallback(() => {
    setPopups((current) => {
      for (const popup of current) {
        clearTimer(openTimers.current, popup.id);
        clearTimer(dismissTimers.current, popup.id);
        clearTimer(removeTimers.current, popup.id);
        removeTimers.current.set(popup.id, window.setTimeout(() => {
          removeTimers.current.delete(popup.id);
          setPopups((items) => items.filter((item) => item.id !== popup.id));
        }, popupMotionMs));
      }
      return current.map((popup) => ({ ...popup, state: "closing" }));
    });
  }, [clearTimer]);

  useEffect(() => {
    setMounted(true);
    return () => {
      for (const timers of [openTimers.current, dismissTimers.current, removeTimers.current]) {
        for (const timer of timers.values()) window.clearTimeout(timer);
        timers.clear();
      }
    };
  }, []);

  const value = useMemo<UiPopupController>(() => ({ clearPopups, dismissPopup, showPopup }), [clearPopups, dismissPopup, showPopup]);

  return (
    <UiPopupContext.Provider value={value}>
      {children}
      {mounted ? createPortal(<UiPopupViewport ariaLabel={ariaLabel} dismissPopup={dismissPopup} onTextMetrics={updatePopupTextMetrics} popups={popups} />, document.body) : null}
    </UiPopupContext.Provider>
  );
}

export function useUiPopup() {
  const context = useContext(UiPopupContext);
  if (!context) throw new Error("useUiPopup must be used inside UiPopupProvider");
  return context;
}

function UiPopupViewport({
  ariaLabel,
  dismissPopup,
  onTextMetrics,
  popups,
}: {
  ariaLabel: string;
  dismissPopup: (id: string) => void;
  onTextMetrics: (id: string, metrics: UiPopupTextMetrics) => void;
  popups: UiPopupRecord[];
}) {
  if (popups.length === 0) return null;

  return (
    <div aria-label={ariaLabel} aria-live="polite" className="ui-popup-viewport" role="region">
      {popups.map((popup) => (
        <UiPopupCard dismissPopup={dismissPopup} key={popup.id} onTextMetrics={onTextMetrics} popup={popup} />
      ))}
    </div>
  );
}

function UiPopupCard({
  dismissPopup,
  onTextMetrics,
  popup,
}: {
  dismissPopup: (id: string) => void;
  onTextMetrics: (id: string, metrics: UiPopupTextMetrics) => void;
  popup: UiPopupRecord;
}) {
  const Icon = popup.icon ?? iconForTone(popup.tone);
  const role = popup.tone === "danger" ? "alert" : "status";
  const titleRef = useRef<HTMLElement | null>(null);
  const copyRef = useRef<HTMLElement | null>(null);
  const [marquee, setMarquee] = useState<UiPopupMarqueeState | null>(null);
  const styleSelector = `.ui-popup-card[data-ui-popup-style-id="${popup.styleId}"]`;
  useDynamicCssProperties(
    styleSelector,
    marquee
      ? {
          "--ui-popup-marquee-distance": `${marquee.distance}px`,
          "--ui-popup-marquee-duration": `${marquee.durationMs}ms`,
          "--ui-popup-timer-duration": `${marquee.timerMs}ms`,
        }
      : {},
    popupDynamicStyleProperties,
    Boolean(marquee),
  );

  useLayoutEffect(() => {
    const titleOverflow = measurePopupTextOverflow(titleRef.current);
    const copyOverflow = measurePopupTextOverflow(copyRef.current);
    const distance = Math.max(titleOverflow, copyOverflow);
    if (distance <= 2) {
      setMarquee(null);
      return;
    }

    const titleScrollable = titleOverflow > 2;
    const copyScrollable = copyOverflow > 2;
    const durationMs = Math.round(clampNumber((distance + 18) * 34 + 2600, 5200, 15000));
    const timerMs = durationMs + popupMotionMs + 900;
    setMarquee((current) => (
      current &&
      current.title === titleScrollable &&
      current.copy === copyScrollable &&
      Math.abs(current.distance - distance) < 1 &&
      current.durationMs === durationMs &&
      current.timerMs === timerMs
        ? current
        : { copy: copyScrollable, distance, durationMs, timerMs, title: titleScrollable }
    ));
    onTextMetrics(popup.id, { timerMs });
  }, [onTextMetrics, popup.copy, popup.id, popup.title]);

  return (
    <article
      aria-atomic="true"
      className="ui-popup-card"
      data-ui-popup-duration={popup.duration}
      data-ui-popup-marquee={marquee ? "true" : "false"}
      data-ui-popup-style-id={popup.styleId}
      data-ui-popup-state={popup.state}
      data-ui-popup-tone={popup.tone}
      data-ui-surface="white"
      role={role}
    >
      <div className="ui-popup-body">
        <span aria-hidden="true" className="ui-popup-icon">
          <Icon size={16} />
        </span>
        <div className="ui-popup-copy">
          <strong className="ui-popup-line" data-ui-popup-overflow={marquee?.title ? "true" : "false"} ref={titleRef}>
            <span className="ui-popup-line-track">{popup.title}</span>
          </strong>
          {popup.copy ? (
            <span className="ui-popup-line" data-ui-popup-overflow={marquee?.copy ? "true" : "false"} ref={copyRef}>
              <span className="ui-popup-line-track">{popup.copy}</span>
            </span>
          ) : null}
        </div>
        <button aria-label={popup.closeLabel ?? "Close popup"} className="ui-popup-close" onClick={() => dismissPopup(popup.id)} type="button">
          <X size={14} />
        </button>
      </div>
      {popup.duration === "manual" ? null : <span aria-hidden="true" className="ui-popup-timer" />}
    </article>
  );
}

function measurePopupTextOverflow(element: HTMLElement | null) {
  if (!element) return 0;
  const track = element.querySelector<HTMLElement>(".ui-popup-line-track");
  if (!track) return 0;
  return Math.max(0, track.scrollWidth - element.clientWidth);
}

function clampNumber(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}

function iconForTone(tone: UiPopupTone): IconType {
  if (tone === "danger") return AlertTriangle;
  if (tone === "good") return BadgeCheck;
  if (tone === "neutral") return Bell;
  if (tone === "warning") return AlertTriangle;
  return CircleInfo;
}
