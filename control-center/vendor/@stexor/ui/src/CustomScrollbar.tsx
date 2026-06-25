"use client";

import { useCallback, useEffect, useId, useRef, useState, type PointerEvent as ReactPointerEvent, type RefObject } from "react";
import { classNames } from "./classNames";
import { clearDynamicCssRule, createDynamicCssRule, cssEscape, setDynamicCssProperties } from "./cssom";

type ScrollMetrics = {
  clientHeight: number;
  maxScroll: number;
  scrollHeight: number;
  scrollTop: number;
  thumbHeight: number;
  trackHeight: number;
};

type DragState = {
  maxScroll: number;
  startScrollTop: number;
  startY: number;
  thumbHeight: number;
  trackHeight: number;
};

export type CustomScrollbarProps = {
  className?: string;
  draggingClassName?: string;
  rootRef?: RefObject<HTMLElement | null>;
  thumbClassName?: string;
  trackClassName?: string;
  visibleClassName?: string;
};

function getScrollRoot() {
  return (
    document.querySelector<HTMLElement>(".ui-experience")
    ?? document.querySelector<HTMLElement>(".ui-shell")
    ?? document.querySelector<HTMLElement>("[data-scroll-root]")
    ?? document.querySelector<HTMLElement>(".shell")
  );
}

function readMetrics(root: HTMLElement | null, track: HTMLDivElement | null): ScrollMetrics | null {
  if (!root || !track) return null;
  const scrollHeight = root.scrollHeight;
  const clientHeight = root.clientHeight;
  const maxScroll = Math.max(0, scrollHeight - clientHeight);
  const trackHeight = track.clientHeight;
  const thumbHeight = maxScroll > 1 ? Math.max(28, (clientHeight / scrollHeight) * trackHeight) : 0;
  return { clientHeight, maxScroll, scrollHeight, scrollTop: root.scrollTop, thumbHeight, trackHeight };
}

export function CustomScrollbar({
  className,
  draggingClassName = "is-scrollbar-dragging",
  rootRef: providedRootRef,
  thumbClassName,
  trackClassName,
  visibleClassName = "visible",
}: CustomScrollbarProps = {}) {
  const scrollbarId = useId();
  const rootRef = useRef<HTMLElement | null>(null);
  const ruleRef = useRef<CSSStyleRule | null>(null);
  const scrollbarRef = useRef<HTMLDivElement | null>(null);
  const listenedRootRef = useRef<HTMLElement | null>(null);
  const trackRef = useRef<HTMLDivElement | null>(null);
  const dragRef = useRef<DragState | null>(null);
  const rafRef = useRef(0);
  const scheduleUpdateRef = useRef<() => void>(() => undefined);
  const [visible, setVisible] = useState(false);

  const setScrollbarVisible = useCallback((nextVisible: boolean) => {
    setVisible(nextVisible);
    const scrollbar = scrollbarRef.current
      ?? document.querySelector<HTMLElement>(`.custom-scrollbar[data-scrollbar-id="${cssEscape(scrollbarId)}"]`);
    scrollbar?.classList.toggle(visibleClassName, nextVisible);
  }, [scrollbarId, visibleClassName]);

  const writeThumb = useCallback((metrics: ScrollMetrics | null) => {
    if (!metrics || metrics.maxScroll <= 1 || metrics.trackHeight <= 0) {
      setScrollbarVisible(false);
      setDynamicCssProperties(ruleRef.current, {
        height: "0px",
        transform: "translate3d(0, 0px, 0)",
      });
      return;
    }

    const travel = Math.max(0, metrics.trackHeight - metrics.thumbHeight);
    const top = travel * (metrics.scrollTop / metrics.maxScroll);
    setScrollbarVisible(true);
    setDynamicCssProperties(ruleRef.current, {
      height: `${metrics.thumbHeight}px`,
      transform: `translate3d(0, ${top}px, 0)`,
    });
  }, [setScrollbarVisible]);

  const update = useCallback(() => {
    rafRef.current = 0;
    const nextRoot = providedRootRef?.current ?? getScrollRoot();
    if (nextRoot && nextRoot !== rootRef.current) rootRef.current = nextRoot;
    if (nextRoot && nextRoot !== listenedRootRef.current) {
      listenedRootRef.current?.removeEventListener("scroll", scheduleUpdateRef.current);
      nextRoot.addEventListener("scroll", scheduleUpdateRef.current, { passive: true });
      listenedRootRef.current = nextRoot;
    }
    writeThumb(readMetrics(rootRef.current, trackRef.current));
  }, [providedRootRef, writeThumb]);

  const scheduleUpdate = useCallback(() => {
    if (rafRef.current) return;
    rafRef.current = window.requestAnimationFrame(update);
  }, [update]);
  scheduleUpdateRef.current = scheduleUpdate;

  useEffect(() => {
    const escapedId = cssEscape(scrollbarId);
    ruleRef.current = createDynamicCssRule(`.custom-scrollbar[data-scrollbar-id="${escapedId}"] .custom-scrollbar-thumb`);
    const schedulePostLayoutUpdate = () => {
      scheduleUpdate();
      window.setTimeout(scheduleUpdate, 0);
      window.setTimeout(scheduleUpdate, 120);
      window.setTimeout(scheduleUpdate, 360);
    };
    rootRef.current = providedRootRef?.current ?? getScrollRoot();
    const root = rootRef.current;
    schedulePostLayoutUpdate();

    document.addEventListener("click", schedulePostLayoutUpdate, true);
    window.addEventListener("hashchange", schedulePostLayoutUpdate);
    window.addEventListener("popstate", schedulePostLayoutUpdate);
    window.addEventListener("resize", scheduleUpdate);

    let observer: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined") {
      observer = new ResizeObserver(scheduleUpdate);
      if (root) observer.observe(root);
      if (trackRef.current) observer.observe(trackRef.current);
    }

    let mutationObserver: MutationObserver | null = null;
    if (root && typeof MutationObserver !== "undefined") {
      mutationObserver = new MutationObserver(scheduleUpdate);
      mutationObserver.observe(root, { attributes: true, characterData: true, childList: true, subtree: true });
    }

    return () => {
      if (rafRef.current) window.cancelAnimationFrame(rafRef.current);
      listenedRootRef.current?.removeEventListener("scroll", scheduleUpdate);
      listenedRootRef.current = null;
      document.removeEventListener("click", schedulePostLayoutUpdate, true);
      window.removeEventListener("hashchange", schedulePostLayoutUpdate);
      window.removeEventListener("popstate", schedulePostLayoutUpdate);
      window.removeEventListener("resize", scheduleUpdate);
      observer?.disconnect();
      mutationObserver?.disconnect();
      clearDynamicCssRule(ruleRef.current);
      document.documentElement.classList.remove(draggingClassName);
      document.body.classList.remove(draggingClassName);
    };
  }, [draggingClassName, providedRootRef, scheduleUpdate, scrollbarId]);

  useEffect(() => {
    function onPointerMove(event: PointerEvent) {
      const drag = dragRef.current;
      const root = rootRef.current;
      if (!drag || !root) return;
      const availableTrack = Math.max(1, drag.trackHeight - drag.thumbHeight);
      const delta = event.clientY - drag.startY;
      root.scrollTop = Math.max(0, Math.min(drag.maxScroll, drag.startScrollTop + (delta / availableTrack) * drag.maxScroll));
      scheduleUpdate();
    }

    function onPointerUp() {
      if (!dragRef.current) return;
      dragRef.current = null;
      document.documentElement.classList.remove(draggingClassName);
      document.body.classList.remove(draggingClassName);
    }

    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", onPointerUp);
    window.addEventListener("pointercancel", onPointerUp);
    return () => {
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", onPointerUp);
      window.removeEventListener("pointercancel", onPointerUp);
    };
  }, [draggingClassName, scheduleUpdate]);

  const beginDrag = useCallback((event: ReactPointerEvent<HTMLDivElement>) => {
    const metrics = readMetrics(rootRef.current, trackRef.current);
    if (!metrics || metrics.maxScroll <= 1) return;
    event.preventDefault();
    document.documentElement.classList.add(draggingClassName);
    document.body.classList.add(draggingClassName);
    dragRef.current = {
      maxScroll: metrics.maxScroll,
      startScrollTop: metrics.scrollTop,
      startY: event.clientY,
      thumbHeight: metrics.thumbHeight,
      trackHeight: metrics.trackHeight,
    };
  }, [draggingClassName]);

  return (
    <div aria-hidden="true" className={classNames("custom-scrollbar", className, visible && visibleClassName)} data-scrollbar-id={scrollbarId} ref={scrollbarRef}>
      <div className={classNames("custom-scrollbar-track", trackClassName)} ref={trackRef}>
        <div className={classNames("custom-scrollbar-thumb", thumbClassName)} onPointerDown={beginDrag} />
      </div>
    </div>
  );
}
