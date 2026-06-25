"use client";

import { useCallback, useEffect, useLayoutEffect, useRef, type ReactNode } from "react";
import { BrandLogo } from "./BrandLogo";
import { PillSidebarNav, type PillNavItem } from "./PillSidebarNav";
import { classNames } from "./classNames";

export type UiBrand = {
  ariaLabel?: string;
  href?: string;
  subtitle?: string | null;
  title?: string;
};

export type UiShellProps<TId extends string = string> = {
  activeId: TId;
  brand: UiBrand;
  busy?: boolean;
  canvas?: ReactNode;
  children: ReactNode;
  className?: string;
  headerClassName?: string;
  navClassName?: string;
  navItems: Array<PillNavItem<TId>>;
  navLabel: string;
  onSelect: (id: TId) => void;
  sceneClassName?: string;
  sceneLabel?: string;
  sheetClassName?: string;
  stageClassName?: string;
};

export function UiShell<TId extends string = string>({
  activeId,
  brand,
  busy = false,
  canvas = <div className="ui-canvas" />,
  children,
  className,
  headerClassName,
  navClassName,
  navItems,
  navLabel,
  onSelect,
  sceneClassName,
  sceneLabel,
  sheetClassName,
  stageClassName,
}: UiShellProps<TId>) {
  const scrollRootRef = useRef<HTMLElement | null>(null);
  const activeIdRef = useRef(activeId);
  const scrollPositionsRef = useRef(new Map<TId, number>());
  const settledScrollPositionsRef = useRef(new Map<TId, number>());
  const scrollSettleTimerRef = useRef<number | null>(null);
  const scrollStorageScope = sceneLabel ?? navLabel;

  const saveActiveScroll = useCallback((id: TId, preferSettled = false) => {
    const root = scrollRootRef.current;
    if (!root) return;
    const top = preferSettled ? settledScrollPositionsRef.current.get(id) ?? root.scrollTop : root.scrollTop;
    scrollPositionsRef.current.set(id, top);
    writeStoredShellScroll(scrollStorageScope, id, top);
  }, [scrollStorageScope]);

  const restoreActiveScroll = useCallback((id: TId) => {
    const root = scrollRootRef.current;
    if (!root) return;
    const storedTop = scrollPositionsRef.current.get(id) ?? readStoredShellScroll(scrollStorageScope, id) ?? 0;
    root.scrollTop = Math.max(0, storedTop);
  }, [scrollStorageScope]);

  useEffect(() => {
    const root = scrollRootRef.current;
    if (!root) return undefined;

    const onScroll = () => {
      const id = activeIdRef.current;
      const top = root.scrollTop;
      scrollPositionsRef.current.set(id, top);
      if (scrollSettleTimerRef.current !== null) window.clearTimeout(scrollSettleTimerRef.current);
      scrollSettleTimerRef.current = window.setTimeout(() => {
        settledScrollPositionsRef.current.set(id, top);
      }, 90);
    };
    const onPageHide = () => saveActiveScroll(activeIdRef.current);

    root.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("pagehide", onPageHide);
    return () => {
      if (scrollSettleTimerRef.current !== null) window.clearTimeout(scrollSettleTimerRef.current);
      root.removeEventListener("scroll", onScroll);
      window.removeEventListener("pagehide", onPageHide);
    };
  }, [saveActiveScroll]);

  useLayoutEffect(() => {
    activeIdRef.current = activeId;
    restoreActiveScroll(activeId);
    const restoreFrame = window.requestAnimationFrame(() => restoreActiveScroll(activeId));
    return () => window.cancelAnimationFrame(restoreFrame);
  }, [activeId, restoreActiveScroll]);

  const handleSelect = useCallback((id: TId) => {
    if (id !== activeIdRef.current) saveActiveScroll(activeIdRef.current, true);
    onSelect(id);
  }, [onSelect, saveActiveScroll]);

  return (
    <main aria-busy={busy} className={classNames("shell", "ui-shell", className)} ref={scrollRootRef}>
      {canvas}
      <header className={classNames("ui-shell-header-surface", "ui-shell-header", headerClassName)}>
        <BrandLogo ariaLabel={brand.ariaLabel} href={brand.href} subtitle={brand.subtitle} title={brand.title} />
      </header>

      <div className={classNames("ui-shell-stage", stageClassName)}>
        <PillSidebarNav activeId={activeId} ariaLabel={navLabel} className={classNames("ui-shell-navbar", navClassName)} items={navItems} onSelect={handleSelect} />
        <section aria-label={sceneLabel ?? navLabel} className={classNames("ui-shell-scene", sceneClassName)} data-scroll-root="" tabIndex={0}>
          <div className={classNames("ui-shell-sheet", sheetClassName)}>{children}</div>
        </section>
      </div>
    </main>
  );
}

function readStoredShellScroll(scope: string, id: string): number | null {
  if (typeof window === "undefined") return null;
  try {
    const value = window.sessionStorage.getItem(getShellScrollStorageKey(scope, id));
    if (!value) return null;
    const top = Number(value);
    return Number.isFinite(top) ? top : null;
  } catch {
    return null;
  }
}

function writeStoredShellScroll(scope: string, id: string, top: number) {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.setItem(getShellScrollStorageKey(scope, id), String(Math.max(0, Math.round(top))));
  } catch {
    // Storage can be unavailable in hardened/private contexts; in-memory restore still works.
  }
}

function getShellScrollStorageKey(scope: string, id: string) {
  return `stexor:ui-shell-scroll:${scope}:${id}`;
}
