"use client";

import {
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent,
  type MouseEvent,
  type ReactNode,
  type RefCallback,
} from "react";
import { createPortal } from "react-dom";
import { classNames } from "./classNames";
import { cssEscape } from "./cssom";
import { uiMotionDurations } from "./motion-tokens";
import { uiOverlayStack, type UiOverlayType } from "./OverlayManager";
import { useDynamicCssProperties } from "./styleMotion";

export type UiOverlayPlacement = "bottom" | "center" | "left" | "right" | "top";
export type UiOverlayMotion = "default" | "morph";
type UiOverlaySurfaceContext = "gray" | "white";

export type UiOverlayRenderProps = {
  closeOverlay: () => void;
  isOpen: boolean;
  openOverlay: () => void;
  panelId: string;
  titleId: string;
  toggleOverlay: () => void;
  triggerProps: {
    "aria-controls": string;
    "aria-expanded": boolean;
    "aria-haspopup": "dialog" | "menu" | "true";
    onClick: (event: MouseEvent<HTMLElement>) => void;
    onKeyDown: (event: KeyboardEvent<HTMLElement>) => void;
    ref: RefCallback<HTMLElement>;
  };
};

export type UiOverlayFrameProps = {
  children: ReactNode | ((props: UiOverlayRenderProps) => ReactNode);
  autoFocusPanel?: boolean;
  className?: string;
  closeOnOutside?: boolean;
  label?: string;
  modal?: boolean;
  motion?: UiOverlayMotion;
  onOpenChange: (open: boolean) => void;
  open: boolean;
  panelClassName?: string;
  placement?: UiOverlayPlacement;
  restoreFocus?: boolean;
  role?: "dialog" | "menu";
  surface?: UiOverlaySurfaceContext;
  title?: ReactNode;
  trigger: (props: UiOverlayRenderProps) => ReactNode;
  type: UiOverlayType;
};

export type PopoverProps = Omit<UiOverlayFrameProps, "modal" | "role" | "type">;
export type DropdownProps = Omit<UiOverlayFrameProps, "modal" | "role" | "type">;

const overlayAnchorProperties = [
  "--ui-overlay-anchor-left",
  "--ui-overlay-anchor-top",
  "--ui-overlay-anchor-width",
] as const;
type UiOverlayVisualState = "closed" | "closing" | "open" | "opening";
const closingDurationMs = uiMotionDurations.overlay;

export function Popover(props: PopoverProps) {
  return <UiOverlayFrame {...props} role="dialog" type="popover" />;
}

export function Dropdown(props: DropdownProps) {
  return <UiOverlayFrame {...props} role="menu" type="dropdown" />;
}

export function UiOverlayFrame({
  autoFocusPanel = true,
  children,
  className,
  closeOnOutside = true,
  label,
  modal = false,
  motion = "default",
  onOpenChange,
  open,
  panelClassName,
  placement = modal ? "right" : "bottom",
  restoreFocus = true,
  role = "dialog",
  surface,
  title,
  trigger,
  type,
}: UiOverlayFrameProps) {
  const generatedId = useId().replace(/:/g, "");
  const layerId = `ui-overlay-${generatedId}`;
  const panelId = `${layerId}-panel`;
  const titleId = `${layerId}-title`;
  const [mounted, setMounted] = useState(open);
  const [overlayState, setOverlayState] = useState<UiOverlayVisualState>(open ? "open" : "closed");
  const layerRef = useRef<HTMLDivElement | null>(null);
  const panelRef = useRef<HTMLElement | null>(null);
  const triggerRef = useRef<HTMLElement | null>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);
  const closeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const openFrameRef = useRef<number | null>(null);
  const openSecondFrameRef = useRef<number | null>(null);
  const [anchorProperties, setAnchorProperties] = useState<Record<string, string | undefined>>({});
  const [surfaceContext, setSurfaceContext] = useState<UiOverlaySurfaceContext | undefined>(undefined);
  useDynamicCssProperties(
    `.ui-overlay-layer[data-ui-overlay-layer="${cssEscape(layerId)}"]`,
    anchorProperties,
    overlayAnchorProperties,
  );

  function updateAnchorStyle() {
    const triggerNode = triggerRef.current;
    updateSurfaceContext(triggerNode);
    if (!triggerNode || modal || typeof window === "undefined") return;
    const rect = triggerNode.getBoundingClientRect();
    setAnchorProperties({
      "--ui-overlay-anchor-left": `${rect.left}px`,
      "--ui-overlay-anchor-top": `${placement === "top" ? rect.top : rect.bottom}px`,
      "--ui-overlay-anchor-width": `${rect.width}px`,
    });
  }

  function updateSurfaceContext(triggerNode: HTMLElement | null) {
    const nextContext = getNearestSurfaceContext(triggerNode);
    setSurfaceContext((current) => (current === nextContext ? current : nextContext));
  }

  function clearCloseTimer() {
    if (!closeTimerRef.current) return;
    clearTimeout(closeTimerRef.current);
    closeTimerRef.current = null;
  }

  function clearOpenFrames() {
    if (openFrameRef.current !== null) cancelAnimationFrame(openFrameRef.current);
    if (openSecondFrameRef.current !== null) cancelAnimationFrame(openSecondFrameRef.current);
    openFrameRef.current = null;
    openSecondFrameRef.current = null;
  }

  function openOverlay() {
    returnFocusRef.current = triggerRef.current ?? (document.activeElement instanceof HTMLElement ? document.activeElement : null);
    updateAnchorStyle();
    onOpenChange(true);
  }

  function closeOverlay() {
    onOpenChange(false);
  }

  function toggleOverlay() {
    if (open) closeOverlay();
    else openOverlay();
  }

  const triggerRefCallback: RefCallback<HTMLElement> = (node) => {
    triggerRef.current = node;
  };

  const renderProps: UiOverlayRenderProps = {
    closeOverlay,
    isOpen: open,
    openOverlay,
    panelId,
    titleId,
    toggleOverlay,
    triggerProps: {
      "aria-controls": panelId,
      "aria-expanded": open,
      "aria-haspopup": role === "menu" ? "menu" : role === "dialog" ? "dialog" : "true",
      onClick: (event) => {
        event.preventDefault();
        toggleOverlay();
      },
      onKeyDown: (event) => {
        if (event.key === "ArrowDown" || event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          openOverlay();
        }
      },
      ref: triggerRefCallback,
    },
  };

  useEffect(() => {
    clearCloseTimer();
    if (open) {
      setMounted(true);
      setOverlayState((currentState) => (currentState === "open" ? "open" : "opening"));
      return;
    }

    clearOpenFrames();
    if (!mounted) {
      setOverlayState("closed");
      return;
    }

    layerRef.current?.setAttribute("aria-hidden", "true");
    setOverlayState("closing");
    closeTimerRef.current = setTimeout(() => {
      const focusNode = returnFocusRef.current;
      setMounted(false);
      setOverlayState("closed");
      closeTimerRef.current = null;
      if (restoreFocus && focusNode && uiOverlayStack.size() === 0) {
        requestAnimationFrame(() => {
          if (focusNode.isConnected) focusNode.focus({ preventScroll: true });
        });
      }
      returnFocusRef.current = null;
    }, closingDurationMs);

    return () => clearCloseTimer();
  }, [mounted, open, restoreFocus]);

  useEffect(() => {
    if (!mounted || !open || overlayState !== "opening") return;
    const panel = panelRef.current;
    if (!panel) return;

    clearOpenFrames();
    panel.getBoundingClientRect();
    openFrameRef.current = requestAnimationFrame(() => {
      openSecondFrameRef.current = requestAnimationFrame(() => {
        setOverlayState("open");
        openFrameRef.current = null;
        openSecondFrameRef.current = null;
      });
    });

    return () => clearOpenFrames();
  }, [mounted, open, overlayState]);

  useEffect(() => {
    if (!mounted || !open) return;
    updateAnchorStyle();
    if (autoFocusPanel) requestAnimationFrame(() => panelRef.current?.focus({ preventScroll: true }));
  }, [autoFocusPanel, mounted, open]);

  useEffect(() => {
    if (!mounted || !open || !panelRef.current || !layerRef.current) return;
    return uiOverlayStack.register({
      closeOnEscape: true,
      id: layerId,
      layer: layerRef.current,
      modal,
      onEscape: closeOverlay,
      panel: panelRef.current,
      type,
    });
  }, [layerId, modal, mounted, open, type]);

  useEffect(() => {
    if (!mounted || !open) return;

    function handleOutsidePointerDown(event: globalThis.MouseEvent) {
      if (!closeOnOutside || modal || !uiOverlayStack.isTop(layerId)) return;
      const target = event.target;
      if (!(target instanceof Node)) return;
      if (panelRef.current?.contains(target) || triggerRef.current?.contains(target)) return;
      closeOverlay();
    }

    function handleKeyDown(event: globalThis.KeyboardEvent) {
      if (!uiOverlayStack.isTop(layerId)) return;
      if (event.key === "Escape") {
        if (!uiOverlayStack.routeEscape()) return;
        event.preventDefault();
        return;
      }
      if (event.key !== "Tab") return;
      const panel = panelRef.current;
      if (!panel) return;
      const focusable = getFocusableElements(panel);
      if (!focusable.length) {
        event.preventDefault();
        panel.focus({ preventScroll: true });
        return;
      }
      const first = focusable[0]!;
      const last = focusable[focusable.length - 1]!;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    document.addEventListener("mousedown", handleOutsidePointerDown, true);
    document.addEventListener("keydown", handleKeyDown);
    window.addEventListener("resize", updateAnchorStyle);
    window.addEventListener("scroll", updateAnchorStyle, true);
    return () => {
      document.removeEventListener("mousedown", handleOutsidePointerDown, true);
      document.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("resize", updateAnchorStyle);
      window.removeEventListener("scroll", updateAnchorStyle, true);
    };
  }, [closeOnOutside, layerId, modal, mounted, open]);

  const resolvedPanelSurface = surface ?? (type === "command-palette" ? "white" : surfaceContext);

  const overlayMarkup = mounted ? (
    <div
      aria-hidden={!open ? true : undefined}
      className={classNames("ui-overlay-layer", modal && "is-modal", className)}
      data-placement={placement}
      data-ui-overlay-motion={motion}
      data-ui-overlay-state={overlayState}
      data-ui-overlay-layer={layerId}
      onMouseDown={(event) => {
        if (!closeOnOutside || event.target !== event.currentTarget || !uiOverlayStack.isTop(layerId)) return;
        closeOverlay();
      }}
      ref={layerRef}
    >
      <section
        aria-label={label}
        aria-labelledby={title ? titleId : undefined}
        aria-modal={modal || undefined}
        className={classNames("ui-overlay-panel", panelClassName)}
        data-ui-surface={resolvedPanelSurface}
        id={panelId}
        ref={panelRef}
        role={role}
        tabIndex={-1}
      >
        {title ? <div className="ui-overlay-title" id={titleId}>{title}</div> : null}
        {typeof children === "function" ? children(renderProps) : children}
      </section>
    </div>
  ) : null;

  return (
    <>
      {trigger(renderProps)}
      {typeof document === "undefined" || !overlayMarkup ? null : createPortal(overlayMarkup, document.body)}
    </>
  );
}

function getFocusableElements(root: HTMLElement) {
  return Array.from(
    root.querySelectorAll<HTMLElement>(
      [
        "a[href]",
        "button:not([disabled])",
        "input:not([disabled])",
        "select:not([disabled])",
        "textarea:not([disabled])",
        "[tabindex]:not([tabindex='-1'])",
      ].join(","),
    ),
  ).filter((element) => !element.hasAttribute("disabled") && element.offsetParent !== null);
}

function getNearestSurfaceContext(triggerNode: HTMLElement | null): UiOverlaySurfaceContext | undefined {
  for (let current = triggerNode; current; current = current.parentElement) {
    const explicitSurface = current.getAttribute("data-ui-surface");
    if (explicitSurface === "gray" || explicitSurface === "white") return explicitSurface;
  }
  return undefined;
}
