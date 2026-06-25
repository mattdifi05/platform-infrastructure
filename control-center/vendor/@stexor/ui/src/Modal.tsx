"use client";

import {
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type MouseEvent,
  type PointerEvent,
  type ReactNode,
  type RefCallback,
} from "react";
import { createPortal } from "react-dom";
import { classNames } from "./classNames";
import { uiOverlayStack } from "./OverlayManager";
import { uiMotionDurations } from "./motion-tokens";

type ModalRenderProps = {
  closeModal: () => void;
  isOpen: boolean;
  layoutId: string;
  linkTriggerProps: {
    "aria-controls": string;
    "aria-expanded": boolean;
    "aria-haspopup": "dialog";
    onClick: (event: MouseEvent<HTMLElement>) => void;
    onMouseDown: (event: MouseEvent<HTMLElement>) => void;
    onPointerDown: (event: PointerEvent<HTMLElement>) => void;
    ref: RefCallback<HTMLElement>;
    role: "button";
  };
  openModal: (event?: MouseEvent<HTMLElement>) => void;
  sourceRef: RefCallback<HTMLElement>;
  titleId: string;
  triggerButtonProps: {
    "aria-controls": string;
    "aria-expanded": boolean;
    "aria-haspopup": "dialog";
    onClick: (event: MouseEvent<HTMLElement>) => void;
    onMouseDown: (event: MouseEvent<HTMLElement>) => void;
    onPointerDown: (event: PointerEvent<HTMLElement>) => void;
    ref: RefCallback<HTMLElement>;
    type: "button";
  };
};

type ModalSize = "md" | "sm";

type ModalProps = {
  backdropClassName?: string;
  children: (props: ModalRenderProps) => ReactNode;
  closeOnBackdrop?: boolean;
  closeOnEscape?: boolean;
  fluidResize?: boolean;
  fluidResizeKey?: string | number;
  layoutId?: string;
  onOpenChange: (open: boolean) => void;
  open: boolean;
  panelClassName?: string;
  restoreFocus?: boolean;
  size?: ModalSize;
  trigger: (props: ModalRenderProps) => ReactNode;
};

type ModalState = "closed" | "closing" | "open" | "opening";
type ResizeBox = { height: number; width: number };
type ScrollSnapshot =
  | { kind: "element"; left: number; node: HTMLElement; top: number }
  | { kind: "window"; left: number; top: number };

const closingDurationMs = uiMotionDurations.overlay;
const fluidResizeDurationMs = 300;
const fluidResizeEasing = "cubic-bezier(0.4, 0, 0.2, 1)";

export function Modal({
  backdropClassName = "",
  children,
  closeOnBackdrop = true,
  closeOnEscape = true,
  fluidResize = false,
  fluidResizeKey,
  layoutId,
  onOpenChange,
  open,
  panelClassName = "",
  restoreFocus = true,
  size = "md",
  trigger,
}: ModalProps) {
  const generatedId = useId().replace(/:/g, "");
  const [mounted, setMounted] = useState(open);
  const [modalState, setModalState] = useState<ModalState>(open ? "open" : "closed");
  const closeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const openFrameRef = useRef<number | null>(null);
  const openSecondFrameRef = useRef<number | null>(null);
  const fluidResizeAnimationRef = useRef<Animation | null>(null);
  const fluidResizeSizeRef = useRef<ResizeBox | null>(null);
  const layerRef = useRef<HTMLDivElement | null>(null);
  const panelRef = useRef<HTMLElement | null>(null);
  const sourceNodeRef = useRef<HTMLElement | null>(null);
  const returnFocusRef = useRef<HTMLElement | null>(null);
  const triggerScrollSnapshotRef = useRef<ScrollSnapshot[] | null>(null);
  const sharedLayoutId = layoutId ?? `modal-${generatedId}`;
  const panelId = `${sharedLayoutId}-panel`;
  const titleId = `${sharedLayoutId}-title`;

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

  function closeModal() {
    onOpenChange(false);
  }

  function rememberTriggerScroll(event: MouseEvent<HTMLElement> | PointerEvent<HTMLElement>) {
    triggerScrollSnapshotRef.current = collectScrollSnapshots(event.currentTarget);
  }

  function handleTriggerPointerDown(event: PointerEvent<HTMLElement>) {
    rememberTriggerScroll(event);
    event.preventDefault();
  }

  function handleTriggerMouseDown(event: MouseEvent<HTMLElement>) {
    rememberTriggerScroll(event);
    event.preventDefault();
  }

  function openModal(event?: MouseEvent<HTMLElement>) {
    event?.preventDefault();
    const activeElement = document.activeElement;
    returnFocusRef.current =
      sourceNodeRef.current ?? (activeElement instanceof HTMLElement ? activeElement : null);
    restoreScrollSnapshots(triggerScrollSnapshotRef.current);
    requestAnimationFrame(() => restoreScrollSnapshots(triggerScrollSnapshotRef.current));
    onOpenChange(true);
  }

  const sourceRef: RefCallback<HTMLElement> = (element) => {
    sourceNodeRef.current = element;
  };

  const renderProps: ModalRenderProps = {
    closeModal,
    isOpen: open,
    layoutId: sharedLayoutId,
    linkTriggerProps: {
      "aria-controls": panelId,
      "aria-expanded": open,
      "aria-haspopup": "dialog",
      onClick: openModal,
      onMouseDown: handleTriggerMouseDown,
      onPointerDown: handleTriggerPointerDown,
      ref: sourceRef,
      role: "button",
    },
    openModal,
    sourceRef,
    titleId,
    triggerButtonProps: {
      "aria-controls": panelId,
      "aria-expanded": open,
      "aria-haspopup": "dialog",
      onClick: openModal,
      onMouseDown: handleTriggerMouseDown,
      onPointerDown: handleTriggerPointerDown,
      ref: sourceRef,
      type: "button",
    },
  };

  useEffect(() => {
    clearCloseTimer();
    if (open) {
      setMounted(true);
      setModalState((currentState) => (currentState === "open" ? "open" : "opening"));
      return;
    }

    clearOpenFrames();
    if (!mounted) {
      setModalState("closed");
      return;
    }

    setModalState("closing");
    closeTimerRef.current = setTimeout(() => {
      const restoreNode = returnFocusRef.current;
      setMounted(false);
      setModalState("closed");
      closeTimerRef.current = null;
      if (restoreFocus && restoreNode) {
        requestAnimationFrame(() => {
          requestAnimationFrame(() => {
            if (restoreNode.isConnected) restoreNode.focus({ preventScroll: true });
          });
        });
      }
      returnFocusRef.current = null;
    }, closingDurationMs);

    return () => {
      clearCloseTimer();
    };
  }, [mounted, open, restoreFocus]);

  useEffect(() => {
    if (!mounted || !open || modalState !== "opening") return;
    const panel = panelRef.current;
    if (!panel) return;

    clearOpenFrames();
    // Commit the starting style before moving to "open"; otherwise a delayed frame can skip the transition.
    panel.getBoundingClientRect();
    openFrameRef.current = requestAnimationFrame(() => {
      openSecondFrameRef.current = requestAnimationFrame(() => {
        setModalState("open");
        openFrameRef.current = null;
        openSecondFrameRef.current = null;
      });
    });

    return () => {
      clearOpenFrames();
    };
  }, [modalState, mounted, open]);

  useLayoutEffect(() => {
    const panel = panelRef.current;
    if (!fluidResize || !mounted || !open || !panel || typeof panel.animate !== "function") {
      fluidResizeAnimationRef.current?.cancel();
      fluidResizeAnimationRef.current = null;
      fluidResizeSizeRef.current = null;
      return;
    }

    const panelElement = panel;
    const reduceMotionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    const nextSize = readResizeBox(panelElement);
    const previousTargetSize = fluidResizeSizeRef.current;

    if (!previousTargetSize || modalState !== "open" || reduceMotionQuery.matches) {
      fluidResizeAnimationRef.current?.cancel();
      fluidResizeAnimationRef.current = null;
      fluidResizeSizeRef.current = nextSize;
      return;
    }

    const activeAnimation = fluidResizeAnimationRef.current;
    const startSize = activeAnimation ? readResizeBox(panelElement) : previousTargetSize;
    activeAnimation?.cancel();
    fluidResizeAnimationRef.current = null;
    const targetSize = activeAnimation ? readResizeBox(panelElement) : nextSize;

    if (resizeBoxesMatch(startSize, targetSize)) {
      fluidResizeSizeRef.current = targetSize;
      return;
    }

    fluidResizeSizeRef.current = targetSize;
    const animation = panelElement.animate(
      [
        { height: `${startSize.height}px`, width: `${startSize.width}px` },
        { height: `${targetSize.height}px`, width: `${targetSize.width}px` },
      ],
      {
        duration: fluidResizeDurationMs,
        easing: fluidResizeEasing,
      },
    );
    fluidResizeAnimationRef.current = animation;

    function clearAnimationState() {
      if (fluidResizeAnimationRef.current !== animation) return;
      fluidResizeAnimationRef.current = null;
      fluidResizeSizeRef.current = readResizeBox(panelElement);
    }

    animation.addEventListener("finish", clearAnimationState, { once: true });
    animation.addEventListener("cancel", clearAnimationState, { once: true });
  }, [fluidResize, fluidResizeKey, modalState, mounted, open]);

  useEffect(() => () => {
    fluidResizeAnimationRef.current?.cancel();
    fluidResizeAnimationRef.current = null;
    fluidResizeSizeRef.current = null;
  }, []);

  useEffect(() => {
    if (!mounted) return;
    const layer = layerRef.current;
    const panel = panelRef.current;
    if (!layer || !panel) return;
    return uiOverlayStack.register({
      closeOnEscape,
      id: sharedLayoutId,
      layer,
      modal: true,
      onEscape: closeModal,
      panel,
    });
  }, [closeOnEscape, mounted, sharedLayoutId]);

  useEffect(() => {
    if (!mounted) return;
    const activeElement = document.activeElement;
    if (!returnFocusRef.current && activeElement instanceof HTMLElement) {
      returnFocusRef.current = activeElement;
    }
    requestAnimationFrame(() => {
      panelRef.current?.focus({ preventScroll: true });
    });
  }, [mounted]);

  useEffect(() => {
    if (!mounted) return;

    function handleKeyDown(event: KeyboardEvent) {
      if (!uiOverlayStack.isTop(sharedLayoutId)) return;
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

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [mounted, sharedLayoutId]);

  const modalMarkup = mounted ? (
    <div
      className={classNames("modal-layer", backdropClassName)}
      data-state={modalState}
      data-ui-overlay-layer={sharedLayoutId}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && closeOnBackdrop && uiOverlayStack.isTop(sharedLayoutId)) closeModal();
      }}
      ref={layerRef}
    >
      <section
        aria-labelledby={titleId}
        aria-modal="true"
        className={classNames("modal-panel", `modal-panel-${size}`, panelClassName)}
        data-fluid-resize={fluidResize ? "true" : undefined}
        id={panelId}
        ref={panelRef}
        role="dialog"
        tabIndex={-1}
      >
        {children(renderProps)}
      </section>
    </div>
  ) : null;

  return (
    <>
      {trigger(renderProps)}
      {typeof document === "undefined" || !modalMarkup ? null : createPortal(modalMarkup, document.body)}
    </>
  );
}

function collectScrollSnapshots(start: HTMLElement): ScrollSnapshot[] {
  if (typeof window === "undefined") return [];
  const snapshots: ScrollSnapshot[] = [];
  const seen = new Set<HTMLElement | Window>();

  function addElementSnapshot(node: HTMLElement, left: number, top: number) {
    if (seen.has(node)) return;
    seen.add(node);
    snapshots.push({ kind: "element", left, node, top });
  }

  seen.add(window);
  snapshots.push({ kind: "window", left: window.scrollX, top: window.scrollY });

  for (let node: HTMLElement | null = start; node; node = node.parentElement) {
    const style = window.getComputedStyle(node);
    const overflow = `${style.overflow} ${style.overflowX} ${style.overflowY}`;
    const canScroll = /auto|scroll|overlay/.test(overflow) || node.scrollTop !== 0 || node.scrollLeft !== 0;
    if (canScroll) addElementSnapshot(node, node.scrollLeft, node.scrollTop);
  }

  return snapshots;
}

function restoreScrollSnapshots(snapshots: ScrollSnapshot[] | null) {
  if (!snapshots?.length || typeof window === "undefined") return;
  for (const snapshot of snapshots) {
    if (snapshot.kind === "window") {
      window.scrollTo(snapshot.left, snapshot.top);
      continue;
    }

    snapshot.node.scrollLeft = snapshot.left;
    snapshot.node.scrollTop = snapshot.top;
  }
}

function readResizeBox(panel: HTMLElement, entry?: ResizeObserverEntry): ResizeBox {
  const borderBoxSize = entry?.borderBoxSize;
  const borderBox = Array.isArray(borderBoxSize) ? borderBoxSize[0] : borderBoxSize;
  if (borderBox) return { height: borderBox.blockSize, width: borderBox.inlineSize };

  const style = window.getComputedStyle(panel);
  const styledWidth = Number.parseFloat(style.width);
  const styledHeight = Number.parseFloat(style.height);
  if (Number.isFinite(styledWidth) && Number.isFinite(styledHeight) && styledWidth > 0 && styledHeight > 0) {
    return { height: styledHeight, width: styledWidth };
  }

  const rect = panel.getBoundingClientRect();
  return { height: rect.height, width: rect.width };
}

function resizeBoxesMatch(left: ResizeBox, right: ResizeBox) {
  return Math.abs(left.height - right.height) < 0.5 && Math.abs(left.width - right.width) < 0.5;
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
