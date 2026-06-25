"use client";

import { useCallback, useEffect, useRef } from "react";

type UiResolvedSurface = "gray" | "white";

const surfaceRootSelector = ".ui-page, .ui-modal, .ui-overlay-panel";

export function useResolvedSurfaceRef<T extends HTMLElement>() {
  const nodeRef = useRef<T | null>(null);

  const refreshSurface = useCallback((node: T | null) => {
    nodeRef.current = node;
    if (node) applyResolvedSurface(node);
  }, []);

  useEffect(() => {
    const node = nodeRef.current;
    if (!node) return;
    applyResolvedSurface(node);
    const surfaceNode = findNearestSurfaceNode(node);
    if (!surfaceNode || typeof MutationObserver === "undefined") return;
    const observer = new MutationObserver(() => applyResolvedSurface(node));
    observer.observe(surfaceNode, { attributeFilter: ["data-ui-surface"], attributes: true });
    return () => observer.disconnect();
  }, []);

  return refreshSurface;
}

function applyResolvedSurface(node: HTMLElement) {
  node.dataset.uiResolvedSurface = resolveNearestSurface(node);
}

function resolveNearestSurface(node: HTMLElement): UiResolvedSurface {
  const surfaceNode = findNearestSurfaceNode(node);
  if (!surfaceNode) return "white";
  const explicitSurface = surfaceNode.getAttribute("data-ui-surface");
  if (explicitSurface === "gray" || explicitSurface === "white") return explicitSurface;
  return "white";
}

function findNearestSurfaceNode(node: HTMLElement) {
  let current = node.parentElement;
  while (current) {
    if (
      current.getAttribute("data-ui-surface") === "gray" ||
      current.getAttribute("data-ui-surface") === "white" ||
      current.matches(surfaceRootSelector)
    ) {
      return current;
    }
    current = current.parentElement;
  }
  return null;
}
