"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { UiTheme } from "./catalog/catalog-theme";
import { clearTimeoutRef, useDynamicCssProperties } from "./styleMotion";

const THEME_WAVE_DURATION_MS = 550;
const THEME_WAVE_EXIT_SCALE = 1.32;
const THEME_WAVE_REVEAL_EDGE_OFFSET = 0.72;
const THEME_WAVE_STYLE_PROPERTIES = [
  "--ui-theme-wave-diameter",
  "--ui-theme-wave-radius",
  "--ui-theme-wave-x",
  "--ui-theme-wave-y",
] as const;

export type ThemeWave = {
  id: string;
  mode: "paint" | "reveal";
  radius: number;
  theme: UiTheme;
  x: number;
  y: number;
};

type ThemeViewTransition = {
  ready: Promise<void>;
};

type ThemeTransitionDocument = Document & {
  startViewTransition?: (updateCallback: () => void) => ThemeViewTransition;
};

export function useThemeWave() {
  const [themeWave, setThemeWave] = useState<ThemeWave | null>(null);
  const themeWaveTimerRef = useRef<number | null>(null);
  const themeWaveCssProperties = useMemo(() => ({
    "--ui-theme-wave-diameter": themeWave ? `${themeWave.radius * 2}px` : undefined,
    "--ui-theme-wave-radius": themeWave ? `${themeWave.radius}px` : undefined,
    "--ui-theme-wave-x": themeWave ? `${themeWave.x}px` : undefined,
    "--ui-theme-wave-y": themeWave ? `${themeWave.y}px` : undefined,
  }), [themeWave]);

  useDynamicCssProperties(".ui-theme-wave-overlay", themeWaveCssProperties, THEME_WAVE_STYLE_PROPERTIES, Boolean(themeWave));

  const cancelThemeWave = useCallback(() => {
    clearTimeoutRef(themeWaveTimerRef);
    setThemeWave(null);
  }, []);

  const startThemeWave = useCallback((nextTheme: UiTheme, source: HTMLElement, commitTheme: () => void) => {
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
      commitTheme();
      return;
    }
    const rect = source.getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    const radius = Math.ceil(Math.hypot(
      Math.max(x, window.innerWidth - x),
      Math.max(y, window.innerHeight - y),
    ));
    const exitRadius = Math.ceil(radius * THEME_WAVE_EXIT_SCALE);
    const transitionDocument = document as ThemeTransitionDocument;
    const canRevealTheme = typeof transitionDocument.startViewTransition === "function";

    setThemeWave({
      id: createThemeWaveId(),
      mode: canRevealTheme ? "reveal" : "paint",
      radius,
      theme: nextTheme,
      x,
      y,
    });
    clearTimeoutRef(themeWaveTimerRef);
    themeWaveTimerRef.current = window.setTimeout(() => {
      themeWaveTimerRef.current = null;
      setThemeWave(null);
    }, THEME_WAVE_DURATION_MS);

    const transition = transitionDocument.startViewTransition?.(() => {
      commitTheme();
    });
    if (!transition) {
      commitTheme();
      return;
    }
    void transition.ready.then(() => {
      document.documentElement.animate(
        [
          { clipPath: `circle(0px at ${x}px ${y}px)`, offset: 0 },
          { clipPath: `circle(${radius}px at ${x}px ${y}px)`, offset: THEME_WAVE_REVEAL_EDGE_OFFSET },
          { clipPath: `circle(${exitRadius}px at ${x}px ${y}px)`, offset: 1 },
        ],
        {
          duration: THEME_WAVE_DURATION_MS,
          easing: getThemeWaveEasing(),
          pseudoElement: "::view-transition-new(root)",
        } as KeyframeAnimationOptions,
      );
    }).catch(() => undefined);
  }, []);

  useEffect(() => cancelThemeWave, [cancelThemeWave]);

  return { cancelThemeWave, startThemeWave, themeWave };
}

export function ThemeWaveOverlay({ wave }: { wave: ThemeWave | null }) {
  return wave ? (
    <div
      aria-hidden="true"
      className="ui-theme-wave-overlay"
      data-ui-theme-wave={wave.theme}
      data-ui-theme-wave-id={wave.id}
      data-ui-theme-wave-mode={wave.mode}
      key={wave.id}
    />
  ) : null;
}

function getThemeWaveEasing() {
  return getComputedStyle(document.documentElement).getPropertyValue("--ui-motion-ease-linear").trim() || "linear";
}

function createThemeWaveId() {
  return String(Math.round(window.performance.now() * 1000));
}
