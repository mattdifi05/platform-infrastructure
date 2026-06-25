"use client";

import { cloneElement, forwardRef, isValidElement, useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { AnchorHTMLAttributes, ButtonHTMLAttributes, HTMLAttributes, MouseEvent, MouseEventHandler, ReactNode, ReactElement } from "react";
import type { IconType } from "./icons";
import { getUiActionVariantTone, uiActionVariantClasses, type UiActionVariant } from "./ActionConfig";
import { classNames } from "./classNames";
import { Slot } from "./Slot";
import {
  BUTTON_DYNAMIC_STYLE_PROPERTIES,
  BUTTON_ICON_ANIMATION_DURATION_MS,
  BUTTON_MORPH_DURATION_MS,
  BUTTON_MORPH_HOVER_UNLOCK_DELAY_MS,
  BUTTON_MORPH_SCALE,
  BUTTON_SUBMIT_DELAY_MS,
  cancelFrameRef,
  clearTimeoutRef,
  readNaturalButtonWidth,
  readVisibleButtonWidth,
  useDynamicCssProperties,
} from "./styleMotion";

export type ButtonVariant = UiActionVariant;

type ButtonSharedProps = {
  asChild?: boolean;
  compact?: boolean;
  disabled?: boolean;
  icon?: IconType;
  iconPosition?: "end" | "start";
  iconSize?: number;
  loading?: boolean;
  spinIconOnClick?: boolean;
  spinIconOnClickDirection?: "forward" | "reverse";
  spinIconOnClickDurationMs?: number;
  solid?: boolean;
  variant?: ButtonVariant;
};

export type ButtonProps = ButtonSharedProps & (
  | ({ href: string } & Omit<AnchorHTMLAttributes<HTMLAnchorElement>, keyof ButtonSharedProps | "href">)
  | ({ href?: undefined } & ButtonHTMLAttributes<HTMLButtonElement>)
);

type ButtonElement = HTMLElement;
type ButtonVisualState = {
  children: ReactNode;
  icon?: IconType;
  iconPosition: "end" | "start";
  iconSize: number;
  loading: boolean;
  solid?: boolean;
  variant: ButtonVariant;
};

export const Button = forwardRef<ButtonElement, ButtonProps>(function Button({
  "aria-busy": ariaBusy,
  "aria-disabled": ariaDisabled,
  asChild = false,
  children,
  className,
  compact = false,
  disabled,
  href,
  icon: Icon,
  iconPosition = "start",
  iconSize = 17,
  loading = false,
  onClick,
  spinIconOnClick = false,
  spinIconOnClickDirection = "forward",
  spinIconOnClickDurationMs = 920,
  solid,
  style: _style,
  type = "button",
  variant = "muted",
  ...props
}: ButtonProps, ref) {
  const dynamicButtonId = useId().replace(/:/g, "");
  const buttonRef = useRef<ButtonElement | null>(null);
  const [iconAnimating, setIconAnimating] = useState(false);
  const [iconAnimationPulse, setIconAnimationPulse] = useState(0);
  const [iconSpinning, setIconSpinning] = useState(false);
  const [buttonMorphing, setButtonMorphing] = useState(false);
  const [morphHoverLocked, setMorphHoverLocked] = useState(false);
  const [morphWidth, setMorphWidth] = useState<number | null>(null);
  const [outgoingVisual, setOutgoingVisual] = useState<ButtonVisualState | null>(null);
  const [morphPulse, setMorphPulse] = useState(0);
  const iconAnimationTimerRef = useRef<number | null>(null);
  const morphFrameRef = useRef<number | null>(null);
  const morphHoverLockTimerRef = useRef<number | null>(null);
  const pendingMorphClearFrameRef = useRef<number | null>(null);
  const pendingMorphStartWidthRef = useRef<number | null>(null);
  const morphTimerRef = useRef<number | null>(null);
  const previousMorphSignatureRef = useRef<string | null>(null);
  const previousVisualRef = useRef<ButtonVisualState | null>(null);
  const previousWidthRef = useRef<number | null>(null);
  const submitDelayTimerRef = useRef<number | null>(null);
  const spinTimerRef = useRef<number | null>(null);
  const childElement = asChild && isValidElement<{ children?: ReactNode }>(children) ? children : null;
  const visualChildren = childElement ? childElement.props.children : children;
  const morphSignature = [
    compact ? "compact" : "regular",
    disabled ? "disabled" : "enabled",
    getIconSignature(Icon),
    iconPosition,
    loading ? "loading" : "idle",
    solid === undefined ? "default-tone" : solid ? "solid-tone" : "soft-tone",
    variant,
    getContentSignature(visualChildren),
  ].join("|");
  const currentVisual = {
    children: visualChildren,
    icon: Icon,
    iconPosition,
    iconSize,
    loading,
    solid,
    variant,
  } satisfies ButtonVisualState;
  const setButtonRef = useCallback((node: ButtonElement | null) => {
    buttonRef.current = node;
    if (typeof ref === "function") {
      ref(node);
    } else if (ref) {
      ref.current = node;
    }
  }, [ref]);
  const iconNode = loading ? (
    <span
      aria-hidden="true"
      className={classNames("button-icon button-spinner", iconAnimationPulse % 2 === 0 ? "is-pulse-even" : "is-pulse-odd")}
      key={`loading-${iconAnimationPulse}`}
    />
  ) : Icon ? (
    <span
      aria-hidden="true"
      className={classNames(
        "button-icon",
        iconAnimating && "is-animating",
        iconSpinning && "is-spinning",
        iconSpinning && spinIconOnClickDirection === "reverse" && "is-spin-reverse",
        iconAnimationPulse % 2 === 0 ? "is-pulse-even" : "is-pulse-odd",
      )}
    >
      <Icon aria-hidden="true" size={iconSize} />
    </span>
  ) : null;
  const content = renderChildren(visualChildren);

  useLayoutEffect(() => {
    const button = buttonRef.current;
    if (!button) return;

    const previousSignature = previousMorphSignatureRef.current;
    const previousWidth = previousWidthRef.current;
    const signatureChanged = previousSignature !== null && previousSignature !== morphSignature;

    previousMorphSignatureRef.current = morphSignature;
    if (!signatureChanged) {
      previousVisualRef.current = currentVisual;
      previousWidthRef.current = readNaturalButtonWidth(button);
      return;
    }

    const visibleWidth = readVisibleButtonWidth(button);
    const nextWidth = readNaturalButtonWidth(button);
    previousWidthRef.current = nextWidth;
    cancelFrameRef(morphFrameRef);
    clearTimeoutRef(morphHoverLockTimerRef);
    clearTimeoutRef(morphTimerRef);

    const pendingStartWidth = pendingMorphStartWidthRef.current;
    pendingMorphStartWidthRef.current = null;
    cancelFrameRef(pendingMorphClearFrameRef);

    const startWidth = pendingStartWidth ?? (buttonMorphing ? visibleWidth : previousWidth ?? visibleWidth);
    setOutgoingVisual(previousVisualRef.current);
    setMorphWidth(startWidth);
    setMorphPulse((current) => current + 1);
    setButtonMorphing(true);
    setMorphHoverLocked(true);
    morphFrameRef.current = window.requestAnimationFrame(() => {
      morphFrameRef.current = window.requestAnimationFrame(() => {
        morphFrameRef.current = null;
        setMorphWidth(nextWidth);
      });
    });
    morphTimerRef.current = window.setTimeout(() => {
      setButtonMorphing(false);
      setMorphWidth(null);
      setOutgoingVisual(null);
      previousWidthRef.current = readNaturalButtonWidth(button);
      morphHoverLockTimerRef.current = window.setTimeout(() => {
        setMorphHoverLocked(false);
        morphHoverLockTimerRef.current = null;
      }, BUTTON_MORPH_HOVER_UNLOCK_DELAY_MS);
      morphTimerRef.current = null;
    }, BUTTON_MORPH_DURATION_MS);
    previousVisualRef.current = currentVisual;
  }, [morphSignature]);

  const handleClick = (event: MouseEvent<ButtonElement>) => {
    pendingMorphStartWidthRef.current = readVisibleButtonWidth(event.currentTarget);
    cancelFrameRef(pendingMorphClearFrameRef);
    pendingMorphClearFrameRef.current = window.requestAnimationFrame(() => {
      pendingMorphClearFrameRef.current = null;
      pendingMorphStartWidthRef.current = null;
    });

    if (Icon && !loading && spinIconOnClick) {
      clearTimeoutRef(spinTimerRef);
      setIconAnimationPulse((current) => current + 1);
      setIconSpinning(true);
      spinTimerRef.current = window.setTimeout(() => {
        setIconSpinning(false);
        spinTimerRef.current = null;
      }, spinIconOnClickDurationMs);
    } else if (Icon && !loading) {
      clearTimeoutRef(iconAnimationTimerRef);
      setIconAnimationPulse((current) => current + 1);
      setIconAnimating(true);
      iconAnimationTimerRef.current = window.setTimeout(() => {
        setIconAnimating(false);
        iconAnimationTimerRef.current = null;
      }, BUTTON_ICON_ANIMATION_DURATION_MS);
    }

    if (disabled) {
      event.preventDefault();
      event.stopPropagation();
      return;
    }

    (onClick as MouseEventHandler<ButtonElement> | undefined)?.(event);

    const submitter = event.currentTarget instanceof HTMLButtonElement ? event.currentTarget : null;
    if (!event.defaultPrevented && submitter?.type === "submit" && Icon) {
      const form = submitter.form;
      if (form) {
        event.preventDefault();
        clearTimeoutRef(submitDelayTimerRef);
        submitDelayTimerRef.current = window.setTimeout(() => {
          if (submitter.isConnected && submitter.getAttribute("aria-disabled") !== "true") {
            form.requestSubmit(submitter);
          }
          submitDelayTimerRef.current = null;
        }, BUTTON_SUBMIT_DELAY_MS);
      }
    }
  };

  useEffect(() => () => {
    clearTimeoutRef(iconAnimationTimerRef);
    cancelFrameRef(morphFrameRef);
    clearTimeoutRef(morphHoverLockTimerRef);
    cancelFrameRef(pendingMorphClearFrameRef);
    clearTimeoutRef(morphTimerRef);
    clearTimeoutRef(submitDelayTimerRef);
    clearTimeoutRef(spinTimerRef);
  }, []);

  const outgoingTone = outgoingVisual ? getUiActionVariantTone(outgoingVisual.variant, outgoingVisual.solid) : null;
  const morphCssActive = buttonMorphing || morphWidth !== null || outgoingTone !== null;
  const dynamicCssProperties = useMemo(() => ({
    "inline-size": morphWidth === null ? undefined : `${morphWidth}px`,
    "--ui-button-morph-out-bg": outgoingTone?.background,
    "--ui-button-morph-out-color": outgoingTone?.color,
    "--ui-button-morph-from-x": morphCssActive ? String(BUTTON_MORPH_SCALE.from) : undefined,
    "--ui-button-morph-over-x": morphCssActive ? String(BUTTON_MORPH_SCALE.over) : undefined,
    "--ui-button-morph-under-x": morphCssActive ? String(BUTTON_MORPH_SCALE.under) : undefined,
    width: morphWidth === null ? undefined : `${morphWidth}px`,
  }), [morphCssActive, morphWidth, outgoingTone]);
  useDynamicCssProperties(
    `.ui-dynamic-button[data-ui-button-id="${dynamicButtonId}"]`,
    dynamicCssProperties,
    BUTTON_DYNAMIC_STYLE_PROPERTIES,
    morphCssActive,
  );
  const dynamicButtonProps = {
    "data-ui-button-id": dynamicButtonId,
  };
  const buttonClassName = classNames(
    "ui-dynamic-button",
    uiActionVariantClasses[variant],
    compact && "compact",
    buttonMorphing && "is-morphing",
    morphHoverLocked && "is-morph-hover-locked",
    buttonMorphing && (morphPulse % 2 === 0 ? "is-morph-even" : "is-morph-odd"),
    disabled && "is-disabled",
    solid === true && "is-solid-tone",
    solid === false && "is-soft-tone",
    spinIconOnClick && "has-spin-icon",
    loading && "is-loading",
    className,
  );
  const isDisabled = Boolean(disabled);
  const ariaDisabledValue = isDisabled ? true : ariaDisabled;
  const buttonContent = (
    <>
      {iconPosition === "start" ? iconNode : null}
      {content}
      {iconPosition === "end" ? iconNode : null}
      {buttonMorphing && outgoingVisual ? (
        <span aria-hidden="true" className="button-morph-outgoing" key={`${morphPulse}-${getVisualSignature(outgoingVisual)}`}>
          {renderButtonVisualContent(outgoingVisual)}
        </span>
      ) : null}
    </>
  );

  if (asChild) {
    const slotProps = props as HTMLAttributes<HTMLElement>;
    const slottedChild = childElement
      ? cloneElement(childElement as ReactElement<{ children?: ReactNode }>, undefined, buttonContent)
      : children;

    return (
      <Slot
        {...slotProps}
        aria-busy={loading ? true : ariaBusy}
        aria-disabled={ariaDisabledValue}
        className={buttonClassName}
        {...dynamicButtonProps}
        onClick={handleClick as MouseEventHandler<HTMLElement>}
        ref={setButtonRef}
        tabIndex={isDisabled ? -1 : slotProps.tabIndex}
      >
        {slottedChild}
      </Slot>
    );
  }

  if (href) {
    const anchorProps = props as AnchorHTMLAttributes<HTMLAnchorElement>;
    return (
      <a
        {...anchorProps}
        aria-busy={loading ? true : ariaBusy}
        aria-disabled={ariaDisabledValue}
        className={buttonClassName}
        {...dynamicButtonProps}
        href={isDisabled ? undefined : href}
        onClick={handleClick}
        ref={setButtonRef}
        tabIndex={isDisabled ? -1 : anchorProps.tabIndex}
      >
        {buttonContent}
      </a>
    );
  }

  const nativeButtonProps = props as ButtonHTMLAttributes<HTMLButtonElement>;
  return (
    <button
      {...nativeButtonProps}
      aria-busy={loading ? true : ariaBusy}
      aria-disabled={ariaDisabledValue}
      className={buttonClassName}
      {...dynamicButtonProps}
      onClick={handleClick}
      ref={setButtonRef}
      type={type as ButtonHTMLAttributes<HTMLButtonElement>["type"]}
    >
      {buttonContent}
    </button>
  );
});

Button.displayName = "Button";

function renderChildren(children: ReactNode) {
  if (children === null || children === undefined || children === false) return null;
  return <span className="button-label">{children}</span>;
}

function renderButtonVisualContent(visual: ButtonVisualState) {
  const Icon = visual.icon;
  const icon = visual.loading ? (
    <span aria-hidden="true" className="button-icon button-spinner" />
  ) : Icon ? (
    <span aria-hidden="true" className="button-icon">
      <Icon aria-hidden="true" size={visual.iconSize} />
    </span>
  ) : null;
  const label = renderChildren(visual.children);

  return (
    <>
      {visual.iconPosition === "start" ? icon : null}
      {label}
      {visual.iconPosition === "end" ? icon : null}
    </>
  );
}

function getContentSignature(children: ReactNode): string {
  if (children === null || children === undefined || children === false) return "";
  if (typeof children === "string" || typeof children === "number" || typeof children === "bigint") return String(children);
  if (Array.isArray(children)) return children.map(getContentSignature).join("");
  if (isValidElement<{ children?: ReactNode }>(children)) return getContentSignature(children.props.children);
  return "node";
}

function getIconSignature(Icon?: IconType) {
  return Icon ? Icon.displayName ?? Icon.name ?? "icon" : "none";
}

function getVisualSignature(visual: ButtonVisualState) {
  return [
    getIconSignature(visual.icon),
    visual.iconPosition,
    visual.loading ? "loading" : "idle",
    visual.solid === undefined ? "default-tone" : visual.solid ? "solid-tone" : "soft-tone",
    visual.variant,
    getContentSignature(visual.children),
  ].join("|");
}
