"use client";

import { useEffect, useRef, useState } from "react";
import type { InputHTMLAttributes, ReactNode, TextareaHTMLAttributes } from "react";
import type { IconType } from "./icons";
import { createDynamicCssRule, cssEscape, nextCssRuleId, setDynamicCssProperties } from "./cssom";
import { classNames } from "./classNames";
import { Select, type SelectOption } from "./Select";
import { uiFieldA11yProps, type UiFieldValidationState } from "./FormValidation";
import { useResolvedSurfaceRef } from "./useResolvedSurface";

export type IconTone = "brand" | "country" | "date" | "email" | "language";

type InputControlProps = Omit<InputHTMLAttributes<HTMLInputElement>, "onChange" | "value"> & {
  controlClassName?: string;
  icon: IconType;
  iconTone?: IconTone;
  label: string;
  onChange: (value: string) => void;
  validation?: UiFieldValidationState;
  value: string;
};

function InputControl({
  autoFocus = false,
  controlClassName,
  icon: Icon,
  iconTone,
  label,
  onChange,
  type = "text",
  validation,
  value,
  ...inputProps
}: InputControlProps) {
  const [focused, setFocused] = useState(autoFocus);
  const surfaceRef = useResolvedSurfaceRef<HTMLSpanElement>();
  const controlActive = focused || Boolean(value);
  const resolvedIconTone = iconTone ?? resolveTextInputIconTone({
    autoComplete: inputProps.autoComplete,
    inputMode: inputProps.inputMode,
    type,
  });

  return (
    <label className="field">
      <span className="field-label">{label}</span>
      <span className={classNames("field-control", controlClassName, `has-icon-tone-${resolvedIconTone}`, validation && `is-${validation.status}`, controlActive && "is-active")} ref={surfaceRef}>
        <span
          className={classNames("field-icon", `is-${resolvedIconTone}`)}
        >
          <Icon aria-hidden="true" size={17} />
        </span>
        <input
          {...uiFieldA11yProps(validation)}
          {...inputProps}
          autoFocus={autoFocus}
          disabled={validation?.disabled || inputProps.disabled}
          type={type}
          value={value}
          onBlur={() => setFocused(false)}
          onChange={(event) => onChange(event.target.value)}
          onFocus={() => setFocused(true)}
        />
      </span>
      <FieldValidationMessage validation={validation} />
    </label>
  );
}

export function TextField({
  autoComplete,
  controlClassName,
  iconTone,
  icon: Icon,
  inputMode,
  label,
  onChange,
  type = "text",
  validation,
  value,
  ...inputProps
}: Omit<InputHTMLAttributes<HTMLInputElement>, "onChange" | "value"> & {
  controlClassName?: string;
  icon: IconType;
  iconTone?: IconTone;
  label: string;
  onChange: (value: string) => void;
  validation?: UiFieldValidationState;
  value: string;
}) {
  return <InputControl autoComplete={autoComplete} controlClassName={controlClassName} icon={Icon} iconTone={iconTone} inputMode={inputMode} label={label} onChange={onChange} type={type} validation={validation} value={value} {...inputProps} />;
}

export function SearchInput({
  className,
  icon: Icon,
  iconTone,
  inputProps,
  label,
  onChange,
  placeholder = label,
  validation,
  value,
}: {
  className?: string;
  icon: IconType;
  iconTone?: IconTone;
  inputProps?: Omit<InputHTMLAttributes<HTMLInputElement>, "onChange" | "placeholder" | "value">;
  label: string;
  onChange: (value: string) => void;
  placeholder?: string;
  validation?: UiFieldValidationState;
  value: string;
}) {
  const resolvedIconTone = iconTone ?? "brand";
  const surfaceRef = useResolvedSurfaceRef<HTMLLabelElement>();

  return (
    <label className={classNames("ui-search", className, `has-icon-tone-${resolvedIconTone}`)} ref={surfaceRef}>
      <span className={classNames("ui-search-icon", `is-${resolvedIconTone}`)}>
        <Icon aria-hidden="true" size={16} />
      </span>
      <input
        {...uiFieldA11yProps(validation)}
        {...inputProps}
        aria-label={inputProps?.["aria-label"] ?? label}
        disabled={validation?.disabled || inputProps?.disabled}
        value={value}
        onChange={(event) => onChange(event.currentTarget.value)}
        placeholder={placeholder}
        type={inputProps?.type ?? "search"}
      />
      <FieldValidationMessage validation={validation} />
    </label>
  );
}

export function SelectField({
  controlClassName,
  icon: Icon,
  iconTone,
  label,
  onChange,
  options,
  value,
}: {
  controlClassName?: string;
  icon: IconType;
  iconTone?: IconTone;
  label: string;
  onChange: (value: string) => void;
  options: SelectOption[];
  value: string;
}) {
  return <Select controlClassName={controlClassName} icon={Icon} iconTone={iconTone} label={label} value={value} options={options} onChange={onChange} />;
}

export function TextareaField({
  controlClassName,
  icon: Icon,
  iconTone,
  label,
  onChange,
  value,
  validation,
  ...props
}: Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "onChange" | "value"> & {
  controlClassName?: string;
  icon: IconType;
  iconTone?: IconTone;
  label: string;
  onChange: (value: string) => void;
  validation?: UiFieldValidationState;
  value: string;
}) {
  const [focused, setFocused] = useState(false);
  const surfaceRef = useResolvedSurfaceRef<HTMLSpanElement>();
  const controlActive = focused || Boolean(value);
  const resolvedIconTone = iconTone ?? "brand";

  return (
    <label className="field">
      <span className="field-label">{label}</span>
      <span className={classNames("field-control", controlClassName, `has-icon-tone-${resolvedIconTone}`, validation && `is-${validation.status}`, controlActive && "is-active")} ref={surfaceRef}>
        <span
          className={classNames("field-icon", `is-${resolvedIconTone}`)}
        >
          <Icon aria-hidden="true" size={17} />
        </span>
        <textarea
          {...uiFieldA11yProps(validation)}
          {...props}
          disabled={validation?.disabled || props.disabled}
          value={value}
          onBlur={() => setFocused(false)}
          onChange={(event) => onChange(event.target.value)}
          onFocus={() => setFocused(true)}
        />
      </span>
      <FieldValidationMessage validation={validation} />
    </label>
  );
}

function FieldValidationMessage({ validation }: { validation?: UiFieldValidationState }) {
  const issue = validation?.issues[0];
  if (!validation?.describedBy || !issue) return null;
  return (
    <span className={classNames("field-message", `is-${issue.severity}`)} id={validation.describedBy} role={issue.severity === "info" ? "status" : "alert"}>
      {issue.message}
    </span>
  );
}

export function FieldGroup({ children, className }: { children: ReactNode; className: string }) {
  return <div className={className}>{children}</div>;
}

function resolveTextInputIconTone({
  autoComplete,
  inputMode,
  type,
}: {
  autoComplete?: string;
  inputMode?: string;
  type?: string;
}): IconTone {
  const semanticHint = `${autoComplete ?? ""} ${inputMode ?? ""} ${type ?? ""}`.toLowerCase();
  return semanticHint.includes("email") ? "email" : "brand";
}

export function SwitchField({
  checked,
  className,
  label,
  onChange,
}: {
  checked: boolean;
  className?: string;
  label: string;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className={classNames("switch-field", className)}>
      <input checked={checked} onChange={(event) => onChange(event.currentTarget.checked)} type="checkbox" />
      <span className="switch-track" aria-hidden="true">
        <span className="switch-thumb" />
      </span>
      <span className="switch-label">{label}</span>
    </label>
  );
}

export function CheckboxField({
  checked,
  children,
  className,
  onChange,
}: {
  checked: boolean;
  children: ReactNode;
  className?: string;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className={classNames("checkbox-field", className)}>
      <input checked={checked} onChange={(event) => onChange(event.currentTarget.checked)} type="checkbox" />
      <span className="checkbox-control" aria-hidden="true">
        <svg viewBox="0 0 24 24" focusable="false">
          <path d="M6.25 12.35 10.25 16.35 17.85 7.95" />
        </svg>
      </span>
      <span className="checkbox-label">{children}</span>
    </label>
  );
}

export function RadioField({
  checked,
  children,
  className,
  name = "ui-radio",
  onChange,
}: {
  checked: boolean;
  children: ReactNode;
  className?: string;
  name?: string;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className={classNames("radio-field", className)}>
      <input checked={checked} name={name} onChange={(event) => onChange(event.currentTarget.checked)} type="radio" />
      <span className="radio-control" aria-hidden="true">
        <span />
      </span>
      <span className="radio-label">{children}</span>
    </label>
  );
}

export function RangeField({
  className,
  label,
  max = 100,
  min = 0,
  onChange,
  step = 1,
  suffix = "%",
  value,
}: {
  className?: string;
  label: string;
  max?: number;
  min?: number;
  onChange: (value: number) => void;
  step?: number;
  suffix?: string;
  value: number;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const rangeIdRef = useRef<string | null>(null);
  const rangeRuleRef = useRef<CSSStyleRule | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const clampedValue = Math.min(max, Math.max(min, value));
  const range = max - min;
  const percentage = range > 0 ? ((clampedValue - min) / range) * 100 : 0;
  const ratio = percentage / 100;
  const rangeInset = 15;
  const thumbOffset = rangeInset - (rangeInset * 2 * ratio);
  if (rangeIdRef.current === null) rangeIdRef.current = nextCssRuleId("ui-range");
  const rangeId = rangeIdRef.current;
  const rangeThumbLeft = `calc(${percentage}% ${thumbOffset < 0 ? "-" : "+"} ${Math.abs(thumbOffset).toFixed(3)}px)`;
  const stepDecimals = String(step).split(".")[1]?.length ?? 0;
  const snapValue = (nextValue: number) => {
    const snapped = Math.round((nextValue - min) / step) * step + min;
    return Number(Math.min(max, Math.max(min, snapped)).toFixed(stepDecimals));
  };
  const updateValueFromPointer = (clientX: number, node: HTMLElement) => {
    if (range <= 0) return;
    const bounds = node.getBoundingClientRect();
    const usableWidth = Math.max(1, bounds.width - rangeInset * 2);
    const nextRatio = Math.min(1, Math.max(0, (clientX - bounds.left - rangeInset) / usableWidth));
    onChange(snapValue(min + nextRatio * range));
  };
  const stopDragging = () => setIsDragging(false);

  useEffect(() => {
    rangeRuleRef.current = createDynamicCssRule(`.range-control[data-range-id="${cssEscape(rangeId)}"]`);
    return () => {
      setDynamicCssProperties(rangeRuleRef.current, {
        "--range-thumb-left": "",
        "--range-value": "",
      });
      rangeRuleRef.current = null;
    };
  }, [rangeId]);

  useEffect(() => {
    setDynamicCssProperties(rangeRuleRef.current, {
      "--range-thumb-left": rangeThumbLeft,
      "--range-value": `${percentage}%`,
    });
  }, [percentage, rangeThumbLeft]);

  return (
    <label className={classNames("range-field", className)}>
      <span className="range-field-head">
        <span className="range-label">{label}</span>
        <strong className="range-value">{Math.round(clampedValue)}{suffix}</strong>
      </span>
      <span
        className={classNames("range-control", isDragging && "is-dragging")}
        onLostPointerCapture={stopDragging}
        onPointerCancel={stopDragging}
        onPointerDown={(event) => {
          event.preventDefault();
          inputRef.current?.focus();
          event.currentTarget.setPointerCapture(event.pointerId);
          setIsDragging(true);
          updateValueFromPointer(event.clientX, event.currentTarget);
        }}
        onPointerMove={(event) => {
          if (!isDragging && !event.currentTarget.hasPointerCapture(event.pointerId)) return;
          event.preventDefault();
          updateValueFromPointer(event.clientX, event.currentTarget);
        }}
        onPointerUp={(event) => {
          if (event.currentTarget.hasPointerCapture(event.pointerId)) {
            event.currentTarget.releasePointerCapture(event.pointerId);
          }
          stopDragging();
        }}
        data-range-id={rangeId}
      >
        <input
          aria-label={label}
          max={max}
          min={min}
          onChange={(event) => onChange(Number(event.currentTarget.value))}
          ref={inputRef}
          step={step}
          type="range"
          value={clampedValue}
        />
        <span className="range-visual" aria-hidden="true">
          <span className="range-visual-fill" />
          <span className="range-visual-fill-cap" />
          <span className="range-visual-thumb" />
        </span>
      </span>
    </label>
  );
}
