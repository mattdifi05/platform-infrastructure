"use client";

import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import { Check, ChevronDown, CircleInfo, type IconType } from "./icons";
import { useI18n } from "./i18n";
import { Modal } from "./Modal";
import { classNames } from "./classNames";
import { ChoiceModalHeader } from "./ModalHeader";
import type { IconTone } from "./Form";
import { EmptyState } from "./States";
import { VirtualList } from "./VirtualList";
import { useResolvedSurfaceRef } from "./useResolvedSurface";

export type SelectOption = { value: string; label: string };

export function Select({
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
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const surfaceRef = useResolvedSurfaceRef<HTMLButtonElement>();
  const resolvedIconTone = iconTone ?? "country";
  const selected = options.find((option) => option.value === value);

  return (
    <Modal
      backdropClassName="choice-modal-backdrop"
      onOpenChange={setOpen}
      open={open}
      panelClassName="choice-modal-panel"
      restoreFocus={false}
      size="sm"
      trigger={({ isOpen, sourceRef, triggerButtonProps }) => (
        <div className={`custom-select ${isOpen ? "is-open" : ""} ${selected ? "has-value" : ""}`}>
          <span className="field-label">{label}</span>
          <button
            {...triggerButtonProps}
            className={classNames("custom-select-button", controlClassName, `has-icon-tone-${resolvedIconTone}`)}
            ref={(node) => {
              sourceRef(node);
              surfaceRef(node);
            }}
          >
            <span
              className={classNames("custom-select-icon", `is-${resolvedIconTone}`)}
              data-active={isOpen ? "true" : "false"}
            >
              <Icon size={17} />
            </span>
            <strong>{selected?.label ?? t("common.select")}</strong>
            <span
              className="custom-select-chevron"
              data-active={isOpen ? "true" : "false"}
            >
              <ChevronDown size={14} />
            </span>
          </button>
        </div>
      )}
    >
      {({ closeModal, titleId }) => (
        <>
          <ChoiceModalHeader icon={Icon} iconTone={resolvedIconTone} kicker={label} onClose={closeModal} title={selected?.label ?? t("common.select")} titleId={titleId} closeLabel={t("common.close")} />
          <SelectList onChange={onChange} onClose={closeModal} options={options} value={value} />
        </>
      )}
    </Modal>
  );
}

export function SelectList({
  className = "custom-select-menu choice-modal-list",
  onChange,
  onClose,
  options,
  value,
}: {
  className?: string;
  onChange: (value: string) => void;
  onClose?: () => void;
  options: SelectOption[];
  value: string;
}) {
  const { t } = useI18n();
  const listboxId = useId().replace(/:/g, "");
  const listRef = useRef<HTMLDivElement | null>(null);
  const selectedOptionRef = useRef<HTMLButtonElement | null>(null);
  const selectedIndex = options.findIndex((option) => option.value === value);
  const [activeIndex, setActiveIndex] = useState(selectedIndex >= 0 ? selectedIndex : 0);
  const virtualized = options.length > 40;

  useEffect(() => {
    if (options.length === 0) {
      setActiveIndex(-1);
      return;
    }
    setActiveIndex(selectedIndex >= 0 ? selectedIndex : 0);
  }, [options, selectedIndex]);

  useEffect(() => {
    if (virtualized || selectedIndex < 0) return;
    const frame = window.requestAnimationFrame(() => {
      const list = listRef.current;
      const selectedOption = selectedOptionRef.current;
      if (!list || !selectedOption) return;
      const centeredTop = selectedOption.offsetTop - ((list.clientHeight - selectedOption.offsetHeight) / 2);
      list.scrollTop = Math.max(0, centeredTop);
    });
    return () => window.cancelAnimationFrame(frame);
  }, [options.length, selectedIndex, virtualized]);

  function commitOption(index: number) {
    const option = options[index];
    if (!option) return;
    onChange(option.value);
    onClose?.();
  }

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (options.length === 0) return;
    const lastIndex = options.length - 1;
    const nextIndexByKey: Record<string, number> = {
      ArrowDown: activeIndex >= lastIndex ? 0 : activeIndex + 1,
      ArrowUp: activeIndex <= 0 ? lastIndex : activeIndex - 1,
      End: lastIndex,
      Home: 0,
    };
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      commitOption(activeIndex);
      return;
    }
    const nextIndex = nextIndexByKey[event.key];
    if (nextIndex === undefined) return;
    event.preventDefault();
    setActiveIndex(nextIndex);
  }

  return (
    <div
      aria-activedescendant={activeIndex >= 0 ? `${listboxId}-option-${activeIndex}` : undefined}
      className={className}
      onKeyDown={handleKeyDown}
      ref={listRef}
      role={options.length > 0 ? "listbox" : undefined}
      tabIndex={options.length > 0 ? 0 : -1}
    >
      {options.length === 0 ? (
        <EmptyState className="ui-feedback-empty is-info" icon={CircleInfo} role="status" surface="gray">
          <div>
            <strong>{t("ui.feedback.empty.noItems")}</strong>
            <span>{t("ui.feedback.empty.noItemsCopy")}</span>
          </div>
        </EmptyState>
      ) : null}
      {virtualized ? (
        <VirtualList
          activeIndex={activeIndex}
          className="choice-modal-virtual-list"
          itemHeight={46}
          items={options}
          renderItem={(option, index) => renderSelectOption(option, index)}
          viewportHeight={360}
        />
      ) : options.map((option, index) => renderSelectOption(option, index))}
    </div>
  );

  function renderSelectOption(option: SelectOption, index: number) {
    return (
      <button
        aria-selected={option.value === value}
        className={classNames(option.value === value && "selected", index === activeIndex && "active")}
        id={`${listboxId}-option-${index}`}
        key={option.value}
        onClick={() => commitOption(index)}
        onMouseMove={() => setActiveIndex(index)}
        ref={option.value === value ? selectedOptionRef : undefined}
        role="option"
        tabIndex={-1}
        type="button"
      >
        <span>{option.label}</span>
        {option.value === value ? <Check size={15} /> : null}
      </button>
    );
  }
}
