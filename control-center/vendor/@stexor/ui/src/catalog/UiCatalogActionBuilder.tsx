"use client";

import { useEffect, useMemo, useState, type KeyboardEvent } from "react";
import {
  getUiActionSpinDirection,
  uiActionBuilderShapes,
  uiActionBuilderVariantOptions,
  type UiActionBuilderVariant,
  type UiActionSpinDirection,
} from "../ActionConfig";
import { Button, ChoiceModalHeader, EmptyState, FieldGroup, Modal, ModalFooter, SearchInput, SwitchField, TextField } from "../client";
import { classNames } from "../classNames";
import { AlertTriangle, Check, ChevronDown, CircleInfo, Save, Search, ShieldCheck, uiIconRegistry, type IconType, type UiIconName } from "../icons";
import { VirtualList } from "../VirtualList";

type BuilderIconOption = { icon: IconType; label: string; searchText: string; value: UiIconName };
const iconOptions = Object.entries(uiIconRegistry).map(([id, icon]) => ({
  icon,
  label: id,
  searchText: `${id} ${humanizeIconName(id)}`.toLowerCase(),
  value: id,
})).sort((first, second) => first.label.localeCompare(second.label)) satisfies BuilderIconOption[];

export function UiButtonBuilderSurface() {
  const [label, setLabel] = useState("Conferma");
  const [variant, setVariant] = useState<UiActionBuilderVariant>("primary");
  const [iconId, setIconId] = useState<UiIconName>("check");
  const [loading, setLoading] = useState(false);
  const [fullColor, setFullColor] = useState(false);
  const [confirmBeforeAction, setConfirmBeforeAction] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const icon = uiIconRegistry[iconId] ?? CircleInfo;
  const actionLabel = label.trim() || "Conferma";
  const previewVariant = loading ? "muted" : variant;
  const previewSolid = loading ? undefined : fullColor;
  const previewClick = confirmBeforeAction && !loading ? () => setConfirmOpen(true) : undefined;
  const spinIconOnClickDirection = getUiActionSpinDirection(iconId);
  const spinIconOnClick = Boolean(spinIconOnClickDirection);

  useEffect(() => {
    if (!confirmBeforeAction || loading) setConfirmOpen(false);
  }, [confirmBeforeAction, loading]);

  return (
    <section className="ui-actions-block ui-action-builder-layout" data-ui-surface="gray" aria-label="Crea action in tempo reale">
        <div className="ui-actions-block-head">
          <div>
            <strong>Builder live</strong>
            <span>Configura forma, testo, icona, colore e loading senza creare un altro sistema.</span>
          </div>
        </div>
        <FieldGroup className="ui-action-builder-controls">
          <TextField icon={Save} label="Testo" value={label} onChange={setLabel} />
          <ColorPickerField solid={fullColor} value={variant} onChange={setVariant} />
          <IconPickerField value={iconId} onChange={setIconId} />
          <SwitchField checked={fullColor} label="Colore pieno" onChange={setFullColor} />
          <SwitchField checked={loading} label="Loading" onChange={setLoading} />
          <SwitchField checked={confirmBeforeAction} label="Modal conferma" onChange={setConfirmBeforeAction} />
        </FieldGroup>
        <div className="ui-action-builder-preview-grid" aria-label="Preview superfici">
          <div className="ui-action-builder-preview" data-ui-surface="white">
            <span className="ui-actions-column-label">Bianco</span>
            <ActionBuilderPreviewButtons actionLabel={actionLabel} icon={icon} loading={loading} onClick={previewClick} solid={previewSolid} spinIconOnClick={spinIconOnClick} spinIconOnClickDirection={spinIconOnClickDirection} variant={previewVariant} />
          </div>
          <div className="ui-action-builder-preview" data-ui-surface="gray">
            <span className="ui-actions-column-label">Grigio</span>
            <ActionBuilderPreviewButtons actionLabel={actionLabel} icon={icon} loading={loading} onClick={previewClick} solid={previewSolid} spinIconOnClick={spinIconOnClick} spinIconOnClickDirection={spinIconOnClickDirection} variant={previewVariant} />
          </div>
        </div>
        <Modal
          backdropClassName="choice-modal-backdrop"
          onOpenChange={setConfirmOpen}
          open={confirmOpen}
          panelClassName="choice-modal-panel"
          size="sm"
          trigger={() => null}
        >
          {({ closeModal, titleId }) => (
            <>
              <ChoiceModalHeader closeLabel="Chiudi" icon={ShieldCheck} iconTone="brand" kicker="Conferma" onClose={closeModal} title="Conferma azione" titleId={titleId} />
              <ModalFooter className="ui-modal-footer">
                <Button icon={icon} onClick={closeModal} solid={fullColor} spinIconOnClick={spinIconOnClick} spinIconOnClickDirection={spinIconOnClickDirection} variant={variant}>{actionLabel}</Button>
              </ModalFooter>
            </>
          )}
        </Modal>
    </section>
  );
}

function ActionBuilderPreviewButtons({
  actionLabel,
  icon,
  loading,
  onClick,
  solid,
  spinIconOnClick,
  spinIconOnClickDirection,
  variant,
}: {
  actionLabel: string;
  icon: IconType;
  loading: boolean;
  onClick?: () => void;
  solid?: boolean;
  spinIconOnClick: boolean;
  spinIconOnClickDirection?: UiActionSpinDirection;
  variant: UiActionBuilderVariant;
}) {
  return (
    <div className="ui-button-strip ui-action-builder-variant-grid" aria-label="Preview action">
      {uiActionBuilderShapes.map((item) => (
        <Button
          aria-label={item.ariaLabel}
          className={item.iconOnly ? "ui-round-icon" : undefined}
          compact={item.compact}
          icon={icon}
          iconSize={item.compact ? 14 : 17}
          key={item.id}
          loading={loading}
          onClick={onClick}
          solid={solid}
          spinIconOnClick={spinIconOnClick}
          spinIconOnClickDirection={spinIconOnClickDirection}
          variant={variant}
        >
          {item.iconOnly ? undefined : actionLabel}
        </Button>
      ))}
    </div>
  );
}

function ColorPickerField({
  onChange,
  solid,
  value,
}: {
  onChange: (value: UiActionBuilderVariant) => void;
  solid: boolean;
  value: UiActionBuilderVariant;
}) {
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(Math.max(0, uiActionBuilderVariantOptions.findIndex((option) => option.value === value)));
  const selected = uiActionBuilderVariantOptions.find((option) => option.value === value) ?? uiActionBuilderVariantOptions[0]!;

  useEffect(() => {
    setActiveIndex(Math.max(0, uiActionBuilderVariantOptions.findIndex((option) => option.value === value)));
  }, [value]);

  function commitOption(option: (typeof uiActionBuilderVariantOptions)[number]) {
    onChange(option.value);
    setOpen(false);
  }

  function handleListKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const lastIndex = uiActionBuilderVariantOptions.length - 1;
    const nextIndexByKey: Record<string, number> = {
      ArrowDown: activeIndex >= lastIndex ? 0 : activeIndex + 1,
      ArrowUp: activeIndex <= 0 ? lastIndex : activeIndex - 1,
      End: lastIndex,
      Home: 0,
    };
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      commitOption(uiActionBuilderVariantOptions[activeIndex] ?? uiActionBuilderVariantOptions[0]!);
      return;
    }
    const nextIndex = nextIndexByKey[event.key];
    if (nextIndex === undefined) return;
    event.preventDefault();
    setActiveIndex(nextIndex);
  }

  return (
    <Modal
      backdropClassName="choice-modal-backdrop"
      onOpenChange={setOpen}
      open={open}
      panelClassName="choice-modal-panel"
      restoreFocus={false}
      size="sm"
      trigger={({ isOpen, sourceRef, triggerButtonProps }) => (
        <div className={`custom-select ui-action-builder-color-picker ${isOpen ? "is-open" : ""} has-value`}>
          <span className="field-label">Colore</span>
          <button
            {...triggerButtonProps}
            className="custom-select-button"
            ref={(node) => sourceRef(node)}
          >
            <span className="ui-action-builder-color-name">
              <span className="ui-action-builder-color-dot" data-ui-action-solid={solid ? "true" : "false"} data-ui-action-variant={selected.value} aria-hidden="true" />
              <strong>{selected.label}</strong>
            </span>
            <span className="custom-select-chevron" data-active={isOpen ? "true" : "false"}>
              <ChevronDown size={14} />
            </span>
          </button>
        </div>
      )}
    >
      {({ closeModal, titleId }) => (
        <>
          <ChoiceModalHeader closeLabel="Chiudi" icon={AlertTriangle} iconTone="brand" kicker="Colore" onClose={closeModal} title={selected.label} titleId={titleId} />
          <div
            aria-label="Colori action"
            className="custom-select-menu choice-modal-list ui-action-builder-color-list"
            onKeyDown={handleListKeyDown}
            role="listbox"
            tabIndex={0}
          >
            {uiActionBuilderVariantOptions.map((option, index) => (
              <button
                aria-selected={option.value === value}
                className={classNames(option.value === value && "selected", index === activeIndex && "active")}
                key={option.value}
                onClick={() => commitOption(option)}
                onMouseMove={() => setActiveIndex(index)}
                role="option"
                tabIndex={-1}
                type="button"
              >
                <span className="ui-action-builder-color-name">
                  <span className="ui-action-builder-color-dot" data-ui-action-solid={solid ? "true" : "false"} data-ui-action-variant={option.value} aria-hidden="true" />
                  <span>{option.label}</span>
                </span>
                {option.value === value ? <Check size={15} /> : null}
              </button>
            ))}
          </div>
        </>
      )}
    </Modal>
  );
}

function IconPickerField({
  onChange,
  value,
}: {
  onChange: (value: UiIconName) => void;
  value: UiIconName;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const selected = iconOptions.find((option) => option.value === value) ?? iconOptions[0]!;
  const SelectedIcon = selected.icon;
  const filteredOptions = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) return iconOptions;
    return iconOptions.filter((option) => option.searchText.includes(normalizedQuery));
  }, [query]);

  useEffect(() => {
    const selectedIndex = filteredOptions.findIndex((option) => option.value === value);
    setActiveIndex(filteredOptions.length === 0 ? -1 : Math.max(0, selectedIndex));
  }, [filteredOptions, value]);

  function commitOption(option: BuilderIconOption) {
    onChange(option.value);
    setOpen(false);
    setQuery("");
  }

  function handleListKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (filteredOptions.length === 0) return;
    const lastIndex = filteredOptions.length - 1;
    const nextIndexByKey: Record<string, number> = {
      ArrowDown: activeIndex < 0 || activeIndex >= lastIndex ? 0 : activeIndex + 1,
      ArrowUp: activeIndex <= 0 ? lastIndex : activeIndex - 1,
      End: lastIndex,
      Home: 0,
    };
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      const option = filteredOptions[Math.max(0, activeIndex)] ?? filteredOptions[0];
      if (option) commitOption(option);
      return;
    }
    const nextIndex = nextIndexByKey[event.key];
    if (nextIndex === undefined) return;
    event.preventDefault();
    setActiveIndex(nextIndex);
  }

  return (
    <Modal
      backdropClassName="choice-modal-backdrop"
      onOpenChange={setOpen}
      open={open}
      panelClassName="choice-modal-panel ui-modal-panel ui-action-builder-icon-modal"
      restoreFocus={false}
      size="sm"
      trigger={({ isOpen, sourceRef, triggerButtonProps }) => (
        <div className={`custom-select ui-action-builder-icon-picker ${isOpen ? "is-open" : ""} has-value`}>
          <span className="field-label">Icona</span>
          <button
            {...triggerButtonProps}
            className="custom-select-button has-icon-tone-brand"
            ref={(node) => sourceRef(node)}
          >
            <span className="custom-select-icon is-brand" data-active={isOpen ? "true" : "false"}>
              <SelectedIcon size={17} />
            </span>
            <strong>{selected.label}</strong>
            <span className="custom-select-chevron" data-active={isOpen ? "true" : "false"}>
              <ChevronDown size={14} />
            </span>
          </button>
        </div>
      )}
    >
      {({ closeModal, titleId }) => (
        <div className="ui-modal">
          <ChoiceModalHeader icon={SelectedIcon} iconTone="brand" kicker="Icona" onClose={closeModal} title="Scegli icona" titleId={titleId} closeLabel="Chiudi" />
          <SearchInput
            icon={Search}
            inputProps={{ autoFocus: true }}
            label="Cerca icona"
            onChange={setQuery}
            placeholder="Cerca icona"
            value={query}
          />
          {filteredOptions.length === 0 ? (
            <EmptyState className="ui-feedback-empty is-info" icon={CircleInfo} role="status" surface="gray">
              <div>
                <strong>Nessuna icona</strong>
                <span>Prova con un altro nome.</span>
              </div>
            </EmptyState>
          ) : (
            <div
              aria-label="Icone"
              className="custom-select-menu choice-modal-list ui-action-builder-icon-list"
              onKeyDown={handleListKeyDown}
              role="listbox"
              tabIndex={0}
            >
              <VirtualList
                activeIndex={activeIndex}
                className="choice-modal-virtual-list ui-action-builder-icon-virtual-list"
                itemHeight={48}
                items={filteredOptions}
                renderItem={(option, index) => renderIconOption({
                  active: index === activeIndex,
                  onChoose: commitOption,
                  option,
                  selected: option.value === value,
                  setActiveIndex: () => setActiveIndex(index),
                })}
                viewportHeight={Math.min(360, Math.max(48, filteredOptions.length * 48))}
              />
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}

function renderIconOption({
  active,
  onChoose,
  option,
  selected,
  setActiveIndex,
}: {
  active: boolean;
  onChoose: (option: BuilderIconOption) => void;
  option: BuilderIconOption;
  selected: boolean;
  setActiveIndex: () => void;
}) {
  const Icon = option.icon;

  return (
    <button
      aria-selected={selected}
      className={classNames("ui-action-builder-icon-option", selected && "selected", active && "active")}
      onClick={() => onChoose(option)}
      onMouseMove={setActiveIndex}
      role="option"
      tabIndex={-1}
      type="button"
    >
      <span className="ui-action-builder-icon-option-label">
        <span className="ui-action-builder-icon-option-icon" aria-hidden="true">
          <Icon size={15} />
        </span>
        <span>{option.label}</span>
      </span>
      {selected ? <Check size={15} /> : null}
    </button>
  );
}

function humanizeIconName(iconName: string) {
  return iconName.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/[-_]/g, " ");
}
