"use client";

import { useRef, useState, type ChangeEvent, type ReactNode } from "react";
import { Bell, Calendar, Camera, Check, FileImage, Languages, Rows3, Save, Search, ShieldCheck, Sliders, Trash, type IconType } from "../icons";
import { AvatarCropper, AvatarFilterStepper, Button, CalendarPickerPanel, ChoiceCard, ChoiceModalHeader, Modal, ModalFooter, SearchInput, SelectList, getAvatarVisualFilterItems, type AvatarCrop } from "../client";
import { classNames } from "../classNames";
import { useI18n } from "../i18n";
import type { UiSeed } from "./catalog-types";

type UiModalId = "avatar" | "calendar" | "classic" | "list" | "options";

const getUiModalListOptions = (t: ReturnType<typeof useI18n>["t"]) => [
  { label: t("ui.modals.list.profile"), value: "identity" },
  { label: t("ui.modals.list.security"), value: "security" },
  { label: t("ui.modals.list.notifications"), value: "notifications" },
  { label: t("ui.modals.list.sessions"), value: "sessions" },
  { label: t("ui.modals.list.advanced"), value: "advanced" },
];

export const getUiModalChoiceItems = (t: ReturnType<typeof useI18n>["t"]) => [
  {
    icon: ShieldCheck,
    id: "balanced",
    text: t("ui.modals.options.balanced.text"),
    title: t("ui.modals.options.balanced.title"),
  },
  {
    icon: Bell,
    id: "quiet",
    text: t("ui.modals.options.quiet.text"),
    title: t("ui.modals.options.quiet.title"),
  },
  {
    icon: Sliders,
    id: "manual",
    text: t("ui.modals.options.manual.text"),
    title: t("ui.modals.options.manual.title"),
  },
] as const;

const initialAvatarCrop: AvatarCrop = { size: 1, x: 0, y: 0 };
const maxAvatarFileSize = 8 * 1024 * 1024;

export function UiModalsSurface({
  seed,
}: {
  seed: UiSeed;
}) {
  const { t } = useI18n();
  const [activeModal, setActiveModal] = useState<UiModalId | null>(null);
  const [modalDate, setModalDate] = useState(seed.dateOfBirth || "1998-05-17");
  const [listChoice, setListChoice] = useState("identity");
  const [listSearch, setListSearch] = useState("");
  const [optionChoice, setOptionChoice] = useState<UiModalChoiceId>("balanced");
  const [avatarChoice, setAvatarChoice] = useState<UiAvatarFilterId>("natural");
  const [avatarPreview, setAvatarPreview] = useState<string | null>(null);
  const [avatarCrop, setAvatarCrop] = useState<AvatarCrop>(initialAvatarCrop);
  const [avatarRemoveConfirmOpen, setAvatarRemoveConfirmOpen] = useState(false);
  const avatarFileInputRef = useRef<HTMLInputElement | null>(null);
  const closeLabel = t("common.close");
  const UiModalListOptions = getUiModalListOptions(t);
  const UiModalChoiceItems = getUiModalChoiceItems(t);
  const UiAvatarFilterItems = getAvatarVisualFilterItems(t);
  const selectedList = UiModalListOptions.find((option) => option.value === listChoice) ?? UiModalListOptions[0]!;
  const avatarFallbackName = `${seed.firstName} ${seed.lastName}`.trim() || seed.username;
  const normalizedListSearch = listSearch.trim().toLowerCase();
  const filteredListOptions = normalizedListSearch
    ? UiModalListOptions.filter((option) => option.label.toLowerCase().includes(normalizedListSearch))
    : UiModalListOptions;
  const selectedOption = UiModalChoiceItems.find((option) => option.id === optionChoice) ?? UiModalChoiceItems[0]!;

  function handleAvatarFile(file: File | null) {
    if (!file) {
      return;
    }

    if (!file.type.startsWith("image/") || file.size > maxAvatarFileSize) {
      setAvatarPreview(null);
      setAvatarChoice("natural");
      setAvatarCrop(initialAvatarCrop);
      return;
    }

    const reader = new FileReader();
    reader.addEventListener("load", () => {
      setAvatarPreview(typeof reader.result === "string" ? reader.result : null);
      setAvatarChoice("natural");
      setAvatarCrop(initialAvatarCrop);
    });
    reader.addEventListener("error", () => {
      setAvatarPreview(null);
      setAvatarChoice("natural");
      setAvatarCrop(initialAvatarCrop);
    });
    reader.readAsDataURL(file);
  }

  function handleAvatarInputChange(event: ChangeEvent<HTMLInputElement>) {
    handleAvatarFile(event.currentTarget.files?.[0] ?? null);
    event.currentTarget.value = "";
  }

  function removeAvatarPreview() {
    setAvatarPreview(null);
    setAvatarChoice("natural");
    setAvatarCrop(initialAvatarCrop);
    setAvatarRemoveConfirmOpen(false);
    if (avatarFileInputRef.current) avatarFileInputRef.current.value = "";
  }

  const avatarPreviewActions = (closeAvatarModal: () => void): ReactNode => (
    <>
      <Modal
        backdropClassName="choice-modal-backdrop"
        layoutId="ui-modal-avatar-remove"
        onOpenChange={setAvatarRemoveConfirmOpen}
        open={avatarRemoveConfirmOpen}
        panelClassName="choice-modal-panel ui-modal-panel"
        size="sm"
        trigger={({ triggerButtonProps }) => (
          avatarPreview ? (
            <Button
              {...triggerButtonProps}
              aria-label={t("ui.avatar.remove")}
              className="ui-avatar-preview-action is-remove"
              compact
              icon={Trash}
              solid
              variant="danger"
            >
              {t("ui.avatar.remove")}
            </Button>
          ) : null
        )}
      >
        {({ closeModal, titleId }) => (
          <div className="ui-modal">
            <ChoiceModalHeader closeLabel={closeLabel} icon={Trash} iconTone="brand" kicker={t("ui.avatar.title")} onClose={closeModal} title={t("ui.avatar.removeConfirmTitle")} titleId={titleId} />
            <p className="ui-modal-copy">{t("ui.avatar.removeConfirmText")}</p>
            <ModalFooter className="ui-modal-footer">
              <Button onClick={closeModal} variant="muted">{t("common.cancel")}</Button>
              <Button icon={Trash} onClick={removeAvatarPreview} variant="danger">{t("ui.avatar.removeConfirmAction")}</Button>
            </ModalFooter>
          </div>
        )}
      </Modal>
      <input accept="image/*" className="ui-avatar-file-input" onChange={handleAvatarInputChange} ref={avatarFileInputRef} type="file" />
      {avatarPreview ? (
        <Button className="ui-avatar-preview-action is-save" compact icon={Save} onClick={closeAvatarModal} solid variant="primary">
          {t("ui.action.save")}
        </Button>
      ) : (
        <Button
          aria-label={t("ui.avatar.upload")}
          className="ui-avatar-preview-action is-upload"
          compact
          icon={Camera}
          onClick={() => avatarFileInputRef.current?.click()}
          solid
          variant="primary"
        >
          {t("ui.action.upload")}
        </Button>
      )}
    </>
  );

  return (
    <div className="ui-modal-board" aria-label={t("ui.modals.aria")}>
      <UiModalGroup title={t("ui.modals.group.dialogs")}>
        <UiModalPattern icon={ShieldCheck} meta={t("ui.modals.classic.meta")} title={t("ui.modals.classic.title")}>
          <Modal
            backdropClassName="choice-modal-backdrop"
            layoutId="ui-modal-classic"
            onOpenChange={(open) => setActiveModal(open ? "classic" : null)}
            open={activeModal === "classic"}
            panelClassName="choice-modal-panel ui-modal-panel"
            trigger={({ triggerButtonProps }) => <Button {...triggerButtonProps} icon={ShieldCheck} variant="primary">{t("ui.modals.classic.open")}</Button>}
          >
            {({ closeModal, titleId }) => (
              <div className="ui-modal">
                <ChoiceModalHeader closeLabel={closeLabel} icon={ShieldCheck} iconTone="brand" kicker={t("ui.modals.classic.kicker")} onClose={closeModal} title={t("ui.modals.classic.header")} titleId={titleId} />
                <p className="ui-modal-copy">{t("ui.modals.classic.copy")}</p>
                <ModalFooter className="ui-modal-footer">
                  <Button icon={Check} onClick={closeModal} variant="primary">{t("ui.action.confirm")}</Button>
                </ModalFooter>
              </div>
            )}
          </Modal>
        </UiModalPattern>
      </UiModalGroup>

      <UiModalGroup title={t("ui.modals.group.choices")}>
        <UiModalPattern icon={Calendar} meta={t("ui.modals.calendar.meta")} title={t("ui.modals.calendar.title")}>
          <Modal
            backdropClassName="choice-modal-backdrop"
            layoutId="ui-modal-calendar"
            onOpenChange={(open) => setActiveModal(open ? "calendar" : null)}
            open={activeModal === "calendar"}
            panelClassName="choice-modal-panel ui-date-modal-panel ui-modal-panel ui-calendar-panel"
            restoreFocus={false}
            size="sm"
            trigger={({ triggerButtonProps }) => <Button {...triggerButtonProps} icon={Calendar} variant="edit">{t("ui.modals.calendar.open")}</Button>}
          >
            {({ closeModal, titleId }) => (
              <CalendarPickerPanel
                closeLabel={closeLabel}
                iconTone="date"
                label={t("ui.modals.calendar.label")}
                onChange={setModalDate}
                onClose={closeModal}
                titleId={titleId}
                value={modalDate}
              />
            )}
          </Modal>
        </UiModalPattern>

        <UiModalPattern icon={FileImage} meta={t("ui.avatar.copy")} title={t("ui.avatar.title")}>
          <Modal
            backdropClassName="choice-modal-backdrop"
            layoutId="ui-modal-avatar"
            onOpenChange={(open) => {
              setActiveModal(open ? "avatar" : null);
              if (!open) setAvatarRemoveConfirmOpen(false);
            }}
            open={activeModal === "avatar"}
            panelClassName="choice-modal-panel ui-modal-panel is-wide is-avatar-editor"
            trigger={({ triggerButtonProps }) => <Button {...triggerButtonProps} icon={FileImage} variant="edit">{t("ui.avatar.edit")}</Button>}
          >
            {({ closeModal, titleId }) => (
              <div className="ui-modal">
                <ChoiceModalHeader closeLabel={closeLabel} icon={FileImage} iconTone="brand" kicker={t("ui.avatar.title")} onClose={closeModal} title={t("ui.avatar.edit")} titleId={titleId}>
                  <p className="ui-modal-copy">{t("ui.avatar.copy")}</p>
                </ChoiceModalHeader>
                <div className="ui-avatar-editor">
                  <AvatarCropper
                    actions={avatarPreviewActions(closeModal)}
                    crop={avatarCrop}
                    cropLabel={t("ui.avatar.crop")}
                    filterControls={(
                      <AvatarFilterStepper
                        filters={UiAvatarFilterItems}
                        nextLabel={`${t("ui.avatar.filters")} successivo`}
                        onChange={setAvatarChoice}
                        previousLabel={`${t("ui.avatar.filters")} precedente`}
                        value={avatarChoice}
                      />
                    )}
                    filterId={avatarChoice}
                    initials="ST"
                    name={avatarFallbackName}
                    onCropChange={setAvatarCrop}
                    source={avatarPreview}
                  />
                </div>
              </div>
            )}
          </Modal>
        </UiModalPattern>

        <UiModalPattern icon={Rows3} meta={t("ui.modals.list.meta", { selected: selectedList.label })} title={t("ui.modals.list.title")}>
          <Modal
            backdropClassName="choice-modal-backdrop"
            layoutId="ui-modal-list"
            onOpenChange={(open) => {
              setActiveModal(open ? "list" : null);
              if (open) setListSearch("");
            }}
            open={activeModal === "list"}
            panelClassName="choice-modal-panel ui-modal-panel"
            size="sm"
            trigger={({ triggerButtonProps }) => <Button {...triggerButtonProps} icon={Rows3} solid={false} variant="primary">{t("ui.modals.list.open")}</Button>}
          >
            {({ closeModal, titleId }) => (
              <div className="ui-modal ui-search-list-modal">
                <ChoiceModalHeader closeLabel={closeLabel} icon={Rows3} iconTone="country" kicker={t("ui.modals.list.kicker")} onClose={closeModal} title={t("ui.modals.list.header")} titleId={titleId} />
                <SearchInput icon={Search} iconTone="brand" label={t("ui.modals.list.search")} value={listSearch} onChange={setListSearch} />
                <SelectList className="custom-select-menu choice-modal-list ui-modal-choice-list" onChange={setListChoice} onClose={closeModal} options={filteredListOptions} value={listChoice} />
              </div>
            )}
          </Modal>
        </UiModalPattern>

        <UiModalPattern icon={Languages} meta={t("ui.modals.options.meta", { selected: selectedOption.title })} title={t("ui.modals.options.title")}>
          <Modal
            backdropClassName="choice-modal-backdrop"
            layoutId="ui-modal-options"
            onOpenChange={(open) => setActiveModal(open ? "options" : null)}
            open={activeModal === "options"}
            panelClassName="choice-modal-panel ui-modal-panel is-wide"
            trigger={({ triggerButtonProps }) => <Button {...triggerButtonProps} icon={Languages} variant="edit">{t("ui.modals.options.open")}</Button>}
          >
            {({ closeModal, titleId }) => (
              <div className="ui-modal">
                <ChoiceModalHeader closeLabel={closeLabel} icon={Languages} iconTone="language" kicker={t("ui.modals.options.kicker")} onClose={closeModal} title={t("ui.modals.options.header")} titleId={titleId} />
                <div className="ui-modal-choice-grid" role="listbox" aria-label={t("ui.modals.options.aria")}>
                  {UiModalChoiceItems.map((item) => (
                    <ChoiceCard
                      aria-selected={optionChoice === item.id}
                      className="ui-choice-card ui-modal-choice-card"
                      icon={item.icon}
                      key={item.id}
                      onClick={() => setOptionChoice(item.id)}
                      role="option"
                      selected={optionChoice === item.id}
                      text={item.text}
                      title={item.title}
                    />
                  ))}
                </div>
                <ModalFooter className="ui-modal-footer">
                  <Button icon={Check} onClick={closeModal} variant="primary">{t("ui.action.apply")}</Button>
                </ModalFooter>
              </div>
            )}
          </Modal>
        </UiModalPattern>
      </UiModalGroup>

    </div>
  );
}

export type UiModalChoiceId = "balanced" | "manual" | "quiet";
type UiAvatarFilterId = "cool" | "mono" | "natural" | "soft" | "warm";

function UiModalGroup({
  children,
  title,
}: {
  children: ReactNode;
  title: string;
}) {
  return (
    <section className="ui-modal-group" aria-label={title}>
      <div className="ui-modal-group-head">
        <strong>{title}</strong>
      </div>
      <div className="ui-modal-pattern-grid">
        {children}
      </div>
    </section>
  );
}

function UiModalPattern({
  children,
  className,
  icon: Icon,
  meta,
  title,
}: {
  children: ReactNode;
  className?: string;
  icon: IconType;
  meta: string;
  title: string;
}) {
  return (
    <section className={classNames("ui-modal-pattern", className)} aria-label={title}>
      <div className="ui-modal-pattern-head">
        <span className="ui-modal-pattern-icon">
          <Icon aria-hidden="true" size={16} />
        </span>
        <div>
          <strong>{title}</strong>
          <span>{meta}</span>
        </div>
      </div>
      <div className="ui-modal-pattern-action">
        {children}
      </div>
    </section>
  );
}
