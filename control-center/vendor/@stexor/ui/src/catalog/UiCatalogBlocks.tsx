"use client";

import { forwardRef, useEffect, useRef, useState, type ButtonHTMLAttributes, type ReactNode } from "react";
import { AvatarCropper, AvatarFilterStepper, Badge, Button, ChoiceCard, CommandPalette, CustomScrollbar, Dropdown, Popover, StatusPill, getAvatarVisualFilterItems, type AvatarCrop, type AvatarVisualFilter, type ButtonVariant } from "../client";
import { BadgeCheck, Bell, ChevronDown, ChevronLeft, ChevronRight, CircleInfo, Copy, FileImage, LayoutGrid, MoreHorizontal, Paste, Search, ShieldCheck, Sliders, type IconType } from "../icons";
import { useI18n } from "../i18n";

type BlockSurface = "gray" | "white";
type BlockVariant = "steps" | "expandable" | "static";
type BlockButtonId = "commands" | "copy" | "info" | "more" | "paste";
type BlockChoiceId = "balanced" | "manual" | "preferences" | "profile" | "quiet" | "review";
type BlockChoiceScrollState = {
  next: boolean;
  previous: boolean;
};
type BlockButtonConfig = {
  icon: IconType;
  iconPosition?: "end" | "start";
  label: string;
  solid?: boolean;
  spinIconOnClick?: boolean;
  variant: ButtonVariant;
};

const blockAvatarImage = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 512'%3E%3Crect width='512' height='512' fill='%23d6e7ff'/%3E%3Ccircle cx='256' cy='204' r='78' fill='%231a73e8'/%3E%3Cpath d='M116 430c28-82 92-126 140-126s112 44 140 126' fill='%231a73e8'/%3E%3C/svg%3E";
const initialBlockAvatarCrop: AvatarCrop = { size: 1, x: 0, y: 0 };
const initialChoiceScrollState: Record<BlockSurface, BlockChoiceScrollState> = {
  gray: { next: true, previous: false },
  white: { next: true, previous: false },
};

function blockCardClass(variant: BlockVariant, kind?: "overlay") {
  return `ui-block-card ui-block-${variant}${kind ? ` is-enterprise is-${kind}` : ""}`;
}

function blockCardSurface(surface: BlockSurface) {
  return surface === "white" ? "gray" : "white";
}

function stepActionVisibilityClass(visible: boolean) {
  return visible ? "is-visible" : "is-hidden";
}

function BlockSurfaceDemo({
  children,
  label,
  surface,
}: {
  children: ReactNode;
  label: string;
  surface: BlockSurface;
}) {
  return (
    <article className="ui-block-demo-surface" data-ui-surface={surface} aria-label={label}>
      <Badge tone="current">{label}</Badge>
      {children}
    </article>
  );
}

export function UiBlocksSurface() {
  const { t } = useI18n();
  const [currentStepBySurface, setCurrentStepBySurface] = useState<Record<BlockSurface, number>>({
    gray: 1,
    white: 0,
  });
  const [expandedBlocks, setExpandedBlocks] = useState<Record<BlockSurface, boolean>>({
    gray: false,
    white: false,
  });
  const [avatarFilterBySurface, setAvatarFilterBySurface] = useState<Record<BlockSurface, AvatarVisualFilter>>({
    gray: "soft",
    white: "natural",
  });
  const [avatarCropBySurface, setAvatarCropBySurface] = useState<Record<BlockSurface, AvatarCrop>>({
    gray: initialBlockAvatarCrop,
    white: initialBlockAvatarCrop,
  });
  const [choiceBySurface, setChoiceBySurface] = useState<Record<BlockSurface, BlockChoiceId>>({
    gray: "quiet",
    white: "balanced",
  });
  const [choiceScrollBySurface, setChoiceScrollBySurface] = useState<Record<BlockSurface, BlockChoiceScrollState>>(initialChoiceScrollState);
  const [activeOverlay, setActiveOverlay] = useState<string | null>(null);
  const choiceCarouselRefs = useRef<Record<BlockSurface, HTMLDivElement | null>>({
    gray: null,
    white: null,
  });
  const avatarFilters = getAvatarVisualFilterItems(t);
  const choiceItems = [
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
    {
      icon: LayoutGrid,
      id: "profile",
      text: t("ui.blocks.steps.profileMeta"),
      title: t("ui.blocks.steps.profile"),
    },
    {
      icon: Bell,
      id: "preferences",
      text: t("ui.blocks.steps.preferencesMeta"),
      title: t("ui.blocks.steps.preferences"),
    },
    {
      icon: BadgeCheck,
      id: "review",
      text: t("ui.blocks.steps.reviewMeta"),
      title: t("ui.blocks.steps.review"),
    },
  ] as const;
  const stepItems = [
    {
      meta: t("ui.blocks.steps.profileMeta"),
      title: t("ui.blocks.steps.profile"),
    },
    {
      meta: t("ui.blocks.steps.preferencesMeta"),
      title: t("ui.blocks.steps.preferences"),
    },
    {
      meta: t("ui.blocks.steps.reviewMeta"),
      title: t("ui.blocks.steps.review"),
    },
  ] as const;
  const surfaces = [
    { id: "white", label: t("ui.surface.white") },
    { id: "gray", label: t("ui.surface.gray") },
  ] as const;
  const commandItems = [
    { group: t("ui.blocks.overlay.group"), icon: Search, id: "search", label: t("common.search"), shortcut: "K" },
    { disabled: true, group: t("ui.blocks.overlay.group"), icon: ShieldCheck, id: "disabled", label: t("ui.status.protected") },
  ];

  function selectChoice(surface: BlockSurface, choiceId: BlockChoiceId, choiceIndex: number) {
    setChoiceBySurface((current) => ({
      ...current,
      [surface]: choiceId,
    }));
    requestAnimationFrame(() => {
      choiceCarouselRefs.current[surface]
        ?.querySelector<HTMLElement>(`[data-ui-block-choice-index="${choiceIndex}"]`)
        ?.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "center" });
      requestAnimationFrame(() => syncChoiceCarousel(surface));
    });
  }

  function moveChoice(surface: BlockSurface, direction: -1 | 1) {
    const currentIndex = getCenteredChoiceIndex(surface) ?? Math.max(0, choiceItems.findIndex((item) => item.id === choiceBySurface[surface]));
    const nextIndex = Math.min(choiceItems.length - 1, Math.max(0, currentIndex + direction));
    const nextChoice = choiceItems[nextIndex];
    if (nextChoice) selectChoice(surface, nextChoice.id, nextIndex);
  }

  function syncChoiceCarousel(surface: BlockSurface) {
    const rail = choiceCarouselRefs.current[surface];
    if (!rail) return;
    const maxScroll = Math.max(0, rail.scrollWidth - rail.clientWidth);
    const nextState = {
      next: rail.scrollLeft < maxScroll - 2,
      previous: rail.scrollLeft > 2,
    };
    setChoiceScrollBySurface((current) => {
      const currentState = current[surface];
      if (currentState.next === nextState.next && currentState.previous === nextState.previous) return current;
      return {
        ...current,
        [surface]: nextState,
      };
    });
  }

  function getCenteredChoiceIndex(surface: BlockSurface) {
    const rail = choiceCarouselRefs.current[surface];
    if (!rail) return null;
    const railBounds = rail.getBoundingClientRect();
    const railCenter = railBounds.left + (railBounds.width / 2);
    const cards = Array.from(rail.querySelectorAll<HTMLElement>("[data-ui-block-choice-index]"));
    if (!cards.length) return null;

    let closestIndex = 0;
    let closestDistance = Number.POSITIVE_INFINITY;
    for (const card of cards) {
      const index = Number(card.dataset.uiBlockChoiceIndex ?? 0);
      const bounds = card.getBoundingClientRect();
      const distance = Math.abs((bounds.left + (bounds.width / 2)) - railCenter);
      if (distance < closestDistance) {
        closestDistance = distance;
        closestIndex = index;
      }
    }
    return closestIndex;
  }

  useEffect(() => {
    function syncAllChoiceCarousels() {
      syncChoiceCarousel("white");
      syncChoiceCarousel("gray");
    }

    syncAllChoiceCarousels();
    window.addEventListener("resize", syncAllChoiceCarousels);
    return () => window.removeEventListener("resize", syncAllChoiceCarousels);
  }, [choiceItems.length]);

  return (
    <div className="ui-blocks-layout" aria-label={t("ui.blocks.aria")}>
      <div className="ui-block-pair">
        {surfaces.map((surface) => {
          const currentStep = currentStepBySurface[surface.id];
          const isFirstStep = currentStep === 0;
          const isLastStep = currentStep === stepItems.length - 1;
          const goBack = () => setCurrentStepBySurface((current) => ({
            ...current,
            [surface.id]: Math.max(0, current[surface.id] - 1),
          }));
          const goForward = () => setCurrentStepBySurface((current) => ({
            ...current,
            [surface.id]: Math.min(stepItems.length - 1, current[surface.id] + 1),
          }));
          const resetSteps = () => setCurrentStepBySurface((current) => ({
            ...current,
            [surface.id]: 0,
          }));
          const rightActionLabel = isLastStep ? t("ui.action.complete") : t("ui.action.next");

          return (
            <BlockSurfaceDemo key={`steps-${surface.id}`} label={surface.label} surface={surface.id}>
              <div className={blockCardClass("steps")} data-ui-surface={blockCardSurface(surface.id)}>
                <div className="ui-block-card-head">
                  <span className="ui-block-card-icon"><LayoutGrid size={18} /></span>
                  <div>
                    <strong>{t("ui.blocks.steps.title")}</strong>
                  </div>
                  <Badge tone="current">{t("ui.blocks.steps.badge")}</Badge>
                </div>
                <div className={`ui-block-meter is-step-${currentStep + 1}`} aria-hidden="true"><span /></div>
                <div
                  className="ui-block-step-list"
                  aria-label={t("ui.blocks.steps.title")}
                  data-current-step={currentStep + 1}
                >
                  {stepItems.map((step, index) => {
                    const stepState = index < currentStep ? "is-done" : index === currentStep ? "is-active" : "is-future";

                    return (
                      <div
                        aria-current={index === currentStep ? "step" : undefined}
                        className={`ui-block-step ${stepState}`}
                        key={`${surface.id}-${step.title}`}
                      >
                        {index < currentStep ? (
                          <span className="ui-block-step-marker is-done">
                            <BadgeCheck size={14} />
                          </span>
                        ) : null}
                        {index === currentStep ? (
                          <span className="ui-block-step-marker is-active">{index + 1}</span>
                        ) : null}
                        {index > currentStep ? <span className="ui-block-step-marker is-future" aria-hidden="true" /> : null}
                        <span>
                          <strong>{step.title}</strong>
                          <small>{step.meta}</small>
                        </span>
                      </div>
                    );
                  })}
                </div>
                <div className="ui-block-actions ui-block-step-flow">
                  <span className="ui-block-step-action-slot is-left" aria-hidden={isFirstStep ? true : undefined}>
                    <Button
                      aria-label={t("common.back")}
                      aria-hidden={isFirstStep ? true : undefined}
                      className={`ui-round-icon ui-block-step-action is-back ${stepActionVisibilityClass(!isFirstStep)}`}
                      compact
                      icon={ChevronLeft}
                      onClick={goBack}
                      tabIndex={isFirstStep ? -1 : undefined}
                      variant="muted"
                    />
                  </span>
                  <span className="ui-block-step-action-slot is-right">
                    <Button
                      aria-label={isLastStep ? undefined : rightActionLabel}
                      className={`ui-block-step-action is-forward ${isLastStep ? "is-complete" : "ui-block-step-round is-next"}`}
                      compact
                      icon={isLastStep ? BadgeCheck : ChevronRight}
                      onClick={isLastStep ? resetSteps : goForward}
                      variant="primary"
                    >
                      {isLastStep ? rightActionLabel : undefined}
                    </Button>
                  </span>
                </div>
              </div>
            </BlockSurfaceDemo>
          );
        })}
      </div>

      <div className="ui-block-pair">
        {surfaces.map((surface) => {
          const selectedChoiceId = choiceBySurface[surface.id];
          const selectedChoice = choiceItems.find((item) => item.id === selectedChoiceId) ?? choiceItems[0]!;
          const choiceScrollState = choiceScrollBySurface[surface.id];

          return (
            <BlockSurfaceDemo key={`choice-carousel-${surface.id}`} label={surface.label} surface={surface.id}>
              <div className={`${blockCardClass("static")} ui-block-choice-carousel`} data-ui-surface={blockCardSurface(surface.id)}>
                <div className="ui-block-card-head">
                  <span className="ui-block-card-icon"><Sliders size={18} /></span>
                  <div>
                    <strong>{t("ui.modals.options.header")}</strong>
                    <small>{t("ui.modals.options.aria")}</small>
                  </div>
                  <StatusPill tone="good">{selectedChoice.title}</StatusPill>
                </div>
                <div
                  className="ui-block-choice-carousel-shell"
                  data-can-scroll-left={choiceScrollState.previous}
                  data-can-scroll-right={choiceScrollState.next}
                >
                  <Button
                    aria-label={t("common.back")}
                    aria-hidden={choiceScrollState.previous ? undefined : true}
                    className={`ui-round-icon ui-block-choice-carousel-arrow is-left ${stepActionVisibilityClass(choiceScrollState.previous)}`}
                    compact
                    disabled={!choiceScrollState.previous}
                    icon={ChevronLeft}
                    onClick={() => moveChoice(surface.id, -1)}
                    tabIndex={choiceScrollState.previous ? undefined : -1}
                    variant="muted"
                  />
                  <div
                    aria-label={t("ui.modals.options.aria")}
                    className="ui-block-choice-carousel-rail"
                    onScroll={() => syncChoiceCarousel(surface.id)}
                    ref={(element) => {
                      choiceCarouselRefs.current[surface.id] = element;
                      if (element) requestAnimationFrame(() => syncChoiceCarousel(surface.id));
                    }}
                    role="radiogroup"
                  >
                    {choiceItems.map((item, index) => (
                      <ChoiceCard
                        aria-checked={selectedChoiceId === item.id}
                        className="ui-choice-card ui-block-choice-carousel-card"
                        data-ui-block-choice-index={index}
                        icon={item.icon}
                        key={`${surface.id}-${item.id}`}
                        onClick={() => selectChoice(surface.id, item.id, index)}
                        role="radio"
                        selected={selectedChoiceId === item.id}
                        text={item.text}
                        title={item.title}
                      />
                    ))}
                  </div>
                  <Button
                    aria-label={t("ui.action.next")}
                    aria-hidden={choiceScrollState.next ? undefined : true}
                    className={`ui-round-icon ui-block-choice-carousel-arrow is-right ${stepActionVisibilityClass(choiceScrollState.next)}`}
                    compact
                    disabled={!choiceScrollState.next}
                    icon={ChevronRight}
                    onClick={() => moveChoice(surface.id, 1)}
                    tabIndex={choiceScrollState.next ? undefined : -1}
                    variant="muted"
                  />
                </div>
              </div>
            </BlockSurfaceDemo>
          );
        })}
      </div>

      <div className="ui-block-pair">
        {surfaces.map((surface) => {
          const avatarFilter = avatarFilterBySurface[surface.id];

          return (
            <BlockSurfaceDemo key={`avatar-filter-${surface.id}`} label={surface.label} surface={surface.id}>
              <div className={`${blockCardClass("static")} ui-block-avatar-filter`} data-ui-surface={blockCardSurface(surface.id)}>
                <div className="ui-block-card-head">
                  <span className="ui-block-card-icon"><FileImage size={18} /></span>
                  <div>
                    <strong>{t("ui.avatar.title")}</strong>
                    <small>{t("ui.avatar.filters")}</small>
                  </div>
                  <StatusPill tone="good">{avatarFilters.find((filter) => filter.id === avatarFilter)?.title ?? t("ui.avatar.filters")}</StatusPill>
                </div>
                <AvatarCropper
                  crop={avatarCropBySurface[surface.id]}
                  cropLabel={t("ui.avatar.crop")}
                  filterControls={(
                    <AvatarFilterStepper
                      filters={avatarFilters}
                      nextLabel={`${t("ui.avatar.filters")} successivo`}
                      onChange={(filterId) => setAvatarFilterBySurface((current) => ({
                        ...current,
                        [surface.id]: filterId,
                      }))}
                      previousLabel={`${t("ui.avatar.filters")} precedente`}
                      value={avatarFilter}
                    />
                  )}
                  filterId={avatarFilter}
                  initials="ST"
                  name="Stexor UI"
                  onCropChange={(crop) => setAvatarCropBySurface((current) => ({
                    ...current,
                    [surface.id]: crop,
                  }))}
                  source={blockAvatarImage}
                />
              </div>
            </BlockSurfaceDemo>
          );
        })}
      </div>

      <div className="ui-block-pair">
        {surfaces.map((surface) => {
          const isExpanded = expandedBlocks[surface.id];

          return (
            <BlockSurfaceDemo key={`expandable-${surface.id}`} label={surface.label} surface={surface.id}>
              <div
                className={`${blockCardClass("expandable")} is-card`}
                data-expanded={isExpanded ? "true" : "false"}
                data-ui-surface={blockCardSurface(surface.id)}
              >
                <button
                  aria-expanded={isExpanded}
                  className="ui-block-disclosure is-card"
                  onClick={() => setExpandedBlocks((current) => ({
                    ...current,
                    [surface.id]: !current[surface.id],
                  }))}
                  type="button"
                >
                  <span className="ui-block-card-icon">
                    <Sliders size={18} />
                  </span>
                  <span>
                    <strong>{t("ui.blocks.expandable.cardTitle")}</strong>
                  </span>
                  <span className="ui-block-summary-side">
                    <StatusPill tone="good">{t("ui.status.active")}</StatusPill>
                    <ChevronDown className="ui-block-chevron" size={14} />
                  </span>
                </button>
                <div className="ui-block-expand-shell" aria-hidden={!isExpanded}>
                  <div className="ui-block-expand-inner">
                    <div className="ui-block-expand-content">
                      <p>{t("ui.blocks.expandable.copy")}</p>
                      <div className="ui-block-meter is-64" aria-hidden="true"><span /></div>
                      <div className="ui-block-actions">
                        <BlockButton id="copy" compact />
                        <BlockButton id="paste" compact />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </BlockSurfaceDemo>
          );
        })}
      </div>

      <div className="ui-block-pair">
        {surfaces.map((surface) => (
          <BlockSurfaceDemo key={`static-${surface.id}`} label={surface.label} surface={surface.id}>
            <div className={blockCardClass("static")} data-ui-surface={blockCardSurface(surface.id)}>
              <div className="ui-block-card-head">
                <span className="ui-block-card-icon"><ShieldCheck size={18} /></span>
                <div>
                  <strong>{t("ui.blocks.static.title")}</strong>
                </div>
                <StatusPill tone="warning">{t("ui.status.attention")}</StatusPill>
              </div>
              <p>{t("ui.blocks.static.copy")}</p>
            </div>
          </BlockSurfaceDemo>
        ))}
      </div>

      <div className="ui-block-pair">
        {surfaces.map((surface) => (
          <BlockSurfaceDemo key={`scrollbar-${surface.id}`} label={surface.label} surface={surface.id}>
            <BlockScrollbarDemo items={stepItems} surface={surface.id} />
          </BlockSurfaceDemo>
        ))}
      </div>

      <div className="ui-block-pair">
        {surfaces.map((surface) => (
          <BlockSurfaceDemo key={`overlay-${surface.id}`} label={surface.label} surface={surface.id}>
            <div className={blockCardClass("static", "overlay")} data-ui-block-kind="overlay" data-ui-surface={blockCardSurface(surface.id)}>
              <div className="ui-block-card-head">
                <span className="ui-block-card-icon"><MoreHorizontal size={18} /></span>
                <div>
                  <strong>{t("ui.blocks.overlay.title")}</strong>
                </div>
                <StatusPill tone="good">{t("ui.blocks.overlay.badge")}</StatusPill>
              </div>
              <p>{t("ui.blocks.overlay.copy")}</p>
              <div className="ui-block-actions">
                <Dropdown
                  motion="morph"
                  onOpenChange={(open) => setActiveOverlay(open ? `${surface.id}-dropdown` : null)}
                  open={activeOverlay === `${surface.id}-dropdown`}
                  title={t("ui.action.more")}
                  trigger={({ triggerProps }) => <BlockButton {...triggerProps} id="more" compact />}
                >
                  <div className="ui-block-overlay-menu">
                    <BlockButton id="copy" compact />
                    <BlockButton id="paste" compact />
                  </div>
                </Dropdown>
                <Popover
                  motion="morph"
                  onOpenChange={(open) => setActiveOverlay(open ? `${surface.id}-popover` : null)}
                  open={activeOverlay === `${surface.id}-popover`}
                  title={t("ui.action.info")}
                  trigger={({ triggerProps }) => <BlockButton {...triggerProps} id="info" compact />}
                >
                  <div className="ui-block-overlay-content">
                    <p>{t("ui.blocks.overlay.copy")}</p>
                  </div>
                </Popover>
                <CommandPalette
                  commands={commandItems}
                  motion="morph"
                  onOpenChange={(open) => setActiveOverlay(open ? `${surface.id}-command` : null)}
                  open={activeOverlay === `${surface.id}-command`}
                  recentCommandIds={["search"]}
                  title={t("ui.blocks.overlay.command")}
                  trigger={({ triggerProps }) => <BlockButton {...triggerProps} id="commands" compact />}
                />
              </div>
            </div>
          </BlockSurfaceDemo>
        ))}
      </div>
    </div>
  );
}

function BlockScrollbarDemo({
  items,
  surface,
}: {
  items: ReadonlyArray<{ meta: string; title: string }>;
  surface: BlockSurface;
}) {
  const scrollRootRef = useRef<HTMLDivElement | null>(null);
  return (
    <div className={`${blockCardClass("static")} ui-block-scroll-demo`} data-ui-surface={blockCardSurface(surface)}>
      <div className="ui-block-card-head">
        <span className="ui-block-card-icon"><LayoutGrid size={18} /></span>
        <div>
          <strong>CustomScrollbar</strong>
        </div>
        <StatusPill tone="good">{items.length}</StatusPill>
      </div>
      <div className="ui-block-scroll-demo-shell">
        <div className="ui-block-scroll-demo-frame" ref={scrollRootRef}>
          {items.concat(items).map((item, index) => (
            <div className="ui-block-scroll-demo-row" key={`${item.title}-${index}`}>
              <span className="ui-block-step-marker is-future" aria-hidden="true" />
              <span>
                <strong>{item.title}</strong>
                <small>{item.meta}</small>
              </span>
            </div>
          ))}
        </div>
        <CustomScrollbar
          className="ui-block-local-scrollbar"
          draggingClassName="ui-block-local-scrollbar-dragging"
          rootRef={scrollRootRef}
          thumbClassName="ui-block-local-scrollbar-thumb"
          visibleClassName="is-visible"
        />
      </div>
    </div>
  );
}

type BlockButtonProps = { compact?: boolean; id: BlockButtonId; solid?: boolean } & Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children">;

const BlockButton = forwardRef<HTMLElement, BlockButtonProps>(function BlockButton({
  id,
  solid,
  ...props
}, ref) {
  const { t } = useI18n();
  const config = getBlockButtonConfig(id, t);

  return (
    <Button
      {...props}
      icon={config.icon}
      iconPosition={config.iconPosition}
      ref={ref}
      solid={solid ?? config.solid}
      spinIconOnClick={config.spinIconOnClick}
      variant={config.variant}
    >
      {config.label}
    </Button>
  );
});

function getBlockButtonConfig(id: BlockButtonId, t: ReturnType<typeof useI18n>["t"]) {
  const configs: Record<BlockButtonId, BlockButtonConfig> = {
    commands: { icon: Search, label: t("ui.blocks.overlay.command"), solid: false, variant: "primary" },
    copy: { icon: Copy, label: t("ui.action.copy"), solid: false, variant: "primary" },
    info: { icon: CircleInfo, label: t("ui.action.info"), solid: false, variant: "primary" },
    more: { icon: MoreHorizontal, label: t("ui.action.more"), variant: "muted" },
    paste: { icon: Paste, label: t("ui.action.paste"), variant: "edit" },
  };
  return configs[id];
}
