"use client";

import type { ReactNode } from "react";
import type { IconType } from "./icons";
import { X } from "./icons";
import { Button } from "./Button";
import { classNames } from "./classNames";
import type { IconTone } from "./Form";

export function ChoiceModalHeader({
  children,
  className,
  closeClassName,
  closeIconSize = 12,
  closeLabel = "Chiudi",
  icon: Icon,
  iconTone,
  kicker,
  onClose,
  title,
  titleId,
}: {
  children?: ReactNode;
  className?: string;
  closeClassName?: string;
  closeIconSize?: number;
  closeLabel?: string;
  icon?: IconType;
  iconTone?: IconTone;
  kicker?: ReactNode;
  onClose: () => void;
  title: ReactNode;
  titleId?: string;
}) {
  const resolvedIconTone = iconTone ?? (Icon ? "brand" : undefined);

  return (
    <header className={classNames("choice-modal-header", className)}>
      <div>
        {kicker ? (
          <span className="choice-modal-kicker">
            {Icon ? (
              <span className={classNames("choice-modal-kicker-icon", resolvedIconTone && `is-${resolvedIconTone}`)}>
                <Icon aria-hidden="true" size={15} />
              </span>
            ) : null}
            {kicker}
          </span>
        ) : null}
        <span className="choice-modal-title-sr" id={titleId}>{title}</span>
        {children}
      </div>
      <Button aria-label={closeLabel} className={classNames("ui-round-icon modal-close-button", closeClassName)} compact icon={X} iconSize={closeIconSize} onClick={onClose} title={closeLabel} variant="muted" />
    </header>
  );
}

export function ModalFooter({
  children,
  className,
}: {
  children: ReactNode;
  className: string;
}) {
  return <footer className={className}>{children}</footer>;
}
