"use client";

import type { ButtonHTMLAttributes } from "react";
import { classNames } from "./classNames";
import type { IconType } from "./icons";
import { uiClassNames } from "./styleClasses";

export function ChoiceCard({
  className = uiClassNames.choiceCard,
  icon: Icon,
  selected = false,
  text,
  title,
  type = "button",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  icon: IconType;
  selected?: boolean;
  text: string;
  title: string;
}) {
  return (
    <button className={classNames(className, selected && "is-selected")} type={type} {...props}>
      <Icon aria-hidden="true" size={22} />
      <span>
        <strong>{title}</strong>
        <small>{text}</small>
      </span>
    </button>
  );
}
