"use client";

import { Children, cloneElement, forwardRef, isValidElement } from "react";
import type { HTMLAttributes, ReactElement, ReactNode, Ref } from "react";
import { classNames } from "./classNames";

type SlotChildProps = HTMLAttributes<HTMLElement> & {
  ref?: Ref<HTMLElement>;
};

type SlotProps = HTMLAttributes<HTMLElement> & {
  children: ReactNode;
};

export const Slot = forwardRef<HTMLElement, SlotProps>(function Slot({
  children,
  className,
  onClick,
  ...slotProps
}, ref) {
  const child = Children.only(children);
  if (!isValidElement<SlotChildProps>(child)) {
    throw new Error("Slot expects a single valid React element.");
  }

  return cloneElement(child as ReactElement<SlotChildProps>, {
    ...slotProps,
    className: classNames(child.props.className, className),
    onClick: composeEventHandlers(child.props.onClick, onClick),
    ref: mergeRefs(child.props.ref, ref),
  });
});

function composeEventHandlers(
  childHandler?: HTMLAttributes<HTMLElement>["onClick"],
  slotHandler?: HTMLAttributes<HTMLElement>["onClick"],
) {
  if (!childHandler) return slotHandler;
  if (!slotHandler) return childHandler;
  return (event: Parameters<NonNullable<HTMLAttributes<HTMLElement>["onClick"]>>[0]) => {
    childHandler(event);
    if (!event.defaultPrevented) slotHandler(event);
  };
}

function mergeRefs(...refs: Array<Ref<HTMLElement> | undefined>) {
  return (node: HTMLElement | null) => {
    for (const ref of refs) {
      if (!ref) continue;
      if (typeof ref === "function") {
        ref(node);
      } else {
        ref.current = node;
      }
    }
  };
}
