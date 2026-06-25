"use client";

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { Button, type ButtonVariant } from "./Button";
import { classNames } from "./classNames";
import type { IconType } from "./icons";

export type ActionFlowButton = {
  ariaLabel?: string;
  className?: string;
  compact?: boolean;
  icon?: IconType;
  iconPosition?: "end" | "start";
  iconSize?: number;
  label?: ReactNode;
  loading?: boolean;
  onClick?: () => void;
  solid?: boolean;
  spinIconOnClick?: boolean;
  spinIconOnClickDirection?: "forward" | "reverse";
  spinIconOnClickDurationMs?: number;
  variant?: ButtonVariant;
};

export type ActionFlowProps = {
  active: boolean;
  action: ActionFlowButton;
  className?: string;
  reveal?: boolean;
  revealAction?: ActionFlowButton;
  revealSize?: "compact" | "regular";
  showLabel?: boolean;
  size?: "compact" | "regular";
};

const ACTION_FLOW_REVEAL_PRESENCE_MS = 320;

export function ActionFlow({
  active,
  action,
  className,
  reveal,
  revealAction,
  revealSize = "regular",
  showLabel = true,
  size = "regular",
}: ActionFlowProps) {
  const revealPresence = useActionFlowPresence(Boolean(revealAction && (reveal ?? active)));
  const revealRendered = Boolean(revealAction && revealPresence !== "hidden");
  const compact = size === "compact";
  const compactReveal = compact || revealSize === "compact";

  return (
    <div
      className={classNames(
        "ui-action-flow is-contained",
        active && "is-running",
        revealRendered && "has-reveal",
        compactReveal && "is-reveal-compact",
        !showLabel && "is-icon-only",
        className,
      )}
    >
      <span className="ui-action-flow-slot is-toggle">
        {renderActionFlowButton(action, action.onClick, { compact, showLabel })}
      </span>
      {revealAction && revealRendered ? (
        <span className={classNames("ui-action-flow-slot is-reveal", `is-${revealPresence}`)}>
          {renderActionFlowButton(revealAction, revealPresence === "exiting" ? undefined : revealAction.onClick, { compact, showLabel })}
        </span>
      ) : null}
    </div>
  );
}

function renderActionFlowButton(action: ActionFlowButton, onClick = action.onClick, options: { compact?: boolean; showLabel?: boolean } = {}) {
  const compact = action.compact ?? options.compact;
  const showLabel = options.showLabel ?? true;
  const ariaLabel = action.ariaLabel ?? (!showLabel ? getActionFlowLabelText(action.label) : undefined);

  return (
    <Button
      aria-label={ariaLabel}
      className={classNames(!showLabel && (action.icon || action.loading) && "ui-round-icon", action.className)}
      compact={compact}
      icon={action.icon}
      iconPosition={action.iconPosition}
      iconSize={action.iconSize ?? (compact ? 14 : undefined)}
      loading={action.loading}
      onClick={onClick}
      solid={action.solid}
      spinIconOnClick={action.spinIconOnClick}
      spinIconOnClickDirection={action.spinIconOnClickDirection}
      spinIconOnClickDurationMs={action.spinIconOnClickDurationMs}
      variant={action.variant}
    >
      {showLabel ? action.label : undefined}
    </Button>
  );
}

function getActionFlowLabelText(label: ReactNode) {
  if (typeof label === "string" || typeof label === "number" || typeof label === "bigint") return String(label);
  return undefined;
}

function useActionFlowPresence(active: boolean) {
  const [presence, setPresence] = useState<"entered" | "entering" | "exiting" | "hidden">(active ? "entered" : "hidden");

  useEffect(() => {
    const nextPresence = active ? "entering" : "exiting";
    const finalPresence = active ? "entered" : "hidden";

    setPresence((current) => {
      if (current === finalPresence) return current;
      if (!active && current === "hidden") return current;
      return nextPresence;
    });

    const timer = window.setTimeout(() => {
      setPresence(finalPresence);
    }, ACTION_FLOW_REVEAL_PRESENCE_MS);

    return () => window.clearTimeout(timer);
  }, [active]);

  return presence;
}
