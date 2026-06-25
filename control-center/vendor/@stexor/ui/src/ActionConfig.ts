const uiActionVariants = [
  "cyan",
  "danger",
  "edit",
  "muted",
  "plain",
  "primary",
  "rose",
  "slate",
  "teal",
  "violet",
  "warning",
] as const;

export type UiActionVariant = typeof uiActionVariants[number];

export const uiActionVariantClasses: Record<UiActionVariant, string> = {
  cyan: "cyan-button",
  danger: "danger-button",
  edit: "edit-button",
  muted: "muted-button",
  plain: "",
  primary: "primary-button",
  rose: "rose-button",
  slate: "slate-button",
  teal: "teal-button",
  violet: "violet-button",
  warning: "warning-button",
};

type UiActionTone = { background: string; color: string };

const uiActionVariantTones: Record<UiActionVariant, UiActionTone> = {
  cyan: { background: "var(--ui-action-cyan-bg)", color: "var(--ui-action-cyan-fg)" },
  danger: { background: "var(--ui-action-danger-bg)", color: "var(--ui-action-danger-fg)" },
  edit: { background: "var(--ui-action-edit-bg)", color: "var(--ui-action-edit-fg)" },
  muted: { background: "var(--ui-action-muted-bg)", color: "var(--ui-action-muted-fg)" },
  plain: { background: "transparent", color: "var(--text)" },
  primary: { background: "var(--ui-action-primary-bg)", color: "var(--ui-action-primary-fg)" },
  rose: { background: "var(--ui-action-rose-bg)", color: "var(--ui-action-rose-fg)" },
  slate: { background: "var(--ui-action-slate-bg)", color: "var(--ui-action-slate-fg)" },
  teal: { background: "var(--ui-action-teal-bg)", color: "var(--ui-action-teal-fg)" },
  violet: { background: "var(--ui-action-violet-bg)", color: "var(--ui-action-violet-fg)" },
  warning: { background: "var(--ui-action-warning-bg)", color: "var(--ui-action-warning-fg)" },
};

const uiActionSolidVariantTones: Partial<Record<UiActionVariant, UiActionTone>> = {
  cyan: { background: "var(--ui-action-cyan-fg)", color: "var(--ui-action-solid-fg)" },
  danger: { background: "var(--ui-action-danger-fg)", color: "var(--ui-action-solid-fg)" },
  edit: { background: "var(--ui-action-edit-fg)", color: "var(--ui-action-solid-fg)" },
  primary: uiActionVariantTones.primary,
  rose: { background: "var(--ui-action-rose-fg)", color: "var(--ui-action-solid-fg)" },
  slate: { background: "var(--ui-action-slate-fg)", color: "var(--ui-action-solid-fg)" },
  teal: { background: "var(--ui-action-teal-fg)", color: "var(--ui-action-solid-fg)" },
  violet: { background: "var(--ui-action-violet-fg)", color: "var(--ui-action-solid-fg)" },
  warning: { background: "var(--ui-action-warning-fg)", color: "var(--ui-action-solid-fg)" },
};

const uiActionSoftVariantTones: Partial<Record<UiActionVariant, UiActionTone>> = {
  primary: { background: "var(--ui-action-primary-soft-bg)", color: "var(--ui-action-primary-soft-fg)" },
};

export function getUiActionVariantTone(variant: UiActionVariant, solid?: boolean): UiActionTone {
  if (solid === true) return uiActionSolidVariantTones[variant] ?? uiActionVariantTones[variant];
  if (solid === false) return uiActionSoftVariantTones[variant] ?? uiActionVariantTones[variant];
  return uiActionVariantTones[variant];
}

export type UiActionBuilderVariant = Exclude<UiActionVariant, "plain">;

export const uiActionBuilderVariantOptions = [
  { label: "Primary", value: "primary" },
  { label: "Muted", value: "muted" },
  { label: "Cyan", value: "cyan" },
  { label: "Teal", value: "teal" },
  { label: "Edit", value: "edit" },
  { label: "Violet", value: "violet" },
  { label: "Rose", value: "rose" },
  { label: "Slate", value: "slate" },
  { label: "Warning", value: "warning" },
  { label: "Danger", value: "danger" },
] as const satisfies ReadonlyArray<{ label: string; value: UiActionBuilderVariant }>;

type UiActionBuilderShape = "compact-icon" | "compact-text" | "icon" | "text";

export const uiActionBuilderShapes = [
  { ariaLabel: undefined, compact: false, iconOnly: false, id: "text", label: "Normale" },
  { ariaLabel: "Solo icona", compact: false, iconOnly: true, id: "icon", label: "Icona" },
  { ariaLabel: undefined, compact: true, iconOnly: false, id: "compact-text", label: "Piccolo" },
  { ariaLabel: "Solo icona piccolo", compact: true, iconOnly: true, id: "compact-icon", label: "Mini icona" },
] as const satisfies ReadonlyArray<{
  ariaLabel?: string;
  compact: boolean;
  iconOnly: boolean;
  id: UiActionBuilderShape;
  label: string;
}>;

export type UiActionSpinDirection = "forward" | "reverse";

export function getUiActionSpinDirection(iconId: string): UiActionSpinDirection | undefined {
  const normalizedIconId = String(iconId).replace(/[-_\s]/g, "").toLowerCase();
  if (normalizedIconId === "history") return "reverse";
  if (normalizedIconId === "refreshccw") return "forward";
  return undefined;
}
