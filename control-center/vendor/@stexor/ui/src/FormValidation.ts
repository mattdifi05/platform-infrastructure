export type UiValidationSeverity = "blocking" | "error" | "info" | "warning";
export type UiFieldStatus = "disabled" | "idle" | "invalid" | "pending" | "valid" | "warning";

export type UiValidationIssue = {
  fieldId?: string;
  message: string;
  severity: UiValidationSeverity;
};

export type UiFieldValidationState = {
  describedBy?: string;
  dirty: boolean;
  disabled: boolean;
  issues: UiValidationIssue[];
  status: UiFieldStatus;
  touched: boolean;
};

export function createUiFieldValidationState({
  describedBy,
  disabled = false,
  initialValue = "",
  issues = [],
  pending = false,
  touched = false,
  value = "",
}: {
  describedBy?: string;
  disabled?: boolean;
  initialValue?: string;
  issues?: UiValidationIssue[];
  pending?: boolean;
  touched?: boolean;
  value?: string;
}): UiFieldValidationState {
  const dirty = value !== initialValue;
  const blockingIssue = issues.some((issue) => issue.severity === "blocking" || issue.severity === "error");
  const warningIssue = issues.some((issue) => issue.severity === "warning");
  const status: UiFieldStatus = disabled
    ? "disabled"
    : pending
      ? "pending"
      : blockingIssue
        ? "invalid"
        : warningIssue
          ? "warning"
        : touched || dirty
          ? "valid"
          : "idle";

  return {
    describedBy,
    dirty,
    disabled,
    issues,
    status,
    touched,
  };
}

export function uiFieldA11yProps(state?: UiFieldValidationState) {
  if (!state) return {};
  return {
    "aria-busy": state.status === "pending" ? true : undefined,
    "aria-describedby": state.describedBy,
    "aria-disabled": state.disabled ? true : undefined,
    "aria-invalid": state.status === "invalid" ? true : undefined,
    "data-dirty": state.dirty ? "true" : undefined,
    "data-status": state.status,
    "data-touched": state.touched ? "true" : undefined,
  };
}
