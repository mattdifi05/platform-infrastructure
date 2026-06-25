"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Calendar, ChevronDown, ChevronLeft, ChevronRight } from "./icons";
import { useI18n } from "./i18n";
import { Modal } from "./Modal";
import { classNames } from "./classNames";
import { parseIsoDate, toIsoDate } from "./date";
import { ChoiceModalHeader } from "./ModalHeader";
import { uiClassNames } from "./styleClasses";
import type { IconTone } from "./Form";
import { useResolvedSurfaceRef } from "./useResolvedSurface";

export function DateInputField({ controlClassName, iconTone, label, value, onChange }: { controlClassName?: string; iconTone?: IconTone; label: string; value: string; onChange: (value: string) => void }) {
  const { locale, t } = useI18n();
  const surfaceRef = useResolvedSurfaceRef<HTMLButtonElement>();
  const resolvedIconTone = iconTone ?? "date";
  const selectedDate = parseIsoDate(value);
  const [open, setOpen] = useState(false);
  const controlActive = open || Boolean(value);
  const iconActive = open;
  const selectedLabel = selectedDate
    ? new Intl.DateTimeFormat(locale, { day: "2-digit", month: "2-digit", year: "numeric" }).format(selectedDate)
    : t("common.select");

  return (
    <Modal
      backdropClassName="choice-modal-backdrop"
      onOpenChange={(nextOpen) => {
        setOpen(nextOpen);
      }}
      open={open}
      panelClassName={classNames("choice-modal-panel", uiClassNames.dateModalPanel)}
      restoreFocus={false}
      size="sm"
      trigger={({ isOpen, sourceRef, triggerButtonProps }) => (
        <div className={classNames("field", uiClassNames.dateInput, isOpen && "is-open")}>
          <span className="field-label">{label}</span>
          <button
            {...triggerButtonProps}
            className={classNames("field-control", uiClassNames.dateButton, controlClassName, `has-icon-tone-${resolvedIconTone}`, controlActive && "is-active")}
            ref={(node) => {
              sourceRef(node);
              surfaceRef(node);
            }}
          >
            <span
              className={classNames("field-icon", `is-${resolvedIconTone}`)}
              data-active={iconActive ? "true" : "false"}
            >
              <Calendar size={17} />
            </span>
            <span className={uiClassNames.dateButtonCopy}>
              <strong>{selectedLabel}</strong>
            </span>
            <span
              className={uiClassNames.dateChevron}
              data-active={iconActive ? "true" : "false"}
            >
              <ChevronDown size={14} />
            </span>
          </button>
        </div>
      )}
    >
      {({ closeModal, titleId }) => (
        <CalendarPickerPanel
          closeLabel={t("common.close")}
          iconTone={resolvedIconTone}
          label={label}
          onChange={onChange}
          onClose={closeModal}
          titleId={titleId}
          value={value}
        />
      )}
    </Modal>
  );
}

export function CalendarPickerPanel({
  closeLabel,
  iconTone,
  label,
  onChange,
  onClose,
  titleId,
  value,
}: {
  closeLabel: string;
  iconTone?: IconTone;
  label: string;
  onChange: (value: string) => void;
  onClose: () => void;
  titleId?: string;
  value: string;
}) {
  const { locale, t } = useI18n();
  const resolvedIconTone = iconTone ?? "date";
  const selectedDate = parseIsoDate(value);
  const currentDate = useMemo(() => new Date(), []);
  const maxDate = useMemo(() => new Date(currentDate.getFullYear(), currentDate.getMonth(), currentDate.getDate()), [currentDate]);
  const minDate = useMemo(() => new Date(1900, 0, 1), []);
  const initialViewDate = selectedDate ?? maxDate;
  const minYear = minDate.getFullYear();
  const maxYear = maxDate.getFullYear();
  const [viewYear, setViewYear] = useState(initialViewDate.getFullYear());
  const [viewMonth, setViewMonth] = useState(initialViewDate.getMonth());
  const [viewMode, setViewMode] = useState<"days" | "years">("days");
  const activeYearRef = useRef<HTMLButtonElement | null>(null);
  const calendarDays = useMemo(
    () => buildCalendarDays(viewYear, viewMonth),
    [viewMonth, viewYear],
  );
  const years = useMemo(
    () => Array.from({ length: maxYear - minYear + 1 }, (_, index) => maxYear - index),
    [maxYear, minYear],
  );
  const weekdayLabels = useMemo(() => buildWeekdayLabels(locale), [locale]);
  const selectedLongLabel = selectedDate
    ? new Intl.DateTimeFormat(locale, { day: "numeric", month: "long", weekday: "long", year: "numeric" }).format(selectedDate)
    : label;
  const viewTitle = new Intl.DateTimeFormat(locale, { month: "long", year: "numeric" }).format(new Date(viewYear, viewMonth, 1));
  useEffect(() => {
    if (!selectedDate) return;
    setViewYear(selectedDate.getFullYear());
    setViewMonth(selectedDate.getMonth());
  }, [selectedDate?.getTime()]);

  useEffect(() => {
    if (viewMode !== "years") return;
    const frame = window.requestAnimationFrame(() => {
      activeYearRef.current?.scrollIntoView({ block: "center" });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [viewMode, viewYear]);

  function moveMonth(offset: number) {
    const next = new Date(viewYear, viewMonth + offset, 1);
    const clamped = clampDate(next, minDate, maxDate);
    setViewYear(clamped.getFullYear());
    setViewMonth(clamped.getMonth());
  }

  function chooseYear(year: number) {
    setViewYear(year);
    setViewMonth(clampMonthForYear(year, viewMonth, minDate, maxDate));
    setViewMode("days");
  }

  function chooseDate(nextDate: Date) {
    if (isDateDisabled(nextDate, minDate, maxDate)) return;
    onChange(toIsoDate(nextDate));
    onClose();
  }

  return (
    <div className="ui-modal ui-calendar-modal">
      <ChoiceModalHeader className={uiClassNames.dateModalHeader} closeLabel={closeLabel} icon={Calendar} iconTone={resolvedIconTone} kicker={label} onClose={onClose} title={label} titleId={titleId} />
      <div
        aria-label={label}
        className={uiClassNames.datePopover}
      >
        <div className={uiClassNames.dateSummary} data-ui-surface="gray">
          <span className={classNames(uiClassNames.dateSummaryIcon, `is-${resolvedIconTone}`)}>
            <Calendar size={18} />
          </span>
          <span>
            <small>{selectedLongLabel}</small>
          </span>
        </div>

        <div className={classNames(uiClassNames.dateToolbar, viewMode === "years" && "is-years")}>
          {viewMode === "days" ? (
            <button aria-label={t("ui.calendar.previousMonth")} className={uiClassNames.dateNav} onClick={() => moveMonth(-1)} type="button">
              <ChevronLeft size={14} />
            </button>
          ) : (
            <span aria-hidden="true" className={uiClassNames.dateNav} />
          )}
          <button
            aria-expanded={viewMode === "years"}
            aria-label={viewMode === "years" ? t("ui.calendar.closeYears") : t("ui.calendar.openYears")}
            className={uiClassNames.dateTitleButton}
            onClick={() => setViewMode((current) => current === "days" ? "years" : "days")}
            type="button"
          >
            {viewTitle}
          </button>
          {viewMode === "days" ? (
            <button aria-label={t("ui.calendar.nextMonth")} className={uiClassNames.dateNav} onClick={() => moveMonth(1)} type="button">
              <ChevronRight size={14} />
            </button>
          ) : (
            <span aria-hidden="true" className={uiClassNames.dateNav} />
          )}
        </div>

        <div className={uiClassNames.dateCalendarSurface}>
          {viewMode === "days" ? (
            <div
              className={uiClassNames.dateView}
              key="days"
            >
              <div className={uiClassNames.dateWeekdays} aria-hidden="true">
                {weekdayLabels.map((day) => (
                  <span key={day}>{day}</span>
                ))}
              </div>

              <div className={uiClassNames.dateDayGrid}>
                {calendarDays.map((day) => {
                  const disabled = isDateDisabled(day.date, minDate, maxDate);
                  const selected = selectedDate ? isSameDate(day.date, selectedDate) : false;
                  return (
                    <button
                      aria-pressed={selected}
                      className={classNames(
                        !day.inMonth && "outside",
                        selected && "selected",
                      )}
                      disabled={disabled}
                      key={toIsoDate(day.date)}
                      onClick={() => chooseDate(day.date)}
                      type="button"
                    >
                      {day.date.getDate()}
                    </button>
                  );
                })}
              </div>
            </div>
          ) : (
            <div
              aria-label={t("ui.calendar.yearsLabel")}
              className={uiClassNames.dateYears}
              key="years"
              role="grid"
            >
              {years.map((year) => {
                const selected = selectedDate?.getFullYear() === year;
                const current = year === viewYear;
                return (
                  <button
                    aria-current={current ? "date" : undefined}
                    aria-label={t("ui.calendar.chooseYear", { year })}
                    aria-pressed={selected}
                    className={classNames(uiClassNames.dateYearButton, selected && "selected", current && "current")}
                    key={year}
                    onClick={() => chooseYear(year)}
                    ref={current ? activeYearRef : undefined}
                    role="gridcell"
                    type="button"
                  >
                    {year}
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function clampDate(date: Date, minDate: Date, maxDate: Date) {
  if (date < minDate) return minDate;
  if (date > maxDate) return maxDate;
  return date;
}

function isDateDisabled(date: Date, minDate: Date, maxDate: Date) {
  return date < minDate || date > maxDate;
}

function clampMonthForYear(year: number, month: number, minDate: Date, maxDate: Date) {
  if (year === minDate.getFullYear()) return Math.max(month, minDate.getMonth());
  if (year === maxDate.getFullYear()) return Math.min(month, maxDate.getMonth());
  return month;
}

function isSameDate(a: Date, b: Date) {
  return a.getFullYear() === b.getFullYear()
    && a.getMonth() === b.getMonth()
    && a.getDate() === b.getDate();
}

function buildWeekdayLabels(locale: string) {
  const start = new Date(2024, 0, 1);
  return Array.from({ length: 7 }, (_, index) => (
    new Intl.DateTimeFormat(locale, { weekday: "short" }).format(new Date(2024, 0, start.getDate() + index))
  ));
}

function buildCalendarDays(year: number, month: number) {
  const first = new Date(year, month, 1);
  const startOffset = (first.getDay() + 6) % 7;
  const start = new Date(year, month, 1 - startOffset);
  return Array.from({ length: 42 }, (_, index) => {
    const date = new Date(start.getFullYear(), start.getMonth(), start.getDate() + index);
    return {
      date,
      inMonth: date.getMonth() === month,
    };
  });
}
