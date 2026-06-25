"use client";

import { useMemo, useState, type KeyboardEvent, type ReactNode } from "react";
import { Button } from "./Button";
import { classNames } from "./classNames";
import { groupCommandPaletteCommands as groupCommands, type CommandPaletteCommand } from "./CommandPaletteModel";
import { SearchInput } from "./Form";
import { Search } from "./icons";
import { UiOverlayFrame, type UiOverlayMotion, type UiOverlayRenderProps } from "./OverlayPatterns";

export type { CommandPaletteCommand } from "./CommandPaletteModel";

export type CommandPaletteProps = {
  closeOnSelect?: boolean;
  commands: CommandPaletteCommand[];
  emptyState?: ReactNode;
  error?: ReactNode;
  label?: string;
  loading?: boolean;
  motion?: UiOverlayMotion;
  onCommandSelect?: (command: CommandPaletteCommand) => void;
  onOpenChange: (open: boolean) => void;
  open: boolean;
  placeholder?: string;
  recentCommandIds?: string[];
  title?: ReactNode;
  trigger: (props: UiOverlayRenderProps) => ReactNode;
};

export function CommandPalette({
  closeOnSelect = true,
  commands,
  emptyState = "No commands",
  error,
  label = "Command palette",
  loading = false,
  motion = "default",
  onCommandSelect,
  onOpenChange,
  open,
  placeholder = "Search commands",
  recentCommandIds = [],
  title = "Command palette",
  trigger,
}: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const [runningCommandId, setRunningCommandId] = useState<string | null>(null);
  const [commandError, setCommandError] = useState<ReactNode>(null);
  const groups = useMemo(() => groupCommands(commands, query, recentCommandIds), [commands, query, recentCommandIds]);
  const visibleCommands = useMemo(() => groups.flatMap((group) => group.commands), [groups]);
  const boundedActiveIndex = Math.min(activeIndex, Math.max(0, visibleCommands.length - 1));

  async function runCommand(command: CommandPaletteCommand, closeOverlay: () => void) {
    if (command.disabled || runningCommandId) return;
    setCommandError(null);
    setRunningCommandId(command.id);
    try {
      await command.onSelect?.();
      onCommandSelect?.(command);
      if (closeOnSelect) closeOverlay();
    } catch (nextError) {
      setCommandError(nextError instanceof Error ? nextError.message : String(nextError));
    } finally {
      setRunningCommandId(null);
    }
  }

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>, closeOverlay: () => void) {
    if (!visibleCommands.length) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveIndex((current) => (current + 1) % visibleCommands.length);
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((current) => (current - 1 + visibleCommands.length) % visibleCommands.length);
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      const command = visibleCommands[boundedActiveIndex];
      if (command) void runCommand(command, closeOverlay);
    }
  }

  return (
    <UiOverlayFrame
      autoFocusPanel={false}
      className="ui-command-layer"
      label={label}
      motion={motion}
      onOpenChange={(nextOpen) => {
        if (nextOpen) {
          setQuery("");
          setActiveIndex(0);
          setCommandError(null);
        }
        onOpenChange(nextOpen);
      }}
      open={open}
      panelClassName="ui-command-panel"
      placement="center"
      title={title}
      trigger={trigger}
      type="command-palette"
    >
      {({ closeOverlay }) => (
        <div className="ui-command-palette" onKeyDown={(event) => handleKeyDown(event, closeOverlay)}>
          <SearchInput
            icon={Search}
            iconTone="brand"
            inputProps={{
              "aria-activedescendant": visibleCommands[boundedActiveIndex] ? `ui-command-${visibleCommands[boundedActiveIndex]!.id}` : undefined,
              "aria-label": placeholder,
              autoFocus: true,
              role: "combobox",
            }}
            label={placeholder}
            onChange={(nextQuery) => {
              setQuery(nextQuery);
              setActiveIndex(0);
            }}
            placeholder={placeholder}
            value={query}
          />
          {loading ? <div className="ui-command-state" role="status">Loading</div> : error || commandError ? (
            <div className="ui-command-state is-error" role="alert">{error ?? commandError}</div>
          ) : visibleCommands.length ? (
            <div className="ui-command-list" role="listbox">
              {groups.map((group) => (
                <section className="ui-command-group" key={group.id}>
                  <span>{group.label}</span>
                  {group.commands.map((command, index) => {
                    const commandIndex = group.startIndex + index;
                    const Icon = command.icon;
                    const active = commandIndex === boundedActiveIndex;
                    return (
                      <button
                        aria-disabled={command.disabled || undefined}
                        aria-selected={active}
                        className={classNames("ui-command-item", active && "is-active")}
                        disabled={command.disabled}
                        id={`ui-command-${command.id}`}
                        key={command.id}
                        onClick={() => void runCommand(command, closeOverlay)}
                        role="option"
                        type="button"
                      >
                        {Icon ? <Icon aria-hidden="true" size={15} /> : null}
                        <strong>{command.label}</strong>
                        {runningCommandId === command.id ? <span>...</span> : command.shortcut ? <kbd>{command.shortcut}</kbd> : null}
                      </button>
                    );
                  })}
                </section>
              ))}
            </div>
          ) : (
            <div className="ui-command-state">{emptyState}</div>
          )}
          <div className="ui-command-footer">
            <Button compact onClick={closeOverlay} variant="muted">Esc</Button>
          </div>
        </div>
      )}
    </UiOverlayFrame>
  );
}
