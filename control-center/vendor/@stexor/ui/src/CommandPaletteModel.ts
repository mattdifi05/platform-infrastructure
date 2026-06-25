import type { IconType } from "./icons";

export type CommandPaletteCommand = {
  disabled?: boolean;
  group?: string;
  icon?: IconType;
  id: string;
  keywords?: string[];
  label: string;
  onSelect?: () => Promise<void> | void;
  shortcut?: string;
};

type CommandPaletteGroup = {
  commands: CommandPaletteCommand[];
  id: string;
  label: string;
  startIndex: number;
};

export function groupCommandPaletteCommands(commands: CommandPaletteCommand[], query: string, recentCommandIds: string[]): CommandPaletteGroup[] {
  const normalizedQuery = query.trim().toLowerCase();
  const filteredCommands = normalizedQuery ? commands.filter((command) => commandMatchesQuery(command, normalizedQuery)) : commands;
  const filteredCommandsById = recentCommandIds.length ? new Map(filteredCommands.map((command) => [command.id, command])) : null;
  const recentIdSet = new Set(recentCommandIds);
  const recent = recentCommandIds.flatMap((id) => {
    const command = filteredCommandsById?.get(id);
    return command ? [command] : [];
  });
  const remaining = filteredCommands.filter((command) => !recentIdSet.has(command.id));
  const grouped = new Map<string, CommandPaletteCommand[]>();
  for (const command of remaining) {
    const group = command.group ?? "Commands";
    const groupCommands = grouped.get(group);
    if (groupCommands) groupCommands.push(command);
    else grouped.set(group, [command]);
  }
  let startIndex = 0;
  return [
    ...(recent.length ? [{ commands: recent, id: "recent", label: "Recent" }] : []),
    ...Array.from(grouped, ([group, groupCommands]) => ({ commands: groupCommands, id: group, label: group })),
  ].map((group) => {
    const indexedGroup = { ...group, startIndex };
    startIndex += group.commands.length;
    return indexedGroup;
  });
}

function commandMatchesQuery(command: CommandPaletteCommand, query: string) {
  if (command.label.toLowerCase().includes(query)) return true;
  for (const keyword of command.keywords ?? []) {
    if (keyword.toLowerCase().includes(query)) return true;
  }
  return false;
}
