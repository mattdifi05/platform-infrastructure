export type UiOverlayType =
  | "command-palette"
  | "dropdown"
  | "modal"
  | "popover";

export type UiOverlayLifecycleEvent = {
  activeId: string | null;
  size: number;
  type: "register" | "unregister" | "sync";
};

export type UiOverlayEntry = {
  closeOnEscape: boolean;
  id: string;
  interactionPriority?: number;
  layer: HTMLElement;
  modal?: boolean;
  onAfterOpen?: () => void;
  onBeforeClose?: () => void;
  onEscape: () => void;
  panel: HTMLElement;
  type?: UiOverlayType;
};

type StoredLayerState = {
  ariaHidden: string | null;
  inert: boolean;
};

class UiOverlayStack {
  #activeEntry: UiOverlayEntry | null = null;
  #entries: UiOverlayEntry[] = [];
  #entryOrder = new Map<string, number>();
  #listeners = new Set<(event: UiOverlayLifecycleEvent) => void>();
  #nextOrder = 0;
  #storedLayerState = new WeakMap<HTMLElement, StoredLayerState>();

  register(entry: UiOverlayEntry) {
    this.#entryOrder.set(entry.id, this.#nextOrder);
    this.#nextOrder += 1;
    const existingIndex = this.#entries.findIndex((candidate) => candidate.id === entry.id);
    if (existingIndex >= 0) this.#entries.splice(existingIndex, 1);
    this.#entries.push(entry);
    this.#activeEntry = this.#findActiveEntry();
    this.#syncDocumentState();
    this.#callLifecycle(entry.onAfterOpen);
    this.#emit("register");
    return () => {
      this.#callLifecycle(entry.onBeforeClose);
      const currentIndex = this.#entries.findIndex((candidate) => candidate.id === entry.id);
      if (currentIndex >= 0) this.#entries.splice(currentIndex, 1);
      this.#entryOrder.delete(entry.id);
      this.#activeEntry = this.#findActiveEntry();
      this.#syncDocumentState();
      this.#emit("unregister");
    };
  }

  activeEntry() {
    return this.#activeEntry;
  }

  #findActiveEntry() {
    let active: UiOverlayEntry | null = null;
    let activeRank = -Infinity;
    for (const entry of this.#entries) {
      const rank = this.#rankFor(entry);
      if (rank >= activeRank) {
        active = entry;
        activeRank = rank;
      }
    }
    return active;
  }

  isTop(id: string) {
    return this.activeEntry()?.id === id;
  }

  routeEscape() {
    const entry = this.activeEntry();
    if (!entry?.closeOnEscape) return false;
    this.#callLifecycle(entry.onEscape);
    return true;
  }

  size() {
    return this.#entries.length;
  }

  snapshot() {
    return {
      activeId: this.activeEntry()?.id ?? null,
      entries: this.#entries.map((entry) => ({
        id: entry.id,
        interactionPriority: this.#rankFor(entry),
        type: entry.type ?? "modal",
      })),
      size: this.size(),
    };
  }

  subscribe(listener: (event: UiOverlayLifecycleEvent) => void) {
    this.#listeners.add(listener);
    listener({ activeId: this.activeEntry()?.id ?? null, size: this.size(), type: "sync" });
    return () => {
      this.#listeners.delete(listener);
    };
  }

  #syncDocumentState() {
    if (typeof document === "undefined") return;

    const hasModalEntry = this.#entries.some((entry) => entry.modal);
    document.documentElement.classList.toggle("modal-open", hasModalEntry);
    document.body.classList.toggle("modal-open", hasModalEntry);

    const activeLayer = this.activeEntry()?.layer ?? null;
    const overlayLayers = new Set(this.#entries.map((entry) => entry.layer));

    for (const child of Array.from(document.body.children)) {
      if (!(child instanceof HTMLElement)) continue;
      if (!this.#storedLayerState.has(child)) {
        this.#storedLayerState.set(child, {
          ariaHidden: child.getAttribute("aria-hidden"),
          inert: child.inert,
        });
      }

      if (this.#entries.length === 0) {
        this.#restoreLayer(child);
        continue;
      }

      const isOverlayLayer = overlayLayers.has(child);
      const isActiveOverlay = child === activeLayer;
      const isInactiveOverlay = isOverlayLayer && !isActiveOverlay;
      if (!hasModalEntry && !isOverlayLayer) {
        this.#restoreLayer(child);
        continue;
      }
      if (isActiveOverlay) {
        child.inert = false;
        child.removeAttribute("aria-hidden");
      } else if (isInactiveOverlay || !isOverlayLayer) {
        child.inert = true;
        child.setAttribute("aria-hidden", "true");
      }
    }

    if (this.#entries.length === 0) this.#storedLayerState = new WeakMap();
  }

  #emit(type: UiOverlayLifecycleEvent["type"]) {
    const event = { activeId: this.activeEntry()?.id ?? null, size: this.size(), type };
    for (const listener of this.#listeners) listener(event);
  }

  #rankFor(entry: UiOverlayEntry) {
    if (entry.interactionPriority !== undefined) return entry.interactionPriority;
    return this.#entryOrder.get(entry.id) ?? 0;
  }

  #restoreLayer(layer: HTMLElement) {
    const stored = this.#storedLayerState.get(layer);
    if (!stored) return;
    layer.inert = stored.inert;
    if (stored.ariaHidden === null) layer.removeAttribute("aria-hidden");
    else layer.setAttribute("aria-hidden", stored.ariaHidden);
  }

  #callLifecycle(callback?: () => void) {
    if (!callback) return;
    try {
      callback();
    } catch {
      // Lifecycle hooks are optional extensions; overlay state must remain recoverable.
    }
  }
}

export const uiOverlayStack = new UiOverlayStack();
