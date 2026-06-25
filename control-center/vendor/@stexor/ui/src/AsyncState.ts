export type UiAsyncStatus =
  | "cancelled"
  | "error"
  | "idle"
  | "loading"
  | "optimistic"
  | "progress"
  | "stale"
  | "success";

export type UiAsyncSnapshot<TData = unknown, TError = Error> = {
  data?: TData;
  error?: TError;
  optimistic: boolean;
  progress: number | null;
  requestId: number;
  stale: boolean;
  status: UiAsyncStatus;
};

type UiAsyncTask<TData> = (signal: AbortSignal, requestId: number) => Promise<TData>;
type UiAsyncListener<TData, TError> = (snapshot: UiAsyncSnapshot<TData, TError>) => void;

export class UiAsyncMachine<TData = unknown, TError = Error> {
  #activeController: AbortController | null = null;
  #listeners = new Set<UiAsyncListener<TData, TError>>();
  #snapshot: UiAsyncSnapshot<TData, TError> = {
    optimistic: false,
    progress: null,
    requestId: 0,
    stale: false,
    status: "idle",
  };

  getSnapshot() {
    return this.#snapshot;
  }

  subscribe(listener: UiAsyncListener<TData, TError>) {
    this.#listeners.add(listener);
    listener(this.#snapshot);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  cancel() {
    const controller = this.#activeController;
    if (!controller) return;
    controller.abort();
    this.#activeController = null;
    this.#commit({
      optimistic: false,
      progress: null,
      requestId: this.#snapshot.requestId,
      stale: false,
      status: "cancelled",
    });
  }

  markStale() {
    this.#commit({ ...this.#snapshot, stale: true, status: "stale" });
  }

  run(task: UiAsyncTask<TData>, options: { optimisticData?: TData; progress?: number } = {}) {
    this.#activeController?.abort();
    const controller = new AbortController();
    const requestId = this.#snapshot.requestId + 1;
    this.#activeController = controller;
    this.#commit({
      data: options.optimisticData,
      optimistic: options.optimisticData !== undefined,
      progress: options.progress ?? null,
      requestId,
      stale: false,
      status: options.optimisticData === undefined ? "loading" : "optimistic",
    });

    return task(controller.signal, requestId).then(
      (data) => {
        if (!this.#isCurrent(requestId, controller)) return this.#snapshot;
        this.#activeController = null;
        this.#commit({
          data,
          optimistic: false,
          progress: 100,
          requestId,
          stale: false,
          status: "success",
        });
        return this.#snapshot;
      },
      (error: TError) => {
        if (!this.#isCurrent(requestId, controller)) return this.#snapshot;
        this.#activeController = null;
        if (controller.signal.aborted) {
          this.#commit({
            optimistic: false,
            progress: null,
            requestId,
            stale: false,
            status: "cancelled",
          });
          return this.#snapshot;
        }
        this.#commit({
          error,
          optimistic: false,
          progress: null,
          requestId,
          stale: false,
          status: "error",
        });
        return this.#snapshot;
      },
    );
  }

  setProgress(progress: number) {
    if (!this.#activeController) return;
    this.#commit({
      ...this.#snapshot,
      progress: Math.max(0, Math.min(100, progress)),
      status: "progress",
    });
  }

  #commit(snapshot: UiAsyncSnapshot<TData, TError>) {
    this.#snapshot = snapshot;
    for (const listener of this.#listeners) listener(snapshot);
  }

  #isCurrent(requestId: number, controller: AbortController) {
    return this.#snapshot.requestId === requestId && this.#activeController === controller;
  }
}

export function createUiAsyncMachine<TData = unknown, TError = Error>() {
  return new UiAsyncMachine<TData, TError>();
}
