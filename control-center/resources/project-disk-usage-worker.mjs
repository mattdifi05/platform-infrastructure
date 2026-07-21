import { parentPort, workerData } from "node:worker_threads";
import { scanProjectTree } from "./project-disk-usage.mjs";

try {
  const value = await scanProjectTree(workerData?.root, workerData?.options);
  parentPort.postMessage({ ok: true, value });
} catch (error) {
  parentPort.postMessage({
    ok: false,
    code: String(error?.code || "PROJECT_DISK_WORKER"),
    message: String(error?.message || "Project disk scan failed safely."),
  });
}
