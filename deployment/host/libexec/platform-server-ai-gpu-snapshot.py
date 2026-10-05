#!/usr/bin/env python3
"""Write a small, non-secret NVIDIA GPU snapshot for Server AI status."""

import csv
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time
from datetime import datetime, timezone

NVIDIA_SMI = "/usr/local/bin/nvidia-smi"
NVIDIA_ARGS = (
    NVIDIA_SMI,
    "--query-gpu=name,driver_version,memory.total,memory.used,memory.free,utilization.gpu,temperature.gpu",
    "--format=csv,noheader,nounits",
)
OUTPUT_PATH = Path("/run/platform-server-ai/gpu.json")
TIMEOUT_SECONDS = 3
MAX_OUTPUT_BYTES = 8 * 1024


def observed_at():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def unavailable_snapshot(timestamp=None):
    return {"available": False, "stale": False, "observedAt": timestamp or observed_at(), "error": "GPU metrics unavailable."}


def read_nvidia_smi():
    """Run only the fixed nvidia-smi query and consume no more than 8 KiB."""
    try:
        process = subprocess.Popen(
            NVIDIA_ARGS,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except OSError:
        raise RuntimeError("nvidia-smi unavailable")
    assert process.stdout is not None
    deadline = time.monotonic() + TIMEOUT_SECONDS
    chunks = []
    size = 0
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("nvidia-smi timeout")
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            if not ready:
                raise TimeoutError("nvidia-smi timeout")
            remaining_bytes = MAX_OUTPUT_BYTES - size
            if remaining_bytes == 0:
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
                break
            chunk = os.read(process.stdout.fileno(), min(4096, remaining_bytes))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_OUTPUT_BYTES:
                raise RuntimeError("nvidia-smi output limit")
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if process.returncode != 0:
            raise RuntimeError("nvidia-smi failed")
        return b"".join(chunks)
    except Exception:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise


def parse_snapshot(raw, timestamp=None):
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError("invalid gpu output")
    rows = [row for row in csv.reader(raw.decode("utf-8", "strict").splitlines()) if any(cell.strip() for cell in row)]
    if len(rows) != 1 or len(rows[0]) != 7:
        raise ValueError("invalid gpu row")
    name, driver, total, used, free, utilization, temperature = (cell.strip() for cell in rows[0])
    if not name or len(name) > 160 or not driver or len(driver) > 64:
        raise ValueError("invalid gpu identity")
    values = [int(value) for value in (total, used, free, utilization, temperature)]
    total_mib, used_mib, free_mib, utilization_percent, temperature_c = values
    if total_mib < 1 or used_mib < 0 or free_mib < 0 or used_mib + free_mib > total_mib + 1:
        raise ValueError("invalid gpu memory")
    if not 0 <= utilization_percent <= 100 or not 0 <= temperature_c <= 150:
        raise ValueError("invalid gpu counters")
    return {
        "available": True,
        "stale": False,
        "name": name,
        "driverVersion": driver,
        "memoryTotalMiB": total_mib,
        "memoryUsedMiB": used_mib,
        "memoryFreeMiB": free_mib,
        "utilizationPercent": utilization_percent,
        "temperatureC": temperature_c,
        "observedAt": timestamp or observed_at(),
    }


def collect_snapshot(command=read_nvidia_smi, timestamp=None):
    try:
        return parse_snapshot(command(), timestamp)
    except Exception:
        return unavailable_snapshot(timestamp)


def write_snapshot(snapshot, output_path=OUTPUT_PATH):
    path = Path(output_path)
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    payload = json.dumps(snapshot, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".gpu-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main():
    write_snapshot(collect_snapshot())


if __name__ == "__main__":
    main()
