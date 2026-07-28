#!/usr/bin/env python3
"""Open and hold the platform activation mutex without a path-following race."""

from __future__ import annotations

import errno
import fcntl
import os
import stat
import sys


def fail(message: str) -> "NoReturn":
    print(message, file=sys.stderr)
    raise SystemExit(1)


def exact_state_directory(value: str) -> tuple[str, os.stat_result]:
    directory = os.path.abspath(value)
    try:
        details = os.lstat(directory)
    except OSError as error:
        fail(f"Activation state directory is unavailable: {error.strerror}.")
    if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
        fail("Activation state directory must be a real directory.")
    if os.path.realpath(directory) != directory:
        fail("Activation state directory must be canonical.")
    if hasattr(os, "getuid") and details.st_uid != os.getuid():
        fail("Activation state directory must be owned by the deployment identity.")
    if stat.S_IMODE(details.st_mode) != 0o700:
        fail("Activation state directory must use mode 0700.")
    return directory, details


def validate_lock(
    directory: str,
    descriptor: int,
    expected_device: int | None = None,
    expected_inode: int | None = None,
) -> os.stat_result:
    target = os.path.join(directory, "activation.lock")
    try:
        descriptor_details = os.fstat(descriptor)
        path_details = os.lstat(target)
    except OSError as error:
        fail(f"Activation mutex identity is unavailable: {error.strerror}.")
    if (
        not stat.S_ISREG(descriptor_details.st_mode)
        or not stat.S_ISREG(path_details.st_mode)
        or stat.S_ISLNK(path_details.st_mode)
        or descriptor_details.st_nlink != 1
        or path_details.st_nlink != 1
        or descriptor_details.st_dev != path_details.st_dev
        or descriptor_details.st_ino != path_details.st_ino
        or stat.S_IMODE(descriptor_details.st_mode) != 0o600
        or stat.S_IMODE(path_details.st_mode) != 0o600
        or (hasattr(os, "getuid") and descriptor_details.st_uid != os.getuid())
        or (hasattr(os, "getuid") and path_details.st_uid != os.getuid())
    ):
        fail(
            "Activation mutex must be the stable, single deployment-owned "
            "mode-0600 regular file opened by descriptor."
        )
    if expected_device is not None and descriptor_details.st_dev != expected_device:
        fail("Activation mutex device changed after acquisition.")
    if expected_inode is not None and descriptor_details.st_ino != expected_inode:
        fail("Activation mutex inode changed after acquisition.")
    return descriptor_details


def acquire(directory: str, script: str, arguments: list[str]) -> None:
    directory, _ = exact_state_directory(directory)
    target = os.path.join(directory, "activation.lock")
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags | os.O_CREAT | os.O_EXCL, 0o600)
        os.fsync(descriptor)
        directory_descriptor = os.open(
            directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        if error.errno != errno.EEXIST:
            fail(f"Activation mutex could not be created safely: {error.strerror}.")
        try:
            descriptor = os.open(target, flags)
        except OSError as open_error:
            fail(f"Activation mutex could not be opened safely: {open_error.strerror}.")
    details = validate_lock(directory, descriptor)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fail("Another platform activation transaction holds the global mutex.")
    os.set_inheritable(descriptor, True)
    environment = os.environ.copy()
    environment["PLATFORM_ACTIVATION_LOCK_FD"] = str(descriptor)
    environment["PLATFORM_ACTIVATION_LOCK_DEVICE"] = str(details.st_dev)
    environment["PLATFORM_ACTIVATION_LOCK_INODE"] = str(details.st_ino)
    os.execve(os.path.realpath(script), [script, *arguments], environment)


def verify(directory: str, descriptor_text: str, device_text: str, inode_text: str) -> None:
    directory, _ = exact_state_directory(directory)
    try:
        descriptor = int(descriptor_text, 10)
        expected_device = int(device_text, 10)
        expected_inode = int(inode_text, 10)
    except ValueError:
        fail("Activation mutex descriptor identity is invalid.")
    validate_lock(directory, descriptor, expected_device, expected_inode)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fail("Activation mutex descriptor does not own the global lock.")


def main() -> None:
    if len(sys.argv) >= 4 and sys.argv[1] == "acquire":
        acquire(sys.argv[2], sys.argv[3], sys.argv[4:])
    elif len(sys.argv) == 6 and sys.argv[1] == "verify":
        verify(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        fail(
            "Usage: platform-activation-lock.py acquire STATE_DIR SCRIPT [ARG...] "
            "| verify STATE_DIR FD DEVICE INODE"
        )


if __name__ == "__main__":
    main()
