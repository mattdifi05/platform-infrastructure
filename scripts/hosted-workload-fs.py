#!/usr/bin/env python3
"""Descriptor-relative filesystem operations for hosted workload snapshots."""

import argparse
import hashlib
import json
import os
import secrets
import stat
import sys


DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
FILE_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def fail(message):
    raise RuntimeError(message)


def identity_from_stat(value):
    return {
        "device": str(value.st_dev),
        "inode": str(value.st_ino),
        "uid": str(value.st_uid),
        "mode": stat.S_IMODE(value.st_mode),
    }


def expected_identity(raw):
    value = json.loads(raw)
    if value is None:
        return None
    return {
        "device": str(value["device"]),
        "inode": str(value["inode"]),
        "uid": str(value["uid"]),
        "mode": int(value["mode"]),
    }


def assert_identity(descriptor, expected, label, directory=True):
    value = os.fstat(descriptor)
    if directory and not stat.S_ISDIR(value.st_mode):
        fail(f"{label} is not a directory")
    if not directory and not stat.S_ISREG(value.st_mode):
        fail(f"{label} is not a regular file")
    actual = identity_from_stat(value)
    if expected is not None and actual != expected:
        fail(f"{label} identity changed")
    return actual


def safe_name(value, label):
    if not value or value in (".", "..") or "/" in value or "\0" in value:
        fail(f"invalid {label}")
    return value


def open_directory(path_or_name, expected, label, dir_fd=None):
    descriptor = os.open(path_or_name, DIRECTORY_FLAGS, dir_fd=dir_fd)
    try:
        assert_identity(descriptor, expected, label)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def open_chain(args, include_staging=True):
    parent = open_directory(args.parent, expected_identity(args.expected_parent), "snapshot parent")
    try:
        root = open_directory(safe_name(args.root_name, "root name"), expected_identity(args.expected_root), "snapshot root", parent)
    except Exception:
        os.close(parent)
        raise
    staging = None
    try:
        if include_staging:
            staging = open_directory(
                safe_name(args.staging_name, "staging name"),
                expected_identity(args.expected_staging),
                "snapshot staging directory",
                root,
            )
        return parent, root, staging
    except Exception:
        os.close(root)
        os.close(parent)
        raise


def create(args):
    parent_expected = expected_identity(args.expected_parent)
    root_expected = expected_identity(args.expected_root)
    parent = open_directory(args.parent, parent_expected, "snapshot parent")
    root = None
    staging = None
    try:
        root_name = safe_name(args.root_name, "root name")
        try:
            root = open_directory(root_name, root_expected, "snapshot root", parent)
        except FileNotFoundError:
            if root_expected is not None:
                fail("snapshot root disappeared before descriptor-relative creation")
            os.mkdir(root_name, 0o700, dir_fd=parent)
            os.fsync(parent)
            root = open_directory(root_name, None, "snapshot root", parent)
        root_identity = assert_identity(root, None, "snapshot root")
        if root_identity["uid"] != str(os.getuid()) or root_identity["mode"] != 0o700:
            fail("snapshot root must be deployment-owned with mode 0700")
        for _ in range(128):
            staging_name = f".staging-{secrets.token_hex(16)}"
            try:
                os.mkdir(staging_name, 0o700, dir_fd=root)
                break
            except FileExistsError:
                continue
        else:
            fail("could not allocate a unique staging directory")
        staging = open_directory(staging_name, None, "snapshot staging directory", root)
        staging_identity = assert_identity(staging, None, "snapshot staging directory")
        os.fsync(root)
        return {
            "parentIdentity": assert_identity(parent, parent_expected, "snapshot parent"),
            "rootIdentity": assert_identity(root, root_identity, "snapshot root"),
            "stagingIdentity": staging_identity,
            "stagingName": staging_name,
        }
    finally:
        if staging is not None:
            os.close(staging)
        if root is not None:
            os.close(root)
        os.close(parent)


def write_file(args):
    parent, root, staging = open_chain(args)
    descriptor = None
    try:
        name = safe_name(args.file_name, "snapshot file name")
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | FILE_NOFOLLOW, 0o400, dir_fd=staging)
        while True:
            chunk = sys.stdin.buffer.read(1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        result = assert_identity(descriptor, None, "snapshot file", directory=False)
        if result["uid"] != str(os.getuid()) or result["mode"] != 0o400:
            fail("snapshot file must be deployment-owned with mode 0400")
        os.fsync(staging)
        return {"fileIdentity": result}
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(staging)
        os.close(root)
        os.close(parent)


def read_digest(descriptor):
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


def verify_generation(directory, expected_files):
    names = sorted(os.listdir(directory))
    expected_names = sorted(item["name"] for item in expected_files)
    if names != expected_names:
        fail("existing content-addressed snapshot has unexpected files")
    identities = {}
    for item in expected_files:
        name = safe_name(item["name"], "snapshot file name")
        descriptor = os.open(name, os.O_RDONLY | FILE_NOFOLLOW, dir_fd=directory)
        try:
            identity = assert_identity(descriptor, None, f"snapshot file {name}", directory=False)
            if identity["uid"] != str(os.getuid()) or identity["mode"] != 0o400:
                fail(f"snapshot file {name} owner or mode is invalid")
            if read_digest(descriptor) != item["sha256"]:
                fail(f"snapshot file {name} digest is invalid")
            identities[name] = identity
        finally:
            os.close(descriptor)
    return identities


def remove_staging(root, staging, staging_name):
    for name in os.listdir(staging):
        safe_name(name, "staging entry")
        os.unlink(name, dir_fd=staging)
    os.fsync(staging)
    os.rmdir(staging_name, dir_fd=root)


def finalize(args):
    expected_files = json.load(sys.stdin)
    if not isinstance(expected_files, list):
        fail("expected snapshot records must be an array")
    parent, root, staging = open_chain(args)
    final_descriptor = None
    try:
        final_name = safe_name(args.final_name, "final generation name")
        try:
            final_descriptor = open_directory(final_name, None, "content-addressed snapshot", root)
            existing_identity = assert_identity(final_descriptor, None, "content-addressed snapshot")
            if existing_identity["uid"] != str(os.getuid()) or existing_identity["mode"] != 0o500:
                fail("existing snapshot generation must be deployment-owned with mode 0500")
            identities = verify_generation(final_descriptor, expected_files)
            remove_staging(root, staging, args.staging_name)
            os.close(staging)
            staging = None
        except FileNotFoundError:
            os.rename(args.staging_name, final_name, src_dir_fd=root, dst_dir_fd=root)
            os.close(staging)
            staging = None
            final_descriptor = open_directory(
                final_name,
                expected_identity(args.expected_staging),
                "content-addressed snapshot",
                root,
            )
            identities = verify_generation(final_descriptor, expected_files)
        os.fchmod(final_descriptor, 0o500)
        os.fsync(final_descriptor)
        os.fsync(root)
        generation_identity = assert_identity(final_descriptor, None, "content-addressed snapshot")
        if generation_identity["uid"] != str(os.getuid()) or generation_identity["mode"] != 0o500:
            fail("snapshot generation must be deployment-owned with mode 0500")
        return {
            "parentIdentity": assert_identity(parent, expected_identity(args.expected_parent), "snapshot parent"),
            "rootIdentity": assert_identity(root, expected_identity(args.expected_root), "snapshot root"),
            "generationIdentity": generation_identity,
            "fileIdentities": identities,
            "finalName": final_name,
        }
    finally:
        if final_descriptor is not None:
            os.close(final_descriptor)
        if staging is not None:
            os.close(staging)
        os.close(root)
        os.close(parent)


def parser():
    result = argparse.ArgumentParser()
    subcommands = result.add_subparsers(dest="command", required=True)
    create_parser = subcommands.add_parser("create")
    create_parser.add_argument("--parent", required=True)
    create_parser.add_argument("--root-name", required=True)
    create_parser.add_argument("--expected-parent", required=True)
    create_parser.add_argument("--expected-root", required=True)

    for command in ("write", "finalize"):
        item = subcommands.add_parser(command)
        item.add_argument("--parent", required=True)
        item.add_argument("--root-name", required=True)
        item.add_argument("--staging-name", required=True)
        item.add_argument("--expected-parent", required=True)
        item.add_argument("--expected-root", required=True)
        item.add_argument("--expected-staging", required=True)
        if command == "write":
            item.add_argument("--file-name", required=True)
        else:
            item.add_argument("--final-name", required=True)
    return result


def main():
    args = parser().parse_args()
    if args.command == "create":
        output = create(args)
    elif args.command == "write":
        output = write_file(args)
    else:
        output = finalize(args)
    sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":")))
    sys.stdout.write("\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        sys.stderr.write(f"{error}\n")
        sys.exit(1)
