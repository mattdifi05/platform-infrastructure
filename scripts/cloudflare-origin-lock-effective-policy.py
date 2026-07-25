#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import socket
import tempfile

KIND = "platform-cloudflare-origin-lock-effective-verification/v1"
VERIFIER_VERSION = "cloudflare-origin-lock-ufw/v2"


def fail(message):
    raise SystemExit(message)


def sha256_file(pathname):
    path = pathlib.Path(pathname)
    if not path.is_file() or path.is_symlink():
        fail(f"effective verification input must be a regular non-symlink file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(pathname, label):
    path = pathlib.Path(pathname)
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be a regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{label} is invalid JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def parse_timestamp(value, label):
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        fail(f"{label} is not an ISO-8601 timestamp")
    if parsed.tzinfo is None:
        fail(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def parse_ports(value):
    try:
        ports = sorted({int(part) for part in value.split()})
    except ValueError:
        fail("effective verification ports must be integers")
    if not ports or any(port < 1 or port > 65535 for port in ports):
        fail("effective verification ports are invalid")
    return ports


def expected_receipt(args, verified_at):
    cidr = read_json(args.cidr_receipt, "CIDR receipt")
    if cidr.get("kind") != "platform-cloudflare-origin-cidr-receipt/v1":
        fail("CIDR receipt kind is invalid")
    ruleset_digest = cidr.get("rulesetDigest")
    if not isinstance(ruleset_digest, str) or len(ruleset_digest) != 64:
        fail("CIDR receipt ruleset digest is invalid")
    fetched_at = cidr.get("fetchedAt")
    parse_timestamp(fetched_at, "CIDR receipt fetchedAt")
    machine_id_digest = sha256_file(args.machine_id)
    hostname = args.hostname or socket.gethostname()
    if not hostname or hostname.strip() != hostname or any(char in hostname for char in "\x00\r\n"):
        fail("host identity is invalid")
    ports = parse_ports(args.ports)
    if args.ssh_port < 1 or args.ssh_port > 65535 or args.ssh_port in ports:
        fail("effective verification SSH port is invalid")
    effective_lines = pathlib.Path(args.effective_rules).read_text(encoding="utf-8").splitlines()
    if not effective_lines or effective_lines[0] != "status=active" or "defaultIncoming=deny" not in effective_lines:
        fail("effective rules snapshot lacks active/default-deny identity")
    managed_count = sum(1 for line in effective_lines if "|cloudflare-origin-" in line)
    if managed_count < 2:
        fail("effective rules snapshot lacks complete managed rule coverage")
    return {
        "version": 1,
        "kind": KIND,
        "status": "passed",
        "result": "passed",
        "verifiedAt": verified_at,
        "verifierVersion": VERIFIER_VERSION,
        "host": {
            "hostname": hostname,
            "machineIdSha256": machine_id_digest,
        },
        "addressFamilies": ["ipv4", "ipv6"],
        "publicTcpPorts": ports,
        "sshPort": args.ssh_port,
        "defaultIncoming": "deny",
        "managedRuleCount": managed_count,
        "effectiveRulesetSha256": sha256_file(args.effective_rules),
        "cidrReceiptSha256": sha256_file(args.cidr_receipt),
        "cidrRulesetDigest": ruleset_digest,
        "cidrFetchedAt": fetched_at,
    }


def atomic_write(pathname, document):
    target = pathlib.Path(pathname)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("create", "validate"))
    parser.add_argument("--effective-rules", required=True)
    parser.add_argument("--cidr-receipt", required=True)
    parser.add_argument("--ports", required=True)
    parser.add_argument("--ssh-port", required=True, type=int)
    parser.add_argument("--machine-id", required=True)
    parser.add_argument("--hostname")
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--verified-at", default=dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"))
    parser.add_argument("--max-age-seconds", type=int, default=604800)
    args = parser.parse_args()
    if args.mode == "create":
        parse_timestamp(args.verified_at, "effective receipt verifiedAt")
        atomic_write(args.receipt, expected_receipt(args, args.verified_at))
        return
    receipt = read_json(args.receipt, "effective verification receipt")
    if set(receipt) != set(expected_receipt(args, args.verified_at)):
        fail("effective verification receipt fields differ from the exact schema")
    verified_at = receipt.get("verifiedAt")
    parsed = parse_timestamp(verified_at, "effective receipt verifiedAt")
    age = (dt.datetime.now(dt.timezone.utc) - parsed).total_seconds()
    if args.max_age_seconds < 1 or age < -300 or age > args.max_age_seconds:
        fail("effective verification receipt is stale or future-dated")
    expected = expected_receipt(args, verified_at)
    if receipt != expected:
        fail("effective verification receipt host, families, verifier, CIDR or ruleset binding is mismatched")


if __name__ == "__main__":
    main()
