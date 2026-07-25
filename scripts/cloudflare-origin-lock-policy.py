#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import pathlib
import tempfile

SOURCE = {
    "ipv4Url": "https://www.cloudflare.com/ips-v4",
    "ipv6Url": "https://www.cloudflare.com/ips-v6",
}


def fail(message):
    raise SystemExit(message)


def read_networks(pathname, version):
    path = pathlib.Path(pathname)
    if not path.is_file() or path.is_symlink():
        fail(f"IPv{version} CIDR input must be a regular non-symlink file")
    networks = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            fail(f"invalid IPv{version} CIDR at line {number}: {error}")
        if network.version != version or value.lower() != str(network).lower():
            fail(f"IPv{version} CIDR at line {number} is wrong-family or non-canonical")
        networks.append(network)
    if not networks:
        fail(f"IPv{version} CIDR input has no networks")
    if len(set(networks)) != len(networks):
        fail(f"IPv{version} CIDR input contains duplicates")
    ordered = sorted(networks, key=lambda network: (int(network.network_address), network.prefixlen))
    for index, left in enumerate(ordered):
        for right in ordered[index + 1 :]:
            if left.overlaps(right):
                fail(f"IPv{version} CIDR input contains overlapping networks: {left} and {right}")
    return [str(network) for network in ordered]


def sha256_file(pathname):
    digest = hashlib.sha256()
    with open(pathname, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_ports(value):
    try:
        ports = sorted({int(part) for part in value.split()})
    except ValueError:
        fail("ports must be integers")
    if not ports or any(port < 1 or port > 65535 for port in ports):
        fail("ports must contain one or more valid TCP ports")
    return ports


def ruleset_digest(ipv4, ipv6, ports, ssh_port):
    contract = {
        "defaultIncoming": "deny",
        "ipv4": ipv4,
        "ipv6": ipv6,
        "ports": ports,
        "sshPort": ssh_port,
    }
    encoded = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def timestamp(value):
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        fail("receipt fetchedAt is not an ISO-8601 timestamp")
    if parsed.tzinfo is None:
        fail("receipt fetchedAt must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def expected_receipt(args):
    ipv4 = read_networks(args.ipv4, 4)
    ipv6 = read_networks(args.ipv6, 6)
    ports = parse_ports(args.ports)
    if args.ssh_port < 1 or args.ssh_port > 65535 or args.ssh_port in ports:
        fail("ssh-port must be valid and distinct from public application ports")
    return {
        "version": 1,
        "kind": "platform-cloudflare-origin-cidr-receipt/v1",
        "source": SOURCE,
        "fetchedAt": args.fetched_at,
        "ipv4Sha256": sha256_file(args.ipv4),
        "ipv6Sha256": sha256_file(args.ipv6),
        "ports": ports,
        "sshPort": args.ssh_port,
        "rulesetDigest": ruleset_digest(ipv4, ipv6, ports, args.ssh_port),
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
    parser.add_argument("--ipv4", required=True)
    parser.add_argument("--ipv6", required=True)
    parser.add_argument("--ports", required=True)
    parser.add_argument("--ssh-port", required=True, type=int)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--fetched-at", default=dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"))
    parser.add_argument("--max-age-seconds", type=int, default=604800)
    args = parser.parse_args()
    expected = expected_receipt(args)
    if args.mode == "create":
        atomic_write(args.receipt, expected)
        return
    receipt_path = pathlib.Path(args.receipt)
    if not receipt_path.is_file() or receipt_path.is_symlink():
        fail("CIDR receipt must be a regular non-symlink file")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"CIDR receipt is invalid JSON: {error}")
    if set(receipt) != set(expected):
        fail("CIDR receipt fields differ from the exact schema")
    fetched_at = timestamp(receipt.get("fetchedAt"))
    age = (dt.datetime.now(dt.timezone.utc) - fetched_at).total_seconds()
    if args.max_age_seconds < 1 or age < -300 or age > args.max_age_seconds:
        fail("CIDR receipt is stale or future-dated")
    expected["fetchedAt"] = receipt["fetchedAt"]
    if receipt != expected:
        fail("CIDR receipt hashes, ports, SSH port, source or ruleset digest are mismatched")


if __name__ == "__main__":
    main()
