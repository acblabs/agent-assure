"""Isolated bounded-output DNS worker for live provider endpoint screening."""

from __future__ import annotations

import ipaddress
import socket
import sys

MAX_RESOLVED_ENDPOINT_ADDRESSES = 64


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    host = sys.argv[1]
    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, RuntimeError):
        return 3

    addresses: set[str] = set()
    for result in results:
        try:
            address = str(ipaddress.ip_address(str(result[4][0])))
        except (IndexError, TypeError, ValueError):
            continue
        addresses.add(address)
        if len(addresses) > MAX_RESOLVED_ENDPOINT_ADDRESSES:
            return 4
    if not addresses:
        return 5
    sys.stdout.write("\n".join(sorted(addresses)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
