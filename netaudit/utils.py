"""
netaudit.utils
~~~~~~~~~~~~~~
Utility functions: port parsing, DNS resolution, reverse DNS.
All functions are pure or have clearly documented side-effects.
"""

from __future__ import annotations

import re
import socket
import sys
from typing import List


# ── Port parsing ───────────────────────────────────────────────────────────────

def parse_ports(spec: str) -> List[int]:
    """
    Parse a flexible port specification string into a sorted, deduplicated list.

    Supported formats (may be combined with commas):
      - Single port  : "22"
      - Range        : "1-1024"
      - Combined     : "22,80,443,8080-8090,8443"

    Raises:
        ValueError: on invalid syntax, out-of-range values, or inverted ranges.

    Examples:
        >>> parse_ports("22,80,443")
        [22, 80, 443]
        >>> parse_ports("8080-8083")
        [8080, 8081, 8082, 8083]
        >>> parse_ports("1-3,8080")
        [1, 2, 3, 8080]
    """
    if not spec or not spec.strip():
        raise ValueError("port specification must not be empty")

    ports: set = set()
    parts = [p.strip() for p in spec.split(",") if p.strip()]

    for part in parts:
        if "-" in part:
            _parse_range(part, ports)
        else:
            _parse_single(part, ports)

    if not ports:
        raise ValueError(f"no valid ports found in specification: '{spec}'")

    return sorted(ports)


def _parse_single(token: str, ports: set) -> None:
    try:
        port = int(token)
    except ValueError:
        raise ValueError(f"invalid port token: '{token}'") from None
    _validate_port(port, token)
    ports.add(port)


def _parse_range(token: str, ports: set) -> None:
    parts = token.split("-", 1)
    if len(parts) != 2:
        raise ValueError(f"invalid range syntax: '{token}'")
    try:
        lo, hi = int(parts[0].strip()), int(parts[1].strip())
    except ValueError:
        raise ValueError(f"non-integer in range: '{token}'") from None

    _validate_port(lo, f"{token} (low end)")
    _validate_port(hi, f"{token} (high end)")

    if lo > hi:
        raise ValueError(
            f"inverted range '{token}': low ({lo}) must be ≤ high ({hi})"
        )
    if hi - lo > 65534:
        raise ValueError(f"range '{token}' exceeds maximum span (65534 ports)")

    ports.update(range(lo, hi + 1))


def _validate_port(port: int, label: str) -> None:
    if not (1 <= port <= 65535):
        raise ValueError(
            f"port out of range [1–65535]: {label} → {port}"
        )


# ── DNS helpers ────────────────────────────────────────────────────────────────

def resolve_host(target: str) -> str:
    """
    Resolve hostname to IPv4 address string.

    Raises:
        SystemExit: on DNS failure (user-friendly message, no traceback).
    """
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror as exc:
        _fatal(f"DNS resolution failed for '{target}': {exc}")


def reverse_dns(ip: str) -> str:
    """
    Attempt reverse DNS lookup. Returns empty string on failure.
    Never raises.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


# ── Misc helpers ───────────────────────────────────────────────────────────────

def safe_filename(name: str) -> str:
    """Sanitise a string for use as a filename component."""
    return re.sub(r"[^\w.\-]", "_", name)


def _fatal(msg: str) -> None:
    print(f"\n[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)
