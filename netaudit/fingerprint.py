"""
netaudit.fingerprint
~~~~~~~~~~~~~~~~~~~~
Service fingerprinting via banner grabbing, HTTP probing, and TLS
certificate inspection. All operations are read-only and safe by design.

Protocol coverage:
  - Raw banner (SSH, SMTP, FTP, POP3, IMAP, Telnet, Redis, etc.)
  - HTTP/HTTPS HEAD probe (Server header, status line)
  - TLS handshake metadata (cert subject, SAN, expiry, self-signed flag)
"""

from __future__ import annotations

import socket
import ssl
import struct
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from .models import CertInfo, PortResult
from .constants import HTTP_PORTS, TLS_PORTS, PORT_HINTS


# ── Dispatcher ────────────────────────────────────────────────────────────────

def fingerprint_port(
    host: str, port: int, timeout: float, result: PortResult
) -> None:
    """
    Populate *result* in-place with banner/fingerprint data.
    Never raises — all exceptions are swallowed and noted in result.error.
    """
    result.service = PORT_HINTS.get(port, "")

    try:
        if port in TLS_PORTS or port == 443:
            _probe_tls(host, port, timeout, result)
        elif port in HTTP_PORTS:
            _probe_http(host, port, tls=False, timeout=timeout, result=result)
        else:
            _probe_raw(host, port, timeout, result)
    except Exception as exc:
        result.error = f"fingerprint error: {exc}"


# ── HTTP probe ─────────────────────────────────────────────────────────────────

def _probe_http(
    host: str,
    port: int,
    tls: bool,
    timeout: float,
    result: PortResult,
) -> None:
    """Send HTTP HEAD / and capture response line + headers."""
    raw = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = _tls_context()
        s = ctx.wrap_socket(raw, server_hostname=host)
    else:
        s = raw

    with s:
        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: NetAudit-Scanner/2.0 (security audit)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(request.encode())
        s.settimeout(timeout)

        buf = bytearray()
        while len(buf) < 8192:
            chunk = _recv_safe(s)
            if not chunk:
                break
            buf.extend(chunk)
            if b"\r\n\r\n" in buf:
                break

    text = buf.decode("utf-8", errors="replace")
    lines = text.splitlines()

    if lines:
        result.banner = lines[0].strip()[:200]

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ": " in line:
            k, _, v = line.partition(": ")
            headers[k.strip().lower()] = v.strip()

    result.http_headers = headers

    # Refine service hint from response
    if "x-powered-by" in headers:
        result.service = result.service or headers["x-powered-by"]
    if "server" in headers:
        result.service = result.service or headers["server"]


# ── TLS probe ─────────────────────────────────────────────────────────────────

def _probe_tls(
    host: str, port: int, timeout: float, result: PortResult
) -> None:
    """TLS handshake → cert metadata + HTTP HEAD if applicable."""
    ctx = _tls_context()
    raw = socket.create_connection((host, port), timeout=timeout)
    with ctx.wrap_socket(raw, server_hostname=host) as s:
        cert_dict = s.getpeercert()  # decoded — works even without verify
        result.cert = _parse_cert(cert_dict) if cert_dict else None

    # After TLS cert, try HTTP over TLS
    _probe_http(host, port, tls=True, timeout=timeout, result=result)


def _parse_cert(cert_dict: dict) -> CertInfo:
    """Convert ssl.getpeercert() dict → CertInfo dataclass."""

    def _rdn(seq) -> str:
        parts = []
        for rdn in seq:
            for k, v in rdn:
                parts.append(f"{k}={v}")
        return ", ".join(parts)

    subject = _rdn(cert_dict.get("subject", []))
    issuer  = _rdn(cert_dict.get("issuer", []))
    nb      = cert_dict.get("notBefore", "")
    na      = cert_dict.get("notAfter",  "")

    san: list = []
    for alt_type, alt_val in cert_dict.get("subjectAltName", []):
        san.append(f"{alt_type}:{alt_val}")

    serial = str(cert_dict.get("serialNumber", ""))
    sig_alg = cert_dict.get("signatureAlgorithm", "")

    expired = False
    days_remaining = 0
    try:
        fmt = "%b %d %H:%M:%S %Y %Z"
        exp_dt = datetime.strptime(na, fmt).replace(tzinfo=timezone.utc)
        now_dt = datetime.now(timezone.utc)
        days_remaining = (exp_dt - now_dt).days
        expired = days_remaining < 0
    except ValueError:
        pass

    self_signed = subject == issuer

    return CertInfo(
        subject=subject,
        issuer=issuer,
        not_before=nb,
        not_after=na,
        san=san,
        serial=serial,
        signature_algorithm=sig_alg,
        expired=expired,
        days_remaining=days_remaining,
        self_signed=self_signed,
    )


# ── Raw banner probe ───────────────────────────────────────────────────────────

def _probe_raw(host: str, port: int, timeout: float, result: PortResult) -> None:
    """
    Connect and wait for a spontaneous banner (SSH, SMTP, FTP, POP3, Redis…).
    For protocols that require a prompt, we also try a null/newline push.
    """
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        data = _recv_safe(s, size=2048)

        # If nothing arrives, nudge with a blank line (Telnet, some services)
        if not data:
            try:
                s.sendall(b"\r\n")
                data = _recv_safe(s, size=512, timeout=1.0)
            except OSError:
                pass

    if not data:
        return

    banner = data.decode("utf-8", errors="replace").strip()[:300]
    result.banner = banner

    # Refine service from banner content
    _refine_service_from_banner(banner, result)


def _refine_service_from_banner(banner: str, result: PortResult) -> None:
    upper = banner.upper()
    if banner.startswith("SSH-"):
        result.service = "SSH"
    elif upper.startswith("220") and ("SMTP" in upper or "MAIL" in upper or "ESMTP" in upper):
        result.service = "SMTP"
    elif upper.startswith("220") and "FTP" in upper:
        result.service = "FTP"
    elif upper.startswith("+OK"):
        result.service = "POP3"
    elif upper.startswith("* OK"):
        result.service = "IMAP"
    elif banner.startswith("-ERR") or banner.startswith("+OK"):
        result.service = "Redis" if "redis" in banner.lower() else result.service
    elif "REDIS" in upper:
        result.service = "Redis"
    elif "MONGO" in upper:
        result.service = "MongoDB"
    elif "MYSQL" in upper or "MariaDB" in banner:
        result.service = "MySQL/MariaDB"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tls_context() -> ssl.SSLContext:
    """Build an audit-mode TLS context: no chain/hostname verification."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _recv_safe(
    sock: socket.socket,
    size: int = 1024,
    timeout: Optional[float] = None,
) -> bytes:
    if timeout is not None:
        sock.settimeout(timeout)
    try:
        return sock.recv(size)
    except (socket.timeout, OSError):
        return b""
