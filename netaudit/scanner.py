"""
netaudit.scanner
~~~~~~~~~~~~~~~~
Core TCP scanning engine with concurrency control, rate limiting,
and structured result collection.
"""

from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .fingerprint import fingerprint_port
from .models import PortResult, ScanMeta, ScanReport, ScanStatus
from .utils import reverse_dns, resolve_host


@dataclass
class ScanConfig:
    """Immutable scan configuration — validated at construction."""

    target: str
    ports: List[int]
    threads: int = 50
    timeout: float = 2.0
    grab_banners: bool = True
    do_rdns: bool = False

    # Safe-mode overrides applied externally via factory
    rate_limit: int = 0  # 0 = no artificial delay

    def __post_init__(self) -> None:
        if not self.target:
            raise ValueError("target must not be empty")
        if not self.ports:
            raise ValueError("port list must not be empty")
        if self.threads < 1 or self.threads > 500:
            raise ValueError("threads must be between 1 and 500")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")

    @classmethod
    def safe(cls, target: str, ports: List[int], **kwargs) -> "ScanConfig":
        """Factory: safe defaults — lower concurrency, longer timeout."""
        kwargs.setdefault("threads", 10)
        kwargs.setdefault("timeout", 3.0)
        return cls(target=target, ports=ports, **kwargs)


class Scanner:
    """
    TCP connect scanner with per-thread rate-limiting semaphore.

    The scanner does NOT use raw sockets, making it unprivileged
    (no root/admin required) and fully portable.
    """

    def __init__(self, config: ScanConfig) -> None:
        self._cfg = config
        self._sem = threading.Semaphore(config.threads)
        self._lock = threading.Lock()
        self._results: List[PortResult] = []
        self._progress_cb: Optional[Callable[[int, int, int], None]] = None

    def on_progress(self, cb: Callable[[int, int, int], None]) -> "Scanner":
        """Register callback(done, total, open_count) called after each port."""
        self._progress_cb = cb
        return self

    # ── Public ────────────────────────────────────────────────────────

    def run(self) -> ScanReport:
        cfg = self._cfg
        t_start = time.monotonic()

        resolved_ip = resolve_host(cfg.target)
        rdns = reverse_dns(resolved_ip) if cfg.do_rdns else ""

        meta = ScanMeta(
            target=cfg.target,
            resolved_ip=resolved_ip,
            rdns=rdns,
            ports_scanned=len(cfg.ports),
            threads=cfg.threads,
            timeout_s=cfg.timeout,
            banners_enabled=cfg.grab_banners,
        )

        open_count = 0
        with ThreadPoolExecutor(max_workers=cfg.threads) as executor:
            futures = {
                executor.submit(self._scan_one, resolved_ip, p): p
                for p in cfg.ports
            }
            total = len(futures)
            done = 0
            for future in as_completed(futures):
                done += 1
                try:
                    result = future.result()
                except Exception as exc:
                    port = futures[future]
                    result = PortResult(
                        port=port,
                        status=ScanStatus.FILTERED,
                        error=str(exc),
                    )
                with self._lock:
                    self._results.append(result)
                    if result.status == ScanStatus.OPEN:
                        open_count += 1
                if self._progress_cb:
                    self._progress_cb(done, total, open_count)

        duration = time.monotonic() - t_start
        meta.duration_s = round(duration, 3)
        meta.open_count = open_count

        return ScanReport(
            meta=meta,
            results=sorted(self._results, key=lambda r: r.port),
        )

    # ── Private ───────────────────────────────────────────────────────

    def _scan_one(self, host: str, port: int) -> PortResult:
        cfg = self._cfg
        with self._sem:
            if cfg.rate_limit > 0:
                time.sleep(1.0 / cfg.rate_limit)
            return _tcp_connect(host, port, cfg.timeout, cfg.grab_banners)


# ── Low-level TCP probe ────────────────────────────────────────────────────────

def _tcp_connect(
    host: str, port: int, timeout: float, grab_banners: bool
) -> PortResult:
    """Single TCP connect attempt. Returns a fully populated PortResult."""
    result = PortResult(port=port)

    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            rtt = (time.monotonic() - t0) * 1000
            result.status = ScanStatus.OPEN
            result.rtt_ms = round(rtt, 2)
    except socket.timeout:
        result.status = ScanStatus.FILTERED
        return result
    except ConnectionRefusedError:
        result.status = ScanStatus.CLOSED
        return result
    except OSError as exc:
        # Covers network unreachable, host down, etc.
        result.status = ScanStatus.FILTERED
        result.error = str(exc)
        return result

    if grab_banners:
        fingerprint_port(host, port, timeout, result)

    return result
