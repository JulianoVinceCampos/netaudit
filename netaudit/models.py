"""
netaudit.models
~~~~~~~~~~~~~~~
Typed data models shared across the entire package.
Using dataclasses for zero-dependency, JSON-serialisable structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# ── Enumerations ──────────────────────────────────────────────────────────────

class ScanStatus(str, Enum):
    OPEN     = "open"
    CLOSED   = "closed"
    FILTERED = "filtered"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ── TLS / Certificate model ────────────────────────────────────────────────────

@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    san: List[str] = field(default_factory=list)
    serial: str = ""
    signature_algorithm: str = ""
    # Computed fields
    expired: bool = False
    days_remaining: int = 0
    self_signed: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Per-port result ────────────────────────────────────────────────────────────

@dataclass
class PortResult:
    port: int
    status: ScanStatus = ScanStatus.FILTERED
    service: str = ""          # heuristic hint (e.g. "SSH", "HTTP")
    protocol: str = "tcp"
    banner: str = ""           # raw first bytes / HTTP status line
    rtt_ms: float = 0.0
    cert: Optional[CertInfo] = None
    http_headers: Dict[str, str] = field(default_factory=dict)
    error: str = ""

    # Populated by findings engine
    findings: List["Finding"] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


# ── Findings / audit notes ─────────────────────────────────────────────────────

@dataclass
class Finding:
    port: int
    risk: RiskLevel
    title: str
    detail: str
    recommendation: str
    references: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["risk"] = self.risk.value
        return d


# ── Scan metadata ──────────────────────────────────────────────────────────────

@dataclass
class ScanMeta:
    target: str
    resolved_ip: str
    rdns: str = ""
    ports_scanned: int = 0
    open_count: int = 0
    closed_count: int = 0
    filtered_count: int = 0
    threads: int = 0
    timeout_s: float = 0.0
    banners_enabled: bool = True
    duration_s: float = 0.0
    scan_started: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    scanner_version: str = "2.0.0"

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Top-level report ───────────────────────────────────────────────────────────

@dataclass
class ScanReport:
    meta: ScanMeta
    results: List[PortResult]
    findings: List[Finding] = field(default_factory=list)

    def open_ports(self) -> List[PortResult]:
        return [r for r in self.results if r.status == ScanStatus.OPEN]

    def tls_ports(self) -> List[PortResult]:
        return [r for r in self.open_ports() if r.cert is not None]

    def highest_risk(self) -> Optional[RiskLevel]:
        if not self.findings:
            return None
        order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM,
                 RiskLevel.LOW, RiskLevel.INFO]
        risks = {f.risk for f in self.findings}
        for r in order:
            if r in risks:
                return r
        return None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "meta": self.meta.as_dict(),
            "findings": [f.as_dict() for f in self.findings],
            "results": [r.as_dict() for r in self.results],
        }
