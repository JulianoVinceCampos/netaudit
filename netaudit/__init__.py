"""
netaudit — TCP Port & Service Audit Scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
A professional-grade, zero-dependency network reconnaissance and
audit tool designed for authorised security assessments.

Quick usage::

    from netaudit.scanner import Scanner, ScanConfig
    from netaudit.utils import parse_ports

    config = ScanConfig(target="127.0.0.1", ports=parse_ports("22,80,443"))
    report = Scanner(config).run()

:copyright: (c) 2025 by the authors.
:license: MIT, see LICENSE for details.
"""

from .constants import VERSION
from .models import (
    CertInfo,
    Finding,
    PortResult,
    RiskLevel,
    ScanMeta,
    ScanReport,
    ScanStatus,
)
from .scanner import Scanner, ScanConfig

__version__ = VERSION
__all__ = [
    "Scanner",
    "ScanConfig",
    "ScanReport",
    "ScanMeta",
    "PortResult",
    "CertInfo",
    "Finding",
    "RiskLevel",
    "ScanStatus",
    "__version__",
]
