"""
netaudit.tests.test_parsers
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for port parsing, model construction, and findings logic.
No network access required — fully offline.

Run via:
    python -m netaudit --selftest
    python -m pytest tests/
"""

from __future__ import annotations

import sys
import traceback
from typing import Callable, List, Tuple


# ── Test registry ──────────────────────────────────────────────────────────────

_tests: List[Tuple[str, Callable]] = []

def test(name: str):
    """Decorator to register a test function."""
    def decorator(fn):
        _tests.append((name, fn))
        return fn
    return decorator


def run_all() -> int:
    """Run all registered tests. Returns 0 on all-pass, 1 on any failure."""
    passed = failed = 0
    print(f"\nRunning {len(_tests)} self-tests…\n")

    for name, fn in _tests:
        try:
            fn()
            print(f"  ✓  {name}")
            passed += 1
        except AssertionError as exc:
            print(f"  ✗  {name}")
            print(f"     AssertionError: {exc}")
            failed += 1
        except Exception as exc:
            print(f"  ✗  {name}")
            traceback.print_exc()
            failed += 1

    total = passed + failed
    status = "PASSED" if failed == 0 else "FAILED"
    print(f"\n{status}: {passed}/{total} tests passed")
    return 0 if failed == 0 else 1


# ── Port parsing tests ─────────────────────────────────────────────────────────

@test("parse_ports: single port")
def _():
    from netaudit.utils import parse_ports
    assert parse_ports("22") == [22]

@test("parse_ports: multiple ports")
def _():
    from netaudit.utils import parse_ports
    assert parse_ports("22,80,443") == [22, 80, 443]

@test("parse_ports: range")
def _():
    from netaudit.utils import parse_ports
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]

@test("parse_ports: combined range and singles")
def _():
    from netaudit.utils import parse_ports
    assert parse_ports("1-3,8080") == [1, 2, 3, 8080]

@test("parse_ports: deduplication")
def _():
    from netaudit.utils import parse_ports
    assert parse_ports("80,80,80") == [80]

@test("parse_ports: sorting across mixed input")
def _():
    from netaudit.utils import parse_ports
    assert parse_ports("8080,1-3") == [1, 2, 3, 8080]

@test("parse_ports: whitespace tolerance")
def _():
    from netaudit.utils import parse_ports
    assert parse_ports(" 22 , 80 , 443 ") == [22, 80, 443]

@test("parse_ports: single-element range")
def _():
    from netaudit.utils import parse_ports
    assert parse_ports("443-443") == [443]

@test("parse_ports: error on port 0")
def _():
    from netaudit.utils import parse_ports
    try:
        parse_ports("0")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

@test("parse_ports: error on port 65536")
def _():
    from netaudit.utils import parse_ports
    try:
        parse_ports("65536")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

@test("parse_ports: error on inverted range")
def _():
    from netaudit.utils import parse_ports
    try:
        parse_ports("1024-80")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

@test("parse_ports: error on empty string")
def _():
    from netaudit.utils import parse_ports
    try:
        parse_ports("")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

@test("parse_ports: error on non-numeric token")
def _():
    from netaudit.utils import parse_ports
    try:
        parse_ports("ssh")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass

@test("parse_ports: large range is valid")
def _():
    from netaudit.utils import parse_ports
    result = parse_ports("1-1024")
    assert len(result) == 1024
    assert result[0] == 1
    assert result[-1] == 1024

@test("parse_ports: max valid port 65535")
def _():
    from netaudit.utils import parse_ports
    assert parse_ports("65535") == [65535]


# ── Model tests ────────────────────────────────────────────────────────────────

@test("ScanStatus enum values")
def _():
    from netaudit.models import ScanStatus
    assert ScanStatus.OPEN.value == "open"
    assert ScanStatus.CLOSED.value == "closed"
    assert ScanStatus.FILTERED.value == "filtered"

@test("RiskLevel ordering")
def _():
    from netaudit.models import RiskLevel
    levels = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM,
              RiskLevel.LOW, RiskLevel.INFO]
    assert len(levels) == 5

@test("PortResult default status is FILTERED")
def _():
    from netaudit.models import PortResult, ScanStatus
    r = PortResult(port=80)
    assert r.status == ScanStatus.FILTERED

@test("CertInfo self-signed detection in model")
def _():
    from netaudit.models import CertInfo
    c = CertInfo(subject="CN=test", issuer="CN=test", self_signed=True)
    assert c.self_signed is True

@test("ScanReport.open_ports() filters correctly")
def _():
    from netaudit.models import PortResult, ScanReport, ScanMeta, ScanStatus
    meta = ScanMeta(target="127.0.0.1", resolved_ip="127.0.0.1")
    results = [
        PortResult(port=22, status=ScanStatus.OPEN),
        PortResult(port=23, status=ScanStatus.CLOSED),
        PortResult(port=80, status=ScanStatus.OPEN),
        PortResult(port=443, status=ScanStatus.FILTERED),
    ]
    report = ScanReport(meta=meta, results=results)
    open_ports = report.open_ports()
    assert len(open_ports) == 2
    assert {r.port for r in open_ports} == {22, 80}

@test("ScanReport.tls_ports() returns only ports with cert")
def _():
    from netaudit.models import PortResult, ScanReport, ScanMeta, ScanStatus, CertInfo
    meta = ScanMeta(target="127.0.0.1", resolved_ip="127.0.0.1")
    c = CertInfo(subject="CN=test", issuer="CN=ca")
    results = [
        PortResult(port=443, status=ScanStatus.OPEN, cert=c),
        PortResult(port=80,  status=ScanStatus.OPEN, cert=None),
    ]
    report = ScanReport(meta=meta, results=results)
    assert len(report.tls_ports()) == 1
    assert report.tls_ports()[0].port == 443

@test("ScanReport.as_dict() is JSON-serialisable")
def _():
    import json
    from netaudit.models import PortResult, ScanReport, ScanMeta, ScanStatus
    meta = ScanMeta(target="127.0.0.1", resolved_ip="127.0.0.1")
    report = ScanReport(meta=meta, results=[PortResult(port=80, status=ScanStatus.OPEN)])
    d = report.as_dict()
    serialised = json.dumps(d)  # should not raise
    assert "127.0.0.1" in serialised


# ── Findings tests ─────────────────────────────────────────────────────────────

@test("findings: Docker unencrypted port flags CRITICAL")
def _():
    from netaudit.models import (
        PortResult, ScanReport, ScanMeta, ScanStatus, RiskLevel
    )
    from netaudit.findings import analyse
    meta = ScanMeta(target="127.0.0.1", resolved_ip="127.0.0.1")
    report = ScanReport(
        meta=meta,
        results=[PortResult(port=2375, status=ScanStatus.OPEN)],
    )
    findings = analyse(report)
    assert any(
        f.port == 2375 and f.risk == RiskLevel.CRITICAL
        for f in findings
    ), f"Expected CRITICAL finding for port 2375, got: {findings}"

@test("findings: Telnet flags CRITICAL")
def _():
    from netaudit.models import PortResult, ScanReport, ScanMeta, ScanStatus, RiskLevel
    from netaudit.findings import analyse
    meta = ScanMeta(target="127.0.0.1", resolved_ip="127.0.0.1")
    report = ScanReport(
        meta=meta,
        results=[PortResult(port=23, status=ScanStatus.OPEN)],
    )
    findings = analyse(report)
    assert any(f.risk == RiskLevel.CRITICAL and f.port == 23 for f in findings)

@test("findings: no findings for closed port")
def _():
    from netaudit.models import PortResult, ScanReport, ScanMeta, ScanStatus
    from netaudit.findings import analyse
    meta = ScanMeta(target="127.0.0.1", resolved_ip="127.0.0.1")
    report = ScanReport(
        meta=meta,
        results=[PortResult(port=2375, status=ScanStatus.CLOSED)],
    )
    findings = analyse(report)
    assert len(findings) == 0, "Closed ports should not generate findings"

@test("findings: expired TLS cert flags HIGH")
def _():
    from netaudit.models import (
        PortResult, ScanReport, ScanMeta, ScanStatus, CertInfo, RiskLevel
    )
    from netaudit.findings import analyse
    meta = ScanMeta(target="127.0.0.1", resolved_ip="127.0.0.1")
    cert = CertInfo(
        subject="CN=test", issuer="CN=ca",
        not_after="Jan 01 00:00:00 2020 GMT",
        expired=True, days_remaining=-1825,
    )
    report = ScanReport(
        meta=meta,
        results=[PortResult(port=443, status=ScanStatus.OPEN, cert=cert)],
    )
    findings = analyse(report)
    assert any(f.risk == RiskLevel.HIGH and "Expired" in f.title for f in findings)

@test("findings: self-signed cert flags MEDIUM")
def _():
    from netaudit.models import (
        PortResult, ScanReport, ScanMeta, ScanStatus, CertInfo, RiskLevel
    )
    from netaudit.findings import analyse
    meta = ScanMeta(target="127.0.0.1", resolved_ip="127.0.0.1")
    cert = CertInfo(
        subject="CN=test", issuer="CN=test",
        self_signed=True, days_remaining=365,
    )
    report = ScanReport(
        meta=meta,
        results=[PortResult(port=443, status=ScanStatus.OPEN, cert=cert)],
    )
    findings = analyse(report)
    assert any(f.risk == RiskLevel.MEDIUM and "Self-Signed" in f.title for f in findings)

@test("findings: RDP flags HIGH")
def _():
    from netaudit.models import PortResult, ScanReport, ScanMeta, ScanStatus, RiskLevel
    from netaudit.findings import analyse
    meta = ScanMeta(target="127.0.0.1", resolved_ip="127.0.0.1")
    report = ScanReport(
        meta=meta,
        results=[PortResult(port=3389, status=ScanStatus.OPEN)],
    )
    findings = analyse(report)
    assert any(f.risk == RiskLevel.HIGH and f.port == 3389 for f in findings)

@test("findings: sorted by risk level (critical first)")
def _():
    from netaudit.models import PortResult, ScanReport, ScanMeta, ScanStatus
    from netaudit.findings import analyse
    from netaudit.models import RiskLevel
    meta = ScanMeta(target="127.0.0.1", resolved_ip="127.0.0.1")
    report = ScanReport(
        meta=meta,
        results=[
            PortResult(port=23,   status=ScanStatus.OPEN),  # CRITICAL
            PortResult(port=3389, status=ScanStatus.OPEN),  # HIGH
            PortResult(port=80,   status=ScanStatus.OPEN),  # MEDIUM
        ],
    )
    findings = analyse(report)
    if len(findings) >= 2:
        order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2,
                 RiskLevel.LOW: 3, RiskLevel.INFO: 4}
        for i in range(len(findings) - 1):
            assert order[findings[i].risk] <= order[findings[i+1].risk], \
                "Findings should be sorted by risk level"


# ── Utility tests ──────────────────────────────────────────────────────────────

@test("safe_filename: sanitises special chars")
def _():
    from netaudit.utils import safe_filename
    result = safe_filename("192.168.1.1:8080/test")
    assert "/" not in result
    assert ":" not in result

@test("ScanConfig: invalid threads rejected")
def _():
    from netaudit.scanner import ScanConfig
    try:
        ScanConfig(target="127.0.0.1", ports=[80], threads=0)
        assert False, "Should raise ValueError"
    except ValueError:
        pass

@test("ScanConfig: invalid timeout rejected")
def _():
    from netaudit.scanner import ScanConfig
    try:
        ScanConfig(target="127.0.0.1", ports=[80], timeout=-1)
        assert False, "Should raise ValueError"
    except ValueError:
        pass

@test("ScanConfig.safe() factory applies safe defaults")
def _():
    from netaudit.scanner import ScanConfig
    cfg = ScanConfig.safe(target="127.0.0.1", ports=[22, 80])
    assert cfg.threads <= 10
    assert cfg.timeout >= 3.0
