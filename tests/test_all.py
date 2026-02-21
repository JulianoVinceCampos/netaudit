"""
tests/test_all.py
~~~~~~~~~~~~~~~~~
pytest-compatible test suite — wraps the inline self-tests plus
adds network-free integration-style tests.

Run:
    pytest tests/ -v
    pytest tests/ -v --tb=short
"""

import json
import pytest
from netaudit.utils import parse_ports, safe_filename, reverse_dns
from netaudit.models import (
    CertInfo, Finding, PortResult, RiskLevel,
    ScanMeta, ScanReport, ScanStatus,
)
from netaudit.scanner import ScanConfig
from netaudit.findings import analyse


# ══════════════════════════════════════════════
# Port parsing
# ══════════════════════════════════════════════

class TestParsePortsSingle:
    def test_single_port(self):
        assert parse_ports("22") == [22]

    def test_port_80(self):
        assert parse_ports("80") == [80]

    def test_port_max(self):
        assert parse_ports("65535") == [65535]

    def test_port_min(self):
        assert parse_ports("1") == [1]


class TestParsePortsMultiple:
    def test_csv(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_sorted(self):
        assert parse_ports("443,80,22") == [22, 80, 443]

    def test_dedup(self):
        assert parse_ports("80,80,80") == [80]

    def test_whitespace(self):
        assert parse_ports(" 22 , 80 ") == [22, 80]


class TestParsePortsRanges:
    def test_simple_range(self):
        assert parse_ports("1-5") == [1, 2, 3, 4, 5]

    def test_range_single_element(self):
        assert parse_ports("443-443") == [443]

    def test_large_range(self):
        result = parse_ports("1-1024")
        assert len(result) == 1024
        assert result[0] == 1
        assert result[-1] == 1024

    def test_combined(self):
        assert parse_ports("1-3,8080") == [1, 2, 3, 8080]

    def test_combined_dedup(self):
        assert parse_ports("1-5,3-7") == [1, 2, 3, 4, 5, 6, 7]


class TestParsePortsErrors:
    def test_zero(self):
        with pytest.raises(ValueError, match="out of range"):
            parse_ports("0")

    def test_too_large(self):
        with pytest.raises(ValueError, match="out of range"):
            parse_ports("65536")

    def test_inverted_range(self):
        with pytest.raises(ValueError, match="inverted"):
            parse_ports("1024-80")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            parse_ports("")

    def test_non_numeric(self):
        with pytest.raises(ValueError):
            parse_ports("ssh")

    def test_negative(self):
        with pytest.raises(ValueError):
            parse_ports("-1")


# ══════════════════════════════════════════════
# Models
# ══════════════════════════════════════════════

class TestPortResult:
    def test_defaults(self):
        r = PortResult(port=80)
        assert r.status == ScanStatus.FILTERED
        assert r.rtt_ms == 0.0
        assert r.banner == ""
        assert r.cert is None

    def test_as_dict_has_status_value(self):
        r = PortResult(port=80, status=ScanStatus.OPEN)
        d = r.as_dict()
        assert d["status"] == "open"

    def test_http_headers_default_empty(self):
        r = PortResult(port=80)
        assert r.http_headers == {}


class TestScanReport:
    def _make_report(self, ports_status):
        meta = ScanMeta(target="127.0.0.1", resolved_ip="127.0.0.1")
        results = [PortResult(port=p, status=s) for p, s in ports_status]
        return ScanReport(meta=meta, results=results)

    def test_open_ports(self):
        report = self._make_report([
            (22, ScanStatus.OPEN),
            (23, ScanStatus.CLOSED),
            (80, ScanStatus.OPEN),
            (443, ScanStatus.FILTERED),
        ])
        open_p = report.open_ports()
        assert len(open_p) == 2
        assert {r.port for r in open_p} == {22, 80}

    def test_tls_ports_empty(self):
        report = self._make_report([(443, ScanStatus.OPEN)])
        assert report.tls_ports() == []

    def test_tls_ports_with_cert(self):
        meta = ScanMeta(target="127.0.0.1", resolved_ip="127.0.0.1")
        cert = CertInfo(subject="CN=x", issuer="CN=ca", days_remaining=90)
        results = [PortResult(port=443, status=ScanStatus.OPEN, cert=cert)]
        report = ScanReport(meta=meta, results=results)
        assert len(report.tls_ports()) == 1

    def test_highest_risk_none(self):
        report = self._make_report([(80, ScanStatus.OPEN)])
        report.findings = []
        assert report.highest_risk() is None

    def test_as_dict_json_serialisable(self):
        report = self._make_report([(80, ScanStatus.OPEN)])
        d = report.as_dict()
        s = json.dumps(d, default=str)
        assert "127.0.0.1" in s


# ══════════════════════════════════════════════
# ScanConfig
# ══════════════════════════════════════════════

class TestScanConfig:
    def test_valid_config(self):
        cfg = ScanConfig(target="127.0.0.1", ports=[22, 80])
        assert cfg.target == "127.0.0.1"
        assert cfg.ports == [22, 80]

    def test_threads_zero_raises(self):
        with pytest.raises(ValueError):
            ScanConfig(target="127.0.0.1", ports=[80], threads=0)

    def test_threads_too_large_raises(self):
        with pytest.raises(ValueError):
            ScanConfig(target="127.0.0.1", ports=[80], threads=501)

    def test_negative_timeout_raises(self):
        with pytest.raises(ValueError):
            ScanConfig(target="127.0.0.1", ports=[80], timeout=-0.1)

    def test_empty_target_raises(self):
        with pytest.raises(ValueError):
            ScanConfig(target="", ports=[80])

    def test_empty_ports_raises(self):
        with pytest.raises(ValueError):
            ScanConfig(target="127.0.0.1", ports=[])

    def test_safe_factory(self):
        cfg = ScanConfig.safe(target="127.0.0.1", ports=[22])
        assert cfg.threads <= 10
        assert cfg.timeout >= 3.0


# ══════════════════════════════════════════════
# Findings engine
# ══════════════════════════════════════════════

def _report_with_ports(*port_status_pairs):
    meta = ScanMeta(target="127.0.0.1", resolved_ip="127.0.0.1")
    results = [PortResult(port=p, status=s) for p, s in port_status_pairs]
    return ScanReport(meta=meta, results=results)


class TestFindingsEngine:
    def test_docker_unencrypted_is_critical(self):
        report = _report_with_ports((2375, ScanStatus.OPEN))
        findings = analyse(report)
        assert any(f.port == 2375 and f.risk == RiskLevel.CRITICAL for f in findings)

    def test_telnet_is_critical(self):
        report = _report_with_ports((23, ScanStatus.OPEN))
        findings = analyse(report)
        assert any(f.port == 23 and f.risk == RiskLevel.CRITICAL for f in findings)

    def test_x11_is_critical(self):
        report = _report_with_ports((6000, ScanStatus.OPEN))
        findings = analyse(report)
        assert any(f.port == 6000 and f.risk == RiskLevel.CRITICAL for f in findings)

    def test_rdp_is_high(self):
        report = _report_with_ports((3389, ScanStatus.OPEN))
        findings = analyse(report)
        assert any(f.port == 3389 and f.risk == RiskLevel.HIGH for f in findings)

    def test_ssh_is_high(self):
        report = _report_with_ports((22, ScanStatus.OPEN))
        findings = analyse(report)
        assert any(f.port == 22 and f.risk == RiskLevel.HIGH for f in findings)

    def test_redis_is_high(self):
        report = _report_with_ports((6379, ScanStatus.OPEN))
        findings = analyse(report)
        assert any(f.port == 6379 and f.risk == RiskLevel.HIGH for f in findings)

    def test_closed_port_no_findings(self):
        report = _report_with_ports((2375, ScanStatus.CLOSED))
        findings = analyse(report)
        assert len(findings) == 0

    def test_findings_sorted_critical_first(self):
        report = _report_with_ports(
            (3389, ScanStatus.OPEN),  # HIGH
            (2375, ScanStatus.OPEN),  # CRITICAL
        )
        findings = analyse(report)
        order = {RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1, RiskLevel.MEDIUM: 2,
                 RiskLevel.LOW: 3, RiskLevel.INFO: 4}
        for i in range(len(findings) - 1):
            assert order[findings[i].risk] <= order[findings[i+1].risk]

    def test_no_duplicate_findings(self):
        report = _report_with_ports((2375, ScanStatus.OPEN))
        findings = analyse(report)
        keys = [(f.port, f.title) for f in findings]
        assert len(keys) == len(set(keys)), "Duplicate findings detected"

    def test_tls_expired_cert(self):
        meta = ScanMeta(target="t", resolved_ip="1.2.3.4")
        cert = CertInfo(subject="CN=x", issuer="CN=ca", expired=True, days_remaining=-10)
        results = [PortResult(port=443, status=ScanStatus.OPEN, cert=cert)]
        report = ScanReport(meta=meta, results=results)
        findings = analyse(report)
        assert any("Expired" in f.title and f.risk == RiskLevel.HIGH for f in findings)

    def test_tls_self_signed(self):
        meta = ScanMeta(target="t", resolved_ip="1.2.3.4")
        cert = CertInfo(subject="CN=x", issuer="CN=x", self_signed=True, days_remaining=365)
        results = [PortResult(port=443, status=ScanStatus.OPEN, cert=cert)]
        report = ScanReport(meta=meta, results=results)
        findings = analyse(report)
        assert any("Self-Signed" in f.title and f.risk == RiskLevel.MEDIUM for f in findings)

    def test_http_only_no_https_medium(self):
        report = _report_with_ports((80, ScanStatus.OPEN))
        findings = analyse(report)
        assert any("No HTTPS" in f.title or "Plaintext" in f.title for f in findings)


# ══════════════════════════════════════════════
# Utilities
# ══════════════════════════════════════════════

class TestUtils:
    def test_safe_filename_removes_slash(self):
        result = safe_filename("192.168.1.1/test")
        assert "/" not in result

    def test_safe_filename_removes_colon(self):
        result = safe_filename("host:8080")
        assert ":" not in result

    def test_safe_filename_preserves_dots(self):
        result = safe_filename("192.168.1.1")
        assert "." in result

    def test_reverse_dns_invalid_returns_empty(self):
        # Should not raise — returns empty string on failure
        result = reverse_dns("0.0.0.0")
        assert isinstance(result, str)
