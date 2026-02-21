"""
netaudit.output
~~~~~~~~~~~~~~~
All output rendering: terminal (ANSI), JSON, CSV, Markdown.
Each renderer is a standalone function — no shared state, fully testable.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from datetime import datetime
from typing import Callable, Optional

from .models import Finding, RiskLevel, ScanReport, ScanStatus
from .constants import VERSION


# ── ANSI helpers ───────────────────────────────────────────────────────────────

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_GREEN  = "\033[92m"
_CYAN   = "\033[96m"
_BLUE   = "\033[94m"
_GREY   = "\033[90m"
_WHITE  = "\033[97m"

def _c(text: str, *codes: str, no_color: bool = False) -> str:
    if no_color or not sys.stdout.isatty() and not _FORCE_COLOR:
        return text
    return "".join(codes) + text + _RESET

_FORCE_COLOR = False  # set True in tests or when piping with color

def set_force_color(value: bool) -> None:
    global _FORCE_COLOR
    _FORCE_COLOR = value


def _risk_color(risk: RiskLevel, no_color: bool) -> str:
    mapping = {
        RiskLevel.CRITICAL: _RED + _BOLD,
        RiskLevel.HIGH:     _RED,
        RiskLevel.MEDIUM:   _YELLOW,
        RiskLevel.LOW:      _CYAN,
        RiskLevel.INFO:     _GREY,
    }
    return mapping.get(risk, "")


# ── Terminal renderer ──────────────────────────────────────────────────────────

def render_terminal(
    report: ScanReport,
    no_color: bool = False,
    verbose: bool = False,
) -> None:
    """Print full audit report to stdout."""
    nc = no_color
    _print_banner(report, nc)
    _print_open_table(report, nc)
    _print_tls_summary(report, nc)
    _print_findings_section(report, nc)
    _print_footer(report, nc)


def _print_banner(report: ScanReport, nc: bool) -> None:
    meta = report.meta
    w = 70
    print()
    print(_c("═" * w, _BOLD, no_color=nc))
    print(_c(f"  NetAudit v{VERSION} — TCP Port & Service Audit Report", _BOLD, _WHITE, no_color=nc))
    print(_c("═" * w, _BOLD, no_color=nc))
    print(f"  Target       : {_c(meta.target, _BOLD, no_color=nc)}")
    print(f"  Resolved IP  : {meta.resolved_ip}")
    if meta.rdns:
        print(f"  Reverse DNS  : {meta.rdns}")
    print(f"  Ports scanned: {meta.ports_scanned:,}")
    print(f"  Scan started : {meta.scan_started[:19].replace('T', ' ')}")
    print(f"  Banners      : {'enabled' if meta.banners_enabled else 'disabled'}")
    print(_c("═" * w, _BOLD, no_color=nc))
    print()


def _print_open_table(report: ScanReport, nc: bool) -> None:
    from .constants import CRITICAL_PORTS, HIGH_RISK_PORTS
    open_ports = report.open_ports()

    section = _c("  OPEN PORTS", _BOLD, _WHITE, no_color=nc)
    count_tag = _c(f"({len(open_ports)} found)", _DIM, no_color=nc)
    print(f"{section} {count_tag}")
    print(_c("  " + "─" * 68, _DIM, no_color=nc))

    if not open_ports:
        print(_c("  No open ports found in scanned range.\n", _GREEN, no_color=nc))
        return

    hdr = f"  {'PORT':<7} {'PROTO':<6} {'SERVICE':<22} {'RTT ms':<9} {'BANNER / SERVER'}"
    print(_c(hdr, _DIM, no_color=nc))
    print(_c("  " + "─" * 68, _DIM, no_color=nc))

    for r in open_ports:
        server = r.http_headers.get("server", r.http_headers.get("Server", ""))
        info   = (r.banner or server or "")[:38]

        if r.port in CRITICAL_PORTS:
            risk_marker = _c("⛔", no_color=nc)
            port_str    = _c(f"{r.port}", _RED, _BOLD, no_color=nc)
        elif r.port in HIGH_RISK_PORTS:
            risk_marker = _c("⚠ ", no_color=nc)
            port_str    = _c(f"{r.port}", _RED, no_color=nc)
        else:
            risk_marker = "  "
            port_str    = _c(f"{r.port}", _GREEN, no_color=nc)

        rtt_str = f"{r.rtt_ms:.1f}" if r.rtt_ms else "-"
        line = (
            f"  {risk_marker}{port_str:<5}  {r.protocol:<6} "
            f"{r.service:<22} {rtt_str:<9} {_c(info, _DIM, no_color=nc)}"
        )
        print(line)

    print()


def _print_tls_summary(report: ScanReport, nc: bool) -> None:
    tls = report.tls_ports()
    if not tls:
        return

    print(_c("  TLS / CERTIFICATE SUMMARY", _BOLD, _WHITE, no_color=nc))
    print(_c("  " + "─" * 68, _DIM, no_color=nc))

    for r in tls:
        c = r.cert
        if c.expired:
            validity_str = _c(f"EXPIRED ({abs(c.days_remaining)}d ago)", _RED, _BOLD, no_color=nc)
        elif c.days_remaining <= 14:
            validity_str = _c(f"EXPIRES IN {c.days_remaining}d — CRITICAL", _RED, no_color=nc)
        elif c.days_remaining <= 30:
            validity_str = _c(f"Expires in {c.days_remaining}d — renew soon", _YELLOW, no_color=nc)
        else:
            validity_str = _c(f"Valid ({c.days_remaining}d remaining)", _GREEN, no_color=nc)

        self_signed = _c(" [SELF-SIGNED]", _YELLOW, no_color=nc) if c.self_signed else ""
        print(f"  Port {_c(str(r.port), _BOLD, no_color=nc)} {r.service}{self_signed}")
        print(f"    Subject   : {c.subject[:80]}")
        print(f"    Issuer    : {c.issuer[:80]}")
        print(f"    Validity  : {validity_str}")
        if c.san:
            san_str = ", ".join(c.san[:6])
            if len(c.san) > 6:
                san_str += f" (+{len(c.san)-6} more)"
            print(f"    SANs      : {san_str}")
        if c.signature_algorithm:
            sig_color = _RED if any(w in c.signature_algorithm.lower() for w in ("md5", "sha1")) else ""
            print(f"    Sig Alg   : {_c(c.signature_algorithm, sig_color, no_color=nc)}")
        print()


def _print_findings_section(report: ScanReport, nc: bool) -> None:
    findings = report.findings
    if not findings:
        print(_c("  No findings generated.\n", _GREEN, no_color=nc))
        return

    print(_c("  AUDIT FINDINGS & RECOMMENDATIONS", _BOLD, _WHITE, no_color=nc))
    print(_c("  " + "─" * 68, _DIM, no_color=nc))

    for f in findings:
        risk_str = _c(f"[{f.risk.value:<8}]", _risk_color(f.risk, nc), no_color=nc)
        print(f"\n  {risk_str} Port {f.port} — {_c(f.title, _BOLD, no_color=nc)}")
        # Word-wrap detail at ~66 chars
        _print_wrapped(f.detail, indent="    ", width=66, nc=nc)
        print(f"\n    {_c('→ Recommendation:', _CYAN, no_color=nc)}")
        _print_wrapped(f.recommendation, indent="      ", width=64, nc=nc)
        if f.references:
            print(f"\n    {_c('References:', _DIM, no_color=nc)}")
            for ref in f.references[:3]:
                print(f"      {_c(ref, _DIM, no_color=nc)}")

    print()


def _print_wrapped(text: str, indent: str, width: int, nc: bool) -> None:
    import textwrap
    wrapped = textwrap.fill(text, width=width, initial_indent=indent,
                            subsequent_indent=indent)
    print(wrapped)


def _print_footer(report: ScanReport, nc: bool) -> None:
    meta = report.meta
    w = 70
    print(_c("═" * w, _BOLD, no_color=nc))

    # Summary counts
    open_c    = len(report.open_ports())
    closed_c  = sum(1 for r in report.results if r.status == ScanStatus.CLOSED)
    filtered_c = sum(1 for r in report.results if r.status == ScanStatus.FILTERED)

    crit_c  = sum(1 for f in report.findings if f.risk == RiskLevel.CRITICAL)
    high_c  = sum(1 for f in report.findings if f.risk == RiskLevel.HIGH)
    med_c   = sum(1 for f in report.findings if f.risk == RiskLevel.MEDIUM)
    low_c   = sum(1 for f in report.findings if f.risk in (RiskLevel.LOW, RiskLevel.INFO))

    print(f"  Ports : {_c(str(open_c)+' open', _GREEN, no_color=nc)}  "
          f"{closed_c} closed  {filtered_c} filtered")

    risk_parts = []
    if crit_c: risk_parts.append(_c(f"{crit_c} CRITICAL", _RED, _BOLD, no_color=nc))
    if high_c: risk_parts.append(_c(f"{high_c} HIGH", _RED, no_color=nc))
    if med_c:  risk_parts.append(_c(f"{med_c} MEDIUM", _YELLOW, no_color=nc))
    if low_c:  risk_parts.append(_c(f"{low_c} LOW/INFO", _CYAN, no_color=nc))

    if risk_parts:
        print(f"  Findings: {' · '.join(risk_parts)}")
    else:
        print(f"  Findings: {_c('None', _GREEN, no_color=nc)}")

    print(f"  Duration: {meta.duration_s:.2f}s  |  "
          f"Scanned: {meta.ports_scanned:,} ports")
    print(_c("═" * w, _BOLD, no_color=nc))
    print()


# ── JSON export ────────────────────────────────────────────────────────────────

def export_json(report: ScanReport, path: str) -> None:
    """Write full report as indented JSON."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report.as_dict(), f, indent=2, default=str, ensure_ascii=False)


# ── CSV export ─────────────────────────────────────────────────────────────────

def export_csv(report: ScanReport, path: str) -> None:
    """Write port results as CSV — one row per port."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fieldnames = [
        "port", "protocol", "status", "service", "rtt_ms", "banner",
        "http_status", "http_server", "http_x_powered_by",
        "tls_subject", "tls_issuer", "tls_not_after",
        "tls_expired", "tls_days_remaining", "tls_self_signed",
        "tls_san_count", "error",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in report.results:
            c = r.cert
            # Parse HTTP status from banner
            http_status = ""
            if r.banner and r.banner.startswith("HTTP/"):
                parts = r.banner.split(None, 2)
                if len(parts) >= 2:
                    http_status = parts[1]
            writer.writerow({
                "port":                 r.port,
                "protocol":             r.protocol,
                "status":               r.status.value,
                "service":              r.service,
                "rtt_ms":               r.rtt_ms if r.rtt_ms else "",
                "banner":               r.banner[:200],
                "http_status":          http_status,
                "http_server":          r.http_headers.get("server", r.http_headers.get("Server", "")),
                "http_x_powered_by":    r.http_headers.get("x-powered-by", ""),
                "tls_subject":          c.subject if c else "",
                "tls_issuer":           c.issuer if c else "",
                "tls_not_after":        c.not_after if c else "",
                "tls_expired":          str(c.expired) if c else "",
                "tls_days_remaining":   c.days_remaining if c else "",
                "tls_self_signed":      str(c.self_signed) if c else "",
                "tls_san_count":        len(c.san) if c else "",
                "error":                r.error,
            })


# ── Markdown export ────────────────────────────────────────────────────────────

def export_markdown(report: ScanReport, path: str) -> None:
    """Write a Markdown-formatted audit report."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    meta = report.meta
    now  = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    a = lines.append

    a(f"# NetAudit Report — {meta.target}")
    a(f"")
    a(f"> Generated by NetAudit v{VERSION} on {now}  ")
    a(f"> **FOR AUTHORISED SECURITY ASSESSMENT USE ONLY**")
    a(f"")
    a(f"## Scan Metadata")
    a(f"")
    a(f"| Property | Value |")
    a(f"|---|---|")
    a(f"| Target | `{meta.target}` |")
    a(f"| Resolved IP | `{meta.resolved_ip}` |")
    if meta.rdns:
        a(f"| Reverse DNS | `{meta.rdns}` |")
    a(f"| Ports Scanned | {meta.ports_scanned:,} |")
    a(f"| Open Ports | {meta.open_count} |")
    a(f"| Scan Duration | {meta.duration_s:.2f}s |")
    a(f"| Scan Time | {meta.scan_started[:19].replace('T', ' ')} UTC |")
    a(f"")

    # Risk summary
    crit_c  = sum(1 for f in report.findings if f.risk == RiskLevel.CRITICAL)
    high_c  = sum(1 for f in report.findings if f.risk == RiskLevel.HIGH)
    med_c   = sum(1 for f in report.findings if f.risk == RiskLevel.MEDIUM)
    low_c   = sum(1 for f in report.findings if f.risk in (RiskLevel.LOW, RiskLevel.INFO))

    a(f"## Risk Summary")
    a(f"")
    a(f"| Risk | Count |")
    a(f"|---|---|")
    a(f"| 🔴 Critical | {crit_c} |")
    a(f"| 🟠 High | {high_c} |")
    a(f"| 🟡 Medium | {med_c} |")
    a(f"| 🔵 Low / Info | {low_c} |")
    a(f"")

    # Open ports table
    open_ports = report.open_ports()
    if open_ports:
        a(f"## Open Ports")
        a(f"")
        a(f"| Port | Protocol | Service | RTT (ms) | Banner |")
        a(f"|---|---|---|---|---|")
        for r in open_ports:
            server = r.http_headers.get("server", r.http_headers.get("Server", ""))
            info   = (r.banner or server or "")[:60]
            a(f"| {r.port} | {r.protocol} | {r.service} | {r.rtt_ms or '-'} | `{info}` |")
        a(f"")

    # TLS
    tls_ports = report.tls_ports()
    if tls_ports:
        a(f"## TLS Certificate Details")
        a(f"")
        for r in tls_ports:
            c = r.cert
            a(f"### Port {r.port} — {r.service}")
            a(f"")
            a(f"| Field | Value |")
            a(f"|---|---|")
            a(f"| Subject | `{c.subject}` |")
            a(f"| Issuer | `{c.issuer}` |")
            a(f"| Valid From | {c.not_before} |")
            a(f"| Expires | {c.not_after} |")
            a(f"| Days Remaining | {'**EXPIRED**' if c.expired else c.days_remaining} |")
            a(f"| Self-Signed | {'⚠️ Yes' if c.self_signed else 'No'} |")
            a(f"| SANs | {', '.join(c.san[:8]) or 'none'} |")
            a(f"")

    # Findings
    if report.findings:
        a(f"## Findings & Recommendations")
        a(f"")
        risk_emoji = {
            RiskLevel.CRITICAL: "🔴",
            RiskLevel.HIGH:     "🟠",
            RiskLevel.MEDIUM:   "🟡",
            RiskLevel.LOW:      "🔵",
            RiskLevel.INFO:     "ℹ️",
        }
        for f in report.findings:
            emoji = risk_emoji.get(f.risk, "")
            a(f"### {emoji} [{f.risk.value}] Port {f.port} — {f.title}")
            a(f"")
            a(f"**Detail:** {f.detail}")
            a(f"")
            a(f"**Recommendation:** {f.recommendation}")
            if f.references:
                a(f"")
                a(f"**References:**")
                for ref in f.references:
                    a(f"- {ref}")
            a(f"")

    a(f"---")
    a(f"*Report generated by [NetAudit](https://github.com/yourusername/netaudit) "
      f"— authorised use only.*")
    a(f"")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ── Progress callback factory ──────────────────────────────────────────────────

def make_progress_callback(total: int, quiet: bool, no_color: bool) -> Callable:
    """Return a progress callback suitable for Scanner.on_progress()."""
    if quiet:
        return lambda done, total, open_c: None

    def _cb(done: int, total: int, open_count: int) -> None:
        if not sys.stdout.isatty():
            return
        pct  = done / total
        bar_w = 36
        filled = int(bar_w * pct)
        bar = "█" * filled + "░" * (bar_w - filled)
        line = (f"\r  [{bar}] {done:>{len(str(total))}}/{total}  "
                f"open: {_c(str(open_count), _GREEN, no_color=no_color)}")
        print(line, end="", flush=True)
        if done == total:
            print()  # newline

    return _cb
