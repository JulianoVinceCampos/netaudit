#!/usr/bin/env python3
"""
netaudit.__main__
~~~~~~~~~~~~~~~~~
CLI entry point. Run as:

    python -m netaudit <target> [options]
    # or after pip install:
    netaudit <target> [options]
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import textwrap
from datetime import datetime

from .constants import DEFAULT_PORTS, VERSION
from .findings import analyse
from .models import ScanStatus
from .output import (
    export_csv,
    export_json,
    export_markdown,
    make_progress_callback,
    render_terminal,
)
from .scanner import Scanner, ScanConfig
from .utils import parse_ports, safe_filename


# ── CLI definition ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netaudit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(f"""\
            NetAudit v{VERSION} — TCP Port & Service Audit Scanner
            ════════════════════════════════════════════════════════
            Zero-dependency, audit-grade network port scanner.
            Performs TCP connect scan, banner grabbing, TLS inspection,
            and generates structured findings with recommendations.

            ⚠  USE ONLY ON SYSTEMS YOU OWN OR HAVE EXPLICIT WRITTEN
               PERMISSION TO TEST. Unauthorised scanning is illegal.
        """),
        epilog=textwrap.dedent("""\
            Examples:
              # Quick scan of localhost — common ports + banners
              python -m netaudit 127.0.0.1 --banners

              # Full audit with all outputs
              python -m netaudit 192.168.1.10 -p 1-1024 --banners --out ./reports

              # Safe mode — reduced concurrency, longer timeout
              python -m netaudit 10.0.0.1 --safe --banners --out ./reports

              # Custom ports + markdown report
              python -m netaudit myhost.local -p 22,80,443,8080-8090 --banners --out ./out

              # Self-tests (no network required)
              python -m netaudit --selftest
        """),
    )

    parser.add_argument(
        "target", nargs="?",
        help="Target IP address or hostname",
    )

    # Port selection
    pg = parser.add_argument_group("Port Selection")
    pg.add_argument(
        "-p", "--ports",
        default=DEFAULT_PORTS,
        metavar="SPEC",
        help=(
            "Port specification: '22,80,443' or '1-1024' or '1-1024,8080,8443'. "
            f"Default: common high-risk ports ({len(parse_ports(DEFAULT_PORTS))} ports)."
        ),
    )

    # Scan behaviour
    sg = parser.add_argument_group("Scan Behaviour")
    sg.add_argument(
        "-t", "--threads",
        type=int, default=50, metavar="N",
        help="Maximum concurrent threads (default: 50)",
    )
    sg.add_argument(
        "--timeout",
        type=float, default=2.0, metavar="SEC",
        help="TCP connect timeout per port in seconds (default: 2.0)",
    )
    sg.add_argument(
        "--banners", action="store_true",
        help="Enable banner grabbing, HTTP probing, and TLS certificate inspection",
    )
    sg.add_argument(
        "--rdns", action="store_true",
        help="Perform reverse DNS lookup on the resolved IP",
    )
    sg.add_argument(
        "--safe", action="store_true",
        help=(
            "Safe scan mode: limits to 10 threads, 3s timeout, adds rate limiting. "
            "Reduces load on the target and minimises firewall triggering."
        ),
    )

    # Output
    og = parser.add_argument_group("Output")
    og.add_argument(
        "--out", metavar="DIR",
        help="Write JSON, CSV, and Markdown reports to this directory",
    )
    og.add_argument(
        "--json", metavar="FILE",
        help="Write JSON report to a specific file path",
    )
    og.add_argument(
        "--csv", metavar="FILE",
        help="Write CSV report to a specific file path",
    )
    og.add_argument(
        "--md", "--markdown", metavar="FILE", dest="markdown",
        help="Write Markdown report to a specific file path",
    )
    og.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colour codes (auto-detected when not a TTY)",
    )
    og.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress all output except open port lines (machine-friendly)",
    )
    og.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable DEBUG-level logging with timestamps",
    )

    # Misc
    parser.add_argument(
        "--selftest", action="store_true",
        help="Run built-in self-tests and exit (no network required)",
    )
    parser.add_argument(
        "--version", action="version", version=f"netaudit {VERSION}",
    )

    return parser


# ── Main ───────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    parser = build_parser()
    args   = parser.parse_args(argv)

    # Self-test mode
    if args.selftest:
        return _run_selftest()

    # Target is required for everything else
    if not args.target:
        parser.print_help()
        return 1

    # Logging
    _configure_logging(args.verbose, args.quiet)
    log = logging.getLogger("netaudit")

    # Safe mode overrides
    threads = args.threads
    timeout = args.timeout
    if args.safe:
        threads = min(threads, 10)
        timeout = max(timeout, 3.0)
        if not args.quiet:
            print(f"[safe mode] threads={threads}, timeout={timeout:.1f}s, rate-limit=20/s")

    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"\n[ERROR] Invalid port specification: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"\n  Resolving {args.target!r} …", end=" ", flush=True)

    # Build config
    cfg = ScanConfig(
        target=args.target,
        ports=ports,
        threads=threads,
        timeout=timeout,
        grab_banners=args.banners,
        do_rdns=args.rdns,
        rate_limit=20 if args.safe else 0,
    )

    # Progress callback
    progress_cb = make_progress_callback(
        total=len(ports), quiet=args.quiet, no_color=args.no_color
    )

    # Run scan
    scanner = Scanner(cfg)
    if not args.quiet:
        print("done.")
    scanner.on_progress(progress_cb)

    report = scanner.run()

    # Post-scan: update counts
    report.meta.closed_count   = sum(1 for r in report.results if r.status == ScanStatus.CLOSED)
    report.meta.filtered_count = sum(1 for r in report.results if r.status == ScanStatus.FILTERED)

    # Analyse findings
    report.findings = analyse(report)

    # Output
    if args.quiet:
        for r in report.open_ports():
            server = r.http_headers.get("server", "")
            print(f"{r.port}/{r.status.value}/{r.service}/{r.rtt_ms}ms/{server}")
    else:
        render_terminal(report, no_color=args.no_color, verbose=args.verbose)

    # File exports
    ts_tag   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_tgt = safe_filename(args.target)

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        base = os.path.join(args.out, f"netaudit_{safe_tgt}_{ts_tag}")
        _export(report, json_path=base+".json", csv_path=base+".csv", md_path=base+".md",
                quiet=args.quiet)

    if args.json:
        export_json(report, args.json)
        if not args.quiet:
            print(f"  JSON  → {args.json}")

    if args.csv:
        export_csv(report, args.csv)
        if not args.quiet:
            print(f"  CSV   → {args.csv}")

    if args.markdown:
        export_markdown(report, args.markdown)
        if not args.quiet:
            print(f"  MD    → {args.markdown}")

    # Exit code: 1 if CRITICAL findings, 0 otherwise
    from .models import RiskLevel
    has_critical = any(f.risk == RiskLevel.CRITICAL for f in report.findings)
    return 1 if has_critical else 0


def _export(report, json_path, csv_path, md_path, quiet):
    export_json(report, json_path)
    export_csv(report, csv_path)
    export_markdown(report, md_path)
    if not quiet:
        print(f"  JSON  → {json_path}")
        print(f"  CSV   → {csv_path}")
        print(f"  MD    → {md_path}")
        print()


# ── Logging ────────────────────────────────────────────────────────────────────

def _configure_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.WARNING)
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(name)-15s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )


# ── Self-tests ─────────────────────────────────────────────────────────────────

def _run_selftest() -> int:
    """Run built-in unit tests. Returns 0 on success, 1 on failure."""
    from .tests.test_parsers import run_all
    return run_all()


if __name__ == "__main__":
    sys.exit(main())
