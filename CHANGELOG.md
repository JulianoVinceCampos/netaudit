# Changelog

All notable changes to NetAudit are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.0.0] — 2025-01-xx

### Added
- Full package structure with `netaudit` importable as a library
- `ScanConfig` dataclass with validated fields and `ScanConfig.safe()` factory
- Modular `fingerprint.py` with protocol-aware probing:
  - Raw banner grabbing (SSH, SMTP, FTP, POP3, IMAP, Redis, MongoDB)
  - HTTP/HTTPS HEAD probe with full response header capture
  - TLS certificate metadata extraction (subject, SAN, expiry, self-signed flag, sig algorithm)
- Rule-based findings engine (`findings.py`) with 10 categories:
  - Critical: Docker unencrypted API, Telnet, X11, etcd, Kubelet read-only
  - High: RDP, SSH, SMB, VNC, Redis, Elasticsearch, MongoDB, Memcached
  - Medium: plaintext protocols, management interfaces, self-signed certs
  - Low/Info: version disclosure in banners, SMTP relay
- Markdown report export (`--md / --markdown`)
- JSON and CSV exports with full field coverage
- Exit code `1` when CRITICAL findings detected (CI/pipeline integration)
- `--selftest` flag — runs all unit tests without network access
- pytest test suite in `tests/` covering parsing, models, findings, and utilities
- GitHub Actions CI: multi-OS (Linux/macOS/Windows), Python 3.8–3.12, lint, type check
- `pyproject.toml` with `[project.scripts]` entry point
- `SECURITY.md`, `CONTRIBUTING.md`, issue templates

### Changed
- Complete rewrite from single-file `scanner.py` to structured package
- Progress bar now shows open count in real time
- Terminal output redesigned with risk-level colour coding and findings section
- Port hint database expanded from ~40 to 70+ entries

### Removed
- Single-file `scanner.py` (superseded by package; `python -m netaudit` replaces it)

---

## [1.0.0] — 2025-01-xx

### Added
- Initial release: single-file TCP connect scanner
- TCP connect scan with open/closed/filtered detection
- Banner grabbing: SSH, SMTP, FTP, HTTP, HTTPS
- TLS certificate metadata (subject, issuer, SAN, expiry)
- JSON and CSV export
- ANSI terminal output with port table and quick findings
- `--safe` mode with concurrency limiting
- Port specification parser: single, range, combined
