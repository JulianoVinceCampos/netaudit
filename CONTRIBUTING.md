# Contributing to NetAudit

Thank you for your interest in contributing. This document covers:
- Development setup
- Running tests
- Code style expectations
- How to submit a pull request

---

## ⚠️ Ethical Requirement

All contributors must agree:
- NetAudit is a tool for **authorised security assessments only**.
- No contribution may weaken the tool's safety posture (e.g. removing timeouts, adding aggressive default behaviour).
- Do not submit examples or tests that target systems you don't own.

---

## Development Setup

```bash
git clone https://github.com/yourusername/netaudit.git
cd netaudit

python3 -m venv venv
source venv/bin/activate   # or .\venv\Scripts\Activate.ps1 on Windows

pip install -e ".[dev]"
```

This installs the package in editable mode plus all dev tools:
`pytest`, `pytest-cov`, `mypy`, `ruff`.

---

## Running Tests

```bash
# All tests via pytest
pytest tests/ -v

# Self-tests (no network, no pytest required)
python -m netaudit --selftest

# With coverage
pytest tests/ --cov=netaudit --cov-report=term-missing
```

All tests must pass on Python 3.8–3.12 on Linux, macOS, and Windows.

---

## Code Style

```bash
# Lint
ruff check netaudit/

# Type check
mypy netaudit/ --ignore-missing-imports
```

Key conventions:
- **Zero external runtime dependencies** — stdlib only. No exceptions.
- Type annotations on all public functions and class attributes.
- Docstrings on all public modules, classes, and functions.
- Functions should be ≤ 40 lines. Extract helpers early.
- Tests for every new finding rule and utility function.
- No bare `except:` — catch specific exceptions.

---

## Adding a New Finding Rule

1. Add your rule function to `netaudit/findings.py` following the existing pattern:

```python
def _rule_my_service(open_set, open_results, report) -> List[Finding]:
    findings = []
    if MY_PORT in open_set:
        findings.append(_f(
            MY_PORT, RiskLevel.HIGH,
            "My Service Title",
            "Detailed explanation of the risk...",
            "Actionable recommendation...",
            ["https://reference-url.example.com"],
        ))
    return findings
```

2. Register it in `_RULES` at the bottom of `findings.py`.
3. Add a test in `tests/test_all.py` covering:
   - The finding fires when port is open
   - The finding does NOT fire when port is closed
   - Correct risk level is assigned

---

## Submitting a Pull Request

1. Fork the repository and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```

2. Make your changes with tests.

3. Ensure CI passes locally:
   ```bash
   ruff check netaudit/
   mypy netaudit/ --ignore-missing-imports
   pytest tests/ -v
   ```

4. Commit with a clear message:
   ```
   feat(findings): add finding rule for Prometheus metrics exposure

   Adds MEDIUM-risk finding for port 9090 (Prometheus) being accessible.
   Includes recommendation to restrict to management IPs and notes
   potential data leakage from /metrics endpoint.
   ```

5. Open a PR against `main` with:
   - Description of what changed and why
   - Any relevant CVE or security reference links
   - Screenshot of terminal output if UI changed

---

## Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Use for |
|---|---|
| `feat:` | New features |
| `fix:` | Bug fixes |
| `docs:` | Documentation only |
| `test:` | Adding or fixing tests |
| `refactor:` | Code restructuring |
| `chore:` | Maintenance, CI, deps |

---

## Questions?

Open a [GitHub Discussion](https://github.com/yourusername/netaudit/discussions)
for questions, ideas, or design proposals.
