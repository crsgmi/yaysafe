# Contributing to yaysafe

Thank you for helping improve yaysafe. The project is experimental and security-sensitive, so
changes should be small, reviewable, and supported by regression tests.

## Before opening a change

- Use an issue for design discussion when behavior or policy will materially change.
- Follow [SECURITY.md](SECURITY.md) for vulnerabilities; do not disclose exploitable details in a
  public issue or pull request.
- Disclose substantial AI-generated contributions in the pull request. AI assistance is welcome,
  but generated output must be reviewed and tested by the contributor.

## Development setup

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]' 'build>=1.2,<2'
.venv/bin/python -m pytest
.venv/bin/python -m ruff format --check .
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy yaysafe
```

Before submitting, also build and inspect the distributions:

```bash
.venv/bin/python scripts/check_release.py
.venv/bin/python -m build
tar -tf dist/yaysafe-*.tar.gz
unzip -l dist/yaysafe-*.whl
```

## Safety rules

- Never source, execute, or evaluate an AUR repository file or test fixture.
- Never invoke `makepkg` during package analysis.
- Never introduce `shell=True` for package-controlled input.
- Keep package contents in the LLM user-data payload, never in system instructions.
- Sanitize every untrusted string before terminal display.
- Preserve `$pkgdir` and `$srcdir` awareness.
- Preserve UNKNOWN and deterministic hard-rule floors.
- Add regression tests for security fixes and false-positive fixes.

Files under `tests/fixtures/` are hostile text samples. Tests may read them but must never run them.

## Pull requests

Explain the threat or false-positive scenario, the chosen behavior, and the verification performed.
Avoid unrelated cleanup in security changes. A passing test suite is necessary but does not replace
review of the security assumptions.
