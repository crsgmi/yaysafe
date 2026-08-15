# yaysafe

> **Experimental software.** yaysafe was built with substantial AI assistance ("vibecoded") and
> has not received an independent security audit. It is an extra review layer, not proof that an
> AUR package is safe.

yaysafe is a security-focused wrapper around [`yay`](https://github.com/Jguer/yay). It retrieves
AUR build files, scans them without executing them, asks an optional configured LLM for contextual
analysis, applies your risk policy, and then hands the terminal back to the real `yay` process.

```text
yaysafe preparation → static scan → LLM review → policy decision → yay
```

The interface is deliberately small and follows familiar `yay`/Arch terminal conventions.

## Requirements

yaysafe does not check for a specific Linux distribution. It needs:

- Python 3.11 or newer
- `git`
- `yay` and the package-management environment it expects
- optionally, LM Studio, Ollama, OpenAI, Anthropic, or another OpenAI-compatible endpoint

Arch Linux and Arch-derived systems are the usual environments because that is where `yay` is
used. The Python runtime itself has no third-party dependencies.

Never run yaysafe, yay, or package builds as root.

## Install

Using `pipx`:

```bash
git clone https://github.com/dahekker/yaysafe.git
cd yaysafe
pipx install .
yaysafe doctor
```

If `yaysafe` is not on `PATH`, run `pipx ensurepath`, open a new shell, and try again.

The included `PKGBUILD` is for future AUR packaging. Do not use it until a matching public release
tag exists.

## Use

```bash
yaysafe -S package-name
yaysafe -S package1 package2
yaysafe -Syu

yaysafe scan package
yaysafe scan package --no-llm
yaysafe scan package --no-cache
yaysafe scan package --verbose
yaysafe scan package --json

yaysafe doctor
yaysafe config
yaysafe config llm
```

Removal, search, information, and other non-build operations pass through to `yay`:

```bash
yaysafe -R package
yaysafe -Ss query
yaysafe -Si package
```

Use `yaysafe -S package` for installation. Bare `yaysafe package` is refused because yay's
interactive selection does not reveal the final package early enough to review it safely.

Running `yaysafe` without arguments opens a small line-oriented menu.

## LLM setup

The default is local LM Studio at:

```text
http://127.0.0.1:1234/v1
```

Run:

```bash
yaysafe config llm
```

Choose a numbered provider:

```text
1  LM Studio (local)
2  Ollama (local)
3  OpenAI
4  Anthropic
5  Custom OpenAI-compatible
```

Accept or change its endpoint, enter an API key when required, then choose a model from the
numbered list discovered from that provider. API-key input is hidden, the config file is private to
your user, and `yaysafe config` always redacts the key. Anthropic uses its native Messages API; the
other choices use OpenAI-compatible model and chat-completion routes.

The response timeout is based on inactivity. A model may generate for longer than the configured
timeout as long as the stream keeps producing data or heartbeat events.

## Configuration

```bash
yaysafe config          # show config with API key redacted
yaysafe config edit     # open it in your editor
yaysafe config path
yaysafe config validate
```

Paths follow XDG conventions:

```text
$XDG_CONFIG_HOME/yaysafe/config.toml
$XDG_CACHE_HOME/yaysafe/
```

They fall back to `~/.config/yaysafe/` and `~/.cache/yaysafe/`.

The default policy allows INFO/LOW, confirms MEDIUM/HIGH/UNKNOWN with No as the default answer, and
blocks CRITICAL.

## What is scanned

yaysafe inspects PKGBUILDs, install hooks, shell scripts, service units, patches, and other relevant
text. It distinguishes ordinary packaging under `$pkgdir` and `$srcdir` from direct host changes.

Static rules produce evidence. The LLM supplies most contextual classification, while a small set
of hard rules prevents clear credential theft, destructive host behavior, or direct remote-code
execution from being silently downgraded.

Before `yay` continues, yaysafe checks that the reviewed repository content has not changed and
uses an isolated handoff that prevents new Git retrieval or post-review editing.

## Privacy and safety

- Retrieved package code is treated as hostile data and is never sourced or executed during scan.
- yaysafe never invokes `makepkg` during analysis.
- Package contents are sent only to the LLM endpoint you configure. Selecting OpenAI, Anthropic, or
  another remote endpoint sends the inspected package files off the machine and may incur charges.
- HTTP redirects are refused for LLM requests.
- Untrusted terminal text is sanitized.
- There is no telemetry, analytics, or crash reporting.

Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## Limitations

**A LOW risk result does not prove that a package is safe. A HIGH risk result does not prove that a
package is malicious.** Static rules and models can both be wrong. yaysafe is not a sandbox,
antivirus product, cryptographic verification system, or replacement for reviewing package
provenance. It does not recursively audit every upstream source archive downloaded by a build.

## Development

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]' 'build>=1.2,<2'
.venv/bin/python -m pytest
.venv/bin/python -m ruff format --check .
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy yaysafe
```

Fixture repositories under `tests/fixtures/` are hostile text samples. Tests may read them but must
never execute them.

See [CONTRIBUTING.md](CONTRIBUTING.md),
[Publishing to GitHub](docs/PUBLISHING_TO_GITHUB.md), and
[Releasing yaysafe](docs/RELEASING.md).
