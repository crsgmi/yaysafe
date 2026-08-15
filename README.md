# yaysafe

Security review for AUR packages before installation.

`yaysafe` is a wrapper around [`yay`](https://github.com/Jguer/yay) that analyzes AUR build files before allowing an installation to continue. It combines deterministic static analysis with optional LLM-assisted review to identify potentially dangerous or unusual package behavior.

```bash
yaysafe -S package-name
```

The goal is simple: make reviewing AUR packages easier without changing the normal `yay` workflow.

## How it works

When you run:

```bash
yaysafe -S package-name
```

yaysafe:

1. Retrieves the package's AUR build files.
2. Analyzes the `PKGBUILD`, install hooks, scripts, service files, patches, and other relevant files.
3. Runs deterministic security checks.
4. Optionally sends the package contents and static findings to a configured LLM for contextual analysis.
5. Produces a risk verdict.
6. Continues with `yay` only according to the configured security policy.

Typical output:

```text
:: Retrieving AUR build files...
:: Running yaysafe security analysis...

==> package-name
    Risk        LOW
    Confidence  95%
    Model       local-model
    Sources     github.com

:: No significant security concerns detected.
:: Continuing with yay...
```

For higher-risk packages, yaysafe displays the relevant findings and asks before continuing.

## What it looks for

The static scanner looks for security-relevant behavior including:

- unexpected writes to the live filesystem
- credential and private-key access
- suspicious network activity
- remote code execution
- shell persistence
- dangerous install hooks
- setuid and Linux capability changes
- obfuscated or dynamically constructed commands
- suspicious use of temporary files
- package-controlled systemd behavior
- execution of downloaded content

The scanner is Arch-aware. Operations involving `$pkgdir` and `$srcdir`, for example, are evaluated differently from equivalent operations against the live system.

The LLM receives the static findings as evidence and provides additional context. This helps distinguish genuinely dangerous behavior from legitimate packaging patterns that happen to involve security-sensitive primitives.

## Risk levels

| Risk | Meaning |
| --- | --- |
| `INFO` | Security-relevant information with little or no immediate concern |
| `LOW` | No significant security concern identified |
| `MEDIUM` | Behavior worth reviewing before installation |
| `HIGH` | Significant security concern; aborting is recommended |
| `CRITICAL` | Strong evidence of extremely dangerous behavior |
| `UNKNOWN` | Analysis could not produce a reliable verdict |

A LOW result is **not proof that a package is safe**, and a HIGH result is **not proof that a package is malicious**.

yaysafe is an additional review layer, not a sandbox, antivirus product, or replacement for checking package provenance.

## Requirements

- Linux
- Python 3.11+
- `git`
- `yay`
- an OpenAI-compatible LLM endpoint if LLM analysis is enabled

Arch Linux is the primary target because yaysafe is designed around `yay` and the AUR.

## Installation

### From source

```bash
git clone https://github.com/crsgmi/yaysafe.git
cd yaysafe
./install.sh
```

The installer uses `pipx` when available and otherwise creates an isolated user virtual
environment. It does not install into the system Python environment.

Manual alternatives:

```bash
pipx install .
python -m pip install .
```

Verify the installation:

```bash
yaysafe doctor
```

### AUR

AUR installation instructions will be added once an official AUR package is published.

## LLM setup

yaysafe can use an OpenAI-compatible API endpoint, making it suitable for local inference servers such as LM Studio.

Open the configuration:

```bash
yaysafe config edit
```

Configure the endpoint and model for your environment.

For example, a local OpenAI-compatible server may use:

```text
http://127.0.0.1:1234/v1
```

The exact endpoint and model depend on your inference server.

Check the resulting configuration with:

```bash
yaysafe doctor
```

### Remote APIs

Remote OpenAI-compatible endpoints can also be configured.

Be aware that enabling a remote provider may transmit AUR package contents to that provider for analysis.

API credentials are configuration data and should never be committed to a repository.

## Usage

Install through the normal guarded workflow:

```bash
yaysafe -S package-name
```

Scan without installing:

```bash
yaysafe scan package-name
```

Show configuration:

```bash
yaysafe config show
```

Edit configuration:

```bash
yaysafe config edit
```

Validate configuration:

```bash
yaysafe config validate
```

Check dependencies and configuration:

```bash
yaysafe doctor
```

For all available commands:

```bash
yaysafe --help
```

## Security model

yaysafe treats package repository contents as untrusted input.

Analysis is designed around a strict review-before-build boundary: package-controlled build files are inspected as data rather than executed as part of the security analysis.

The security decision combines two components:

### Static analysis

Deterministic rules identify concrete security-sensitive operations and provide evidence for the final verdict.

Some findings act as hard safety constraints where allowing contextual analysis to completely dismiss them would be inappropriate.

### Contextual analysis

The configured LLM evaluates the package as a whole and interprets static findings in context.

For example:

```bash
chmod 4755 "$pkgdir/opt/example/helper"
```

is materially different from:

```bash
chmod 4755 /usr/local/bin/example
```

Both are security-relevant, but they do not represent the same behavior.

The LLM helps make that distinction while deterministic checks preserve safety boundaries for particularly dangerous operations.

## Prompt injection

Package contents may contain arbitrary text, including instructions deliberately written to manipulate an LLM.

yaysafe treats package contents as untrusted data and structures LLM requests so package-provided instructions are not considered authoritative.

This reduces prompt-injection risk but cannot guarantee that every model will behave correctly.

Deterministic security checks therefore remain part of the verdict process.

## Privacy

With a local inference endpoint, LLM analysis can remain entirely on the local machine.

When a remote endpoint is configured, package contents required for analysis may be sent to that provider.

yaysafe does not require a cloud LLM.

## Project status

yaysafe is experimental software and has not received an independent security audit.

The project is developed with substantial assistance from coding models, with automated tests and manual testing used to validate behavior. This does not imply that the implementation or security analysis is error-free.

False positives and false negatives are possible.

For security vulnerabilities in yaysafe itself, see [SECURITY.md](SECURITY.md).

## License

yaysafe is released under the [MIT License](LICENSE).
