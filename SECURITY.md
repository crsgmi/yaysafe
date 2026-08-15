# Security policy

## Project status

yaysafe is experimental, AI-assisted software and has not received an independent security audit.
It is an additional review layer, not a sandbox or proof that an AUR package is safe.

Security fixes are provided on a best-effort basis for the latest tagged release. Pre-release
versions may change without backward-compatibility guarantees.

## Reporting a vulnerability

Please do not disclose an exploitable vulnerability in a public issue or pull request.

Use GitHub's **Report a vulnerability** form under the repository's Security tab. Repository
administrators should enable private vulnerability reporting before announcing the project. If
that form is unavailable, open a public issue containing no vulnerability details and ask the
maintainer for a private contact method.

Particularly important reports include any way to:

- execute a retrieved PKGBUILD, install hook, script, fixture, or other package content during
  analysis;
- substitute unreviewed content between analysis and the final yay build;
- expose an API key, credential, private package content, or local file;
- send package content anywhere except the configured LLM endpoint;
- inject terminal control sequences into displayed output;
- bypass a hard deterministic rule or silently convert an UNKNOWN result into a safe result;
- escape repository size, symlink, path, or cache integrity boundaries.

Include the affected version, operating-system/package-manager environment, yay/Python versions, a
minimal reproducer using synthetic data, and the expected impact. Do not include real credentials,
private keys, or other people's private package contents.

The maintainer will acknowledge and investigate reports as availability permits. No response or
remediation deadline is guaranteed for this volunteer project.

## Coordinated disclosure

Please allow time for a fix and release before publishing details. Once a fix is available, the
maintainer may publish a GitHub security advisory describing affected versions and mitigations.
