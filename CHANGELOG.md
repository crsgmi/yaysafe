# Changelog

All notable changes to yaysafe are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) after the experimental `0.x` phase.

## [Unreleased]

### Added

- Deterministic, Arch-aware inspection of PKGBUILDs, install hooks, scripts, service units, patches,
  and other relevant repository text without executing package code.
- Numbered LM Studio, Ollama, OpenAI, Anthropic, and custom provider setup with model discovery,
  hidden API-key entry, native Anthropic Messages support, streaming inactivity timeouts, strict
  JSON validation, prompt-size limits, and prompt-injection boundaries.
- LLM-primary contextual verdicts constrained by a deliberately small set of deterministic hard
  security rules.
- Compact yay-style terminal output, default-No policy prompts, detailed inspection, JSON scan
  output, doctor checks, configuration editing, and private scan caching.
- Whole-repository integrity hashing and an isolated yay handoff that retains the exact reviewed
  worktree while disabling edit hooks, redownload, and new Git retrieval.
- Regression coverage for path-operation context, staged `$pkgdir` behavior, sensitive credential
  access, LLM failures, terminal injection, symlinks, cache invalidation, and yay argument handling.

### Security

- Package repositories are retrieved with inherited Git configuration, hooks, external protocols,
  and credential prompting disabled.
- LLM redirects are refused, terminal controls are sanitized, and UNKNOWN is never silently
  presented as safe.

[Unreleased]: https://github.com/dahekker/yaysafe/commits/main
