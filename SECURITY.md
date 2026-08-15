# Security Policy

yaysafe is security-sensitive software. Vulnerabilities that affect the integrity of its analysis or allow package-controlled content to escape the intended review boundary are particularly important.

## Reporting a vulnerability

Please do not disclose exploitable vulnerabilities through a public GitHub issue.

Use GitHub's private vulnerability reporting feature from the repository's **Security** tab instead.

A useful report should include:

- the affected yaysafe version or commit
- a description of the vulnerability
- steps to reproduce it
- the expected security impact
- relevant environment information
- a minimal synthetic test case when possible

Do not include real credentials, private keys, access tokens, or other people's private information.

## Security-sensitive areas

Reports are especially useful when they involve:

- execution of package-controlled code during analysis
- bypassing the review-before-build boundary
- arbitrary local file access
- credential or secret disclosure
- command or shell injection
- terminal escape-sequence injection
- prompt injection that bypasses deterministic safety constraints
- incorrect handling of HIGH or CRITICAL findings
- repository mutation between analysis and installation
- unintended transmission of data to an LLM provider
- cache or verdict integrity issues

## Supported versions

Security fixes are provided on a best-effort basis for the latest release.

yaysafe is currently pre-1.0 software, so older releases may not receive fixes.

## Disclosure

Please allow reasonable time to investigate and fix a reported vulnerability before publishing technical details.

Confirmed vulnerabilities may be documented through GitHub Security Advisories after a fix is available.
