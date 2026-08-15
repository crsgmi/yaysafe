from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from yaysafe.config import ScannerConfig
from yaysafe.models import Finding, InspectedFile, PackageMetadata, Risk, StaticResult
from yaysafe.rules import analyze_rules, extract_install_hook_names, extract_source_data

PRIORITY_NAMES = {"PKGBUILD", ".SRCINFO"}
RELEVANT_SUFFIXES = {
    ".install",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".service",
    ".socket",
    ".timer",
    ".desktop",
    ".patch",
    ".diff",
}
TEXT_SUFFIXES = RELEVANT_SUFFIXES | {
    ".conf",
    ".cfg",
    ".toml",
    ".yaml",
    ".yml",
    ".json",
    ".txt",
    ".md",
}
MAX_REPOSITORY_FILES = 20_000
MAX_STATIC_FINDINGS = 4096


class ScanError(RuntimeError):
    pass


def _candidate(path: Path) -> bool:
    return path.name in PRIORITY_NAMES or path.suffix.lower() in TEXT_SUFFIXES or not path.suffix


def _decode_text(data: bytes) -> str | None:
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        decoded = data.decode("utf-8", errors="replace")
        if decoded.count("\ufffd") > max(2, len(decoded) // 20):
            return None
        return decoded


def _repository_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(name for name in directories if name != ".git")
        for name in directories:
            path = current_path / name
            if path.is_symlink():
                paths.append(path)
        paths.extend(current_path / name for name in sorted(filenames))
        if len(paths) > MAX_REPOSITORY_FILES:
            raise ScanError(
                f"repository exceeds the safe file-count limit of {MAX_REPOSITORY_FILES}"
            )
    return sorted(paths, key=lambda item: item.relative_to(root).as_posix())


def collect_files(root: Path, config: ScannerConfig) -> tuple[list[InspectedFile], list[str]]:
    root = root.resolve(strict=True)
    files: list[InspectedFile] = []
    skipped: list[str] = []
    total = 0
    paths = sorted(_repository_paths(root), key=lambda p: (p.name not in PRIORITY_NAMES, str(p)))
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if ".git" in path.relative_to(root).parts:
            continue
        if path.is_symlink():
            try:
                target = os.readlink(path)
            except OSError:
                target = "unreadable target"
            skipped.append(f"{relative}: symlink -> {target}")
            continue
        try:
            if not path.is_file() or not _candidate(path):
                continue
            stat = path.stat(follow_symlinks=False)
        except OSError:
            skipped.append(f"{relative}: unreadable")
            continue
        if stat.st_size > config.max_file_size:
            skipped.append(f"{relative}: exceeds per-file limit")
            continue
        if total + stat.st_size > config.max_total_prompt_size:
            skipped.append(f"{relative}: exceeds total limit")
            continue
        try:
            data = path.read_bytes()
        except OSError:
            skipped.append(f"{relative}: unreadable")
            continue
        text = _decode_text(data)
        if text is None:
            skipped.append(f"{relative}: binary")
            continue
        files.append(InspectedFile(relative, text, len(data), path))
        total += len(data)
    if not any(item.relative_path == "PKGBUILD" for item in files):
        raise ScanError("retrieved repository has no readable PKGBUILD")
    return files, skipped


def content_digest(files: list[InspectedFile]) -> str:
    digest = hashlib.sha256()
    for item in sorted(files, key=lambda value: value.relative_path):
        name = item.relative_path.encode("utf-8", errors="surrogateescape")
        try:
            content = item.path.read_bytes()
        except OSError as exc:
            raise ScanError(
                f"inspected file changed or became unreadable: {item.relative_path}"
            ) from exc
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def repository_digest(root: Path, max_size: int = 268_435_456) -> str:
    """Hash every repository artifact without following symlinks.

    Scan limits decide what can be sent to analysis, but must never allow a changed
    skipped artifact to retain an old cache result.
    """
    resolved = root.resolve(strict=True)
    digest = hashlib.sha256()
    total_size = 0
    for path in _repository_paths(resolved):
        relative_path = path.relative_to(resolved)
        if ".git" in relative_path.parts:
            continue
        relative = relative_path.as_posix().encode("utf-8", errors="surrogateescape")
        if path.is_symlink():
            target = os.readlink(path).encode("utf-8", errors="surrogateescape")
            total_size += len(target)
            if total_size > max_size:
                raise ScanError(
                    f"repository exceeds scanner.max_repository_size ({max_size} bytes)"
                )
            digest.update(b"L")
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(len(target).to_bytes(8, "big"))
            digest.update(target)
            continue
        if not path.is_file():
            continue
        try:
            file_size = path.stat(follow_symlinks=False).st_size
            total_size += file_size
        except OSError as exc:
            raise ScanError(f"cannot inspect repository file: {relative_path}") from exc
        if total_size > max_size:
            raise ScanError(f"repository exceeds scanner.max_repository_size ({max_size} bytes)")
        digest.update(b"F")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            actual_size = 0
            with os.fdopen(descriptor, "rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    actual_size += len(chunk)
                    if total_size - file_size + actual_size > max_size:
                        raise ScanError(
                            "repository grew beyond scanner.max_repository_size while hashing"
                        )
                    digest.update(chunk)
            if actual_size != file_size:
                raise ScanError(f"repository file changed while hashing: {relative_path}")
        except OSError as exc:
            raise ScanError(
                f"repository file changed or became unreadable: {relative_path}"
            ) from exc
    return digest.hexdigest()


def _assignment(pkgbuild: str, name: str) -> str:
    match = re.search(rf"(?m)^\s*{re.escape(name)}\s*=\s*([^\n#]+)", pkgbuild)
    if not match:
        return ""
    return match.group(1).strip().strip("'\"")


def scan_repository(
    root: Path, package_name: str, config: ScannerConfig, *, package_base: str = ""
) -> StaticResult:
    if not config.enabled:
        raise ScanError("static scanner is disabled; refusing to treat analysis as complete")
    initial_digest = repository_digest(root, config.max_repository_size)
    files, skipped = collect_files(root, config)
    pkgbuild = next(item.content for item in files if item.relative_path == "PKGBUILD")
    urls, domains = extract_source_data(pkgbuild)
    metadata = PackageMetadata(
        name=package_name,
        package_base=package_base or package_name,
        description=_assignment(pkgbuild, "pkgdesc"),
        url=_assignment(pkgbuild, "url"),
        version=_assignment(pkgbuild, "pkgver"),
        source_urls=urls,
        source_domains=domains,
        vcs_package=(
            package_name.endswith(("-git", "-hg", "-svn", "-bzr"))
            or bool(re.search(r"(?:git|hg|svn|bzr)\+https?://", pkgbuild, re.IGNORECASE))
        ),
    )
    findings = analyze_rules(files, metadata)
    install_hooks = extract_install_hook_names(pkgbuild)
    for skipped_item in skipped:
        skipped_path, _, reason = skipped_item.partition(": ")
        suffix = Path(skipped_path).suffix.lower()
        if suffix not in RELEVANT_SUFFIXES and skipped_path not in install_hooks:
            continue
        findings.append(
            Finding(
                Risk.MEDIUM,
                "analysis-coverage",
                skipped_path,
                0,
                reason,
                "A security-relevant repository file could not be inspected; analysis coverage is incomplete.",
                "analysis-coverage",
            )
        )
    if len(findings) > MAX_STATIC_FINDINGS:
        raise ScanError(f"static analysis exceeds the safe limit of {MAX_STATIC_FINDINGS} findings")
    metadata.skipped_checksums = sorted(
        {
            f.matched_text.split("=", 1)[0].strip()
            for f in findings
            if f.rule_id == "skipped-checksum"
        }
    )
    final_digest = repository_digest(root, config.max_repository_size)
    if final_digest != initial_digest:
        raise ScanError("retrieved repository changed while security analysis was reading it")
    return StaticResult(findings, metadata, files, final_digest, skipped)
