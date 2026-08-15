from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

AUR_RPC = "https://aur.archlinux.org/rpc/v5"
AUR_GIT = "https://aur.archlinux.org"
MAX_RETRIEVED_PACKAGE_BASES = 256
MAX_SRCINFO_SIZE = 4 * 1024 * 1024
MAX_DECLARED_DEPENDENCIES = 4096
MAX_AUR_RESPONSE_SIZE = 8 * 1024 * 1024


class AURError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AURPackage:
    name: str
    package_base: str
    version: str = ""
    description: str = ""
    url: str = ""


@dataclass(slots=True)
class RetrievedPackage:
    package: AURPackage
    root: Path
    requested_names: list[str] = field(default_factory=list)


FetchJSON = Callable[[str, float], dict[str, Any]]


def _fetch_json(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "yaysafe/1.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_AUR_RESPONSE_SIZE + 1)
            if len(raw) > MAX_AUR_RESPONSE_SIZE:
                raise AURError("AUR metadata response exceeds the safe size limit")
            data = json.loads(raw)
    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        raise AURError(f"AUR metadata request failed: {exc}") from exc
    if not isinstance(data, dict):
        raise AURError("AUR metadata response is invalid")
    return data


def normalize_target(value: str) -> str:
    target = value.split("/", 1)[-1]
    return re.split(r"[<>=]", target, maxsplit=1)[0].strip()


class AURClient:
    def __init__(
        self,
        *,
        timeout: float = 30.0,
        fetch_json: FetchJSON = _fetch_json,
        git: str = "git",
        aur_url: str = AUR_GIT,
        rpc_url: str = AUR_RPC,
    ) -> None:
        self.timeout = timeout
        self.fetch_json = fetch_json
        self.git = git
        self.aur_url = _validated_service_url(aur_url, "AUR URL")
        self.rpc_url = _validated_service_url(rpc_url, "AUR RPC URL", allow_query_marker=True)

    def _rpc_request(self, operation: str, parameters: list[tuple[str, str]]) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(self.rpc_url)
        if self.rpc_url.endswith("?") or parsed.path.rstrip("/").endswith("/rpc"):
            query = urllib.parse.urlencode([("v", "5"), ("type", operation), *parameters])
            separator = "" if self.rpc_url.endswith("?") else "?"
            url = f"{self.rpc_url}{separator}{query}"
        else:
            query = urllib.parse.urlencode(parameters)
            url = f"{self.rpc_url.rstrip('/')}/{operation}?{query}"
        return self.fetch_json(url, self.timeout)

    def info(self, names: Iterable[str]) -> dict[str, AURPackage]:
        requested = [normalize_target(name) for name in names if normalize_target(name)]
        if not requested:
            return {}
        results: dict[str, AURPackage] = {}
        for start in range(0, len(requested), 100):
            data = self._rpc_request(
                "info", [("arg[]", name) for name in requested[start : start + 100]]
            )
            items = data.get("results", [])
            if not isinstance(items, list):
                raise AURError("AUR metadata response has no results array")
            for item in items:
                if not isinstance(item, dict) or not item.get("Name"):
                    continue
                package = AURPackage(
                    name=str(item["Name"]),
                    package_base=str(item.get("PackageBase") or item["Name"]),
                    version=str(item.get("Version", "")),
                    description=str(item.get("Description", "")),
                    url=str(item.get("URL", "")),
                )
                results[package.name] = package
        return results

    def find_provider(self, dependency: str) -> AURPackage | None:
        name = normalize_target(dependency)
        data = self._rpc_request("search", [("arg", name), ("by", "provides")])
        candidates = data.get("results", [])
        if not isinstance(candidates, list) or not candidates:
            return None
        exact = next(
            (x for x in candidates if isinstance(x, dict) and x.get("Name") == name), candidates[0]
        )
        if not isinstance(exact, dict) or not exact.get("Name"):
            return None
        return AURPackage(
            str(exact["Name"]),
            str(exact.get("PackageBase") or exact["Name"]),
            str(exact.get("Version", "")),
            str(exact.get("Description", "")),
            str(exact.get("URL", "")),
        )

    def clone(self, package: AURPackage, destination: Path) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@._+:-]*", package.package_base):
            raise AURError("AUR returned an unsafe package base name")
        target = destination / package.package_base
        command = [
            self.git,
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.ext.allow=never",
            "clone",
            "--depth",
            "1",
            "--",
            f"{self.aur_url.rstrip('/')}/{package.package_base}.git",
            str(target),
        ]
        environment = {
            key: value for key, value in os.environ.items() if not key.startswith("GIT_")
        }
        environment.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AURError(f"could not retrieve {package.package_base}: {exc}") from exc
        if result.returncode != 0:
            detail = (
                result.stderr.strip().splitlines()[-1]
                if result.stderr.strip()
                else "git clone failed"
            )
            raise AURError(f"could not retrieve {package.package_base}: {detail}")
        pkgbuild = target / "PKGBUILD"
        if not (target / ".git").is_dir() or pkgbuild.is_symlink() or not pkgbuild.is_file():
            raise AURError(f"retrieved repository for {package.package_base} is invalid")
        return target


def _validated_service_url(value: str, label: str, *, allow_query_marker: bool = False) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise AURError(f"{label} is not a valid URL") from exc
    has_query_marker = "?" in value
    query_ok = not has_query_marker or (
        allow_query_marker and value.endswith("?") and not parsed.query
    )
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or "#" in value
        or parsed.fragment
        or not query_ok
    ):
        raise AURError(f"{label} is not a safe http(s) endpoint")
    return value.rstrip("/") if not value.endswith("?") else value


def parse_srcinfo_dependencies(path: Path) -> list[str]:
    if path.is_symlink():
        raise AURError("retrieved .SRCINFO is a symlink; refusing to follow it")
    if not path.is_file():
        raise AURError("retrieved repository has no regular .SRCINFO")
    try:
        if path.stat(follow_symlinks=False).st_size > MAX_SRCINFO_SIZE:
            raise AURError("retrieved .SRCINFO exceeds the safe size limit")
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise AURError(f"cannot read retrieved .SRCINFO: {exc}") from exc
    dependencies: list[str] = []
    for line in content.splitlines():
        match = re.match(
            r"\s*(?:depends|makedepends|checkdepends)(?:_[a-z0-9_]+)?\s*=\s*(.+?)\s*$", line
        )
        if match:
            requirement = match.group(1).strip()
            if normalize_target(requirement) and requirement not in dependencies:
                dependencies.append(requirement)
                if len(dependencies) > MAX_DECLARED_DEPENDENCIES:
                    raise AURError("retrieved .SRCINFO declares too many dependencies")
    return dependencies


def dependency_satisfied(name: str) -> bool:
    try:
        return (
            subprocess.run(
                ["pacman", "-T", "--", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0
        )
    except OSError:
        return False


def official_package_exists(name: str) -> bool:
    try:
        return (
            subprocess.run(
                ["pacman", "-Si", "--", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0
        )
    except OSError:
        return False


def official_target_exists(name: str) -> bool:
    if official_package_exists(name):
        return True
    try:
        return (
            subprocess.run(
                ["pacman", "-Sg", "--", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0
        )
    except OSError:
        return False


def resolve_and_retrieve(
    names: list[str],
    destination: Path,
    client: AURClient,
    *,
    dependency_check: Callable[[str], bool] = dependency_satisfied,
    official_check: Callable[[str], bool] = official_package_exists,
) -> list[RetrievedPackage]:
    info = client.info(names)
    missing = [name for name in map(normalize_target, names) if name not in info]
    if missing:
        raise AURError("package not found in AUR: " + ", ".join(missing))
    queue = list(info.values())
    queued_bases = {package.package_base for package in queue}
    by_base: dict[str, RetrievedPackage] = {}
    while queue:
        package = queue.pop(0)
        queued_bases.discard(package.package_base)
        if package.package_base in by_base:
            if package.name not in by_base[package.package_base].requested_names:
                by_base[package.package_base].requested_names.append(package.name)
            continue
        root = client.clone(package, destination)
        retrieved = RetrievedPackage(package, root, [package.name])
        by_base[package.package_base] = retrieved
        for dependency in parse_srcinfo_dependencies(root / ".SRCINFO"):
            dependency_name = normalize_target(dependency)
            if dependency_check(dependency) or official_check(dependency_name):
                continue
            dep_info = client.info([dependency_name]).get(dependency_name)
            if dep_info is None:
                dep_info = client.find_provider(dependency_name)
            if dep_info is None:
                raise AURError(
                    f"cannot resolve AUR dependency {dependency} required by {package.name}"
                )
            if dep_info.package_base not in by_base and dep_info.package_base not in queued_bases:
                if len(by_base) + len(queued_bases) >= MAX_RETRIEVED_PACKAGE_BASES:
                    raise AURError(
                        "AUR dependency graph exceeds the safe retrieval limit of "
                        f"{MAX_RETRIEVED_PACKAGE_BASES} package bases"
                    )
                queue.append(dep_info)
                queued_bases.add(dep_info.package_base)
    return list(by_base.values())
