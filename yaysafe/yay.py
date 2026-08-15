from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from yaysafe.aur import normalize_target, official_target_exists

OPTIONS_WITH_VALUE = {
    "--arch",
    "--assume-installed",
    "--aururl",
    "--aurrpcurl",
    "--builddir",
    "--cachedir",
    "--color",
    "--config",
    "--dbpath",
    "--editor",
    "--editorflags",
    "--gpg",
    "--gpgdir",
    "--gpgflags",
    "--hookdir",
    "--ignore",
    "--ignoregroup",
    "--logfile",
    "--makepkg",
    "--makepkgconf",
    "--mflags",
    "--overwrite",
    "--pacman",
    "--print-format",
    "--root",
    "--searchby",
    "--sortby",
    "--sudo",
    "--sudoflags",
    "--sysroot",
}
SHORT_OPTIONS_WITH_VALUE = {"-b", "-r"}


class YayError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class YayInvocation:
    args: list[str]
    sync: bool
    install: bool
    sysupgrade: bool
    targets: list[str]
    explicit_operation: bool


def classify_args(args: list[str]) -> YayInvocation:
    sync = False
    sysupgrade = False
    non_install_sync = False
    explicit_operation = False
    targets: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in OPTIONS_WITH_VALUE:
            skip_next = True
            continue
        if arg in SHORT_OPTIONS_WITH_VALUE:
            skip_next = True
            continue
        if any(arg.startswith(option) and arg != option for option in SHORT_OPTIONS_WITH_VALUE):
            continue
        if any(arg.startswith(option + "=") for option in OPTIONS_WITH_VALUE):
            continue
        if arg == "--sync" or (arg.startswith("-") and not arg.startswith("--") and "S" in arg[1:]):
            sync = True
        if arg in {
            "--build",
            "--database",
            "--deptest",
            "--files",
            "--getpkgbuild",
            "--query",
            "--remove",
            "--show",
            "--sync",
            "--upgrade",
            "--web",
            "--yay",
        } or (
            arg.startswith("-")
            and not arg.startswith("--")
            and any(flag in arg[1:] for flag in "BDFGQRSTUWY")
        ):
            explicit_operation = True
        if arg == "--sysupgrade" or (
            arg.startswith("-") and not arg.startswith("--") and "u" in arg[1:]
        ):
            sysupgrade = True
        if arg in {
            "--search",
            "--info",
            "--list",
            "--groups",
            "--clean",
            "--print",
        }:
            non_install_sync = True
        if (
            arg.startswith("-")
            and not arg.startswith("--")
            and any(flag in arg[1:] for flag in "silgcp")
        ):
            non_install_sync = True
        if not arg.startswith("-"):
            targets.append(arg)
    install = sync and not non_install_sync and (bool(targets) or sysupgrade)
    return YayInvocation(list(args), sync, install, sysupgrade, targets, explicit_operation)


def aur_targets(invocation: YayInvocation) -> list[str]:
    candidates: list[str] = []
    for target in invocation.targets:
        if target.startswith(("core/", "extra/", "multilib/")):
            continue
        name = normalize_target(target)
        if target.startswith("aur/") or not official_target_exists(name):
            candidates.append(name)
    if invocation.sysupgrade:
        candidates.extend(aur_upgrades())
    return list(dict.fromkeys(candidates))


def aur_upgrades() -> list[str]:
    if not shutil.which("yay"):
        raise FileNotFoundError("yay is not installed")
    try:
        result = subprocess.run(
            ["yay", "-Qua", "--quiet", "--color=never"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise YayError(f"could not determine pending AUR upgrades: {exc}") from exc
    if result.returncode not in (0, 1):
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "yay failed"
        raise YayError(f"could not determine pending AUR upgrades: {detail}")
    return [line.strip().split()[0] for line in result.stdout.splitlines() if line.strip()]


def run_yay(args: list[str], *, env: dict[str, str] | None = None) -> int:
    if not shutil.which("yay"):
        raise FileNotFoundError("yay is not installed")
    return subprocess.run(["yay", *args], check=False, env=env).returncode


def yay_current_config() -> dict[str, Any]:
    if not shutil.which("yay"):
        raise FileNotFoundError("yay is not installed")
    try:
        result = subprocess.run(
            ["yay", "-P", "--currentconfig", "--color=never"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise YayError(f"could not read yay configuration: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "yay failed"
        raise YayError(f"could not read yay configuration: {detail}")
    try:
        config = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise YayError("yay returned malformed configuration JSON") from exc
    if not isinstance(config, dict):
        raise YayError("yay returned an invalid configuration value")
    return config


def yay_option_value(args: list[str], option: str) -> str | None:
    before_separator = args[: args.index("--")] if "--" in args else args
    value: str | None = None
    index = 0
    while index < len(before_separator):
        argument = before_separator[index]
        if argument == option and index + 1 < len(before_separator):
            value = before_separator[index + 1]
            index += 2
            continue
        if argument.startswith(option + "="):
            value = argument.split("=", 1)[1]
        index += 1
    return value


def isolated_yay_environment(
    config: dict[str, Any], config_root: Path, builddir: str
) -> dict[str, str]:
    """Snapshot effective yay options without loading mutation-capable Lua hooks."""
    yay_directory = config_root / "yay"
    yay_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    git_binary = shutil.which("git")
    if not git_binary:
        raise FileNotFoundError("git is not installed")
    git_wrapper = config_root / "git-wrapper"
    wrapper_source = f"""#!{sys.executable}
import os
import sys

environment = {{key: value for key, value in os.environ.items() if not key.startswith("GIT_")}}
environment.update({{
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_TERMINAL_PROMPT": "0",
}})
git = {git_binary!r}
blocked = {{"clone", "fetch", "pull", "submodule"}}
if any(argument in blocked for argument in sys.argv[1:]):
    print("yaysafe: yay attempted to retrieve unreviewed Git content; aborting", file=sys.stderr)
    raise SystemExit(78)
if any(argument in {{"clean", "merge", "reset"}} for argument in sys.argv[1:]):
    # The worktree is a fresh, digest-verified clone. Yay normally normalizes/cleans its cache
    # here, but this per-invocation directory has nothing stale to normalize.
    raise SystemExit(0)
os.execve(git, [git, "-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null",
                  "-c", "protocol.ext.allow=never", *sys.argv[1:]], environment)
"""
    git_wrapper.write_text(wrapper_source, encoding="utf-8")
    git_wrapper.chmod(0o700)
    snapshot = dict(config)
    snapshot.update(
        {
            "buildDir": builddir,
            "redownload": "no",
            "editmenu": False,
            "answeredit": "",
            "debug": False,
            "gitbin": str(git_wrapper),
            "gitflags": "",
        }
    )
    config_path = yay_directory / "config.json"
    config_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    config_path.chmod(0o600)
    lua_path = yay_directory / "init.lua"
    lua_path.write_text(
        "-- yaysafe: intentionally empty; mutation hooks are disabled\n", encoding="utf-8"
    )
    lua_path.chmod(0o600)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment["XDG_CONFIG_HOME"] = str(config_root)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def with_reviewed_builddir(args: list[str], builddir: str) -> list[str]:
    before_separator, separator_and_targets = (
        (args[: args.index("--")], args[args.index("--") :]) if "--" in args else (args, [])
    )
    controlled: list[str] = []
    skip_next = False
    for arg in before_separator:
        if skip_next:
            skip_next = False
            continue
        if arg == "--builddir":
            skip_next = True
            continue
        if arg.startswith(
            (
                "--builddir=",
                "--debug=",
                "--editmenu=",
                "--noredownload=",
                "--redownload=",
                "--redownloadall=",
            )
        ) or arg in {
            "--debug",
            "--editmenu",
            "--noredownload",
            "--redownload",
            "--redownloadall",
        }:
            continue
        controlled.append(arg)
    security_args = [
        "--builddir",
        builddir,
        "--noredownload",
        "--editmenu=false",
        "--debug=false",
    ]
    return [*controlled, *security_args, *separator_and_targets]
