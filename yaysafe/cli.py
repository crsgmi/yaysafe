from __future__ import annotations

import argparse
import dataclasses
import getpass
import hashlib
import json
import os
import platform
import shlex
import shutil
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from yaysafe import __version__
from yaysafe.aur import AURClient, AURError, RetrievedPackage, resolve_and_retrieve
from yaysafe.cache import ScanCache
from yaysafe.config import (
    Config,
    ConfigError,
    cache_dir,
    config_path,
    edit_config,
    load_config,
    redacted_config_text,
    save_llm_selection,
    select_editor,
)
from yaysafe.llm import LLMClient, LLMError, create_llm_client, unknown_result
from yaysafe.models import LLMResult, Risk, StaticResult, Verdict
from yaysafe.sanitize import sanitize_terminal
from yaysafe.scanner import ScanError, repository_digest, scan_repository
from yaysafe.ui import UI, view_files
from yaysafe.verdict import PolicyAction, combine_results, policy_action
from yaysafe.yay import (
    YayError,
    YayInvocation,
    aur_targets,
    classify_args,
    isolated_yay_environment,
    run_yay,
    with_reviewed_builddir,
    yay_current_config,
    yay_option_value,
)

EXIT_ERROR = 1
EXIT_BLOCKED = 2
EXIT_UNKNOWN = 3
EXIT_CONFIG = 4


@dataclasses.dataclass(frozen=True, slots=True)
class ProviderPreset:
    key: str
    label: str
    base_url: str
    api_key: str
    requires_api_key: bool = False
    cloud: bool = False


PROVIDER_PRESETS = (
    ProviderPreset("lmstudio", "LM Studio (local)", "http://127.0.0.1:1234/v1", "lm-studio"),
    ProviderPreset("ollama", "Ollama (local)", "http://127.0.0.1:11434/v1", "ollama"),
    ProviderPreset(
        "openai",
        "OpenAI",
        "https://api.openai.com/v1",
        "",
        requires_api_key=True,
        cloud=True,
    ),
    ProviderPreset(
        "anthropic",
        "Anthropic",
        "https://api.anthropic.com/v1",
        "",
        requires_api_key=True,
        cloud=True,
    ),
    ProviderPreset(
        "openai-compatible",
        "Custom OpenAI-compatible",
        "http://127.0.0.1:1234/v1",
        "",
    ),
)


def _prompt(ui: UI, text: str) -> str:
    """Read a terminal response and keep redirected output line-oriented."""
    try:
        return input(text)
    finally:
        if not sys.stdin.isatty():
            print(file=ui.out)


def _profile(
    config: Config,
    static: StaticResult,
    *,
    llm_requested: bool,
    model: str,
) -> dict[str, object]:
    return {
        "scanner": "rules-v5-shell-context-hardening",
        "max_file_size": config.scanner.max_file_size,
        "max_total_prompt_size": config.scanner.max_total_prompt_size,
        "max_repository_size": config.scanner.max_repository_size,
        "llm": llm_requested,
        "provider": config.llm.provider if llm_requested else "",
        "base_url": config.llm.base_url if llm_requested else "",
        "api_key_fingerprint": (
            hashlib.sha256(config.llm.api_key.encode("utf-8")).hexdigest() if llm_requested else ""
        ),
        "model": model if llm_requested else "",
        "max_tokens": config.llm.max_tokens if llm_requested else 0,
        "max_prompt_size": config.llm.max_prompt_size if llm_requested else 0,
        "reasoning_effort": config.llm.reasoning_effort if llm_requested else "",
        "prompt": "arch-review-v5-strict-consistency",
        "package": static.metadata.name,
        "package_base": static.metadata.package_base,
        "metadata": static.metadata.to_dict(),
        "skipped_files": static.skipped_files,
    }


def analyze_retrieved(
    retrieved: RetrievedPackage,
    config: Config,
    cache: ScanCache,
    *,
    use_llm: bool,
    use_cache: bool,
    on_llm: Callable[[], None] | None = None,
) -> tuple[Verdict, StaticResult]:
    package_name = (
        retrieved.requested_names[0] if retrieved.requested_names else retrieved.package.name
    )
    static = scan_repository(
        retrieved.root, package_name, config.scanner, package_base=retrieved.package.package_base
    )
    static.metadata.description = retrieved.package.description or static.metadata.description
    static.metadata.url = retrieved.package.url or static.metadata.url
    static.metadata.version = retrieved.package.version or static.metadata.version
    llm_requested = use_llm and config.llm.enabled
    llm_result: LLMResult | None = None
    resolved_model = ""
    llm_client: LLMClient | None = None
    model_error = ""
    if llm_requested:
        if on_llm:
            on_llm()
        llm_client = create_llm_client(dataclasses.replace(config.llm))
        try:
            resolved_model = llm_client.resolve_model()
            llm_client.config.model = resolved_model
        except LLMError as exc:
            model_error = str(exc)
    profile = _profile(
        config,
        static,
        llm_requested=llm_requested,
        model=resolved_model or config.llm.model,
    )
    key = cache.key(static.content_digest, profile)
    if use_cache and not model_error:
        cached = cache.load(key, static.content_digest)
        if cached:
            return cached, static
    if llm_requested:
        assert llm_client is not None
        llm_result = (
            unknown_result(model_error) if model_error else llm_client.analyze(package_name, static)
        )
    verdict = combine_results(package_name, static, llm_result, llm_requested=llm_requested)
    if use_cache and (
        not llm_requested or (llm_result is not None and llm_result.risk != Risk.UNKNOWN)
    ):
        try:
            cache.store(key, static.content_digest, verdict)
        except OSError:
            # Caching is an optimization. A completed fresh analysis remains valid if the
            # cache is unavailable or has unsafe permissions/layout.
            pass
    return verdict, static


def _retrieve_and_analyze(
    names: list[str],
    destination: Path,
    config: Config,
    ui: UI,
    *,
    use_llm: bool,
    use_cache: bool,
    quiet: bool,
    aur_client: AURClient | None = None,
) -> list[tuple[Verdict, StaticResult]]:
    if not quiet:
        ui.section("Retrieving AUR build files...")
    retrieved = resolve_and_retrieve(names, destination, aur_client or AURClient())
    if not quiet:
        ui.section("Running static analysis...")
    cache = ScanCache()
    return [
        analyze_retrieved(
            item,
            config,
            cache,
            use_llm=use_llm,
            use_cache=use_cache,
            on_llm=(lambda: ui.section("Querying LLM...")) if not quiet else None,
        )
        for item in retrieved
    ]


def _confirmation(ui: UI, verdict: Verdict, static: StaticResult) -> bool:
    while True:
        print(file=ui.out)
        ui.section(f"Install {verdict.package} anyway? [y/N/v/e]")
        try:
            answer = _prompt(ui, "==> ").strip().lower()
        except EOFError:
            return False
        if answer in {"y", "yes"}:
            return True
        if answer in {"", "n", "no"}:
            return False
        if answer == "v":
            relevant = [item.path for item in static.files]
            if not view_files(relevant):
                ui.warning("no pager or readable files are available")
        elif answer == "e":
            ui.analysis_details(verdict)
        else:
            ui.warning("enter y, n, v, or e")


def _enforce_policy(
    ui: UI, results: list[tuple[Verdict, StaticResult]], config: Config
) -> int | None:
    for verdict, static in results:
        print(file=ui.out)
        ui.verdict(verdict)
        action = policy_action(verdict.risk, config.policy)
        if action == PolicyAction.BLOCK:
            print(file=ui.out)
            ui.section("Installation blocked by policy.")
            if verdict.risk == Risk.CRITICAL:
                ui.warning(
                    "set policy.block_critical = false only after reviewing the package files"
                )
                return EXIT_BLOCKED
            return EXIT_UNKNOWN
        if action == PolicyAction.CONFIRM:
            if verdict.risk == Risk.MEDIUM:
                ui.section("yaysafe recommends reviewing this package.")
            elif verdict.risk in {Risk.HIGH, Risk.CRITICAL}:
                ui.section("yaysafe recommends aborting this installation.")
            else:
                ui.section("Package safety could not be determined.")
            if not _confirmation(ui, verdict, static):
                return EXIT_UNKNOWN if verdict.risk == Risk.UNKNOWN else EXIT_BLOCKED
    return None


def handle_yay(args: list[str], config: Config, ui: UI) -> int:
    invocation: YayInvocation = classify_args(args)
    if not invocation.install:
        if invocation.targets and not invocation.explicit_operation:
            raise YayError(
                "yay's implicit search/install menu cannot be reviewed safely; use "
                "yaysafe -S <package>"
            )
        return run_yay(args)
    targets = aur_targets(invocation)
    if not targets:
        return run_yay(args)
    yay_options = args[: args.index("--")] if "--" in args else args
    if any(option == "--save" or option.startswith("--save=") for option in yay_options):
        raise AURError(
            "--save cannot be used during a reviewed install because yaysafe isolates yay's "
            "temporary security settings; save yay options in a separate non-install command"
        )
    yay_config = yay_current_config()
    aur_url = yay_option_value(args, "--aururl") or str(
        yay_config.get("aururl", "https://aur.archlinux.org")
    )
    rpc_url = yay_option_value(args, "--aurrpcurl") or str(
        yay_config.get("aurrpcurl", "https://aur.archlinux.org/rpc?")
    )
    aur_client = AURClient(aur_url=aur_url, rpc_url=rpc_url)
    with tempfile.TemporaryDirectory(prefix="yaysafe-build-") as raw_temp:
        workspace = Path(raw_temp)
        builddir = workspace / "packages"
        builddir.mkdir(mode=0o700)
        results = _retrieve_and_analyze(
            targets,
            builddir,
            config,
            ui,
            use_llm=True,
            use_cache=True,
            quiet=False,
            aur_client=aur_client,
        )
        blocked = _enforce_policy(ui, results, config)
        if blocked is not None:
            return blocked
        for _, static in results:
            pkgbuild = next(
                (item.path for item in static.files if item.relative_path == "PKGBUILD"), None
            )
            if (
                pkgbuild is None
                or repository_digest(pkgbuild.parent, config.scanner.max_repository_size)
                != static.content_digest
            ):
                raise ScanError(
                    "reviewed package content changed after analysis; refusing to continue"
                )
        print(file=ui.out)
        ui.section("Security analysis passed.")
        ui.section("Continuing with yay...")
        # Keep the exact reviewed repositories available to yay for this build invocation.
        environment = isolated_yay_environment(yay_config, workspace / "config", str(builddir))
        return run_yay(with_reviewed_builddir(args, str(builddir)), env=environment)


def _scan_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yaysafe scan", description="Retrieve and scan AUR packages without building them"
    )
    parser.add_argument("package", nargs="+", help="AUR package name")
    parser.add_argument(
        "--json", action="store_true", dest="json_output", help="print machine-readable JSON"
    )
    parser.add_argument("--no-llm", action="store_true", help="run deterministic analysis only")
    parser.add_argument(
        "--no-cache", action="store_true", help="ignore and do not write scan cache"
    )
    parser.add_argument("--verbose", "--explain", action="store_true", help="show all findings")
    return parser


def command_scan(args: list[str], config: Config, ui: UI) -> int:
    options = _scan_parser().parse_args(args)
    with tempfile.TemporaryDirectory(prefix="yaysafe-scan-") as raw_temp:
        results = _retrieve_and_analyze(
            options.package,
            Path(raw_temp),
            config,
            ui,
            use_llm=not options.no_llm,
            use_cache=not options.no_cache,
            quiet=options.json_output,
        )
        verdicts = [verdict for verdict, _ in results]
        if options.json_output:
            value: object = (
                verdicts[0].to_dict()
                if len(verdicts) == 1
                else [item.to_dict() for item in verdicts]
            )
            print(json.dumps(value, sort_keys=True, indent=2))
        else:
            for verdict in verdicts:
                print(file=ui.out)
                ui.verdict(verdict, verbose=options.verbose)
    return 0


def _normalize_endpoint(value: str) -> str:
    endpoint = value.strip().rstrip("/")
    try:
        parsed = urlsplit(endpoint)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ConfigError("LLM endpoint is not a valid URL") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ConfigError("LLM endpoint must be an http:// or https:// URL")
    if "?" in endpoint or "#" in endpoint or parsed.query or parsed.fragment:
        raise ConfigError("LLM endpoint must not contain a query string or fragment")
    path = parsed.path.rstrip("/") or "/v1"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def command_config_llm(ui: UI) -> int:
    path = config_path()
    config = load_config(path)
    ui.section("Select LLM provider")
    for index, preset in enumerate(PROVIDER_PRESETS, 1):
        print(f"    {index:<3}{preset.label}", file=ui.out)
    default_provider = next(
        (
            index
            for index, preset in enumerate(PROVIDER_PRESETS, 1)
            if preset.key == config.llm.provider
        ),
        1,
    )
    while True:
        try:
            answer = (
                _prompt(ui, f"\n==> Select provider [{default_provider}] (q to cancel): ")
                .strip()
                .lower()
            )
        except EOFError:
            ui.section("Configuration unchanged.")
            return 0
        if answer in {"q", "quit"}:
            ui.section("Configuration unchanged.")
            return 0
        try:
            provider_index = int(answer) if answer else default_provider
        except ValueError:
            ui.warning(f"enter a number from 1 to {len(PROVIDER_PRESETS)}, or q")
            continue
        if 1 <= provider_index <= len(PROVIDER_PRESETS):
            break
        ui.warning(f"enter a number from 1 to {len(PROVIDER_PRESETS)}, or q")

    preset = PROVIDER_PRESETS[provider_index - 1]
    same_provider = preset.key == config.llm.provider
    endpoint_default = config.llm.base_url if same_provider else preset.base_url
    print(file=ui.out)
    ui.section(f"Configure {preset.label}")
    try:
        entered = _prompt(ui, f"==> Endpoint URL [{endpoint_default}]: ").strip()
    except EOFError:
        ui.section("Configuration unchanged.")
        return 0
    endpoint = _normalize_endpoint(entered or endpoint_default)

    existing_key = config.llm.api_key if same_provider else ""
    api_key = preset.api_key
    if preset.cloud:
        ui.warning(
            "package repository contents will be sent to this provider; usage charges may apply"
        )
    if preset.requires_api_key or preset.key == "openai-compatible":
        keep_existing = bool(existing_key)
        qualifier = " [configured; Enter keeps it]" if keep_existing else ""
        optional = " (optional)" if not preset.requires_api_key else ""
        try:
            entered_key = getpass.getpass(f"==> API key{optional}{qualifier}: ").strip()
        except EOFError:
            ui.section("Configuration unchanged.")
            return 0
        if entered_key == "-" and not preset.requires_api_key:
            api_key = ""
        elif entered_key:
            api_key = entered_key
        elif keep_existing:
            api_key = existing_key
        elif preset.requires_api_key:
            ui.error(f"an API key is required for {preset.label}")
            return EXIT_CONFIG

    probe_config = dataclasses.replace(
        config.llm,
        enabled=True,
        provider=preset.key,
        base_url=endpoint,
        api_key=api_key,
        model="",
        timeout=min(config.llm.timeout, 15.0),
    )
    ui.status("Querying models from", sanitize_terminal(endpoint, max_length=300))
    try:
        models = list(dict.fromkeys(create_llm_client(probe_config).list_models()))
    except LLMError as exc:
        ui.error(str(exc))
        ui.warning("verify the provider URL and credentials, then try again")
        return EXIT_ERROR
    if not models:
        ui.error("the endpoint returned no available models")
        return EXIT_ERROR
    print(file=ui.out)
    ui.section("Available models")
    for index, model in enumerate(models, 1):
        print(f"    {index:<3}{sanitize_terminal(model, max_length=300)}", file=ui.out)
    default_index = (
        models.index(config.llm.model) + 1 if same_provider and config.llm.model in models else 1
    )
    while True:
        try:
            answer = (
                _prompt(ui, f"\n==> Select model [{default_index}] (q to cancel): ").strip().lower()
            )
        except EOFError:
            ui.section("Configuration unchanged.")
            return 0
        if answer in {"q", "quit"}:
            ui.section("Configuration unchanged.")
            return 0
        try:
            selected_index = int(answer) if answer else default_index
        except ValueError:
            ui.warning(f"enter a number from 1 to {len(models)}, or q")
            continue
        if 1 <= selected_index <= len(models):
            break
        ui.warning(f"enter a number from 1 to {len(models)}, or q")
    selected = models[selected_index - 1]
    save_llm_selection(
        endpoint,
        selected,
        path,
        provider=preset.key,
        api_key=api_key,
    )
    print(file=ui.out)
    ui.status("LLM provider:", preset.label)
    ui.status("LLM endpoint:", sanitize_terminal(endpoint, max_length=300))
    ui.status("Selected model:", sanitize_terminal(selected, max_length=300))
    ui.section("LLM configuration saved.")
    return 0


def command_config(args: list[str], ui: UI) -> int:
    action = args[0] if args else "show"
    if len(args) > 1 or action not in {"show", "llm", "edit", "path", "validate"}:
        ui.error("usage: yaysafe config [llm|edit|path|validate]")
        return EXIT_CONFIG
    path = config_path()
    if action == "llm":
        return command_config_llm(ui)
    if action == "edit":
        return edit_config(path)
    if action == "path":
        print(path)
        return 0
    if action == "validate":
        load_config(path)
        ui.status("configuration", "OK")
        return 0
    print(redacted_config_text(path), end="")
    return 0


def command_cache(args: list[str], ui: UI) -> int:
    if args != ["clear"]:
        ui.error("usage: yaysafe cache clear")
        return EXIT_ERROR
    ui.section("Clear all cached scan results? [y/N]")
    try:
        answer = _prompt(ui, "==> ").strip().lower()
    except EOFError:
        answer = ""
    if answer not in {"y", "yes"}:
        ui.section("Cache unchanged.")
        return 0
    count = ScanCache().clear()
    ui.status("Cleared cached scan results:", str(count))
    return 0


def command_doctor(config: Config, ui: UI, *, config_error: str = "") -> int:
    ui.section("yaysafe doctor")
    checks_ok = True

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal checks_ok
        checks_ok = checks_ok and ok
        value = "OK" if ok else "FAILED"
        ui.status(f"{label:<18}", value + (f" ({detail})" if detail else ""))

    yay_available = shutil.which("yay") is not None
    check("yay", yay_available)
    if yay_available:
        try:
            current_yay = yay_current_config()
            check("yay configuration", bool(current_yay))
        except YayError as exc:
            check("yay configuration", False, str(exc))
    check("git", shutil.which("git") is not None)
    check("Python", sys.version_info >= (3, 11), platform.python_version())
    check("configuration", not config_error, config_error)
    if config.llm.enabled:
        health_config = dataclasses.replace(config.llm, timeout=min(config.llm.timeout, 10.0))
        ok, model = create_llm_client(health_config).health()
        ui.status(f"{'LLM provider':<18}", config.llm.provider)
        check("LLM endpoint", ok, "" if ok else model)
        ui.status(f"{'model':<18}", model if ok else "UNKNOWN")
    else:
        ui.status(f"{'LLM endpoint':<18}", "disabled")
    check("editor", select_editor() is not None)
    try:
        target = cache_dir()
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        safe_cache = target.is_dir() and not target.is_symlink()
        if safe_cache:
            target.chmod(0o700)
        check("cache directory", safe_cache and os.access(target, os.W_OK), str(target))
    except OSError as exc:
        check("cache directory", False, str(exc))
    check("dependencies", True, "standard library only")
    check(
        "static scanner",
        config.scanner.enabled,
        "enabled" if config.scanner.enabled else "disabled",
    )
    print(file=ui.out)
    ui.section(
        "yaysafe is ready."
        if checks_ok
        else "Resolve failed checks before installing AUR packages."
    )
    return 0 if checks_ok else EXIT_ERROR


def interactive(config: Config, ui: UI) -> int:
    while True:
        print(f"yaysafe {__version__}\n", file=ui.out)
        ui.section("What would you like to do?")
        print(
            "\n    1  Install package\n    2  Scan package\n    3  Edit configuration\n    4  Configure LLM\n    5  Show configuration\n    6  Doctor\n    7  Clear scan cache\n    q  Quit\n",
            file=ui.out,
        )
        try:
            choice = _prompt(ui, "==> ").strip().lower()
        except EOFError:
            return 0
        if choice in {"q", "quit"}:
            return 0
        if choice in {"1", "2"}:
            try:
                packages = shlex.split(_prompt(ui, ":: Package name(s): ").strip())
            except (EOFError, ValueError):
                packages = []
            if not packages:
                ui.warning("no package name supplied")
                continue
            return (
                handle_yay(["-S", *packages], config, ui)
                if choice == "1"
                else command_scan(packages, config, ui)
            )
        if choice == "3":
            return command_config(["edit"], ui)
        if choice == "4":
            return command_config(["llm"], ui)
        if choice == "5":
            return command_config([], ui)
        if choice == "6":
            return command_doctor(config, ui)
        if choice == "7":
            return command_cache(["clear"], ui)
        ui.warning("choose 1-7 or q")


def _help() -> str:
    return f"""yaysafe {__version__}

Security-focused wrapper around yay.

Usage:
  yaysafe -S PACKAGE...          scan AUR content, then continue with yay
  yaysafe scan PACKAGE [OPTIONS] scan without installing
  yaysafe config [COMMAND]       configure LLM, show, edit, locate, or validate
  yaysafe doctor                 check local readiness
  yaysafe cache clear            clear cached scan results
  yaysafe [YAY ARGUMENTS]        pass compatible operations through to yay

Scan options:
  --json       machine-readable output
  --no-llm     deterministic scanner only
  --no-cache   bypass scan cache
  --verbose    show every finding
"""


def _run(argv: list[str]) -> int:
    if os.geteuid() == 0:
        print(
            "error: yaysafe must not be run as root; yay and makepkg expect an unprivileged user",
            file=sys.stderr,
        )
        return EXIT_ERROR
    if argv in (["-h"], ["--help"]):
        print(_help(), end="")
        return 0
    if argv in (["-V"], ["--version"]):
        print(f"yaysafe {__version__}")
        return 0
    if argv and argv[0] == "config":
        try:
            ui_config = load_config().ui
        except ConfigError:
            ui_config = Config().ui
        return command_config(argv[1:], UI(ui_config))
    if argv == ["doctor"]:
        try:
            doctor_config = load_config()
            config_error = ""
        except ConfigError as exc:
            doctor_config = Config()
            config_error = str(exc)
        return command_doctor(doctor_config, UI(doctor_config.ui), config_error=config_error)
    try:
        config = load_config()
    except ConfigError as exc:
        print(f"error: {sanitize_terminal(exc)}", file=sys.stderr)
        return EXIT_CONFIG
    ui = UI(config.ui)
    if not argv:
        return interactive(config, ui)
    if argv[0] == "scan":
        return command_scan(argv[1:], config, ui)
    if argv[0] == "doctor":
        return command_doctor(config, ui)
    if argv[0] == "cache":
        return command_cache(argv[1:], ui)
    return handle_yay(argv, config, ui)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return _run(list(sys.argv[1:] if argv is None else argv))
    except KeyboardInterrupt:
        print("\n:: Interrupted.", file=sys.stderr)
        return 130
    except ConfigError as exc:
        print(f"error: {sanitize_terminal(exc)}", file=sys.stderr)
        return EXIT_CONFIG
    except (AURError, YayError, ScanError, FileNotFoundError, OSError) as exc:
        print(f"error: {sanitize_terminal(exc)}", file=sys.stderr)
        return EXIT_ERROR
    except SystemExit as exc:
        return int(exc.code or 0)
