#!/usr/bin/env bash

set -Eeuo pipefail

say() {
    printf '%s\n' "$*"
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: ./install.sh

Install yaysafe from this source checkout for the current user.
The installer prefers pipx and otherwise uses an isolated user virtual environment.
EOF
}

if (( $# > 1 )); then
    usage >&2
    exit 2
fi
if (( $# == 1 )); then
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
fi

if (( EUID == 0 )); then
    fail "do not install or run yaysafe as root"
fi

user_home="${HOME:-}"
[[ "$user_home" == /* ]] || fail "HOME must be an absolute path"

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -f "$project_dir/pyproject.toml" ]] || fail "pyproject.toml not found beside install.sh"

python_cmd=""
for candidate in python3 python; do
    if type -P "$candidate" >/dev/null 2>&1; then
        python_cmd="$(type -P "$candidate")"
        break
    fi
done
[[ -n "$python_cmd" ]] || fail "Python 3.11 or newer is required"

if ! "$python_cmd" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
    fail "Python 3.11 or newer is required"
fi

say ":: Installing yaysafe..."

pipx_cmd="$(type -P pipx 2>/dev/null || true)"
if [[ -n "$pipx_cmd" ]]; then
    "$pipx_cmd" install --force "$project_dir"
elif "$python_cmd" -m pipx --version >/dev/null 2>&1; then
    "$python_cmd" -m pipx install --force "$project_dir"
else
    data_root="${XDG_DATA_HOME:-$user_home/.local/share}"
    if [[ "$data_root" != /* ]]; then
        data_root="$user_home/.local/share"
    fi
    install_root="$data_root/yaysafe"
    venv_dir="$install_root/venv"
    bin_dir="$user_home/.local/bin"
    command_path="$bin_dir/yaysafe"

    [[ ! -L "$install_root" ]] || fail "refusing to use symlinked directory: $install_root"
    install -d -m 700 "$install_root"
    install -d -m 755 "$bin_dir"

    if [[ -e "$command_path" || -L "$command_path" ]]; then
        existing_target="$(readlink -f -- "$command_path" 2>/dev/null || true)"
        expected_target="$(readlink -f -- "$venv_dir/bin/yaysafe" 2>/dev/null || true)"
        if [[ -z "$expected_target" || "$existing_target" != "$expected_target" ]]; then
            fail "refusing to replace existing command: $command_path"
        fi
    fi

    if [[ ! -x "$venv_dir/bin/python" ]]; then
        "$python_cmd" -m venv "$venv_dir" || fail "could not create a virtual environment"
    fi
    "$venv_dir/bin/python" -m pip install --upgrade "$project_dir"
    ln -sfn -- "$venv_dir/bin/yaysafe" "$command_path"
fi

hash -r
if command -v yaysafe >/dev/null 2>&1; then
    say
    yaysafe --version
    say ":: Installation complete. Run: yaysafe doctor"
elif [[ -x "$user_home/.local/bin/yaysafe" ]]; then
    say
    "$user_home/.local/bin/yaysafe" --version
    say ":: Installation complete. Add $user_home/.local/bin to PATH, then run: yaysafe doctor"
else
    fail "installation finished, but the yaysafe command could not be located"
fi

if ! command -v yay >/dev/null 2>&1; then
    say "warning: yay is not installed or not on PATH; it is required for AUR installation"
fi
if ! command -v git >/dev/null 2>&1; then
    say "warning: git is not installed or not on PATH; it is required by yaysafe"
fi
