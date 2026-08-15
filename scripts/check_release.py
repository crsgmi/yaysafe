from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_PATTERN = re.compile(r"^__version__\s*=\s*[\"']([^\"']+)[\"']\s*$", re.MULTILINE)
PKGVER_PATTERN = re.compile(r"^pkgver=([^\s#]+)\s*$", re.MULTILINE)


def project_versions(root: Path = ROOT) -> dict[str, str]:
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    init_text = (root / "yaysafe/__init__.py").read_text(encoding="utf-8")
    pkgbuild_text = (root / "PKGBUILD").read_text(encoding="utf-8")
    init_match = VERSION_PATTERN.search(init_text)
    pkgbuild_match = PKGVER_PATTERN.search(pkgbuild_text)
    if init_match is None or pkgbuild_match is None:
        raise ValueError("could not read every project version")
    return {
        "pyproject.toml": str(pyproject["project"]["version"]),
        "yaysafe/__init__.py": init_match.group(1),
        "PKGBUILD": pkgbuild_match.group(1),
    }


def validate_release(tag: str = "", root: Path = ROOT) -> str:
    versions = project_versions(root)
    unique = set(versions.values())
    if len(unique) != 1:
        detail = ", ".join(f"{name}={version}" for name, version in versions.items())
        raise ValueError(f"project versions do not match: {detail}")
    version = unique.pop()
    if tag and tag.removeprefix("v") != version:
        raise ValueError(f"tag {tag!r} does not match project version {version!r}")
    return version


def main() -> int:
    parser = argparse.ArgumentParser(description="validate yaysafe release version alignment")
    parser.add_argument("tag", nargs="?", default="", help="optional Git tag, such as v0.1.1")
    args = parser.parse_args()
    try:
        version = validate_release(args.tag)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    print(f"release metadata OK: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
