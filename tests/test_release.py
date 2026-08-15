import re
import tomllib
from pathlib import Path

import pytest

from scripts.check_release import project_versions, validate_release


def test_release_versions_are_aligned() -> None:
    versions = project_versions()
    assert versions == {
        "pyproject.toml": "0.1.0",
        "yaysafe/__init__.py": "0.1.0",
        "PKGBUILD": "0.1.0",
    }
    assert validate_release("v0.1.0") == "0.1.0"


def test_release_tag_mismatch_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "yaysafe").mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "yaysafe"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    (tmp_path / "yaysafe/__init__.py").write_text('__version__ = "0.1.0"\n')
    (tmp_path / "PKGBUILD").write_text("pkgver=0.1.0\n")

    with pytest.raises(ValueError, match="does not match"):
        validate_release("v0.2.0", tmp_path)


def test_public_metadata_is_transparently_experimental() -> None:
    root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    classifiers = pyproject["project"]["classifiers"]
    readme = (root / "README.md").read_text(encoding="utf-8").lower()

    assert "Development Status :: 4 - Beta" in classifiers
    assert all("Production/Stable" not in item for item in classifiers)
    assert "substantial assistance from coding models" in readme
    assert "independent security audit" in readme
    security = (root / "SECURITY.md").read_text(encoding="utf-8").lower()
    assert "private vulnerability reporting" in security


def test_github_actions_are_pinned_to_commits() -> None:
    root = Path(__file__).resolve().parents[1]
    workflows = list((root / ".github/workflows").glob("*.yml"))
    assert workflows
    uses_pattern = re.compile(r"^\s*-?\s*uses:\s*[^@\s]+@([^\s#]+)", re.MULTILINE)
    for workflow in workflows:
        references = uses_pattern.findall(workflow.read_text(encoding="utf-8"))
        assert references
        assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in references)
