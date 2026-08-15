# Releasing yaysafe

This procedure is intentionally manual. A tag does not publish to GitHub, PyPI, or the AUR by
itself.

The intended sequence is: initial GitHub publication, CI and public review, the `v0.1.0` tag, a
GitHub release, an immutable source checksum, an updated PKGBUILD and `.SRCINFO`, package testing,
and only then possible AUR publication.

## Prepare

1. Confirm `CHANGELOG.md` describes the release and has the correct date.
2. Set the same version in `pyproject.toml`, `yaysafe/__init__.py`, and `PKGBUILD`.
3. Set `pkgrel=1` for a new upstream version.
4. Run the complete local verification:

   ```bash
   python scripts/check_release.py
   python -m ruff format --check .
   python -m ruff check .
   python -m mypy yaysafe
   python -m pytest
   python -m build
   bash -n PKGBUILD
   makepkg --printsrcinfo
   ```

5. Review the staged Git diff and verify that no config, cache, API key, model transcript, generated
   artifact, or hostile temporary repository is included.

## Tag and publish on GitHub

Create an annotated tag only after CI passes on the release commit:

```bash
git tag -a v0.1.0 -m 'yaysafe 0.1.0'
git push origin main
git push origin v0.1.0
```

The tag CI run validates version alignment and retains the built wheel and source distribution as a
workflow artifact. Download those artifacts, verify their hashes, then create a GitHub pre-release
named `v0.1.0`. Attach the wheel and source distribution and use the matching changelog section as
release notes.

## Prepare the AUR package

Do not submit the upstream working tree directly as the AUR Git repository. Clone the empty AUR
package repository separately and commit only its packaging files, normally `PKGBUILD` and generated
`.SRCINFO`.

Before the first AUR submission, replace the Git-tag source and `SKIP` checksum in `PKGBUILD` with a
stable published release asset and its real SHA-256 or BLAKE2 checksum. Build in a clean Arch chroot,
add a maintainer identity you have intentionally chosen for publication, regenerate `.SRCINFO`, run
`namcap` when available, and request public packaging review if uncertain.

Never reuse the upstream Git history as the AUR package repository, and never push generated
packages, source trees, local config, or signing keys.
