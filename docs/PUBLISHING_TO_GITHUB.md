# Publishing yaysafe to GitHub

The prepared `yaysafe-public` tree is a fresh Git repository on branch `main`; all intended files
are staged, but there is no commit and no remote. The private working tree and local yaysafe
configuration are not part of it.

## 1. Review the staged publication

```bash
cd /path/to/yaysafe-public
git status
git diff --cached --check
git diff --cached --stat
git diff --cached
```

The full diff is large because this will be the initial commit. Confirm that the staged files do not
contain your API key, LM Studio conversations, private paths, package checkout data, build output, or
anything else you do not want to publish.

## 2. Set your public Git identity

Git commit identity becomes public and is difficult to rewrite after others clone the repository.
Set it for this repository only. Use a GitHub noreply address if you do not want to publish a
personal email:

```bash
git config user.name "YOUR PUBLIC NAME"
git config user.email "YOUR GITHUB NOREPLY ADDRESS"
git config --local --list
```

Check the exact noreply address shown in GitHub **Settings → Emails**; do not guess it.

## 3. Create the initial commit

```bash
git commit -m "Initial experimental release of yaysafe"
git log --show-signature --stat -1
```

Signing the commit is recommended when you already have Git or SSH signing configured. Do not copy
a private signing key into the repository.

## 4. Create the GitHub repository

On GitHub, create a public repository named `yaysafe` under the `dahekker` account. Do not ask
GitHub to add a README, license, or `.gitignore`; all three are already present. Do not create a
release or tag yet.

Then connect and push:

```bash
git remote add origin git@github.com:dahekker/yaysafe.git
git remote -v
git push -u origin main
```

Use the HTTPS remote instead if that is how your Git credentials are configured:

```bash
git remote add origin https://github.com/dahekker/yaysafe.git
```

Use only one `git remote add origin` command.

## 5. Configure the repository before announcing it

In GitHub repository settings:

1. Enable **Private vulnerability reporting** under Security.
2. Enable secret scanning and push protection when the options are available.
3. Confirm Issues are enabled so the supplied issue forms appear.
4. Add the description: `Experimental security review wrapper for yay and AUR packages`.
5. Add topics such as `arch-linux`, `aur`, `yay`, `pkgbuild`, `security`, and `lm-studio`.
6. Protect `main` after the first CI run. Require the Python 3.11 and Python 3.14 CI checks, block
   force pushes, and require the branch to be up to date before merging.

Dependabot will discover the included monthly update configuration after the default branch exists.

## 6. Verify the public result

Wait for the initial CI workflow to finish. Open the README, license, security policy, issue forms,
and Actions log from a logged-out/private browser window. Clone the public repository into a new
temporary directory and run:

```bash
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]' 'build>=1.2,<2'
.venv/bin/python scripts/check_release.py v0.1.0
.venv/bin/python -m pytest
.venv/bin/python -m ruff format --check .
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy yaysafe
```

## 7. Tag only after public review

Leave the project untagged while trusted testers review the initial public commit. Address any
credible reports, update the changelog, and rerun the full validation. When ready, follow
[RELEASING.md](RELEASING.md) to create the annotated `v0.1.0` tag and GitHub pre-release.

Do not submit to the AUR until the tag and release asset are publicly downloadable and the AUR
PKGBUILD uses a real checksum for that immutable release source.
