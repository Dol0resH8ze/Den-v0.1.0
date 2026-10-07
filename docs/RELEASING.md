# Publishing Den 0.2.0

Distribution name: `den-terminal`. Import and command: `den`.
This release is experimental/Alpha, not an audited security product.

## Accounts (one-time setup)

Create separate accounts on https://test.pypi.org/account/register/ and
https://pypi.org/account/register/. Verify the email address and configure
two-factor authentication on each account. Do not put credentials in this
repository, issue comments, shell commands, or chat.

For manual uploading, create an API token from each site's account settings.
For the very first upload of a new project, a project-scoped token is not yet
available; use the necessary account scope and replace it with a project-scoped
token after the project exists. TestPyPI and PyPI tokens are different. Paste
the appropriate token only at Twine's hidden interactive prompt.

An alternative for future releases is GitHub Actions Trusted Publishing, which
avoids a long-lived upload token. This repository does not automatically publish
on a commit or tag.

## Build and validate

Run these PowerShell commands from the project directory:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev,release]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m build --outdir dist/pypi
.\.venv\Scripts\python.exe -m twine check --strict dist/pypi/den_terminal-0.2.0-py3-none-any.whl dist/pypi/den_terminal-0.2.0.tar.gz
```

Inspect the wheel and source distribution. Only intended package files,
documentation, tests, examples and metadata belong in them. Private Tor keys,
environments, logs, caches, and obsolete `hush` source must not be included.
Check that the package version and `den.__version__` match.

Use the exact two filenames below for uploads. Old source ZIPs in `dist/` are
not PyPI release distributions; do not upload everything under `dist/`.

## TestPyPI first

```powershell
.\.venv\Scripts\python.exe -m twine upload --repository testpypi --username __token__ dist/pypi/den_terminal-0.2.0-py3-none-any.whl dist/pypi/den_terminal-0.2.0.tar.gz
```

Paste the **TestPyPI** token when prompted. A successful upload appears at
https://test.pypi.org/project/den-terminal/0.2.0/ . A 404 name lookup before the
first upload does not reserve the name or guarantee PyPI will accept it.

Test in a new environment. Install dependencies from normal PyPI, then fetch
only Den from TestPyPI so dependencies are not resolved across mixed indexes:

```powershell
py -3 -m venv .venv-release-check
.\.venv-release-check\Scripts\python.exe -I -m pip install PyNaCl==1.6.2 "python-socks[asyncio]==2.8.1" prompt-toolkit==3.0.52
.\.venv-release-check\Scripts\python.exe -I -m pip install --no-deps --index-url https://test.pypi.org/simple/ den-terminal==0.2.0
.\.venv-release-check\Scripts\python.exe -I -m den --version
.\.venv-release-check\Scripts\python.exe -I -m den demo
.\.venv-release-check\Scripts\python.exe -m pip check
```

`-I` prevents a local checkout or PYTHONPATH from masking a broken installation.
Use a different fresh environment if `.venv-release-check` already contains Den.
If isolated Python cannot import `encodings`, repair or install a complete Python
3.12+ runtime and recreate the environment; this is a Python installation issue.
Do not remove isolation just to make the release check pass.

## Publish the same artifacts to PyPI

After TestPyPI installation succeeds, upload those same two validated files:

```powershell
.\.venv\Scripts\python.exe -m twine upload --username __token__ dist/pypi/den_terminal-0.2.0-py3-none-any.whl dist/pypi/den_terminal-0.2.0.tar.gz
```

Paste the **PyPI** token at the hidden prompt. Verify the page at
https://pypi.org/project/den-terminal/0.2.0/ and test a clean
`python -m pip install den-terminal==0.2.0` installation.

PyPI releases are immutable: uploaded filenames cannot be overwritten. If a
published release needs correction, update the version in `pyproject.toml` and
`den/__init__.py`, rebuild into a fresh release directory, and validate again.
Do not repeatedly rebuild version 0.2.0 and expect PyPI to replace it.

## Primary references

- https://packaging.python.org/en/latest/tutorials/packaging-projects/
- https://packaging.python.org/en/latest/guides/using-testpypi/
- https://pypi.org/help/#apitoken
- https://docs.pypi.org/trusted-publishers/

