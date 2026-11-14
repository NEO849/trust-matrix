# Releasing

`trust-matrix` is published to PyPI through
[PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) — OpenID
Connect, no API token stored anywhere. The `release` workflow
(`.github/workflows/release.yml`) builds the distributions once, publishes them
to PyPI with [PEP 740](https://peps.python.org/pep-0740/) attestations, and
attaches the same artifacts to the GitHub Release.

## One-time setup (maintainer, on PyPI)

Because the project does not exist on PyPI yet, register a **pending** Trusted
Publisher. On <https://pypi.org/manage/account/publishing/> add a GitHub
publisher with exactly these values:

| Field | Value |
| --- | --- |
| PyPI Project Name | `trust-matrix` |
| Owner | `NEO849` |
| Repository name | `trust-matrix` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

Requires 2FA enabled on the PyPI account. No token is created or copied.

## Cutting a release

1. Make sure `version` in `pyproject.toml` is the version you intend to ship.
2. Publish a GitHub Release whose tag is that version (e.g. `v0.1.0`). Publishing
   the Release triggers the workflow.
3. The workflow builds, publishes to PyPI, and uploads the artifacts to the
   Release. Watch it under the repository's **Actions** tab.

After the first successful publish the pending publisher becomes a normal one;
no further PyPI configuration is needed for later releases.
