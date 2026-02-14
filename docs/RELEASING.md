# Releasing mcp-pvp

This guide covers the complete process for bumping the version and creating a release.

## Overview

mcp-pvp uses [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`

- **PATCH** (0.6.0 → 0.6.1): Bug fixes, documentation updates
- **MINOR** (0.6.0 → 0.7.0): New features, backward-compatible changes
- **MAJOR** (0.6.0 → 1.0.0): Breaking API changes

The version is defined in two files (kept in sync by the bump script):
- `pyproject.toml` — package metadata
- `src/mcp_pvp/__init__.py` — runtime `__version__`

## Prerequisites

```bash
cd mcp-pvp
make install-dev
```

Ensure all checks pass before releasing:

```bash
make check   # runs lint, format-check, typecheck, security, test
```

## Step-by-Step Release

### 1. Bump the version

Use one of the following:

```bash
# Automatic bump
make bump-patch   # 0.6.0 → 0.6.1
make bump-minor   # 0.6.0 → 0.7.0
make bump-major   # 0.6.0 → 1.0.0

# Or set an explicit version
make bump-version VERSION=0.7.0
```

This updates `pyproject.toml` and `src/mcp_pvp/__init__.py`.

### 2. Update CHANGELOG.md

Move items from `[Unreleased]` into a new version section with today's date:

```markdown
## [Unreleased]

## [0.7.0] - 2026-02-14
### Added
- New feature description

### Fixed
- Bug fix description

### Changed
- Breaking change or behavioral change
```

> **Tip:** The GitHub Actions release workflow extracts the changelog section matching the tag version to populate the GitHub Release body. Make sure the heading format is exactly `## [X.Y.Z]`.

### 3. Verify the version

```bash
make version  # prints the current version from __init__.py
```

### 4. Run all checks

```bash
make check
```

This runs `lint`, `format-check`, `typecheck`, `security`, and `test` in sequence. All must pass.

### 5. Commit the version bump

```bash
git add -A
git commit -m "Release v0.7.0"
```

### 6. Create a git tag

```bash
make release VERSION=0.7.0
```

This will:
- Verify there are no uncommitted changes
- Create an annotated tag `v0.7.0`

Alternatively, tag manually:

```bash
git tag -a v0.7.0 -m "Release v0.7.0"
```

### 7. Push to GitHub

```bash
git push origin main
git push origin v0.7.0
```

### 8. GitHub Actions takes over

Pushing the tag triggers the [release workflow](../.github/workflows/release.yml), which automatically:

1. **Validates** — verifies the tag version matches `__version__`, runs tests, lint, and type checks
2. **Builds** — creates sdist and wheel distributions, checks them with `twine`
3. **Releases** — creates a GitHub Release with changelog notes and build artifacts
4. **Publishes to PyPI** *(when enabled)* — publishes via trusted publishing (OIDC)

> **Note:** PyPI publishing is currently disabled (`PUBLISH_PYPI: 'false'` in the workflow). Set it to `'true'` and configure [PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/) when ready to publish publicly.

## Quick Reference

| Step | Command |
|------|---------|
| Check current version | `make version` |
| Run all checks | `make check` |
| Bump patch version | `make bump-patch` |
| Bump minor version | `make bump-minor` |
| Bump major version | `make bump-major` |
| Set explicit version | `make bump-version VERSION=X.Y.Z` |
| Create release tag | `make release VERSION=X.Y.Z` |
| Build locally | `make build` |

## Troubleshooting

### Tag version doesn't match package version

The release workflow validates that the git tag matches `__version__`. If they diverge:

```bash
make version                      # check current __version__
git tag -l 'v*' --sort=-v:refname # check existing tags
```

Fix by bumping to the correct version and re-tagging.

### Release workflow fails

Check the [Actions tab](https://github.com/Spidux-ai/mcp-pvp/actions) for details. Common issues:
- Test failures — fix and re-release with a new patch version
- Lint/type errors — run `make lint-fix && make format` locally, commit, re-tag
- Version mismatch — ensure `make bump-version` was run before tagging

### Need to redo a release

```bash
# Delete the local and remote tag
git tag -d v0.7.0
git push origin :refs/tags/v0.7.0

# Fix the issue, then re-tag and push
git tag -a v0.7.0 -m "Release v0.7.0"
git push origin v0.7.0
```

> **Warning:** Never re-tag a version that has already been published to PyPI. Bump to a new patch version instead.
