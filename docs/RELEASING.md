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

## Automated Release (Recommended)

The release script handles the entire flow in one command:

```bash
# One-command release
make auto-release-patch   # bump patch, check, commit, tag, push
make auto-release-minor   # bump minor, check, commit, tag, push
make auto-release-major   # bump major, check, commit, tag, push

# Or run the script directly for more options
./scripts/release.sh patch
./scripts/release.sh minor
./scripts/release.sh 0.8.0          # explicit version
./scripts/release.sh patch --dry-run # preview without changes
./scripts/release.sh patch --no-push # stop after tagging
```

### What the script does

1. **Preflight checks** — verifies you're on `main`, no uncommitted changes, up to date with remote
2. **Bumps the version** — updates `pyproject.toml` and `src/mcp_pvp/__init__.py`
3. **Updates CHANGELOG.md** — moves `[Unreleased]` entries into a dated version section (warns if empty)
4. **Runs all checks** — lint, format, typecheck, security, tests (`make check`)
5. **Commits** — `git add -A && git commit -m "Release vX.Y.Z"`
6. **Tags** — `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
7. **Pushes** — pushes commit and tag to origin (asks for confirmation)

### Before you run it

Add your changes under `[Unreleased]` in `CHANGELOG.md`:

```markdown
## [Unreleased]
### Added
- New feature description

### Fixed
- Bug fix description
```

> **Tip:** The GitHub Actions release workflow extracts the changelog section matching the tag version to populate the GitHub Release body. Make sure entries are under `[Unreleased]` before running the script.

### Dry run

Preview what would happen without making any changes:

```bash
make auto-release-dry BUMP=patch
```

---

## Manual Release (Step-by-Step)

If you prefer to run each step individually:

### 1. Bump the version

```bash
make bump-patch   # 0.6.0 → 0.6.1
make bump-minor   # 0.6.0 → 0.7.0
make bump-major   # 0.6.0 → 1.0.0
```

### 2. Update CHANGELOG.md

Move `[Unreleased]` entries into a new version section with today's date.

### 3. Run all checks

```bash
make check
```

### 4. Commit, tag, push

```bash
git add -A
git commit -m "Release v0.7.0"
make release VERSION=0.7.0
git push origin main
git push origin v0.7.0
```

---

## GitHub Actions takes over

Pushing the tag triggers the [release workflow](../.github/workflows/release.yml), which automatically:

1. **Validates** — verifies the tag version matches `__version__`, runs tests, lint, and type checks
2. **Builds** — creates sdist and wheel distributions, checks them with `twine`
3. **Releases** — creates a GitHub Release with changelog notes and build artifacts
4. **Publishes to PyPI** *(when enabled)* — publishes via trusted publishing (OIDC)

> **Note:** PyPI publishing is currently disabled (`PUBLISH_PYPI: 'false'` in the workflow). Set it to `'true'` and configure [PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/) when ready to publish publicly.

## Quick Reference

| Action | Command |
|--------|---------|
| **Full automated release** | `make auto-release-patch` / `minor` / `major` |
| Dry run | `make auto-release-dry BUMP=patch` |
| Script with options | `./scripts/release.sh patch --no-push` |
| Check current version | `make version` |
| Run all checks | `make check` |
| Bump version only | `make bump-patch` / `bump-minor` / `bump-major` |
| Create tag only | `make release VERSION=X.Y.Z` |
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

Check the [Actions tab](https://github.com/hidet-io/mcp-pvp/actions) for details. Common issues:
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
