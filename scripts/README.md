# Scripts

Utility scripts for mcp-pvp development and release management.

## Version Management

### bump_version.py

Automated version bumping script that updates version in all source files.

**Usage:**

```bash
# Bump to specific version
python scripts/bump_version.py 0.5.0

# Or use make commands
make bump-major   # 0.4.0 -> 1.0.0
make bump-minor   # 0.4.0 -> 0.5.0
make bump-patch   # 0.4.0 -> 0.4.1

# Or specify exact version with make
make bump-version VERSION=0.5.0
```

**What it updates:**

The script updates the version in exactly **2 files**:
- `pyproject.toml` - Package metadata
- `src/mcp_pvp/__init__.py` - `__version__` variable

**Dynamic version usage:**

All other files (examples, docs, etc.) should import `__version__` dynamically:

```python
from mcp_pvp import __version__

print(f"Running mcp-pvp v{__version__}")
```

This ensures a single source of truth for versioning.

**Release workflow:**

```bash
# 1. Bump version
make bump-minor  # or bump-major/bump-patch

# 2. Update CHANGELOG.md
# Add release notes for the new version

# 3. Commit changes
git add -A
git commit -m "Bump version to v0.5.0"

# 4. Create tag
git tag -a v0.5.0 -m "Release v0.5.0"

# 5. Push to GitHub
git push && git push --tags

# GitHub Actions will automatically:
# - Run tests
# - Build packages
# - Publish to PyPI
```

## Version Locations

### Source files (updated by script):
- ✅ `pyproject.toml` - Package version
- ✅ `src/mcp_pvp/__init__.py` - `__version__` variable

### Files using dynamic imports:
- ✅ `examples/observability/production_config.py` - Imports `__version__`
- ✅ `examples/observability/dev_config.py` - Imports `__version__`
- ✅ `src/mcp_pvp/observability.py` - Imports from `__init__.py`

### Documentation (manual updates needed):
- ⚠️ `CHANGELOG.md` - Update manually with release notes
- ⚠️ `docs/*.md` - Update examples if they reference specific versions
- ⚠️ `README.md` - Usually doesn't need version updates

### Version display in runtime:

```python
# Any Python code can access version
from mcp_pvp import __version__
print(__version__)  # e.g., "0.4.0"

# Or via make
make version  # Prints: 0.4.0
```

## Best Practices

1. **Single source of truth**: Version is defined in `__init__.py` and `pyproject.toml` only
2. **Dynamic imports**: All runtime code imports `__version__` instead of hardcoding
3. **Semantic versioning**: Follow [semver](https://semver.org/)
   - MAJOR: Breaking changes
   - MINOR: New features (backward compatible)
   - PATCH: Bug fixes (backward compatible)
4. **CHANGELOG**: Always update before tagging release
5. **Git tags**: Always prefix with `v` (e.g., `v0.4.0`)
