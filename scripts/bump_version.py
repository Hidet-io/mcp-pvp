#!/usr/bin/env python3
"""Version bumping script for mcp-pvp.

This script updates the version number in both source files:
- pyproject.toml
- src/mcp_pvp/__init__.py

All other files (examples, docs) should import __version__ dynamically.

Usage:
    python scripts/bump_version.py 0.4.0
    python scripts/bump_version.py --major  # 0.3.0 -> 1.0.0
    python scripts/bump_version.py --minor  # 0.3.0 -> 0.4.0
    python scripts/bump_version.py --patch  # 0.3.0 -> 0.3.1
"""

import argparse
import re
import sys
from pathlib import Path


def get_current_version() -> str:
    """Get current version from __init__.py."""
    init_file = Path("src/mcp_pvp/__init__.py")
    content = init_file.read_text()
    match = re.search(r'__version__ = "(\d+\.\d+\.\d+)"', content)
    if not match:
        raise ValueError("Could not find __version__ in __init__.py")
    return match.group(1)


def parse_version(version: str) -> tuple[int, int, int]:
    """Parse version string into (major, minor, patch)."""
    parts = version.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid version format: {version}")
    return int(parts[0]), int(parts[1]), int(parts[2])


def format_version(major: int, minor: int, patch: int) -> str:
    """Format version tuple as string."""
    return f"{major}.{minor}.{patch}"


def bump_version(current: str, bump_type: str) -> str:
    """Bump version based on type (major/minor/patch)."""
    major, minor, patch = parse_version(current)

    if bump_type == "major":
        return format_version(major + 1, 0, 0)
    elif bump_type == "minor":
        return format_version(major, minor + 1, 0)
    elif bump_type == "patch":
        return format_version(major, minor, patch + 1)
    else:
        raise ValueError(f"Invalid bump type: {bump_type}")


def update_file(file_path: Path, old_version: str, new_version: str) -> bool:
    """Update version in a file. Returns True if changed."""
    content = file_path.read_text()
    new_content = content.replace(f'"{old_version}"', f'"{new_version}"')

    if new_content != content:
        file_path.write_text(new_content)
        return True
    return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Bump mcp-pvp version")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("version", nargs="?", help="New version (e.g., 0.4.0)")
    group.add_argument("--major", action="store_true", help="Bump major version")
    group.add_argument("--minor", action="store_true", help="Bump minor version")
    group.add_argument("--patch", action="store_true", help="Bump patch version")

    args = parser.parse_args()

    # Get current version
    try:
        current_version = get_current_version()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Determine new version
    if args.version:
        new_version = args.version
        # Validate format
        try:
            parse_version(new_version)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    elif args.major:
        new_version = bump_version(current_version, "major")
    elif args.minor:
        new_version = bump_version(current_version, "minor")
    else:  # args.patch
        new_version = bump_version(current_version, "patch")

    print(f"Current version: {current_version}")
    print(f"New version: {new_version}")

    # Update files
    files_to_update = [
        Path("pyproject.toml"),
        Path("src/mcp_pvp/__init__.py"),
    ]

    print("\nUpdating files:")
    for file_path in files_to_update:
        if not file_path.exists():
            print(f"  ⚠️  {file_path} - NOT FOUND")
            continue

        changed = update_file(file_path, current_version, new_version)
        if changed:
            print(f"  ✅ {file_path}")
        else:
            print(f"  ⚠️  {file_path} - no changes")

    print(f"\n✨ Version bumped from {current_version} to {new_version}")
    print("\n📝 Next steps:")
    print(f"  1. Update CHANGELOG.md with release notes for v{new_version}")
    print(f"  2. Commit: git add -A && git commit -m 'Bump version to v{new_version}'")
    print(f"  3. Create tag: git tag -a v{new_version} -m 'Release v{new_version}'")
    print("  4. Push: git push && git push --tags")

    return 0


if __name__ == "__main__":
    sys.exit(main())
