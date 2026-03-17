#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# Automated release script for mcp-pvp
#
# Usage:
#   ./scripts/release.sh patch          # 0.6.1 → 0.6.2
#   ./scripts/release.sh minor          # 0.6.1 → 0.7.0
#   ./scripts/release.sh major          # 0.6.1 → 1.0.0
#   ./scripts/release.sh 0.8.0          # explicit version
#   ./scripts/release.sh patch --dry-run
#   ./scripts/release.sh patch --no-push
# ──────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

DRY_RUN=false
NO_PUSH=false

# ─── Helpers ──────────────────────────────────────────────────

info()  { echo -e "${CYAN}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✅${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠️${NC}  $*"; }
fail()  { echo -e "${RED}❌${NC} $*" >&2; exit 1; }
step()  { echo -e "\n${BOLD}── $* ──${NC}"; }

confirm() {
    local msg="$1"
    if $DRY_RUN; then
        info "(dry-run) Would prompt: $msg"
        return 0
    fi
    echo -en "${YELLOW}$msg [y/N]${NC} "
    read -r answer
    [[ "$answer" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
}

run() {
    if $DRY_RUN; then
        echo -e "  ${CYAN}(dry-run)${NC} $*"
    else
        "$@"
    fi
}

# ─── Parse arguments ─────────────────────────────────────────

BUMP_ARG=""

for arg in "$@"; do
    case "$arg" in
        --dry-run)  DRY_RUN=true ;;
        --no-push)  NO_PUSH=true ;;
        -h|--help)
            echo "Usage: $0 <patch|minor|major|X.Y.Z> [--dry-run] [--no-push]"
            echo ""
            echo "Options:"
            echo "  patch|minor|major   Bump type (relative to current version)"
            echo "  X.Y.Z              Explicit version number"
            echo "  --dry-run          Show what would happen without making changes"
            echo "  --no-push          Stop after tagging (don't push to remote)"
            exit 0
            ;;
        *)
            if [ -z "$BUMP_ARG" ]; then
                BUMP_ARG="$arg"
            else
                fail "Unexpected argument: $arg"
            fi
            ;;
    esac
done

[ -n "$BUMP_ARG" ] || fail "Missing bump type. Usage: $0 <patch|minor|major|X.Y.Z> [--dry-run] [--no-push]"

# ─── Ensure we're in repo root ────────────────────────────────

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

[ -f pyproject.toml ] || fail "pyproject.toml not found. Run from the mcp-pvp repo root."
[ -d .git ] || fail "Not a git repository."

# ─── Preflight checks ────────────────────────────────────────

step "Preflight checks"

# Current branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    warn "You are on branch '${CURRENT_BRANCH}', not 'main'."
    confirm "Continue anyway?"
fi

# Uncommitted changes
if ! git diff --quiet || ! git diff --cached --quiet; then
    fail "You have uncommitted changes. Commit or stash them first."
fi

# Ensure we're up to date with remote
info "Fetching latest from origin..."
git fetch origin "$CURRENT_BRANCH" --quiet 2>/dev/null || true
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse "origin/$CURRENT_BRANCH" 2>/dev/null || echo "$LOCAL")
if [ "$LOCAL" != "$REMOTE" ]; then
    warn "Local branch is not up to date with origin/$CURRENT_BRANCH."
    confirm "Continue anyway?"
fi

ok "Preflight checks passed"

# ─── Get current version ──────────────────────────────────────

CURRENT_VERSION=$(uv run python -c "from src.mcp_pvp import __version__; print(__version__)")
info "Current version: ${BOLD}$CURRENT_VERSION${NC}"

# ─── Bump version ─────────────────────────────────────────────

step "Bumping version"

case "$BUMP_ARG" in
    patch|minor|major)
        BUMP_FLAG="--$BUMP_ARG"
        run uv run python scripts/bump_version.py $BUMP_FLAG
        ;;
    *)
        # Validate explicit version format
        if ! echo "$BUMP_ARG" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
            fail "Invalid version format: $BUMP_ARG (expected X.Y.Z)"
        fi
        run uv run python scripts/bump_version.py "$BUMP_ARG"
        ;;
esac

if $DRY_RUN; then
    # Compute what the new version would be
    case "$BUMP_ARG" in
        patch)
            IFS='.' read -r ma mi pa <<< "$CURRENT_VERSION"
            NEW_VERSION="$ma.$mi.$((pa + 1))"
            ;;
        minor)
            IFS='.' read -r ma mi pa <<< "$CURRENT_VERSION"
            NEW_VERSION="$ma.$((mi + 1)).0"
            ;;
        major)
            IFS='.' read -r ma mi pa <<< "$CURRENT_VERSION"
            NEW_VERSION="$((ma + 1)).0.0"
            ;;
        *)
            NEW_VERSION="$BUMP_ARG"
            ;;
    esac
else
    NEW_VERSION=$(uv run python -c "from src.mcp_pvp import __version__; print(__version__)")
fi

ok "Version: ${CURRENT_VERSION} → ${BOLD}${NEW_VERSION}${NC}"

# ─── Update changelog ─────────────────────────────────────────

step "Updating CHANGELOG.md"

TODAY=$(date +%Y-%m-%d)
CHANGELOG="CHANGELOG.md"

if grep -q "## \[$NEW_VERSION\]" "$CHANGELOG" 2>/dev/null; then
    ok "Changelog already has a [$NEW_VERSION] section"
else
    if grep -q '## \[Unreleased\]' "$CHANGELOG"; then
        # Check if there are entries under [Unreleased]
        UNRELEASED_CONTENT=$(awk '/## \[Unreleased\]/{found=1; next} /## \[/{found=0} found' "$CHANGELOG" | grep -v '^$' || true)
        if [ -n "$UNRELEASED_CONTENT" ]; then
            info "Moving [Unreleased] entries into [$NEW_VERSION]"
            if ! $DRY_RUN; then
                sed -i '' "s/## \[Unreleased\]/## [Unreleased]\n\n## [$NEW_VERSION] - $TODAY/" "$CHANGELOG"
            fi
            ok "Changelog updated with [$NEW_VERSION] - $TODAY"
        else
            warn "No entries found under [Unreleased]."
            echo ""
            echo -e "  ${YELLOW}Please add release notes to CHANGELOG.md before continuing.${NC}"
            echo -e "  Expected format under [Unreleased]:"
            echo ""
            echo -e "    ### Added"
            echo -e "    - New feature description"
            echo ""
            echo -e "    ### Fixed"
            echo -e "    - Bug fix description"
            echo ""
            if ! $DRY_RUN; then
                confirm "Continue without changelog entries?"
                # Add empty section anyway
                sed -i '' "s/## \[Unreleased\]/## [Unreleased]\n\n## [$NEW_VERSION] - $TODAY/" "$CHANGELOG"
            fi
        fi
    else
        warn "No [Unreleased] section found in CHANGELOG.md. Skipping changelog update."
    fi
fi

# ─── Run checks ───────────────────────────────────────────────

step "Running checks"

if $DRY_RUN; then
    info "(dry-run) Would run: make check"
else
    info "Running lint, format-check, typecheck, security, and tests..."
    if ! make check; then
        fail "Checks failed. Fix the issues and try again."
    fi
    ok "All checks passed"
fi

# ─── Commit ────────────────────────────────────────────────────

step "Committing release"

COMMIT_MSG="Release v${NEW_VERSION}"

run git add -A
run git commit -m "$COMMIT_MSG"

ok "Committed: $COMMIT_MSG"

# ─── Tag ───────────────────────────────────────────────────────

step "Creating tag"

TAG="v${NEW_VERSION}"

if git tag -l "$TAG" | grep -q "$TAG"; then
    fail "Tag $TAG already exists. Delete it first: git tag -d $TAG"
fi

run git tag -a "$TAG" -m "Release $TAG"

ok "Created tag: $TAG"

# ─── Push ──────────────────────────────────────────────────────

if $NO_PUSH; then
    warn "Skipping push (--no-push). Run manually:"
    echo "  git push origin $CURRENT_BRANCH"
    echo "  git push origin $TAG"
else
    step "Pushing to origin"

    confirm "Push commit and tag to origin? This will trigger the release workflow."

    run git push origin "$CURRENT_BRANCH"
    run git push origin "$TAG"

    ok "Pushed to origin"
fi

# ─── Done ──────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}🎉 Release v${NEW_VERSION} complete!${NC}"
echo ""
if ! $NO_PUSH && ! $DRY_RUN; then
    echo -e "  ${CYAN}GitHub Actions will now:${NC}"
    echo "    1. Validate version + run tests"
    echo "    2. Build sdist and wheel"
    echo "    3. Create GitHub Release with changelog notes"
    echo "    4. Publish to PyPI (if enabled)"
    echo ""
    echo -e "  ${CYAN}Monitor:${NC} https://github.com/hidet-io/mcp-pvp/actions"
fi
