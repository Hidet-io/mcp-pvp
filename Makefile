.PHONY: help install install-dev install-all clean test test-cov lint format typecheck security pre-commit run-http run-mcp build example

# Default target
help:
	@echo "mcp-pvp Makefile commands:"
	@echo ""
	@echo "Setup & Installation:"
	@echo "  make install          - Install core dependencies with uv"
	@echo "  make install-dev      - Install with dev dependencies"
	@echo "  make install-all      - Install all optional dependencies (presidio, http, dev)"
	@echo ""
	@echo "Development:"
	@echo "  make clean            - Remove build artifacts and caches"
	@echo "  make test             - Run tests with pytest"
	@echo "  make test-cov         - Run tests with coverage report"
	@echo "  make lint             - Run ruff linter"
	@echo "  make format           - Format code with ruff"
	@echo "  make typecheck        - Run mypy type checker"
	@echo "  make pre-commit       - Run all pre-commit hooks"
	@echo "  make check            - Run lint, format-check, typecheck, and test"
	@echo ""
	@echo "Run Services:"
	@echo "  make run-http         - Start HTTP API server"
	@echo "  make run-mcp          - Start MCP server (stub)"
	@echo "  make example          - Run safe_email_sender example"
	@echo ""
	@echo "Build:"
	@echo "  make build            - Build distribution packages"
	@echo "  make version          - Show current version"
	@echo ""
	@echo "Release (Maintainers):"
	@echo "  make release-check    - Pre-release checklist"
	@echo "  make release VERSION=0.x.x - Create and tag release"
	@echo ""

# Installation
install:
	uv pip install -e .

install-dev:
	uv pip install -e ".[dev]"

install-all:
	uv pip install -e ".[all]"

# Cleanup
clean:
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete

# Testing
test:
	pytest

test-cov:
	pytest --cov --cov-report=html --cov-report=term

test-fast:
	pytest -x

# Code quality
lint:
	ruff check .

lint-fix:
	ruff check . --fix

format:
	ruff format .

format-check:
	ruff format --check .

typecheck:
	mypy src/

security:
	uv run bandit -r src/ -c pyproject.toml

# Pre-commit
pre-commit:
	pre-commit run --all-files

pre-commit-install:
	pre-commit install

# Combined check (run before commits)
check: lint format-check typecheck security test
	@echo "✅ All checks passed!"

# Run services
run-http:
	python -m mcp_pvp.bindings.http.app

run-mcp:
	python -m mcp_pvp.bindings.mcp.server

example:
	python examples/safe_email_sender/example.py

# Build
build:
	python -m build

# Release (maintainers only)
release-check:
	@echo "Pre-release checklist:"
	@echo "  1. ✓ Version updated in pyproject.toml and __init__.py"
	@echo "  2. ✓ CHANGELOG.md updated with release date"
	@echo "  3. ✓ All tests passing (make test)"
	@echo "  4. ✓ Code quality checks passing (make check)"
	@echo ""
	@echo "Run 'make release VERSION=0.x.x' to create release"

release:
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION not specified. Usage: make release VERSION=0.x.x"; \
		exit 1; \
	fi
	@echo "Creating release v$(VERSION)..."
	@git diff --quiet || (echo "Error: Uncommitted changes. Commit or stash first." && exit 1)
	@git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	@echo "✅ Tag v$(VERSION) created locally"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Review tag: git show v$(VERSION)"
	@echo "  2. Push tag: git push origin v$(VERSION)"
	@echo "  3. GitHub Actions will build and publish to PyPI"

# Update dependencies
update:
	uv pip compile pyproject.toml -o requirements.txt

# Show current version
version:
	@python -c "from src.mcp_pvp import __version__; print(__version__)"
